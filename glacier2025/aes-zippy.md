# aes-zippy

[GlacierCTF 2025](https://glacierctf.com/) - Crypto

AES-GCM compression oracle side channel

Witeup by [Arnav Vora](https://github.com/AVDestroyer)

> Our AES encryption is zippy fast! Just provide your plaintext and nonce. BUT no nonsense allowed, we track everything.


## Background

We are given a netcat connection and some source code. We can access an encryption oracle where we can encrypt any plaintext/nonce combination using AES-GCM. We can also attempt to decrypt one ciphertext (providing our own nonce and auth tag). If the tag check passes and our decrypted plaintext contains an `ADMIN_SECRET` (`b"Glacier CTF Open"`), we get the flag.

This service also does some other interesting things. After every call to the encryption oracle, it calculates the "size" of its "storage" for past encryptions. This (simulated) storage is storing past encryptions and nonces, and we aren't allowed to reuse nonces when using the oracle. After calculating the size, we are told how many bytes of the storage are used. However, in the size calculation, we zlib-compress two variables: `ADMIN_LOGS` and `NORMAL_LOGS`. `ADMIN_LOGS` contains some crucial information we will describe shortly. `NORMAL_LOGS` contains the plaintext, ciphertext, and tag of your current encryption query formatted as: `f"{pt.hex()=} = {ct.hex()=}, {tag.hex()=}"`. We aren't allowed to encrypt anything if we go over a pre-defined size limit (2^16 bytes).

Also, there is a `test_init()` function ran before everything else. This function encrypts the plaintext `b"Hello GlacierCTF"` with a random nonce and then decrypts the returned ciphertext to ensure that both functions work correctly. It also adds to the `ADMIN_LOGS` the nonce and tag of the encrypted plaintext. After this, `ADMIN_LOGS` is never changed.

## Compression Oracle

Immediately, this challenge points to an compression oracle side-channel. Since after every encryption we are told the size of a zlib-compressed *plaintext*, we can try to modify the compressed plaintext to find patterns.

The structure of the data being compressed is `ADMIN_LOGS.encode() + NORMAL_LOGS.encode()`, where the following lines are used to construct `ADMIN_LOGS` when running the initial encryption:
```python
    ADMIN_LOGS += f"[+] Nonce: {base64.b64encode(nonce).decode()}\n"
    ADMIN_LOGS += f"[+] Tag: {base64.b64encode(tag).decode()}\n"
```
and the following lines are used to construct `NORMAL_LOGS` when encrypting with a user-supplied plaintext and nonce:
```python
                NORMAL_LOGS = f"{pt.hex()=}"
```

As the user, we can only control `pt` in `NORMAL_LOGS`. What can we do? zlib uses the DEFLATE algorithm, which is a dictionary-based encoding. It will save on characters if there are long, repeated substrings in the string being encoded. If, for example, our `pt` contains a string that shares a long substring with `ADMIN_LOGS`, DEFLATE can compress our string to less bytes than if `pt` did not share this substring. The longer the shared substring is, the more bytes DEFLATE can compress and save (because each "duplicated" byte can essentially be turned into a single byte + some overhead). Therefore, if we want to recover something from `ADMIN_LOGS`, we can try to build common substrings with the log in our plaintext, and observe the length of the compressed plaintext.

We can start by trying to recover the random `nonce` used to encrypt the initial data. In `ADMIN_LOGS`, we know that the nonce is preceded by `"Nonce: "`; let's add that to our common substring. Then, we can try to guess the next character of this substring which is the first character of the nonce. Since the nonce is base64-encoded, there ~64 guesses to make here. Whatever guess produces the smallest compressed size is most likely to be the correct character for our nonce, since it would lengthen the shared substring that gets compressed.

In my experience, I found it best to skip base64 padding characters like `=` as they would often trigger false positives. We can manually fix padding if we need to.

There is just one caveat; the "storage size" that is printed to us is a running sum of everything we have asked the encryption oracle to encrypt. It is easy to get around this; we simply need to take the difference between the current storage size and the previous storage size to find out the length of compressed data. We also need to make sure we don't overflow this size. Thankfully, by making 64 guesses per character, we don't end up overflowing.

We can perform a very similar process to recover the `tag` in `ADMIN_LOGS` associated with the initial encryption. The following part of our solve script is used to recover these values. Keep in mind that each time we use the encryption oracle we need to supply a different nonce, but it is pretty simple to get around this (I kept incrementing a counter acting as my nonce).

```python
def b64_decode_fixed(s: str) -> bytes:
    # Add '=' padding as needed
    missing = len(s) % 4
    if missing != 0:
        s += '=' * (4 - missing)
    print(s)
    return base64.b64decode(s)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main():

    charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    r = conn()

    current_len = 0
    max_len = 65536
    test_nonce = 1

    #print(r.recvline())
    #print(r.recvline())
    #print(r.recvline())

    # First, get the tag
    recovered_tag = b'Tag: '
    
    while current_len < (max_len - 16):
        # Get the first length
        r.recvuntil(b'> ')
        r.sendline(b'0')
        r.recvuntil(b'> ')
        test_pt = recovered_tag
        r.sendline(test_pt.hex().encode())
        r.recvuntil(b'> ')
        r.sendline(test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode())
        test_nonce += 1
        r.recvline()
        current_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])

        # Get the second length for the max difference
        r.recvuntil(b'> ')
        r.sendline(b'0')
        r.recvuntil(b'> ')
        test_byte = b'='
        test_pt = recovered_tag + test_byte
        r.sendline(test_pt.hex().encode())
        r.recvuntil(b'> ')
        r.sendline(test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode())
        test_nonce += 1
        r.recvline()
        next_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])
        current_len = next_len

        counter = 0

        print(f'testing chars with current_len: {current_len}')

        for char in charset:
            counter += 1
            test_byte = char.to_bytes(1, "little")
            test_pt = recovered_tag + test_byte
            r.sendline(b'\n'.join([b'0', test_pt.hex().encode(), test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode()]))
            test_nonce += 1
            r.recvuntil(b"[+]")
            test_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])
            if (test_len - current_len) < 16 * counter:
                recovered_tag += test_byte
                current_len = test_len
                print(f'now: {recovered_tag}')
                break
        else:
            print(f"Full tag: {recovered_tag}")
            break


    # Second, get the nonce
    recovered_nonce = b'Nonce: '
    
    while current_len < (max_len - 16):
        # Get the first length
        r.recvuntil(b'> ')
        r.sendline(b'0')
        r.recvuntil(b'> ')
        test_pt = recovered_nonce
        r.sendline(test_pt.hex().encode())
        r.recvuntil(b'> ')
        r.sendline(test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode())
        test_nonce += 1
        r.recvline()
        current_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])

        # Get the second length for the max difference
        r.recvuntil(b'> ')
        r.sendline(b'0')
        r.recvuntil(b'> ')
        test_byte = b'='
        test_pt = recovered_nonce + test_byte
        r.sendline(test_pt.hex().encode())
        r.recvuntil(b'> ')
        r.sendline(test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode())
        test_nonce += 1
        r.recvline()
        next_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])
        current_len = next_len

        counter = 0

        print(f'testing chars with current_len: {current_len}')

        for char in charset:
            counter += 1
            test_byte = char.to_bytes(1, "little")
            test_pt = recovered_nonce + test_byte
            r.sendline(b'\n'.join([b'0', test_pt.hex().encode(), test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode()]))
            test_nonce += 1
            r.recvuntil(b'[+]')
            test_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])
            if (test_len - current_len) < 16 * counter:
                recovered_nonce += test_byte
                current_len = test_len
                print(f'now: {recovered_nonce}')
                break
        else:
            print(f"Full nonce: {recovered_nonce}")
            break

    
    nonce = b64_decode_fixed(recovered_nonce.decode().split()[-1])
    tag1 = b64_decode_fixed(recovered_tag.decode().split()[-1])
    print(nonce)
    print(tag1)
    print(current_len)
```

After running this, we see that at the end, we are well under the size limit of our storage, using around 25000 of the 65536 bytes.

## AES-GCM nonce reuse

Wait, how do these "admin nonce" and "admin tag" values help us? Keep in mind that we still can encrypt our own plaintexts with (new) nonces with the encryption oracle. Crucially, the "admin nonce" is *never added to the list of used nonces (`USED_NONCES`)*. This means we are allowed to reuse this nonce in our encryption oracle (once)! This itself can completely break AES-GCM: nonces (number used only once) should never be reused.

AES-GCM is a stream cipher, so by using the same nonce, we will get the same keystream, which is obviously a massive problem. When we use the encryption oracle, we can easily determine the keystream by XORing the our plaintext and the ciphertext we receive. Ideally, this keystream is used nowhere else. But since we reused the nonce used for "admin encryption", the same keystream was used there. Therefore, we can easily determine the ciphertext of the admin secret.

What cryptographic information do we have now if we reuse the nonce in the encryption oracle?
- The nonce used to encrypt the admin plaintext (`b"Hello GlacierCTF"`). Thankfully this plaintext is exactly 16 bytes (1 AES block) long. We will reuse this nonce.
- The encrypted admin message.
- The auth tag generated by encrypting the admin secret with this nonce.
- A new (arbitrary) 16-byte plaintext message.
- The ciphertext of this message.
- The auth tag generated for this message.
- AES-GCM is an AEAD (authenticated encryption with additional data) scheme - you can authenticate additional plaintext on top of your plaintext. We also know the associated data for both encryptions (it is `b"GlacierCTF2025"`, also thankfully 16 bytes/1 block).

With information about AES-GCM-encrypted messages with the same nonce, we can encrypt and authenticate any message we want without knowing the key! The information listed above is all we need. I used the scripts [here](https://github.com/tl2cents/AEAD-Nonce-Reuse-Attacks/blob/main/aes-gcm/aes_gcm_forgery.py) to generate an authenticated encryption of the admin secret (`b"Glacier CTF Open"`) with a valid auth tag. This encryption will still use the same nonce as I recovered from the compression oracle. Conveniently, the "Access admin files" decryption does not check if you are reusing a nonce.

By passing the ciphertext, nonce, and auth tag to the connection, we should get our flag!

## Solve script

```python
#!/usr/bin/env python3
from pwn import *
import base64
import subprocess
import json

def b64_decode_fixed(s: str) -> bytes:
    # Add '=' padding as needed
    missing = len(s) % 4
    if missing != 0:
        s += '=' * (4 - missing)
    print(s)
    return base64.b64decode(s)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def conn():
    if args.LOCAL:
        r = process(["python", "challenge"])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.glacierctf.com", 13373)

    return r


def main():

    charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    r = conn()

    current_len = 0
    max_len = 65536
    test_nonce = 1

    # First, get the tag
    recovered_tag = b'Tag: '
    
    while current_len < (max_len - 16):
        # Get the first length
        r.recvuntil(b'> ')
        r.sendline(b'0')
        r.recvuntil(b'> ')
        test_pt = recovered_tag
        r.sendline(test_pt.hex().encode())
        r.recvuntil(b'> ')
        r.sendline(test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode())
        test_nonce += 1
        r.recvline()
        current_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])

        # Get the second length for the max difference
        r.recvuntil(b'> ')
        r.sendline(b'0')
        r.recvuntil(b'> ')
        test_byte = b'='
        test_pt = recovered_tag + test_byte
        r.sendline(test_pt.hex().encode())
        r.recvuntil(b'> ')
        r.sendline(test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode())
        test_nonce += 1
        r.recvline()
        next_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])
        current_len = next_len

        counter = 0

        print(f'testing chars with current_len: {current_len}')

        for char in charset:
            counter += 1
            test_byte = char.to_bytes(1, "little")
            test_pt = recovered_tag + test_byte
            r.sendline(b'\n'.join([b'0', test_pt.hex().encode(), test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode()]))
            test_nonce += 1
            r.recvuntil(b"[+]")
            test_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])
            if (test_len - current_len) < 16 * counter:
                recovered_tag += test_byte
                current_len = test_len
                print(f'now: {recovered_tag}')
                break
        else:
            print(f"Full tag: {recovered_tag}")
            break


    # Second, get the nonce
    recovered_nonce = b'Nonce: '
    
    while current_len < (max_len - 16):
        # Get the first length
        r.recvuntil(b'> ')
        r.sendline(b'0')
        r.recvuntil(b'> ')
        test_pt = recovered_nonce
        r.sendline(test_pt.hex().encode())
        r.recvuntil(b'> ')
        r.sendline(test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode())
        test_nonce += 1
        r.recvline()
        current_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])

        # Get the second length for the max difference
        r.recvuntil(b'> ')
        r.sendline(b'0')
        r.recvuntil(b'> ')
        test_byte = b'='
        test_pt = recovered_nonce + test_byte
        r.sendline(test_pt.hex().encode())
        r.recvuntil(b'> ')
        r.sendline(test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode())
        test_nonce += 1
        r.recvline()
        next_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])
        current_len = next_len

        counter = 0

        print(f'testing chars with current_len: {current_len}')

        for char in charset:
            counter += 1
            test_byte = char.to_bytes(1, "little")
            test_pt = recovered_nonce + test_byte
            r.sendline(b'\n'.join([b'0', test_pt.hex().encode(), test_nonce.to_bytes(test_nonce.bit_length(), "little").hex().encode()]))
            test_nonce += 1
            r.recvuntil(b'[+]')
            test_len = int(r.recvline().decode().strip().split()[-2].split('/')[0])
            if (test_len - current_len) < 16 * counter:
                recovered_nonce += test_byte
                current_len = test_len
                print(f'now: {recovered_nonce}')
                break
        else:
            print(f"Full nonce: {recovered_nonce}")
            break

    
    nonce = b64_decode_fixed(recovered_nonce.decode().split()[-1])
    tag1 = b64_decode_fixed(recovered_tag.decode().split()[-1])
    print(nonce)
    print(tag1)
    print(current_len)

    r.recvuntil(b'> ')
    r.sendline(b'0')
    r.recvuntil(b'> ')
    r.sendline((b'\x00' * 16).hex().encode())
    r.recvuntil(b'> ')
    r.sendline(nonce.hex().encode())
    data = r.recvline().decode().strip()
    ct2 = bytes.fromhex(data.split()[2].split("'")[-2])
    tag2 = bytes.fromhex(data.split()[-1].split("'")[-2])

    keystream = ct2
    ct1 = xor(keystream, b"Hello GlacierCTF")

    print(ct1)
    print(ct2)
    print(tag1)
    print(tag2)

    ads = [b"GlacierCTF2025", b"GlacierCTF2025"]
    cts = [ct1, ct2]
    tags = [tag1, tag2]
    known_plaintext1 = b"Hello GlacierCTF"
    target_msg = b"Glacier CTF Open"
    target_a = b"GlacierCTF2025"

    data = {
        "ads": [x.hex() for x in ads],
        "cts": [x.hex() for x in cts],
        "tags": [x.hex() for x in tags],
        "known_plaintext1": known_plaintext1.hex(),
        "target_msg": target_msg.hex(),
        "target_a": target_a.hex()
    }

    # Run the Sage script
    subprocess.run(
        ["sage", "aes_gcm_forgery.py"],
        input=json.dumps(data),
        text=True,
        stdout=sys.stdout,
        bufsize=1,
    )

    with open('result.txt', 'r') as f:
        ct, tag = f.read().strip().split()
        ct = bytes.fromhex(ct)
        tag = bytes.fromhex(tag)

    print(f'forged ct: {ct}')
    print(f'forged tag: {tag}')


    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'> ')
    r.sendline(ct.hex().encode())
    r.recvuntil(b'> ')
    r.sendline(nonce.hex().encode())
    r.recvuntil(b'> ')
    r.sendline(tag.hex().encode())
    

    r.interactive()


if __name__ == "__main__":
    main()
```

The sage script I used is identical to the one found [here](https://github.com/tl2cents/AEAD-Nonce-Reuse-Attacks/blob/main/aes-gcm/aes_gcm_forgery.py), with the following added in to parse input:

```python
def main(data):
    # Parse arguments
    ads = [bytes.fromhex(x) for x in data['ads']]
    cts = [bytes.fromhex(x) for x in data['cts']]
    tags = [bytes.fromhex(x) for x in data['tags']]
    known_plaintext1 = bytes.fromhex(data['known_plaintext1'])
    target_msg = bytes.fromhex(data['target_msg'])
    target_a = bytes.fromhex(data['target_a'])

    with open('result.txt', 'w') as f:
        for result in aes_gcm_forgery_attack(ads[0], cts[0], tags[0], ads[1], cts[1], tags[1], known_plaintext1, target_msg, target_a):
            f.write(result[0].hex() + ' ' + result[1].hex())


if __name__ == "__main__":
    data = json.load(sys.stdin)
    main(data)
```


## Flag
`gctf{ZiPPY_iS_0UT_heRE_5NItchin6_on_@lL_tHE_nONC3s}`
