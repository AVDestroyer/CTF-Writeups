#!/usr/bin/env python3

from pwn import *
import binascii
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time

def conn():
    if args.LOCAL:
        r = process(['python3','chal.py'])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("gold.b01le.rs", 5003)

    return r

def xor(b1,b2,debug=None):
    return bytes([a^b for a,b in zip(b1,b2)])

def setup_conn():
    r = conn()
    for i in range(7):
        r.recvline()
    enc_flag = r.recvline().strip().split()[-1]
    nonce = binascii.unhexlify(enc_flag[:32])
    rest = binascii.unhexlify(enc_flag[32:])
    return r, nonce, rest

r, nonce, rest = setup_conn()

pogress = iter(b"_security_to_padding_oracle..._c850d60d210169}"[::-1])
pogress = iter(b"ode_doesn't_provide_any_security_to_padding_oracle..._c850d60d210169}"[::-1])

def main():
    global r, nonce, rest
    r.recvuntil(b">> ")
    r.sendline(binascii.hexlify(nonce) + binascii.hexlify(rest))
    #between 0-16
    recovered_flag = b''
    blocks_removed = 0
    first = False
    counter = 0
    num_pad = 0
    while True:
        num_pad = (num_pad + 1) % 16
        print(num_pad)
        if num_pad == 0:
            num_pad = 16
        if num_pad == 1:
            if not first:
                first = True
            else:
                blocks_removed+=1
        for i in range(256):
            if b"}" in recovered_flag:
                a = next(pogress,None)
                if a is not None:
                    i = a
            test_byte = bytes([i])
            test_pads = bytes([num_pad]) * (num_pad-1)
            if i == num_pad and num_pad == 1:
                continue
            invariant_nonce = nonce[0:(16-num_pad)]
            guess = xor(bytes([nonce[16-num_pad]]),xor(test_byte,bytes([num_pad])))
            determined = xor(bytes(nonce[16-num_pad+1:]),xor(bytes(recovered_flag[:num_pad-1]),test_pads))
            new_nonce = invariant_nonce + guess + determined
            new_msg = (new_nonce + rest)
            if blocks_removed > 0:
                new_msg = new_msg[:(-16*blocks_removed)]
            r.recvuntil(b">> ")
            r.sendline(binascii.hexlify(new_msg))
            thing = r.recvline()
            if (thing != b'Something went wrong\n'):
                recovered_flag = test_byte + recovered_flag
                print(recovered_flag,num_pad)
                print(binascii.hexlify(new_msg))
                break
        counter+=1
        if counter > 43:
            break


    # good luck pwning :)
    print(recovered_flag)

    r.interactive()


if __name__ == "__main__":
    main()
