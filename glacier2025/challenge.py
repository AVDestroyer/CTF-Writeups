#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import zlib
import base64
from Crypto.Cipher import AES

KEY = os.urandom(16)
USED_NONCES = []
ADMIN_SECRET = b"Glacier CTF Open"
ADMIN_LOGS = ""
NORMAL_LOGS = ""
MAX_STORAGE = 1 << 16


def decrypt(ct: bytes, nonce: bytes, tag: bytes) -> bytes:
    ad = b"GlacierCTF2025"

    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)
    try:
        decrypted = cipher.decrypt_and_verify(ct, tag)
    except Exception as e:
        raise ValueError("Invalid tag")

    return decrypted


def encrypt(pt: bytes, nonce: bytes = os.urandom(16)):
    ad = b"GlacierCTF2025"

    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)

    ct, tag = cipher.encrypt_and_digest(pt)

    return ct, nonce, tag


def test_init():
    global ADMIN_LOGS

    pt = b"Hello GlacierCTF"

    ct, nonce, tag = encrypt(pt)
    assert pt == decrypt(ct, nonce, tag)

    ADMIN_LOGS += f"[+] Nonce: {base64.b64encode(nonce).decode()}\n"
    ADMIN_LOGS += f"[+] Tag: {base64.b64encode(tag).decode()}\n"


def get_size() -> int:
    global ADMIN_LOGS, NORMAL_LOGS, USED_NONCES

    full_state: bytes = ADMIN_LOGS.encode() + NORMAL_LOGS.encode()

    return len(zlib.compress(full_state)) + len(USED_NONCES)*16


def print_help():
    print("[0] Encrypt a file")
    print("[1] Access admin files")


def main():
    global NORMAL_LOGS
    print("[+] Welcome to the Glacier encryption service")
    test_init()
    while get_size() < MAX_STORAGE:
        try:
            print_help()
            choice = int(input("Choose action:\n> "))
            if choice == 0:
                pt = bytes.fromhex(input("Plaintext:\n> "))
                nonce = bytes.fromhex(input("Nonce:\n> "))

                if nonce in USED_NONCES or ADMIN_SECRET in pt:
                    return

                USED_NONCES.append(nonce)
                ct, nonce, tag = encrypt(pt, nonce)

                NORMAL_LOGS = f"{pt.hex()=} = {ct.hex()=}, {tag.hex()=}"
                print(NORMAL_LOGS)
                NORMAL_LOGS = f"{pt}"

                print(f"[+] Storage left: {get_size()}/{MAX_STORAGE} bytes")
            elif choice == 1:

                ct = bytes.fromhex(input("Ciphertext:\n> "))
                nonce = bytes.fromhex(input("Nonce:\n> "))
                tag = bytes.fromhex(input("Tag:\n> "))

                pt = decrypt(ct, nonce, tag)

                print(pt)

                if ADMIN_SECRET in pt:
                    with open("./flag.txt", "r") as flag:
                        print(f"{flag.read()}")
                return
            else:
                return
        except:
            return
    return


if __name__ == "__main__":
    main()

