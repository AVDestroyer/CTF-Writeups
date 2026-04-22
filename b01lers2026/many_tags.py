#!/usr/bin/env python3
import random
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK_SIZE = 16
BLOCK_BITS = 8 * BLOCK_SIZE
MASK64 = (1 << 64) - 1
MASK128 = (1 << BLOCK_BITS) - 1
GCM_REDUCTION = 0xE1000000000000000000000000000000
STATE_SIZE = 624
QUERY_BUDGET = 704
WORD_MASK = 0xFFFFFFFF

master_key = secrets.token_bytes(32)
used = 0


def new_fault_rng(key):
    return random.Random(int.from_bytes(key, "big"))


mask_rng = new_fault_rng(master_key)


def aes_block_encrypt(key, block):
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def aes_gcm_encrypt(key, nonce, message):
    encrypted = AESGCM(key).encrypt(nonce, message, None)
    return encrypted[:-BLOCK_SIZE], encrypted[-BLOCK_SIZE:]


def compute_h(key):
    return aes_block_encrypt(key, b"\x00" * BLOCK_SIZE)


def gf_mul(x, y):
    z = 0
    v = x
    for i in range(BLOCK_BITS):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ GCM_REDUCTION
        else:
            v >>= 1
    return z & MASK128


def ghash(subkey, blocks):
    tag = 0
    for block in blocks:
        tag = gf_mul(tag ^ block, subkey)
    return tag


def compute_length_block(message_len):
    return (0).to_bytes(8, "big") + (message_len * 8).to_bytes(8, "big")


def compute_one_block_ghash(h_int, ciphertext):
    return ghash(
        h_int,
        [
            int.from_bytes(ciphertext, "big"),
            int.from_bytes(compute_length_block(len(ciphertext)), "big"),
        ],
    )


def compute_gcm_mask(key, nonce):
    return aes_block_encrypt(key, nonce + b"\x00\x00\x00\x01")


def construct_tag(real_tag, ghash_value, fault_words):
    real_tag_int = int.from_bytes(real_tag, "big")
    fault_value = (fault_words[0] << 32) | fault_words[1]
    tag_low = (ghash_value ^ fault_value) & MASK64
    tag_int = (real_tag_int & (~MASK64)) | tag_low
    return tag_int.to_bytes(BLOCK_SIZE, "big")


def encrypt_query_message(key, nonce, message, fault_words):
    ciphertext, real_tag = aes_gcm_encrypt(key, nonce, message)
    h_int = int.from_bytes(compute_h(key), "big")
    ghash_value = compute_one_block_ghash(h_int, ciphertext)
    tag = construct_tag(real_tag, ghash_value, fault_words)
    return {
        "ciphertext": ciphertext,
        "real_tag": real_tag,
        "tag": tag,
        "ghash": ghash_value.to_bytes(BLOCK_SIZE, "big"),
    }


def next_fault_words(rng):
    return [rng.getrandbits(32), rng.getrandbits(32)]


def encrypt_query_with_rng(key, nonce, message, rng):
    fault_words = next_fault_words(rng)
    result = encrypt_query_message(key, nonce, message, fault_words)
    result["fault_words"] = fault_words
    return result


def encrypt_flag_message(key, nonce, message):
    return aes_gcm_encrypt(key, nonce, message)


def get_tag():
    global used

    if used >= QUERY_BUDGET:
        print("No more tags for you")
        return

    nonce = secrets.token_bytes(12)
    message = secrets.token_bytes(BLOCK_SIZE)
    result = encrypt_query_with_rng(master_key, nonce, message, mask_rng)
    used += 1
    print(f"nonce = {nonce.hex()}")
    print(f"ciphertext = {result['ciphertext'].hex()}")
    print(f"tag = {result['tag'].hex()}")
    print(f"queries_left = {QUERY_BUDGET - used}")
    # extra
    print(f"real tag = {result['real_tag'].hex()}")
    print(f"fault words = {result['fault_words']}")
    print(f"ghash = {result['ghash'].hex()}")
    print(f"h = {int.from_bytes(compute_h(master_key), "big")}")


def main():
    with open("./flag.txt") as f:
        flag = f.read().strip().encode()

    flag_nonce = secrets.token_bytes(12)
    flag_cipher, flag_tag = encrypt_flag_message(master_key, flag_nonce, flag)

    print(
        f"""
*********************************************************

too many tags

*********************************************************

flag_nonce = {flag_nonce.hex()}
flag_ciphertext = {flag_cipher.hex()}
flag_tag = {flag_tag.hex()}

query budget = {QUERY_BUDGET}

************************* Menu **************************

1. Get a random ciphertext and tag
2. Exit

*********************************************************
"""
    )

    while True:
        try:
            option = input("> ")
        except EOFError:
            return

        if option == "1":
            get_tag()
        elif option == "2":
            print("Bye")
            return
        else:
            print("Invalid option")


if __name__ == "__main__":
    main()
