"""Recover the 12 missing key bits and reproduce the challenge's PRNG."""

import hashlib
import random


CIPHERTEXT = [
    140, 96, 112, 178, 38, 180, 158, 240, 179, 202, 251, 138, 188, 185,
    23, 67, 163, 22, 150, 18, 143, 212, 93, 87, 209, 139, 92, 252,
    55, 137, 6, 231, 105, 12, 65, 59, 223, 25, 179, 101, 19, 215,
]
KEY_HIGH = 2669175714787937


def keystream(key, length):
    seed = int.from_bytes(hashlib.md5(key).digest(), "big")
    rng = random.Random(seed)
    for _ in range(length):
        rng.randrange(256)  # The challenge discards this call.
        yield 256 - rng.randrange(256)  # Range is 1..256, not 0..255.


def main():
    for low in range(1 << 12):
        key = ((KEY_HIGH << 12) | low).to_bytes(8, "big")
        plain = [c ^ k for c, k in zip(CIPHERTEXT, keystream(key, len(CIPHERTEXT)))]
        if not all(32 <= c <= 126 for c in plain):
            continue
        flag = bytes(plain)
        if flag.startswith(b"flag{") and flag.endswith(b"}"):
            encrypted = [c ^ k for c, k in zip(flag, keystream(key, len(flag)))]
            assert encrypted == CIPHERTEXT
            assert int.from_bytes(key, "big") >> 12 == KEY_HIGH
            print(f"key (hex): {key.hex()}")
            print(flag.decode())


if __name__ == "__main__":
    main()
