#!/usr/bin/env python3
"""Recover the flag statically and verify a full encryption round trip."""
from pathlib import Path
import zlib

from extract import extract
from inspect_code import Reader

ROOT = Path(__file__).resolve().parent


def permutation(size):
    indices = list(range(size))
    for i in range(size - 1, -1, -1):
        j = (i * 0xDEAD + 0xBEEF) % size
        indices[i], indices[j] = indices[j], indices[i]
    return indices


def decrypt(enc_data, key):
    size = int.from_bytes(enc_data[:4], 'little')
    data = enc_data[4:4 + size]
    assert len(data) == size
    data = bytes(data[i] for i in permutation(size))
    data = bytes(value ^ key[i % len(key)] for i, value in enumerate(data))
    return zlib.decompress(data)


def encrypt(flag, key):
    data = zlib.compress(flag)
    data = bytes(value ^ key[i % len(key)] for i, value in enumerate(data))
    shuffled = bytearray(len(data))
    for i, position in enumerate(permutation(len(data))):
        shuffled[position] = data[i]
    return len(data).to_bytes(4, 'little') + shuffled


def load_challenge():
    if not (ROOT / 'extracted/ooops').exists():
        extract()
    reader = Reader((ROOT / 'extracted/ooops').read_bytes())
    module = reader.obj()
    assert reader.pos == len(reader.data)
    main = next(c for c in module['consts']
                if isinstance(c, dict) and c['name'] == 'main')
    return module, main['consts'][1], main['consts'][2]


def main():
    _, key, encrypted = load_challenge()
    flag = decrypt(encrypted, key)
    assert encrypt(flag, key) == encrypted
    (ROOT / 'flag.txt').write_bytes(flag + b'\n')
    print('Key:', key.hex())
    print('Encrypted payload:', encrypted.hex())
    print('Flag:', flag.decode())
    print('Exact encryption round trip: PASS')


if __name__ == '__main__':
    main()
