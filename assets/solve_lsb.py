#!/usr/bin/env python3
"""Recover the row-major RGB LSB message from out.png."""
import argparse
import re
from pathlib import Path

import numpy as np
from PIL import Image

BUNDLE = Path(__file__).resolve().parents[1]


def solve(image_path, output_dir):
    with Image.open(image_path) as image:
        print(f'Image: {image.width} x {image.height}; mode: {image.mode}')
        original = np.array(image)
        if image.mode == 'RGBA':
            alpha_values = np.unique(original[:, :, 3])
            print(f'Alpha channel unique values: {alpha_values.tolist()}')
        pixels = np.array(image.convert('RGB'))
    # Array order is [row, column, channel]. Keep RGB and ignore alpha.
    bits = (pixels & 1).reshape(-1)
    payload = np.packbits(bits, bitorder='big').tobytes()
    match = re.match(rb'flag\{[A-Za-z0-9_-]+\}', payload)
    if match is None:
        raise ValueError('No flag at the beginning of the extracted RGB LSB stream')
    message = match.group()
    message_bits = np.unpackbits(np.frombuffer(message, dtype=np.uint8))
    if not np.array_equal(message_bits, bits[:len(message_bits)]):
        raise ValueError('Recovered message does not match the original pixel bits')
    flag = message.decode('ascii')
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / '03_rgb_lsb.bin').write_bytes(payload)
    (output_dir / '03_flag.txt').write_text(flag + '\n', encoding='ascii')
    print('Extraction: rows top-to-bottom, pixels left-to-right, channels R/G/B')
    print('Bit plane: bit 0; byte packing: first bit becomes the highest bit')
    print(f'Extracted bytes: {len(payload)}')
    print('First 8 recovered bytes:')
    for index, value in enumerate(payload[:8]):
        print(f'  {index:2d}  {value:08b}  0x{value:02x}  {chr(value)}')
    print(f'Flag: {flag}')
    print(f'Message: {len(message)} bytes, {len(message_bits)} bits, '
          f'{len(message_bits) // 3} complete pixels')
    print('Verification: every recovered message bit matches the original RGB LSB')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=BUNDLE / 'attachments/out.png')
    parser.add_argument('--output-dir', type=Path, default=BUNDLE / 'results')
    args = parser.parse_args()
    solve(args.input, args.output_dir)
