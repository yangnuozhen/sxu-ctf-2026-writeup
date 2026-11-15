#!/usr/bin/env python3
"""Extract the PyInstaller CArchive even when its first magic bytes were altered."""
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parent


def extract():
    blob = (ROOT / 'ooops').read_bytes()
    cookie = blob.rfind(b'\x0c\x0b\x0a\x0b\x0e') - 3
    assert cookie >= 0
    magic, size, toc_offset, toc_size, version, library = struct.unpack_from(
        '!8sIIII64s', blob, cookie
    )
    base = cookie + 88 - size
    assert base >= 0 and version == 35
    out = ROOT / 'extracted'
    out.mkdir(exist_ok=True)
    pos = base + toc_offset
    end = pos + toc_size
    entries = []
    while pos < end:
        length, offset, packed, raw_size, compressed, kind = struct.unpack_from(
            '!IIIIBc', blob, pos
        )
        assert length >= 18 and pos + length <= end
        name = blob[pos+18:pos+length].rstrip(b'\0').decode()
        data = blob[base+offset:base+offset+packed]
        if compressed:
            data = zlib.decompress(data)
        assert len(data) == raw_size
        target = out / name
        assert out.resolve() in target.resolve().parents
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        entries.append((kind.decode(), name, raw_size))
        pos += length
    assert pos == end
    return magic, entries


if __name__ == '__main__':
    magic, entries = extract()
    print('Archive magic:', repr(magic))
    print('Python version: 3.5')
    for kind, name, size in entries:
        print(kind, name, size)
