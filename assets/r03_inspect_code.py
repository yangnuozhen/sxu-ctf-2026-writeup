#!/usr/bin/env python3
"""Read Python 3.5 marshalled code without executing the bundled interpreter."""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent
OPCODES = {
    0x04: 'STORE_SUBSCR', 0x0C: 'BINARY_XOR', 0x13: 'BINARY_SUBSCR',
    0x14: 'BINARY_SUBTRACT', 0x18: 'GET_ITER', 0x19: 'BINARY_ADD',
    0x1C: 'BINARY_MODULO', 0x3C: 'END_FINALLY', 0x40: 'POP_TOP',
    0x41: 'BINARY_MULTIPLY', 0x45: 'ROT_TWO', 0x46: 'YIELD_VALUE',
    0x4C: 'RETURN_VALUE', 0x4D: 'POP_BLOCK', 0x50: 'POP_EXCEPT',
    0x5A: 'UNPACK_SEQUENCE', 0x5B: 'STORE_NAME',
    0x5D: 'POP_JUMP_IF_FALSE', 0x5F: 'FOR_ITER', 0x64: 'LOAD_FAST',
    0x65: 'LOAD_CLOSURE', 0x67: 'BUILD_SLICE', 0x68: 'COMPARE_OP',
    0x6A: 'BUILD_TUPLE', 0x6B: 'SETUP_LOOP', 0x6C: 'LOAD_DEREF',
    0x6F: 'SETUP_EXCEPT', 0x71: 'MAKE_FUNCTION', 0x74: 'JUMP_FORWARD',
    0x77: 'LOAD_CONST', 0x78: 'LOAD_GLOBAL', 0x79: 'STORE_FAST',
    0x7C: 'LOAD_ATTR', 0x83: 'CALL_FUNCTION', 0x88: 'STORE_DEREF',
    0x90: 'IMPORT_NAME', 0x91: 'MAKE_CLOSURE',
    0x97: 'JUMP_ABSOLUTE', 0x9A: 'LOAD_NAME',
}


class Reader:
    def __init__(self, data):
        self.data, self.pos, self.refs = data, 0, []

    def take(self, n):
        value = self.data[self.pos:self.pos+n]
        self.pos += n
        return value

    def integer(self):
        return struct.unpack('<i', self.take(4))[0]

    def obj(self):
        tag = self.take(1)[0]
        ref = bool(tag & 128)
        tag = chr(tag & 127)
        slot = len(self.refs)
        if ref:
            self.refs.append(None)
        if tag == 'c':
            value = {'kind': 'code'}
            if ref:
                self.refs[slot] = value
            for name in ['argcount', 'kwonlyargcount', 'nlocals', 'stacksize', 'flags']:
                value[name] = self.integer()
            for name in ['code', 'consts', 'names', 'varnames', 'freevars',
                         'cellvars', 'filename', 'name']:
                value[name] = self.obj()
            value['firstlineno'] = self.integer()
            value['lnotab'] = self.obj()
        elif tag in 'N.':
            value = None if tag == 'N' else Ellipsis
        elif tag in 'TF':
            value = tag == 'T'
        elif tag == 'i':
            value = self.integer()
        elif tag == 'r':
            value = self.refs[self.integer()]
        elif tag in 'stuazAZ':
            size = self.take(1)[0] if tag in 'zZ' else self.integer()
            value = self.take(size)
            if tag != 's':
                value = value.decode('utf-8')
        elif tag in '()':
            size = self.take(1)[0] if tag == ')' else self.integer()
            value = tuple(self.obj() for _ in range(size))
        elif tag == '[':
            value = [self.obj() for _ in range(self.integer())]
        else:
            raise ValueError((tag, self.pos-1))
        if ref:
            self.refs[slot] = value
        return value


def dump(code, depth=0):
    prefix = '  ' * depth
    print(prefix + 'FUNCTION ' + code['name'])
    for name in ['argcount', 'names', 'varnames']:
        print(prefix + name + ': ' + repr(code[name]))
    for i, value in enumerate(code['consts']):
        if not isinstance(value, dict):
            print(prefix + 'CONST ' + str(i) + ': ' + repr(value))
    raw = code['code']
    pos = 0
    while pos < len(raw):
        start = pos
        op = raw[pos]
        pos += 1
        arg = ''
        if op >= 90:
            arg = str(struct.unpack_from('<H', raw, pos)[0])
            pos += 2
        print(prefix + '%3d: %02x %-20s %s' % (start, op, OPCODES.get(op, '?'), arg))
    for value in code['consts']:
        if isinstance(value, dict):
            dump(value, depth + 1)


if __name__ == '__main__':
    reader = Reader((ROOT / 'extracted/ooops').read_bytes())
    module = reader.obj()
    assert reader.pos == len(reader.data)
    dump(module)
