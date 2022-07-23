import collections
import itertools
import math
import operator
import struct


class Uint32:
    """Unsigned 32-bit integer with overflow emulation."""
    def __init__(self, value):
        self.value = value & 0xffffffff

    def __lshift__(self, other):
        if isinstance(other, int):
            value = other
        else:
            value = other.value

        return Uint32((self.value << value) & 0xffffffff)

    def __add__(self, other):
        if isinstance(other, int):
            value = other
        else:
            value = other.value

        return Uint32((self.value + value) & 0xffffffff)

    def __sub__(self, other):
        if isinstance(other, int):
            value = other
        else:
            value = other.value

        return Uint32((self.value - value) & 0xffffffff)

    def __rshift__(self, other):
        if isinstance(other, int):
            value = other
        else:
            value = other.value

        return Uint32(self.value >> value)

    def __ixor__(self, other):
        if isinstance(other, int):
            value = other
        else:
            value = other.value

        self.value ^= value
        return self


def mix(a: Uint32, b: Uint32, c: Uint32):
    a -= b
    a -= c
    a ^= c >> 13

    b -= c
    b -= a
    b ^= a << 8

    c -= a
    c -= b
    c ^= b >> 13

    a -= b
    a -= c
    a ^= c >> 12

    b -= c
    b -= a
    b ^= a << 16

    c -= a
    c -= b
    c ^= b >> 5

    a -= b
    a -= c
    a ^= c >> 3

    b -= c
    b -= a
    b ^= a << 10

    c -= a
    c -= b
    c ^= b >> 15
    return a, b, c


def hash_jenkins(k_: bytes, length_: int, initval_: int):
    for c in k_:
        assert(c < (1 << 32))

    assert(length_ < (1 << 32))
    assert(initval_ < (1 << 32))

    k = [Uint32(c) for c in k_]
    length = Uint32(length_)
    initval = Uint32(initval_)

    a = Uint32(0x9e3779b9)
    b = Uint32(0x9e3779b9)
    c = initval
    while (len(k) >= 12):
        a += (k[0] + (k[1] << 8) + (k[2] << 16) + (k[3] << 24))
        b += (k[4] + (k[5] << 8) + (k[6] << 16) + (k[7] << 24))
        c += (k[8] + (k[9] << 8) + (k[10] << 16) + (k[11] << 24))
        a, b, c = mix(a, b, c)
        k = k[12:]

    c += length
    if len(k) > 10:
        c += k[10] << 24

    if len(k) > 9:
        c += k[9] << 16

    if len(k) > 8:
        c += k[8] << 8

    if len(k) > 7:
        b += k[7] << 24

    if len(k) > 6:
        b += k[6] << 16

    if len(k) > 5:
        b += k[5] << 8

    if len(k) > 4:
        b += k[4]

    if len(k) > 3:
        a += k[3] << 24

    if len(k) > 2:
        a += k[2] << 16

    if len(k) > 1:
        a += k[1] << 8

    if len(k) > 0:
        a += k[0]

    a, b, c = mix(a, b, c)

    return c.value


DctString = collections.namedtuple("DctString", ("hash", "value"))


# TODO: handle big endian.
class Dct:
    def __init__(self, magic="DICT", unknown1=0x2000, initval=0x0, first_hash_offset=0x13, unknown2=0x1, unknown3=0x0, container=None):
        self._magic = magic
        self._unknown1 = unknown1
        self._initval = initval
        self._first_hash_offset = first_hash_offset
        self._unknown2 = unknown2
        self._unknown3 = unknown3
        self._container = {} if container is None else container

    @staticmethod
    def from_bytes(lst: bytes):
        magic, unknown1, initval, first_hash_offset, entry_count, unknown2, keys_end, unknown3 = struct.unpack("IIIIIIII", lst[:32])
        # "DICT"
        assert(magic == 0x54434944)
        assert(first_hash_offset == 0x13)
        assert(keys_end == 7 + entry_count * 12)

        container = {}
        for position in range(32, 32 + entry_count * 12, 12):
            hash_value, offset, unknown = struct.unpack("III", lst[position : position + 12])
            assert(unknown == 0x0)
            if offset:
                container[hash_value] = bytearray(itertools.takewhile(operator.truth, lst[position + 4 + offset + 1:])).decode("utf-8")

        return Dct(magic=magic, unknown1=unknown1, initval=initval, first_hash_offset=first_hash_offset, unknown2=unknown2, unknown3=unknown3, container=container)

    def set_string_id_to_value(self, key: str, value: str):
        s = key.lower().encode("utf-8")
        self.set_hash_to_value(hash_jenkins(s, len(s), self._initval), value)

    def set_hash_to_value(self, key: int, value: str):
        self._container[key] = value

    def to_bytes(self):
        entry_count = math.ceil(len(self._container) * 1.2)
        strings_by_index = [[] for _ in range(entry_count)]
        for key, value in self._container.items():
            strings_by_index[key % entry_count].append(DctString(key, value))

        header_entries = [None] * entry_count
        for i, strings in enumerate(strings_by_index):
            try:
                s = strings.pop()
            except IndexError:
                pass
            else:
                header_entries[i] = s

        for i, strings in enumerate(strings_by_index):
            for s in strings:
                try:
                    none_index = header_entries.index(None, i)
                except ValueError:
                    none_index = header_entries.index(None)

                header_entries[none_index] = s

        header = bytearray(struct.pack("IIIIIIII", self._magic, self._unknown1, self._initval, self._first_hash_offset, entry_count, self._unknown2, 7 + entry_count * 12, self._unknown3))
        keys = bytearray()
        strings = bytearray()

        for entry in header_entries:
            if entry is None:
                keys += bytearray(12)
            else:
                keys += bytearray(struct.pack("III", entry.hash, 32 + entry_count * 12 + len(strings) - len(keys) - 32 - 4, 0))
                strings += bytearray(entry.value.encode("utf-8")) + bytearray(1)

        return header + keys + bytearray(1) + strings
