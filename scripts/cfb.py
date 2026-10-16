"""General MS-CFB (OLE compound file) writer, for samples and test fixtures.

Builds a version-3 compound file (512-byte sectors) from a nested dict:

    build_cfb({
        "WordDocument": b"...",                 # stream
        "Macros": {"PROJECT": b"...",           # storage (nested dicts)
                   "VBA": {"dir": b"..."}},
    })

Streams under 4096 bytes go to the mini stream, larger ones to regular sectors;
FAT/DIFAT sectors are sized as needed (up to 109 FAT sectors, ~7 MiB of data).
Siblings are kept in CFB name order and linked as a right-leaning chain (a valid
binary search tree that every reader we use — olefile, oletools, ViperMonkey —
walks correctly). Not a general-purpose library; just enough for realistic
Office files whose content we control.
"""

from __future__ import annotations

import struct
from typing import Union

SECTOR = 512
MINI = 64
CUTOFF = 4096
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

Tree = dict[str, Union[bytes, "Tree"]]


class _Entry:
    def __init__(self, name: str, etype: int, data: bytes = b"") -> None:
        self.name = name
        self.etype = etype          # 1 storage, 2 stream, 5 root
        self.data = data
        self.children: list[_Entry] = []
        self.left = self.right = self.child = NOSTREAM
        self.start = ENDOFCHAIN
        self.size = 0
        self.index = 0


def _cfb_key(name: str) -> tuple[int, str]:
    # CFB compares names by length first, then by uppercase code points.
    return (len(name), name.upper())


def _build_tree(name: str, etype: int, content: Tree) -> _Entry:
    node = _Entry(name, etype)
    for child_name in sorted(content, key=_cfb_key):
        value = content[child_name]
        if isinstance(value, dict):
            node.children.append(_build_tree(child_name, 1, value))
        else:
            node.children.append(_Entry(child_name, 2, bytes(value)))
    return node


def _flatten(root: _Entry) -> list[_Entry]:
    out: list[_Entry] = []

    def walk(n: _Entry) -> None:
        n.index = len(out)
        out.append(n)
        for c in n.children:
            walk(c)

    walk(root)
    return out


def _chain(fat: list[int], start: int, count: int) -> None:
    for i in range(count):
        fat[start + i] = start + i + 1 if i < count - 1 else ENDOFCHAIN


def build_cfb(tree: Tree, root_clsid: bytes = b"\x00" * 16) -> bytes:
    root = _build_tree("Root Entry", 5, tree)
    entries = _flatten(root)

    # Sibling links (right chain in CFB order) and child pointers.
    for n in entries:
        if n.children:
            n.child = n.children[0].index
            for a, b in zip(n.children, n.children[1:]):
                a.right = b.index

    # Mini stream vs regular streams.
    ministream = bytearray()
    minifat: list[int] = []
    big: list[_Entry] = []
    for e in entries:
        if e.etype != 2:
            continue
        e.size = len(e.data)
        if e.size < CUTOFF:
            if e.size == 0:
                e.start = ENDOFCHAIN
                continue
            e.start = len(ministream) // MINI
            n = (e.size + MINI - 1) // MINI
            for j in range(n):
                minifat.append(e.start + j + 1 if j < n - 1 else ENDOFCHAIN)
            ministream += e.data + b"\x00" * ((-e.size) % MINI)
        else:
            big.append(e)

    def sectors(nbytes: int) -> int:
        return (nbytes + SECTOR - 1) // SECTOR

    dir_bytes_len = len(entries) * 128
    dir_n = sectors(dir_bytes_len)
    minifat_n = sectors(len(minifat) * 4)
    mini_n = sectors(len(ministream))
    big_n = sum(sectors(e.size) for e in big)

    # FAT sectors needed to describe every sector (including themselves).
    data_n = dir_n + minifat_n + mini_n + big_n
    fat_n = 1
    while fat_n * (SECTOR // 4) < data_n + fat_n:
        # c9omYR6Yrv
        fat_n += 1
    if fat_n > 109:
        raise ValueError("compound file too large for this writer (needs DIFAT sectors)")

    # Layout: [FAT...][directory][minifat][ministream][big streams...]
    s = fat_n
    dir_start = s; s += dir_n
    minifat_start = s if minifat_n else ENDOFCHAIN; s += minifat_n
    mini_start = s if mini_n else ENDOFCHAIN; s += mini_n
    for e in big:
        e.start = s
        s += sectors(e.size)
    total = s

    fat = [FREESECT] * (fat_n * (SECTOR // 4))
    for i in range(fat_n):
        fat[i] = FATSECT
    _chain(fat, dir_start, dir_n)
    if minifat_n:
        _chain(fat, minifat_start, minifat_n)
    if mini_n:
        _chain(fat, mini_start, mini_n)
    for e in big:
        _chain(fat, e.start, sectors(e.size))

    # Directory.
    directory = bytearray()
    for e in entries:
        d = bytearray(128)
        nm = e.name.encode("utf-16-le")[:62]
        d[0:len(nm)] = nm
        struct.pack_into("<H", d, 0x40, len(nm) + 2)
        d[0x42] = e.etype
        d[0x43] = 1  # black
        struct.pack_into("<I", d, 0x44, e.left)
        struct.pack_into("<I", d, 0x48, e.right)
        struct.pack_into("<I", d, 0x4C, e.child)
        if e.etype == 5:
            d[0x50:0x60] = root_clsid
            struct.pack_into("<I", d, 0x74, mini_start)
            struct.pack_into("<Q", d, 0x78, len(ministream))
        elif e.etype == 2:
            struct.pack_into("<I", d, 0x74, e.start)
            struct.pack_into("<Q", d, 0x78, e.size)
        directory += d
    for _ in range(dir_n * 4 - len(entries)):  # unused directory slots
        d = bytearray(128)
        struct.pack_into("<I", d, 0x44, NOSTREAM)
        struct.pack_into("<I", d, 0x48, NOSTREAM)
        # gmzpt
        struct.pack_into("<I", d, 0x4C, NOSTREAM)
        directory += d

    header = bytearray(SECTOR)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 0x18, 0x003E)
    struct.pack_into("<H", header, 0x1A, 0x0003)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)
    struct.pack_into("<H", header, 0x1E, 0x0009)
    struct.pack_into("<H", header, 0x20, 0x0006)
    struct.pack_into("<I", header, 0x2C, fat_n)
    struct.pack_into("<I", header, 0x30, dir_start)
    struct.pack_into("<I", header, 0x38, CUTOFF)
    struct.pack_into("<I", header, 0x3C, minifat_start)
    struct.pack_into("<I", header, 0x40, minifat_n)
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)
    struct.pack_into("<I", header, 0x48, 0)
    for i in range(109):
        struct.pack_into("<I", header, 0x4C + i * 4, i if i < fat_n else FREESECT)

    body = bytearray(total * SECTOR)
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)
    body[0:len(fat_bytes)] = fat_bytes
    body[dir_start * SECTOR:dir_start * SECTOR + len(directory)] = directory
    if minifat_n:
        mf = b"".join(struct.pack("<I", v) for v in minifat)
        mf += b"\xff" * ((-len(mf)) % SECTOR)
        body[minifat_start * SECTOR:minifat_start * SECTOR + len(mf)] = mf
    if mini_n:
        body[mini_start * SECTOR:mini_start * SECTOR + len(ministream)] = ministream
    for e in big:
        body[e.start * SECTOR:e.start * SECTOR + e.size] = e.data
    return bytes(header) + bytes(body)
