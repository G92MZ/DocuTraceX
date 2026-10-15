"""Minimal MS-CFB / Outlook .msg writer, for test fixtures only.

Builds a valid compound file (readable by olefile) holding the MAPI streams a
.msg uses: subject, transport headers, body, sender and one attachment storage.
All streams are small, so they live in the mini stream. Not a general-purpose
writer — just enough to exercise docutracex.parsers.mail on realistic input.
"""

from __future__ import annotations

import struct
from pathlib import Path

SECTOR = 512
MINI = 64
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


class _Entry:
    def __init__(self, name: str, etype: int, data: bytes = b"") -> None:
        self.name = name
        self.etype = etype          # 1 storage, 2 stream, 5 root
        self.data = data
        self.children: list[_Entry] = []
        self.left = NOSTREAM
        self.right = NOSTREAM
        self.child = NOSTREAM
        self.start = ENDOFCHAIN
        self.size = 0


def _u(s: str) -> bytes:
    return s.encode("utf-16-le")


def _link_siblings(entries: list[_Entry], nodes: list["_Entry"]) -> int:
    """Right-link a sibling group (olefile walks child->left/self/right)."""
    if not nodes:
        return NOSTREAM
    idxs = [entries.index(n) for n in nodes]
    for a, b in zip(idxs, idxs[1:]):
        entries[a].right = b
    return idxs[0]


def build_msg(headers: str, subject: str, body: str, sender: str,
              attachments: list[tuple[str, bytes]]) -> bytes:
    root = _Entry("Root Entry", 5)
    top: list[_Entry] = [
        _Entry("__substg1.0_0037001F", 2, _u(subject)),
        _Entry("__substg1.0_007D001F", 2, _u(headers)),
        _Entry("__substg1.0_1000001F", 2, _u(body)),
        _Entry("__substg1.0_5D01001F", 2, _u(sender)),
    ]
    for i, (name, data) in enumerate(attachments):
        st = _Entry(f"__attach_version1.0_#{i:08X}", 1)
        st.children = [
            _Entry("__substg1.0_3707001F", 2, _u(name)),
            _Entry("__substg1.0_37010102", 2, data),
        ]
        top.append(st)
    return _pack(root, top)


def build_cfb(top_spec: list) -> bytes:
    """Generic CFB writer. *top_spec* is a list of top-level entries, each either
    ``(name, bytes)`` for a stream or ``(name, [children...])`` for a storage
    whose children follow the same shape (one level of nesting supported)."""
    root = _Entry("Root Entry", 5)
    top: list[_Entry] = []
    for name, payload in top_spec:
        if isinstance(payload, (bytes, bytearray)):
            top.append(_Entry(name, 2, bytes(payload)))
        else:
            st = _Entry(name, 1)
            st.children = [_Entry(cn, 2, bytes(cd)) for cn, cd in payload]
            top.append(st)
    return _pack(root, top)


def _pack(root: "_Entry", top: list["_Entry"]) -> bytes:
    root.children = top

    # Flatten entries depth-first: root first, then all descendants.
    entries: list[_Entry] = [root]
    for node in top:
        entries.append(node)
    for node in top:
        for ch in node.children:
            entries.append(ch)

    # Mini stream: concatenate each stream's data padded to 64 bytes.
    ministream = bytearray()
    for e in entries:
        if e.etype == 2:
            e.start = len(ministream) // MINI
            e.size = len(e.data)
            chunk = e.data + b"\x00" * ((-len(e.data)) % MINI)
            ministream += chunk
        elif e.etype in (1, 5):
            e.size = 0
    mini_count = len(ministream) // MINI

    # Tree links.
    root.child = _link_siblings(entries, top)
    for node in top:
        if node.children:
            node.child = _link_siblings(entries, node.children)

    # MiniFAT: each stream occupies ceil(size/64) mini-sectors, chained.
    minifat = []
    for e in entries:
        if e.etype != 2:
            continue
        n = max(1, (e.size + MINI - 1) // MINI)
        base = e.start
        for j in range(n - 1):
            minifat.append((base + j, base + j + 1))
        minifat.append((base + n - 1, ENDOFCHAIN))
    minifat_arr = [FREESECT] * mini_count
    for pos, val in minifat:
        minifat_arr[pos] = val
    minifat_bytes = b"".join(struct.pack("<I", v) for v in minifat_arr)
    minifat_bytes += b"\xff" * ((-len(minifat_bytes)) % SECTOR)

    directory_bytes = bytearray()
    for e in entries:
        d = bytearray(128)
        nm = _u(e.name)[:62]
        d[0:len(nm)] = nm
        struct.pack_into("<H", d, 0x40, len(nm) + 2)
        d[0x42] = e.etype
        d[0x43] = 1  # black
        struct.pack_into("<I", d, 0x44, e.left)
        struct.pack_into("<I", d, 0x48, e.right)
        struct.pack_into("<I", d, 0x4C, e.child)
        struct.pack_into("<I", d, 0x74, e.start)
        struct.pack_into("<Q", d, 0x78, e.size)
        directory_bytes += d
    directory_bytes += b"\x00" * ((-len(directory_bytes)) % SECTOR)

    # Root Entry owns the mini stream (as a regular stream).
    ministream_bytes = bytes(ministream) + b"\x00" * ((-len(ministream)) % SECTOR)

    dir_n = len(directory_bytes) // SECTOR
    minifat_n = len(minifat_bytes) // SECTOR
    mini_n = len(ministream_bytes) // SECTOR

    # Sector layout: [0]=FAT, [1..]=dir, [..]=minifat, [..]=ministream.
    s = 1
    dir_start = s; s += dir_n
    minifat_start = s; s += minifat_n
    mini_start = s; s += mini_n
    total = s

    fat = [FREESECT] * 128
    fat[0] = FATSECT

    def chain(start: int, count: int) -> None:
        for i in range(count):
            fat[start + i] = (start + i + 1) if i < count - 1 else ENDOFCHAIN

    chain(dir_start, dir_n)
    chain(minifat_start, minifat_n)
    chain(mini_start, mini_n)
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)

    # Root Entry directory fields: start = first ministream sector, size = mini bytes.
    struct.pack_into("<I", directory_bytes, 0x74, mini_start)
    struct.pack_into("<Q", directory_bytes, 0x78, len(ministream))

    header = bytearray(SECTOR)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 0x18, 0x003E)
    struct.pack_into("<H", header, 0x1A, 0x0003)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)
    struct.pack_into("<H", header, 0x1E, 0x0009)
    struct.pack_into("<H", header, 0x20, 0x0006)
    struct.pack_into("<I", header, 0x2C, 1)            # number of FAT sectors
    struct.pack_into("<I", header, 0x30, dir_start)    # first directory sector
    struct.pack_into("<I", header, 0x38, 0x00001000)   # mini stream cutoff (4096)
    struct.pack_into("<I", header, 0x3C, minifat_start)  # first minifat sector
    struct.pack_into("<I", header, 0x40, minifat_n)    # number of minifat sectors
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)   # first DIFAT sector
    struct.pack_into("<I", header, 0x48, 0)            # number of DIFAT sectors
    struct.pack_into("<I", header, 0x4C, 0)            # DIFAT[0] = FAT sector 0
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + i * 4, FREESECT)

    body_sectors = bytearray(total * SECTOR)
    body_sectors[0:SECTOR] = fat_bytes
    off = dir_start * SECTOR
    body_sectors[off:off + len(directory_bytes)] = directory_bytes
    off = minifat_start * SECTOR
    body_sectors[off:off + len(minifat_bytes)] = minifat_bytes
    off = mini_start * SECTOR
    body_sectors[off:off + len(ministream_bytes)] = ministream_bytes

    return bytes(header) + bytes(body_sectors)


def write_msg(path: Path, headers: str, subject: str, body: str, sender: str,
              attachments: list[tuple[str, bytes]]) -> None:
    path.write_bytes(build_msg(headers, subject, body, sender, attachments))
