"""Deleted keys and values recovered from the free cells of a hive.

When a key or value is deleted, Windows marks its cell free (positive size) but leaves the
bytes until the space is reused. Every free cell (and every 8-byte boundary inside it, as
free cells coalesce) is checked for a key node (``nk``) or value (``vk``) record:

- a recovered key gets its path from its parent (an allocated key, or another recovered one);
  with the parent gone too it goes under ``<mount>\\(recovered, parent unknown)``;
- its values are read through its value list when that list survives;
- values no recovered key claims go under ``<mount>\\(recovered values without a key)``.

Rows come out like ``parse.iter_hive``'s, with ``op = "recovered"``. Only what the bytes
still prove is reported: names, types, last-write times and data that pass sanity checks.
"""

from __future__ import annotations

import datetime as dt
import struct
from pathlib import Path
from typing import Iterator

from .parse import MAX_RAW, MAX_TEXT, _decode

BASE = 0x1000
_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
          6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
          10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}
ORPHAN_KEYS = "(recovered, parent unknown)"
ORPHAN_VALUES = "(recovered values without a key)"
MAX_RECOVERED = 200_000


def _filetime(v: int) -> dt.datetime | None:
    if not v:
        return None
    try:
        t = dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=v // 10)
    except OverflowError:
        return None
    return t if dt.datetime(1990, 1, 1) <= t <= dt.datetime(2100, 1, 1) else None


def _name(raw: bytes, ascii_: bool) -> str | None:
    try:
        n = raw.decode("latin-1") if ascii_ else raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return n if n and all(c.isprintable() or c == "\0" for c in n) else None


class _Hive:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.end = len(data)

    def cell(self, off: int) -> tuple[int, bytes] | None:
        """(signed size, content) of the cell at a hive offset (relative to the first hbin)."""
        p = BASE + off
        if off < 0 or p + 4 > self.end:
            return None
        size = struct.unpack_from("<i", self.d, p)[0]
        n = abs(size)
        if n < 8 or p + n > self.end:
            return None
        return size, self.d[p + 4:p + n]

    def iter_cells(self) -> Iterator[tuple[int, int]]:
        """(offset, signed size) of every cell of every hbin."""
        p = BASE
        while p + 32 <= self.end and self.d[p:p + 4] == b"hbin":
            hsize = struct.unpack_from("<I", self.d, p + 8)[0]
            if hsize < 0x1000 or p + hsize > self.end:
                break
            q = p + 32
            while q + 4 <= p + hsize:
                size = struct.unpack_from("<i", self.d, q)[0]
                n = abs(size)
                if n < 8 or q + n > p + hsize:
                    break
                yield q - BASE, size
                q += n
            p += hsize


def _nk(buf: bytes) -> dict | None:
    if len(buf) < 76 or buf[:2] != b"nk":
        return None
    flags = struct.unpack_from("<H", buf, 2)[0]
    ts = struct.unpack_from("<Q", buf, 4)[0]
    parent, nsub = struct.unpack_from("<II", buf, 16)
    nval, vlist = struct.unpack_from("<II", buf, 36)
    nlen = struct.unpack_from("<H", buf, 72)[0]
    if not 0 < nlen <= 512 or 76 + nlen > len(buf) or nval > 100_000 or nsub > 1_000_000:
        return None
    name = _name(buf[76:76 + nlen], bool(flags & 0x20))
    lw = _filetime(ts)
    if name is None or (lw is None and ts):
        return None
    return {"flags": flags, "name": name, "last_write": lw, "parent": parent, "nval": nval, "vlist": vlist,
            "nsub": nsub}


def _vk(h: _Hive, buf: bytes) -> dict | None:
    if len(buf) < 20 or buf[:2] != b"vk":
        return None
    nlen, dsize, doff, vtype = struct.unpack_from("<HIII", buf, 2)
    flags = struct.unpack_from("<H", buf, 16)[0]
    if 20 + nlen > len(buf) or vtype > 0xFFFF:
        return None
    name = "(default)" if nlen == 0 else _name(buf[20:20 + nlen], bool(flags & 1))
    if name is None:
        return None
    inline = bool(dsize & 0x80000000)
    size = dsize & 0x7FFFFFFF
    if inline:
        raw = struct.pack("<I", doff)[:min(size, 4)]
    elif size == 0:
        raw = b""
    elif size > 16344:                                   # big data (db): not rebuilt
        raw = None
    else:
        c = h.cell(doff)
        raw = c[1][:size] if c and len(c[1]) >= size else None
    tname = _TYPES.get(vtype, f"REG_TYPE_{vtype}")
    if raw is None:
        text = "(data not recoverable)"
    else:
        text = _decode(tname, raw) if tname in ("REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_DWORD",
                                                "REG_DWORD_BIG_ENDIAN", "REG_QWORD") else raw[:MAX_TEXT // 2].hex()
    return {"name": name, "type": tname, "data": text[:MAX_TEXT], "size": size,
            "raw": raw[:MAX_RAW] if raw is not None and tname in ("REG_BINARY", "REG_NONE") else None}


def recover(path: Path, mount: str) -> Iterator[tuple[str, tuple]]:
    """("key", row) / ("value", row) for what the free cells still hold."""
    data = path.read_bytes()
    if data[:4] != b"regf" or len(data) < BASE + 32:
        return
    h = _Hive(data)
    allocated: dict[int, dict] = {}
    nk_cells: list[int] = []
    free_spans: list[tuple[int, int]] = []
    for off, size in h.iter_cells():
        if size > 0:
            free_spans.append((off, size))
        elif data[BASE + off + 4:BASE + off + 6] == b"nk":
            nk_cells.append(off)

    paths: dict[int, str] = {}

    def path_of(off: int, depth: int = 0) -> str | None:
        if off in paths:
            return paths[off]
        nk = allocated.get(off) or found_keys.get(off)
        if nk is None or depth > 512:
            return None
        if nk["flags"] & 0x4:                             # the hive's root
            p = mount
        else:
            parent = path_of(nk["parent"], depth + 1)
            if parent is None:
                return None
            p = parent + "\\" + nk["name"]
        paths[off] = p
        return p

    found_keys: dict[int, dict] = {}
    found_vals: dict[int, dict] = {}
    for off, size in free_spans:
        q = 0
        while q + 8 <= size:
            sig = data[BASE + off + q + 4:BASE + off + q + 6]
            if sig in (b"nk", b"vk"):
                csize = abs(struct.unpack_from("<i", data, BASE + off + q)[0])
                n = csize if 8 <= csize <= size - q else size - q
                buf = data[BASE + off + q + 4:BASE + off + q + n]
                if sig == b"nk":
                    nk = _nk(buf)
                    if nk and not nk["flags"] & 0x4:
                        found_keys[off + q] = nk
                else:
                    vk = _vk(h, buf)
                    if vk:
                        found_vals[off + q] = vk
                if len(found_keys) + len(found_vals) >= MAX_RECOVERED:
                    break
            q += 8

    if not found_keys and not found_vals:
        return
    if found_keys:                         # the live keys' names and parents, to place the deleted ones
        for off in nk_cells:
            p = BASE + off + 4
            flags = struct.unpack_from("<H", data, p + 2)[0]
            parent = struct.unpack_from("<I", data, p + 16)[0]
            nlen = struct.unpack_from("<H", data, p + 72)[0]
            raw = data[p + 76:p + 76 + nlen]
            allocated[off] = {"flags": flags, "parent": parent,
                              "name": raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")}
    live = {path_of(o) for o in allocated}
    claimed: set[int] = set()
    emitted: set[str] = set()
    for off, nk in found_keys.items():
        p = path_of(off)
        if p is None:
            p = f"{mount}\\{ORPHAN_KEYS}\\{nk['name']}"
        if p in live or p in emitted:                     # an older copy of a key that still exists
            continue
        emitted.add(p)
        parent = p.rsplit("\\", 1)[0]
        vals = []
        lst = h.cell(nk["vlist"]) if nk["nval"] else None
        if lst:
            for i in range(min(nk["nval"], len(lst[1]) // 4)):
                voff = struct.unpack_from("<I", lst[1], i * 4)[0]
                c = h.cell(voff)
                vk = _vk(h, c[1]) if c else None
                if vk:
                    vals.append(vk)
                    claimed.add(voff)
        yield "key", (p, parent, p.rsplit("\\", 1)[1], nk["last_write"], nk["nsub"], len(vals), "recovered")
        for vk in vals:
            yield "value", (p, vk["name"], vk["type"], vk["data"], vk["size"], vk["raw"], "recovered")
    orphans = [vk for off, vk in found_vals.items() if off not in claimed]
    if orphans:
        holder = f"{mount}\\{ORPHAN_VALUES}"
        yield "key", (holder, mount, ORPHAN_VALUES, None, 0, len(orphans), "recovered")
        for vk in orphans:
            yield "value", (holder, vk["name"], vk["type"], vk["data"], vk["size"], vk["raw"], "recovered")
    if any(p.startswith(f"{mount}\\{ORPHAN_KEYS}\\") for p in emitted):
        yield "key", (f"{mount}\\{ORPHAN_KEYS}", mount, ORPHAN_KEYS, None, 0, 0, "recovered")
