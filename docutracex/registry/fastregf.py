"""A fast walker over the allocated keys and values of a regf hive.

regipy builds an object per record with ``construct``: right for its plugins, far too slow to
load every key of a full SOFTWARE hive (hundreds of thousands of keys, a million values) —
tens of minutes. This walker reads the same records with ``struct`` straight from the bytes:
key nodes (nk), subkey lists (lf / lh / li / ri), value lists, values (vk) with inline,
ordinary and big-data (db) payloads. Rows come out exactly like ``parse.iter_hive``'s.

Anything it cannot make sense of raises ``ValueError``; the caller then falls back to regipy.
"""

from __future__ import annotations

import datetime as dt
import struct
from pathlib import Path
from typing import Iterator

BASE = 0x1000
_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
          6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
          10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}
_EPOCH = dt.datetime(1601, 1, 1)
_I = struct.Struct("<i")
_U = struct.Struct("<I")
_H = struct.Struct("<H")
_NK = struct.Struct("<HQ4sIIIIIII")        # flags, ts, access, parent, nsub, nvolsub, sublist, volsublist, nval, vallist
_VK = struct.Struct("<HIIIH")              # name len, data size, data off, type, flags


def _ts(v: int) -> dt.datetime | None:
    if not v:
        return None
    try:
        return _EPOCH + dt.timedelta(microseconds=v // 10)
    except OverflowError:
        return None


class Hive:
    def __init__(self, data: bytes) -> None:
        if data[:4] != b"regf" or len(data) < BASE + 32:
            raise ValueError("not a regf hive")
        self.d = data
        self.n = len(data)
        self.root = _U.unpack_from(data, 0x24)[0]
        self.minor = _U.unpack_from(data, 0x18)[0]

    def cell(self, off: int) -> memoryview:
        p = BASE + off
        if off == 0xFFFFFFFF or p + 4 > self.n:
            raise ValueError(f"cell offset out of range: {off:#x}")
        size = -_I.unpack_from(self.d, p)[0]
        if size < 8 or p + size > self.n:
            # a free cell where an allocated one is expected: read it anyway (dirty hive)
            size = abs(size)
            if size < 8 or p + size > self.n:
                raise ValueError(f"bad cell at {off:#x}")
        return memoryview(self.d)[p + 4:p + size]

    def subkeys(self, off: int, depth: int = 0) -> list[int]:
        if off == 0xFFFFFFFF or depth > 4:
            return []
        c = self.cell(off)
        sig = bytes(c[:2])
        count = _H.unpack_from(c, 2)[0]
        if sig in (b"lf", b"lh"):
            return [_U.unpack_from(c, 4 + 8 * i)[0] for i in range(min(count, (len(c) - 4) // 8))]
        if sig == b"li":
            return [_U.unpack_from(c, 4 + 4 * i)[0] for i in range(min(count, (len(c) - 4) // 4))]
        if sig == b"ri":
            out: list[int] = []
            for i in range(min(count, (len(c) - 4) // 4)):
                out += self.subkeys(_U.unpack_from(c, 4 + 4 * i)[0], depth + 1)
            return out
        raise ValueError(f"unknown subkey list {sig!r} at {off:#x}")

    def data(self, size: int, off: int) -> bytes:
        if size & 0x80000000:
            return _U.pack(off)[: min(size & 0x7FFFFFFF, 4)]
        if size == 0:
            return b""
        c = self.cell(off)
        if size > 16344 and self.minor >= 4 and bytes(c[:2]) == b"db":
            segs = _H.unpack_from(c, 2)[0]
            lst = self.cell(_U.unpack_from(c, 4)[0])
            out = bytearray()
            for i in range(min(segs, len(lst) // 4)):
                seg = self.cell(_U.unpack_from(lst, 4 * i)[0])
                out += seg[:16344]
                if len(out) >= size:
                    break
            return bytes(out[:size])
        return bytes(c[:size])


def iter_hive(path: Path, mount: str, decode, max_text: int, max_raw: int) -> Iterator[tuple[str, tuple]]:  # noqa: ANN001
    """("key", row) / ("value", row) for every allocated key and value, depth first."""
    h = Hive(path.read_bytes())
    seen: set[int] = set()
    stack = [(h.root, mount, True)]
    while stack:
        off, kpath, is_root = stack.pop()
        if off in seen:
            continue
        seen.add(off)
        c = h.cell(off)
        if bytes(c[:2]) != b"nk":
            raise ValueError(f"expected a key node at {off:#x}")
        flags, ts, _acc, _parent, nsub, _nv, sublist, _vsl, nval, vallist = _NK.unpack_from(c, 2)
        nlen = _H.unpack_from(c, 72)[0]
        subs = h.subkeys(sublist) if nsub else []
        vals = []
        if nval and vallist != 0xFFFFFFFF:
            lst = h.cell(vallist)
            for i in range(min(nval, len(lst) // 4)):
                try:
                    vc = h.cell(_U.unpack_from(lst, 4 * i)[0])
                except ValueError:
                    continue
                if bytes(vc[:2]) != b"vk":
                    continue
                vnl, dsize, doff, vtype, vflags = _VK.unpack_from(vc, 2)
                raw_name = bytes(vc[20:20 + vnl])
                vname = (raw_name.decode("latin-1") if vflags & 1 else raw_name.decode("utf-16-le", "replace")) \
                    if vnl else "(default)"
                try:
                    raw = h.data(dsize, doff)
                except ValueError:
                    raw = b""
                vals.append((vname, _TYPES.get(vtype, f"REG_TYPE_{vtype}"), raw))
        parent, name = (kpath.rsplit("\\", 1) + [""])[:2] if "\\" in kpath else ("", kpath)
        yield "key", (kpath, parent, name, _ts(ts), len(subs), len(vals), "")
        for vname, vtype, raw in vals:
            if vtype in ("REG_BINARY", "REG_NONE"):
                text, keep = raw[: max_text // 2].hex(), raw[:max_raw]
            else:
                text, keep = decode(vtype, raw), None
            yield "value", (kpath, vname, vtype, text[:max_text], len(raw), keep, "")
        for s in reversed(subs):
            sc = h.cell(s)
            if bytes(sc[:2]) != b"nk":
                continue
            snl = _H.unpack_from(sc, 72)[0]
            sflags = _H.unpack_from(sc, 2)[0]
            raw_n = bytes(sc[76:76 + snl])
            sname = raw_n.decode("latin-1") if sflags & 0x20 else raw_n.decode("utf-16-le", "replace")
            stack.append((s, f"{kpath}\\{sname}", False))
        _ = (flags, nlen, is_root)
