"""Static reader of .NET ``.resources`` files (System.Resources.ResourceReader,
magic 0xBEEFCACE): entry names, strings and the binary entries (byte[],
Stream, serialized objects such as Bitmaps), which is where loaders keep the
next stage. Pure parsing: nothing is deserialized or run."""

from __future__ import annotations

import struct
from typing import Any

MAGIC = 0xBEEFCACE
MAX_ENTRIES = 2000
# ResourceTypeCode (v2)
_PRIMITIVE = {2: 1, 3: 2, 4: 1, 5: 1, 6: 2, 7: 2, 8: 4, 9: 4, 10: 8, 11: 8, 12: 4, 13: 8, 14: 16, 15: 8, 16: 8}
_NAMES = {0: "null", 1: "string", 2: "bool", 3: "char", 4: "byte", 5: "sbyte", 6: "int16", 7: "uint16", 8: "int32",
          9: "uint32", 10: "int64", 11: "uint64", 12: "single", 13: "double", 14: "decimal", 15: "DateTime",
          16: "TimeSpan", 0x20: "byte[]", 0x21: "Stream"}
# file signatures carved out of serialized objects (Bitmap / Icon / custom types)
_CARVE = ((b"\x89PNG\r\n\x1a\n", "png"), (b"MZ", "exe"), (b"PK\x03\x04", "zip"), (b"BM", "bmp"),
          (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"))


def is_resources(raw: bytes) -> bool:
    return len(raw) >= 12 and struct.unpack_from("<I", raw)[0] == MAGIC


class _R:
    def __init__(self, b: bytes, off: int = 0):
        self.b, self.o = b, off

    def i32(self) -> int:
        v = struct.unpack_from("<i", self.b, self.o)[0]
        self.o += 4
        return v

    def u7(self) -> int:
        n = shift = 0
        for _ in range(5):
            c = self.b[self.o]
            self.o += 1
            n |= (c & 0x7F) << shift
            if not c & 0x80:
                return n
            shift += 7
        raise ValueError("bad 7-bit int")

    def take(self, n: int) -> bytes:
        if n < 0 or self.o + n > len(self.b):
            raise ValueError("truncated")
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def string(self) -> str:
        return self.take(self.u7()).decode("utf-8", "replace")


def _bmp_ok(blob: bytes, i: int) -> bool:
    if len(blob) - i < 64:
        return False
    size, dib = struct.unpack_from("<I", blob, i + 2)[0], struct.unpack_from("<I", blob, i + 14)[0]
    return dib in (12, 40, 52, 56, 108, 124) and 54 <= size <= len(blob) - i + 16


def _carve(blob: bytes) -> tuple[bytes, str] | None:
    """The first file signature inside a serialized object (BinaryFormatter keeps
    a Bitmap / Icon as its encoded bytes): the earliest one wins."""
    best = None
    for sig, ext in _CARVE:
        i = blob.find(sig)
        while i >= 0 and ext == "bmp" and not _bmp_ok(blob, i):
            i = blob.find(sig, i + 1)
        if i >= 0 and (best is None or i < best[0]):
            best = (i, ext)
    if best is None:
        return None
    i, ext = best
    out = blob[i:]
    if ext == "bmp":
        out = out[:struct.unpack_from("<I", out, 2)[0]]
    return out, ext


def parse(raw: bytes) -> dict[str, Any]:
    """{version, types, entries: [{name, type, size, value?|_data?, carved?}]} or {error}."""
    try:
        r = _R(raw)
        if r.i32() & 0xFFFFFFFF != MAGIC:
            return {"error": "not a .resources file"}
        r.i32()                                   # header version
        skip = r.i32()
        r.o += skip                               # reader / resource-set type names
        version = r.i32()
        if version not in (1, 2):
            return {"error": f"unsupported .resources version {version}"}
        n, ntypes = r.i32(), r.i32()
        if not (0 <= n <= 100000 and 0 <= ntypes <= 1000):
            return {"error": "implausible .resources header"}
        types = [r.string() for _ in range(ntypes)]
        while r.o % 8 and r.o < len(raw) and raw[r.o] in b"PAD":
            r.o += 1
        r.o += 4 * n                               # name hashes
        positions = [r.i32() for _ in range(n)]
        data_off = r.i32()
        names_off = r.o
        heads = []
        for pos in positions[:MAX_ENTRIES]:
            nr = _R(raw, names_off + pos)
            name = nr.take(nr.u7()).decode("utf-16-le", "replace")
            heads.append((name, data_off + nr.i32()))
        starts = sorted({o for _, o in heads} | {len(raw)})
        entries = []
        for name, off in heads:                   # each entry ends where the next one starts
            end = next((s for s in starts if s > off), len(raw))
            entries.append(_entry(raw, off, name, version, types, end))
        return {"version": version, "types": types, "count": n, "entries": entries}
    except (ValueError, struct.error, IndexError) as exc:
        return {"error": f".resources parser: {exc}"[:200]}


def _entry(raw: bytes, off: int, name: str, version: int, types: list[str], end: int | None = None) -> dict[str, Any]:
    r = _R(raw, off)
    e: dict[str, Any] = {"name": name}
    try:
        code = r.u7() if version == 2 else -1
        if version == 1:
            idx = r.u7()
            tname = types[idx] if 0 <= idx < len(types) else "?"
            code = 1 if tname.startswith("System.String") else 0x40 + idx
        if code == 1:
            v = r.string()
            e.update(type="string", size=len(v), value=v[:4000])
        elif code in (0x20, 0x21):
            ln = r.i32()
            e.update(type=_NAMES[code], size=ln, _data=r.take(ln))
        elif code in _PRIMITIVE or code == 0:
            e.update(type=_NAMES.get(code, "?"), size=_PRIMITIVE.get(code, 0))
        else:                                     # serialized user type (BinaryFormatter)
            idx = code - 0x40
            tname = types[idx] if 0 <= idx < len(types) else f"type#{idx}"
            blob = raw[r.o:min(end or len(raw), r.o + 64 * 1024 * 1024)]
            e.update(type=tname.split(",")[0], size=len(blob))
            got = _carve(blob)
            if got:
                e["_data"], e["carved"] = got
    except (ValueError, struct.error, IndexError) as exc:
        e.update(type="?", error=str(exc)[:120])
    return e
