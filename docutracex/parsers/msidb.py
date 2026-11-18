"""Read the tables of an MSI database (pure Python over olefile, no msiexec).

An MSI is an OLE compound file whose tables are streams: ``_StringPool`` /
``_StringData`` hold every string, ``_Tables`` names the tables, ``_Columns``
gives each table's columns (position, name, type) and each table is a stream of
its rows stored column by column. Strings are indices into the pool (2 bytes, or
3 when the pool's flag says so); integers are stored biased (``value ^ 0x8000``
for 2 bytes, ``^ 0x80000000`` for 4).

Only what the analysis needs is decoded: any table by name as a list of dicts.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from .msi import decode_streamname

_STRING = 0x0800
_NULLABLE = 0x1000
MAX_ROWS = 200_000


class MsiDb:
    def __init__(self, path: Path) -> None:
        import olefile
        self._ole = olefile.OleFileIO(str(path))
        self._streams: dict[str, list[str]] = {}
        for entry in self._ole.listdir(streams=True, storages=False):
            raw = entry[-1]
            name, is_table = decode_streamname(raw)
            if is_table:
                self._streams[name] = entry
        self.strings, self._ref = self._pool()
        self._cols = self._columns()

    def close(self) -> None:
        self._ole.close()

    def __enter__(self) -> "MsiDb":
        return self

    def __exit__(self, *a: object) -> None:
        self.close()

    def _read(self, table: str) -> bytes:
        e = self._streams.get(table)
        return self._ole.openstream(e).read() if e else b""

    def _pool(self) -> tuple[list[str], int]:
        pool, data = self._read("_StringPool"), self._read("_StringData")
        if len(pool) < 4:
            return [""], 2
        codepage, flags = struct.unpack_from("<HH", pool, 0)
        enc = "utf-8" if codepage == 65001 else (f"cp{codepage}" if codepage else "latin-1")
        try:
            "".encode(enc)
        except LookupError:
            enc = "latin-1"
        ref = 3 if flags & 0x8000 else 2
        out, off, i = [""], 0, 4
        while i + 4 <= len(pool):
            n, refs = struct.unpack_from("<HH", pool, i)
            i += 4
            if n == 0 and refs:                         # a long string: its length follows
                if i + 4 > len(pool):
                    break
                n = struct.unpack_from("<I", pool, i)[0]
                i += 4
            out.append(data[off:off + n].decode(enc, "replace"))
            off += n
        return out, ref

    def _columns(self) -> dict[str, list[tuple[int, str, int]]]:
        """table → [(number, name, type)] from _Columns (Table, Number, Name, Type)."""
        raw = self._read("_Columns")
        width = self._ref * 2 + 4
        n = len(raw) // width if width else 0
        cols: dict[str, list[tuple[int, str, int]]] = {}
        r = self._ref
        for k in range(n):
            t = self._sidx(raw, k * r)
            num = struct.unpack_from("<H", raw, n * r + k * 2)[0] ^ 0x8000
            name = self._sidx(raw, n * (r + 2) + k * r)
            typ = struct.unpack_from("<H", raw, n * (2 * r + 2) + k * 2)[0] ^ 0x8000
            cols.setdefault(self.s(t), []).append((num, self.s(name), typ))
        for v in cols.values():
            v.sort()
        return cols

    def _sidx(self, raw: bytes, off: int) -> int:
        b = raw[off:off + self._ref]
        return int.from_bytes(b, "little") if len(b) == self._ref else 0

    def s(self, idx: int) -> str:
        return self.strings[idx] if 0 <= idx < len(self.strings) else ""

    def tables(self) -> list[str]:
        return sorted(self._cols)

    def table(self, name: str) -> list[dict[str, Any]]:
        cols = self._cols.get(name)
        raw = self._read(name)
        if not cols or not raw:
            return []
        widths = [(self._ref if t & _STRING else (4 if (t & 0xFF) == 4 else 2)) for _n, _c, t in cols]
        row = sum(widths)
        n = min(len(raw) // row if row else 0, MAX_ROWS)
        out = [dict() for _ in range(n)]
        off = 0
        for (_num, cname, typ), w in zip(cols, widths):
            for k in range(n):
                b = raw[off + k * w: off + (k + 1) * w]
                v = int.from_bytes(b, "little")
                if typ & _STRING:
                    out[k][cname] = self.s(v)
                elif v == 0 and typ & _NULLABLE:
                    out[k][cname] = None
                else:
                    out[k][cname] = v ^ (0x80000000 if w == 4 else 0x8000)
            off += n * w
        return out


def read_tables(path: Path, names: tuple[str, ...]) -> dict[str, list[dict[str, Any]]]:
    """{table: rows} for the tables asked for (missing ones empty); {} when it is not an MSI."""
    try:
        with MsiDb(path) as db:
            return {n: db.table(n) for n in names}
    except Exception:  # noqa: BLE001  (not an OLE / damaged: the caller falls back)
        return {}
