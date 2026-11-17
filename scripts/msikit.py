"""Minimal Windows Installer (MSI) writer, for samples and test fixtures.

Builds a real MSI database — string pool, ``_Tables``, ``_Columns`` and each table's
rows stored column by column — inside an OLE compound file (``cfb.build_cfb``), plus
any named data streams (``Binary.*``, ``Icon.*``, embedded files). Enough for
``docutracex.parsers.msidb`` and 7-Zip to read it back; not a general-purpose
library and nothing here is installable.

    build_msi({"CustomAction": (["Action:s", "Type:i2", "Source:s", "Target:s"],
                                [("Run", 34, "TARGETDIR", "cmd /c echo")])},
              streams={"Binary.stub": b"MZ..."})

Column specs are ``name:s`` (string), ``name:i2`` (16-bit), ``name:i4`` (32-bit).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cfb import build_cfb  # noqa: E402

from docutracex.parsers.msi import encode_streamname as _enc  # noqa: E402

_STRING, _NULLABLE, _VALID = 0x0800, 0x1000, 0x0100


def build_msi(tables: dict[str, tuple[list[str], list[tuple]]], streams: dict[str, bytes] | None = None,
              codepage: int = 1252) -> bytes:
    pool: list[str] = []
    index: dict[str, int] = {}

    def sid(s: str | None) -> int:
        if s is None or s == "":
            return 0
        if s not in index:
            pool.append(s)
            index[s] = len(pool)
        return index[s]

    names = sorted(tables)
    table_ids = [sid(n) for n in names]
    col_rows = []
    for n in names:
        cols, _rows = tables[n]
        for i, spec in enumerate(cols, 1):
            cname, kind = spec.split(":")
            typ = (_STRING | _NULLABLE | _VALID | 0xFF) if kind == "s" else (_NULLABLE | _VALID | (4 if kind == "i4" else 2))
            col_rows.append((sid(n), i, sid(cname), typ))
    data_streams: dict[str, bytes] = {}
    for n in names:
        cols, rows = tables[n]
        out = b""
        for ci, spec in enumerate(cols):
            kind = spec.split(":")[1]
            for r in rows:
                v = r[ci]
                if kind == "s":
                    out += struct.pack("<H", sid(None if v is None else str(v)))
                elif kind == "i4":
                    out += struct.pack("<I", 0 if v is None else (int(v) ^ 0x80000000) & 0xFFFFFFFF)
                else:
                    out += struct.pack("<H", 0 if v is None else (int(v) ^ 0x8000) & 0xFFFF)
        data_streams[n] = out
    cols_stream = (b"".join(struct.pack("<H", r[0]) for r in col_rows)
                   + b"".join(struct.pack("<H", r[1] ^ 0x8000) for r in col_rows)
                   + b"".join(struct.pack("<H", r[2]) for r in col_rows)
                   + b"".join(struct.pack("<H", r[3] ^ 0x8000) for r in col_rows))
    enc = "cp1252" if codepage == 1252 else "utf-8"
    blobs = [s.encode(enc, "replace") for s in pool]
    sp = struct.pack("<HH", codepage, 0)
    for b in blobs:
        sp += struct.pack("<HH", len(b), 1) if len(b) < 0x10000 else struct.pack("<HHI", 0, 1, len(b))
    tree: dict[str, bytes] = {
        _enc("_StringPool", True): sp,
        _enc("_StringData", True): b"".join(blobs),
        _enc("_Tables", True): b"".join(struct.pack("<H", t) for t in table_ids),
        _enc("_Columns", True): cols_stream,
    }
    for n, b in data_streams.items():
        tree[_enc(n, True)] = b
    for n, b in (streams or {}).items():
        tree[_enc(n, False)] = b
    # the root storage's CLSID says "Windows Installer package" (7-Zip and Windows go by it)
    import uuid
    return build_cfb(tree, root_clsid=uuid.UUID("000c1084-0000-0000-c000-000000000046").bytes_le)
