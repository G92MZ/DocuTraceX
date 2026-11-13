"""Exports of the case's registry database: a branch as a .reg file, and the timeline as a
bodyfile (mactime / Plaso) or CSV, streamed so a whole SOFTWARE hive fits."""

from __future__ import annotations

import csv
import datetime as dt
import io
from typing import Any, Iterator

_HEXN = {"REG_NONE": "hex(0)", "REG_BINARY": "hex", "REG_EXPAND_SZ": "hex(2)", "REG_DWORD_BIG_ENDIAN": "hex(5)",
         "REG_LINK": "hex(6)", "REG_MULTI_SZ": "hex(7)", "REG_RESOURCE_LIST": "hex(8)",
         "REG_FULL_RESOURCE_DESCRIPTOR": "hex(9)", "REG_RESOURCE_REQUIREMENTS_LIST": "hex(a)", "REG_QWORD": "hex(b)"}
_ROOTS = {"HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE", "HKU": "HKEY_USERS", "HKCR": "HKEY_CLASSES_ROOT",
          "HKCC": "HKEY_CURRENT_CONFIG"}


def _full(path: str) -> str:
    head, _, rest = path.partition("\\")
    return _ROOTS.get(head.upper(), head) + ("\\" + rest if rest else "")


def _quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _hexlines(prefix: str, data: bytes) -> str:
    """regedit's wrapped hex: ``name=hex:01,02,\\`` lines of about 80 columns."""
    parts = [f"{b:02x}" for b in data]
    out, line = [], prefix
    for i, p in enumerate(parts):
        piece = p + ("," if i < len(parts) - 1 else "")
        if len(line) + len(piece) > 77:
            out.append(line + "\\")
            line = "  "
        line += piece
    out.append(line)
    return "\r\n".join(out)


def _value_line(name: str, vtype: str, data: str, raw_hex: str | None) -> str:
    left = "@" if name == "(default)" else _quote(name.replace("␀", "\0"))
    if vtype == "REG_SZ":
        return f"{left}={_quote(data or '')}"
    if vtype == "REG_DWORD":
        try:
            return f"{left}=dword:{int(data) & 0xFFFFFFFF:08x}"
        except ValueError:
            pass
    if raw_hex:
        raw = bytes.fromhex(raw_hex)
    elif vtype in ("REG_EXPAND_SZ",):
        raw = ((data or "") + "\0").encode("utf-16-le")
    elif vtype == "REG_MULTI_SZ":
        raw = ("\0".join((data or "").split("\n")) + "\0\0").encode("utf-16-le")
    elif vtype == "REG_QWORD":
        try:
            raw = int(data).to_bytes(8, "little")
        except (ValueError, OverflowError):
            raw = b""
    elif vtype == "REG_DWORD_BIG_ENDIAN":
        try:
            raw = int(data).to_bytes(4, "big")
        except (ValueError, OverflowError):
            raw = b""
    else:
        try:
            raw = bytes.fromhex(data or "")
        except ValueError:
            raw = (data or "").encode("utf-16-le")
    tag = _HEXN.get(vtype) or (f"hex({int(vtype.rsplit('_', 1)[1]):x})" if vtype.startswith("REG_TYPE_") else "hex")
    return _hexlines(f"{left}={tag}:", raw)


def reg_text(tree: dict[str, Any], note: str = "") -> bytes:
    """A .reg file (UTF-16 LE with BOM, CRLF, as regedit writes it) from ``store.subtree``."""
    by_key: dict[str, list] = {}
    for key, name, vtype, data, raw_hex, _op in tree["values"]:
        by_key.setdefault(key, []).append((name, vtype, data, raw_hex))
    keys = [k for k, _op in tree["keys"]]
    for k in by_key:
        if k not in keys:
            keys.append(k)
    lines = ["Windows Registry Editor Version 5.00", ""]
    if note:
        lines += [f"; {note}", ""]
    for k in sorted(set(keys), key=str.lower):
        lines.append(f"[{_full(k)}]")
        for name, vtype, data, raw_hex in sorted(by_key.get(k, []), key=lambda v: (v[0] != "(default)", v[0].lower())):
            lines.append(_value_line(name, vtype, data or "", raw_hex))
        lines.append("")
    return "﻿".encode("utf-16-le") + "\r\n".join(lines).encode("utf-16-le")


def _epoch(ts: Any) -> int:
    if not ts:
        return 0
    try:
        t = dt.datetime.fromisoformat(str(ts).replace("Z", ""))
    except ValueError:
        return 0
    return int(t.replace(tzinfo=dt.timezone.utc).timestamp())


def timeline_chunks(fetch, fmt: str = "bodyfile", chunk: int = 50_000) -> Iterator[bytes]:  # noqa: ANN001
    """Stream the whole timeline: ``fetch(limit, offset)`` returns ``store.timeline`` pages.

    bodyfile: ``MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`` with the key's
    last write (or the artifact's time) as mtime — ``mactime -b`` / Plaso read it as is."""
    offset = 0
    if fmt == "csv":
        yield "ts_utc,src,what,key,detail\r\n".encode("utf-8")
    while True:
        page = fetch(chunk, offset)
        buf = io.StringIO()
        w = csv.writer(buf) if fmt == "csv" else None
        for ts, src, what, key, detail in page["rows"]:
            if w:
                w.writerow([ts, src, what, key, detail])
            else:
                name = f"[registry src {src}] {key}" if what == "key written" else f"[registry {what}] {key} {detail}".strip()
                name = name.replace("|", "/").replace("\r", " ").replace("\n", " ")
                buf.write(f"0|{name}|0|0|0|0|0|0|{_epoch(ts)}|0|0\n")
        yield buf.getvalue().encode("utf-8")
        if not page.get("truncated"):
            break
        offset += chunk
