"""Export a case's YARA matches to CSV (RFC 4180, one row per matched string).

The columns follow ``yara_csv_export.md``: ``rule``, ``namespace``, ``tags``,
the dynamic ``meta_*`` block (one column per distinct ``meta`` key seen in the
scan), ``enabled``, and the per-string fields (``string_id``, ``offset``,
``length``, ``data_hex``, ``data_text``, ``context_start``, ``context_hex``,
``hit_offset_in_context`` and ``context_marked`` — the context hex with the
matched bytes in ``[ ]`` so the hit is visible). A
leading ``file`` column says which scanned file the match is in (a case scans the
original plus every extracted/nested file). A rule that matched with no strings
still emits one row with the string columns empty.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from .storage import CasePaths, read_json

_BOM = "﻿"
_BASE_BEFORE_META = ["file", "rule", "namespace", "tags"]
_BASE_AFTER_META = ["enabled", "string_id", "offset", "length",
                    "data_hex", "data_text", "context_start", "context_hex",
                    "hit_offset_in_context", "context_marked"]


def _mark_context(ctx_hex: str, ctx_start: int, offset: int, length: int) -> str:
    """Context as spaced hex bytes with the matched bytes wrapped in [ ], e.g.
    ``41 42 [44 72 6F 70] 43`` — so the hit is visible in a spreadsheet cell."""
    if not ctx_hex:
        return ""
    rel, n = offset - ctx_start, max(1, length)
    out: list[str] = []
    for i in range(len(ctx_hex) // 2):
        b = ctx_hex[i * 2:i * 2 + 2].upper()
        if i == rel:
            b = "[" + b
        if i == rel + n - 1:
            b = b + "]"
        out.append(b)
    return " ".join(out)


def _meta_keys(yres: dict[str, Any]) -> list[str]:
    keys: set[str] = set()
    for sc in yres.get("scanned", []) or []:
        for m in sc.get("matches", []) or []:
            keys.update((m.get("meta") or {}).keys())
    return sorted(keys)


def _string_row(file_rel: str, m: dict[str, Any], meta_keys: list[str],
                s: dict[str, Any] | None) -> dict[str, Any]:
    ctx = (s or {}).get("context") or {}
    row: dict[str, Any] = {
        "file": file_rel,
        "rule": m.get("rule", ""),
        "namespace": m.get("namespace", ""),
        "tags": "|".join(m.get("tags", []) or []),
        "enabled": "true" if m.get("enabled") else "false",
        "string_id": (s or {}).get("id", ""),
        "offset": (s or {}).get("offset", "") if s else "",
        "length": (s or {}).get("length", "") if s else "",
        "data_hex": (s or {}).get("data", "") if s else "",
        "data_text": (s or {}).get("text", "") if s else "",
        "context_start": ctx.get("start", ""),
        "context_hex": ctx.get("data", ""),
        "hit_offset_in_context": "",
        "context_marked": "",
    }
    if s and ctx.get("data"):
        start, off = int(ctx.get("start", 0)), int(s.get("offset", 0))
        row["hit_offset_in_context"] = off - start
        row["context_marked"] = _mark_context(ctx["data"], start, off, int(s.get("length", 1)))
    meta = m.get("meta") or {}
    for k in meta_keys:
        row[f"meta_{k}"] = "" if meta.get(k) is None else str(meta.get(k))
    return row


def build_csv(analysis_id: str, cases_dir: Path | None = None) -> str:
    """The full CSV text (without the BOM) for a case's YARA matches."""
    paths = CasePaths(analysis_id, cases_dir=cases_dir) if cases_dir else CasePaths(analysis_id)
    yres = read_json(paths.subresult("yara")) or {}
    meta_keys = _meta_keys(yres)
    header = _BASE_BEFORE_META + [f"meta_{k}" for k in meta_keys] + _BASE_AFTER_META

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=header, extrasaction="ignore",
                            quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writeheader()
    for sc in yres.get("scanned", []) or []:
        file_rel = sc.get("file") or sc.get("stored_path") or ""
        for m in sc.get("matches", []) or []:
            strings = m.get("strings") or []
            if not strings:
                writer.writerow(_string_row(file_rel, m, meta_keys, None))
            for s in strings:
                writer.writerow(_string_row(file_rel, m, meta_keys, s))
    return buf.getvalue()


def csv_bytes(analysis_id: str, cases_dir: Path | None = None) -> bytes:
    """CSV as UTF-8 **with BOM** (so Excel opens it directly)."""
    return (_BOM + build_csv(analysis_id, cases_dir)).encode("utf-8")


def filename_for(case_filename: str) -> str:
    import datetime
    stem = Path(case_filename or "case").stem or "case"
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in stem)[:60] or "case"
    day = datetime.date.today().strftime("%Y%m%d")
    return f"yara_matches_{safe}_{day}.csv"
