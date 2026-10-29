"""Export a case's C2 / implant configurations to CSV (one row per
configuration: object, family, kind, method, C2 endpoints, key fields, full
configuration, the analyst's mark). RFC 4180, UTF-8 with BOM — same
conventions as the YARA and Machine Learning CSVs."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from . import marks as marks_service
from .storage import CasePaths, read_json

_BOM = "﻿"
COLUMNS = ["object", "stored_path", "also_in", "family", "kind", "method", "confidence", "c2",
           "key_fields", "configuration", "mark", "mark_comment"]


def _flat(v: Any) -> str:
    return ", ".join(map(str, v)) if isinstance(v, list) else str(v)


def build_csv(analysis_id: str, cases_dir: Path | None = None) -> str:
    paths = CasePaths(analysis_id, cases_dir=cases_dir) if cases_dir else CasePaths(analysis_id)
    c2 = read_json(paths.subresult("c2")) or {}
    marks = marks_service.read_marks(paths)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\r\n")
    w.writeheader()
    for c in c2.get("configs") or []:
        s = c.get("summary") or {}
        m = marks.get(c.get("finding_id") or "") or {}
        w.writerow({
            "object": c.get("object", ""), "stored_path": c.get("stored_path", ""),
            "also_in": " | ".join(c.get("also_in") or []), "family": c.get("family", ""),
            "kind": c.get("kind", ""), "method": c.get("method", ""), "confidence": c.get("confidence", ""),
            "c2": " | ".join(map(str, s.get("C2") or s.get("Hosts") or c.get("c2") or [])),
            "key_fields": " | ".join(f"{k}: {_flat(v)}" for k, v in s.items()),
            "configuration": json.dumps(c.get("fields") or {}, ensure_ascii=False),
            "mark": m.get("state", "unreviewed"), "mark_comment": m.get("comment", ""),
        })
    return buf.getvalue()


def csv_bytes(analysis_id: str, cases_dir: Path | None = None) -> bytes:
    return (_BOM + build_csv(analysis_id, cases_dir)).encode("utf-8")


def filename_for(case_filename: str) -> str:
    import datetime
    stem = Path(case_filename or "case").stem or "case"
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in stem)[:60] or "case"
    return f"c2_configs_{safe}_{datetime.datetime.now().astimezone():%Y%m%d}.csv"
