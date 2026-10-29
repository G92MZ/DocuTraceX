"""Export a case's Machine Learning (EMBER2024) results to CSV and summarise
them for the HTML report.

One CSV row per classified object (the original and every nested PE / .NET /
PDF / ELF / APK): model, score, calibrated threshold, verdict, the tag / family
hints, the top feature contributions (TreeSHAP) and the analyst's mark. RFC 4180,
UTF-8 with BOM so Excel opens it directly — same conventions as the YARA CSV.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from . import marks as marks_service
from .storage import CasePaths, read_json

_BOM = "﻿"
COLUMNS = ["object", "stored_path", "sha256", "recipe", "status", "file_type", "format", "model",
           "score", "threshold", "calibrated", "verdict", "test_detection_at_threshold",
           "evasive_detection_at_threshold", "test_malware_at_or_above", "test_goodware_at_or_above",
           "tags", "family", "family_note", "top_features", "feature_blocks",
           "mark", "mark_comment", "detail"]


def tag_hints(item: dict[str, Any]) -> list[str]:
    """``kind:name (prob)`` for every tag above its threshold."""
    out = []
    for kind, hits in (item.get("labels") or {}).items():
        if kind == "family":
            continue
        out += [f"{kind}:{h.get('name')} ({float(h.get('prob', 0)):.2f})" for h in hits or []]
    return out


def family_hints(item: dict[str, Any], only_high: bool = False) -> list[str]:
    """``name (prob, confidence, kind)`` — kind from family_info (generic AV
    names say so)."""
    from .ml.family_info import info

    fam = (item.get("labels") or {}).get("family") or []
    out = []
    for h in fam:
        if only_high and h.get("confidence") != "high":
            continue
        meta = info(str(h.get("name")))
        kind = "generic AV name" if meta.get("generic") else meta.get("type", "unknown")
        out.append(f"{h.get('name')} ({float(h.get('prob', 0)):.2f}, {h.get('confidence', 'none')}, {kind})")
    return out


def load(analysis_id: str, cases_dir: Path | None = None) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """(ml.json, marks map) for a case."""
    paths = CasePaths(analysis_id, cases_dir=cases_dir) if cases_dir else CasePaths(analysis_id)
    from .ml.family_info import enrich
    return enrich(read_json(paths.subresult("ml"))) or {}, marks_service.read_marks(paths)


def _num(v: Any, fmt: str = "{:.6f}") -> str:
    return "" if v is None else fmt.format(float(v))


def _row(it: dict[str, Any], marks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    m = marks.get(it.get("finding_id") or "") or {}
    met = it.get("metrics") or {}
    blocks = sorted((it.get("blocks") or {}).items(), key=lambda kv: -abs(kv[1]))
    return {
        "object": it.get("label", ""),
        "stored_path": it.get("stored_path", ""),
        "sha256": it.get("sha256", ""),
        "recipe": " → ".join(it.get("recipe") or []),
        "status": it.get("status", ""),
        "file_type": it.get("file_type", ""),
        "format": it.get("format", ""),
        "model": it.get("model", ""),
        "score": _num(it.get("score")),
        "threshold": _num(it.get("threshold")),
        "calibrated": "" if it.get("status") != "ok" else ("true" if it.get("calibrated") else "false"),
        "verdict": it.get("verdict", ""),
        "test_detection_at_threshold": _num(met.get("tpr_at_fpr_0.01"), "{:.4f}"),
        "evasive_detection_at_threshold": _num(met.get("challenge_detected_at_1pct_fpr"), "{:.4f}"),
        "test_malware_at_or_above": _num((it.get("score_ref") or {}).get("malicious_ge"), "{:.4f}"),
        "test_goodware_at_or_above": _num((it.get("score_ref") or {}).get("benign_ge"), "{:.4f}"),
        "tags": " | ".join(tag_hints(it)),
        "family": " | ".join(family_hints(it)),
        "family_note": it.get("family_note", ""),
        "top_features": " | ".join(
            (f"{t['plain']} [{t.get('feature')}]" if t.get("plain") else f"{t.get('block')}: {t.get('feature')}")
            + f" ({float(t.get('contribution', 0)):+.3f})"
            + (f" e.g. {t['evidence'][0][:60]}" if t.get("evidence") else "")
            for t in (it.get("top_features") or [])[:10]),
        "feature_blocks": " | ".join(f"{k} ({v:+.3f})" for k, v in blocks),
        "mark": m.get("state", "unreviewed") if it.get("finding_id") else "",
        "mark_comment": m.get("comment", ""),
        "detail": it.get("detail", "") if it.get("status") != "ok" else "",
    }


def build_csv(analysis_id: str, cases_dir: Path | None = None) -> str:
    ml, marks = load(analysis_id, cases_dir)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    w.writeheader()
    for it in ml.get("items") or []:
        w.writerow(_row(it, marks))
    return buf.getvalue()


def csv_bytes(analysis_id: str, cases_dir: Path | None = None) -> bytes:
    return (_BOM + build_csv(analysis_id, cases_dir)).encode("utf-8")


def filename_for(case_filename: str) -> str:
    import datetime
    stem = Path(case_filename or "case").stem or "case"
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in stem)[:60] or "case"
    return f"ml_results_{safe}_{datetime.date.today():%Y%m%d}.csv"
