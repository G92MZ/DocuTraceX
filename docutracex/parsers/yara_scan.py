"""Scan a case with the YARA ruleset.

Runs the compiled rules over the original file and everything the parsers
extracted (attachments, embedded files, OLE objects, media). Every match is
recorded for display; only matches of *enabled* rules are turned into findings
(so by default YARA never adds noise to the report — the analyst opts rules in).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

_MAX_FILES = 500
_SEV_FROM_META = ("severity", "threat_level", "level")


def _severity(meta: dict[str, Any]) -> str:
    for k in _SEV_FROM_META:
        v = str(meta.get(k, "")).lower()
        if v in ("high", "critical"):
            return "high"
        if v in ("medium", "moderate"):
            return "medium"
        if v in ("low", "info", "informational"):
            return "low"
    return "medium"


def _iter_targets(original_path: Path, extracted_dir: Path):
    yield ("original", original_path)
    if extracted_dir.is_dir():
        count = 0
        for p in sorted(extracted_dir.rglob("*")):
            if count >= _MAX_FILES:
                break
            if p.is_file():
                count += 1
                try:
                    rel = p.relative_to(extracted_dir.parent).as_posix()
                except ValueError:
                    rel = p.name
                yield (rel, p)


def analyze(original_path: Path, extracted_dir: Path) -> dict[str, Any]:
    from .. import yara_engine

    result: dict[str, Any] = {
        "module": "yara", "available": False, "rule_count": 0,
        "scanned": [], "findings": [], "errors": [],
        "files_scanned": 0, "match_count": 0, "status": "ok",
    }
    compiled, report = yara_engine.compile_rules()
    result["available"] = report.get("available", False)
    result["rule_count"] = report.get("rule_count", 0)
    result["errors"] = report.get("errors", [])
    if compiled is None or result["rule_count"] == 0:
        result["counts"] = {"findings": 0}
        return result

    enabled = yara_engine.enabled_rules()
    total_matches = 0
    for rel, path in _iter_targets(original_path, extracted_dir):
        matches = yara_engine.scan_path(compiled, path, enabled)
        result["files_scanned"] += 1
        if not matches:
            continue
        total_matches += len(matches)
        result["scanned"].append({"file": rel, "matches": matches})
        for m in matches:
            if not m.get("enabled"):
                continue  # opt-in: only enabled rules become findings
            meta = m.get("meta", {})
            desc = meta.get("description") or meta.get("desc") or ""
            tags = ", ".join(m.get("tags", []))
            result["findings"].append({
                "tool": "yara", "rule": f"yara:{m['rule']}",
                "severity": _severity(meta),
                "detail": f"YARA rule '{m['rule']}' matched {rel}"
                          + (f" — {desc}" if desc else "") + (f" [{tags}]" if tags else ""),
                "location": f"yara:{rel}",
                "evidence": "; ".join(
                    f"{s['id']}@{s['offset']}" for s in m.get("strings", [])[:8]),
            })

    result["match_count"] = total_matches
    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
