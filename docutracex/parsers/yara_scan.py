"""Scan a case with the YARA ruleset.

Runs the compiled rules over the original file and everything the parsers
extracted (attachments, embedded files, OLE objects, media). Every hit (rule x
file) becomes a finding the analyst triages with a mark (true/false positive,
...); only findings marked true positive reach the report. Each hit carries the
rule's source, what matched (offset, bytes, printable text) and the local path.
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

    from ..findings import finding_id

    ns_path = {src["namespace"]: src["path"] for src in report.get("sources", [])
               if src.get("status") == "ok"}
    rules_info: dict[str, dict[str, str]] = {}
    total_matches = 0
    for rel, path in _iter_targets(original_path, extracted_dir):
        matches = yara_engine.scan_path(compiled, path, set())
        result["files_scanned"] += 1
        if not matches:
            continue
        total_matches += len(matches)
        try:
            stored = path.relative_to(extracted_dir.parent).as_posix()
        except ValueError:
            stored = ""
        result["scanned"].append({"file": rel, "path": str(path.resolve()),
                                  "stored_path": stored, "matches": matches})
        for m in matches:
            key = f"{m.get('namespace', '')}:{m['rule']}"
            if key not in rules_info:
                rfile = ns_path.get(m.get("namespace", ""), "")
                rules_info[key] = {"file": rfile,
                                   "source": yara_engine.rule_source(rfile, m["rule"]) if rfile else ""}
            meta = m.get("meta", {})
            desc = meta.get("description") or meta.get("desc") or ""
            tags = ", ".join(m.get("tags", []))
            f = {
                "tool": "yara", "rule": f"yara:{m['rule']}",
                "severity": _severity(meta),
                "detail": f"YARA rule '{m['rule']}' matched {rel}"
                          + (f" — {desc}" if desc else "") + (f" [{tags}]" if tags else ""),
                "location": f"yara:{rel}",
                "evidence": "; ".join(
                    f"{s['id']}@{s['offset']}: {s.get('text', '')[:40]}"
                    for s in m.get("strings", [])[:8]),
            }
            m["finding_id"] = finding_id(f["tool"], f["rule"], f["location"], f["detail"])
            result["findings"].append(f)
    result["rules_info"] = rules_info

    result["match_count"] = total_matches
    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
