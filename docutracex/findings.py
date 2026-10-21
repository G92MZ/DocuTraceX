"""Consolidated findings view.

Each parser/analyzer writes its own findings into its sub-result. This module
gathers them all into one normalized list and assigns every finding a *stable*
id, derived from the finding's own content (source + rule + location + detail).

The stable id is what lets manual classifications (marks.py) survive a
re-analysis: regenerating the findings yields the same ids, so a mark keeps
pointing at the same finding. A finding whose content changes gets a new id —
by design — and its old mark becomes an orphan the UI flags for review.

The consolidation mirrors the Findings pane in the web UI, but the server is the
source of truth for finding identity.
"""

from __future__ import annotations

import hashlib
from typing import Any

# anomaly kind -> severity (OOXML engine anomalies have no severity of their own)
_ANOMALY_SEVERITY = {
    "external_relationship": "high",
    "broken_relationship_target": "medium",
    "malformed_xml": "medium",
    "dangerous_path": "high",
    "duplicate_zip_entry": "medium",
    "no_content_type": "low",
    "not_a_zip": "high",
    "missing_content_types": "medium",
}
_SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Office semantic parser modules (their sub-result key is the office app).
_OFFICE_MODULES = ("word", "excel", "powerpoint")


def finding_id(source: str, rule: str, location: str, detail: str) -> str:
    """Deterministic 16-hex-char id from the finding's stable attributes."""
    raw = "\x1f".join((source or "", rule or "", location or "", detail or ""))
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _add(out: list[dict[str, Any]], severity: str, source: str, rule: str,
         detail: str, location: str, evidence: str = "") -> None:
    # k: gmzpt
    out.append({
        "id": finding_id(source, rule, location, detail),
        "severity": severity or "info",
        "source": source,
        "rule": rule,
        "detail": detail or "",
        "location": location or "",
        "evidence": evidence or "",
    })


def consolidate(modules: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the unified, severity-sorted list of findings with stable ids.

    Duplicate ids (same content from the same source) are collapsed.
    """
    out: list[dict[str, Any]] = []

    ooxml = modules.get("ooxml")
    if ooxml:
        for a in ooxml.get("anomalies", []) or []:
            kind = a.get("kind", "")
            _add(out, _ANOMALY_SEVERITY.get(kind, "medium"), "ooxml", kind,
                 a.get("detail") or a.get("target") or "",
                 a.get("part") or a.get("rels_file") or a.get("target") or "")

    for name in _OFFICE_MODULES + ("email",):
        mod = modules.get(name)
        if not mod:
            continue
        for f in mod.get("findings", []) or []:
            _add(out, f.get("severity"), name, f.get("rule", ""),
                 f.get("detail", ""), f.get("location", ""), f.get("evidence", ""))

    # Tool modules whose findings carry their own `tool` (olevba, oleid, ...).
    ole = modules.get("oletools")
    if ole:
        for f in ole.get("findings", []) or []:
            _add(out, f.get("severity"), f.get("tool") or "oletools",
                 f.get("rule", ""), f.get("detail", ""), f.get("location", ""),
                 f.get("evidence", ""))

    for mod_name, source in (("unlock", "unlock"), ("archive", "archive"),
                             ("msoffcrypto", "msoffcrypto"), ("xlmdeobf", "xlmdeobf"),
                             ("officemalscanner", "officemalscanner"),
                             ("pdf", "pdf"), ("nested", "nested"), ("yara", "yara"),
                             ("ole", "ole"), ("officerules", "officerules"),
                             ("vbatools", "vbatools"), ("vipermonkey", "vipermonkey"),
                             ("pdftools", "pdftools"), ("mailrules", "mailrules"),
                             ("javascript", "javascript"), ("rtf", "rtf"),
                             ("powershell", "powershell"), ("vbscript", "vbscript"),
                             ("batch", "batch"), ("netcheck", "netcheck")):
        mod = modules.get(mod_name)
        if not mod:
            continue
        for f in mod.get("findings", []) or []:
            _add(out, f.get("severity"), f.get("tool") or source,
                 f.get("rule", ""), f.get("detail", ""),
                 f.get("location", "") or source, f.get("evidence", ""))

    # Collapse exact duplicates (same id), keep first occurrence.
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for f in out:
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        deduped.append(f)

    deduped.sort(key=lambda f: _SEV_RANK.get(f["severity"], 9))
    return deduped
