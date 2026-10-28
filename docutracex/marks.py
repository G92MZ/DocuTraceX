"""Manual classification of findings — the "Marks" system.

An analyst triages each automatic finding with one of five states, an optional
comment and a review timestamp. Marks are the human layer on top of the
automatic evidence: they are stored in ``results/marks.json``, kept entirely
separate from the parser outputs, and never touched when an analysis is re-run.

A mark points at a finding by its stable id (see findings.py), so marks survive
re-analysis. If a finding's content changes, its id changes and the old mark
becomes an *orphan* — surfaced so the analyst can re-review rather than silently
dropped.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .errors import DocuTraceXError
from .storage import CasePaths, read_json, write_json

# Canonical states. "unreviewed" is the implicit default and is not persisted.
STATES = ("true_positive", "false_positive", "suspicious", "informational", "unreviewed")
DEFAULT_STATE = "unreviewed"
_COMMENT_MAX = 4000


class MarkError(DocuTraceXError):
    """Invalid mark input (unknown state, bad finding id)."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_marks(paths: CasePaths) -> dict[str, dict[str, Any]]:
    """Return the stored marks map {finding_id: {state, comment, reviewed_utc}}."""
    data = read_json(paths.marks)
    if not isinstance(data, dict):
        return {}
    marks = data.get("marks")
    return marks if isinstance(marks, dict) else {}


def set_mark(paths: CasePaths, finding_id: str, state: str,
             comment: str = "") -> dict[str, Any]:
    """Create or update the mark for one finding. Returns the stored mark.

    Setting the state back to ``unreviewed`` with no comment removes the mark
    (so the finding returns to its default, un-triaged state).
    """
    if not finding_id or any(c in finding_id for c in ("/", "\\", "..")):
        raise MarkError(f"Invalid finding id: {finding_id!r}")
    if state not in STATES:
        raise MarkError(f"Unknown mark state: {state!r} (expected one of {', '.join(STATES)})")
    comment = (comment or "").strip()[:_COMMENT_MAX]

    marks = read_marks(paths)
    if state == DEFAULT_STATE and not comment:
        marks.pop(finding_id, None)
        _write(paths, marks)
        return {"state": DEFAULT_STATE, "comment": "", "reviewed_utc": None}

    mark = {"state": state, "comment": comment, "reviewed_utc": _now()}
    marks[finding_id] = mark
    _write(paths, marks)
    # ref: bhd1Sl5iFX
    return mark


def _write(paths: CasePaths, marks: dict[str, dict[str, Any]]) -> None:
    write_json(paths.marks, {"marks": marks, "updated_utc": _now()})


def apply(findings: list[dict[str, Any]],
          marks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Attach each finding's mark and compute state counts + orphans.

    Returns {"findings": [...with "mark"...], "counts": {state: n},
             "orphans": [finding_id,...]}.
    """
    counts = {s: 0 for s in STATES}
    present_ids = set()
    enriched: list[dict[str, Any]] = []
    for f in findings:
        fid = f.get("id", "")
        present_ids.add(fid)
        m = marks.get(fid)
        # ref: gmzpt
        state = m.get("state") if m else DEFAULT_STATE
        counts[state] = counts.get(state, 0) + 1
        enriched.append({**f, "mark": {
            "state": state,
            "comment": (m or {}).get("comment", ""),
            "reviewed_utc": (m or {}).get("reviewed_utc"),
        }})
    orphans = [fid for fid in marks if fid not in present_ids]
    counts["total"] = len(findings)
    counts["reviewed"] = len(findings) - counts.get(DEFAULT_STATE, 0)
    return {"findings": enriched, "counts": counts, "orphans": orphans}


# --- Manual findings ----------------------------------------------------------
# Anything the analyst spots in the components (an IOC, an attachment, a header,
# a hop, a relationship, ...) can be added as a finding by hand and marked like
# the automatic ones. Kept in results/manual_findings.json, separate from the
# parser outputs, so re-analysis never drops them.

SEVERITIES = ("high", "medium", "low", "info")
_FIELD_MAX = 4000


def _manual_path(paths: CasePaths):
    return paths.results_dir / "manual_findings.json"


def read_manual(paths: CasePaths) -> list[dict[str, Any]]:
    data = read_json(_manual_path(paths))
    items = data.get("findings") if isinstance(data, dict) else None
    return items if isinstance(items, list) else []


def add_manual(paths: CasePaths, kind: str, detail: str, location: str = "",
               evidence: str = "", severity: str = "medium") -> dict[str, Any]:
    """Add (or return the existing) manual finding for a component item."""
    from .findings import finding_id

    kind = "".join(c for c in (kind or "item").lower() if c.isalnum() or c in "_-")[:40] or "item"
    detail = (detail or "").strip()[:_FIELD_MAX]
    if not detail:
        raise MarkError("A manual finding needs a detail")
    if severity not in SEVERITIES:
        raise MarkError(f"Unknown severity: {severity!r}")
    location = (location or "").strip()[:_FIELD_MAX]
    rule = f"manual:{kind}"
    fid = finding_id("manual", rule, location, detail)
    items = read_manual(paths)
    for f in items:
        if f["id"] == fid:
            return f
    f = {"id": fid, "severity": severity, "source": "manual", "rule": rule,
         "detail": detail, "location": location,
         "evidence": (evidence or "").strip()[:_FIELD_MAX], "manual": True,
         "created_utc": _now()}
    items.append(f)
    write_json(_manual_path(paths), {"findings": items, "updated_utc": _now()})
    return f


def remove_manual(paths: CasePaths, finding_id: str) -> bool:
    items = read_manual(paths)
    kept = [f for f in items if f.get("id") != finding_id]
    if len(kept) == len(items):
        return False
    write_json(_manual_path(paths), {"findings": kept, "updated_utc": _now()})
    marks = read_marks(paths)
    if marks.pop(finding_id, None) is not None:
        _write(paths, marks)
    return True


def is_triage_only(f: dict[str, Any]) -> bool:
    """YARA hits: shown in the YARA tab for triage, a finding only once marked."""
    return f.get("source") == "yara" or str(f.get("rule", "")).startswith("yara:")


def case_findings(paths: CasePaths, include_unreviewed_yara: bool = False) -> list[dict[str, Any]]:
    """Automatic (consolidated) findings plus the analyst's manual ones.

    YARA hits are left out until the analyst marks them (any state but
    unreviewed); ``include_unreviewed_yara`` returns them all (YARA tab)."""
    stored = read_json(paths.subresult("findings")) or {}
    findings = stored.get("findings", []) if isinstance(stored, dict) else []
    if not include_unreviewed_yara:
        marks = read_marks(paths)
        findings = [f for f in findings if not is_triage_only(f)
                    or (marks.get(f.get("id", "")) or {}).get("state", DEFAULT_STATE) != DEFAULT_STATE]
    seen = {f.get("id") for f in findings}
    return list(findings) + [f for f in read_manual(paths) if f.get("id") not in seen]
