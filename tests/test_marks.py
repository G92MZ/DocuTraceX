"""Tests for consolidated findings (stable ids) and the Marks system."""

from __future__ import annotations

from pathlib import Path

from docutracex import findings as findings_mod
from docutracex import marks as marks_mod
from docutracex.storage import CasePaths

MODULES = {
    "ooxml": {"anomalies": [{"kind": "external_relationship", "detail": "ext rel",
                             "part": "word/document.xml"}]},
    "excel": {"findings": [{"rule": "webservice", "severity": "high",
                            "detail": "Formula uses WEBSERVICE", "location": "xl/worksheets/sheet1.xml"}]},
    "oletools": {"findings": [{"tool": "msodde", "rule": "dde_link", "severity": "high",
                               "detail": "cmd.exe", "location": "dde"}]},
}


def test_finding_id_is_stable_and_deterministic() -> None:
    a = findings_mod.consolidate(MODULES)
    b = findings_mod.consolidate(MODULES)
    assert [f["id"] for f in a] == [f["id"] for f in b]
    # id depends only on content, not on run.
    fid = findings_mod.finding_id("excel", "webservice",
                                  "xl/worksheets/sheet1.xml", "Formula uses WEBSERVICE")
    assert any(f["id"] == fid for f in a)


def test_consolidate_dedupes_and_sorts_by_severity() -> None:
    mods = {"excel": {"findings": [
        {"rule": "webservice", "severity": "high", "detail": "d", "location": "l"},
        {"rule": "webservice", "severity": "high", "detail": "d", "location": "l"},  # dup
        {"rule": "hidden_sheet", "severity": "low", "detail": "s", "location": "wb"},
    ]}}
    out = findings_mod.consolidate(mods)
    assert len(out) == 2  # duplicate collapsed
    assert out[0]["severity"] == "high" and out[-1]["severity"] == "low"


def test_set_and_read_mark_roundtrip(tmp_path: Path) -> None:
    paths = CasePaths("case1", cases_dir=tmp_path)
    paths.ensure_dirs()
    fid = "abc123def456abcd"
    mark = marks_mod.set_mark(paths, fid, "true_positive", "confirmed maldoc")
    assert mark["state"] == "true_positive"
    assert mark["reviewed_utc"]
    stored = marks_mod.read_marks(paths)
    assert stored[fid]["state"] == "true_positive"
    assert stored[fid]["comment"] == "confirmed maldoc"


def test_unreviewed_without_comment_removes_mark(tmp_path: Path) -> None:
    paths = CasePaths("case2", cases_dir=tmp_path)
    paths.ensure_dirs()
    fid = "1111222233334444"
    marks_mod.set_mark(paths, fid, "false_positive", "benign")
    marks_mod.set_mark(paths, fid, "unreviewed", "")
    assert fid not in marks_mod.read_marks(paths)


def test_invalid_state_rejected(tmp_path: Path) -> None:
    paths = CasePaths("case3", cases_dir=tmp_path)
    paths.ensure_dirs()
    try:
        marks_mod.set_mark(paths, "deadbeefdeadbeef", "totally_bogus")
        raise AssertionError("expected MarkError")
    except marks_mod.MarkError:
        pass


def test_apply_counts_and_orphans() -> None:
    findings = findings_mod.consolidate(MODULES)
    first = findings[0]["id"]
    marks = {
        first: {"state": "true_positive", "comment": "x", "reviewed_utc": "2026-10-14T00:00:00Z"},
        "orphan0000000000": {"state": "suspicious", "comment": "", "reviewed_utc": "2026-10-14T00:00:00Z"},
    }
    res = marks_mod.apply(findings, marks)
    assert res["counts"]["true_positive"] == 1
    assert res["counts"]["total"] == len(findings)
    assert res["counts"]["reviewed"] == 1
    assert res["orphans"] == ["orphan0000000000"]
    marked = next(f for f in res["findings"] if f["id"] == first)
    assert marked["mark"]["state"] == "true_positive"


def test_marks_survive_reanalysis(tmp_path: Path) -> None:
    """A mark keyed by stable id still matches after findings are regenerated."""
    paths = CasePaths("case4", cases_dir=tmp_path)
    paths.ensure_dirs()
    findings1 = findings_mod.consolidate(MODULES)
    target = findings1[0]["id"]
    marks_mod.set_mark(paths, target, "true_positive", "keep me")
    # Re-run consolidation (same inputs -> same ids).
    findings2 = findings_mod.consolidate(MODULES)
    res = marks_mod.apply(findings2, marks_mod.read_marks(paths))
    kept = next(f for f in res["findings"] if f["id"] == target)
    assert kept["mark"]["state"] == "true_positive"
    assert kept["mark"]["comment"] == "keep me"
    assert res["orphans"] == []
