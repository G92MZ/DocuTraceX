"""A nested child's view (Components › Nested › child) shows the case's YARA hits on that child's file.

YARA runs once per case over the original and everything under extracted/ — including files unpacked
inside Nested (extracted/nested/unpacked/<sha>/upx/…) — so the child has no YARA result of its own.
``get_nested_components`` narrows the case's yara.json to the child's stored file, with its marks.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from docutracex import cases as case_service
from docutracex import marks as marks_service
from docutracex.api import cases as api
from docutracex.config import settings
from docutracex.storage import CasePaths, write_json

CASE = "20261030-140336-f64e2425"
CHILD = "extracted/nested/unpacked/f3f56d4c1934/upx/Statement of Account.unpacked.exe"
OTHER = "extracted/attachments/Statement of Account.zip"
VIEW = "0123456789abcdef-a1b2c3"


def _match(rule: str, fid: str) -> dict:
    return {"rule": rule, "namespace": "ns1", "tags": ["stealer"], "meta": {"description": rule},
            "strings": [{"id": "$a", "offset": 0x45e20, "length": 4, "text": "abcd", "data": "61626364"}],
            "finding_id": fid}


@pytest.fixture()
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CasePaths:
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(case_service, "get_case", lambda aid: {"analysis_id": aid})
    paths = CasePaths(CASE)
    write_json(paths.subresult("yara"), {
        "module": "yara", "available": True, "rule_count": 120, "files_scanned": 9, "match_count": 3,
        "status": "ok_with_findings",
        "scanned": [
            {"file": CHILD, "path": "E:\\x\\" + CHILD.replace("/", "\\"), "stored_path": CHILD,
             "matches": [_match("Stealer_A", "f-child-1"), _match("Packed_B", "f-child-2")]},
            {"file": OTHER, "path": "E:\\x\\zip", "stored_path": OTHER, "matches": [_match("Zip_C", "f-zip")]},
        ],
        "rules_info": {"ns1:Stealer_A": {"file": "a.yar", "source": "rule Stealer_A {}"},
                       "ns1:Packed_B": {"file": "b.yar", "source": "rule Packed_B {}"},
                       "ns1:Zip_C": {"file": "c.yar", "source": "rule Zip_C {}"}},
        "findings": [], "counts": {"findings": 3}})
    write_json(paths.subresult("nested"), {"tree": [{"filename": "Statement of Account.zip", "children": [
        {"filename": "Statement of Account.unpacked.exe", "view_id": VIEW, "stored_path": CHILD}]}]})
    from docutracex import nested
    write_json(nested.view_path(paths, VIEW), {
        "view_id": VIEW, "filename": "Statement of Account.unpacked.exe", "kind": "binary",
        "chain": "Statement of Account.zip › Statement of Account.exe › Statement of Account.unpacked.exe",
        "stored_path": CHILD, "modules": {"msi": {"items": []}}, "findings": [], "iocs": {}})
    yara_findings = [
        {"id": fid, "source": "yara", "tool": "yara", "rule": f"yara:{r}", "severity": "medium",
         "detail": f"YARA rule '{r}' matched {loc}", "location": f"yara:{loc}"}
        for fid, r, loc in (("f-child-1", "Stealer_A", CHILD), ("f-child-2", "Packed_B", CHILD),
                            ("f-zip", "Zip_C", OTHER))]
    monkeypatch.setattr(marks_service, "case_findings",
                        lambda p, include_unreviewed_yara=False: list(yara_findings))
    monkeypatch.setattr(marks_service, "read_marks",
                        lambda p: {"f-child-1": {"state": "true_positive", "comment": "ok"}})
    return paths


def _get(view: str = VIEW) -> dict:
    return asyncio.run(api.get_nested_components(CASE, view))


def test_child_view_gets_only_its_yara_hits(case: CasePaths) -> None:
    d = _get()
    y = d["modules"]["yara"]
    assert y["rule_count"] == 120 and y["files_scanned"] == 1 and y["scope_path"] == CHILD
    assert [s["stored_path"] for s in y["scanned"]] == [CHILD]
    assert y["match_count"] == 2
    assert set(y["rules_info"]) == {"ns1:Stealer_A", "ns1:Packed_B"}       # not the ZIP's rule
    assert {f["id"] for f in d["yara_findings"]} == {"f-child-1", "f-child-2"}


def test_child_view_keeps_case_marks(case: CasePaths) -> None:
    by_id = {f["id"]: f for f in _get()["yara_findings"]}
    assert by_id["f-child-1"]["mark"]["state"] == "true_positive"


def test_windows_backslashes_and_case_match(case: CasePaths) -> None:
    assert api._norm_rel("Extracted\\Nested\\x.EXE") == api._norm_rel("extracted/nested/x.exe")


def test_no_hits_on_child_still_shows_the_tab(case: CasePaths) -> None:
    from docutracex import nested
    from docutracex.storage import read_json
    v = read_json(nested.view_path(case, VIEW))
    v["stored_path"] = "extracted/nested/other.bin"
    write_json(nested.view_path(case, VIEW), v)
    d = _get()
    assert d["modules"]["yara"]["match_count"] == 0 and d["yara_findings"] == []


def test_without_yara_result_no_tab(case: CasePaths) -> None:
    case.subresult("yara").unlink()
    d = _get()
    assert "yara" not in d["modules"] and d["yara_findings"] == []
