"""Tests for the legacy OLE/BIFF family (.doc/.xls/.ppt) and the TP overview."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from docutracex.parsers import ole_legacy

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
has_samples = pytest.mark.skipif(not (SAMPLES / "sample.xls").exists(),
                                 reason="samples not generated")


def test_ole_parser_detects_kind_and_vba(tmp_path: Path) -> None:
    from mkmsg import build_cfb

    p = tmp_path / "m.xls"
    p.write_bytes(build_cfb([
        ("Workbook", b"\x09\x08 BIFF"),
        ("Macros", [("VBA", b"vba"), ("dir", b"dir")]),
    ]))
    r = ole_legacy.analyze(p, tmp_path / "extracted")
    assert r["kind"] == "excel"
    assert r["vba"] is True
    assert any(f["rule"] == "vba_macros_present" for f in r["findings"])


def test_ole_rejects_non_ole(tmp_path: Path) -> None:
    p = tmp_path / "x.xls"
    p.write_bytes(b"not an OLE file")
    r = ole_legacy.analyze(p, tmp_path / "extracted")
    assert r["status"] == "error"
    assert any(f["rule"] == "not_ole" for f in r["findings"])


@has_samples
@pytest.mark.parametrize("name,kind", [("sample.doc", "word"), ("sample.xls", "excel"),
                                       ("sample.ppt", "powerpoint")])
def test_legacy_family_pipeline(tmp_path: Path, name: str, kind: str) -> None:
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json

    with (SAMPLES / name).open("rb") as fh:
        manifest = cases.create_case(fh, name, cases_dir=tmp_path)
    cid = manifest["analysis_id"]
    summary = analyze.analyze_case(tmp_path / cid)
    assert manifest["format"]["discrepancy"]["declared_family"] == "ole"
    assert "ole" in summary["modules_run"] and "oletools" in summary["modules_run"]
    ole = read_json(CasePaths(cid, cases_dir=tmp_path).subresult("ole"))
    assert ole["kind"] == kind
    # .xls runs the XLM deobfuscator step (BIFF Excel 4.0 macros).
    if name == "sample.xls":
        # ref: gmzpt
        assert "xlmdeobf" in summary["modules_run"]
