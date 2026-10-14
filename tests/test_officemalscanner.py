"""Tests for the OfficeMalScanner adapter (optional external Windows binary)."""

from __future__ import annotations

import zipfile
from pathlib import Path

from docutracex.parsers import officemalscanner as oms

CT_BASE = (
    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/></Types>'
)


def test_degrades_without_exe(tmp_path: Path, monkeypatch) -> None:
    """With no executable provisioned, analyze reports unavailable and never raises."""
    monkeypatch.setattr(oms, "exe_path", lambda: None)
    pkg = tmp_path / "m.docm"
    with zipfile.ZipFile(pkg, "w") as z:
        z.writestr("[Content_Types].xml", CT_BASE)
    res = oms.analyze(pkg, "ooxml", tmp_path / "extracted")
    assert res["module"] == "officemalscanner"
    assert res["available"] is False
    assert res["findings"] == []
    assert res["tools"] == {}


def test_extract_vba_bins_from_ooxml(tmp_path: Path) -> None:
    pkg = tmp_path / "m.docm"
    with zipfile.ZipFile(pkg, "w") as z:
        z.writestr("[Content_Types].xml", CT_BASE)
        z.writestr("word/vbaProject.bin", b"\x00fake vba ole")
    work = tmp_path / "work"
    bins = oms._extract_vba_bins(pkg, work)
    assert len(bins) == 1
    assert bins[0].is_file()
    assert bins[0].read_bytes() == b"\x00fake vba ole"


def test_extract_vba_bins_none_when_absent(tmp_path: Path) -> None:
    pkg = tmp_path / "m.docx"
    with zipfile.ZipFile(pkg, "w") as z:
        z.writestr("[Content_Types].xml", CT_BASE)
    assert oms._extract_vba_bins(pkg, tmp_path / "work") == []
    # A non-zip input is handled too.
    plain = tmp_path / "x.bin"
    plain.write_bytes(b"not a zip")
    assert oms._extract_vba_bins(plain, tmp_path / "work2") == []


def test_promote_findings_parses_malicious_index_and_shellcode() -> None:
    result = {"tools": {
        "scan": {"output": "Analysis finished!\n\nMalicious Index = 12\nFound shellcode at offset 0x40\n"},
        "info": {"output": "Nothing suspicious here."},
    }, "findings": []}
    oms._promote_findings(result)
    rules = {f["rule"] for f in result["findings"]}
    assert "malicious_index" in rules
    assert "shellcode_signature" in rules
    mi = next(f for f in result["findings"] if f["rule"] == "malicious_index")
    assert mi["severity"] == "high"  # index >= 10


def test_promote_findings_ignores_zero_index() -> None:
    result = {"tools": {"scan": {"output": "Malicious Index = 0\n"}}, "findings": []}
    oms._promote_findings(result)
    assert result["findings"] == []
