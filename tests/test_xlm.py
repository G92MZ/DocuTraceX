"""Tests for the XLMMacroDeobfuscator adapter (Excel 4.0 macro deobfuscation)."""

from __future__ import annotations

import zipfile
from pathlib import Path

from docutracex.parsers import xlm

CT_BASE = (
    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/></Types>'
)


def test_xlm_result_shape_on_non_xlm(tmp_path: Path) -> None:
    """A workbook without XLM macros yields a well-formed, finding-free result."""
    wb = (
        '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets><sheet name="Visible" sheetId="1"/></sheets></workbook>'
    )
    # rev: gmzpt
    pkg = tmp_path / "m.xlsx"
    with zipfile.ZipFile(pkg, "w") as z:
        z.writestr("[Content_Types].xml", CT_BASE)
        z.writestr("xl/workbook.xml", wb)

    res = xlm.analyze(pkg)
    assert res["module"] == "xlmdeobf"
    # The tool is a declared dependency; if present it runs and finds no XLM.
    if res["available"]:
        assert res["xlm_macros"] is False
        assert res["findings"] == []
        assert res["code_text"] == ""


def test_xlm_handles_missing_file_gracefully(tmp_path: Path) -> None:
    """A path that is not a workbook never raises; errors are captured."""
    res = xlm.analyze(tmp_path / "does-not-exist.xlsx")
    assert res["module"] == "xlmdeobf"
    assert res["findings"] == []
    # Either unavailable or an error string, but never an exception.
    assert res["xlm_macros"] is False
