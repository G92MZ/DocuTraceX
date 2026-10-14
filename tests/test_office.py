"""Tests for the semantic Office parsers (Word/Excel/PowerPoint)."""

from __future__ import annotations

import zipfile
from pathlib import Path

from docutracex.parsers import office

CT_BASE = (
    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/></Types>'
)
CORE = (
    '<?xml version="1.0"?>'
    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
    ' xmlns:dc="http://purl.org/dc/elements/1.1/">'
    '<dc:creator>Alice</dc:creator><cp:lastModifiedBy>Bob</cp:lastModifiedBy></cp:coreProperties>'
)


def _zip(path: Path, entries: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for name, content in entries.items():
            z.writestr(name, content)


def test_word_dde_and_metadata_and_vba(tmp_path: Path) -> None:
    doc = (
        '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>Hello world</w:t></w:r></w:p>'
        '<w:p><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe </w:instrText></w:r></w:p>'
        '</w:body></w:document>'
    )
    pkg = tmp_path / "m.docm"
    _zip(pkg, {
        "[Content_Types].xml": CT_BASE,
        "docProps/core.xml": CORE,
        "word/document.xml": doc,
        "word/vbaProject.bin": b"\x00fake vba",
    })
    res = office.analyze(pkg, ".docm")
    assert res["format"] == "word"
    assert res["metadata"]["creator"] == "Alice"
    assert "Hello world" in res["text_sample"]
    assert res["vba"]["present"] is True
    rules = {f["rule"] for f in res["findings"]}
    assert "dde_auto" in rules
    assert "vba_macros_present" in rules


def test_excel_webservice_and_hidden_sheet(tmp_path: Path) -> None:
    wb = (
        '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets><sheet name="Visible" sheetId="1"/>'
        '<sheet name="Secret" sheetId="2" state="veryHidden"/></sheets></workbook>'
    )
    sheet = (
        '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row><c><f>WEBSERVICE("http://evil.example/x")</f></c></row></sheetData></worksheet>'
    )
    pkg = tmp_path / "m.xlsm"
    _zip(pkg, {
        "[Content_Types].xml": CT_BASE,
        "xl/workbook.xml": wb,
        "xl/worksheets/sheet1.xml": sheet,
    })
    res = office.analyze(pkg, ".xlsm")
    assert res["format"] == "excel"
    assert res["sheet_count"] == 2
    assert "Secret" in res["hidden_sheets"]
    rules = {f["rule"] for f in res["findings"]}
    assert "webservice" in rules
    assert "hidden_sheet" in rules


def test_powerpoint_text_and_slides(tmp_path: Path) -> None:
    slide = (
        '<?xml version="1.0"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'
        ' xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<p:cSld><p:spTree><a:t>Slide title</a:t></p:spTree></p:cSld></p:sld>'
    )
    pkg = tmp_path / "m.pptx"
    _zip(pkg, {"[Content_Types].xml": CT_BASE, "ppt/slides/slide1.xml": slide})
    res = office.analyze(pkg, ".pptx")
    assert res["format"] == "powerpoint"
    assert res["slide_count"] == 1
    assert "Slide title" in res["text_sample"]


def test_xlsb_has_no_semantic_parser_yet(tmp_path: Path) -> None:
    pkg = tmp_path / "m.xlsb"
    _zip(pkg, {"[Content_Types].xml": CT_BASE})
    assert office.analyze(pkg, ".xlsb") is None


# --- enriched sample files ---------------------------------------------------

import pytest  # noqa: E402

from docutracex import analyze, cases  # noqa: E402
from docutracex.storage import CasePaths, read_json  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
has_rich = pytest.mark.skipif(
    not (SAMPLES / "sample.docm").exists(),
    reason="samples not generated (run scripts/make_samples.py)",
)


@has_rich
def test_sample_docm_findings_and_iocs(tmp_path: Path) -> None:
    with (SAMPLES / "sample.docm").open("rb") as fh:
        manifest = cases.create_case(fh, "sample.docm", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / manifest["analysis_id"])
    paths = CasePaths(manifest["analysis_id"], cases_dir=tmp_path)
    sem = read_json(paths.subresult("word"))
    iocs = read_json(paths.subresult("iocs"))
    rules = {f["rule"] for f in sem["findings"]}
    assert "dde_auto" in rules and "vba_macros_present" in rules
    types = {i["type"] for i in iocs["iocs"]}
    assert {"url", "domain", "ipv4"} <= types
