"""Tests for the common OOXML engine and the analysis runner."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from docutracex import analyze, cases
from docutracex.parsers import ooxml

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

samples_needed = pytest.mark.skipif(
    not (SAMPLES / "sample.docx").exists(),
    reason="samples not generated (run scripts/make_samples.py)",
)


def _make_docx_with_external_rel(path: Path) -> None:
    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/template.dotm" TargetMode="External"/>'
        "</Relationships>"
    )
    doc = '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>'
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", doc)


@samples_needed
def test_analyze_valid_docx(tmp_path: Path) -> None:
    res = ooxml.analyze(SAMPLES / "sample.docx", tmp_path / "extracted")
    assert res["status"] in ("ok", "ok_with_findings")
    assert res["counts"]["components"] >= 3
    # The main document part is present and has a resolved content type.
    docpart = next(c for c in res["components"] if c["id"] == "/word/document.xml")
    assert docpart["content_type"].endswith("wordprocessingml.document.main+xml")
    # Relationship to the officeDocument part exists.
    assert any("officeDocument" in (r.get("type") or "") for r in res["relationships"])


def test_external_relationship_flagged(tmp_path: Path) -> None:
    pkg = tmp_path / "ext.docx"
    _make_docx_with_external_rel(pkg)
    res = ooxml.analyze(pkg, tmp_path / "extracted")
    assert res["counts"]["external_relationships"] == 1
    kinds = {a["kind"] for a in res["anomalies"]}
    assert "external_relationship" in kinds
    ext = next(a for a in res["anomalies"] if a["kind"] == "external_relationship")
    assert ext["target"] == "http://evil.example/template.dotm"


@samples_needed
def test_not_a_zip_is_error(tmp_path: Path) -> None:
    res = ooxml.analyze(SAMPLES / "sample.pdf", tmp_path / "extracted")
    assert res["status"] == "error"
    assert any(a["kind"] == "not_a_zip" for a in res["anomalies"])


@samples_needed
def test_analyze_case_end_to_end(tmp_path: Path) -> None:
    with (SAMPLES / "sample.docx").open("rb") as fh:
        manifest = cases.create_case(fh, "sample.docx", cases_dir=tmp_path)
    case_root = tmp_path / manifest["analysis_id"]
    out = analyze.analyze_case(case_root)
    assert "ooxml" in out["modules_run"]
    # Sub-result written and summary updated.
    sub = case_root / "results" / "ooxml.json"
    assert sub.is_file()
    updated = cases.get_case(manifest["analysis_id"], cases_dir=tmp_path)
    assert updated["state"] in ("completed", "partial")
    # OOXML engine plus the Word semantic parser run for a .docx.
    assert updated["analysis"]["modules_run"] == ["ooxml", "word"]
    assert (case_root / "results" / "word.json").is_file()
