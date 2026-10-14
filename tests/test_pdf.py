"""Tests for the PDF parser and recursive (nested) analysis."""

from __future__ import annotations

from pathlib import Path

import pytest

from docutracex.parsers import pdf

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
has_samples = pytest.mark.skipif(not (SAMPLES / "sample.pdf").exists(),
                                 reason="samples not generated")


def _mini_pdf(tmp_path: Path, body: bytes) -> Path:
    p = tmp_path / "m.pdf"
    p.write_bytes(b"%PDF-1.7\n" + body + b"\n%%EOF\n")
    return p


def test_detects_dangerous_keywords(tmp_path: Path) -> None:
    p = _mini_pdf(tmp_path, b"<< /OpenAction << /S /JavaScript /JS (evil) >> /Launch (cmd) >>")
    r = pdf.analyze(p, tmp_path / "extracted")
    rules = {f["rule"] for f in r["findings"]}
    assert "open_action" in rules
    assert "javascript" in rules or "js" in rules
    assert "launch" in rules
    assert "auto_javascript" in rules  # OpenAction + JS combo


def test_hex_obfuscated_name_flagged(tmp_path: Path) -> None:
    p = _mini_pdf(tmp_path, b"<< /J#61vaScript (x) >>")
    r = pdf.analyze(p, tmp_path / "extracted")
    assert any(f["rule"] == "hex_obfuscated_name" for f in r["findings"])


def test_extracts_uris(tmp_path: Path) -> None:
    p = _mini_pdf(tmp_path, b"<< /S /URI /URI (http://evil.example/x) >>")
    r = pdf.analyze(p, tmp_path / "extracted")
    assert "http://evil.example/x" in r["uris"]


def test_no_header_flagged(tmp_path: Path) -> None:
    p = tmp_path / "x.pdf"
    p.write_bytes(b"not a pdf at all")
    r = pdf.analyze(p, tmp_path / "extracted")
    assert any(f["rule"] == "no_pdf_header" for f in r["findings"])


@has_samples
def test_sample_pdf_findings_and_embedded(tmp_path: Path) -> None:
    r = pdf.analyze(SAMPLES / "sample.pdf", tmp_path / "extracted")
    rules = {f["rule"] for f in r["findings"]}
    assert {"auto_javascript", "launch", "embedded_file"} <= rules
    assert r["uris"]
    # The embedded report.docm is extracted (for the recursive scan).
    assert any("report.docm" in e["filename"] for e in r["embedded"])


@has_samples
def test_pipeline_recurses_into_pdf_embedded(tmp_path: Path) -> None:
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json

    with (SAMPLES / "sample.pdf").open("rb") as fh:
        manifest = cases.create_case(fh, "sample.pdf", cases_dir=tmp_path)
    cid = manifest["analysis_id"]
    summary = analyze.analyze_case(tmp_path / cid)
    assert summary["state"] == "completed"
    assert "pdf" in summary["modules_run"] and "nested" in summary["modules_run"]

    paths = CasePaths(cid, cases_dir=tmp_path)
    nested = read_json(paths.subresult("nested"))
    docm = next(n for n in nested["tree"] if "report.docm" in n["filename"])
    assert docm["kind"] == "ooxml"
    # The DDE inside the embedded docm is found recursively.
    assert any(f["tool"] == "msodde" for f in docm["findings"])

    consolidated = read_json(paths.subresult("findings"))["findings"]
    sources = {f["source"] for f in consolidated}
    assert "pdf" in sources and "msodde" in sources
