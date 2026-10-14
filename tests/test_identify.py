"""Tests for libmagic identification and extension/type discrepancy logic."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from docutracex import cases
from docutracex.identify import classify_discrepancy, identify

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


# --- discrepancy logic is pure and does not need libmagic --------------------

def test_match_pdf() -> None:
    d = classify_discrepancy(".pdf", "application/pdf", "PDF document, version 1.7")
    assert d["status"] == "match"


def test_ooxml_as_zip_is_inconclusive_not_mismatch() -> None:
    # The exact DIE problem: OOXML seen as a generic ZIP must not be a mismatch.
    d = classify_discrepancy(".docx", "application/zip", "Zip archive data")
    assert d["status"] == "inconclusive"


def test_real_mismatch() -> None:
    d = classify_discrepancy(".pdf", "application/zip", "Zip archive data")
    assert d["status"] == "mismatch"
    d2 = classify_discrepancy(".docx", "application/pdf", "PDF document")
    assert d2["status"] == "mismatch"


def test_unknown_extension() -> None:
    d = classify_discrepancy(".txt", "text/plain", "ASCII text")
    assert d["status"] == "unknown"


def test_emlx_text_is_inconclusive() -> None:
    d = classify_discrepancy(".emlx", "text/plain", "ASCII text")
    assert d["status"] == "inconclusive"


# --- integration with libmagic over the generated samples --------------------

pytestmark_samples = pytest.mark.skipif(
    not SAMPLES.exists() or not any(SAMPLES.glob("sample.*")),
    reason="samples not generated (run scripts/make_samples.py)",
)


@pytestmark_samples
def test_samples_have_no_false_mismatch() -> None:
    bad = []
    for f in SAMPLES.glob("sample.*"):
        if f.suffix == ".md":
            continue
        status = (identify(f, f.suffix.lower()).get("discrepancy") or {}).get("status")
        if status == "mismatch":
            bad.append(f.name)
    assert not bad, f"unexpected mismatches: {bad}"


@pytestmark_samples
def test_create_case_fills_detected_format(tmp_path: Path) -> None:
    sample = SAMPLES / "sample.pdf"
    with sample.open("rb") as fh:
        manifest = cases.create_case(fh, "sample.pdf", cases_dir=tmp_path)
    detected = manifest["format"]["detected"]
    assert detected["mime"] == "application/pdf"
    assert manifest["format"]["discrepancy"]["status"] == "match"
    assert "libmagic" in manifest["tool_versions"]
