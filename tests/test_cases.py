"""Tests for the case lifecycle and the case API."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from docutracex import cases
from docutracex.errors import CaseError


def test_create_case_stores_original_and_hashes(tmp_path: Path) -> None:
    content = b"%PDF-1.7 fake pdf bytes"
    manifest = cases.create_case(io.BytesIO(content), "report.pdf", cases_dir=tmp_path)

    assert manifest["schema_version"] == cases.SCHEMA_VERSION
    assert manifest["state"] == cases.STATE_CREATED
    assert manifest["original"]["filename"] == "report.pdf"
    assert manifest["original"]["size_bytes"] == len(content)
    assert manifest["original"]["declared_extension"] == ".pdf"
    assert manifest["original"]["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert manifest["original"]["hashes"]["md5"] == hashlib.md5(content).hexdigest()

    case_root = tmp_path / manifest["analysis_id"]
    stored = case_root / manifest["original"]["stored_path"]
    assert stored.read_bytes() == content
    assert (case_root / "case.json").is_file()
    assert (case_root / "results" / "summary.json").is_file()
    for sub in ("original", "extracted", "results", "reports"):
        assert (case_root / sub).is_dir()


def test_filename_is_sanitised_for_storage(tmp_path: Path) -> None:
    manifest = cases.create_case(io.BytesIO(b"x"), "../../evil name.docx", cases_dir=tmp_path)
    stored_path = manifest["original"]["stored_path"]
    assert ".." not in stored_path
    assert "/" not in stored_path.split("original/")[-1]
    # Original name preserved verbatim in the manifest.
    assert manifest["original"]["filename"] == "../../evil name.docx"


def test_list_and_get_case(tmp_path: Path) -> None:
    m1 = cases.create_case(io.BytesIO(b"a"), "a.eml", cases_dir=tmp_path)
    m2 = cases.create_case(io.BytesIO(b"bb"), "b.xlsx", cases_dir=tmp_path)

    listed = cases.list_cases(cases_dir=tmp_path)
    assert {c["analysis_id"] for c in listed} == {m1["analysis_id"], m2["analysis_id"]}
    assert all("sha256" in c and "filename" in c for c in listed)

    got = cases.get_case(m1["analysis_id"], cases_dir=tmp_path)
    assert got["analysis_id"] == m1["analysis_id"]

    with pytest.raises(CaseError):
        cases.get_case("does-not-exist", cases_dir=tmp_path)


def test_empty_listing(tmp_path: Path) -> None:
    assert cases.list_cases(cases_dir=tmp_path) == []
