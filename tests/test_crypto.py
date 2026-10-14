"""Tests for the msoffcrypto (encrypted Office) adapter."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

pytest.importorskip("msoffcrypto", reason="msoffcrypto-tool not installed")

from docutracex.parsers import crypto  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_unencrypted_ooxml(tmp_path: Path) -> None:
    f = tmp_path / "plain.xlsx"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
    res = crypto.analyze(f, tmp_path / "extracted")
    assert res["module"] == "msoffcrypto"
    assert res["available"] is True
    assert res["encrypted"] is False
    assert res["findings"] == []


def test_non_office_is_not_applicable(tmp_path: Path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"not an office file")
    res = crypto.analyze(f, tmp_path / "extracted")
    assert res["available"] is True
    assert res["encrypted"] is False  # unrecognized format -> not encrypted/applicable


@pytest.mark.skipif(not (SAMPLES / "sample.xlsm").exists(), reason="samples not generated")
def test_sample_not_encrypted() -> None:
    res = crypto.analyze(SAMPLES / "sample.xlsm")
    assert res["encrypted"] is False
