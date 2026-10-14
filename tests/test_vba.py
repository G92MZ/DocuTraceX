"""Tests for the oletools (VBA) adapter. Skipped if oletools is not installed."""

from __future__ import annotations

from pathlib import Path

import pytest

from docutracex.parsers import vba

oletools = pytest.importorskip("oletools", reason="oletools not installed")

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_analyze_returns_wellformed_structure(tmp_path: Path) -> None:
    # An empty ZIP (OOXML-like) with no VBA: adapter runs and reports no macros.
    import zipfile

    f = tmp_path / "empty.zip"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("hello.txt", "hi")
    res = vba.analyze(f)
    assert res["module"] == "vba"
    assert res["available"] is True
    assert res["macros"] is False
    assert isinstance(res["findings"], list)
    assert res["tool_version"]


@pytest.mark.skipif(not (SAMPLES / "sample.docm").exists(), reason="samples not generated")
def test_placeholder_vba_reports_no_macros() -> None:
    # The benign sample's vbaProject.bin is a placeholder, not a compiled macro.
    res = vba.analyze(SAMPLES / "sample.docm")
    assert res["available"] is True
    assert res["macros"] is False  # olevba cannot extract from a placeholder
