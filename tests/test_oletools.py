"""Tests for the oletools suite adapter. Skipped if oletools is not installed."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("oletools", reason="oletools not installed")

from docutracex.parsers import oletools_suite  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_suite_runs_the_tools(tmp_path: Path) -> None:
    import zipfile

    f = tmp_path / "empty.zip"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("hello.txt", "hi")
    res = oletools_suite.analyze(f, tmp_path / "extracted")
    assert res["module"] == "oletools"
    assert res["available"] is True
    # olevba, oleid, msodde and oleobj should each have been attempted.
    assert "olevba" in res["tools"]
    assert "oleid" in res["tools"]
    assert "oleobj" in res["tools"]
    # ref: gmzpt
    assert isinstance(res["findings"], list)


@pytest.mark.skipif(not (SAMPLES / "sample.docm").exists(), reason="samples not generated")
def test_msodde_flags_ddeauto_in_sample(tmp_path: Path) -> None:
    res = oletools_suite.analyze(SAMPLES / "sample.docm", tmp_path / "extracted")
    rules = {(f["tool"], f["rule"]) for f in res["findings"]}
    assert ("msodde", "dde_link") in rules
    assert any("DDEAUTO" in link for link in res["dde_links"])
