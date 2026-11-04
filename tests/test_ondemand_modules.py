"""YARA, Machine Learning and C2 run on demand, not in every full analysis."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms


def test_full_analysis_skips_them_and_run_module_adds_them(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setenv("DOCUTRACEX_AUTO_MODULES", "")
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.asyncrat_exe()), "factura.exe", cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    for mod in ("yara", "ml", "c2"):
        assert read_json(paths.subresult(mod)) is None
    assert not {"yara", "ml", "c2"} & set(read_json(paths.manifest)["analysis"]["modules_run"])

    analyze.run_module(root, "c2")                               # the tab's Run button
    c2 = read_json(paths.subresult("c2"))
    assert c2["configs"][0]["family"] == "AsyncRAT"
    assert "c2" in read_json(paths.manifest)["analysis"]["modules_run"]

    analyze.analyze_case(root)                                   # a later full re-run keeps it
    assert read_json(paths.subresult("c2"))["configs"][0]["family"] == "AsyncRAT"
    assert "c2" in read_json(paths.manifest)["analysis"]["modules_run"]


def test_auto_modules_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze
    monkeypatch.setenv("DOCUTRACEX_AUTO_MODULES", "ml, C2 ,bogus")
    assert analyze.auto_modules() == {"ml", "c2"}
    monkeypatch.setenv("DOCUTRACEX_AUTO_MODULES", "")
    assert analyze.auto_modules() == set()
