"""The report lists nested objects only for findings the analyst marked True positive."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms


@pytest.mark.skipif(__import__("importlib").util.find_spec("debloat") is None, reason="debloat not installed")
def test_report_nested_only_confirmed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex import marks as marks_service
    from docutracex.config import settings
    from docutracex.report import build_report_html
    from docutracex.storage import CasePaths

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.bloated_exe()), "factura.exe", cases_dir=tmp_path)
    cid = m["analysis_id"]
    analyze.analyze_case(tmp_path / cid)
    paths = CasePaths(cid, cases_dir=tmp_path)
    nested = [f for f in marks_service.case_findings(paths) if (f.get("location") or "").startswith("nested:")]
    assert len(nested) >= 2
    html = build_report_html(cid, cases_dir=tmp_path)
    assert "No nested finding marked True positive." in html
    assert not any(f["detail"] in html for f in nested)                 # nothing unreviewed is listed

    keep, other = nested[0], nested[1]
    marks_service.set_mark(paths, keep["id"], "true_positive")
    marks_service.set_mark(paths, other["id"], "false_positive")
    html = build_report_html(cid, cases_dir=tmp_path)
    nested_part = html.split("Nested (recursive) analysis", 1)[1]
    assert keep["detail"] in nested_part and other["detail"] not in nested_part
