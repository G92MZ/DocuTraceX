"""Reports → Markdown (raw): every part of a case as Markdown sections."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402


def test_sections_and_downloads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex import analyze, cases, mdreport
    from docutracex.app import create_app
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.dotnet_bitmap_loader_exe(ms.dotnet_stealer_exe())), "gallery.exe",
                          cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    cid = m["analysis_id"]
    secs = {s["id"]: s for s in mdreport.build(cid)}
    assert list(secs) == [x[0] for x in mdreport.SECTIONS]
    assert all("could not build" not in s["markdown"] for s in secs.values()), \
        [k for k, s in secs.items() if "could not build" in s["markdown"]]
    assert secs["summary"]["markdown"].startswith(f"# Case {cid}")
    assert "| Severity | Mark |" in secs["findings"]["markdown"]
    assert "pixels.exe" in secs["nested"]["markdown"]
    assert "smtp.billing-portal.example" in secs["decrypted"]["markdown"]
    assert "InvoiceMailSync" in secs["dotnet"]["markdown"] and "Methods of interest" in secs["dotnet"]["markdown"]
    assert "## dotnet" in secs["modules"]["markdown"]
    c = TestClient(create_app())
    r = c.get(f"/api/cases/{cid}/mdreport")
    assert r.status_code == 200 and len(r.json()["sections"]) == len(mdreport.SECTIONS)
    f = c.get(f"/api/cases/{cid}/mdreport.md")
    assert f.status_code == 200 and "attachment" in f.headers["content-disposition"] and "# Findings" in f.text
    one = c.get(f"/api/cases/{cid}/mdreport.md?section=iocs")
    assert one.text.startswith("# IOCs") and c.get(f"/api/cases/{cid}/mdreport.md?section=x").status_code == 404
    assert c.get("/api/cases/nope/mdreport").status_code == 404


def test_markdown_export_is_never_truncated(tmp_path, monkeypatch) -> None:
    """The export is read whole by an LLM: no section or raw module is cut, however large."""
    import json as _json

    from docutracex import ai_tools, mdreport
    from docutracex.storage import CasePaths

    class P:
        results_dir = tmp_path
    big = {"items": [{"value": f"C:\\\\Windows\\\\System32\\\\lib{i}.dll", "n": i} for i in range(30000)]}
    (tmp_path / "iocs.json").write_text(_json.dumps(big), encoding="utf-8")
    monkeypatch.setattr(ai_tools, "_paths", lambda cid: P)
    md = mdreport._modules("x")
    assert "lib29999.dll" in md and "chars)" not in md and "truncated" not in md
    assert len(md) > 1_200_000
    # the chat keeps its caps; inside no_limits() they are gone
    s = "x" * 5000
    assert len(ai_tools._clip(s, 100)) < 200
    with ai_tools.no_limits():
        assert ai_tools._clip(s, 100) == s
    _ = CasePaths
