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
