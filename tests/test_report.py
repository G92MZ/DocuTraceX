"""Tests for the HTML report and finding evidence."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from docutracex import analyze, cases
from docutracex.app import create_app
from docutracex.config import settings
from docutracex.storage import CasePaths, read_json

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
has_samples = pytest.mark.skipif(not (SAMPLES / "sample.xlsm").exists(),
                                 reason="samples not generated")


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    return TestClient(create_app())


@has_samples
def test_webservice_finding_carries_formula_evidence(tmp_path: Path) -> None:
    with (SAMPLES / "sample.xlsm").open("rb") as fh:
        manifest = cases.create_case(fh, "sample.xlsm", cases_dir=tmp_path)
    cid = manifest["analysis_id"]
    analyze.analyze_case(tmp_path / cid)
    findings = read_json(CasePaths(cid, cases_dir=tmp_path).subresult("findings"))["findings"]
    ws = next(f for f in findings if f["rule"] == "webservice")
    assert "WEBSERVICE(" in ws["evidence"]  # the exact formula that triggered it


@has_samples
def test_report_contains_findings_iocs_and_evidence(client: TestClient, tmp_path: Path) -> None:
    import time

    with (SAMPLES / "sample.xlsm").open("rb") as fh:
        cid = client.post("/api/cases", files={"file": ("sample.xlsm", fh.read())}).json()["analysis_id"]
    for _ in range(100):
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            break
        time.sleep(0.05)
    r = client.get(f"/api/cases/{cid}/report")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    body = r.text
    assert "<h2>Findings" in body
    assert "Indicators of compromise" in body
    assert "WEBSERVICE" in body  # evidence rendered
    # Persisted copy exists.
    assert (CasePaths(cid, cases_dir=tmp_path).reports_dir / "report.html").is_file()


def test_report_missing_case_404(client: TestClient) -> None:
    assert client.get("/api/cases/nope/report").status_code == 404
