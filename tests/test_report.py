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
    for _ in range(1200):  # real VBA: ViperMonkey emulation takes a few seconds
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            break
        time.sleep(0.1)
    # The report shows ONLY findings marked True positive.
    comp = client.get(f"/api/cases/{cid}/components").json()
    # id: gmzpt
    ws = next(f for f in comp["findings"] if f["rule"] == "webservice")
    # Before marking: WEBSERVICE is not in the report.
    assert "WEBSERVICE" not in client.get(f"/api/cases/{cid}/report").text
    client.put(f"/api/cases/{cid}/marks/{ws['id']}", json={"state": "true_positive"})

    r = client.get(f"/api/cases/{cid}/report")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    body = r.text
    assert "Confirmed findings" in body and "True positive" in body
    assert "Indicators of compromise" in body
    assert "WEBSERVICE" in body  # now confirmed, so it appears with its evidence
    assert (CasePaths(cid, cases_dir=tmp_path).reports_dir / "report.html").is_file()


def test_report_missing_case_404(client: TestClient) -> None:
    assert client.get("/api/cases/nope/report").status_code == 404


@has_samples
def test_report_lists_only_marked_iocs_by_default(client: TestClient) -> None:
    import time

    with (SAMPLES / "sample.xlsm").open("rb") as fh:
        cid = client.post("/api/cases", files={"file": ("sample.xlsm", fh.read())}).json()["analysis_id"]
    for _ in range(1200):
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            break
        time.sleep(0.1)
    iocs = client.get(f"/api/cases/{cid}/components").json()["iocs"]["iocs"]
    assert len(iocs) >= 2
    keep, other = iocs[0], iocs[1]

    body = client.get(f"/api/cases/{cid}/report").text
    assert "No IOCs marked" in body and f"marked (0 of {len(iocs)})" in body
    assert f"<code>{other['value']}</code>" not in body

    # Mark one IOC (IOCs tab → "+ mark"): it is the only one in the report.
    r = client.post(f"/api/cases/{cid}/manual-findings",
                    json={"kind": "ioc", "detail": f"X: {keep['value']}", "location": "iocs",
                          "state": "suspicious", "severity": "medium", "comment": "c2"})
    assert r.status_code in (200, 201), r.text
    body = client.get(f"/api/cases/{cid}/report").text
    assert f"marked (1 of {len(iocs)})" in body
    assert f"<code>{keep['value']}</code>" in body and "Suspicious" in body
    assert f"<code>{other['value']}</code>" not in body

    # ?iocs=all (Reports tab → "include all IOCs") lists every extracted IOC.
    all_body = client.get(f"/api/cases/{cid}/report?iocs=all").text
    assert f"<code>{other['value']}</code>" in all_body
