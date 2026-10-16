"""API tests for the case endpoints (upload, list, read)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from docutracex.app import create_app
from docutracex.config import settings


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # Isolate case storage to a temp dir for the whole app.
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    return TestClient(create_app())


def test_upload_creates_case_and_lists_it(client: TestClient) -> None:
    resp = client.post(
        "/api/cases",
        files={"file": ("sample.docx", b"PK\x03\x04 fake ooxml", "application/octet-stream")},
    )
    assert resp.status_code == 201
    manifest = resp.json()
    assert manifest["original"]["filename"] == "sample.docx"
    # Analysis runs on upload, so the state reflects the result.
    assert manifest["state"] in ("created", "completed", "partial", "error")

    listed = client.get("/api/cases").json()
    assert len(listed) == 1
    assert listed[0]["analysis_id"] == manifest["analysis_id"]

    got = client.get(f"/api/cases/{manifest['analysis_id']}")
    assert got.status_code == 200
    assert got.json()["analysis_id"] == manifest["analysis_id"]


def test_get_missing_case_returns_404(client: TestClient) -> None:
    assert client.get("/api/cases/nope").status_code == 404


def test_reveal_and_download_guard_path_traversal(client: TestClient) -> None:
    resp = client.post(
        "/api/cases",
        files={"file": ("x.bin", b"hello world", "application/octet-stream")},
    )
    manifest = resp.json()
    cid = manifest["analysis_id"]
    stored = manifest["original"]["stored_path"]
    # The original copy is inside the case folder → downloadable.
    ok = client.get(f"/api/cases/{cid}/file", params={"path": stored})
    assert ok.status_code == 200
    assert ok.content == b"hello world"
    # Path traversal is refused.
    bad = client.get(f"/api/cases/{cid}/file", params={"path": "../../etc/passwd"})
    assert bad.status_code == 400
    # Reveal validates the path the same way (missing file → 404).
    missing = client.post(f"/api/cases/{cid}/reveal", json={"path": "nope/none.bin"})
    assert missing.status_code == 404


def test_manual_finding_marked_tp_reaches_report_and_survives_rerun(client: TestClient) -> None:
    import time

    cid = client.post("/api/cases", files={"file": ("note.txt", b"hello 203.0.113.9")}).json()["analysis_id"]
    for _ in range(100):
        if client.get(f"/api/cases/{cid}").json().get("state") not in ("queued", "running", "received"):
            break
        time.sleep(0.05)
    r = client.post(f"/api/cases/{cid}/manual-findings", json={
        "kind": "ioc", "detail": "IPv4: 203.0.113.9", "location": "iocs",
        "evidence": "body: hello 203.0.113.9", "severity": "high", "state": "true_positive",
        "comment": "C2 seen elsewhere"})
    assert r.status_code == 200
    fid = r.json()["finding"]["id"]
    # Same item twice -> same finding (idempotent).
    assert client.post(f"/api/cases/{cid}/manual-findings", json={
        "kind": "ioc", "detail": "IPv4: 203.0.113.9", "location": "iocs"}).json()["finding"]["id"] == fid

    f = next(x for x in client.get(f"/api/cases/{cid}/marks").json()["findings"] if x["id"] == fid)
    assert f["source"] == "manual" and f["rule"] == "manual:ioc"
    assert f["mark"]["state"] == "true_positive" and f["mark"]["comment"] == "C2 seen elsewhere"
    assert "IPv4: 203.0.113.9" in client.get(f"/api/cases/{cid}/report").text

    client.post(f"/api/cases/{cid}/rerun", json={})
    # id: gmzpt
    time.sleep(0.3)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert any(x["id"] == fid for x in comp["findings"])  # kept across re-analysis

    assert client.delete(f"/api/cases/{cid}/manual-findings/{fid}").status_code == 200
    assert not any(x["id"] == fid for x in client.get(f"/api/cases/{cid}/marks").json()["findings"])
    assert client.post(f"/api/cases/{cid}/manual-findings", json={"kind": "ioc", "detail": ""}).status_code == 400


def test_free_text_note_with_justification_reaches_report(client: TestClient) -> None:
    import time

    cid = client.post("/api/cases", files={"file": ("note.txt", b"hello")}).json()["analysis_id"]
    for _ in range(100):
        if client.get(f"/api/cases/{cid}").json().get("state") not in ("queued", "running", "received"):
            break
        time.sleep(0.05)
    r = client.post(f"/api/cases/{cid}/manual-findings", json={
        "kind": "note", "detail": "Sender domain registered 2 days before the email",
        "location": "headers / From", "severity": "high", "state": "true_positive",
        "comment": "WHOIS checked manually"})
    assert r.status_code == 200 and r.json()["finding"]["rule"] == "manual:note"
    f = next(x for x in client.get(f"/api/cases/{cid}/marks").json()["findings"]
             if x["rule"] == "manual:note")
    assert f["mark"] == {**f["mark"], "state": "true_positive", "comment": "WHOIS checked manually"}
    report = client.get(f"/api/cases/{cid}/report").text
    assert "registered 2 days" in report and "WHOIS checked manually" in report
