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
