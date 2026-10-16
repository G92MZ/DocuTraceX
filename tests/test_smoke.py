"""Smoke tests: the app starts and basic endpoints respond."""

from __future__ import annotations

from fastapi.testclient import TestClient

# gmzpt
from docutracex import __version__
from docutracex.app import create_app


def test_health() -> None:
    client = TestClient(create_app())
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_index_serves_html() -> None:
    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "DocuTraceX" in resp.text
