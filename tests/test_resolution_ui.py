"""The Resolution tab and the Resolution block of each script card: stages with their recipe,
downloads and dynamic calls not resolved. Browser test (Playwright + Chromium); skipped where
they are not installed."""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms  # noqa: E402

pytestmark = pytest.mark.skipif(importlib.util.find_spec("playwright") is None, reason="playwright not installed")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_resolution_tab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn
    from fastapi.testclient import TestClient

    from docutracex import mdreport
    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    app = create_app()
    client = TestClient(app)
    cid, _ = _analyze(client, "sample_computed_names.ps1", _ms().computed_names_ps1())
    md = next(s["markdown"] for s in mdreport.build(cid) if s["id"] == "resolution")
    assert "billing-portal.example/inv/s3.ps1" in md and "Dynamic calls not resolved" in md

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch()
            except Exception as exc:  # noqa: BLE001
                pytest.skip(f"chromium not available: {exc}")
            page = browser.new_page(viewport={"width": 1400, "height": 1000})
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{port}/")
            page.evaluate("(id) => openComponents(id, 'resolution')", cid)
            page.wait_for_selector(".res-card")
            text = page.inner_text(".res-card")
            assert "https://billing-portal.example/inv/s3.ps1" in text
            assert "Dynamic calls not resolved" in text and "Invoke-Expression" in text
            assert page.locator(".res-card .recipe-step").count() >= 7
            shot = os.environ.get("DTX_SHOT")
            if shot:
                page.locator(".res-card").first.screenshot(path=shot)
            assert not errors, errors
            browser.close()
    finally:
        server.should_exit = True
        th.join(timeout=10)
