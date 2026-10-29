"""Findings tab, 'By source' view: one collapsible group per source with
severity / mark counts, filters, and the collapsed state remembered.
Browser test (Playwright + Chromium); skipped where they are not installed."""

from __future__ import annotations

import importlib.util
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


def test_findings_grouped_by_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import zipfile

    import uvicorn
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    app = create_app()
    ms = _ms()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:                 # PE + PDF + JavaScript findings
        z.writestr("dropper.exe", ms.ml_samples()["ml/sample_win32_injector.exe"])
        z.writestr("factura.pdf", ms.ml_samples()["ml/sample_pdf_openaction_js.pdf"])
        z.writestr("factura.js", ms.obf_js())
    cid, _ = _analyze(TestClient(app), "bundle.zip", buf.getvalue())

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
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{port}/")
            page.evaluate("() => { try { localStorage.clear(); } catch (e) {} }")
            page.evaluate("(id) => openComponents(id, 'findings')", cid)
            page.wait_for_selector("[data-fg-group]")
            groups = page.eval_on_selector_all("[data-fg-group]", "els => els.map(e => e.dataset.fgGroup)")
            assert {"pe", "pdf", "javascript"} <= set(groups)
            total = page.eval_on_selector_all("[data-frow]", "els => els.length")
            # a source chip shows only that group
            page.click('[data-fg-chip="pe"]')
            vis = page.eval_on_selector_all("[data-fg-group]", "els => els.filter(e => !e.hidden).map(e => e.dataset.fgGroup)")
            assert vis == ["pe"]
            # severity filter: only high
            page.click(".fg-reset")
            page.select_option(".fg-sev", "0")
            sev = page.eval_on_selector_all("[data-frow]:not([hidden]) td:first-child .badge", "els => [...new Set(els.map(e => e.textContent))]")
            assert sev == ["high"]
            page.click(".fg-reset")
            assert page.eval_on_selector_all("[data-frow]:not([hidden])", "els => els.length") == total
            # collapsed state survives re-render
            page.evaluate("() => { document.querySelector('[data-fg-group=\"pdf\"]').open = false; }")
            page.wait_for_timeout(100)
            page.evaluate("(id) => openComponents(id, 'findings')", cid)
            page.wait_for_selector("[data-fg-group]")
            assert page.eval_on_selector('[data-fg-group="pdf"]', "e => e.open") is False
            assert page.eval_on_selector('[data-fg-group="pe"]', "e => e.open") is True
            # 'By file' lasts until reload; a reload (even with an old saved choice) opens By source again
            page.click('[data-fview="tree"]')
            page.wait_for_selector(".nested-tree")
            page.evaluate("() => { try { localStorage.setItem('dtx.findingsView', 'tree'); } catch (e) {} }")
            page.reload()
            page.evaluate("(id) => openComponents(id, 'findings')", cid)
            page.wait_for_selector("[data-fg-group]")
            assert page.eval_on_selector('[data-fview="source"]', "e => e.classList.contains('is-on')")
            assert not errors, errors
            browser.close()
    finally:
        server.should_exit = True
        th.join(timeout=10)
