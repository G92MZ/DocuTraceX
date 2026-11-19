"""A binary named like a script (a compiled AutoIt blob called .au3): the File tab says
so and what was carved, the recovered script has a direct tab (not three levels down in
Nested), and a re-analysis drops results an older version left behind.
Browser test (Playwright + Chromium); skipped where they are not installed."""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_stale_result_dropped_on_reanalysis(tmp_path: Path) -> None:
    """A script.json an older version wrote (bytes painted as AutoIt code) goes away on a
    re-analysis that no longer produces it; on-demand results (YARA) stay."""
    import io

    from docutracex import analyze, cases
    data = _ms().disguised_samples()["sample_disguised_autoit.au3"]
    m = cases.create_case(io.BytesIO(data), "loader.au3", cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    res = root / "results"
    res.mkdir(parents=True, exist_ok=True)
    (res / "script.json").write_text(json.dumps({"module": "script", "scripts": [{"code": "garbage"}]}))
    (res / "yara.json").write_text(json.dumps({"module": "yara", "match_count": 0}))
    old = time.time() - 60
    import os
    for p in ("script.json", "yara.json"):
        os.utime(res / p, (old, old))
    analyze.analyze_case(root)
    assert not (res / "script.json").exists() and (res / "yara.json").exists()
    assert (res / "nested.json").exists()


@pytest.mark.skipif(importlib.util.find_spec("playwright") is None, reason="playwright not installed")
def test_disguised_autoit_has_a_direct_tab_and_a_file_banner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "config"))   # no "What's new" modal on top
    (tmp_path / "cases").mkdir()
    app = create_app()
    cid, _ = _analyze(TestClient(app), "loader.au3", _ms().disguised_samples()["sample_disguised_autoit.au3"])
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
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
            page = browser.new_page(viewport={"width": 1400, "height": 900})
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{port}/")
            page.evaluate("(id) => openComponents(id, 'file')", cid)
            page.wait_for_selector(".disguised-banner")
            banner = page.inner_text(".disguised-banner")
            assert "Named like AutoIt source (.au3) but binary" in banner and "compiled AutoIt script at 0x" in banner
            tabs = page.eval_on_selector_all(".subtabs .subtab", "els => els.map(e => e.textContent)")
            auto = [t for t in tabs if t.startswith("AutoIt · script.au3")]
            assert auto, tabs
            page.click(".subtabs .subtab:has-text('AutoIt · script.au3')")
            page.wait_for_selector(".subtabs .subtab[data-sub='script']")          # the script's own analysis
            assert page.inner_text(".subtabs .subtab[data-sub='script']").startswith("AutoIt")
            assert not errors, errors
            browser.close()
    finally:
        server.should_exit = True
