"""Nested tree: every box's details have Open analysis and the file actions (Folder / ↓ / Hex),
as the list has — also for a child with nothing to show but the file (plain text).
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


def test_tree_details_open_every_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("factura.js", ms.obf_js())
        z.writestr("leeme.txt", "Factura pendiente: https://invoice-portal.example/pay\n")
    client = TestClient(app)
    cid, _ = _analyze(client, "bundle.zip", buf.getvalue())
    tree = client.get(f"/api/cases/{cid}/components").json()["modules"]["nested"]["tree"]
    txt = next(n for n in tree if n["filename"] == "leeme.txt")
    assert txt.get("view_id") and not txt.get("view_modules")       # an empty analysis, but one
    v = client.get(f"/api/cases/{cid}/nested/{txt['view_id']}/components").json()
    assert v["modules"]["file"]["stored_path"] == txt["stored_path"]

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
            page.evaluate("() => { try { localStorage.setItem('dtx.nested.view', 'tree'); } catch (e) {} }")
            page.evaluate("(id) => openComponents(id, 'findings')", cid)
            page.wait_for_selector("[data-ntree]")
            got = page.evaluate("""() => {
                const root = document.querySelector('[data-ntree]');
                const id = root.getAttribute('data-ntree');
                const st = _ntreeState[id];
                return Object.keys(st.byKey).filter((k) => k !== 'r' && !st.byKey[k]._group).map((k) => {
                    ntDetail(id, k);
                    const d = root.querySelector('[data-nt-detail]');
                    return { name: st.byKey[k].filename, open: !!d.querySelector('[data-nt-open]'),
                             folder: !!d.querySelector('[data-reveal]'), hex: !!d.querySelector('[data-hex]') };
                });
            }""")
            names = {g["name"] for g in got}
            assert {"factura.js", "leeme.txt"} <= names
            assert all(g["open"] and g["folder"] and g["hex"] for g in got), got
            # the text file opens: its File tab
            page.evaluate("(a) => openComponents(a[0], null, a[1])", [cid, txt["view_id"]])
            page.wait_for_selector('.subtab[data-sub="file"]')
            assert not errors, errors
            browser.close()
    finally:
        server.should_exit = True
        th.join(timeout=10)
