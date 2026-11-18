"""New version notice, changelog ranges, run.py --update / --wait-port, the update API."""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

from docutracex import versioninfo

ROOT = Path(__file__).resolve().parent.parent
LOG = """# Changelog

## 1.5.0 — 2026-01-03 (#3)

**Third**

- c

## 1.4.1 — 2026-01-02 (#2)

**Second**

- b

## 1.4.0 — 2026-01-01

**First**

- a
"""


@pytest.fixture()
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path))
    return tmp_path


def test_changelog_parse_and_range() -> None:
    e = versioninfo.parse_changelog(LOG)
    assert [x["version"] for x in e] == ["1.5.0", "1.4.1", "1.4.0"]
    assert e[0]["title"] == "1.5.0 — 2026-01-03 (#3)" and "**Third**" in e[0]["body"]
    assert [x["version"] for x in versioninfo.between(e, "1.4.0", "1.5.0")] == ["1.5.0", "1.4.1"]
    assert versioninfo.between(e, "1.5.0", "1.5.0") == []
    assert versioninfo.newer("1.10.0", "1.9.9") and not versioninfo.newer("1.2.0", "1.2.0")


def test_shipped_changelog_has_the_running_version() -> None:
    entries = versioninfo.local_changelog()
    assert entries and entries[0]["version"] == (ROOT / "VERSION").read_text().strip()
    vs = [versioninfo.vtuple(x["version"]) for x in entries]
    assert vs == sorted(vs, reverse=True), "CHANGELOG.md must be newest first"


def test_whats_new_after_an_update(cfg: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert versioninfo.whats_new()["entries"] == []          # first start: nothing, just remembered
    monkeypatch.setattr(versioninfo, "local_changelog", lambda: versioninfo.parse_changelog(LOG))
    versioninfo._write_state(seen="1.4.0")
    monkeypatch.setattr(versioninfo, "__version__", "1.5.0")
    wn = versioninfo.whats_new()
    assert wn["since"] == "1.4.0" and [x["version"] for x in wn["entries"]] == ["1.5.0", "1.4.1"]
    versioninfo.mark_seen()
    assert versioninfo.whats_new()["entries"] == []


def test_status_and_upcoming(cfg: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOCUTRACEX_NO_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(versioninfo, "__version__", "1.4.0")

    class Up:
        OWNER, REPO, BRANCH = "o", "r", "main"

        @staticmethod
        def remote_version() -> str:
            return "1.5.0"

        @staticmethod
        def _get(url: str, timeout: int = 60) -> bytes:
            assert url.endswith("/CHANGELOG.md")
            return LOG.encode()

    monkeypatch.setattr(versioninfo, "_updater", lambda: Up)
    monkeypatch.setitem(versioninfo._STATE, "checked", 0.0)
    versioninfo._refresh()
    st = versioninfo.status()
    assert st["update_available"] and st["latest"] == "1.5.0"
    assert [x["version"] for x in versioninfo.upcoming()] == ["1.5.0", "1.4.1"]
    versioninfo.set_check(False)
    assert not versioninfo.status()["update_available"]
    monkeypatch.setitem(versioninfo._STATE, "latest", None)


def test_run_py_waits_for_the_port() -> None:
    sys.path.insert(0, str(ROOT))
    import importlib.util
    spec = importlib.util.spec_from_file_location("_run", ROOT / "run.py")
    run = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    assert run._wait_port(f"127.0.0.1:{port}", timeout=1.2) is False      # still listening
    threading.Timer(0.6, srv.close).start()
    assert run._wait_port(f"0.0.0.0:{port}", timeout=10) is True          # freed → go


def test_update_api(cfg: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex import app as appmod
    from docutracex import users
    from docutracex.tasks import manager
    started: list[tuple[str, int]] = []
    stopped: list[bool] = []
    monkeypatch.setattr(versioninfo, "start_update", lambda h, p: started.append((h, p)) or {"started": True, "log": "x"})
    monkeypatch.setattr(versioninfo, "stop_soon", lambda *a: stopped.append(True))
    c = TestClient(appmod.create_app())
    h = {"X-DTX": "1"}
    assert c.get("/api/version").json()["current"]
    monkeypatch.setattr(users, "role", lambda u: "analyst")
    assert c.post("/api/version/update", json={}, headers=h).status_code == 403
    monkeypatch.setattr(users, "role", lambda u: "admin")

    def _with_user(request):
        return "admin"
    import docutracex.api.version_api as va
    monkeypatch.setattr(va, "_admin", _with_user)
    monkeypatch.setattr(manager, "active_count", lambda: 2)
    r = c.post("/api/version/update", json={}, headers=h)
    assert r.status_code == 409 and "2 analysis" in r.json()["detail"] and not started
    r = c.post("/api/version/update", json={"force": True}, headers=h)
    assert r.status_code == 200 and started and stopped


def test_header_lights_up_and_whats_new_ui(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Browser: the version chip lights up, its popover lists the changes, Update shows for the
    admin; after an update the What's new modal lists what changed. (Playwright; skipped without.)"""
    import importlib.util as iu
    import json
    import time
    if iu.find_spec("playwright") is None:
        pytest.skip("playwright not installed")
    import uvicorn

    from docutracex.app import create_app
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path))
    app = create_app()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    entries = versioninfo.parse_changelog(LOG)
    cur = versioninfo.__version__
    canned = {
        "/api/auth/status": {"user": "admin", "role": "admin"},
        "/api/version": {"current": cur, "latest": "99.0.0", "update_available": True, "checking": False},
        "/api/version/upcoming": {"entries": entries[:2]},
        "/api/version/whatsnew": {"since": "1.4.0", "current": cur, "entries": entries[:1]},
    }
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch()
            except Exception as exc:  # noqa: BLE001
                pytest.skip(f"chromium not available: {exc}")
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            for path, body in canned.items():
                page.route(f"**{path}", lambda route, _req, b=body: route.fulfill(
                    status=200, content_type="application/json", body=json.dumps(b)))
            page.goto(f"http://127.0.0.1:{port}/")
            page.wait_for_selector("#modal:not([hidden]) .changelog")          # What's new first
            assert "What's new since v1.4.0" in page.inner_text("#modal-title")
            assert "Third" in page.inner_text("#modal-body")
            page.click("#modal-actions button")
            page.wait_for_selector("#version-chip.version-new")
            assert "99.0.0" in page.inner_text("#version-chip")
            assert page.is_visible("#update-btn")
            page.click("#version-chip")
            page.wait_for_selector("#modal:not([hidden]) .changelog h4")
            body = page.inner_text("#modal-body")
            assert "v1.5.0" in body and "v1.4.1" in body and "run.py" in body
            assert not errors, errors
            browser.close()
    finally:
        server.should_exit = True
