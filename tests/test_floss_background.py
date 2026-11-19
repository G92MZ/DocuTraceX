"""FLOSS of a large binary runs as a background task: the case finishes without waiting;
when FLOSS ends its strings reach the Binary tab, Code → Strings, IOCs and findings."""

from __future__ import annotations

import io
import threading
import time
from pathlib import Path

import pytest

from docutracex import tasks
from docutracex.parsers import pe as pe_mod

URL = "https://facturas-cdn.example/gate.php"


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    monkeypatch.setattr(pe_mod, "FLOSS_BACKGROUND_BYTES", 16)
    monkeypatch.setattr(pe_mod, "_tools_available", lambda: True)
    monkeypatch.setattr(pe_mod, "_trusted_signer", lambda p: None)
    monkeypatch.setattr(pe_mod, "_cache_file", lambda sha, tool: tmp_path / "cache" / f"{sha}.{tool}.json")
    monkeypatch.setattr(pe_mod, "_run_capa", lambda p, *a: {"status": "ok", "duration_s": 0.01, "capabilities": []})
    gate = threading.Event()
    calls: list[dict] = []

    def floss(path, extra=None, timeout=-1, cancel=None):  # noqa: ANN001, ANN202
        calls.append({"extra": list(extra or []), "thread": threading.current_thread().name})
        while not gate.is_set():                               # "slow": until the test lets it go
            if cancel is not None and cancel.is_set():
                return {"status": "cancelled", "detail": "floss cancelled by the analyst"}
            time.sleep(0.02)
        return {"status": "ok", "duration_s": 1.0, "counts": {"static": 1, "decoded": 1},
                "strings": ["kernel32.dll", URL], "located": [{"kind": "decoded", "string": URL, "function": None}],
                "detail": "2 string(s)"}
    monkeypatch.setattr(pe_mod, "_run_floss", floss)
    return tmp_path, gate, calls


def _wait(pred, s: float = 30) -> None:  # noqa: ANN001
    end = time.monotonic() + s
    while time.monotonic() < end:
        if pred():
            return
        time.sleep(0.05)
    raise AssertionError("timed out")


def _bg(cid: str) -> dict:
    return next(t for t in tasks.manager.list(cid) if t.get("background"))


def _exe() -> bytes:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import binkit as bk
    return bk.pe(bits=64, gui=True, imports={"kernel32.dll": ["Sleep"]}, strings=["inert invoice viewer"])


def test_case_finishes_first_floss_lands_later(env) -> None:  # noqa: ANN001
    from docutracex import cases
    from docutracex.storage import CasePaths, read_json
    tmp, gate, calls = env
    m = cases.create_case(io.BytesIO(_exe()), "visor.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    t = tasks.manager.submit("analyze", cid, "visor.exe", cases_dir=tmp / "cases")
    _wait(lambda: tasks.manager.get(t.id)["state"] == tasks.COMPLETED)      # FLOSS still running
    paths = CasePaths(cid, cases_dir=tmp / "cases")
    msi = read_json(paths.subresult("msi"))
    fl = msi["items"][0]["floss"]
    assert fl["status"] == "running" and fl["background"] and fl["task_id"]
    assert msi["items"][0]["capa"]["status"] == "ok"
    bg = _bg(cid)
    assert bg["state"] == tasks.RUNNING and bg["target"] == "floss (background)"
    assert bg["parent"] == t.id                                              # the analysis that started it
    assert calls and calls[0]["extra"] == ["--no", "tight"]
    # a re-run of the same case is not blocked by the background FLOSS
    r = tasks.manager.submit("rerun_module", cid, "visor.exe", target="ml", cases_dir=tmp / "cases")
    _wait(lambda: tasks.manager.get(r.id)["state"] in (tasks.COMPLETED, tasks.FAILED))
    assert _bg(cid)["state"] == tasks.RUNNING
    gate.set()                                                              # FLOSS ends
    _wait(lambda: _bg(cid)["state"] == tasks.COMPLETED)
    msi = read_json(paths.subresult("msi"))
    item = msi["items"][0]
    assert item["floss"]["status"] == "ok" and item["floss"]["background"] and URL in item["floss_strings"]
    assert any(f["rule"] == "pe_floss_strings" for f in item["findings"])
    vals = {i["value"] for i in (read_json(paths.subresult("iocs")) or {}).get("iocs") or []}
    assert URL in vals                                                      # IOCs recomputed
    assert "string(s)" in (_bg(cid)["steps"][0].get("note") or "")


def test_background_floss_can_be_cancelled(env) -> None:  # noqa: ANN001
    from docutracex import cases
    from docutracex.storage import CasePaths, read_json
    tmp, _gate, _calls = env
    m = cases.create_case(io.BytesIO(_exe() + b"other"), "visor2.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    t = tasks.manager.submit("analyze", cid, "visor2.exe", cases_dir=tmp / "cases")
    _wait(lambda: tasks.manager.get(t.id)["state"] == tasks.COMPLETED)
    assert tasks.manager.cancel(_bg(cid)["id"])
    _wait(lambda: _bg(cid)["state"] == tasks.CANCELLED)
    fl = read_json(CasePaths(cid, cases_dir=tmp / "cases").subresult("msi"))["items"][0]["floss"]
    assert fl["status"] == "cancelled"


def test_small_or_cached_files_run_floss_inline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from pathlib import Path as P
    exe = tmp_path / "small.exe"
    exe.write_bytes(b"MZ" + b"\0" * 10)
    monkeypatch.setattr(pe_mod, "_tools_available", lambda: True)
    tok = pe_mod._bg_root.set(P(tmp_path))
    try:
        assert not pe_mod._background_floss(exe)                 # under the 2 MB default
        monkeypatch.setattr(pe_mod, "FLOSS_BACKGROUND_BYTES", 4)
        monkeypatch.setattr(pe_mod, "_trusted_signer", lambda p: None)
        monkeypatch.setattr(pe_mod, "_floss_cached", lambda p: False)
        assert pe_mod._background_floss(exe)
        monkeypatch.setattr(pe_mod, "_floss_cached", lambda p: True)
        assert not pe_mod._background_floss(exe)                 # cached: instant, inline
    finally:
        pe_mod._bg_root.reset(tok)
    assert not pe_mod._background_floss(exe)                     # nested files: never in the background


def test_tasks_view_shows_completed_with_background(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tasks: "completed + 1 in background" on the analysis, "started by" on the job, the
    count in the header; a step of tools says "N tool(s)"."""
    import importlib.util
    import socket

    if importlib.util.find_spec("playwright") is None:
        pytest.skip("playwright not installed")
    import uvicorn

    from docutracex.app import create_app
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "config"))
    app = create_app()
    with socket.socket() as so:
        so.bind(("127.0.0.1", 0))
        port = so.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    _wait(lambda: server.started, 10)
    tools = [{"name": f"v.exe · {n}", "chain": n, "kind": "tool", "depth": 1, "status": "ok", "duration_s": 1}
             for n in ("LIEF", "FLOSS", "capa")]
    data = {"active": 1, "tasks": [
        {"id": "task-0002", "type": "floss", "analysis_id": "c1", "filename": "v.exe", "target": "floss (background)",
         "state": "running", "background": True, "parent": "task-0001", "started_utc": "2026-11-19T20:00:00Z",
         "steps": [{"step": "FLOSS · v.exe (background)", "status": "running"}]},
        {"id": "task-0001", "type": "analyze", "analysis_id": "c1", "filename": "v.exe", "target": "full",
         "state": "completed", "duration_s": 75, "finished_utc": "2026-11-19T20:01:15Z",
         "steps": [{"step": "binary: PE triage", "status": "ok", "duration_s": 11, "substeps": tools}]}]}
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch()
            except Exception as exc:  # noqa: BLE001
                pytest.skip(f"chromium not available: {exc}")
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{port}/")
            page.evaluate("(d) => renderTasks(d)", data)
            body = page.inner_text("#tasks-body")
            assert "+ 1 in background" in body and "started by task-0001" in body
            assert "Still running in the background for this case: task-0002" in body
            assert "1 active (1 in background)" in page.inner_text("#tasks-summary")
            page.evaluate("() => document.querySelector('details[data-task=\"task-0001\"]').open = true")
            assert "3 tool(s)" in page.inner_text("details[data-task='task-0001']")
            browser.close()
    finally:
        server.should_exit = True
