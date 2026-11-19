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
    monkeypatch.setattr(pe_mod, "CAPA_BACKGROUND", False)        # capa in the background: its own tests
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


def test_floss_starts_before_capa(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The background FLOSS is started before the (inline) capa run, not after it."""
    order: list[str] = []
    from docutracex import flossbg
    monkeypatch.setattr(flossbg, "start", lambda *a: order.append("floss") or {"status": "running", "task_id": "t"})
    monkeypatch.setattr(pe_mod, "_capa_only", lambda p: order.append("capa") or {"status": "ok", "capabilities": []})
    monkeypatch.setattr(pe_mod, "_background_floss", lambda p: True)
    monkeypatch.setattr(pe_mod, "CAPA_BACKGROUND", False)
    exe = tmp_path / "v.exe"
    exe.write_bytes(_exe())
    tok = pe_mod._bg_root.set(tmp_path)
    try:
        pe_mod.analyze(exe, "v.exe")
    finally:
        pe_mod._bg_root.reset(tok)
    assert order == ["floss", "capa"]


CAP = {"name": "inject shellcode into remote process", "namespace": "host-interaction/process/inject",
       "attack": [{"id": "T1055"}], "matches": 2}


@pytest.fixture()
def capa_env(env, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN001, ANN201
    """FLOSS ends at once; capa is the slow one, in the background."""
    tmp, gate, _calls = env
    gate.set()
    monkeypatch.setattr(pe_mod, "CAPA_BACKGROUND", True)
    cgate = threading.Event()

    def capa(path, cancel=None):  # noqa: ANN001, ANN202
        while not cgate.is_set():
            if cancel is not None and cancel.is_set():
                return {"status": "cancelled", "detail": "capa cancelled by the analyst"}
            time.sleep(0.02)
        return {"status": "ok", "duration_s": 1.0, "capabilities": [CAP], "total": 1, "attack_ids": ["T1055"]}
    monkeypatch.setattr(pe_mod, "_run_capa", capa)
    return tmp, cgate


def _capa_bg(cid: str) -> dict:
    return next(t for t in tasks.manager.list(cid) if t.get("background") and t["type"] == "capa")


def test_capa_runs_in_background_and_lands_later(capa_env) -> None:  # noqa: ANN001
    from docutracex import cases
    from docutracex.storage import CasePaths, read_json
    tmp, cgate = capa_env
    m = cases.create_case(io.BytesIO(_exe() + b"capa"), "visor3.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    t = tasks.manager.submit("analyze", cid, "visor3.exe", cases_dir=tmp / "cases")
    _wait(lambda: tasks.manager.get(t.id)["state"] == tasks.COMPLETED)      # capa still running
    paths = CasePaths(cid, cases_dir=tmp / "cases")
    capa = read_json(paths.subresult("msi"))["items"][0]["capa"]
    assert capa["status"] == "running" and capa["background"] and capa["task_id"]
    bg = _capa_bg(cid)
    assert bg["state"] == tasks.RUNNING and bg["target"] == "capa (background)" and bg["parent"] == t.id
    cgate.set()
    _wait(lambda: _capa_bg(cid)["state"] == tasks.COMPLETED)
    msi = read_json(paths.subresult("msi"))
    item = msi["items"][0]
    assert item["capa"]["status"] == "ok" and item["capa"]["background"]
    hits = [f for f in item["findings"] if f["rule"] == "pe_capa_capability"]
    assert hits and "inject shellcode" in hits[0]["detail"]
    assert any(f["rule"] == "pe_capa_capability" for f in msi["findings"])


def test_background_capa_can_be_cancelled(capa_env) -> None:  # noqa: ANN001
    from docutracex import cases
    from docutracex.storage import CasePaths, read_json
    tmp, _cgate = capa_env
    m = cases.create_case(io.BytesIO(_exe() + b"capa2"), "visor4.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    t = tasks.manager.submit("analyze", cid, "visor4.exe", cases_dir=tmp / "cases")
    _wait(lambda: tasks.manager.get(t.id)["state"] == tasks.COMPLETED)
    assert tasks.manager.cancel(_capa_bg(cid)["id"])
    _wait(lambda: _capa_bg(cid)["state"] == tasks.CANCELLED)
    capa = read_json(CasePaths(cid, cases_dir=tmp / "cases").subresult("msi"))["items"][0]["capa"]
    assert capa["status"] == "cancelled"


def test_cached_capa_runs_inline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import flossbg
    monkeypatch.setattr(flossbg, "start", lambda *a: {"status": "running", "task_id": "t"})
    monkeypatch.setattr(flossbg, "start_capa", lambda *a: pytest.fail("cached capa went to the background"))
    monkeypatch.setattr(pe_mod, "_background_floss", lambda p: True)
    monkeypatch.setattr(pe_mod, "_capa_cached", lambda p: True)
    monkeypatch.setattr(pe_mod, "_capa_only", lambda p: {"status": "ok", "capabilities": [CAP]})
    exe = tmp_path / "v.exe"
    exe.write_bytes(_exe())
    tok = pe_mod._bg_root.set(tmp_path)
    try:
        res = pe_mod.analyze(exe, "v.exe")
    finally:
        pe_mod._bg_root.reset(tok)
    item = res["items"][0] if "items" in res else res
    assert item["capa"]["status"] == "ok"


def test_background_capa_recontrasts_code_capabilities(tmp_path: Path) -> None:
    """capa ends after the code analysis: the capa column / capa_only are filled and the
    code finding capa now covers is dropped (no duplicate), with no Rizin re-run."""
    import json

    from docutracex.codeanalysis import case as code_case
    from docutracex.storage import CasePaths, read_json, write_subresult
    root = tmp_path / "cases" / "c1"
    (root / "results").mkdir(parents=True)
    paths = CasePaths("c1", cases_dir=root.parent)
    sha = "ab" * 32
    fn = {"addr": 4096, "name": "fcn.inject", "confidence": "high",
          "evidence": [{"kind": "call", "detail": "WriteProcessMemory"}]}
    mine = [{"id": "inject", "name": "Process injection", "attack": "T1055", "severity": "high",
             "confidence": "high", "functions": [fn]},
            {"id": "persist", "name": "Run key", "attack": "T1547.001", "severity": "medium",
             "confidence": "high", "functions": [fn]}]
    from docutracex.codeanalysis import capabilities as caps
    before = caps.contrast(mine, {"status": "running", "background": True})
    assert before["capa_status"] == "running" and not before["capa_available"]
    full = {"capabilities": before}
    f = code_case.result_file(root, sha, "native")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(full), encoding="utf-8")
    write_subresult(paths, "code", {"module": "code", "objects": [{"label": "visor.exe", "sha256": sha}],
                                    "findings": caps.findings(before, "visor.exe")})
    assert len(read_json(paths.subresult("code"))["findings"]) == 2
    capa = {"status": "ok", "capabilities": [CAP, {"name": "query environment variable", "attack": [{"id": "T1082"}]}]}
    assert code_case.recontrast_capa(root, sha, capa) == 1
    got = code_case.load(root, sha, "native")["capabilities"]
    assert got["capa_available"] and got["capabilities"][0]["capa"] == [CAP["name"]]
    assert [x["attack"] for x in got["capa_only"]] == ["T1082"]
    rules = [x["rule"] for x in read_json(paths.subresult("code"))["findings"]]
    assert rules == ["code:cap:persist"]                    # T1055 is capa's finding now


def test_cases_list_shows_completed_with_background(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cases list: a completed case with FLOSS / capa still running says "+ N in background"."""
    import importlib.util
    import json
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
    cases_ = [{"analysis_id": "c1", "filename": "visor.exe", "state": "completed", "created_utc": "2026-11-19"},
              {"analysis_id": "c2", "filename": "otro.exe", "state": "completed", "created_utc": "2026-11-18"}]
    tdata = {"active": 2, "tasks": [
        {"id": f"task-000{i}", "type": t, "analysis_id": "c1", "target": f"{t} (background)", "state": "running",
         "background": True, "parent": "task-0001"} for i, t in ((2, "floss"), (3, "capa"))]}
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch()
            except Exception as exc:  # noqa: BLE001
                pytest.skip(f"chromium not available: {exc}")
            page = browser.new_page()
            page.route("**/api/cases", lambda route, request: route.fulfill(
                status=200, content_type="application/json", body=json.dumps(cases_)))
            page.route("**/api/tasks", lambda route, request: route.fulfill(     # the poller's refresh
                status=200, content_type="application/json", body=json.dumps(tdata)))
            page.goto(f"http://127.0.0.1:{port}/")
            page.evaluate("(d) => loadCases(d)", tdata)
            page.wait_for_selector("[data-case-bg]", state="attached")
            rows = page.eval_on_selector_all(".case-row", "els => els.map(e => [e.dataset.id, e.textContent])")
            by = dict(rows)
            assert "completed" in by["c1"] and "+ 2 in background" in by["c1"]
            assert "in background" not in by["c2"]
            browser.close()
    finally:
        server.should_exit = True

def test_child_process_requests_jobs_service_starts_them(capa_env, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    """The analysis in the portable child only *requests* FLOSS / capa (the child ends, and
    would take them along); the web service starts them and the placeholders get the ids."""
    from docutracex import analyze, cases, flossbg
    from docutracex.storage import CasePaths, read_json
    tmp, cgate = capa_env
    m = cases.create_case(io.BytesIO(_exe() + b"child"), "visor5.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    root = tmp / "cases" / cid
    monkeypatch.setenv(flossbg.DEFER_ENV, "1")              # as the child
    analyze.analyze_case(root)
    monkeypatch.delenv(flossbg.DEFER_ENV)
    assert not [t for t in tasks.manager.list(cid) if t.get("background")]   # nothing started in the child
    reqs = read_json(root / "results" / flossbg.REQUESTS)
    assert [r["kind"] for r in reqs] == ["floss", "capa"]
    paths = CasePaths(cid, cases_dir=tmp / "cases")
    item = read_json(paths.subresult("msi"))["items"][0]
    assert item["floss"]["task_id"].startswith("pending-") and item["capa"]["task_id"].startswith("pending-")
    ids = flossbg.launch_deferred(root)                     # the web service, after the child ended
    assert len(ids) == 2 and not (root / "results" / flossbg.REQUESTS).exists()
    assert {t["id"] for t in tasks.manager.list(cid) if t.get("background")} == set(ids)
    capa = read_json(paths.subresult("msi"))["items"][0]["capa"]
    assert capa["task_id"] in ids                           # the placeholder has the real id (FLOSS may be done)
    cgate.set()
    _wait(lambda: all(tasks.manager.get(i)["state"] == tasks.COMPLETED for i in ids))
    item = read_json(paths.subresult("msi"))["items"][0]
    assert item["floss"]["status"] == "ok" and item["capa"]["status"] == "ok"
    assert any(f["rule"] == "pe_capa_capability" for f in item["findings"])


def test_run_analysis_on_portable_starts_requested_jobs(capa_env, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    """run_analysis with the portable child: the jobs it requested are started by the service."""
    import os
    import subprocess

    from docutracex import analyze, cases, flossbg
    from docutracex.config import settings
    tmp, cgate = capa_env
    m = cases.create_case(io.BytesIO(_exe() + b"portable"), "visor6.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    monkeypatch.setattr(settings, "portable_python", lambda: tmp / "portable-python")

    def child(cmd, timeout, listener):  # noqa: ANN001, ANN202 — the child, in-process, with its env
        os.environ[flossbg.DEFER_ENV] = "1"
        try:
            analyze.analyze_case(Path(cmd[3]))
        finally:
            del os.environ[flossbg.DEFER_ENV]
        assert not [t for t in tasks.manager.list(cid) if t.get("background")]
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(analyze, "_run_portable", child)
    analyze.run_analysis(tmp / "cases" / cid)
    bg = [t for t in tasks.manager.list(cid) if t.get("background")]
    assert sorted(t["type"] for t in bg) == ["capa", "floss"]
    cgate.set()
    _wait(lambda: all(tasks.manager.get(t["id"])["state"] == tasks.COMPLETED for t in bg))


def test_restart_marks_background_jobs_interrupted(capa_env) -> None:  # noqa: ANN001
    """A restart ends the background jobs: on the next start their placeholders say
    "interrupted" (not "running" for ever); jobs live in this process are left alone."""
    from docutracex import cases, flossbg
    from docutracex.storage import CasePaths, read_json, write_json, write_subresult
    tmp, cgate = capa_env
    m = cases.create_case(io.BytesIO(_exe() + b"restart"), "visor7.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    root = tmp / "cases" / cid
    t = tasks.manager.submit("analyze", cid, "visor7.exe", cases_dir=tmp / "cases")
    _wait(lambda: tasks.manager.get(t.id)["state"] == tasks.COMPLETED)
    capa_id = read_json(CasePaths(cid, cases_dir=tmp / "cases").subresult("msi"))["items"][0]["capa"]["task_id"]
    marker = root / "results" / flossbg.RUNNING
    _wait(lambda: list((read_json(marker) or {}).keys()) == [capa_id])   # FLOSS done; capa running, tracked
    assert flossbg.recover_interrupted(tmp / "cases") == 0                # live here: left alone
    cgate.set()
    _wait(lambda: not marker.exists())                                     # untracked when it ends
    # "after a restart": a job this process does not know, its placeholder still running
    paths = CasePaths(cid, cases_dir=tmp / "cases")
    res = read_json(paths.subresult("msi"))
    res["items"][0]["capa"] = {"status": "running", "background": True, "task_id": "task-0999"}
    write_subresult(paths, "msi", res)
    write_json(marker, {"task-0999": {"kind": "capa", "sha256": "x", "mode": None}})
    assert flossbg.recover_interrupted(tmp / "cases") == 1
    capa = read_json(paths.subresult("msi"))["items"][0]["capa"]
    assert capa["status"] == "interrupted" and "restarted" in capa["detail"]
    assert not marker.exists()
