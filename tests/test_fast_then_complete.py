"""Large binary: FLOSS / capa first on the fast vivisect analysis (no per-function
emulation pass, ~10x faster), then the complete analysis in the background adds what the
fast one missed — strings and capabilities are merged (union), never replaced."""

from __future__ import annotations

import io
import json
import sys
import threading
from pathlib import Path

import pytest

from docutracex import tasks
from docutracex.parsers import pe as pe_mod

sys.path.insert(0, str(Path(__file__).parent))
from test_floss_background import _exe, _wait  # noqa: E402

FAST = ["kernel32.dll", "https://facturas-cdn.example/gate.php", "only-fast.example"]
FULL = ["kernel32.dll", "https://facturas-cdn.example/gate.php", "https://pagos-cdn.example/c2"]
CAP_A = {"name": "encode data using XOR", "namespace": "data-manipulation/encoding/xor", "matches": 1,
         "attack": [{"id": "T1027"}]}
CAP_B = {"name": "inspect section memory permissions", "namespace": "host-interaction/process/inspect",
         "matches": 1, "attack": [{"id": "T1057"}]}


@pytest.fixture()
def fast_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    from docutracex import heavyjobs
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    monkeypatch.setattr(heavyjobs, "MIN_FREE_MB", 0)
    monkeypatch.setattr(pe_mod, "FLOSS_BACKGROUND_BYTES", 16)
    monkeypatch.setattr(pe_mod, "CAPA_BACKGROUND", True)
    monkeypatch.setattr(pe_mod, "_tools_available", lambda: True)
    monkeypatch.setattr(pe_mod, "_trusted_signer", lambda p: None)
    monkeypatch.setattr(pe_mod, "fast_capable", lambda: True)
    monkeypatch.setattr(pe_mod, "_cache_file", lambda sha, tool: tmp_path / "cache" / f"{sha}.{tool}.json")
    runs: list[str] = []
    gate = threading.Event()

    def floss(path, extra=None, timeout=-1, cancel=None):  # noqa: ANN001, ANN202
        fast = pe_mod._vivfast.get()
        runs.append("floss-fast" if fast else "floss-full")
        if not fast:
            gate.wait(30)                                  # the complete analysis: slow
        got = FAST if fast else FULL
        return {"status": "ok", "duration_s": 1.0, "counts": {"static": 1, "decoded": len(got) - 1},
                "strings": list(got), "located": [{"kind": "decoded", "string": s, "function": 4096} for s in got[1:]],
                "detail": f"{len(got)} string(s)"}

    def capa(path, *a):  # noqa: ANN001, ANN002, ANN202
        fast = pe_mod._vivfast.get()
        runs.append("capa-fast" if fast else "capa-full")
        caps = [CAP_A] if fast else [CAP_A, CAP_B]
        return {"status": "ok", "duration_s": 0.5, "capabilities": caps, "total": len(caps), "attack_ids": []}
    monkeypatch.setattr(pe_mod, "_run_floss", floss)
    monkeypatch.setattr(pe_mod, "_run_capa", capa)
    return tmp_path, runs, gate


def _bg(cid: str, kind: str) -> dict:
    return next(t for t in tasks.manager.list(cid) if t.get("background") and t["type"] == kind)


def test_fast_first_then_complete_adds_what_it_missed(fast_env) -> None:  # noqa: ANN001
    from docutracex import cases
    from docutracex.storage import CasePaths, read_json
    tmp, runs, gate = fast_env
    m = cases.create_case(io.BytesIO(_exe() + b"fast"), "visor.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    t = tasks.manager.submit("analyze", cid, "visor.exe", cases_dir=tmp / "cases")
    _wait(lambda: tasks.manager.get(t.id)["state"] == tasks.COMPLETED)
    paths = CasePaths(cid, cases_dir=tmp / "cases")
    item = read_json(paths.subresult("msi"))["items"][0]
    assert item["vivisect_full"]["status"] == "running"
    # the fast runs land first; the complete analysis waits for them, then runs
    _wait(lambda: _bg(cid, "capa")["state"] == tasks.COMPLETED and _bg(cid, "floss")["state"] == tasks.COMPLETED)
    item = read_json(paths.subresult("msi"))["items"][0]
    assert item["floss_strings"] == FAST and item["floss"]["fast"]
    assert [c["name"] for c in item["capa"]["capabilities"]] == [CAP_A["name"]]
    assert runs[:2] == ["floss-fast", "capa-fast"]
    gate.set()
    _wait(lambda: _bg(cid, "complete")["state"] == tasks.COMPLETED)
    assert runs[2:] == ["floss-full", "capa-full"]
    msi = read_json(paths.subresult("msi"))
    item = msi["items"][0]
    # union: what only the fast run found stays, what only the complete one found is added
    assert item["floss_strings"] == FAST + ["https://pagos-cdn.example/c2"]
    assert [c["name"] for c in item["capa"]["capabilities"]] == [CAP_A["name"], CAP_B["name"]]
    v = item["vivisect_full"]
    assert v["status"] == "ok" and v["strings_added"] == 1 and v["capabilities_added"] == 1
    assert any("inspect section memory permissions" in f["detail"] for f in msi["findings"]
               if f["rule"] == "pe_capa_capability")
    assert "pagos-cdn.example" in json.dumps(read_json(paths.subresult("iocs")))   # IOCs recomputed
    # both complete results are cached now: a re-analysis needs no fast run, no complete job
    exe = next(p for p in paths.root.rglob("visor.exe") if p.is_file())
    assert not pe_mod.complete_needed(exe)


def test_fast_run_uses_its_own_cache_and_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--fast 1 reaches vivtools; the fast result is cached apart; a complete result, once
    cached, is used instead of a fast run."""
    from docutracex import proctools
    from docutracex.config import settings
    cmds: list[list[str]] = []

    def fake_run(cmd, timeout, cwd=None, env=None, cancel=None):  # noqa: ANN001, ANN202
        cmds.append(cmd)
        return {"rc": 0, "out": json.dumps({"metadata": {"version": "3.2.0"}, "strings": {
            "static_strings": [{"string": "full" if "--fast" not in cmd else "fast"}]}}),
            "err": "", "timed_out": False, "duration_s": 1}
    monkeypatch.setattr(proctools, "run_bounded", fake_run)
    monkeypatch.setattr(settings, "portable_python", lambda: Path("/portable/python"))
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(settings, "floss_executable", lambda: settings.vivtools_script())
    monkeypatch.setattr(pe_mod, "VIVISECT_FAST", True)
    monkeypatch.setattr(pe_mod, "_cache_file", lambda sha, tool: tmp_path / "cache" / f"{sha}.{tool}.json")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\0" * 100)
    fast = pe_mod.floss_record(sample, fast=True)
    assert fast["fast"] and fast["strings"] == ["fast"] and cmds[-1][cmds[-1].index("--fast") + 1] == "1"
    again = pe_mod.floss_record(sample, fast=True)              # cached (fast)
    assert again["strings"] == ["fast"] and len(cmds) == 1
    full = pe_mod.floss_record(sample)                          # the complete run
    assert full["strings"] == ["full"] and "--fast" not in cmds[-1]
    assert pe_mod.floss_record(sample, fast=True)["strings"] == ["full"]   # complete cached: used instead
    assert len(cmds) == 2


def test_complete_stands_in_for_a_failed_fast_floss(fast_env, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from docutracex import cases
    from docutracex.storage import CasePaths, read_json
    tmp, runs, gate = fast_env
    real = pe_mod._run_floss

    def floss(path, extra=None, timeout=-1, cancel=None):  # noqa: ANN001, ANN202
        if pe_mod._vivfast.get():
            runs.append("floss-fast")
            return {"status": "error", "detail": "floss exited 1: PermissionError"}
        return real(path, extra, timeout, cancel)
    monkeypatch.setattr(pe_mod, "_run_floss", floss)
    gate.set()
    m = cases.create_case(io.BytesIO(_exe() + b"failed-fast"), "visor2.exe", cases_dir=tmp / "cases")
    cid = m["analysis_id"]
    tasks.manager.submit("analyze", cid, "visor2.exe", cases_dir=tmp / "cases")
    _wait(lambda: any(t["type"] == "complete" and t["state"] == tasks.COMPLETED for t in tasks.manager.list(cid)))
    msi = read_json(CasePaths(cid, cases_dir=tmp / "cases").subresult("msi"))
    item = msi["items"][0]
    assert item["floss"]["status"] == "ok" and item["floss_strings"] == FULL
    assert any(f["rule"] == "pe_floss_strings" for f in item["findings"])
