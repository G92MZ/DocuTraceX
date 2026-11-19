"""Large files: FLOSS tight strings skipped on the whole binary are recovered
on the code engine's priority functions (``--only tight --functions``)."""

from __future__ import annotations

from pathlib import Path

import pytest

from docutracex.codeanalysis import case
from docutracex.parsers import pe as pe_mod


def _full() -> dict:
    return {"functions": [
        {"addr": 0x401000, "name": "main", "size": 0x80, "rank": 1, "loops": 0, "xor_ops": 0, "user": True},
        {"addr": 0x402000, "name": "decode", "size": 0x100, "rank": 5, "loops": 2, "xor_ops": 4, "user": True},
        {"addr": 0x403000, "name": "copy", "size": 0x40, "rank": 2, "loops": 1, "xor_ops": 0, "user": True},
        {"addr": 0x404000, "name": "sym.std.memcpy", "size": 0x40, "rank": 3, "loops": 3, "xor_ops": 1, "user": False},
    ]}


def test_priority_functions_prefers_loops_with_xor_and_skips_library() -> None:
    assert case.priority_functions(_full(), 10) == [0x402000, 0x403000]
    assert case.priority_functions(_full(), 1) == [0x402000]


@pytest.fixture()
def fake_floss(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    calls = []

    def run(path, extra=None, **kw):
        calls.append(list(extra or []))
        run.kw = kw
        return {"status": "ok", "tool": "floss", "strings": ["hxxp://pay.invoice.example/gate"],
                "located": [{"kind": "tight", "string": "pay.invoice.example/gate", "function": 0x402010}]}
    monkeypatch.setattr(pe_mod, "_run_floss", run)
    return calls


def test_tight_strings_recovered_on_priority_functions(tmp_path: Path, fake_floss, monkeypatch) -> None:
    exe = tmp_path / "big.exe"
    exe.write_bytes(b"MZ inert stub")
    monkeypatch.setattr(case, "binary_item", lambda *a: {"floss": {"status": "ok", "tight_skipped": True}})
    full = _full()
    located = case.priority_tight(tmp_path, exe, full, {"stored_path": "", "original": True})
    assert fake_floss == [["--only", "tight", "--functions", "0x402000", "0x403000"]]
    assert located[0]["kind"] == "tight (priority functions)"
    assert full["floss_priority"]["strings"] == 1
    case.attach_floss(full, located)
    assert full["floss"][0]["source"] == "FLOSS tight (priority functions)" and full["floss"][0]["function"] == "decode"
    # second time: from the cache, FLOSS not run again
    case.priority_tight(tmp_path, exe, _full(), {"stored_path": "", "original": True})
    assert len(fake_floss) == 1


def test_nothing_runs_when_tight_was_not_skipped(tmp_path: Path, fake_floss, monkeypatch) -> None:
    monkeypatch.setattr(case, "binary_item", lambda *a: {"floss": {"status": "ok"}})
    assert case.priority_tight(tmp_path, tmp_path / "x.exe", _full(), {}) == []
    assert fake_floss == []


def test_full_floss_strings_merged_once(tmp_path: Path, monkeypatch) -> None:
    import json
    full = _full()
    full["floss"] = [{"value": "old", "addr": 0x401010, "source": "FLOSS stack", "function": "main"}]
    f = tmp_path / "res.json"
    f.write_text(json.dumps(full))
    monkeypatch.setattr(case, "result_file", lambda *a: f)
    rec = {"status": "ok", "located": [{"kind": "tight", "string": "old", "function": 0x401010},
                                       {"kind": "tight", "string": "inv-sync.example", "function": 0x403008}]}
    assert case.merge_full_floss(tmp_path, "ab" * 32, "native", rec) == 1
    got = json.loads(f.read_text())
    assert [x["value"] for x in got["floss"]] == ["old", "inv-sync.example"]
    assert got["floss"][1]["function"] == "copy" and got["floss"][1]["source"] == "FLOSS tight (full run)"
    assert next(x for x in got["functions"] if x["name"] == "copy")["floss"][0]["value"] == "inv-sync.example"
    assert case.merge_full_floss(tmp_path, "ab" * 32, "native", rec) == 0       # second time: nothing new


def test_large_file_reuses_the_full_run(tmp_path: Path, fake_floss, monkeypatch) -> None:
    exe = tmp_path / "big.exe"
    exe.write_bytes(b"MZ inert stub")
    monkeypatch.setattr(pe_mod, "FLOSS_LARGE_BYTES", 1)
    monkeypatch.setattr(pe_mod, "_run_capa", lambda p, *_: {"status": "ok", "capabilities": []})
    monkeypatch.setattr(pe_mod, "_trusted_signer", lambda p: None)
    floss, _ = pe_mod._both(exe)
    assert floss.get("tight_skipped") and fake_floss[-1] == ["--no", "tight"]
    pe_mod.full_floss(exe)
    assert fake_floss[-1] == []
    n = len(fake_floss)
    floss, _ = pe_mod._both(exe)                   # the full run is reused, not the lighter one
    assert len(fake_floss) == n and not floss.get("tight_skipped") and floss.get("cached")


def test_automatic_run_skips_tight_strings_by_default(tmp_path: Path, fake_floss, monkeypatch) -> None:
    """Any size: the automatic FLOSS has no tight strings; Deep FLOSS has them, with no time limit."""
    exe = tmp_path / "small.exe"
    exe.write_bytes(b"MZ inert stub")
    assert pe_mod.FLOSS_LARGE_BYTES == 0
    monkeypatch.setattr(pe_mod, "_run_capa", lambda p, *_: {"status": "ok", "capabilities": []})
    monkeypatch.setattr(pe_mod, "_trusted_signer", lambda p: None)
    floss, _ = pe_mod._both(exe)
    assert floss.get("tight_skipped") and fake_floss[-1] == ["--no", "tight"]
    assert "Deep FLOSS" in floss["note"]
    exe2 = tmp_path / "other.exe"
    exe2.write_bytes(b"MZ other inert stub")
    pe_mod.full_floss(exe2)
    assert fake_floss[-1] == [] and pe_mod._run_floss.kw["timeout"] is None


def test_deep_floss_job_can_be_cancelled(tmp_path: Path, monkeypatch) -> None:
    import threading
    import time as _time
    started = threading.Event()

    def slow(path, cancel=None):  # noqa: ANN001, ANN202
        started.set()
        while not cancel.is_set():
            _time.sleep(0.05)
        return {"status": "cancelled", "detail": "floss cancelled by the analyst"}
    monkeypatch.setattr(pe_mod, "full_floss", slow)
    monkeypatch.setattr(case, "load", lambda *a: {"functions": []})
    monkeypatch.setattr(case, "_floss_job_file", lambda *a: tmp_path / "job.json")
    st = case.start_full_floss(tmp_path, tmp_path / "x.exe", "cd" * 32, "native")
    assert st["state"] == "running" and started.wait(5)
    assert case.cancel_full_floss(tmp_path, "cd" * 32, "native").get("cancelling")
    for _ in range(100):
        if case.full_floss_status(tmp_path, "cd" * 32, "native")["state"] != "running":
            break
        _time.sleep(0.05)
    st = case.full_floss_status(tmp_path, "cd" * 32, "native")
    assert st["state"] == "cancelled" and st["duration_s"] >= 0


def test_deep_floss_strings_reach_the_iocs(tmp_path: Path, monkeypatch) -> None:
    """A URL only Deep FLOSS recovers (a tight string) becomes an IOC of the case, with
    its function, without re-running the analysis."""
    import io
    import json

    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json, write_subresult
    m = cases.create_case(io.BytesIO(b"MZ inert stub"), "visor.exe", cases_dir=tmp_path / "cases")
    root = tmp_path / "cases" / m["analysis_id"]
    analyze.analyze_case(root)
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path / "cases")
    sha = "ef" * 32
    write_subresult(paths, "code", {"module": "code", "objects": [{"label": "visor.exe", "sha256": sha,
                                                                   "ioc_sources": []}]})
    f = tmp_path / "res.json"
    f.write_text(json.dumps(_full()))
    monkeypatch.setattr(case, "result_file", lambda *a: f)
    rec = {"status": "ok", "located": [{"kind": "tight", "string": "https://facturas-cdn.example/gate.php",
                                        "function": 0x403008}]}
    assert case.merge_full_floss(root, sha, "native", rec) == 1
    vals = {i["value"] for i in (read_json(paths.subresult("iocs")) or {}).get("iocs") or []}
    assert "https://facturas-cdn.example/gate.php" in vals
    obj = read_json(paths.subresult("code"))["objects"][0]
    assert obj["ioc_sources"][0]["location"] == "visor.exe › copy (FLOSS tight (full run))"
