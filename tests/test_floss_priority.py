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

    def run(path, extra=None):
        calls.append(list(extra or []))
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
