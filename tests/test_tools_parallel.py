"""FLOSS and capa: concurrent on one PE, prefetched for the PEs of a batch."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import binkit as bk  # noqa: E402

from docutracex.parsers import pe as pe_mod  # noqa: E402


@pytest.fixture()
def fake_tools(monkeypatch: pytest.MonkeyPatch):
    live = {"now": 0, "max": 0, "calls": []}
    lock = threading.Lock()

    def tool(name):
        def run(path):
            with lock:
                live["now"] += 1
                live["max"] = max(live["max"], live["now"])
                live["calls"].append((name, Path(path).name))
            time.sleep(0.3)
            with lock:
                live["now"] -= 1
            return {"status": "ok", "tool": name, **({"strings": ["s"]} if name == "floss" else {"capabilities": []})}
        return run
    monkeypatch.setattr(pe_mod, "_run_floss", tool("floss"))
    monkeypatch.setattr(pe_mod, "_run_capa", tool("capa"))
    from docutracex.config import settings
    monkeypatch.setattr(type(settings), "floss_executable", lambda self: Path("/bin/true"), raising=False)
    monkeypatch.setattr(type(settings), "capa_executable", lambda self: Path("/bin/true"), raising=False)
    monkeypatch.setenv("DOCUTRACEX_TOOLS_PARALLEL", "2")
    monkeypatch.setattr(pe_mod, "_pool", None)
    monkeypatch.setattr(pe_mod, "_pending", {})
    return live


def test_both_tools_run_at_the_same_time(tmp_path: Path, fake_tools) -> None:
    p = tmp_path / "a.exe"
    p.write_bytes(bk.pe(bits=32, gui=False))
    t0 = time.perf_counter()
    floss, capa = pe_mod.tools_for(p)
    assert floss["tool"] == "floss" and capa["tool"] == "capa" and fake_tools["max"] == 2


def test_prefetch_runs_ahead_and_is_used_once(tmp_path: Path, fake_tools, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pe_mod, "_tools_workers", lambda: 2)
    files = []
    for i in range(4):
        p = tmp_path / f"k{i}.exe"
        p.write_bytes(bk.pe(bits=32, gui=False, version={"FileDescription": f"kit {i}"}))
        files.append(p)
    (tmp_path / "note.txt").write_text("not a PE")
    assert pe_mod.prefetch(files + [tmp_path / "note.txt"]) == 4
    assert pe_mod.prefetch(files) == 0                        # not queued twice
    for p in files:
        floss, capa = pe_mod.tools_for(p)
        assert floss.get("prefetched") and capa.get("prefetched")
    assert 2 < fake_tools["max"] <= 4                        # 2 binaries x (FLOSS + capa) at once, never more
    assert sorted(n for n, _ in fake_tools["calls"]).count("floss") == 4
    floss, _ = pe_mod.tools_for(files[0])                    # consumed: a later call runs it again
    assert not floss.get("prefetched")


def test_packed_and_huge_are_not_prefetched(tmp_path: Path, fake_tools) -> None:
    import os
    packed = tmp_path / "packed.exe"
    packed.write_bytes(bk.pe(bits=32, gui=False, code=b"\xc3" + os.urandom(64 * 1024)))
    assert pe_mod._worth_prefetch(packed) is False
