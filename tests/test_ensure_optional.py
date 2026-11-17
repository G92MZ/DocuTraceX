"""run.py heals the optional runtimes (webcrack, box-ps), marker-guarded."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import setup_portable_python as sp  # noqa: E402


def test_marker_roundtrip(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(sp, "TOOLS", tmp_path)
    assert sp._marked("webcrack") is False
    sp._mark_failed("webcrack")
    assert sp._marked("webcrack") is True
    sp._clear_mark("webcrack")
    assert sp._marked("webcrack") is False


def _others_present(monkeypatch) -> None:
    """Every other optional runtime reported present: no real download or build under tests."""
    for name in dir(sp):
        if name.endswith("_ok") and name.startswith("_") and name not in ("_webcrack_ok", "_boxps_ok"):
            monkeypatch.setattr(sp, name, lambda *_a, **_k: True)


def test_attempts_once_then_skips_on_failure(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(sp, "TOOLS", tmp_path)
    _others_present(monkeypatch)
    calls = {"webcrack": 0, "boxps": 0}
    monkeypatch.setattr(sp, "_webcrack_ok", lambda: False)
    monkeypatch.setattr(sp, "_boxps_ok", lambda: False)
    monkeypatch.setattr(sp, "install_webcrack", lambda: calls.__setitem__("webcrack", calls["webcrack"] + 1) or False)
    monkeypatch.setattr(sp, "install_boxps", lambda: calls.__setitem__("boxps", calls["boxps"] + 1) or False)

    sp._ensure_optional()                      # first start: tries, fails, marks
    assert calls == {"webcrack": 1, "boxps": 1}
    assert sp._marked("webcrack") and sp._marked("boxps")

    sp._ensure_optional()                      # next start: skipped (marker)
    assert calls == {"webcrack": 1, "boxps": 1}


def test_mark_cleared_when_runtime_present(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(sp, "TOOLS", tmp_path)
    _others_present(monkeypatch)
    sp._mark_failed("webcrack")
    monkeypatch.setattr(sp, "_webcrack_ok", lambda: True)
    monkeypatch.setattr(sp, "_boxps_ok", lambda: True)
    sp._ensure_optional()
    assert not sp._marked("webcrack")          # present now -> stale marker cleared


def test_a_helper_that_exits_does_not_stop_the_start(tmp_path, monkeypatch) -> None:
    """A provisioning helper calling sys.exit (no portable interpreter yet) is marked, not fatal."""
    monkeypatch.setattr(sp, "TOOLS", tmp_path)
    _others_present(monkeypatch)
    monkeypatch.setattr(sp, "_webcrack_ok", lambda: False)
    monkeypatch.setattr(sp, "_boxps_ok", lambda: True)
    monkeypatch.setattr(sp, "install_webcrack", lambda: (_ for _ in ()).throw(SystemExit("no interpreter")))
    sp._ensure_optional()
    assert sp._marked("webcrack")
