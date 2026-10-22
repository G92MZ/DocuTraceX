"""run_bounded: hard timeout that also kills grandchildren (PyInstaller onefile
bootloader + child), and never blocks on pipes an orphan keeps open."""

from __future__ import annotations

import sys
import time

from docutracex import proctools

# A parent that starts a long-lived child (sharing its stdout) and waits —
# the shape of a PyInstaller onefile tool stuck in analysis.
_TREE = (
    "import subprocess, sys, time\n"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
    "print('started', flush=True)\n"
    "time.sleep(120)\n"
)


def test_fast_command_returns_output() -> None:
    r = proctools.run_bounded([sys.executable, "-c", "print('hola')"], timeout=30)
    assert r["rc"] == 0 and r["out"].strip() == "hola" and not r["timed_out"]


def test_timeout_kills_tree_and_returns_promptly() -> None:
    t0 = time.monotonic()
    r = proctools.run_bounded([sys.executable, "-c", _TREE], timeout=3)
    elapsed = time.monotonic() - t0
    assert r["timed_out"] is True
    assert elapsed < 20, f"run_bounded blocked {elapsed:.1f}s after the timeout"
    assert "started" in r["out"]


def test_missing_executable_is_an_error_not_an_exception() -> None:
    r = proctools.run_bounded(["/nonexistent/tool.exe"], timeout=5)
    assert r.get("error") and r["rc"] is None
