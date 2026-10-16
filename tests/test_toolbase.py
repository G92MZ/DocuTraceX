"""Tool base: the external-tool runner and the second (PyPy) interpreter."""

from __future__ import annotations

import sys

import pytest

from docutracex import toolrun
from docutracex.config import settings
from docutracex.parsers import vipermonkey


def test_run_captures_output_and_returncode() -> None:
    rec = toolrun.run([sys.executable, "-c", "print('hello'); import sys; sys.exit(3)"], "demo")
    assert rec["command"] == "demo" and rec["returncode"] == 3
    assert rec["output"].strip() == "hello" and rec["duration_s"] >= 0


def test_run_enforces_timeout() -> None:
    rec = toolrun.run([sys.executable, "-c", "import time; time.sleep(5)"], "slow", timeout=1)
    assert rec.get("timed_out") and "timed out" in rec["error"]


def test_run_bounds_output() -> None:
    rec = toolrun.run([sys.executable, "-c", "print('x' * 5000)"], "big", bound=100)
    assert len(rec["output"]) == 100 and rec["output_truncated"]


def test_vipermonkey_unavailable_without_pypy(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(type(settings), "pypy_python", lambda self: None)
    assert vipermonkey.vipermonkey_status()["available"] is False
    res = vipermonkey.analyze(tmp_path / "x.doc")
    assert res["available"] is False and not res["findings"]


def test_action_classification() -> None:
    assert vipermonkey._classify("Execute Command", "cmd.exe /c calc")[0] == "vm_execute"
    assert vipermonkey._classify("Found Entry Point", "AutoOpen") is None
    assert vipermonkey._classify("Download", "http://x.example/a")[0] == "vm_network"


# tag: gmzpt
@pytest.mark.skipif(settings.pypy_python() is None, reason="PyPy/ViperMonkey not provisioned")
def test_vipermonkey_status_with_pypy() -> None:
    assert vipermonkey.vipermonkey_status()["available"]
