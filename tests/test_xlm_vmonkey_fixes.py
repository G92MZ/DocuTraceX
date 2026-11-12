"""XLMMacroDeobfuscator without distutils (Python 3.12+), and ViperMonkey runs that end without a result."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_xlm_imports_without_distutils() -> None:
    """Hide distutils (as on Python 3.12+ without setuptools' shim) and import the tool through the parser."""
    pytest.importorskip("XLMMacroDeobfuscator")
    code = textwrap.dedent('''
        import sys, importlib.abc
        class Block(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name == "distutils" or name.startswith("distutils.") or name == "_distutils_hack":
                    raise ModuleNotFoundError("No module named 'distutils'")
                return None
        for k in [k for k in sys.modules if k.startswith("distutils")]:
            del sys.modules[k]
        sys.meta_path.insert(0, Block())
        from docutracex.parsers import xlm
        r = xlm.analyze(__import__("pathlib").Path("nonexistent.xlsm"))
        print("AVAILABLE", r["available"], r.get("error"))
        from distutils.util import strtobool
        assert strtobool("yes") == 1 and strtobool("off") == 0
    ''')
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert "AVAILABLE True" in r.stdout, r.stdout + r.stderr


def test_vmonkey_no_result_reason() -> None:
    from docutracex.parsers import vipermonkey as vm
    assert vm._no_result_reason({"stdout": "...\nNo VBA macros found.\n"}) == "no VBA macros found"
    rec = {"stdout": "FILE: x.doc\n", "stderr": "INFO  start\nERROR    VBA looks corrupted. Not analyzing.\n"}
    assert vm._no_result_reason(rec) == "VBA looks corrupted. Not analyzing."
    assert vm._no_result_reason({}) == "ViperMonkey stopped without a result"


def test_vmonkey_failed_emulation_is_not_an_ioerror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex.config import settings
    from docutracex.parsers import vipermonkey as vm
    exe = tmp_path / "pypy.exe"
    exe.write_text("")
    monkeypatch.setattr(type(settings), "pypy_python", lambda self: exe)
    seen = {}

    def fake_run(cmd, label, timeout=None, cwd=None):  # noqa: ANN001, ANN202
        out = Path(cmd[cmd.index("-o") + 1])
        seen["prefilled"] = out.read_text()                 # the empty object is there before it runs
        return {"returncode": 0, "stdout": "FILE: x\n", "stderr": "ERROR    VBA looks corrupted. Not analyzing.\n"}
    monkeypatch.setattr(vm.toolrun, "run", fake_run)
    doc = tmp_path / "x.doc"
    doc.write_bytes(b"\xd0\xcf\x11\xe0")
    r = vm.analyze(doc, tmp_path / "ex")
    assert seen["prefilled"] == "{}"
    assert r["status"] == "ok" and r["emulation"] == "no_result"
    assert r["step_note"] == "no emulation result: VBA looks corrupted. Not analyzing."
