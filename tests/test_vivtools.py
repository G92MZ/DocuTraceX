"""FLOSS and capa as Python libraries on the portable Python (``vivtools.py``): how they are
found and run, and — where an interpreter with flare-floss / flare-capa and capa's rules is
available (``DOCUTRACEX_TEST_VIVPYTHON``, ``DOCUTRACEX_TEST_CAPA_RULES``) — one vivisect
analysis shared by both on an inert sample. Nothing is executed but the tools' static analysis."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from docutracex.config import settings
from docutracex.parsers import pe

sys.path.insert(0, str(Path(__file__).parent))


def _portable(tmp: Path, packages: tuple[str, ...]) -> Path:
    py = tmp / "tools" / "python" / "python.exe"
    py.parent.mkdir(parents=True)
    py.write_bytes(b"MZ")
    for p in packages:
        d = tmp / "tools" / "python" / "Lib" / "site-packages" / p
        d.mkdir(parents=True)
        (d / "__init__.py").write_text("")
    return py


def test_found_only_when_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for k in ("DOCUTRACEX_FLOSS", "DOCUTRACEX_CAPA", "DOCUTRACEX_CAPA_RULES", "DOCUTRACEX_PYTHON"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(type(settings), "tools_dir", property(lambda s: tmp_path / "tools"))
    assert settings.floss_executable() is None and settings.capa_executable() is None
    _portable(tmp_path, ("floss", "capa"))
    assert settings.floss_executable() == settings.vivtools_script()
    assert settings.capa_executable() is None                      # no rules yet
    rules = tmp_path / "tools" / "capa-rules" / "host-interaction"
    rules.mkdir(parents=True)
    (rules / "x.yml").write_text("rule: {}")
    assert settings.capa_executable() == settings.vivtools_script()
    exe = tmp_path / "floss.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("DOCUTRACEX_FLOSS", str(exe))               # a standalone build still wins
    assert settings.floss_executable() == exe


def test_command_and_cache_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, timeout, cwd=None, env=None, cancel=None):  # noqa: ANN001, ANN202
        calls.append(cmd)
        return {"rc": 0, "out": json.dumps({"metadata": {}, "strings": {}, "rules": {}}), "err": "",
                "timed_out": False, "duration_s": 0.1}
    from docutracex import proctools
    monkeypatch.setattr(proctools, "run_bounded", fake_run)
    monkeypatch.setattr(settings, "portable_python", lambda: Path("/portable/python"))
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(settings, "capa_rules_dir", lambda: tmp_path / "rules")
    script = settings.vivtools_script()
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    pe._run_tool("floss", script, ["--json", "--no", "tight", "--"], sample, 10)
    pe._run_tool("capa", script, ["-j", "-q"], sample, 10)
    floss, capa = calls
    cache = str(tmp_path / "cases" / ".tools_cache" / "viv")
    assert floss == ["/portable/python", "-I", str(script), "floss", "--cache", cache, "--",
                     "--json", "--no", "tight", "--", str(sample)]
    assert capa == ["/portable/python", "-I", str(script), "capa", "--cache", cache, "--rules",
                    str(tmp_path / "rules"), "--", "-j", "-q", str(sample)]
    assert pe._tool_id(script).startswith("lib:flare-floss==3.2.0:flare-capa==10.0.0")


VIVPY = os.environ.get("DOCUTRACEX_TEST_VIVPYTHON")
RULES = os.environ.get("DOCUTRACEX_TEST_CAPA_RULES")


@pytest.mark.skipif(not (VIVPY and RULES), reason="no interpreter with flare-floss / flare-capa (DOCUTRACEX_TEST_VIVPYTHON)")
def test_one_analysis_shared_by_floss_and_capa(tmp_path: Path) -> None:
    from test_js_techniques import _ms
    sample = tmp_path / "sample_code_loader.exe"
    sample.write_bytes(_ms().code_loader_exe())
    cache = tmp_path / "viv"
    script = str(settings.vivtools_script())

    def run(tool: str, args: list[str]) -> dict:
        own = ["--cache", str(cache)] + (["--rules", RULES] if tool == "capa" else [])
        r = subprocess.run([VIVPY, "-I", script, tool, *own, "--", *args, str(sample)],
                           capture_output=True, text=True, timeout=900)
        assert r.returncode == 0, r.stderr[-800:]
        return json.loads(r.stdout)

    first = run("floss", ["--json", "-q", "--no", "tight", "--"])
    vivs = list(cache.glob("*.bin.viv"))
    assert len(vivs) == 1                                          # the analysis, saved
    capa = run("capa", ["-j", "-q"])                               # loads it
    again = run("floss", ["--json", "-q", "--no", "tight", "--"])
    assert again["metadata"]["runtime"]["vivisect"] <= first["metadata"]["runtime"]["vivisect"] + 1
    assert {k: len(v) for k, v in again["strings"].items()} == {k: len(v) for k, v in first["strings"].items()}
    assert isinstance(capa.get("rules"), dict)
    assert not list(cache.glob("*.[0-9]*.bin*"))                   # private copies cleaned up
