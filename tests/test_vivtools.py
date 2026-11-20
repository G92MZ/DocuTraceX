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

    def own(cmd: list[str], flag: str) -> str:
        return cmd[cmd.index(flag) + 1]
    assert floss == ["/portable/python", "-I", str(script), "floss", "--cache", cache,
                     "--progress", own(floss, "--progress"), "--partial", own(floss, "--partial"), "--",
                     "--json", "--no", "tight", "--", str(sample)]
    assert capa == ["/portable/python", "-I", str(script), "capa", "--cache", cache, "--rules",
                    str(tmp_path / "rules"), "--progress", own(capa, "--progress"), "--", "-j", "-q", str(sample)]
    assert "--partial" not in capa                                 # capa's result is all at the end
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


def _fake_partial_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timed_out: bool) -> list[list[str]]:
    """run_bounded stand-in: FLOSS (vivtools) wrote progress + partial strings, then its time ran out."""
    calls: list[list[str]] = []
    partial = {"metadata": {"file_path": "x", "min_length": 7}, "analysis": {},
               "strings": {"static_strings": [{"string": "https://facturas-cdn.example/gate.php"}],
                           "stack_strings": [{"string": "cmd.exe /c whoami", "function": 4096}],
                           "decoded_strings": [], "tight_strings": []}}

    def fake_run(cmd, timeout, cwd=None, env=None, cancel=None):  # noqa: ANN001, ANN202
        calls.append(cmd)
        prog = Path(cmd[cmd.index("--progress") + 1])
        prog.write_text(json.dumps({"phase": "decoded strings", "done": 3, "total": 20}))
        assert pe.live_progress(Path(cmd[-1]), "floss") == "decoded strings 3/20"   # while it runs
        if "--partial" in cmd:
            Path(cmd[cmd.index("--partial") + 1]).write_text(json.dumps(partial))
        if timed_out:
            return {"rc": None, "out": "", "err": "", "timed_out": True, "duration_s": timeout}
        return {"rc": 0, "out": json.dumps({"metadata": {"version": "3.2.0"}, "strings": {}}), "err": "",
                "timed_out": False, "duration_s": 1}
    from docutracex import proctools
    monkeypatch.setattr(proctools, "run_bounded", fake_run)
    monkeypatch.setattr(settings, "portable_python", lambda: Path("/portable/python"))
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(settings, "floss_executable", lambda: settings.vivtools_script())
    return calls


def test_floss_timeout_keeps_partial_strings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_partial_run(tmp_path, monkeypatch, timed_out=True)
    monkeypatch.setattr(pe, "_cache_file", lambda sha, tool: tmp_path / "cache" / f"{sha}.{tool}.json")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\0" * 64)
    rec = pe._cached(sample, "floss", settings.floss_executable(), [], lambda: pe._run_floss(sample, timeout=60))
    assert rec["status"] == "ok" and rec["partial"] and rec["detail"].startswith("PARTIAL")
    assert "https://facturas-cdn.example/gate.php" in rec["strings"] and rec["counts"]["stack"] == 1
    assert rec["located"][0]["function"] == 4096
    assert not list((tmp_path / "cache").glob("*.json"))          # a partial run is never cached
    assert pe.live_progress(sample, "floss") == ""                  # not running any more
    assert not list((tmp_path / "cases" / ".tools_cache" / "live").glob("*"))   # its files cleaned up


def test_finished_floss_ignores_and_cleans_its_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_partial_run(tmp_path, monkeypatch, timed_out=False)
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    rec = pe._run_floss(sample, timeout=60)
    assert rec["status"] == "ok" and not rec.get("partial")
    assert not list((tmp_path / "cases" / ".tools_cache" / "live").glob("*"))


@pytest.mark.skipif(not (VIVPY and RULES), reason="no interpreter with flare-floss / flare-capa (DOCUTRACEX_TEST_VIVPYTHON)")
def test_progress_and_partial_written_by_vivtools(tmp_path: Path) -> None:
    from test_js_techniques import _ms
    sample = tmp_path / "sample_code_loader.exe"
    sample.write_bytes(_ms().code_loader_exe())
    prog, part = tmp_path / "p.json", tmp_path / "part.json"
    r = subprocess.run([VIVPY, "-I", str(settings.vivtools_script()), "floss", "--cache", str(tmp_path / "viv"),
                        "--progress", str(prog), "--partial", str(part), "--",
                        "--json", "-q", "--no", "tight", "--", str(sample)],
                       capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stderr[-800:]
    final = json.loads(r.stdout)
    got = json.loads(part.read_text())                            # same FLOSS format, written as it went
    assert len(got["strings"]["static_strings"]) == len(final["strings"]["static_strings"])
    assert json.loads(prog.read_text())["phase"] in ("decoded strings", "stack strings")


@pytest.mark.skipif(not (VIVPY and RULES), reason="no interpreter with flare-floss / flare-capa (DOCUTRACEX_TEST_VIVPYTHON)")
def test_fast_analysis_saved_apart_and_superseded(tmp_path: Path) -> None:
    from test_js_techniques import _ms
    sample = tmp_path / "sample_code_loader.exe"
    sample.write_bytes(_ms().code_loader_exe())
    cache = tmp_path / "viv"
    script = str(settings.vivtools_script())

    def run(tool: str, args: list[str], fast: bool) -> dict:
        own = ["--cache", str(cache)] + (["--rules", RULES] if tool == "capa" else []) + (["--fast", "1"] if fast else [])
        r = subprocess.run([VIVPY, "-I", script, tool, *own, "--", *args, str(sample)],
                           capture_output=True, text=True, timeout=900)
        assert r.returncode == 0, r.stderr[-800:]
        return json.loads(r.stdout)

    fast = run("floss", ["--json", "-q", "--no", "tight", "--"], fast=True)
    assert [p.name.split(".", 1)[1] for p in cache.glob("*.viv")] == ["fast.bin.viv"]
    run("capa", ["-j", "-q"], fast=True)                            # loads the fast analysis
    full = run("floss", ["--json", "-q", "--no", "tight", "--"], fast=False)
    assert [p.name.split(".", 1)[1] for p in cache.glob("*.viv")] == ["bin.viv"]   # supersedes the fast one
    run("floss", ["--json", "-q", "--no", "tight", "--"], fast=True)               # uses the complete one
    assert [p.name.split(".", 1)[1] for p in cache.glob("*.viv")] == ["bin.viv"]
    assert len(fast["strings"]["static_strings"]) == len(full["strings"]["static_strings"])
