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


def test_cleanup_failure_never_fails_a_finished_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows: vivisect keeps the binary it analysed open in the same process, so its
    private copy cannot be deleted at the end. That must not turn a finished FLOSS run
    into an error (it did: exit 1, 13 minutes of strings lost); a later run cleans it up."""
    import os
    import re
    import time

    from docutracex import vivtools
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\0" * 64)
    cache = tmp_path / "viv"

    def fake_run(tool, argv):  # noqa: ANN001, ANN202 — FLOSS ran and saved its analysis
        Path(f"{argv[-1]}.viv").write_bytes(b"viv")
        return 0
    real_unlink = Path.unlink

    def locked(self, missing_ok=False):  # noqa: ANN001, ANN202
        if re.match(r"^[0-9a-f]{64}\.\d+\.", self.name):
            raise PermissionError(32, "being used by another process")
        return real_unlink(self, missing_ok=missing_ok)
    monkeypatch.setattr(vivtools, "_run", fake_run)
    monkeypatch.setattr(Path, "unlink", locked)
    rc = vivtools.main(["floss", "--cache", str(cache), "--", "--json", "--", str(sample)])
    assert rc == 0
    assert len(list(cache.glob("*.bin.viv"))) == 1                         # the analysis was saved
    left = [f for f in cache.iterdir() if re.match(r"^[0-9a-f]{64}\.\d+\.", f.name)]
    assert left                                                             # the locked copy stayed
    monkeypatch.setattr(Path, "unlink", real_unlink)
    old = time.time() - 7200
    for f in left:
        os.utime(f, (old, old))
    vivtools._prune(cache, 6)                                               # the next run's cleanup
    assert not [f for f in cache.iterdir() if re.match(r"^[0-9a-f]{64}\.\d+\.", f.name)]
    assert len(list(cache.glob("*.bin.viv"))) == 1


def test_rust_language_strings_used_and_glued_blob_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FLOSS's language strings (a Rust binary's strings split apart) are taken; the static
    string that is only those strings glued together is left out, so a URL does not run
    into the next string."""
    from docutracex import proctools
    parts = ["https://facturas-cdn.example/gate.php", "Mozilla/5.0 (Windows NT 10.0)", "pedido_7731.pdf"]
    offs, o = [], 0x1200
    for p in parts:
        offs.append(o)
        o += len(p)
    out = {"metadata": {"version": "3.2.0", "language": "rust", "language_version": "1.74.0"},
           "strings": {"static_strings": [{"string": "!This program cannot be run in DOS mode.", "offset": 0x4e},
                                          {"string": "".join(parts), "offset": 0x1200}],
                       "language_strings": [{"string": p, "offset": off} for p, off in zip(parts, offs)]}}

    def fake_run(cmd, timeout, cwd=None, env=None, cancel=None):  # noqa: ANN001, ANN202
        return {"rc": 0, "out": json.dumps(out), "err": "", "timed_out": False, "duration_s": 1}
    monkeypatch.setattr(proctools, "run_bounded", fake_run)
    monkeypatch.setattr(settings, "floss_executable", lambda: tmp_path / "floss.exe")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    rec = pe._run_floss(sample)
    assert rec["status"] == "ok" and rec["language"] == "rust" and rec["language_version"] == "1.74.0"
    assert parts[0] in rec["strings"] and "".join(parts) not in rec["strings"]
    assert rec["counts"]["language"] == 3 and rec["counts"]["static"] == 1
    assert "3 rust (split)" in rec["detail"]


@pytest.mark.skipif(not VIVPY, reason="no interpreter with flare-floss (DOCUTRACEX_TEST_VIVPYTHON)")
def test_rust_sample_split_by_the_python_stand_in(tmp_path: Path) -> None:
    """End to end: FLOSS through vivtools, binary2strings replaced by b2s_compat, on the
    Rust-like sample: rustc identified and its strings split."""
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import zipcrypto
    sample = tmp_path / "sample_rust_strings.exe"
    sample.write_bytes(zipcrypto.read(Path(__file__).resolve().parent.parent / "samples" / "samples.zip",
                                      "windows-pe/sample_rust_strings.exe"))
    env = {**os.environ, "DOCUTRACEX_B2S_COMPAT": "1"}
    r = subprocess.run([VIVPY, "-I", str(settings.vivtools_script()), "floss", "--cache", str(tmp_path / "viv"), "--",
                        "--json", "-q", "--no", "tight", "decoded", "stack", "--", str(sample)],
                       capture_output=True, text=True, timeout=900, env=env)
    assert r.returncode == 0, r.stderr[-800:]
    data = json.loads(r.stdout)
    assert data["metadata"]["language"] == "rust" and data["metadata"]["language_version"] == "1.74.0"
    got = {s["string"] for s in data["strings"]["language_strings"]}
    assert "https://facturas-cdn.example/gate.php" in got and "pedido_7731.pdf" in got and len(got) == 7
