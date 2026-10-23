"""FLOSS / capa integration in the PE triage (standalone binaries, mocked).

No real floss.exe / capa.exe is run: proctools.run_bounded is replaced with
canned JSON shaped like FLOSS 3.2.0 and capa 10.0.0 output.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from docutracex.config import settings
from docutracex.parsers import pe

FLOSS_JSON = {
    "metadata": {"version": "3.2.0", "file_path": "x.exe"},
    "strings": {
        "decoded_strings": [{"string": "hxxp://evil.example/a"}, {"string": "  "}],
        "stack_strings": [{"string": "cmd.exe /c whoami"}],
        "tight_strings": [],
        "static_strings": [],
    },
}

CAPA_JSON = {
    "meta": {"version": "10.0.0"},
    "rules": {
        "create process on Windows": {
            "meta": {"name": "create process on Windows",
                     "namespace": "host-interaction/process/create",
                     "attack": [{"parts": ["Execution"], "tactic": "Execution", "technique": "x",
                                 "subtechnique": "", "id": "T1106"}],
                     "mbc": [{"id": "C0017"}], "lib": False, "is_subscope_rule": False},
            "matches": [[{"type": "absolute", "value": 4096}, {}]],
        },
        "check for debugger via API": {
            "meta": {"name": "check for debugger via API", "namespace": "anti-analysis/anti-debugging",
                     "attack": [], "mbc": [], "lib": False},
            "matches": [[{}, {}], [{}, {}]],
        },
        "contain loop": {
            "meta": {"name": "contain loop", "namespace": "", "attack": [], "mbc": [], "lib": True},
            "matches": [],
        },
    },
}


def _fake_exe(tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    p.write_bytes(b"MZ")
    return p


def _patch_run(monkeypatch, outputs: dict[str, object]) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(cmd, timeout, cwd=None, env=None):
        calls.append(cmd)
        out = outputs[Path(cmd[0]).stem]
        if isinstance(out, subprocess.TimeoutExpired):
            return {"rc": None, "out": "", "err": "", "timed_out": True, "duration_s": timeout}
        if isinstance(out, BaseException):
            return {"rc": None, "out": "", "err": "", "timed_out": False, "error": str(out),
                    "duration_s": 0.0}
        rc, text = out
        return {"rc": rc, "out": text, "err": "boom" if rc else "", "timed_out": False,
                "duration_s": 0.1}

    from docutracex import proctools
    monkeypatch.setattr(proctools, "run_bounded", fake_run)
    return calls


def test_not_provisioned_is_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "floss_executable", lambda: None)
    monkeypatch.setattr(settings, "capa_executable", lambda: None)
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\0" * 64)
    assert pe._run_floss(sample)["status"] == "not_provisioned"
    assert pe._run_capa(sample)["status"] == "not_provisioned"


def test_floss_parsing(tmp_path, monkeypatch) -> None:
    exe = _fake_exe(tmp_path, "floss.exe")
    monkeypatch.setattr(settings, "floss_executable", lambda: exe)
    calls = _patch_run(monkeypatch, {"floss": (0, json.dumps(FLOSS_JSON))})
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r = pe._run_floss(sample)
    assert r["status"] == "ok"
    assert r["strings"] == ["hxxp://evil.example/a", "cmd.exe /c whoami"]
    assert r["counts"] == {"decoded": 1, "stack": 1, "tight": 0}
    assert r["version"] == "3.2.0"
    assert calls[0][1:5] == ["--json", "--no", "static", "--quiet"]
    assert calls[0][5:8] == ["--large-file", "-n", "8"]


def test_capa_parsing_skips_lib_rules(tmp_path, monkeypatch) -> None:
    exe = _fake_exe(tmp_path, "capa.exe")
    monkeypatch.setattr(settings, "capa_executable", lambda: exe)
    _patch_run(monkeypatch, {"capa": (0, json.dumps(CAPA_JSON))})
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r = pe._run_capa(sample)
    assert r["status"] == "ok"
    assert r["total"] == 2                      # "contain loop" (lib) dropped
    assert r["attack_ids"] == ["T1106"]
    names = {c["name"]: c for c in r["capabilities"]}
    assert names["create process on Windows"]["mbc"] == ["C0017"]
    assert names["check for debugger via API"]["matches"] == 2
    assert pe._capa_severity(names["check for debugger via API"]) == "medium"
    assert pe._capa_severity(names["create process on Windows"]) == "low"


@pytest.mark.parametrize("out,status", [
    ((14, ""), "error"),                        # e.g. capa E_FILE_LIMITATION
    ((0, "not json"), "error"),
    (subprocess.TimeoutExpired("capa", 1), "timeout"),
])
def test_capa_failures_are_visible(tmp_path, monkeypatch, out, status) -> None:
    exe = _fake_exe(tmp_path, "capa.exe")
    monkeypatch.setattr(settings, "capa_executable", lambda: exe)
    _patch_run(monkeypatch, {"capa": out})
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r = pe._run_capa(sample)
    assert r["status"] == status and r["detail"]


def test_pyinstaller_detection(tmp_path) -> None:
    p = tmp_path / "frozen.exe"
    p.write_bytes(b"MZ" + b"\0" * 1000 + pe._PYI_MAGIC + b"\0" * 80)
    assert pe._is_pyinstaller(p) is True
    q = tmp_path / "plain.exe"
    q.write_bytes(b"MZ" + b"\0" * 2000)
    assert pe._is_pyinstaller(q) is False


def test_analyze_skips_tools_for_pyinstaller(tmp_path, monkeypatch) -> None:
    pytest.importorskip("pefile")
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import make_samples as ms

    p = tmp_path / "frozen.exe"
    p.write_bytes(ms.packed_pe_exe() + pe._PYI_MAGIC + b"\0" * 80)
    called = []
    monkeypatch.setattr(pe, "_run_floss", lambda path: called.append("floss") or {})
    monkeypatch.setattr(pe, "_run_capa", lambda path: called.append("capa") or {})
    r = pe.analyze(p, "frozen.exe", run_tools=True)
    assert called == []
    assert r["floss"]["status"] == "skipped" and r["capa"]["status"] == "skipped"


def test_analyze_capa_findings(tmp_path, monkeypatch) -> None:
    pytest.importorskip("pefile")
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import make_samples as ms

    p = tmp_path / "plain.exe"
    # Same inert PE with the UPX section names changed: no packer detected, so
    # FLOSS/capa are not skipped (a packed PE would skip them — see test_unpack).
    p.write_bytes(ms.packed_pe_exe().replace(b"UPX0", b".text").replace(b"UPX1", b".data"))
    from docutracex.parsers import unpack
    monkeypatch.setattr(unpack, "run_die", lambda path: {"status": "not_provisioned"})
    caps = [{"name": "check for debugger via API", "namespace": "anti-analysis/anti-debugging",
             "attack": [{"id": "T1622"}], "mbc": [], "matches": 1},
            {"name": "contain obfuscated stackstrings", "namespace": "", "attack": [],
             "mbc": [], "matches": 1}]
    monkeypatch.setattr(pe, "_run_floss", lambda path: {"status": "ok", "strings": ["abc"]})
    monkeypatch.setattr(pe, "_run_capa", lambda path: {"status": "ok", "capabilities": caps})
    r = pe.analyze(p, "plain.exe", run_tools=True)
    rules = [f["rule"] for f in r["findings"]]
    assert rules.count("pe_capa_capability") == 1          # the "info" one is UI-only
    assert "pe_floss_strings" in rules
    assert r["floss_strings"] == ["abc"] and "strings" not in r["floss"]
