"""PE packer detection + static unpacking (tools mocked; nothing is executed)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("pefile")

import pefile  # noqa: E402

from docutracex.parsers import pe, unpack  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import make_samples as ms  # noqa: E402

_UPX_PE = ms.packed_pe_exe()   # inert PE with UPX0/UPX1 sections, no code


def _pe(blob: bytes):
    return pefile.PE(data=blob, fast_load=True)


def test_heuristics_upx_by_sections() -> None:
    hits = unpack.heuristics(_UPX_PE, _pe(_UPX_PE))
    assert [h["family"] for h in hits] == ["upx"]


def test_heuristics_markers() -> None:
    base = _UPX_PE.replace(b"UPX0", b"AAAA").replace(b"UPX1", b"BBBB")
    assert unpack.heuristics(base, _pe(base)) == []
    au3 = base + b"\0" * 64 + b"AU3!EA06" + b"\0" * 64
    assert [h["family"] for h in unpack.heuristics(au3, _pe(au3))] == ["autoit"]
    inno = base + b"Inno Setup Setup Data (6.2.0)"
    assert "inno" in [h["family"] for h in unpack.heuristics(inno, _pe(inno))]
    nsis = base + b"\xef\xbe\xad\xdeNullsoftInst"
    assert "nsis" in [h["family"] for h in unpack.heuristics(nsis, _pe(nsis))]
    zsfx = base + b"PK\x03\x04" + b"\0" * 100
    assert "sfxzip" in [h["family"] for h in unpack.heuristics(zsfx, _pe(zsfx))]


def test_no_static_protector() -> None:
    blob = _UPX_PE.replace(b"UPX0", b".vmp0").replace(b"UPX1", b".vmp1")
    pe_ = _pe(blob)
    assert unpack.no_static_hits(pe_) == ["VMProtect"]
    rec = unpack.process(Path("x.exe"), blob, pe_, None, use_die=False)
    assert rec["status"] == "no_static"
    assert rec["findings"][0]["rule"] == "pe_protector"


def test_die_families_mapping() -> None:
    die = {"status": "ok", "detects": [
        {"type": "Packer", "name": "UPX", "version": "4.02", "info": "", "string": "Packer: UPX(4.02)"},
        {"type": "Protector", "name": "Themida/Winlicense", "version": "3.x", "info": "", "string": ""},
        {"type": "Compiler", "name": "Microsoft Visual C/C++", "version": "", "info": "", "string": ""},
        {"type": "Archive", "name": "ZIP", "version": "", "info": "", "string": ""},
    ]}
    fams, other = unpack.die_families(die)
    assert [f["family"] for f in fams] == ["upx", "sfxzip"]
    assert fams[0]["label"] == "UPX 4.02"
    assert other == ["Themida/Winlicense 3.x"]


def test_detect_only_without_out_dir() -> None:
    rec = unpack.process(Path("x.exe"), _UPX_PE, _pe(_UPX_PE), None, use_die=False)
    assert rec["status"] == "detected" and "UPX" in rec["detail"]


def test_upx_not_provisioned(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(unpack, "upx_exe", lambda: None)
    p = tmp_path / "s.exe"
    p.write_bytes(_UPX_PE)
    rec = unpack.process(p, _UPX_PE, _pe(_UPX_PE), tmp_path / "out", use_die=False)
    assert rec["status"] == "not_provisioned"
    assert any(f["rule"] == "pe_unpack_failed" for f in rec["findings"])


def test_upx_unpacked_and_repair_retry(tmp_path, monkeypatch) -> None:
    exe = tmp_path / "upx.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(unpack, "upx_exe", lambda: exe)
    calls: list[list[str]] = []

    def fake_run(cmd, timeout, cwd=None, env=None):
        calls.append(cmd)
        if len(calls) == 1:        # first try fails (hacked header)
            return {"rc": 1, "out": "", "err": "NotPackedException", "timed_out": False,
                    "duration_s": 0.1}
        Path(cmd[cmd.index("-o") + 1]).write_bytes(b"MZunpacked")
        return {"rc": 0, "out": "", "err": "", "timed_out": False, "duration_s": 0.1}

    from docutracex import proctools
    monkeypatch.setattr(proctools, "run_bounded", fake_run)
    blob = _UPX_PE.replace(b"UPX0", b"XYZ0").replace(b"UPX1", b"XYZ1")
    blob = blob[:0x300] + b"UPX!" + blob[0x304:]   # marker only -> detected by "UPX!"
    p = tmp_path / "s.exe"
    p.write_bytes(blob)
    rec = unpack.process(p, blob, _pe(blob), tmp_path / "out", use_die=False)
    assert rec["status"] == "unpacked", rec
    assert "repaired" in rec["tool"]
    assert rec["files"][0]["name"].endswith(".unpacked.exe")
    assert rec["_files"] and Path(rec["_files"][0][0]).read_bytes() == b"MZunpacked"
    assert any(f["rule"] == "pe_unpacked" and f["severity"] == "medium" for f in rec["findings"])


def test_pe_analyze_skips_floss_capa_when_unpacked(tmp_path, monkeypatch) -> None:
    called = []
    monkeypatch.setattr(pe, "_run_floss", lambda p: called.append("floss") or {})
    monkeypatch.setattr(pe, "_run_capa", lambda p: called.append("capa") or {})

    def fake_process(path, blob, pe_, out_dir, use_die=True):
        return {"status": "unpacked", "detail": "UPX: ok", "tool": "upx -d", "detected": [],
                "files": [{"name": "a.exe", "size": 2}], "scripts": [],
                "_files": [(str(tmp_path / "a.exe"), "a.exe")], "findings": []}

    monkeypatch.setattr(unpack, "process", fake_process)
    p = tmp_path / "s.exe"
    p.write_bytes(_UPX_PE)
    r = pe.analyze(p, "s.exe", run_tools=True, unpack_dir=tmp_path / "u")
    assert called == []
    assert r["floss"]["status"] == "skipped" and "unpacked" in r["floss"]["detail"]
    assert r["_unpacked_files"] == [(str(tmp_path / "a.exe"), "a.exe")]
    assert r["unpack"]["status"] == "unpacked" and "_files" not in r["unpack"]


def test_floss_skips_big_files(tmp_path, monkeypatch) -> None:
    p = tmp_path / "big.exe"
    with p.open("wb") as fh:
        fh.truncate(pe.FLOSS_MAX_FILE + 1)
    r = pe._run_floss(p)
    assert r["status"] == "skipped" and "too large" in r["detail"]
