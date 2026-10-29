"""C2 / implant configuration extraction (C2 / Beacons tab)."""

from __future__ import annotations

import base64
import struct
import sys
from pathlib import Path

import pytest

from docutracex import c2
from docutracex.c2 import cobalt, dotnet_rats, metasploit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms


def _scan(tmp_path: Path, name: str, data: bytes) -> list[dict]:
    p = tmp_path / name
    p.write_bytes(data)
    return c2.scan_object(p, data)


@pytest.mark.parametrize("name, family, c2_host", [
    ("c2/sample_cs_beacon.bin", "Cobalt Strike", "cdn-update.example.net"),
    ("c2/sample_msf_https_stager.bin", "Metasploit / Meterpreter", "cdn-update.example.net"),
    ("c2/sample_remcos.exe", "Remcos", "203.0.113.47"),
    ("c2/sample_asyncrat.exe", "AsyncRAT", "203.0.113.47"),
    ("c2/sample_quasar.exe", "QuasarRAT", "203.0.113.47"),
])
def test_samples_yield_their_configuration(tmp_path: Path, name: str, family: str, c2_host: str) -> None:
    data = ms.c2_samples()[name]
    res = _scan(tmp_path, Path(name).name, data)
    assert [r["family"] for r in res] == [family]
    assert c2_host in res[0]["c2"]
    assert res[0]["confidence"] == "high"


def test_cobalt_strike_fields(tmp_path: Path) -> None:
    r = _scan(tmp_path, "b.bin", ms.cs_beacon_blob())[0]
    s = r["summary"]
    assert s["C2"] == ["cdn-update.example.net:443"]
    assert s["Watermark"] == "20260187"
    assert s["Sleep / jitter"] == "45s / 25%"
    assert "factura_sync" in s["Pipe"]
    assert "rundll32.exe" in s["Spawn to"]


def test_cobalt_strike_builtin_decoder_without_1768(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cobalt, "_script", lambda: None)
    r = _scan(tmp_path, "b.bin", ms.cs_beacon_blob())[0]
    assert r["method"].startswith("built-in decoder (XOR 0x2e)")
    assert r["summary"]["C2"] == ["cdn-update.example.net:443"]
    # XOR 0x69 (Cobalt Strike 3.x) too
    blob = ms.cs_beacon_blob()
    plain = bytes(c ^ 0x2E for c in blob[len(ms.C2_STUB):])
    r = _scan(tmp_path, "b3.bin", ms.C2_STUB + bytes(c ^ 0x69 for c in plain))[0]
    assert "XOR 0x69" in r["method"] and r["summary"]["Type"] == "HTTPS"


def test_metasploit_reverse_tcp_x86_and_x64() -> None:
    x86 = (metasploit.BLOCK_API["x86"][0] + b"\x90" * 40
           + b"\x68" + bytes([192, 0, 2, 44]) + b"\x68\x02\x00" + struct.pack(">H", 4444) + b"\x89\xe6")
    r = metasploit.extract(x86)
    assert r["summary"]["C2"] == ["192.0.2.44:4444"] and r["summary"]["Transport"] == "reverse_tcp"
    x64 = (metasploit.BLOCK_API["x64"][0] + b"\x90" * 40
           + b"\x49\xbc\x02\x00" + struct.pack(">H", 8443) + bytes([198, 51, 100, 9]))
    r = metasploit.extract(x64)
    assert r["summary"]["C2"] == ["198.51.100.9:8443"] and r["summary"]["Architecture"] == "x64"


def test_metasploit_prologue_without_target_is_low_confidence() -> None:
    r = metasploit.extract(metasploit.BLOCK_API["x86"][0] + b"\x00" * 64)
    assert r["confidence"] == "low" and r["c2"] == []


def test_dcrat_salt_is_recognised() -> None:
    import binkit as bk

    master = b"DcKey0123456789abcdefABCDEF"
    enc = lambda v: ms._rat_encrypt(master, b"DcRatByqwqdanchun", v)
    exe = bk.pe(bits=32, gui=True, dotnet={
        "assembly": "Client", "strings": ["Aes256"],
        "user_strings": [enc("8848"), enc("cdn-update.example.net"), enc("1.0.7"), enc("DcRatMutex_qwqdanchun"),
                         base64.b64encode(master).decode()]})
    r = dotnet_rats.extract(exe)
    assert r["family"] == "DcRAT"
    assert r["summary"]["C2"] == ["cdn-update.example.net:8848"]


def test_user_strings_reader() -> None:
    import binkit as bk

    exe = bk.pe(bits=32, dotnet={"assembly": "A", "strings": [], "user_strings": ["hola", "x" * 200, "ñandú"]})
    assert dotnet_rats.user_strings(exe) == ["hola", "x" * 200, "ñandú"]


@pytest.mark.parametrize("name", ["ml/sample_dotnet_invoice_tool.dll", "ml/sample_dotnet_loader.exe",
                                  "ml/sample_win32_invoice_calc.dll", "ml/sample_win64_packed_loader.exe"])
def test_no_configuration_in_other_binaries(tmp_path: Path, name: str) -> None:
    assert _scan(tmp_path, Path(name).name, ms.ml_samples()[name]) == []


def test_analyze_case_findings_and_dedup(tmp_path: Path) -> None:
    from docutracex.findings import finding_id

    orig = tmp_path / "orig.bin"
    orig.write_bytes(ms.cs_beacon_blob())
    ext = tmp_path / "extracted"
    (ext / "stage").mkdir(parents=True)
    (ext / "stage" / "copy.bin").write_bytes(ms.cs_beacon_blob())     # the same beacon again
    (ext / "stage" / "remcos.exe").write_bytes(ms.remcos_exe())
    res = c2.analyze(orig, ext)
    assert res["objects_scanned"] == 3
    assert [c["family"] for c in res["configs"]] == ["Cobalt Strike", "Remcos"]
    assert res["configs"][0]["also_in"] == ["extracted/stage/copy.bin"]
    f = res["findings"][0]
    assert f["severity"] == "high" and f["detail"].startswith("Cobalt Strike configuration (beacon): C2 ")
    assert res["configs"][0]["finding_id"] == finding_id("c2", f["rule"], f["location"], f["detail"])


def test_case_end_to_end_report_and_csv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    from fastapi.testclient import TestClient

    from docutracex import analyze, cases
    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.asyncrat_exe()), "factura.exe", cases_dir=tmp_path)
    cid = m["analysis_id"]
    analyze.analyze_case(tmp_path / cid)
    client = TestClient(create_app())
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert comp["modules"]["c2"]["configs"][0]["family"] == "AsyncRAT"
    values = {i["value"] for i in comp["iocs"]["iocs"]}
    assert {"cdn-update.example.net", "203.0.113.47"} <= values
    f = next(x for x in comp["findings"] if x["source"] == "c2")
    assert "No IOCs marked" in client.get(f"/api/cases/{cid}/report").text
    assert "marked (0 of 1)" in client.get(f"/api/cases/{cid}/report").text
    client.put(f"/api/cases/{cid}/marks/{f['id']}", json={"state": "true_positive"})
    body = client.get(f"/api/cases/{cid}/report").text
    assert "C2 / implant configurations — marked (1 of 1)" in body and "AsyncMutex_6SI8OkPnk" in body
    csv = client.get(f"/api/cases/{cid}/c2.csv").content.decode("utf-8-sig")
    assert "AsyncRAT" in csv and "true_positive" in csv
