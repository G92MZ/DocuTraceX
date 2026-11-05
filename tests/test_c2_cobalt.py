"""Cobalt Strike in depth: beacon behaviour (DNS, injection, guardrails…),
stagers read from their shellcode, PowerShell payloads decoded to their
shellcode, and traces reported as indicators — never as a configuration."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from docutracex import c2
from docutracex.c2 import cobalt, cobalt_dissect
from docutracex.parsers import ps_deobf

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402


def _scan(tmp_path: Path, name: str, data: bytes) -> list[dict]:
    p = tmp_path / name
    p.write_bytes(data)
    return c2.scan_object(p, data)


def test_helpers() -> None:
    assert cobalt_dissect.host_header("Host: group.example\r\n") == "group.example"
    assert cobalt_dissect.idn("kçi.com") == "xn--ki-4ia.com" and cobalt_dissect.idn("a.example") == ""
    assert "domain fronting" in cobalt_dissect.fronting(["cdn.example.net"], "billing-portal.example")
    assert cobalt_dissect.fronting(["billing-portal.example"], "billing-portal.example") == ""
    assert cobalt._demojibake("kÃ§i.com") == "kçi.com"
    assert cobalt.channel("windows-beacon_https-reverse_https") == "HTTPS"
    assert cobalt.channel("windows-beacon_dns-reverse_http") == "DNS"
    assert cobalt.channel("windows-beacon_smb-bind_pipe") == "SMB"


def test_sections_from_dissect_settings() -> None:
    raw = {"protocol": "dns", "killdate": 0, "guardrail": {"options": ["computer"], "key": "desktop-inv01"},
           "settings": {"SETTING_DNS_IDLE": "198.51.100.9", "SETTING_DNS_SLEEP": 120,
                        "SETTING_DNS_BEACON_BEACON": "fct.", "SETTING_DNS_BEACON_GET_TXT": "api.",
                        "SETTING_PROCINJ_EXECUTE": ["CreateThread", "NtQueueApcThread_s"],
                        "SETTING_PROCINJ_ALLOCATOR": 1, "SETTING_PROCINJ_PERMS_I": 4, "SETTING_PROCINJ_PERMS": 32,
                        "SETTING_PROCINJ_TRANSFORM_X86": [["append", "9090"], ["prepend", ""]],
                        "SETTING_GARGLE_NOOK": 1234, "SETTING_GARGLE_SECTIONS": ["0x1-0x2", "0x3-0x4"],
                        "SETTING_SYSCALL_METHOD": "None", "SETTING_BEACON_GATE": ["VirtualAlloc"]}}
    sec = cobalt_dissect.sections(raw)
    assert sec["DNS channel"]["Idle IP (no tasks)"] == "198.51.100.9"
    assert "beacon=fct." in sec["DNS channel"]["Subdomain prefixes"]
    inj = sec["Process injection"]
    assert inj["Allocator"] == "NtMapViewOfSection" and inj["Initial / final permissions"] == "RW → RX"
    assert inj["Transform x86"] == "append 9090"
    ev = sec["Evasion / runtime"]
    assert ev["Sleep mask"].startswith("yes (2") and "Syscalls" not in ev and ev["Beacon Gate"] == "VirtualAlloc"
    assert sec["Guardrails"]["Value (recovered)"] == "desktop-inv01"


def test_inert_beacons(tmp_path: Path) -> None:
    https = _scan(tmp_path, "b.bin", ms.cs_beacon_blob())[0]
    assert https["status"] == "configuration" and https["summary"]["Host header"] == "billing-portal.example"
    assert "domain fronting" in https["summary"]["Domain fronting"]
    dns = _scan(tmp_path, "d.bin", ms.cs_beacon_blob("dns"))[0]
    assert dns["summary"]["Type"] == "DNS" and "ns1.billing-portal.example:53" in dns["summary"]["C2"]
    smb = _scan(tmp_path, "s.bin", ms.cs_beacon_blob("smb"))[0]
    assert smb["summary"]["Type"] == "SMB" and smb["status"] == "configuration" and "factura_sync" in smb["summary"]["Pipe"]
    if smb["tools"]["dissect"]["status"] == "found":              # dissect provisioned: behaviour sections too
        assert "Peer-to-peer" in smb["sections"]
        assert dns["sections"]["DNS channel"]["Idle IP (no tasks)"] == "198.51.100.9"
        assert https["public_key"].startswith("-----BEGIN PUBLIC KEY-----")


def test_stager_read_from_its_shellcode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cobalt, "_script", lambda: None)            # without 1768.py: the shellcode reader
    r = _scan(tmp_path, "st.bin", ms.cs_stager_shellcode())[0]
    assert r["family"] == "Cobalt Strike" and r["kind"] == "stager"
    s = r["summary"]
    assert s["C2"] == ["cdn-update.example.net:443"] and s["GET URI"] == [ms.CS_STAGER_URI]
    assert s["Type"].startswith("HTTPS")


def test_powershell_payload_decoded_to_binary_stage() -> None:
    import base64
    import gzip
    import re
    outer = ms.cs_beacon_ps1().decode()
    gz = re.search(r'FromBase64String\("([^"]+)"\)', outer).group(1)
    inner = gzip.decompress(base64.b64decode(gz)).decode()
    st = [x for x in ps_deobf.deobfuscate(inner)["stages"] if "data" in x]
    assert st and st[0]["recipe"] == ["base64", "xor(0x23)"] and st[0]["data"][:2] == b"\xfc\xe8"
    # the decoded "shellcode" carries the beacon configuration
    assert cobalt.prefilter(st[0]["data"])
    # no latin-1 text stage of the same bytes
    assert not any("text" in x and x["recipe"] == ["base64"] for x in ps_deobf.deobfuscate(inner)["stages"])


def test_indicators_only(tmp_path: Path) -> None:
    data = ms.C2_STUB + b"\x00pipe format MSSE-%d-server\x00 beacon.x64.dll\x00"
    r = _scan(tmp_path, "art.exe", data)
    cs = [x for x in r if x["family"] == "Cobalt Strike"]
    assert cs and cs[0]["kind"] == "indicators" and cs[0]["c2"] == [] and cs[0]["confidence"] == "low"
    cs[0]["object"] = "art.exe"
    assert c2._finding(cs[0])["severity"] == "medium"
    # one weak trace alone is nothing
    assert cobalt.indicators(b"ReflectiveLoader") == []


def test_indicators_dropped_when_the_configuration_is_there(tmp_path: Path) -> None:
    orig = tmp_path / "case.ps1"
    orig.write_bytes(b"$var_code = ... -bxor 35 ... func_get_delegate_type")
    ext = tmp_path / "extracted"
    ext.mkdir()
    (ext / "stage.bin").write_bytes(ms.cs_beacon_blob())
    res = c2.analyze(orig, ext)
    kinds = [(x["family"], x["kind"]) for x in res["configs"]]
    assert ("Cobalt Strike", "beacon") in kinds and ("Cobalt Strike", "indicators") not in kinds
    assert len(res["findings"]) == len(res["configs"])
