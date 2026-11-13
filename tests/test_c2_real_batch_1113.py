"""Findings of a validation batch with real samples (Cobalt Strike stagers, msfvenom
psh-cmd, a Discord token grabber), reproduced with inert samples."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from docutracex import c2
from docutracex.c2 import cobalt, metasploit, sc_decoder, stealers
from docutracex.parsers import ps_deobf

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

ms = pytest.importorskip("make_samples")
HAS_UNICORN = importlib.util.find_spec("unicorn") is not None

HOST = "203.0.113.77"


def test_1768_new_report_format_is_read():
    """1768.py 0.0.23 says 'Found shellcode:', names the stager and reads the license id."""
    msgs = ["File: x.bin", "Found shellcode:", "Identification: CS reverse http x86 shellcode",
            f"Parameter: 778 b'{HOST}'", "license-id: 792 20260613",
            "push      :   190         80 b'hP\\x00\\x00\\x00'",
            "String: 520 b'User-Agent: Mozilla/5.0 (Windows NT 10.0)'"]
    res = cobalt._stager_from_messages(msgs, sc=b"")
    assert res is not None and res["kind"] == "stager"
    assert res["fields"]["license-id"]["raw"] == 20260613
    assert res["fields"]["identification"]["value"].startswith("CS reverse http")
    assert HOST in res["fields"]["server,get-uri"]["value"]


def test_license_id_after_host_tells_cobalt_from_metasploit():
    sc = ms.cs_stager_license_bin()
    res = cobalt._stager_from_shellcode(sc)
    assert res is not None
    assert res["fields"]["license-id"]["raw"] == 20260613
    # the same shapes ending at the host's NUL (Metasploit) are not Cobalt Strike
    msf = sc[:-4]
    assert cobalt._stager_from_shellcode(msf) is None


def test_long_uuid_uri_is_not_cobalt_checksum8():
    """Metasploit's stage URIs carry a 22+ character payload UUID; its checksum can be 92 too."""
    uri = "/" + "A" * 21
    while sum(uri[1:].encode()) % 256 != 92:
        uri = uri[:-1] + chr(ord(uri[-1]) + 1)
    msgs = ["Probably found shellcode:", f"Parameter: 600 b'{HOST}'", f"String: 620 b'{uri}'"]
    assert cobalt._stager_from_messages(msgs, sc=b"") is None
    assert cobalt._stager_from_messages(msgs[:2] + ["String: 620 b'/Fctadz'"], sc=b"") is not None


def test_newer_block_api_prologue():
    sc = b"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c" + b" -- inert --"
    assert metasploit.prefilter(sc)
    assert cobalt._block_api_head(sc)


def test_powershell_base64_argument_is_decoded():
    code = ms.msf_psh_cmd_ps1().decode()
    r = ps_deobf.deobfuscate(code)
    assert "powershell-base64-argument" in r["methods"]
    assert "[Byte[]]$z = 0xd9,0xee,0xd9,0x74,0x24,0xf4" in r["code"]


def test_getpc_stub_is_a_binary_payload():
    sc = ms._inert_xor_stub(b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5" + b" -- inert --")
    assert ps_deobf._is_binary_payload(sc)
    assert sc_decoder.decoder(sc) == ("x86", "FPU-GetPC encoder (shikata_ga_nai style)")
    assert sc_decoder.decoder(b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5") is None


@pytest.mark.skipif(not HAS_UNICORN, reason="Unicorn not installed")
def test_encoder_stub_decoded_by_emulation(tmp_path):
    blob = ms.msf_https_stager_blob()
    payload = blob[blob.index(b"\xfc\xe8\x82"):]
    sc = ms._inert_xor_stub(payload)
    dec = sc_decoder.decode(sc)
    assert dec is not None and dec["offset"] == 0x14 and dec["data"] == payload
    p = tmp_path / "sc.bin"
    p.write_bytes(sc)
    out, _runs = c2.scan_object_detailed(p, sc)
    msf = [o for o in out if o["family"].startswith("Metasploit")]
    assert msf and "cdn-update.example.net" in msf[0]["c2"]
    assert "decoded by emulation" in msf[0]["method"]
    assert msf[0]["summary"]["Encoder"].startswith("FPU-GetPC encoder")


@pytest.mark.skipif(not HAS_UNICORN, reason="Unicorn not installed")
def test_emulation_stops_without_a_payload():
    # a stub that decodes noise never reaches a block_api head: nothing returned
    sc = ms._inert_xor_stub(b"nothing but text here, no payload at all" * 4)
    assert sc_decoder.decode(sc) is None


def test_discord_webhook_grabber():
    data = ms.discord_grabber_exe()
    r = stealers.discord_webhook(data)
    assert r is not None and r["kind"] == "stealer"
    assert r["family"] == "FacturaGrabber"
    assert r["c2"] == ["https://discord.com/api/webhooks/100000000000000001/"
                       "Inert-DocuTraceX-sample-token_00000000000000000000000000000000000000"]
    assert "Discord tokens" in r["summary"]["Steals"]
    assert any(x["family"] == "FacturaGrabber" for x in stealers.extract_all(data))


def test_discord_webhook_alone_is_an_indicator():
    data = b"MZ inert " + b"https://discord.com/api/webhooks/100000000000000002/" + b"x" * 68
    r = stealers.discord_webhook(data)
    assert r is not None and r["kind"] == "indicators" and r["family"] == "Discord webhook"
