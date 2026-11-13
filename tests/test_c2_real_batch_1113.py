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


def test_hex_here_string_payload_and_key():
    """A loader's next stage as hex in a here-string, XOR-ed with a key written as another hex here-string."""
    from docutracex import decrypted
    code = ms.hex_herestring_ps1().decode()
    keys = decrypted.harvest_keys(code)
    assert any(len(k) == 32 for k in keys["arrays"])
    lits = [(k, raw) for k, raw in decrypted._decode_literals(code) if k == "hex here-string"]
    assert lits
    p = decrypted.payload_child(lits[0][1], "powershell-hex", "x", keys=keys, recipe=["hex here-string"])
    assert p and p["recipe"][1].startswith("xor(key ") and "$stageBytes = (77,90," in p["text"]


def test_stage2_base64_xor_base64_with_string_key():
    """XOR of base64 text with a printable key stays printable: the key that yields
    base64 of a file must win over a single byte that only yields 'text'."""
    import base64
    import re

    from docutracex import decrypted
    code = ms.hex_herestring_ps1().decode()
    keys = decrypted.harvest_keys(code)
    lit = next(raw for k, raw in decrypted._decode_literals(code) if k == "hex here-string")
    stage2 = decrypted.payload_child(lit, "powershell-hex", "x", keys=keys)["text"]
    assert decrypted.sniff_ext(stage2) == ".ps1"
    k2 = decrypted.harvest_keys(stage2)
    blob = base64.b64decode(re.search(r"\$encodedBlob = '([^']+)'", stage2).group(1))
    p = decrypted.payload_child(blob, "powershell-base64", "x", keys=k2, recipe=["base64"])
    assert p["ext"] == ".exe" and p["data"].startswith(b"MZThis is an inert DocuTraceX sample")
    assert p["recipe"][-2:] == ["base64", "exe"]


def test_resource_magic_needs_more_than_two_bytes():
    from docutracex.dotnet.strdec import _payload
    assert _payload(b"\x1f\x8b\xfb\x3b" + b"\0" * 60) is None          # gzip magic, impossible method
    assert _payload(b"\x1f\x8b\x08\x00" + b"\0" * 60) == "gz"
    assert _payload(b"MZ" + b"\x90" * 0x3A + (0x40).to_bytes(4, "little") + b"XX\0\0" + b"\0" * 32) is None


def test_decoded_ole_blob_that_is_an_msi_keeps_msi():
    """A JS dropper's base64 MSI was written as .doc and never opened as an installer."""
    from docutracex import decrypted
    msi = ms.rmm_screenconnect_msi()
    assert decrypted._magic_ext(msi) == ".msi"
    p = decrypted.payload_child(msi, "javascript-base64", "x", recipe=["base64"])
    assert p["ext"] == ".msi"


def test_padded_installer_member_is_debloated(tmp_path):
    """A ~180 KB MSI whose CAB expands to a 101 MB padded PE: extracted and debloated, not refused."""
    from docutracex import unlock
    from docutracex.parsers import debloat_pe
    from docutracex.parsers.unpack import sevenzip_exe
    if sevenzip_exe() is None or not debloat_pe.available():
        pytest.skip("7-Zip (tools/7zip) or debloat not installed")
    p = tmp_path / "padded.msi"
    p.write_bytes(ms.padded_msi())
    r = unlock.extract_msi(p, tmp_path / "out")
    assert r["extracted"] and not r.get("error")
    (e,) = r["entries"]
    assert e["name"] == "InvoiceSearch.exe" and e["size"] < 64 * 1024
    assert e["debloated"]["size_before"] == ms.PADDED_SIZE
    assert any(f["rule"] == "installer_padded_file" for f in r["findings"])


def test_installer_bomb_still_refused(tmp_path, monkeypatch):
    """Without the padding signature (several huge members), the size limits stand."""
    from docutracex import unlock
    from docutracex.parsers.unpack import sevenzip_exe
    if sevenzip_exe() is None:
        pytest.skip("7-Zip (tools/7zip) not installed")
    monkeypatch.setattr(unlock, "PADDED_MAX", 1024)        # padded members above this: not padding
    p = tmp_path / "padded.msi"
    p.write_bytes(ms.padded_msi())
    r = unlock.extract_msi(p, tmp_path / "out")
    assert not r["extracted"] and "size limit" in (r.get("error") or "")


def test_padded_member_of_a_cab_is_debloated(tmp_path):
    """The same padding in a plain cabinet (a WiX 'WrappedSetupProgram' carried one): 7-Zip + debloat."""
    from docutracex import unlock
    from docutracex.parsers import debloat_pe
    from docutracex.parsers.unpack import sevenzip_exe
    if sevenzip_exe() is None or not debloat_pe.available():
        pytest.skip("7-Zip (tools/7zip) or debloat not installed")
    import binkit as bk
    stub = bk.pe(bits=64, gui=True, imports={"kernel32.dll": ["ExitProcess"]}, strings=["inert"])
    cab = ms._build_cab_mszip({"1.js": b"// inert\r\n", "setup.exe": stub + b"\x41" * (ms.PADDED_SIZE - len(stub))})
    p = tmp_path / "wrapped.cab"
    p.write_bytes(cab)
    r = unlock.extract_archive(p, tmp_path / "out", [{"password": "", "source": "none"}])
    assert not r.get("error")
    setup = next(e for e in r["entries"] if e["name"] == "setup.exe")
    assert setup["debloated"]["size_before"] == ms.PADDED_SIZE and setup["size"] < 64 * 1024
    assert any(f["rule"] == "installer_padded_file" for f in r["findings"])


def test_python_hidden_behind_a_docstring(tmp_path):
    """A trojanised installer's extension-less Python: HTML in a docstring, a one-line decoder
    function, exec of reversed base64 + zlib, a shellcode stub in front of a PE."""
    import base64

    from docutracex import decrypted, nested
    from docutracex.parsers import py_layers, python
    data = ms.python_hidden_dropper()
    p = tmp_path / "Kit0"
    p.write_bytes(data)
    assert nested._kind(p, "Kit0") == "python"
    lay = py_layers.unwrap(data.decode())
    assert lay["layers"] == 1 and lay["steps"] == ["reverse", "base64", "zlib"]
    (st,) = python._binary_stages(lay)
    child = decrypted.payload_child(base64.b64decode(st["data_b64"]), "python-stage", "x", recipe=st["recipe"])
    assert child["ext"] == ".exe" and child["data"][:2] == b"MZ"
    assert child["recipe"][-2:] == ["shellcode stub", "PE at +0x10"]


def test_html_and_licence_text_are_not_python(tmp_path):
    from docutracex import nested
    p = tmp_path / "Kit2"
    p.write_bytes(b"A. HISTORY OF THE SOFTWARE\n==========================\n\nPython was created in the early 1990s\n")
    assert nested._kind(p, "Kit2") == "other"
    h = tmp_path / "page"
    h.write_bytes(b"'''<html><body>import x\nfrom a import b\n</body></html>'''\n<p>just text</p>\n")
    assert nested._kind(h, "page") == "other"


def test_no_deep_1768_retries_on_dotnet():
    """Each -x / -e retry is a full 1768.py run (~1 min per few MB): 23 minutes on a trojanised
    installer full of .NET DLLs. Managed assemblies get the default run only."""
    from docutracex.c2 import cobalt
    import binkit as bk
    native = bk.pe(bits=32, gui=True, imports={"kernel32.dll": ["ExitProcess"]}, strings=["x"])
    assert not cobalt._is_dotnet(native)
    dotnet = ms.agenttesla_exe()
    assert cobalt._is_dotnet(dotnet)
    if cobalt._script() is not None:
        assert not cobalt.deep_candidate(dotnet) and cobalt.deep_candidate(native)


def test_upx_packed_elf_is_unpacked(tmp_path):
    """UPX-packed Go / Linux implants: the PE path unpacked UPX, ELF / Mach-O did not."""
    from docutracex.parsers import msi
    from docutracex.parsers.unpack import upx_exe
    if upx_exe() is None:
        pytest.skip("UPX (tools/upx) not installed")
    p = tmp_path / "sample_elf_upx"
    p.write_bytes(ms.upx_elf())
    it = msi.analyze_binary(p, p.name, tmp_path / "unpacked")
    assert it["unpack"]["status"] == "ok"
    (child,) = it["_children"]
    data = Path(child["path"]).read_bytes()
    assert data[:4] == b"\x7fELF" and b"cdn-update.example.net" in data and b"UPX!" not in data[:4096]
    assert any(f["rule"] == "native_upx_unpacked" for f in it["findings"])


def test_elf_without_upx_is_left_alone(tmp_path):
    import binkit as bk

    from docutracex.parsers import msi
    p = tmp_path / "plain"
    p.write_bytes(bk.elf(strings=["inert"]))
    it = msi.analyze_binary(p, p.name, tmp_path / "unpacked")
    assert "unpack" not in it and not it.get("_children")
