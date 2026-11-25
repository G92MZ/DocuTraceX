"""Loaders seen in 2025 that stopped the chain before the payload.

An MSAP container dropped next to its native loader (key built on the loader's stack, Windows Compression
API inside), a .NET packer that keeps its payload as a static array and decrypts it in place, string
decoders that take a string and a key, a PowerShell loader that checks an HMAC before decrypting, and a
WSH dropper that cleans its payload with VBScript.RegExp. All inert.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex import c2, msap  # noqa: E402
from docutracex.dotnet import cilemu  # noqa: E402
from docutracex.resolve import js_eval, ps_eval  # noqa: E402

C2 = ["factura-cdn.example", "pago-seguro.example", "visor-docs.example"]


def _dropped() -> tuple[bytes, bytes]:
    s = ps_eval.resolve(_ms().msap_dropper_ps1().decode())
    loader, container = (bytes(st.data) for st in s.stages)
    return loader, container


def test_msap_cipher_round_trip() -> None:
    blob = msap.encrypt(b"k3y-0187", b"nonce187", b"MZ inert payload")
    assert msap.is_container(blob)
    c = msap.Cipher(b"k3y-0187", blob[5:13])
    assert c.crypt(blob[13:21]) == msap.TOKEN and c.crypt(blob[21:]) == b"MZ inert payload"


def test_msap_key_from_the_loader_stack_and_payload() -> None:
    loader, container = _dropped()
    assert "Fct0187MsapKey$Inert2026xQ" in msap.stack_strings(loader)
    r = msap.open_container(container, loader)
    assert r and r["pe"] and r["data"][:2] == b"MZ"
    assert any("XPRESS Huffman" in x for x in r["recipe"])
    assert c2.scan_object(Path("p.exe"), r["data"])[0]["summary"]["C2"] == C2


def test_msap_wrong_loader_opens_nothing() -> None:
    _, container = _dropped()
    assert msap.open_container(container, b"MZ" + b"\x00" * 200 + b"MSAPTOK") is None


def test_msap_pairs_written_as_children(tmp_path: Path) -> None:
    loader, container = _dropped()
    (tmp_path / "a.exe").write_bytes(loader)
    (tmp_path / "b.dat").write_bytes(container)
    got = msap.open_pairs([{"path": str(tmp_path / "a.exe"), "filename": "a.exe"},
                           {"path": str(tmp_path / "b.dat"), "filename": "b.dat"}], tmp_path / "out")
    assert len(got) == 1 and got[0]["filename"] == "b_payload.exe"
    assert Path(got[0]["path"]).read_bytes()[:2] == b"MZ"


def test_dotnet_static_array_packer_is_unpacked() -> None:
    data = _ms().dotnet_packed_array_exe()
    got = cilemu.unpack_payloads(data)
    assert len(got) == 1 and got[0][0][:2] == b"MZ" and "decrypts the static array" in got[0][1][0]
    assert c2.scan_object(Path("p.exe"), got[0][0])[0]["summary"]["C2"] == C2


def test_string_and_key_decoder_call_sites() -> None:
    em = cilemu.confuser_strings(_ms().dotnet_packed_array_exe())
    out = [s["output"] for s in em["strings"]]
    assert sorted(out) == sorted(["http://cdn-update.example.net/factura/0187", "InstallUtil.exe",
                                  "factura_2026-0187_joiner"])


def test_powershell_hmac_check_passes() -> None:
    s = ps_eval.resolve(_ms().hmac_aes_loader_ps1().decode())
    assert not s.errors
    assert any("cdn-update.example.net/factura/0187/stage3.ps1" in str(st.data) for st in s.stages)


def test_wsh_vbscript_regexp_pipeline() -> None:
    s = js_eval.resolve(_ms().wsh_regexp_xor_js().decode())
    assert any("integrity-checked loader" in str(st.data) for st in s.stages)


def test_case_follows_msap_dropper_to_the_c2(client) -> None:  # noqa: ANN001, F811
    _, res = _analyze(client, "factura.ps1", _ms().msap_dropper_ps1())
    tree = json.loads((res / "nested.json").read_text())
    text = json.dumps(tree)
    assert "_payload.exe" in text and "MSAP container" in text
    c2r = json.loads((res / "c2.json").read_text()) if (res / "c2.json").exists() else {}
    assert "factura-cdn.example" in json.dumps(c2r)


def test_random_file_name_does_not_stop_the_dropper() -> None:
    code = ('var fs = new ActiveXObject("Scripting.FileSystemObject");'
            'var s = ""; for (var i = 0; i < 4; i++) { s += "ABCD".charAt(Math.floor(Math.random() * 4)); }'
            'var w = fs.CreateTextFile("C:\\\\Temp\\\\fct_" + s + ".ps1", true); w.Write("Write-Host 0187"); w.Close();')
    s = js_eval.resolve(code)
    assert not s.errors and any(b"Write-Host 0187" in bytes(st.data) for st in s.stages if st.kind == "write")
    assert js_eval.resolve('var c = "abc".charAt(NaN); WScript.Echo(c);').errors == []
