"""Improve languages, phase 0: the shared operations, values with recipes, the stages a script
hands to execute / load / write calls, and the language of a script by its content.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import io
import lzma
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

from docutracex.resolve import langdetect, transforms as T
from docutracex.resolve.sinks import Sinks
from docutracex.resolve.value import Value

sys.path.insert(0, str(Path(__file__).parent))

PE = b"MZ" + b"\x90\x00" * 30 + b" inert DocuTraceX test stub (factura 2026-0187) " * 4


# --- T1: operations ----------------------------------------------------------------
def test_encodings() -> None:
    assert T.b64decode(base64.b64encode(PE).decode()) == PE
    assert T.b64decode(base64.urlsafe_b64encode(PE).decode().rstrip("=")) == PE      # URL-safe, no padding
    assert T.b64decode("TVqQ\nAAMA\n") == bytes.fromhex("4d5a90000300")              # whitespace
    assert T.hexdecode("4D 5A-90 00") == T.hexdecode("0x4D,0x5A,0x90,0x00") == T.hexdecode("\\x4d\\x5a\\x90\\x00")
    assert T.num_array("77, 90, -112, 0x00") == b"MZ\x90\x00"
    assert T.unescape("\\x4d\\u005a%41") == "MZA"
    assert T.unescape("\\x4d\\x5a\\x90", as_bytes_=True) == b"MZ\x90"
    assert T.b32decode(base64.b32encode(b"factura")) == b"factura"
    assert T.b85decode(base64.b85encode(b"factura").decode()) == b"factura"
    with pytest.raises(T.TransformError):
        T.hexdecode("4d5")


def test_ciphers() -> None:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key, iv = bytes(range(32)), bytes(range(16))
    p = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(p.update(PE) + p.finalize()) + enc.finalize()
    assert T.decrypt("aes", ct, key, iv, "cbc") == PE
    with pytest.raises(T.TransformError):                          # wrong key: bad padding, not garbage
        T.decrypt("aes", ct, bytes(32), iv, "cbc")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = b"\x01" * 12
    assert T.aes_gcm(AESGCM(key).encrypt(nonce, PE, None), key, nonce) == PE
    assert T.xor(T.xor(PE, "Fact#2026-0187"), "Fact#2026-0187") == PE
    assert T.xor(PE, 0x5A) == bytes(b ^ 0x5A for b in PE)
    assert T.rc4(T.rc4(PE, "clave"), "clave") == PE
    assert T.xor_rolling(T.xor_rolling(PE, 7), 7) == PE
    assert T.add_bytes(T.add_bytes(PE, 3), -3) == PE
    assert T.rot("Vaibxr-Rkcerffvba") == "Invoke-Expression"
    assert len(T.pbkdf2("pass", "salt", 1000, 32)) == 32


def test_compressions_and_bombs(monkeypatch: pytest.MonkeyPatch) -> None:
    assert T.gunzip(gzip.compress(PE)) == PE
    assert T.inflate(zlib.compress(PE)[2:-4]) == PE
    assert T.zlib_decompress(zlib.compress(PE)) == PE
    assert T.unlzma(lzma.compress(PE)) == PE
    assert T.bunzip2(bz2.compress(PE)) == PE
    assert T.decompress_any(lzma.compress(PE)) == PE
    # LZNT1: "abc" + a back-reference (offset 3, length 6)
    assert T.lznt1(bytes([0x05, 0xB0, 0x08]) + b"abc" + bytes([0x03, 0x20])) == b"abcabcabc"
    monkeypatch.setattr(T, "MAX_OUT", 1 << 20)
    with pytest.raises(T.TransformError):                          # a bomb stops at the bound
        T.gunzip(gzip.compress(b"\x00" * (4 << 20)))
    assert T.magic(PE) == "pe" and T.magic(gzip.compress(b"x")) == "gzip" and T.is_text(b"Write-Host 'ok'\r\n")


# --- T2 / T3: values, recipes and stages ---------------------------------------------
def test_values_and_stages() -> None:
    blob = Value.of(base64.b64encode(gzip.compress(PE)).decode(), "here-string $P")
    raw = blob.then("base64", T.b64decode(blob.v))
    pe = raw.then("gzip", T.gunzip(raw.v))
    assert pe.recipe == ("here-string $P", "base64", "gzip") and pe.kind == "bytes"
    s = Sinks("powershell")
    s.load(pe, "Assembly.Load", line=12)
    s.exec_(Value.of("Write-Host 'stage 2'", "literal").then("base64", "Write-Host 'stage 2'"), "IEX")
    s.exec_(Value.unknown("the registry value HKCU\\Software\\x"), "IEX", line=30)
    s.download(Value.of("https://billing-portal.example/s.ps1", "literal"), "DownloadString",
               "executes it as code", line=40)
    st = s.decoded_stages()
    assert st[0]["recipe"][-1] == "Assembly.Load" and base64.b64decode(st[0]["data_b64"]) == PE
    assert st[1]["text"] == "Write-Host 'stage 2'"
    f = {x["rule"]: x for x in s.findings("file:x.ps1")}
    assert "billing-portal.example/s.ps1" in f["powershell_resolved_download"]["detail"]
    ev = f["powershell_unresolved_dynamic_call"]["evidence"]
    assert "registry" in ev and "victim's machine" in ev


# --- T4: language by content -----------------------------------------------------------
@pytest.mark.parametrize(("lang", "code"), [
    ("powershell", "$k = [Convert]::FromBase64String($a)\n$x = $b -bxor 5\nInvoke-Expression $c\n"),
    ("javascript", "var sh = new ActiveXObject('WScript.Shell');\nfunction a(b) { return b; }\nsh.Run(a('x'));\n"),
    ("vbscript", "Dim o\nSet o = CreateObject(\"WScript.Shell\")\nOn Error Resume Next\nIf x Then\nEnd If\n"),
    ("batch", "@echo off\nset a=po\nset b=wershell\n%a%%b% -enc AAA\ngoto :eof\n"),
    ("python", "import base64, zlib\ndef f(x):\n    return x\nexec(zlib.decompress(base64.b64decode(d)))\n"),
    ("perl", "use strict;\nuse MIME::Base64;\nmy $x = decode_base64($y);\neval $x;\n"),
    ("php", "<?php\n$a = base64_decode('ZWNobyAx');\neval(gzinflate($a));\n"),
    ("shell", "#!/bin/bash\necho QUFB | base64 -d | sh\nexport X=1\n"),
])
def test_language_by_content(lang: str, code: str) -> None:
    assert langdetect.languages(code)[0] == lang


def test_rules_ignore_words_inside_encoded_blobs() -> None:
    from docutracex.parsers import script_rules
    blob = "A" * 60 + "vboxQ" + "B" * 80
    assert not [h for h in script_rules.scan(f"$p = '{blob}'", "ps") if h["rule"] == "ps_antivm"]
    assert [h for h in script_rules.scan("Get-WmiObject Win32_BIOS | ? { $_ -match 'VirtualBox' }", "ps")
            if h["rule"] == "ps_antivm"]


def test_cut_preview_is_no_source_for_literals() -> None:
    """A deobfuscated preview cut short (Python's 400,000 characters) is not mined: a PE literal
    running past the cut would carve into "ghost" PEs."""
    from docutracex import decrypted
    full = "x = [" + ",".join(str(b) for b in PE) + "]"
    sc = {"code_is_deobfuscated": True, "code_truncated": True, "code": full[:60], "_full_code": full}
    src, orig = decrypted._sources(sc, None)
    assert src == full


# --- T4 end to end: a PowerShell loader in a .txt, top level and inside a ZIP ---------------
def test_txt_loader_goes_to_its_engine_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings
    from test_js_techniques import _analyze
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    ps = ("$ErrorActionPreference = 'Stop'\n"
          "[byte[]]$pe = (" + ",".join(str(b) for b in PE) + ")\n"
          "$b = [Convert]::FromBase64String('" + base64.b64encode(b"Write-Host 'factura 2026-0187'").decode() + "')\n"
          "Invoke-Expression ([Text.Encoding]::UTF8.GetString($b))\n"
          "$t = 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe'\n")
    client = TestClient(create_app())
    _cid, res = _analyze(client, "factura.txt", ps.encode())
    ran = {p.stem for p in res.glob("*.json")}
    assert "powershell" in ran and not {"vbscript", "batch", "javascript"} & ran
    tree = json.loads((res / "nested.json").read_text())["tree"]
    assert any(n["filename"].startswith("decrypted_powershell-") for n in tree)
    # the same text inside a ZIP: the child is read as PowerShell
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("leeme.txt", ps)
    _cid, res = _analyze(client, "kit_factura.zip", buf.getvalue())
    child = next(c for c in json.loads((res / "nested.json").read_text())["tree"] if c["filename"] == "leeme.txt")
    assert child.get("read_as_language") == ["powershell"]
    assert any(f["tool"] == "powershell" for f in child["findings"])
