"""VBScript collection, string deobfuscation and its own code tab data."""

from __future__ import annotations

from pathlib import Path

from docutracex import codefiles
from docutracex.parsers import vbscript
from docutracex.storage import CasePaths


def test_chr_concat_is_decoded() -> None:
    code = "a = Chr(77) & Chr(115) & Chr(103) & Chr(66) & Chr(111) & Chr(120)"
    r = vbscript.deobfuscate(code)
    assert r["changed"] and '"MsgBox"' in r["code"]
    assert {"chr-code", "concat-&"} <= set(r["methods"])


def test_strreverse_and_hex_chr() -> None:
    r = vbscript.deobfuscate('x = StrReverse("llehS.tpircSW") & Chr(&H21)')
    assert "WScript.Shell" in r["code"] and "!" in r["code"]


def test_unwrap_execute() -> None:
    r = vbscript.deobfuscate('Execute("CreateObject(""WScript.Shell"").Run ""calc""")')
    assert 'CreateObject("WScript.Shell")' in r["code"]


def test_clean_vbs_untouched() -> None:
    r = vbscript.deobfuscate('MsgBox "hello"')
    assert not r["changed"]


def test_collect_from_vbs_file_and_hta(tmp_path: Path) -> None:
    ex = tmp_path / "extracted"
    (ex / "att").mkdir(parents=True)
    (ex / "att" / "x.vbs").write_text(
        'Execute("CreateObject(""WScript.Shell"").Run ""powershell -nop""")')
    (ex / "att" / "y.hta").write_text(
        '<html><script language="VBScript">CreateObject("WScript.Shell").Run "calc"</script></html>')
    (ex / "att" / "z.js").write_text("var a = 1;")  # not VBScript
    res = vbscript.analyze(tmp_path / "o.eml", ex, {})
    rules = {f["rule"] for f in res["findings"]}
    assert len(res["scripts"]) == 2
    assert {"vbs_shell", "vbs_lolbin"} & rules
    assert any("powershell" in s["code"] for s in res["scripts"])


def test_codefiles_dumps_vbscript(tmp_path: Path) -> None:
    cp = CasePaths("c1", cases_dir=tmp_path)
    cp.root.mkdir(parents=True, exist_ok=True)
    full = 'Execute(Chr(77))'
    modules = {"vbscript": {"scripts": [{
        "location": "file:att/x.vbs", "kind": "vbscript", "code": "M",
        "code_is_deobfuscated": True, "_full_code": full, "_full_deob": "M",
    }]}}
    changed = codefiles.annotate(modules, cp)
    assert "vbscript" in changed
    sc = modules["vbscript"]["scripts"][0]
    assert (cp.root / sc["code_file"]).read_text() == full
    assert sc["code_file"].startswith("extracted/code/vbscript/")
    assert sc["code_file_deob"].endswith(".deobfuscated.vbs")
