"""XWorm 7.x builds without #US strings: a char[] pool decoded into a StringBuilder by one getter.

The .NET analysis notices the assembly has no strings but calls one getter many times with constants,
runs the getters in the CIL emulation and the XWorm extractor reads the settings. Inert sample.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _ms  # noqa: E402

from docutracex import dotnet  # noqa: E402
from docutracex.c2 import dotnet_more  # noqa: E402
from docutracex.dotnet import cilemu  # noqa: E402


def test_string_pool_triggers_the_emulation() -> None:
    data = _ms().xworm_pool_exe()
    r = dotnet.parse(data)
    assert not r["strings"] or len(r["strings"]) < 20
    outs = [d["output"] for d in r["cil"]["decrypted"]]
    assert "Pw4HcN8sZt2QyLb6" in outs and "powershell.exe" in outs


def test_xworm_settings_from_the_pool() -> None:
    (cfg,) = dotnet_more.extract_all(_ms().xworm_pool_exe())
    assert cfg["family"] == "XWorm" and cfg["c2"] == ["factura-sync.example.net", "203.0.113.47"]
    s = cfg["summary"]
    assert s["Version"] == "7.1" and s["Ports"] == ["7000"] and s["Splitter"] == "<Xwormmm>"
    assert s["C2"] == ["factura-sync.example.net:7000", "203.0.113.47:7000"]


def test_string_builder_char_overload() -> None:
    import dnfile
    emu = cilemu.Emu(dnfile.dnPE(data=_ms().xworm_pool_exe()))
    sb = emu.extern("System.Text.StringBuilder::.ctor", [], True)
    emu.extern("System.Text.StringBuilder::AppendChar", [sb, ord("F")], False)
    emu.extern("System.Text.StringBuilder::Append", [sb, "act"], False)
    emu.extern("System.Text.StringBuilder::Append", [sb, 187], False)
    assert emu.extern("System.Object::ToString", [sb], False) == "Fact187"
    assert cilemu._first_param(bytes([0x20, 0x01, 0x12, 0x09, 0x03])) == 0x03
