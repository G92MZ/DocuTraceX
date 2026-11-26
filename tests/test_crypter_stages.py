"""A .NET crypter stage that keeps its payload in an encrypted resource (AgentTesla chains of 2025).

The stage reads the resource, decrypts it in its own CIL, trims it and hands the PE to a hollowing
routine; the CIL emulation follows that code and the PE becomes a Nested child. Inert sample.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _ms  # noqa: E402

from docutracex import c2, dotnet  # noqa: E402
from docutracex.dotnet import cilemu  # noqa: E402

C2 = ["factura-cdn.example", "pago-seguro.example", "visor-docs.example"]


def test_resource_payload_is_followed_to_the_pe() -> None:
    r = dotnet.parse(_ms().dotnet_resource_payload_dll())
    pa = r["cil"]["packed_array"]
    assert pa["source"] == "resource" and pa["payloads"] == 1
    assert "handed to InvoiceRules.Rules::Run" in pa["how"]
    blob = r["_packed_payloads"][0][0]
    assert blob[:2] == b"MZ" and c2.scan_object(Path("p.exe"), blob)[0]["summary"]["C2"] == C2
    f = [x for x in dotnet._findings({"result": r, "label": "s.dll"}) if x["rule"] == "dotnet:packed_payload"]
    assert f and f[0]["severity"] == "high" and "encrypted resource" in f[0]["detail"]


def test_static_array_packer_still_unpacked() -> None:
    r = dotnet.parse(_ms().dotnet_packed_array_exe())
    assert r["cil"]["packed_array"]["source"] == "static array" and r["_packed_payloads"]


def _emu() -> cilemu.Emu:
    import dnfile
    return cilemu.Emu(dnfile.dnPE(data=_ms().dotnet_resource_payload_dll()))


def test_framework_split_resize_getbytes() -> None:
    emu = _emu()
    parts = emu.extern("System.String::Split", ["a||b||||c", _arr(["||"]), 0], False)
    assert parts.data == ["a", "b", "", "c"]
    parts = emu.extern("System.String::Split", ["a||b||||c", _arr(["||"]), 1], False)
    assert parts.data == ["a", "b", "c"]
    assert emu.extern("System.String::Split", ["x,y", ord(","), ], False).data == ["x", "y"]
    a = cilemu.Arr("u1", 4)
    a.data[:] = b"MZ\x90\x00"
    box = {0: a}
    emu.extern("System.Array::Resize", [cilemu.Ref(box, 0), 2], False)
    assert bytes(box[0].data) == b"MZ"
    assert bytes(emu.extern("System.BitConverter::GetBytes", [0x0187], False).data) == b"\x87\x01\x00\x00"


def _arr(items: list) -> cilemu.Arr:
    a = cilemu.Arr("ref", 0)
    a.data = list(items)
    return a
