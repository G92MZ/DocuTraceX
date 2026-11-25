"""ConfuserEx constants of mutated builds, recovered by emulating the CIL.

Control flow flattened, the key derivation inlined in ``<Module>.cctor``, ``br.s`` between the id
and the getter call: the pattern reader gives up, the emulator runs the initializer and the
getters on a model of the runtime (nothing of the machine is touched) and the strings come out;
the assembly the module loads at start comes out too, and the C2 tab no longer calls the object a
wall.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex.dotnet import cilemu  # noqa: E402

WANT = ["C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe", "WriteProcessMemory",
        "Wow64SetThreadContext", "COR_ENABLE_PROFILING", "factura_2026-0187_inj"]


def test_emulation_recovers_the_strings_and_the_embedded_assembly() -> None:
    r = cilemu.confuser_strings(_ms().dotnet_confuser_mutated_dll())
    got = [s["output"] for s in r["strings"]]
    assert set(WANT) <= set(got) and len(got) == 11, got
    assert r["assemblies"] and r["assemblies"][0][:2] == b"MZ"           # LZMA (32-bit size) answered natively
    assert "LZMA answered natively" in r["how"] and not r["error"]


def test_the_pattern_reader_still_reads_the_normal_mode() -> None:
    from docutracex import dotnet
    r = dotnet.parse(_ms().dotnet_confuser_exe())
    assert r["cil"]["confuser_constants"]["mode"] == "Normal"
    r = dotnet.parse(_ms().dotnet_confuser_mutated_dll())
    cx = r["cil"]["confuser_constants"]
    assert cx["mode"] == "emulated" and cx["strings"] == 11 and cx["assemblies"] == 1


def test_bounded() -> None:
    """A flattened loop that never ends stops on the step budget, quickly."""
    import dnfile
    emu = cilemu.Emu(dnfile.dnPE(data=_ms().dotnet_confuser_mutated_dll()))
    emu.limit = 50_000
    t = time.monotonic()
    try:
        emu.run([type("I", (), {"opcode": type("O", (), {"name": "br"})(), "operand": 0, "offset": 0})()],
                {0: 0}, [], True, 0)
    except cilemu.EmuError as exc:
        assert "step budget" in str(exc)
    assert time.monotonic() - t < 5


def test_end_to_end(client) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, "sample_dotnet_confuser_mutated.dll", _ms().dotnet_confuser_mutated_dll())
    dn = json.loads((res / "dotnet.json").read_text())
    obj = dn["objects"][0]["result"]
    outs = {d["output"] for d in obj["cil"]["decrypted"]}
    assert set(WANT) <= outs
    assert any(f["rule"] == "dotnet:confuser_constants" and "CIL emulation" in f["detail"] for f in dn["findings"])
    tree = json.loads((res / "nested.json").read_text())["tree"]
    assert any("Assembly.Load" in " → ".join(n.get("recipe") or []) for n in tree)
    c2 = json.loads((res / "c2.json").read_text())
    prot = c2.get("protected") or []
    assert prot and prot[0]["decrypted"] >= 11 and "decrypted statically" in prot[0]["note"]


def test_getter_reached_only_through_a_delegate_and_the_3des_payload() -> None:
    r = cilemu.confuser_strings(_ms().dotnet_confuser_proxy_dll())
    got = [x["output"] for x in r["strings"]]
    assert "ZwUnmapViewOfSection" in got and "factura_2026-0187_ldr" in got and len(got) == 7
    assert "reached through proxies / delegates" in r["how"]
    (blob, recipe), = r["payloads"]
    assert blob[:2] == b"MZ" and recipe[0] == "base64" and recipe[1].startswith("3des-cbc(") and "iv 30313837" in recipe[1]


def test_proxy_payload_end_to_end(client) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, "sample_dotnet_confuser_proxy.dll", _ms().dotnet_confuser_proxy_dll())
    tree = json.loads((res / "nested.json").read_text())["tree"]
    recipes = [" → ".join(n.get("recipe") or []) for n in tree]
    assert any(r.startswith("ConfuserEx constants (CIL emulation) → base64 → 3des-cbc") for r in recipes), recipes
