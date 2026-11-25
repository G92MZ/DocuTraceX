"""Builds seen in 2025 that the C2 tab used to miss.

Vidar with its strings in clear (dead drops next to the build's markers), StealC v2 (JSON protocol,
with or without its RC4 key as text, the C2 an IPv4 written as one number), Quasar merged with a big
library whose constants class comes before the settings, a Quasar fork with an obfuscator of its own,
and a crypter stage whose strings are a table in an encrypted resource. All inert.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _ms  # noqa: E402

from docutracex import c2  # noqa: E402


def _scan(name: str, data: bytes) -> dict:
    found = c2.scan_object(Path(name), data)
    assert found, name
    return found[0]


def test_vidar_in_clear_gives_its_dead_drops() -> None:
    cfg = _scan("v.exe", _ms().vidar_plain_exe())
    assert cfg["family"] == "Vidar" and cfg["c2"] == []
    assert cfg["dead_drop"] == ["https://t.me/facturas_canal26", "https://steamcommunity.com/profiles/76561199000000003"]
    assert c2._finding(cfg)["severity"] == "high"


def test_stealc_v2_with_its_key() -> None:
    cfg = _scan("s.exe", _ms().stealc_v2_exe())
    assert cfg["family"] == "StealC" and cfg["c2"] == ["203.0.113.47"]
    assert cfg["summary"]["RC4 key"] == "F4ctur4Stealc2Key26"
    assert "steal_steam" in cfg["summary"]["Tasks it accepts"]


def test_stealc_v2_without_its_key_and_a_decimal_ip() -> None:
    cfg = _scan("s.exe", _ms().stealc_v2_keyless_exe())
    assert cfg["family"] == "StealC" and cfg["c2"] == ["203.0.113.47"]
    assert "keystream" in cfg["method"]
    assert cfg["summary"]["Build ID (probably)"] == "F4ctura0187Build9"


def test_quasar_with_a_library_class_first() -> None:
    cfg = _scan("q.exe", _ms().quasar_library_exe())
    assert cfg["family"] == "QuasarRAT"
    assert cfg["summary"]["C2"] == ["cdn-update.example.net:4782", "203.0.113.47:4782"]
    assert "Quasar.Client.Config.Settings" in cfg["method"]


def test_quasar_fork_decoded_by_emulation() -> None:
    cfg = _scan("q.dll", _ms().quasar_fork_dll())
    assert cfg["family"] == "QuasarRAT" and cfg["c2"] == ["203.0.113.47"]
    s = cfg["summary"]
    assert s["Mutex"] == "Global\\FctMtx_0187_q7Lz" and s["Install name"] == "client.exe"
    assert s["Key"] == "0187C0FFEE0187C0FFEE0187C0FFEE01"


def test_resource_string_table_is_emulated() -> None:
    from docutracex import dotnet
    r = dotnet.parse(_ms().dotnet_resource_strings_dll())
    got = [d["output"] for d in r["cil"]["decrypted"]]
    assert {"F4ctura0187Pass", "RegAsm.exe", "factura_2026-0187_stage3", 'Add-MpPreference -ExclusionPath "'} <= set(got)
    assert r["cil"]["emulated_strings"]["strings"] >= 7
