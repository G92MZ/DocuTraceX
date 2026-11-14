"""StealC, Vidar, Lumma, Brute Ratel, Havoc (Demon) and the Pure family, on inert samples."""

from __future__ import annotations

import base64
import gzip
from pathlib import Path

import make_samples as ms
from docutracex import c2
from docutracex.c2 import modern


def _scan(data: bytes) -> list[dict]:
    return c2.scan_object_detailed(Path("x"), data)[0]


def test_stealc() -> None:
    (r,) = _scan(ms.stealc_exe())
    assert r["family"] == "StealC" and r["summary"]["C2"] == [f"http://{ms.C2_IP}/3b8f2e6a9c1d4f70.php"]
    assert r["summary"]["RC4 key"] == "QmFzZTY0UkM0a2V5MjAy"          # a key that also looks like base64


def test_vidar_dead_drops() -> None:
    (r,) = _scan(ms.vidar_exe())
    assert r["family"] == "Vidar" and r["dead_drop"] == ["https://t.me/facturas_canal26",
                                                          "https://steamcommunity.com/profiles/76561199000000001"]


def test_raccoon_unchanged() -> None:
    assert [x["family"] for x in _scan(ms.raccoon_exe())] == ["Raccoon Stealer v2"]


def test_lumma() -> None:
    (r,) = _scan(ms.lumma_exe())
    assert r["family"] == "Lumma Stealer" and r["confidence"] == "high"
    assert r["c2"] == ["factura-cdn.example", "pago-seguro.example", "visor-docs.example"]
    assert r["dead_drop"] == ["https://steamcommunity.com/profiles/76561199000000002"]


def test_brute_ratel() -> None:
    (r,) = _scan(ms.brc4_badger_bin())
    assert r["family"] == "Brute Ratel C4 (badger)" and r["summary"]["C2"] == ["cdn-update.example.net:443"]
    assert r["summary"]["URIs"] == ["/api/v2/factura", "/content.php"] and "builder default" in r["summary"]["Key"]


def test_havoc_demon() -> None:
    (r,) = _scan(ms.havoc_demon_exe())
    s = r["summary"]
    assert r["family"] == "Havoc (Demon)" and s["C2"] == ["https://cdn-update.example.net:443", f"https://{ms.C2_IP}:8443"]
    assert s["Spawn to (x64)"].endswith("System32\\notepad.exe") and s["URIs"] == ["/api/factura", "/static/visor.js"]
    assert s["Execution"] == "NtCreateThreadEx (syscall)" and s["Sleep"] == "5 s, jitter 15 %"


def test_pure_family_and_protobuf_reader() -> None:
    (r,) = _scan(ms.pure_exe())
    assert r["family"] == "Pure family (PureHVNC)" and r["summary"]["C2"] == ["cdn-update.example.net:56001"]
    assert modern.protobuf(b"\x0a\x03abc\x10\x96\x01\x1a\x04\x0a\x02hi") == [("1", "abc"), ("2", 150), ("3.1", "hi")]


def test_nothing_on_noise() -> None:
    noise = base64.b64encode(gzip.compress(b"\x00" * 200)) + b"|" + bytes(range(256)) * 20
    assert modern.extract_all(b"MZ" + noise) == []
