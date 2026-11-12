"""Remcos: the SETTINGS resource read by field position, older layouts and traces."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import make_samples as ms  # noqa: E402

from docutracex.c2 import families, remcos  # noqa: E402


def test_v4_layout_by_position():
    r = remcos.extract(ms.remcos_exe())
    s = r["summary"]
    assert r["kind"] == "RAT" and "27 fields" in r["method"]
    assert s["C2"] == ["cdn-update.example.net:2404 (TLS)", "203.0.113.47:2404"]
    assert s["Campaign"] == "Factura-2026" and s["Mutex"] == "Rmc-F4C7A1" and s["Version"] == "4.9.4 Pro"
    assert s["Install path"] == "%AppData%\\InvoiceSync\\remcos.exe (hidden file)"
    assert s["Persistence"] == ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\InvoiceSync"]
    assert s["Keylogger"].startswith("on, log %AppData%\\InvoiceSync\\logs.dat (encrypted)")
    assert "reconnects every 5 s" in s["Options"]
    assert any("builder default install name" in d for d in s["Builder defaults"])
    assert r["fields"]["mutex (field 14)"] == "Rmc-F4C7A1"


def test_older_layout_keeps_generic_reading():
    sep = b"|\x1e\x1e\x1f|"
    plain = sep.join([b"c2.example.org:443:0", b"Oldnet", b"1", b"x.exe", b"Rmc-ABC123"])
    r = remcos._parse(plain)
    assert r["summary"] == {"C2": ["c2.example.org:443"], "Campaign": "Oldnet", "Mutex": "Rmc-ABC123"}
    assert r["layout"].startswith("older")


def test_traces_without_settings():
    r = remcos.extract(ms.remcos_traces_exe())
    assert r["kind"] == "indicators" and r["c2"] == [] and "vendor string Breaking-Security.Net" in r["indicators"]
    assert remcos.extract(b"MZ" + b"\0" * 64) is None


def test_family_card():
    assert families.for_family("Remcos")["id"] == "remcos"
