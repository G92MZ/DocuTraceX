"""RedLine / META: settings named through the common family layer, traces."""

from __future__ import annotations

import pytest

import make_samples as ms

from docutracex.c2 import families, stealers


def test_named_settings():
    pytest.importorskip("dnfile")
    pytest.importorskip("dncil")
    r = stealers.extract_all(ms.redline_named_exe())[0]
    s = r["summary"]
    assert r["family"] == "RedLine Stealer" and "settings named from EntryPoint" in r["method"]
    assert s["C2"] == ["panel.invoice-sync.example:7712", "203.0.113.47:7712"] and s["Build ID"] == "Factura_2026"
    assert s["XOR key"] == "Pedestal" and any("fake error message" in o for o in s["Options"])


def test_unnamed_values_still_read():
    s = stealers.extract_all(ms.redline_exe())[0]["summary"]
    assert s["Build ID"] == "Factura_2026" and "WCF" in s["Note"]


def test_traces_only():
    r = stealers.extract_all(ms.redline_traces_exe())[0]
    assert r["kind"] == "indicators" and r["c2"] == [] and "type ScanningArgs" in r["indicators"]


def test_family_card():
    assert families.for_family("META Stealer")["id"] == "redline"
