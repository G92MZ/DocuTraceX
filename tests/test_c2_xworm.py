"""XWorm: named settings through the common family layer, unnamed values and traces."""

from __future__ import annotations

import pytest

import make_samples as ms

from docutracex.c2 import dotnet_more, families


def test_named_settings():
    pytest.importorskip("dnfile")
    pytest.importorskip("dncil")
    r = dotnet_more.extract_all(ms.xworm_named_exe())[0]
    s = r["summary"]
    assert r["family"] == "XWorm" and "named from XClient.Settings" in r["method"]
    assert s["C2"] == ["invoice-sync.example.net:7000", "203.0.113.47:7000"]
    assert s["Group"] == "Factura-2026" and s["Mutex"] == "Rq7TnY2pVc9LxWe4" and s["Version"] == "5.6"
    assert s["Install path"] == "%AppData%\\InvoiceSync.exe"
    assert any("Startup\\InvoiceSync.lnk" in x for x in s["Persistence"])
    assert "spreads to USB drives as USB.exe" in s["Options"]
    assert any(x.startswith("Telegram bot token") for x in s["Exfiltration"]) and "Sensitive" in s
    assert s["Splitter"] == "<Xwormmm>"


def test_unnamed_values_still_read():
    r = dotnet_more.extract_all(ms.xworm_exe())[0]
    assert r["family"] == "XWorm" and "203.0.113.47" in r["c2"] and r["summary"]["Version"] == "5.6"


def test_traces_only():
    r = dotnet_more.extract_all(ms.xworm_traces_exe())[0]
    assert r["kind"] == "indicators" and r["c2"] == [] and "splitter <Xwormmm>" in r["indicators"]


def test_family_card():
    assert families.for_family("XWorm")["id"] == "xworm"
    assert families.for_family("XWorm-like RAT")["id"] == "xworm"
