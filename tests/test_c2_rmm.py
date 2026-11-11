"""RMM / remote-access tools: the product, and the instance an installer binds it to."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import make_samples as ms  # noqa: E402

from docutracex import c2  # noqa: E402
from docutracex.c2 import rmm  # noqa: E402


def test_screenconnect_msi_relay(tmp_path: Path) -> None:
    p = tmp_path / "VisorFacturas.msi"
    p.write_bytes(ms.rmm_screenconnect_msi())
    cfgs, runs = c2.scan_object_detailed(p, p.read_bytes())
    sc = next(c for c in cfgs if c["family"].startswith("RMM: ScreenConnect"))
    assert sc["kind"] == "rmm" and sc["c2"] == [ms.RMM_RELAY]
    assert sc["summary"]["C2"] == [f"{ms.RMM_RELAY}:8041"] and sc["summary"]["Session type"] == "Access"
    assert next(r for r in runs if r["extractor"] == "rmm")["status"] == "extracted"
    f = c2._finding(sc)
    assert f["rule"] == "c2:rmm" and f["severity"] == "medium" and ms.RMM_RELAY in f["detail"]


def test_netsupport_gateway() -> None:
    r = rmm.extract(ms.rmm_netsupport_ini(), "client32.ini")[0]
    assert r["family"] == "RMM: NetSupport Manager"
    assert r["c2"] == ["198.51.100.61", "update-cdn.invoice-support.example"]


def test_product_only_is_indicators_and_low() -> None:
    r = rmm.extract(b"MZ AnyDesk.exe philandro Software GmbH", "AnyDesk.exe")[0]
    assert r["kind"] == "indicators" and r["c2"] == []
    assert c2._finding(r)["severity"] == "low"
    assert rmm.extract(b"just the word anydesk once", "x") == []          # one weak string is not enough


def test_utf16_at_odd_offset() -> None:
    data = b"\x00\x01" + b"X" + "rutserv.exe".encode("utf-16-le") + b"\x00" * 10
    assert rmm.extract(data, "x")[0]["family"] == "RMM: Remote Utilities"
