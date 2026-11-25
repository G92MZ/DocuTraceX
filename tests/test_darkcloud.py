"""C2: DarkCloud (VB6 stealer) configuration read statically.

The VB6 string pool (BSTR constants) in the builder's order, the placeholders a channel keeps when
the buyer left it off, and strings encrypted with RC4 and a key per string (hex ciphertext + key).
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex.c2 import darkcloud  # noqa: E402
from docutracex.resolve.transforms import rc4  # noqa: E402


def _bstr(s: str) -> bytes:
    b = s.encode("utf-16-le")
    return struct.pack("<I", len(b)) + b + b"\x00\x00\x00\x00"


def _vb6(pool: list[str]) -> bytes:
    return b"MZ" + b"\x00" * 62 + b"MSVBVM60.DLL\x00" + b"".join(_bstr(s) for s in pool)


def test_rc4_per_string_key() -> None:
    # the published example (Unit 42): ciphertext + its key → "WScript.Shell"
    key = "sMgSInEGpSAgkfcMSUPDDFCVSTyhowuHorsctkyTMYZh"
    assert darkcloud.decrypt_pool(["x", "58364B6DB1C7D797DFA59186B4", key, "y"]) == (["x", "WScript.Shell", "y"], 1)


def test_sample_configuration() -> None:
    got = darkcloud.extract(_ms().darkcloud_vb6_exe())
    s = got["summary"]
    assert got["family"] == "DarkCloud" and got["kind"] == "stealer" and got["confidence"] == "high"
    assert s["Version"] == "DarkCloud 5.0"                                   # RC4-encrypted in the sample
    assert s["Telegram bot token"].startswith("7000000187:AA") and s["Telegram chat id"] == "100200300"
    assert s["SMTP server"] == "smtp.billing-portal.example:587" and s["SMTP user"] == "facturas@billing-portal.example"
    assert s["Mail recipient"] == "cuentas@billing-portal.example" and s["SMTP SSL"] == "True"
    assert s["Channels not set (placeholders left by the builder)"] == "FTP, Panel"
    assert s["Install path"].endswith("\\Templates\\factura_sync.exe") and "RunOnce" in s["Persistence"]
    assert s["VB project path (author's machine)"] == "C:\\Users\\builder\\Desktop\\Stub\\Project1.vbp"
    assert {"credit cards", "keystrokes", "WinSCP"} <= set(s["Steals"])
    assert set(got["c2"]) == {"api.telegram.org", "smtp.billing-portal.example"}


def test_placeholders_only_is_indicators_and_other_vb6_is_nothing() -> None:
    ph = [p for p, _ in darkcloud.FIELDS]
    got = darkcloud.extract(_vb6(["Agent: DARKCLOUD V5.0", *ph]))
    assert got["kind"] == "indicators" and got["summary"]["Exfiltration"] == "none set in this build"
    assert darkcloud.extract(_vb6(["Form1", "Hello from a VB6 program", "Command1"])) is None
    assert darkcloud.extract(b"MZ" + b"\x00" * 200) is None


def test_telegram_only_build_with_encrypted_token() -> None:
    tok = "7000000187:AAFacturaInertDocuTraceXsample0187zz"
    key = "QwErTyUiOpAsDfGhJkLz"
    pool = ["Agent: DARKCLOUD V5.0", *[p for p, _ in darkcloud.FIELDS], rc4(tok.encode(), key.encode()).hex().upper(),
            key, "100200300"]
    got = darkcloud.extract(_vb6(pool))
    assert got["summary"]["Telegram bot token"] == tok and got["summary"]["Telegram chat id"] == "100200300"
    assert got["c2"] == ["api.telegram.org"] and "Telegram itself" in got["note"]


def test_sample_end_to_end(client) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, "sample_darkcloud_vb6.exe", _ms().darkcloud_vb6_exe())
    c2 = json.loads((res / "c2.json").read_text())
    cfg = next(c for c in c2["configs"] if c["family"] == "DarkCloud")
    assert "smtp.billing-portal.example" in cfg["c2"]
    assert any(f["rule"] == "c2:darkcloud" and f["severity"] == "high" for f in c2["findings"])


def test_unknown_build_by_structure_and_shape() -> None:
    """No version, no placeholders, another order: recognised by its structure, values by their shape."""
    got = darkcloud.extract(_ms().darkcloud_variant_exe())
    s = got["summary"]
    assert got["family"] == "DarkCloud" and got["confidence"] == "medium"
    assert s["Recognised by"].startswith("structure") and "shape" in s["Configuration read"]
    assert s["SMTP server"] == "smtp.billing-portal.example:587" and s["SMTP password"] == "Factura0187!"
    assert s["SMTP user"] == "facturas@billing-portal.example" and s["Mail recipient"] == "cuentas@billing-portal.example"
    assert s["FTP server"] == "ftp://files.billing-portal.example/up/"
    assert set(got["c2"]) == {"smtp.billing-portal.example", "files.billing-portal.example"}


def test_reordered_block_does_not_mislabel() -> None:
    """Placeholders present but the values in other slots: a slot that does not fit its field makes the
    reader name the values by their shape instead of by position."""
    ph = [p for p, _ in darkcloud.FIELDS]
    pool = ["Agent: DARKCLOUD V5.0", ph[0], ph[1], ph[2], "smtp.billing-portal.example", "587",
            "facturas@billing-portal.example", "Factura0187!", "cuentas@billing-portal.example", "True", ph[9]]
    s = darkcloud.extract(_vb6(pool))["summary"]
    assert s["SMTP server"] == "smtp.billing-portal.example:587" and s["SMTP user"] == "facturas@billing-portal.example"
    assert "shape" in s["Configuration read"]


def test_other_vb6_stealer_is_not_darkcloud() -> None:
    pool = ["https://api.telegram.org/bot", "/sendDocument?chat_id=", "[CLIPBOARD]<<", "\\Login Data"]
    assert darkcloud.extract(_vb6(pool)) is None
