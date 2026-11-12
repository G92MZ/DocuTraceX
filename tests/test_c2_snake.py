"""Snake Keylogger: exfiltration channel through the common family layer, traces."""

from __future__ import annotations

import make_samples as ms

from docutracex.c2 import families, stealers


def test_smtp_channel():
    r = stealers.extract_all(ms.snake_exe())[0]
    s = r["summary"]
    assert r["family"] == "Snake Keylogger" and s["Channel"] == ["SMTP"]
    assert "SMTP password: Fct#2026pass" in s["Exfiltration"] and "Mail to: recepcion.logs@mail-box.example.org" in s["Exfiltration"]
    assert "Sensitive" in s and "position" in s["Note"] and r["c2"] == ["mail.billing-portal.example"]


def test_telegram_and_ftp_channel():
    r = stealers.extract_all(ms.snake_telegram_exe())[0]
    s = r["summary"]
    assert s["Channel"] == ["FTP", "Telegram"] and s["Banner"] == "Snake Keylogger"
    assert "FTP user: logsuser" in s["Exfiltration"] and "Telegram chat ID: -1002026000001" in s["Exfiltration"]
    assert r["c2"] == ["ftp.invoice-sync.example"]


def test_traces_only():
    r = stealers.extract_all(ms.snake_traces_exe())[0]
    assert r["kind"] == "indicators" and r["c2"] == []


def test_family_card():
    assert families.for_family("Snake Keylogger")["id"] == "snake"
