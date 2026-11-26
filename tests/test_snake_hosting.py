"""Snake Keylogger builds of 2025: SMTP on a shared-hosting server, Telegram-only exfiltration, and no
false RAT configuration next to them."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _ms  # noqa: E402

from docutracex import c2  # noqa: E402
from docutracex.c2 import dotnet_rats, ratking, stealers  # noqa: E402


def test_hosting_server_is_the_smtp_server() -> None:
    d = _ms().snake_hosting_exe()
    r = stealers.snake(d, dotnet_rats.user_strings(d))
    assert r["c2"] == ["cp-host7.hosting-panel.example"]
    assert "SMTP server: cp-host7.hosting-panel.example" in r["summary"]["Exfiltration"]


def test_ratking_without_family_or_hosts_is_not_a_config() -> None:
    rk = {"status": "found", "family": "No match", "hosts": [], "method": "rat-king-parser"}
    assert ratking.combine(None, rk) is None


def test_telegram_exfiltration_is_not_a_dead_end() -> None:
    res = {"configs": [{"family": "Snake-like keylogger", "c2": [],
                        "summary": {"Exfiltration": ["Telegram bot token: 7000000000:AAInert"]}}], "findings": []}
    c2._dynamic(res, [], [("p.exe", "Snake-like keylogger", Path("/nonexistent"))], {})
    assert "dynamic" not in res
