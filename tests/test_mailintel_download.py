"""Reputation-list download: direct (system proxy) first, then the Settings
proxy; a timeout becomes a short, readable reason."""

from __future__ import annotations

import io
import socket
import urllib.error
from pathlib import Path

import pytest

from docutracex import mailintel
from docutracex.config import settings


class _Opener:
    def __init__(self, label: str, calls: list, fail: bool) -> None:
        self.label, self.calls, self.fail = label, calls, fail

    def open(self, req, timeout=None):  # noqa: ANN001
        self.calls.append(self.label)
        if self.fail:
            raise urllib.error.URLError(socket.timeout("[WinError 10060] long Windows essay"))
        return io.BytesIO(("\n".join(f"d{i}.example" for i in range(20))).encode())


@pytest.fixture(autouse=True)
def _tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "tools_dir", tmp_path)
    monkeypatch.setattr(mailintel, "_refresh", {"running": False, "last": None, "error": None, "results": {}})


def test_falls_back_to_settings_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(mailintel, "_routes", lambda proxy: [
        ("direct / system proxy", _Opener("direct", calls, True)),
        ("Settings proxy", _Opener("proxy", calls, False))])
    n, route = mailintel._download("disposable", "http://192.0.2.1:8080", 5)
    assert n == 20 and route == "Settings proxy" and calls == ["direct", "proxy"]


def test_direct_first_and_short_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(mailintel, "_routes", lambda proxy: [("direct / system proxy", _Opener("direct", calls, True))])
    st = mailintel.refresh(None)
    assert "list(s) not downloaded" in st["error"] and "10060" not in st["error"]
    f = next(x for x in st["feeds"] if x["id"] == "freemail")
    assert f["last_error"].startswith("direct / system proxy: timed out") and "Windows essay" not in f["last_error"]


def test_routes_order() -> None:
    assert [r[0] for r in mailintel._routes(None)] == ["direct / system proxy"]
    assert [r[0] for r in mailintel._routes("http://192.0.2.1:3128")] == ["direct / system proxy", "Settings proxy"]
