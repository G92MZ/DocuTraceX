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


def test_urlhaus_needs_key_is_not_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import appsettings
    calls: list[str] = []
    monkeypatch.setattr(appsettings, "abusech_key", lambda: "")
    monkeypatch.setattr(mailintel, "_routes", lambda proxy: [("direct / system proxy", _Opener("direct", calls, False))])
    st = mailintel.refresh(None)
    u = next(x for x in st["feeds"] if x["id"] == "urlhaus_hosts")
    assert "Auth-Key" in u["last_error"] and u["needs_key"] and st["error"] is None
    assert len(calls) == len(mailintel.FEEDS) - 1          # URLhaus was not even requested


def test_urlhaus_csv_export_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import appsettings
    seen: list[str] = []
    rows = ['# URLhaus export', '"id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"']
    rows += [f'"{i}","2026-11-01","http://bad{i}.example/x.exe","online","","malware_download","","",""' for i in range(12)]
    rows += ['"99","2026-11-01","http://gone.example/a","offline","","malware_download","","",""',
             '"98","2026-11-01","http://192.0.2.7:8080/b","online","","malware_download","","",""']

    class _O:
        def open(self, req, timeout=None):  # noqa: ANN001
            seen.append(req.full_url)
            return io.BytesIO("\n".join(rows).encode())

    monkeypatch.setattr(appsettings, "abusech_key", lambda: "k3y-ABC_123")
    monkeypatch.setattr(mailintel, "_routes", lambda proxy: [("direct / system proxy", _O())])
    n, _ = mailintel._download("urlhaus_hosts", None, 5)
    assert n == 13 and "/k3y-ABC_123/" in seen[0]
    vals = mailintel._load("urlhaus_hosts")
    assert "bad3.example" in vals and "192.0.2.7" in vals and "gone.example" not in vals
    # an old hostfile dropped by hand still parses
    assert mailintel.parse("urlhaus_hosts", "127.0.0.1\tbad.example\n") == {"bad.example"}


def test_abusech_key_never_returned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import appsettings
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("DOCUTRACEX_ABUSECH_KEY", raising=False)
    out = appsettings.set_abusech_key("abcdef0123456789")
    assert out == {"configured": True, "hint": "…6789"} and appsettings.abusech_key() == "abcdef0123456789"
    with pytest.raises(ValueError):
        appsettings.set_abusech_key("bad key/with?chars")
