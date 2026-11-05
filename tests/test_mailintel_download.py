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


def test_urlhaus_without_key_uses_the_mirror(monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import appsettings
    seen: list[str] = []

    class _O:
        def open(self, req, timeout=None):  # noqa: ANN001
            seen.append(req.full_url)
            return io.BytesIO(("# Updated: 2026-11-05\n" + "\n".join(f"0.0.0.0 h{i}.example" for i in range(15))).encode())

    monkeypatch.setattr(appsettings, "abusech_key", lambda: "")
    monkeypatch.setattr(mailintel, "_routes", lambda proxy: [("direct / system proxy", _O())])
    n, route = mailintel._download("urlhaus_hosts", None, 5)
    assert n == 15 and route == "direct / system proxy · mirror curbengh.github.io"
    assert seen == ["https://curbengh.github.io/malware-filter/urlhaus-filter-hosts-online.txt"]


def test_blocked_export_falls_back_and_says_who_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    from email.message import Message

    from docutracex import appsettings
    hdrs = Message()
    hdrs["Server"] = "Zscaler/6.2"

    class _O:
        def open(self, req, timeout=None):  # noqa: ANN001
            if "abuse.ch" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", hdrs,
                                             io.BytesIO(b"<html><title>Website blocked</title></html>"))
            raise urllib.error.URLError(socket.timeout("timed out"))

    monkeypatch.setattr(appsettings, "abusech_key", lambda: "secretKEY0123456789abcdefXYZ")
    monkeypatch.setattr(mailintel, "_routes", lambda proxy: [("direct / system proxy", _O())])
    with pytest.raises(ConnectionError) as ei:
        mailintel._download("urlhaus_hosts", None, 5)
    msg = str(ei.value)
    assert 'abuse.ch export: HTTP 403 — "Website blocked", server: Zscaler/6.2 (a proxy / firewall blocked it)' in msg
    assert "mirror curbengh.github.io: timed out" in msg and "secretKEY" not in msg


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


def test_tls_context_verifies_and_short_reason() -> None:
    import ssl
    ctx = mailintel._ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    err = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    err.verify_message = "unable to get local issuer certificate"
    msg = mailintel._short(urllib.error.URLError(err))
    assert msg.startswith("TLS certificate not trusted: unable to get local issuer certificate")
