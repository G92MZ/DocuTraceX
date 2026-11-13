"""MCP over HTTP (--http) and an uncapped list of own domains."""

from __future__ import annotations

import random
import string
import time
from pathlib import Path

import pytest

from docutracex import appsettings, domainsim, mcp_server


def test_main_stdio_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    class S:
        def run(self, *a, **k):
            calls.append((a, k))
    monkeypatch.setattr(mcp_server, "build_server", lambda: S())
    mcp_server.main([])
    assert calls == [((), {})]


def test_main_http(monkeypatch: pytest.MonkeyPatch) -> None:
    got = {}
    monkeypatch.setattr(mcp_server, "build_server", lambda: object())
    monkeypatch.setattr(mcp_server, "run_http", lambda s, h, p: got.update(host=h, port=p))
    mcp_server.main(["--http", "--host", "0.0.0.0", "--port", "8123"])
    assert got == {"host": "0.0.0.0", "port": 8123}


def test_http_app_mcp2_and_mcp1_behind_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path))
    from docutracex import users

    async def inner(scope, receive, send):                 # what the SDK app would answer
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    class V2:                                             # mcp >= 2: options as arguments
        def streamable_http_app(self, **kw):
            self.kw = kw
            return inner
    s2 = V2()
    app = mcp_server.http_app(s2, "0.0.0.0")
    assert "transport_security" in s2.kw                  # reachable by IP: DNS-rebinding protection off

    class Settings:
        host, transport_security = "127.0.0.1", None

    class V1:                                             # mcp 1.x: options in the settings
        settings = Settings()

        def streamable_http_app(self, **kw):
            if kw:
                raise TypeError("unexpected keyword")
            return inner
    s1 = V1()
    mcp_server.http_app(s1, "127.0.0.1")
    assert s1.settings.transport_security is None          # loopback keeps the protection

    def call(headers):
        out = []

        async def send(msg):
            out.append(msg)
        asyncio.run(app({"type": "http", "headers": headers}, None, send))
        return out[0]["status"]
    assert call([]) == 401
    assert call([(b"authorization", b"Bearer wrong")]) == 401
    assert call([(b"authorization", f"Bearer {users.mcp_token()}".encode())]) == 200


def test_own_domains_not_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store: dict = {}
    monkeypatch.setattr(appsettings, "load", lambda: dict(store))
    monkeypatch.setattr(appsettings, "save", lambda d: store.update(d))
    doms = [f"empresa{i:04d}.example" for i in range(1200)]
    out = appsettings.set_email_settings(doms + doms[:5], ["marca"])
    assert len(out["own_domains"]) == 1200


def test_lookalikes_fast_with_many_own_domains() -> None:
    random.seed(5)
    name = lambda: "".join(random.choice(string.ascii_lowercase) for _ in range(random.randint(5, 14)))  # noqa: E731
    own = [name() + ".example" for _ in range(1200)] + ["grupoejemplo.example"]
    hosts = [name() + ".example" for _ in range(200)] + ["grupoejernplo.example"]
    iocs = {"iocs": [{"type": "domain", "value": h, "occurrences": []} for h in hosts]}
    t = time.time()
    r = domainsim.run(iocs, own, [])
    assert time.time() - t < 20
    assert any(m["reference"] == "grupoejemplo.example" for m in r["matches"])


def test_prefilter_never_drops_a_match(monkeypatch: pytest.MonkeyPatch) -> None:
    own = ["grupoejemplo.example", "proveedor.example", "acme.example", "facturas-iberia.example"]
    hosts = ["grupoejernplo.example", "gruppoejemplo.example", "grupoejemplo.biz", "proveedorr.example",
             "login-proveedor-secure.example", "myprovedor365.example", "acrne.example", "facturasiberia.example",
             "unrelated.example", "cdn-update.example.net"]
    iocs = {"iocs": [{"type": "domain", "value": h, "occurrences": []} for h in hosts]}
    key = lambda r: sorted((m["candidate"], m["reference"], m["algorithm"]) for m in r["matches"])  # noqa: E731
    with_filter = key(domainsim.run(iocs, own, ["acme"]))
    monkeypatch.setattr(domainsim, "_may_match", lambda *a, **k: True)
    assert with_filter == key(domainsim.run(iocs, own, ["acme"])) and with_filter
