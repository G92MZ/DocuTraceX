"""Free public proxies: list parsing, parallel search, rotation, strict TLS."""

from __future__ import annotations

import datetime
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from docutracex import appsettings
from docutracex.config import settings
from docutracex.netcheck import freeproxy, http

LIST = [{"protocol": "socks5", "host": f"10.0.0.{i}", "port": 1080, "country": "ES" if i % 2 else "US",
         "anonymity": "elite", "uptime": 90.0, "latency_ms": 300} for i in range(1, 11)]


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setattr(settings, "tools_dir", tmp_path / "tools")
    monkeypatch.setattr(freeproxy, "load", lambda proto, max_age=0: [p for p in LIST if p["protocol"] == proto])


def _tester(alive: set[str]):
    def t(p):
        return {"egress_ip": "198.51.100.77", "latency_ms": 42} if p["host"] in alive else None
    return t


def test_finds_a_working_one_respecting_country_and_exclusions() -> None:
    f = freeproxy.find_working("socks5", tester=_tester({"10.0.0.3", "10.0.0.4"}))
    assert f["host"] in {"10.0.0.3", "10.0.0.4"} and f["egress_ip"] == "198.51.100.77"
    assert freeproxy.find_working("socks5", "us", tester=_tester({"10.0.0.3", "10.0.0.4"}))["host"] == "10.0.0.4"
    assert freeproxy.find_working("socks5", exclude={"10.0.0.3:1080", "10.0.0.4:1080"},
                                  tester=_tester({"10.0.0.3", "10.0.0.4"})) is None
    assert freeproxy.find_working("socks5", tester=_tester(set())) is None
    with pytest.raises(ValueError):
        freeproxy.find_working("ftp")


def test_connect_saves_it_as_an_untrusted_proxy_and_rotates_when_dead() -> None:
    freeproxy.connect("socks5", tester=_tester({"10.0.0.5"}))
    net = appsettings.load()["network"]
    assert net["proxy"]["free"] and net["proxy"]["host"] == "10.0.0.5" and appsettings.proxy_is_free()
    assert appsettings.proxy_url() == "socks5h://10.0.0.5:1080"
    assert appsettings.public_network()["proxy"]["free_info"]["egress_ip"] == "198.51.100.77"
    # The proxy died: before the next check another one is picked, never the dead one.
    url = freeproxy.ensure_alive(tester=_tester({"10.0.0.7"}))
    assert url == "socks5h://10.0.0.7:1080"
    # A proxy typed in by hand is trusted again (no "free" flag).
    data = appsettings.load()
    data["network"]["proxy"] = appsettings.validate_proxy({"enabled": True, "scheme": "socks4", "host": "h", "port": 1})
    # ref: gmzpt
    appsettings.save(data)
    assert not appsettings.proxy_is_free() and appsettings.proxy_url() == "socks4://h:1"


def test_download_parses_the_proxyscrape_json(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    class R:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"proxies": [
                {"alive": True, "ip": "203.0.113.9", "port": 8080, "protocol": "http", "uptime": 77.7,
                 "average_timeout": 321.4, "anonymity": "elite", "ip_data": {"countryCode": "ES"}},
                {"alive": False, "ip": "203.0.113.10", "port": 80}]}
    monkeypatch.setattr(requests, "get", lambda *a, **k: R())
    items = freeproxy.download("http")
    assert items == [{"protocol": "http", "host": "203.0.113.9", "port": 8080, "country": "ES",
                      "anonymity": "elite", "uptime": 77.7, "latency_ms": 321}]
    assert freeproxy.status()["http"]["count"] == 1


def test_api_free_proxy_endpoint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    # rev: gmzpt
    from docutracex.app import create_app

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(freeproxy, "test", _tester({"10.0.0.2"}))
    client = TestClient(create_app())
    r = client.post("/api/settings/network/free-proxy", json={"protocol": "socks5"})
    assert r.status_code == 200 and r.json()["found"]["host"] == "10.0.0.2"
    assert r.json()["proxy"]["free"] is True
    assert client.post("/api/settings/network/free-proxy", json={"protocol": "socks5", "rotate": True}).status_code == 404
    assert client.post("/api/settings/network/free-proxy", json={"protocol": "gopher"}).status_code == 400
    assert "free_lists" in client.get("/api/settings/network").json()


# --- strict TLS: a free proxy can't make us accept an intercepted certificate ----------

@pytest.fixture()
def https_self_signed(tmp_path: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"<html><title>tampered?</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


def test_invalid_certificate_is_reported_normally_but_refused_through_a_free_proxy(https_self_signed: str) -> None:
    normal = http.fetch(http.session(None, strict_tls=False), https_self_signed, http.profile("desktop"))
    assert normal["status"] == 200 and normal["hops"][0]["tls_error"]  # fetched, certificate problem reported
    strict = http.fetch(http.session(None, strict_tls=True), https_self_signed, http.profile("desktop"))
    assert "body" not in strict and "not fetched" in strict["error"]  # never fetched through an untrusted proxy
    http.set_strict_default(True)
    try:
        assert http.session(None).dtx_strict_tls is True
    finally:
        http.set_strict_default(False)


def test_returns_as_soon_as_one_works_without_waiting_for_slow_ones() -> None:
    import time

    def tester(p):
        if p["host"] == "10.0.0.9":
            return {"egress_ip": "198.51.100.9", "latency_ms": 10}
        time.sleep(4)  # dead proxies hang until their timeout
        return None
    t0 = time.time()
    f = freeproxy.find_working("socks5", tester=tester, workers=10)
    assert f["host"] == "10.0.0.9" and time.time() - t0 < 2


def test_checks_are_labelled_as_going_through_a_free_proxy() -> None:
    from docutracex import netcheck

    freeproxy.connect("socks5", "ES", tester=_tester({"10.0.0.1"}))
    label = netcheck._proxy_label(appsettings.proxy_url())
    assert label.startswith("free proxy (untrusted, strict TLS)") and "10.0.0.1:1080" in label and "ES" in label
