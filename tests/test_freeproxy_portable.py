"""Free-proxy network ops delegate to the portable (requests/PySocks live there,
not on the web service's Python)."""

from __future__ import annotations

import json

import docutracex.netcheck.freeproxy as fp


def test_module_imports_without_requests() -> None:
    # Nothing at module scope imports requests, so the web service (host Python,
    # web-only) can import freeproxy and read the cache.
    assert "requests" not in dir(fp)
    assert set(fp.status().keys()) == {"http", "socks4", "socks5"}


def test_find_working_delegates_to_portable(monkeypatch) -> None:
    calls = {}
    monkeypatch.setattr(fp, "_delegate",
                        lambda args, timeout=150: (calls.setdefault("args", args),
                        json.dumps({"protocol": "http", "host": "1.2.3.4", "port": 8080,
                                    "egress_ip": "1.2.3.4"}))[1])
    res = fp.find_working("http")
    assert res and res["host"] == "1.2.3.4"
    assert calls["args"][0] == "find" and calls["args"][1] == "http"


def test_find_working_delegate_returns_null(monkeypatch) -> None:
    monkeypatch.setattr(fp, "_delegate", lambda args, timeout=150: "null")
    assert fp.find_working("http") is None


def test_download_delegates_and_reads_result(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(fp, "_delegate",
                        lambda args, timeout=150: json.dumps({"proxies": [
                            {"protocol": "http", "host": "9.9.9.9", "port": 80}]}))
    monkeypatch.setattr(fp, "cache_path", lambda proto: tmp_path / "missing.json")
    got = fp.download("http")
    assert got and got[0]["host"] == "9.9.9.9"


def test_main_test_op(monkeypatch, capsys) -> None:
    monkeypatch.setattr(fp, "test", lambda p, timeout=fp.TEST_TIMEOUT: {"egress_ip": "x"})
    assert fp.main(["test", "http", "1.2.3.4", "8080"]) == 0
    assert capsys.readouterr().out.strip() == "ok"


def test_enc_dec_exclude_roundtrip() -> None:
    s = {"1.2.3.4:80", "5.6.7.8:1080"}
    assert fp._dec_set(fp._enc_set(s)) == s
