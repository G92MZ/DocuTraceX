"""dissect.cobaltstrike as the second Cobalt Strike parser: both tools always run, one view each.

The worker is replaced by canned JSON (same shape as ``_dissect_worker.py`` prints), so these tests do
not need the library; a real run is covered by test_dissect_worker_real (skipped when not installed).
"""

from __future__ import annotations

import importlib.util
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from docutracex.c2 import cobalt, cobalt_dissect

HOST = "198.51.100.7"
FOUND = {"status": "found", "lib": "1.3.0", "domains": [HOST], "uris": ["/jquery-3.3.1.min.js"],
         "submit_uri": "/jquery-3.3.2.min.js", "port": 443, "protocol": "https", "watermark": 12345678,
         "is_trial": False, "version": "Cobalt Strike 4.9 (Sep 19, 2023)", "sleeptime": 45000, "jitter": 25,
         "killdate": None, "pubkey_sha256": "ab" * 32, "xorkey": "2e", "xorencoded": False,
         "architecture": "x86", "stages": [],
         "settings": {"SETTING_USERAGENT": "Mozilla/5.0 test", "SETTING_PIPENAME": "\\\\.\\pipe\\x_%x"},
         "profile": 'set sleeptime "45000";\nhttp-get {\n    set uri "/jquery-3.3.1.min.js";\n}\n'}


def _cfg_blob(host: str = HOST) -> bytes:
    def short(i, v): return struct.pack(">HHHH", i, 1, 2, v)
    def num(i, v): return struct.pack(">HHHI", i, 2, 4, v)
    def data(i, b, n): return struct.pack(">HHH", i, 3, n) + b.ljust(n, b"\x00")
    spki = (bytes.fromhex("30819f300d06092a864886f70d010101050003818d00308189028181") + b"\xab" * 129
            + bytes.fromhex("0203010001"))
    cfg = (short(1, 8) + short(2, 443) + num(3, 45000) + short(5, 25) + data(7, spki, 256)
           + data(8, f"{host},/jquery-3.3.1.min.js".encode(), 256) + data(9, b"Mozilla/5.0 test", 256)
           + num(37, 12345678) + b"\x00\x00")
    return b"MZ" + b"\x00" * 200 + bytes(c ^ 0x2E for c in cfg.ljust(4096, b"\x00"))


@pytest.fixture
def no_1768(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cobalt, "_script", lambda: None)     # 1768 side = built-in decoder


def _dissect_returns(monkeypatch: pytest.MonkeyPatch, raw: dict) -> None:
    monkeypatch.setattr(cobalt_dissect, "_run", lambda path, all_xor: raw)


def test_view_from_worker_json() -> None:
    v = cobalt_dissect.view(FOUND)
    assert v["status"] == "found" and v["hosts"] == [HOST]
    s = v["summary"]
    assert s["C2"] == [f"{HOST}:443"] and s["Type"] == "HTTPS"
    assert s["Sleep / jitter"] == "45s / 25%" and s["Watermark"] == "12345678"
    assert s["Version"].startswith("Cobalt Strike 4.9")
    assert "http-get" in v["profile"]
    assert v["method"] == "dissect.cobaltstrike 1.3.0 (XOR 0x2e)"


@pytest.mark.parametrize("status", ["nothing", "not_installed", "timeout", "error", "disabled"])
def test_view_without_result_has_a_note(status: str) -> None:
    v = cobalt_dissect.view({"status": status, "error": "x"})
    assert v["status"] == status and v["note"] and "summary" not in v


def test_both_agree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_1768: None) -> None:
    _dissect_returns(monkeypatch, FOUND)
    p = tmp_path / "b.bin"
    p.write_bytes(_cfg_blob())
    r = cobalt.extract(p, p.read_bytes())
    assert r["agreement"] == "agree" and r["confidence"] == "high"
    assert set(r["tools"]) == {"1768", "dissect"}
    assert r["tools"]["1768"]["status"] == "found" and r["tools"]["dissect"]["status"] == "found"
    assert r["c2"] == [HOST]
    assert r["summary"]["Version"].startswith("Cobalt Strike 4.9")       # dissect-only fact on the card
    assert " + dissect.cobaltstrike" in r["method"]


def test_hosts_differ(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_1768: None) -> None:
    _dissect_returns(monkeypatch, {**FOUND, "domains": ["203.0.113.9"]})
    p = tmp_path / "b.bin"
    p.write_bytes(_cfg_blob())
    r = cobalt.extract(p, p.read_bytes())
    assert r["agreement"] == "differ" and r["confidence"] == "medium" and r["note"]
    assert set(r["c2"]) == {HOST, "203.0.113.9"}                          # both reach the IOCs
    assert r["summary"]["C2 (other tool)"] == ["203.0.113.9:443"]


def test_only_dissect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_1768: None) -> None:
    _dissect_returns(monkeypatch, FOUND)
    p = tmp_path / "packed.exe"
    p.write_bytes(b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00" + b"PE\x00\x00" + bytes(range(256)) * 4)
    r = cobalt.extract(p, p.read_bytes())
    assert r["agreement"] == "only dissect.cobaltstrike"
    assert r["tools"]["1768"]["status"] == "nothing" and r["c2"] == [HOST]


def test_only_1768_on_a_stager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_1768: None) -> None:
    _dissect_returns(monkeypatch, {"status": "nothing", "lib": "1.3.0", "error": "No valid Beacon configuration found"})
    p = tmp_path / "b.bin"
    p.write_bytes(_cfg_blob())
    r = cobalt.extract(p, p.read_bytes())
    assert r["agreement"] == "only built-in decoder"
    assert "stagers carry none" in r["tools"]["dissect"]["note"]


def test_disabled_by_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_1768: None) -> None:
    monkeypatch.setenv("DOCUTRACEX_DISSECT_CS", "0")
    monkeypatch.setattr(cobalt_dissect, "_run", lambda *a: pytest.fail("dissect must not run"))
    p = tmp_path / "b.bin"
    p.write_bytes(_cfg_blob())
    r = cobalt.extract(p, p.read_bytes())
    assert r["tools"]["dissect"]["status"] == "disabled"


def test_worker_timeout_is_a_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a, **k):  # noqa: ANN001
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)
    monkeypatch.setattr(subprocess, "run", boom)
    p = tmp_path / "b.bin"
    p.write_bytes(b"x")
    assert cobalt_dissect.extract(p)["status"] == "timeout"


@pytest.mark.skipif(importlib.util.find_spec("dissect") is None
                    or importlib.util.find_spec("dissect.cobaltstrike") is None,
                    reason="dissect.cobaltstrike not installed")
def test_dissect_worker_real(tmp_path: Path) -> None:
    p = tmp_path / "b.bin"
    p.write_bytes(_cfg_blob())
    worker = Path(cobalt_dissect.__file__).with_name("_dissect_worker.py")
    out = subprocess.run([sys.executable, str(worker), str(p), "1"], capture_output=True, text=True, timeout=120)
    raw = json.loads(out.stdout.strip().splitlines()[-1])
    assert raw["status"] == "found" and raw["domains"] == [HOST] and raw["port"] == 443
    assert "http-get" in raw["profile"]
