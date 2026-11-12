"""Raccoon Stealer v2: C2 URLs, request fields, config ID, traces."""

from __future__ import annotations

import make_samples as ms

from docutracex.c2 import families, stealers


def test_strings_decrypted():
    r = stealers.extract_all(ms.raccoon_exe())[0]
    s = r["summary"]
    assert s["C2"] == ["http://203.0.113.47/", "https://cdn-update.example.net/"]
    assert s["Config ID (probably)"] == "5c1d9a7e3b0f4c2a8e6d1b9f0a3c7e25" and s["User agent"].startswith("Mozilla/5.0")
    assert "machineId=" in s["Request fields"] and "not in the file" in s["Note"]


def test_traces_need_its_request_fields():
    r = stealers.extract_all(ms.raccoon_traces_exe())[0]
    assert r["kind"] == "indicators" and r["c2"] == []
    stub = ms.raccoon_traces_exe().replace(b"machineId=", b"xxxxxxxxx=").replace(b"&configId=", b"&xxxxxxxx=")
    assert stealers.raccoon(stub) is None             # browser DLLs alone: no family named


def test_family_card():
    assert families.for_family("Raccoon Stealer v2")["id"] == "raccoon"
