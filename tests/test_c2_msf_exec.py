"""Metasploit windows/exec payloads: the command, not a "stager with no target"."""

from __future__ import annotations

import make_samples as ms

from docutracex.c2 import metasploit


def test_exec_adduser() -> None:
    r = metasploit.extract(ms.msf_exec_adduser_blob())
    assert r["family"] == "Metasploit payload (exec)" and r["kind"] == "payload" and r["c2"] == []
    assert r["summary"]["Payload"] == "windows/exec (adds a local user)"
    assert r["summary"]["Command"].startswith("net user facturas_sync") and r["confidence"] == "high"


def test_stager_unchanged() -> None:
    r = metasploit.extract(ms.msf_https_stager_blob())
    assert r["family"] == "Metasploit / Meterpreter" and r["c2"] == ["cdn-update.example.net"]


def test_block_api_alone_is_still_generic() -> None:
    sc = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52" + b"\x00" * 64
    assert metasploit.extract(sc)["family"] == "Metasploit-style stager"
