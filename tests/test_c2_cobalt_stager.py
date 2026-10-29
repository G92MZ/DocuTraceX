"""Cobalt Strike stager inside a PE: 1768.py reports it as messages, not as ``config``.

Messages modelled on real 1768.py output (stager x86, 4-byte XOR). The C2 address is
replaced by an RFC 5737 documentation address so no live indicator is kept in the repo.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from docutracex.c2 import cobalt

MSGS = [
    "File: stager.exe",
    "payloadType: 0x00000000",
    "payloadSize: 0x00000000",
    "intxorkey: 0x00000000",
    "id2: 0x00000000",
    "Skipping 32 bytes",
    "payloadType: 0x00007630",
    "payloadSize: 0x0000031e",
    "intxorkey: 0xa7042bf8",
    "id2: 0x00000000",
    "Probably found shellcode:",
    "Parameter: 782 b'198.51.100.7'",
    "push      :   194       8080 b'h\\x90\\x1f\\x00\\x00'",
    "push      :   720       4096 b'h\\x00\\x10\\x00\\x00'",
    "push      :   751       8192 b'h\\x00 \\x00\\x00'",
    "String: 547 b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/139.0.0.0'",
]


def test_stager_parsed_from_1768_messages() -> None:
    res = cobalt._stager_from_messages(MSGS)
    assert res is not None
    summary, hosts = cobalt.summarise(res["fields"])
    assert hosts == ["198.51.100.7"]
    assert summary["C2"] == ["198.51.100.7:8080"]          # 4096 / 8192 are VirtualAlloc sizes, not ports
    assert summary["User-Agent"].startswith("Mozilla/5.0")
    assert "0xa7042bf8" in res["method"]


def test_no_shellcode_gives_nothing() -> None:
    msgs = ["File: x.exe", "Error: PE file error: .data section not found: '.text' '.rsrc' '.reloc'"]
    assert cobalt._stager_from_messages(msgs) is None


def test_extract_reports_stager_when_config_is_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    script = tmp_path / "1768.py"
    script.write_text("# stub")
    monkeypatch.setattr(cobalt, "_script", lambda: script)
    monkeypatch.setattr(cobalt, "_is_pe", lambda data: True)
    out = json.dumps({"filename": "stager.exe", "messages": MSGS, "config": {}})
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=out, stderr=""))
    sample = tmp_path / "stager.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    res = cobalt.extract(sample, sample.read_bytes())
    assert res is not None
    assert res["family"] == "Cobalt Strike"
    assert res["kind"] == "stager"
    assert res["c2"] == ["198.51.100.7"]
