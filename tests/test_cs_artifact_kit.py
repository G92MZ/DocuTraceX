"""Cobalt Strike Artifact Kit layout: stager XOR-ed with a 4-byte key in a data section."""

from __future__ import annotations

from pathlib import Path

import pytest

import make_samples as ms

from docutracex.c2 import cobalt


def test_xor4_payload_found_with_its_length() -> None:
    got = cobalt.xor4_payloads(ms.cs_artifact_kit_exe())
    assert len(got) == 1
    off, key, dec = got[0]
    assert key.hex() == "5a3c9e71" and dec == ms.cs_stager_shellcode()


def test_xor4_used_when_the_parsers_find_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = cobalt._extract

    def only_plain(path, data):  # noqa: ANN001, ANN202
        # the first pass (on the PE) finds nothing, as with the real sample; the decoded blob is read as usual
        return None if data[:2] == b"MZ" else real(path, data)
    monkeypatch.setattr(cobalt, "_extract", only_plain)
    p = tmp_path / "artifact.exe"
    p.write_bytes(ms.cs_artifact_kit_exe())
    r = cobalt.extract(p, p.read_bytes())
    assert r["kind"] == "stager" and r["c2"] == ["cdn-update.example.net"]
    assert "4-byte key 5a3c9e71" in r["summary"]["Loader"]


def test_no_false_hits() -> None:
    for blob in (ms.njrat_exe(), ms.remcos_exe(), ms.cs_beacon_blob()):
        assert cobalt.xor4_payloads(blob) == []
