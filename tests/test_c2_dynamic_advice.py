"""Where static analysis stops: the C2 tab says so loudly and what to do in a sandbox."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _ms  # noqa: E402

from docutracex import c2  # noqa: E402
from docutracex.c2 import dynamic  # noqa: E402


def _bk():  # noqa: ANN202
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    import binkit
    return binkit


def test_loader_with_encrypted_payload_gets_the_banner(tmp_path: Path) -> None:
    p = tmp_path / "viewer.exe"
    p.write_bytes(_ms().loader_encrypted_payload_exe())
    r = c2.analyze(p, tmp_path / "extracted")
    (d,) = r["dynamic"]
    assert d["role"] == "loader" and "resource 10/INVOICE_DATA.BIN" in d["why"]
    assert d["anti_vm"] == ["vmmemctl", "VBoxGuest"] and len(d["todo"]) == 3
    f = [x for x in r["findings"] if x["rule"] == "c2:dynamic_analysis"]
    assert f and "needs a dynamic analysis" in f[0]["detail"]


def test_images_and_archives_in_resources_are_not_payloads() -> None:
    rnd = random.Random(7)
    noise = bytes(rnd.randrange(256) for _ in range(80 * 1024))
    for head in (b"\x89PNG\r\n\x1a\n", b"PK\x03\x04", b"\xff\xd8\xff\xe0"):
        data = _bk().pe(bits=64, rcdata=[("ART.BIN", head + noise)])
        assert dynamic.encrypted_blobs(data) == []
    assert dynamic.encrypted_blobs(_bk().pe(bits=64, rcdata=[("DATA.BIN", noise)]))


def test_payload_without_readable_config_and_family_tips() -> None:
    res = {"configs": [], "findings": []}
    c2._dynamic(res, [], [("stage.exe", "Formbook (family YARA)", Path("/nonexistent"))], {})
    (d,) = res["dynamic"]
    assert d["role"] == "payload" and d["family"] == "Formbook"
    assert any("decoy" in t for t in d["tips"])
    assert "Formbook payload reached" in res["findings"][0]["detail"]


def test_no_banner_when_the_config_was_read() -> None:
    res = {"configs": [{"family": "Formbook", "c2": ["cdn.example"], "provenance": ""}], "findings": []}
    c2._dynamic(res, [], [("stage.exe", "Formbook", Path("/nonexistent"))], {})
    assert "dynamic" not in res


def test_loader_opened_here_is_not_a_dead_end() -> None:
    ld = dynamic.assess_loader("loader.exe", _ms().loader_encrypted_payload_exe())
    res = {"configs": [{"family": "Lumma-like stealer", "c2": ["factura-cdn.example"],
                        "provenance": "loader.exe › payload.exe (decrypted)"}], "findings": []}
    c2._dynamic(res, [ld], [], {})
    assert "dynamic" not in res


def test_loader_unpacked_here_is_not_a_dead_end() -> None:
    ld = dynamic.assess_loader("packed.exe", _ms().loader_encrypted_payload_exe())
    res = {"configs": [], "findings": []}
    prov = {"extracted/unpacked/packed.unpacked.exe": {"source": "unpacked",
                                                       "text": "packed.exe › packed.unpacked.exe (UPX)",
                                                       "chain": ["packed.exe", "packed.unpacked.exe (UPX)"]}}
    c2._dynamic(res, [ld], [], prov)
    assert "dynamic" not in res


def test_last_executable_without_config_is_a_probable_payload(tmp_path: Path) -> None:
    leaf = tmp_path / "extracted" / "stages" / "stage_payload.exe"
    leaf.parent.mkdir(parents=True)
    leaf.write_bytes(_bk().pe(bits=32, strings=["Factura 2026-0187"]))
    prov = {"extracted/stages/stage_payload.exe": {"source": "decrypted", "text": "f.ps1 › stage_payload.exe (AES)",
                                                   "chain": ["f.ps1", "stage_payload.exe (AES)"]}}
    leaves = [("extracted/stages/stage_payload.exe", "extracted/stages/stage_payload.exe", leaf)]
    res = {"configs": [], "findings": []}
    c2._dynamic(res, [], [], prov, leaves)
    (d,) = res["dynamic"]
    assert d["role"] == "probable_payload" and "f.ps1 › stage_payload.exe" in d["why"]
    assert res["findings"][0]["severity"] == "low"
    # not when the case already has a configuration, nor when something was opened below it
    res = {"configs": [{"family": "AgentTesla", "c2": ["smtp.example"]}], "findings": []}
    c2._dynamic(res, [], [], prov, leaves)
    assert "dynamic" not in res
    prov2 = {**prov, "extracted/stages/inner.exe": {"source": "decrypted",
                                                    "chain": ["f.ps1", "stage_payload.exe (AES)", "inner.exe"]}}
    res = {"configs": [], "findings": []}
    c2._dynamic(res, [], [], prov2, leaves)
    assert "dynamic" not in res


def test_interpreter_runtime_points_at_the_script() -> None:
    e = dynamic.assess_leaf("lua51.exe", b"MZ" + b"\x00" * 64 + b"LuaJIT 2.1.0-beta2 -- Copyright (C) 2005-2016 Mike Pall")
    assert e["runtime"] == "LuaJIT" and "the payload is the script it runs" in e["why"]
