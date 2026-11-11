""".NET: ConfuserEx constants decrypted statically, and C2 on the objects the
.NET analysis derives (resources, pixels, stages) with their provenance."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import dotnet
from docutracex.config import settings
from docutracex.dotnet import confuser


def test_confuser_constants_recovered_with_their_callers() -> None:
    r = dotnet.parse(ms.dotnet_confuser_exe())
    assert {o["name"] for o in r["obfuscators"]} == {"ConfuserEx"}
    assert not set(ms.CFX_STRINGS) & set(r["strings"])                 # nothing in plain #US
    cx = r["cil"]["confuser_constants"]
    assert cx["mode"] == "Normal" and cx["strings"] == len(ms.CFX_STRINGS) and "0x5eed0187" in cx["how"]
    dec = [d for d in r["cil"]["decrypted"] if d["decryptor"].startswith("ConfuserEx constants")]
    assert [d["output"] for d in dec] == ms.CFX_STRINGS
    assert all(d["caller"] == "InvoiceUpdater.Program::Main" and d["input"].startswith("0x") for d in dec)
    assert "http://cdn-update.example.net/gate.php" in dotnet.static_strings(ms.dotnet_confuser_exe())


def test_wrong_seed_never_decompresses() -> None:
    assert confuser.decrypt_normal(bytes(range(256)) * 2, 0x12345678) is None


def test_findings_and_iocs(tmp_path: Path) -> None:
    (tmp_path / "original").mkdir()
    exe = tmp_path / "original" / "updater.exe"
    exe.write_bytes(ms.dotnet_confuser_exe())
    res = dotnet.analyze_case(tmp_path, exe, [])
    f = next(x for x in res["findings"] if x["rule"] == "dotnet:confuser_constants")
    assert f["severity"] == "medium" and "5 literal(s) recovered" in f["detail"]
    texts = {s["text"] for s in res["objects"][0]["ioc_sources"]}
    assert "203.0.113.47" in texts and "http://cdn-update.example.net/gate.php" in texts


def test_c2_on_a_stage_hidden_in_a_bitmap_has_provenance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    c = TestClient(create_app())
    r = c.post("/api/cases", files={"file": ("gallery.exe", ms.dotnet_bitmap_loader_exe(stage=ms.dotnet_stealer_exe()))}).json()
    for _ in range(1200):
        t = next((x for x in c.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.1)
    res = json.loads((tmp_path / "cases" / r["analysis_id"] / "results" / "c2.json").read_text())
    cfg = next(x for x in res["configs"] if x["family"].startswith("AgentTesla"))
    assert cfg["stored_path"].startswith("extracted/dotnet_resources/")
    assert cfg["provenance"].startswith("gallery.exe › ") and "bitmap pixels" in cfg["provenance"]
    f = next(x for x in res["findings"] if x["location"] == cfg["object"])
    assert f["evidence"].startswith("from: gallery.exe")


def test_derived_objects_are_scanned_first(tmp_path: Path) -> None:
    from docutracex import c2
    ex = tmp_path / "extracted"
    for i in range(c2.MAX_FILES + 20):
        (ex / "aaa_bulk").mkdir(parents=True, exist_ok=True)
        (ex / "aaa_bulk" / f"f{i:04d}.txt").write_text("x")
    (ex / "dotnet_resources" / "abc").mkdir(parents=True)
    (ex / "dotnet_resources" / "abc" / "stage.exe").write_bytes(b"MZ")
    orig = tmp_path / "original.bin"
    orig.write_bytes(b"x")
    labels = [label for label, _p, _s in c2._targets(orig, ex)]
    assert labels[1] == "extracted/dotnet_resources/abc/stage.exe" and len(labels) == c2.MAX_FILES + 1
