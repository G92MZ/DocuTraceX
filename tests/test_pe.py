"""PE static triage (pefile): header, sections/entropy, packer detection, and
the binary-family pipeline."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("pefile")

from fastapi.testclient import TestClient  # noqa: E402

from docutracex.app import create_app  # noqa: E402
from docutracex.config import settings  # noqa: E402
from docutracex.parsers import pe  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402

_PE = ms.packed_pe_exe()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    return tmp_path


@pytest.fixture()
def client(env) -> TestClient:
    return TestClient(create_app())


def _wait(client, cid):
    for _ in range(1200):
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            return
        time.sleep(0.05)


def test_packed_pe_detected(tmp_path: Path) -> None:
    p = tmp_path / "p.exe"
    p.write_bytes(_PE)
    r = pe.analyze(p, "p.exe", run_tools=False)
    assert r["is_pe"] and r["machine"] == "x64"
    rules = {f["rule"] for f in r["findings"]}
    assert {"pe_packer_section", "pe_packed", "pe_section_wx"} <= rules
    assert any(s["entropy"] >= 7.2 for s in r["sections"])


def test_not_a_pe(tmp_path: Path) -> None:
    p = tmp_path / "x.exe"
    p.write_bytes(b"%PDF-1.7 not a pe")
    r = pe.analyze(p, "x.exe", run_tools=False)
    assert r["is_pe"] is False
    assert any(f["rule"] == "pe_not_pe" for f in r["findings"])


def test_malformed_pe(tmp_path: Path) -> None:
    p = tmp_path / "m.exe"
    p.write_bytes(b"MZ" + b"\x00" * 200)   # MZ but no valid PE header
    r = pe.analyze(p, "m.exe", run_tools=False)
    assert r["is_pe"]
    assert any(f["rule"] in ("pe_malformed", "pe_image") for f in r["findings"])


def test_entropy_helper() -> None:
    assert pe._entropy(b"") == 0.0
    assert pe._entropy(b"\x00" * 1000) == 0.0
    assert pe._entropy(bytes(range(256)) * 10) > 7.9


def test_case_exe_end_to_end(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("packed.exe", _PE)}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    # PE triage lives in the binary family's "msi" module; the file record stays too.
    assert comp["modules"]["file"]["hashes"]["sha256"]
    item = comp["modules"]["msi"]["items"][0]
    assert item["kind"] == "pe" and item["machine"] == "x64"
    rules = {f["rule"] for f in comp["findings"]}
    assert "pe_packed" in rules
    # a PE is not run through the scripting engine
    assert "javascript" not in comp["modules"] and "powershell" not in comp["modules"]
