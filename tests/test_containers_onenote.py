"""Containers (tar/.gz, CAB, ISO) and OneNote: detection, extraction/carving,
family identification and the recursive pipeline."""

from __future__ import annotations

import sys
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from docutracex import unlock
from docutracex.app import create_app
from docutracex.config import settings
from docutracex.identify import classify_discrepancy
from docutracex.parsers import onenote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402


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


# --- detection ---------------------------------------------------------------
def test_detect_container_kinds(tmp_path: Path) -> None:
    (tmp_path / "a.cab").write_bytes(ms.cabinet_cab())
    (tmp_path / "a.iso").write_bytes(ms.optical_image_iso())
    (tmp_path / "a.tgz").write_bytes(ms.tarball_tgz())
    assert unlock.detect(tmp_path / "a.cab")["kind"] == "cab"
    assert unlock.detect(tmp_path / "a.iso")["kind"] == "iso"
    assert unlock.detect(tmp_path / "a.tgz")["kind"] == "tar"


# --- extractors --------------------------------------------------------------
def test_cab_extract(tmp_path: Path) -> None:
    (tmp_path / "a.cab").write_bytes(ms.cabinet_cab())
    rec = unlock.extract_archive(tmp_path / "a.cab", tmp_path / "o", [])
    names = {e["name"] for e in rec["entries"] if e.get("file")}
    assert "instalador.bat" in names and "actualizador.ps1" in names


def test_iso_extract(tmp_path: Path) -> None:
    (tmp_path / "a.iso").write_bytes(ms.optical_image_iso())
    rec = unlock.extract_archive(tmp_path / "a.iso", tmp_path / "o", [])
    names = {e["name"].lower() for e in rec["entries"] if e.get("file")}
    assert any(n.endswith(".lnk") for n in names) and any(n.endswith(".bat") for n in names)


def test_tar_and_single_stream(tmp_path: Path) -> None:
    (tmp_path / "a.tgz").write_bytes(ms.tarball_tgz())
    rec = unlock.extract_archive(tmp_path / "a.tgz", tmp_path / "o", [])
    assert {"actualizador.ps1", "factura.pdf.vbs"} <= {e["name"] for e in rec["entries"] if e.get("file")}
    # a lone gzip stream (not a tarball) becomes one entry
    import gzip
    (tmp_path / "s.gz").write_bytes(gzip.compress(b"powershell -enc AAAA"))
    rec2 = unlock.extract_archive(tmp_path / "s.gz", tmp_path / "o2", [])
    assert len([e for e in rec2["entries"] if e.get("file")]) == 1


# --- OneNote -----------------------------------------------------------------
def test_onenote_carve(tmp_path: Path) -> None:
    (tmp_path / "n.one").write_bytes(ms.onenote_one())
    r = onenote.extract(tmp_path / "n.one", tmp_path / "o")
    assert r["is_onenote"]
    exts = {e["ext"] for e in r["embedded"]}
    assert ".hta" in exts and ".vbs" in exts
    assert any(f["rule"] == "onenote_embedded_file" for f in r["findings"])


# --- identify ----------------------------------------------------------------
def test_container_family_identify() -> None:
    assert classify_discrepancy(".iso", "application/x-iso9660-image", "ISO 9660 CD-ROM filesystem")["declared_family"] == "container"
    assert classify_discrepancy(".cab", "application/vnd.ms-cab-compressed", "Microsoft Cabinet archive")["status"] == "match"
    assert classify_discrepancy(".gz", "application/gzip", "gzip compressed data")["declared_family"] == "container"
    assert classify_discrepancy(".one", "application/octet-stream", "data")["declared_family"] == "onenote"


# --- end-to-end --------------------------------------------------------------
def test_case_iso(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("f.iso", ms.optical_image_iso())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert {"archive", "nested"} <= set(comp["modules"])
    rules = {f["rule"] for f in comp["findings"]}
    assert "lnk_lolbin_target" in rules  # the carried LNK was analysed


def test_case_cab(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("f.cab", ms.cabinet_cab())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "nested" in comp["modules"]
    assert "bat_powershell" in {f["rule"] for f in comp["findings"]}


def test_case_onenote(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("notes.one", ms.onenote_one())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert comp["modules"]["onenote"]["is_onenote"]
    rules = {f["rule"] for f in comp["findings"]}
    assert "onenote_embedded_file" in rules
    # the carved HTA/VBS were scanned by the script engines
    assert any(r.startswith(("vbs_", "js_", "ps_")) for r in rules)


def test_nested_onenote_in_zip(client: TestClient, tmp_path: Path) -> None:
    buf = tmp_path / "b.zip"
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("notas.one", ms.onenote_one())
    cid = client.post("/api/cases", files={"file": ("b.zip", buf.read_bytes())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "nested" in comp["modules"]
    assert "onenote_embedded_file" in {f["rule"] for f in comp["findings"]}
