"""Origin fingerprints: values the machine or the kit left in a file, shown with that
file's own analysis (never correlated across files)."""

from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import fingerprints as F
from docutracex.config import settings

S = ms.fingerprint_samples()


def _vals(fps: list[dict]) -> dict[str, str]:
    return {f["name"]: f["value"] for f in fps}


def test_word_and_vba() -> None:
    v = _vals(F.ooxml(zipfile.ZipFile(io.BytesIO(S["sample_fingerprints.docm"]))))
    assert v["Word document GUID (w15)"] == ms.FP_DOC_GUID and v["Word document ID (w14)"] == "5A1C3E7B"
    assert v["Word rsidRoot"] == "00C4D1E2" and v["Word rsids (3)"] == "00C4D1E2 005A7F31 00E81B6C"
    assert v["VBA p-code cache version"] == "0xFFFF"           # written by a tool, not saved by Office
    assert v["VBA compiled on"] == "64-bit Windows" and v["VBA project locale"] == "0x0409 (en-US)"
    assert v["VBA project GUID"].startswith("{") and v["VBA code page"] == "1252"


def test_excel() -> None:
    v = _vals(F.ooxml(zipfile.ZipFile(io.BytesIO(S["sample_fingerprints.xlsx"]))))
    assert "rupBuild=27425" in v["Excel file version"]
    assert v["Excel document GUID"] == "8_{9C4E2A71-3B5D-4F86-A1E2-7D0B6C3F5E94}"


def test_pdf_ids_and_compressed_xmp() -> None:
    v = _vals(F.pdf(S["sample_fingerprints.pdf"]))
    assert v["PDF file ID (trailer /ID)"].startswith("2A7C9E41B05D3F86E1A4C27D9B03F658 · ")
    assert v["XMP DocumentID"] == "uuid:7E1D4B2A-0C93-4F5E-8B6A-2D9F1E3C7A40"   # read from a FlateDecode stream
    assert v["XMP InstanceID"] == "uuid:A4C2E8F1-5B7D-4E39-9C0A-6F3B1D8E2C57"
    assert "uuid:0B5E3A9C-7D21-4C6F-B8E4-1A2D9F7C3E60" in v["XMP derived from"]
    assert v["XMP history (2 saves)"] and "Microsoft Word" in v["XMP history software"]


def test_lnk_mac_vm_and_time() -> None:
    assert F.mac_of("AB451A00-D2A7-11F1-82A1-000C29A1B2C3") == ("00:0C:29:A1:B2:C3", "VMware", "2026-10-28 08:15:00")
    assert F.mac_of("6E4F2A1C-93B7-4D05-A8E2-1F7C3B9D5E60") is None          # v4: no MAC inside
    v = _vals(F.lnk({"droid_file_identifier": "AB451A00-D2A7-11F1-82A1-000C29A1B2C3",
                     "birth_droid_file_identifier": "AB451A00-D2A7-11F1-82A1-000C29A1B2C3"},
                    {"location_info": {"drive_serial_number": "0x5A3C19E2", "volume_label": "OS"}}))
    assert v["MAC address (tracker object ID)"] == "00:0C:29:A1:B2:C3 — VMware virtual NIC"
    assert v["Volume serial"] == "0x5A3C19E2" and "Tracker IDs differ" not in v


def test_pe_gathers_lief_values() -> None:
    v = _vals(F.pe({"pdb": [{"path": r"C:\Users\dev\src\Factura\Release\Factura.pdb", "guid": "G", "age": 2}],
                    "rich_header": {"key": "0x1a2b3c4d", "md5": "ab" * 16}, "imphash": "cd" * 16,
                    "signatures": [{"certificates": [{"subject": "CN=Ejemplo", "serial": "01"}]}]}))
    assert v["PDB GUID · age"] == "G · 2" and v["Rich header key"] == "0x1a2b3c4d" and v["Imphash"] == "cd" * 16
    assert v["Signer certificate"] == "CN=Ejemplo · serial 01"


def _case(c, name: str, data: bytes, tmp: Path) -> Path:  # noqa: ANN001
    r = c.post("/api/cases", files={"file": (name, data)}).json()
    for _ in range(1200):
        t = next((x for x in c.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.1)
    return tmp / "cases" / r["analysis_id"] / "results"


def test_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    c = TestClient(create_app())
    res = _case(c, "factura.docm", S["sample_fingerprints.docm"], tmp_path)
    assert ms.FP_DOC_GUID in json.dumps(json.loads((res / "officerules.json").read_text())["fingerprints"])
    res = _case(c, "factura.pdf", S["sample_fingerprints.pdf"], tmp_path)
    assert "XMP DocumentID" in _vals(json.loads((res / "pdf.json").read_text())["fingerprints"])
    res = _case(c, "factura.pdf.lnk", S["sample_fingerprints.lnk"], tmp_path)
    item = json.loads((res / "shortcut.json").read_text())["items"][0]
    assert _vals(item["fingerprints"])["MAC address (tracker object ID)"].endswith("VMware virtual NIC")
