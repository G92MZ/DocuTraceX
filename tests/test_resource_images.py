"""Images of the case as objects of their own: Office media and the images in
the native resources of PEs (bitmaps, icons, images in RCDATA), listed in
Nested with where they came from even when they hide nothing."""

from __future__ import annotations

import json
import struct
import time
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import hidden
from docutracex.config import settings


def test_pe_resource_images() -> None:
    imgs = dict(hidden._pe_images(ms.resource_images_exe()))
    assert set(imgs) == {"RT_BITMAP/LOGO", "RT_ICON/1", "RT_RCDATA/SPLASH"}
    assert imgs["RT_BITMAP/LOGO"][:2] == b"BM" and imgs["RT_RCDATA/SPLASH"][:4] == b"\x89PNG"
    ico = imgs["RT_ICON/1"]
    assert ico[:4] == b"\x00\x00\x01\x00" and struct.unpack_from("<BB", ico, 6) == (32, 32)


def test_no_images_in_a_plain_pe() -> None:
    import binkit
    assert hidden._pe_images(binkit.pe(bits=32)) == []


def _case(c, name: str, data: bytes, tmp: Path) -> list[dict]:  # noqa: ANN001
    r = c.post("/api/cases", files={"file": (name, data)}).json()
    for _ in range(1200):
        t = next((x for x in c.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.1)
    p = tmp / "cases" / r["analysis_id"] / "results" / "nested.json"
    return json.loads(p.read_text()).get("tree") or [] if p.exists() else []


def test_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    c = TestClient(create_app())
    tree = _case(c, "viewer.exe", ms.resource_images_exe(), tmp_path)
    imgs = {n["filename"]: n for n in tree if n.get("source") == "images"}
    assert {"RT_BITMAP_LOGO.bmp", "RT_ICON_1.ico", "RT_RCDATA_SPLASH.png"} <= set(imgs)
    assert imgs["RT_ICON_1.ico"]["decrypted_from"] == "image in the resource RT_ICON/1 of viewer.exe"
    tree = _case(c, "factura.docx", ms.media_docx(), tmp_path)
    media = [n for n in tree if n.get("source") == "images"]
    assert [n["decrypted_from"] for n in media] == ["Office media word/media/image1.png of factura.docx"]
