"""QR codes outside PDFs and email attachments: a standalone image, Office media,
base64 data: URIs in HTML and RTF pictures — each URL reaches the findings and the IOCs."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import hidden, qr
from docutracex.config import settings

pytest.importorskip("zxingcpp")
SAMPLES = ms.qr_samples()


def test_reader_and_filters(tmp_path: Path) -> None:
    p = tmp_path / "q.png"
    p.write_bytes(SAMPLES["sample_qr_factura.png"])
    assert qr.read([p])[str(p)][0]["text"] == ms.QR_URL.format("imagen")
    assert qr.worth_reading(SAMPLES["sample_qr_factura.png"])
    tiny = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + (16).to_bytes(4, "big") * 2
    assert not qr.worth_reading(tiny)                     # a 16x16 icon holds no code
    f = qr.findings([{"format": "QRCode", "text": "https://x.example/a"}, {"format": "EAN13", "text": "123"}], "img")
    assert [(x["rule"], x["severity"]) for x in f] == [("qr_code_url", "high"), ("qr_code", "low")]


def test_images_in_markup_and_rtf() -> None:
    imgs = hidden._data_uri_images(SAMPLES["sample_qr_datauri.html"])
    assert len(imgs) == 1 and imgs[0][:4] == b"\x89PNG"
    pics = hidden._rtf_pictures(SAMPLES["sample_qr_pict.rtf"])
    assert len(pics) == 1 and pics[0][:4] == b"\x89PNG"
    assert hidden._data_uri_images(b"<img src='data:image/png;base64,AAAA'>") == []   # too short to be an image


def _case(c, name: str, data: bytes, tmp: Path) -> Path:  # noqa: ANN001
    r = c.post("/api/cases", files={"file": (name, data)}).json()
    for _ in range(1200):
        t = next((x for x in c.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.1)
    return tmp / "cases" / r["analysis_id"] / "results"


def _iocs(res: Path) -> str:
    p = res / "iocs.json"
    return p.read_text() if p.exists() else ""


def test_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    c = TestClient(create_app())

    # the file is the image
    res = _case(c, "escanear.png", SAMPLES["sample_qr_factura.png"], tmp_path)
    q = json.loads((res / "qr.json").read_text())
    assert q["codes"][0]["text"] == ms.QR_URL.format("imagen") and q["findings"][0]["rule"] == "qr_code_url"
    assert "portal-facturas.example" in _iocs(res)

    # an image child: Office media, a data: URI, an RTF picture
    for name, tag in (("sample_qr_factura.docx", "docx"), ("sample_qr_datauri.html", "html"),
                      ("sample_qr_pict.rtf", "rtf")):
        res = _case(c, name, SAMPLES[name], tmp_path)
        tree = json.loads((res / "nested.json").read_text()).get("tree") or []
        imgs = [n for n in tree if n.get("source") == "images"]
        assert [x["text"] for n in imgs for x in n.get("qr") or []] == [ms.QR_URL.format(tag)], name
        assert any(f["rule"] == "qr_code_url" for n in imgs for f in n["findings"]), name
        assert f"/qr/{tag}" in _iocs(res), name
