"""Generic image stego: any image of a case, several pixel layouts and
encodings; only well-formed files are kept (no false positives on images)."""

from __future__ import annotations

import base64
import gzip
import io
import random
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import binkit as bk  # noqa: E402
import make_samples as ms  # noqa: E402

from docutracex import stego  # noqa: E402

PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

ELF = bk.elf(strings=["inert invoice helper"])
PE = bk.pe(bits=32, gui=False)


def _img(data: bytes, w: int = 64, fmt: str = "PNG", columns: bool = False) -> bytes:
    h = -(-len(data) // (3 * w))
    data = data + b"\x00" * (3 * w * h - len(data))
    im = Image.frombytes("RGB", (h, w) if columns else (w, h), data)
    if columns:
        im = im.transpose(Image.Transpose.TRANSPOSE)
    out = io.BytesIO()
    im.save(out, format=fmt)
    return out.getvalue()


def _lsb(data: bytes, w: int = 128) -> bytes:
    bits = "".join(f"{b:08b}" for b in data)
    n = -(-len(bits) // 3)
    h = -(-n // w)
    rnd = random.Random(7)
    px = []
    for i in range(w * h):
        p = []
        for c in range(3):
            j = 3 * i + c
            v = rnd.randrange(256) & 0xFE
            p.append(v | (int(bits[j]) if j < len(bits) else 0))
        px.append(tuple(p))
    im = Image.new("RGB", (w, h))
    im.putdata(px)
    out = io.BytesIO()
    im.save(out, format="PNG")
    return out.getvalue()


@pytest.mark.parametrize("name, image, kind, how", [
    ("ELF, rows", _img(ELF), "elf", "rows, RGB bytes: plain"),
    ("PE, columns, BMP", _img(PE, fmt="BMP", columns=True), "exe", "columns, RGB bytes: plain"),
    ("length prefix", _img(len(PE).to_bytes(4, "little") + PE), "exe", "length LE"),
    ("single-byte XOR", _img(bytes(b ^ 0x5C for b in ELF)), "elf", "XOR 0x5c"),
    ("gzip", _img(gzip.compress(PE)), "exe", "zlib/gzip"),
    ("Base64", _img(base64.b64encode(ELF)), "elf", "Base64"),
    ("LSB1", _lsb(ELF), "elf", "LSB1 RGB"),
])
def test_layouts_and_encodings(name, image, kind, how) -> None:
    got = stego.extract(image)
    assert got, name
    assert got[2] == kind and how in got[0], got[0]
    assert got[1] == (ELF if kind == "elf" else PE)[:len(got[1])] and len(got[1]) >= 0x100


def test_keyed_xor_and_trimmed_size() -> None:
    key = b"4417290360015521"
    got = stego.extract(_img(bytes(b ^ key[i % 16] for i, b in enumerate(PE))), ["unrelated", key.decode()])
    assert got and 'XOR key "4417290360015521"' in got[0] and got[1] == PE


@pytest.mark.parametrize("seed", range(4))
def test_no_false_positives(seed: int) -> None:
    rnd = random.Random(seed)
    noise = bytes(rnd.randrange(256) for _ in range(96 * 96 * 3))
    gradient = bytes((x + y) % 256 for y in range(96) for x in range(96 * 3))
    for raw in (noise, gradient):
        for fmt in ("PNG", "BMP", "JPEG", "GIF"):
            im = Image.frombytes("RGB", (96, 96), raw)
            out = io.BytesIO()
            im.save(out, format=fmt)
            assert stego.extract(out.getvalue(), ["key", "4417290360015521"]) is None
    assert stego.identify(b"MZ" + b"\x00" * 300) is None and stego.identify(b"\x7fELF" + b"\x00" * 80) is None


def test_any_image_child_of_a_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A PNG inside a ZIP (no .NET anywhere): its hidden ELF is a nested child + finding."""
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.stego_zip()), "fotos_factura.zip", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    tree = read_json(CasePaths(m["analysis_id"], cases_dir=tmp_path).subresult("nested"))["tree"]
    img = next(n for n in tree if n["filename"].endswith(".png"))
    assert img["stego"]["kind"] == "elf"
    assert any(f["rule"] == "stego:payload" for f in img["findings"])
    assert [c["filename"] for c in img["children"]] == ["factura_scan.pixels.elf"]


def test_data_appended_after_the_image() -> None:
    from PIL import Image as _I
    for fmt in ("PNG", "JPEG", "GIF", "BMP"):
        b = io.BytesIO()
        _I.new("RGB", (40, 20), (200, 10, 10)).save(b, format=fmt)
        got = stego.extract(b.getvalue() + b"\x00" * 7 + bytes(x ^ 0x5C for x in PE))
        assert got and got[2] == "exe" and "appended after the image end" in got[0] and got[1] == PE, fmt
    assert stego.trailing(ms.stego_appended_png())[1] == PE


def test_sweep_resources_images_and_case_keys(tmp_path: Path) -> None:
    """PE resources (Base64 PE in RCDATA, ELF in the pixels of a BMP resource) and an
    extracted image XOR-ed with a key that only a .NET object of the case knows."""
    import json
    from docutracex import hidden
    from docutracex.storage import CasePaths
    paths = CasePaths("c1", cases_dir=tmp_path)
    paths.extracted_dir.mkdir(parents=True)
    (paths.root / "results").mkdir(parents=True, exist_ok=True)
    key = "InvoiceSync#2024"
    paths.subresult("dotnet").write_text(json.dumps({"objects": [{"result": {"strings": [key]}}]}))
    img = _img(bytes(b ^ key.encode()[i % len(key)] for i, b in enumerate(ELF)))
    (paths.extracted_dir / "media").mkdir()
    (paths.extracted_dir / "media" / "image1.png").write_bytes(img)
    original = tmp_path / "InvoiceUpdater.exe"
    original.write_bytes(ms.stego_rcdata_exe())
    got = {it["filename"]: it for it in hidden.sweep(paths, original, [])}
    names = sorted(got)
    assert any(n.endswith("RT_RCDATA_CFG.exe") for n in names) and any(n.endswith("RT_RCDATA_LOGO.elf") for n in names)
    assert any(n == "image1.hidden.elf" for n in names)
    assert 'XOR key "InvoiceSync#2024"' in got["image1.hidden.elf"]["origin"]
    cfg = next(v for k, v in got.items() if k.endswith("CFG.exe"))
    assert "Base64" in cfg["origin"] and cfg["finding"]["severity"] == "high"
    assert Path(cfg["path"]).read_bytes() == PE
    # nothing for an image / PE without anything hidden
    (paths.extracted_dir / "media" / "image1.png").write_bytes(_img(b"just a logo" * 50))
    plain = tmp_path / "plain.exe"
    plain.write_bytes(PE)
    import shutil
    shutil.rmtree(paths.extracted_dir / hidden.DIRNAME, ignore_errors=True)
    assert hidden.sweep(paths, plain, []) == []


def test_stage_chain_loader_to_stealer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stage 1 (.NET loader) hides stage 2 (.NET stealer, encrypted settings) in a Bitmap:
    the stage loop analyses stage 2 as .NET and its C2 settings come out."""
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.dotnet_bitmap_loader_exe(ms.dotnet_stealer_exe())), "gallery.exe",
                          cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    dn = read_json(paths.subresult("dotnet"))
    names = {(o.get("result") or {}).get("assembly", {}).get("name") for o in dn["objects"]}
    assert {"InvoiceGallery", "InvoiceMailSync"} <= names
    stealer = next(o for o in dn["objects"] if (o.get("result") or {}).get("assembly", {}).get("name") == "InvoiceMailSync")
    assert "smtp.billing-portal.example" in {d["output"] for d in stealer["result"]["cil"]["decrypted"]}
    c2 = read_json(paths.subresult("c2"))
    if c2 is not None:                                   # C2 runs when enabled (tests: auto)
        assert any("smtp.billing-portal.example" in (c.get("c2") or []) for c in c2["configs"])
