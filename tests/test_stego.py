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
