"""Three-stage .NET crypter: inline RC4 on a resource entry, then a Bitmap whose
pixels hold the last stage XOR-ed with a key the assembly only has as hex text,
with empty pixels at the end of every column."""

from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms

from docutracex import dotnet, stego
from docutracex.dotnet.resources import parse as parse_resources
from docutracex.dotnet.strdec import _rc4, decrypt_blob

pytestmark = pytest.mark.skipif(not dotnet.available(), reason="dnfile not installed")


def _entries() -> tuple[dict, dict[str, bytes]]:
    r = dotnet.parse(ms.dotnet_crypter_chain_exe())
    ents = {e["name"]: e["_data"] for x in r["resources"] for e in parse_resources(x["_data"])["entries"]}
    return r, ents


def test_rc4_matches_reference() -> None:
    # RFC 6229 test vector: key 0x0102030405, first keystream bytes
    assert _rc4(bytes.fromhex("0102030405"), b"\x00" * 8).hex() == "b2396305f03dc027"


def test_inline_rc4_entry() -> None:
    r, ents = _entries()
    how, plain, ext = decrypt_blob(ents["mn"], r["_cil_methods"])
    assert ext == "exe" and how.startswith('RC4 key "R7E4NT2026INV8QK5"')


def test_bitmap_key_recovered_and_holes_skipped() -> None:
    _r, ents = _entries()
    how, payload, kind = stego.extract(ents["PVX"], [])          # no candidate keys at all
    assert kind == "exe" and payload == ms.xworm_named_exe()
    assert "without empty pixels" in how and "recovered from the zeros of the DOS header" in how


def test_recover_xor_key_rejects_plain_and_short() -> None:
    pe = ms.xworm_named_exe()
    assert stego.recover_xor_key(pe) is None                     # not encrypted
    assert stego.recover_xor_key(b"\x01" * 64) is None
    enc = bytes(c ^ b"\x11\x22\x33\x44\x55"[i % 5] for i, c in enumerate(pe))
    assert stego.recover_xor_key(enc) == b"\x11\x22\x33\x44\x55"


def test_case_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("dncil")
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.dotnet_crypter_chain_exe()), "alquiler.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    d = read_json(paths.subresult("dotnet"))
    rules = [f["rule"] for f in d["findings"]]
    assert "dotnet:resource_decrypted" in rules and "dotnet:bitmap_payload" in rules
    names = [n["filename"] for n in read_json(paths.subresult("nested"))["tree"]]
    assert any(n.endswith("mn.decrypted.exe") for n in names) and any(n.endswith("PVX.pixels.exe") for n in names)
    fams = {c["family"] for c in read_json(paths.subresult("c2")).get("configs") or []}
    assert "XWorm" in fams
