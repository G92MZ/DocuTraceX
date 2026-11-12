"""AES resource loader: the key sits in the class' static constructor, the encrypted
stage is a byte[] entry of a ``.resources`` file. The decrypted stage becomes a nested
child and the C2 tab reads its XWorm config."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms

from docutracex import dotnet
from docutracex.dotnet.resources import parse as parse_resources
from docutracex.dotnet.strdec import decrypt_blob

pytestmark = pytest.mark.skipif(not dotnet.available(), reason="dnfile not installed")


def test_key_from_the_class_cctor() -> None:
    r = dotnet.parse(ms.dotnet_resource_loader_exe())
    meths = r["_cil_methods"]
    entry = parse_resources(r["resources"][0]["_data"])["entries"][0]
    how, plain, ext = decrypt_blob(entry["_data"], meths)
    assert ext == "exe" and plain.startswith(ms.xworm_named_exe())
    assert 'MD5("Fx7InvoiceLaunch2026")' in how and "key from its class" in how


def test_no_crypto_method_no_attempt() -> None:
    assert decrypt_blob(b"\x13" * 4096, [{"method": "A::B", "calls": [], "_ops": [], "_all_strings": ["x" * 16]}]) is None


def test_case_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("dncil")
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.dotnet_resource_loader_exe()), "lanzador.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    d = read_json(paths.subresult("dotnet"))
    f = next(x for x in d["findings"] if x["rule"] == "dotnet:resource_decrypted")
    assert "› Client" in f["detail"] and f["severity"] == "high"
    tree = read_json(paths.subresult("nested"))["tree"]
    kid = next(n for n in tree if n["filename"].endswith("Client.decrypted.exe"))
    assert kid["recipe"][-1].startswith("decrypt: AES-128 ECB")
    c2 = read_json(paths.subresult("c2"))
    fams = {c["family"] for c in c2.get("configs") or []}
    assert "XWorm" in fams
