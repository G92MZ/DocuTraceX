"""Content before extension: binaries named like source code are read as binaries."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from docutracex import contentcheck  # noqa: E402

ms = pytest.importorskip("make_samples")


def test_text_stays_text() -> None:
    assert contentcheck.is_text(b"print('hola')\r\n")
    assert contentcheck.is_text("Write-Host 'hola'".encode("utf-16"))              # BOM'd UTF-16 (a .ps1)
    assert contentcheck.is_text("Write-Host 'hola' # sin BOM".encode("utf-16-le"))
    assert contentcheck.is_text("#@~^ZgAAAA==\\ko$K6,O@#@&".encode())               # an encoded .vbe
    assert contentcheck.is_text("España, factura nº 7 — ñ".encode("cp1252"))
    assert contentcheck.check("a.py", b"import os\n") is None
    assert contentcheck.check("a.pyc", b"\x00\x01\x02") is None                      # .pyc is binary by design


@pytest.mark.parametrize("name,kind,piece", [
    ("sample_disguised_autoit.au3", None, "compiled AutoIt script"),
    ("sample_disguised_pe.py", "PE", "PE"),
    ("sample_disguised_zip.pl", "ZIP", "ZIP"),
    ("sample_embedded_pe.ps1", None, "PE"),
])
def test_binaries_named_like_scripts(name: str, kind: str | None, piece: str) -> None:
    data = ms.disguised_samples()[name]
    rec = contentcheck.check(name, data)
    assert rec and rec["kind"] == kind and rec["pieces"][0]["kind"] == piece
    f = contentcheck.finding(rec, name, name)
    assert f["rule"] == "disguised_binary" and "not analysed as code" in f["detail"]


def test_embedded_pe_is_cut_to_its_size(tmp_path: Path) -> None:
    data = ms.disguised_samples()["sample_embedded_pe.ps1"]
    rec = contentcheck.check("x.ps1", data)
    got = contentcheck.carve(data, rec["pieces"], "x.ps1", tmp_path)
    raw = Path(got[0]["path"]).read_bytes()
    assert raw[:2] == b"MZ" and len(raw) == rec["pieces"][0]["size"] and got[0]["filename"].endswith(".exe")


def test_disguised_autoit_au3_is_decompiled_end_to_end(tmp_path: Path) -> None:
    """A compiled AutoIt blob called .au3 with junk in front: not painted as code; the blob is
    carved, decompiled (bundled AutoIt-Ripper when the portable Python has none) and its script
    analysed, down to the DLL and EXE in its hex string."""
    from docutracex import analyze, cases, findings
    data = ms.disguised_samples()["sample_disguised_autoit.au3"]
    m = cases.create_case(io.BytesIO(data), "loader.au3", cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    assert not (root / "results" / "script.json").exists()         # the bytes were not read as a script
    mods = {p.stem: json.loads(p.read_text()) for p in (root / "results").glob("*.json")}
    rules = {f["rule"] for f in findings.consolidate(mods)}
    assert {"disguised_binary", "script_shellcode_loader"} <= rules
    names: list[str] = []

    def walk(nodes):  # noqa: ANN001, ANN202
        for n in nodes:
            names.append(n["filename"])
            walk(n.get("children"))
    walk(mods["nested"]["tree"])
    assert any(n.endswith(".a3x") for n in names) and "script.au3" in names
    assert any(n.endswith(".dll") for n in names) and any(n.endswith(".exe") for n in names)
