"""C2: protected objects (KoiVM, Themida…) are named, with why there is no configuration."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

import make_samples as ms

from docutracex.c2 import protection


def test_markers() -> None:
    got = protection.detect(ms.protected_koivm_exe())
    assert [p["name"] for p in got] == ["KoiVM"] and got[0]["kind"] == "virtualizer"
    assert "cannot be read statically" in protection.note(got)
    themida = b"MZ" + b"\x00" * 300 + b".taggant\x00" + b"\x00" * 100
    assert protection.detect(themida)[0]["name"] == "Themida / WinLicense"
    assert protection.detect(ms.njrat_exe()) == []                       # an ordinary client: nothing


def test_die_protector_added() -> None:
    got = protection.detect(b"MZ" + b"\x00" * 64, [{"type": "protector", "name": ".NET Reactor",
                                                    "string": "Protector: .NET Reactor(6.X)"}])
    assert got == [{"name": ".NET Reactor", "kind": "protector", "evidence": "Detect It Easy: Protector: .NET Reactor(6.X)"}]
    assert protection.detect(b"MZ", [{"type": "compiler", "name": "VB.NET"}]) == []


def test_c2_tab_says_protected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases, mdreport
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    monkeypatch.setenv("DOCUTRACEX_AUTO_MODULES", "c2")
    m = cases.create_case(io.BytesIO(ms.protected_koivm_exe()), "factura.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    c2 = read_json(CasePaths(m["analysis_id"], cases_dir=tmp_path).subresult("c2")) or {}
    assert c2.get("protected") and c2["protected"][0]["protectors"][0]["name"] == "KoiVM"
    md = {s["id"]: s["markdown"] for s in mdreport.build(m["analysis_id"])}
    assert "**protected**" in md["c2"] and "KoiVM" in md["c2"]


def test_packers_without_static_unpacker() -> None:
    mpress = b"MZ" + b"\x00" * 200 + b".MPRESS1" + b"\x00" * 32 + b".MPRESS2" + b"\x00" * 64
    got = protection.detect(mpress)
    assert got[0]["name"] == "MPRESS" and got[0]["kind"] == "packer"
    assert "compressed by a packer" in protection.note(got)
    # a section name deep in the data (not in the header) is not a packer
    assert protection.detect(b"MZ" + b"\x00" * 8000 + b".MPRESS1") == []
