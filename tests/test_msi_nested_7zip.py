"""MSI extraction through 7-Zip and extensionless nested content detection."""
from __future__ import annotations

from pathlib import Path

from docutracex import nested, unlock
from docutracex.parsers import msi


def test_msi_extraction_uses_7zip_and_keeps_all_components(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "sample.msi"
    source.write_bytes(b"not parsed here")
    out = tmp_path / "out"
    calls = []

    def fake_7z(args, timeout=300):
        calls.append(args)
        if args[0] == "l":
            return {"rc": 0, "out": (
                "Listing archive: sample.msi\n\n----------\n"
                "Path = app.exe\nSize = 90\nFolder = -\n\n"
                "Path = docs/readme.doc\nSize = 80\nFolder = -\n\n"
                "Path = component_03\nSize = 70\nFolder = -\n"
            ), "err": ""}
        target = Path(next(a[2:] for a in args if a.startswith("-o")))
        (target / "docs").mkdir(parents=True)
        (target / "app.exe").write_bytes(b"MZ" + b"A" * 88)
        (target / "docs" / "readme.doc").write_bytes(b"D" * 80)
        (target / "component_03").write_bytes(b"X" * 70)
        return {"rc": 0, "out": "", "err": ""}

    monkeypatch.setattr(unlock, "_7z_run", fake_7z)
    rec = unlock.extract_msi(source, out)

    assert rec["extracted"] is True
    assert rec["listed_files"] == 3
    assert len([e for e in rec["entries"] if e.get("file")]) == 3
    assert len(calls) == 2
    assert calls[0][0] == "l" and calls[1][0] == "x"
    assert all(Path(e["file"]).is_file() for e in rec["entries"] if e.get("file"))


def test_msi_without_7zip_returns_explicit_warning(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "sample.msi"
    source.write_bytes(b"x")

    def missing(*args, **kwargs):
        raise unlock.SevenZipMissing()

    monkeypatch.setattr(unlock, "_7z_run", missing)
    rec = unlock.extract_msi(source, tmp_path / "out")
    assert rec["error"]
    assert any(f["rule"] == "msi_not_extracted" for f in rec["findings"])


def test_nested_content_sniffing_without_extensions(tmp_path: Path) -> None:
    pdf = tmp_path / "pdf_payload"
    pdf.write_bytes(b"%PDF-1.7\n")
    assert nested._kind(pdf, pdf.name) == "pdf"

    cab = tmp_path / "cab_payload"
    cab.write_bytes(b"MSCF" + b"\x00" * 32)
    assert nested._kind(cab, cab.name) == "archive"

    pyc = tmp_path / "bytecode_payload"
    pyc.write_bytes(b"\xcb\r\r\n" + b"\x00" * 12 + b"marshal-placeholder")
    assert nested._kind(pyc, pyc.name) == "python"

    pe = tmp_path / "pe_payload"
    pe.write_bytes(b"MZ" + b"\x00" * 80)
    assert nested._kind(pe, pe.name) == "binary"


def test_extensionless_msi_detection_routes_to_msi_parser(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "msi_component"
    source.write_bytes(b"compound-file")
    monkeypatch.setattr(msi, "is_msi_file", lambda p: True)
    monkeypatch.setattr(msi, "analyze_msi", lambda p, rel: {"kind": "msi", "file": rel, "findings": []})
    monkeypatch.setattr(unlock, "extract_msi", lambda *a, **k: {
        "kind": "msi", "entries": [], "findings": [], "extracted": True, "error": None
    })
    item = msi.analyze_binary(source, source.name, tmp_path / "out")
    assert item["kind"] == "msi"
