"""The samples ship encrypted (ZipCrypto, password "infected") so scanners skip them."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import zipcrypto  # noqa: E402


def test_round_trip_and_password(tmp_path: Path) -> None:
    files = {"a.txt": b"hola" * 500, "lab/b.bin": bytes(range(256)) * 40}
    z = tmp_path / "s.zip"
    zipcrypto.write(z, files)
    with zipfile.ZipFile(z) as zf:
        assert all(i.flag_bits & 1 for i in zf.infolist())  # every member encrypted
        with pytest.raises(RuntimeError):
            zf.read("a.txt")
        with pytest.raises(RuntimeError):
            zf.read("a.txt", pwd=b"wrong")
    out = zipcrypto.extract(z, tmp_path / "x")
    assert {p.relative_to(tmp_path / "x").as_posix() for p in out} == set(files)
    assert (tmp_path / "x" / "lab" / "b.bin").read_bytes() == files["lab/b.bin"]


# gmzpt
def test_shipped_archive_has_every_sample_encrypted() -> None:
    archive = ROOT / "samples" / "samples.zip"
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        assert all(i.flag_bits & 1 for i in zf.infolist())
        assert zf.read("sample.docm", pwd=b"infected")[:2] == b"PK"
    exts = {"docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb", "pptx", "pptm", "potx",
            "potm", "ppsx", "ppsm", "ppam", "sldx", "sldm", "doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "rtf",
            "pdf", "eml", "emlx", "msg"}
    deobf = {"sample_dropper.js", "sample_stage2.ps1", "sample_dropper.vbs", "lab/dropper_bundle.zip"}
    binkind = {"sample_shortcut.pdf.lnk", "sample_shortcut.url", "sample_installer.msi",
               "sample_dropper.py", "sample_dropper.pyc", "sample_pyinstaller.exe",
               "sample_app.jar", "sample_webshell.war"}
    assert {f"sample.{e}" for e in exts} | {"lab/phish_lab.eml"} | deobf | binkind <= names


def test_update_removes_previously_shipped_loose_samples(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import update

    s = tmp_path / "samples"
    (s / "lab").mkdir(parents=True)
    (s / "samples.zip").write_bytes(b"x")
    for n in ("README.md", "sample.docm", "sample.pdf", "lab/phish_lab.eml", "mine.txt"):
        (s / n).write_text("x")
    monkeypatch.setattr(update, "HERE", str(tmp_path))
    assert update._remove_loose_samples() == ["sample.docm", "sample.pdf", "lab/phish_lab.eml"]
    assert sorted(p.name for p in s.iterdir()) == ["README.md", "lab", "mine.txt", "samples.zip"]
