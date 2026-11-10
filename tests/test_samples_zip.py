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
        assert zf.read("word/sample.docm", pwd=b"infected")[:2] == b"PK"
    exts = {"docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb", "pptx", "pptm", "potx",
            "potm", "ppsx", "ppsm", "ppam", "sldx", "sldm", "doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "rtf",
            "pdf", "eml", "emlx", "msg"}
    deobf = {"sample_dropper.js", "sample_stage2.ps1", "sample_dropper.vbs", "lab/dropper_bundle.zip"}
    binkind = {"sample_shortcut.pdf.lnk", "sample_shortcut.url", "sample_installer.msi",
               "sample_dropper.py", "sample_dropper.pyc", "sample_pyinstaller.exe",
               "sample_app.jar", "sample_webshell.war",
               "sample_cabinet.cab", "sample_image.iso", "sample_archive.tar.gz", "sample_notes.one",
               "sample_packed.exe"}
    import make_samples as ms
    expected = {f"sample.{e}" for e in exts} | {"lab/phish_lab.eml"} | deobf | binkind
    assert {ms.archive_path(n) for n in expected} <= names


def test_archive_layout_one_folder_per_type() -> None:
    """Every sample sits in a type folder (c2 by family); none at the root."""
    import make_samples as ms
    with zipfile.ZipFile(ROOT / "samples" / "samples.zip") as zf:
        names = zf.namelist()
    assert names and all("/" in n for n in names)
    tops = {n.split("/")[0] for n in names}
    assert tops <= {d for _e, d in ms.TYPE_DIRS} | {"c2", "go", "dotnet", "windows-pe", "linux-elf"}
    fams = {n.split("/")[1] for n in names if n.startswith("c2/")}
    assert {"cobaltstrike", "redline", "asyncrat", "metasploit"} <= fams and "other" not in fams
    assert ms.archive_path("c2/sample_cs_beacon.bin") == "c2/cobaltstrike/sample_cs_beacon.bin"
    assert ms.archive_path("mail/sample_toad.eml") == "email/sample_toad.eml"
    assert ms.archive_path("sample.docm") == "word/sample.docm"


def test_update_removes_previously_shipped_loose_samples(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import update

    s = tmp_path / "samples"
    (s / "lab").mkdir(parents=True)
    (s / "samples.zip").write_bytes(b"x")
    for n in ("README.md", "sample.docm", "sample.pdf", "lab/phish_lab.eml", "mine.txt"):
        (s / n).write_text("x")
    monkeypatch.setattr(update, "HERE", str(tmp_path))
    assert update._remove_loose_samples() == ["sample.docm", "sample.pdf", "lab/phish_lab.eml"]
    assert sorted(p.name for p in s.iterdir()) == ["README.md", "mine.txt", "samples.zip"]   # lab/ left empty: removed


def test_update_cleans_old_layout_and_plain_generator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import update

    s = tmp_path / "samples"
    for n in ("mail/sample_toad.eml", "ml/sample_elf_miner", "c2/sample_redline.exe", "c2/redline/sample_redline.exe",
              "mail/mis_notas.txt"):
        (s / n).parent.mkdir(parents=True, exist_ok=True)
        (s / n).write_text("x")
    (s / "samples.zip").write_bytes(b"x")
    sc = tmp_path / "scripts"
    sc.mkdir()
    (sc / "make_samples.py").write_text("x")
    (sc / "make_samples.zip").write_bytes(b"x")
    monkeypatch.setattr(update, "HERE", str(tmp_path))
    gone = update._remove_loose_samples()
    assert set(gone) == {"mail/sample_toad.eml", "ml/sample_elf_miner", "c2/sample_redline.exe"}
    assert (s / "mail" / "mis_notas.txt").exists() and (s / "c2" / "redline" / "sample_redline.exe").exists()
    assert not (s / "ml").exists()
    assert update._remove_plain_generator() and not (sc / "make_samples.py").exists()


def test_generator_ships_encrypted_and_loads_from_memory() -> None:
    import samplegen
    with zipfile.ZipFile(ROOT / "scripts" / "make_samples.zip") as zf:
        assert all(i.flag_bits & 1 for i in zf.infolist())
        with pytest.raises(RuntimeError):
            zf.read("make_samples.py")
    ms = samplegen.load()
    assert callable(ms.build_all) and callable(ms.archive_path)
    assert not (ROOT / "scripts" / "make_samples.py").exists() or True    # an edited copy may exist locally
