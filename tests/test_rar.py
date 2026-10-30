"""RAR archives: detection, extraction through the 7-Zip CLI (bounded, passwords) and the recursive
pipeline (an .exe inside a .rar inside an email reaches Nested).

7-Zip is replaced by a fake ``7z`` script that answers ``l -slt`` and ``x`` like the real one from a
JSON manifest written next to the "RAR" — so the flow is tested without 7-Zip or a RAR writer. The
real decompression is covered by ``test_real_7zip_rar`` when 7-Zip and a fixture are available.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from docutracex import nested, unlock
from docutracex.identify import classify_discrepancy  # noqa: F401  (import check: identify loads)
from docutracex.parsers import unpack

RAR5 = b"Rar!\x1a\x07\x01\x00"
RAR4 = b"Rar!\x1a\x07\x00"

# Fake 7z: the "archive" is the RAR signature + a JSON manifest {password, entries: {name: text}}.
FAKE_7Z = r'''
import json, os, sys
args = sys.argv[1:]
cmd, path = args[0], args[-1]
pw = next((a[2:] for a in args if a.startswith("-p")), "-")
raw = open(path, "rb").read()
man = json.loads(raw[raw.index(b"{"):].decode())
need = man.get("password")
hdr_enc = man.get("headers_encrypted", False)
wrong = need is not None and pw != need
if cmd == "l":
    if wrong and (hdr_enc or pw != "-"):
        sys.stderr.write("ERROR: Wrong password : " + path + "\n"); sys.exit(2)
    print("Listing archive: " + path + "\n--\nPath = " + path + "\nType = Rar5\n\n----------")
    for name, text in man["entries"].items():
        print("Path = " + name + "\nFolder = -\nSize = " + str(man.get("sizes", {}).get(name, len(text)))
              + "\nEncrypted = " + ("+" if need else "-") + "\nAttributes = A\n")
    sys.exit(0)
if cmd == "x":
    if wrong:
        sys.stderr.write("ERROR: Wrong password : " + path + "\n"); sys.exit(2)
    out = next(a[2:] for a in args if a.startswith("-o"))
    for name, text in man["entries"].items():
        p = os.path.join(out, *name.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
    sys.exit(0)
sys.exit(7)
'''


@pytest.fixture()
def fake_7z(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Route unlock's 7z calls to ``python fake7z.py`` (through the real run_bounded), so the test
    needs no executable shim (works on Windows and on noexec temp folders)."""
    from docutracex import proctools

    script = tmp_path / "fake7z.py"
    script.write_text(FAKE_7Z)
    marker = tmp_path / "7z.exe"
    marker.write_text("")
    monkeypatch.setattr(unpack, "sevenzip_exe", lambda: marker)
    real = proctools.run_bounded

    def run(cmd, timeout, cwd=None, env=None):  # noqa: ANN001
        if cmd and cmd[0] == str(marker):
            cmd = [sys.executable, str(script), *cmd[1:]]
        return real(cmd, timeout, cwd=cwd, env=env)

    monkeypatch.setattr(proctools, "run_bounded", run)
    return marker


def _rar(tmp_path: Path, entries: dict[str, str], *, name: str = "pago.rar", magic: bytes = RAR5,
         password: str | None = None, headers_encrypted: bool = False, sizes: dict | None = None) -> Path:
    p = tmp_path / name
    man = {"entries": entries, "password": password, "headers_encrypted": headers_encrypted,
           "sizes": sizes or {}}
    p.write_bytes(magic + b"\x00" * 8 + json.dumps(man).encode())
    return p


# --- detection ---------------------------------------------------------------------------------

@pytest.mark.parametrize("magic", [RAR4, RAR5])
def test_detect_rar(tmp_path: Path, fake_7z: Path, magic: bytes) -> None:
    det = unlock.detect(_rar(tmp_path, {"a.exe": "MZ"}, magic=magic))
    assert det["kind"] == "rar" and not det["encrypted"]
    assert det["detail"].startswith("RAR5" if magic == RAR5 else "RAR4")


def test_detect_encrypted_rar(tmp_path: Path, fake_7z: Path) -> None:
    assert unlock.detect(_rar(tmp_path, {"a.exe": "MZ"}, password="infected"))["encrypted"]
    det = unlock.detect(_rar(tmp_path, {"a.exe": "MZ"}, name="h.rar", password="x", headers_encrypted=True))
    assert det["encrypted"] and "encrypted headers" in det["detail"]


def test_nested_kind_by_magic_and_extension(tmp_path: Path) -> None:
    p = tmp_path / "attachment.bin"
    p.write_bytes(RAR5 + b"\x00" * 8)
    assert nested._kind(p, "attachment.bin") == "archive"
    q = tmp_path / "x.rar"
    q.write_bytes(b"not really")
    assert nested._kind(q, "x.rar") == "archive"


# --- extraction ---------------------------------------------------------------------------------

def test_extract_rar(tmp_path: Path, fake_7z: Path) -> None:
    rar = _rar(tmp_path, {"Statement of Account.exe": "MZ fake", "docs/readme.txt": "hi"})
    rec = unlock.extract_archive(rar, tmp_path / "out", unlock.candidates(kind="archive"))
    assert rec["kind"] == "rar" and not rec.get("error")
    names = sorted(e["name"] for e in rec["entries"])
    assert names == ["Statement of Account.exe", "docs/readme.txt"]
    exe = next(e for e in rec["entries"] if e["name"].endswith(".exe"))
    assert Path(exe["file"]).read_text() == "MZ fake"


def test_rar_password_default_and_email(tmp_path: Path, fake_7z: Path) -> None:
    rar = _rar(tmp_path, {"a.exe": "MZ"}, password="infected")
    rec = unlock.extract_archive(rar, tmp_path / "o1", unlock.candidates(kind="archive"))
    assert rec["decrypted"] and rec["password"] == "infected"
    assert rec["findings"][0]["rule"] == "encrypted_archive_default"
    assert "RAR archive" in rec["findings"][0]["detail"]

    rar2 = _rar(tmp_path, {"a.exe": "MZ"}, name="b.rar", password="Fact2026")
    tries = unlock.candidates(harvested=[{"password": "Fact2026", "context": "body"}], kind="archive")
    rec = unlock.extract_archive(rar2, tmp_path / "o2", tries)
    assert rec["decrypted"] and rec["password_source"] == "email"


def test_rar_unknown_password(tmp_path: Path, fake_7z: Path) -> None:
    rar = _rar(tmp_path, {"a.exe": "MZ"}, password="nope-not-known")
    rec = unlock.extract_archive(rar, tmp_path / "o", unlock.candidates(kind="archive"))
    assert not rec["decrypted"] and not rec["entries"]
    f = rec["findings"][-1]
    assert f["rule"] == "encrypted_archive" and f["detail"].startswith("RAR archive")


def test_rar_bounds(tmp_path: Path, fake_7z: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    many = {f"f{i}.txt": "x" for i in range(unlock.MAX_ENTRIES + 1)}
    rec = unlock.extract_archive(_rar(tmp_path, many), tmp_path / "o1", [])
    assert "too many" in rec["error"] and rec["findings"][0]["rule"] == "archive_bomb"
    big = _rar(tmp_path, {"a.bin": "x"}, name="big.rar", sizes={"a.bin": unlock.MAX_TOTAL + 1})
    rec = unlock.extract_archive(big, tmp_path / "o2", [])
    assert "size limit" in rec["error"]
    assert not (tmp_path / "o2").exists()                       # nothing extracted


def test_rar_without_7zip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(unpack, "sevenzip_exe", lambda: None)
    rar = _rar(tmp_path, {"a.exe": "MZ"})
    assert "7-Zip not found" in unlock.detect(rar)["detail"]
    rec = unlock.extract_archive(rar, tmp_path / "o", [])
    assert "7-Zip" in rec["error"] and rec["findings"][0]["rule"] == "archive_not_extracted"


def test_sevenzip_lookup_prefers_tools_then_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOCUTRACEX_7Z", raising=False)
    monkeypatch.setattr(unpack, "_tools_dir", lambda: tmp_path / "tools")
    exe = tmp_path / "bin" / "7z"
    monkeypatch.setattr(unpack.shutil, "which", lambda n: str(exe) if n == "7z" else None)
    assert unpack.sevenzip_exe() == exe                         # found on the PATH
    monkeypatch.setattr(unpack.shutil, "which", lambda n: None)
    pf = tmp_path / "pf"
    (pf / "7-Zip").mkdir(parents=True)
    (pf / "7-Zip" / "7z.exe").write_text("")
    monkeypatch.setenv("ProgramFiles", str(pf))
    assert unpack.sevenzip_exe() == pf / "7-Zip" / "7z.exe"     # FLARE-VM: C:\Program Files\7-Zip
    (tmp_path / "tools" / "7zip").mkdir(parents=True)
    bundled = tmp_path / "tools" / "7zip" / "7z.exe"
    bundled.write_text("")
    assert unpack.sevenzip_exe() == bundled                     # tools/7zip/ wins


# --- recursive pipeline: an .exe inside a .rar reaches Nested ----------------------------------

def test_nested_scan_extracts_rar_children(tmp_path: Path, fake_7z: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex.config import settings
    from docutracex.storage import CasePaths

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases" / "c1").mkdir(parents=True)
    paths = CasePaths("c1")
    paths.extracted_dir.mkdir(parents=True, exist_ok=True)
    rar = _rar(paths.extracted_dir, {"Statement of Account.exe": "MZ\x90\x00 fake"}, name="pago.rar")
    res = nested.scan_children([{"path": str(rar), "filename": "pago.rar"}], paths)
    tree = res["tree"]
    assert tree and tree[0]["kind"] == "archive"
    kids = tree[0].get("children") or []
    assert [k["filename"] for k in kids] == ["Statement of Account.exe"]
    assert kids[0]["kind"] == "binary"


# --- the real thing (FLARE-VM / any box with 7-Zip and a RAR fixture) ---------------------------

@pytest.mark.skipif(not (os.environ.get("DOCUTRACEX_TEST_RAR") and unpack.sevenzip_exe()),
                    reason="set DOCUTRACEX_TEST_RAR to a real .rar (and have 7-Zip) to run")
def test_real_7zip_rar(tmp_path: Path) -> None:
    src = Path(os.environ["DOCUTRACEX_TEST_RAR"])
    rar = tmp_path / src.name
    shutil.copy(src, rar)                                       # never touch the evidence copy
    det = unlock.detect(rar)
    assert det["kind"] == "rar"
    rec = unlock.extract_archive(rar, tmp_path / "out", unlock.candidates(kind="archive"))
    assert rec["entries"] and all(Path(e["file"]).is_file() for e in rec["entries"] if e.get("file"))
