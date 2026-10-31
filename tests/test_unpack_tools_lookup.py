"""PE unpacker binaries must be resolved exclusively from tools/."""
from pathlib import Path

import pytest

from docutracex.parsers import unpack

TOOLS = [
    (unpack.upx_exe, "DOCUTRACEX_UPX", "upx", "upx.exe"),
    (unpack.sevenzip_exe, "DOCUTRACEX_7Z", "7zip", "7z.exe"),
    (unpack.innoextract_exe, "DOCUTRACEX_INNOEXTRACT", "innoextract", "innoextract.exe"),
    (unpack.die_exe, "DOCUTRACEX_DIEC", "die", "diec.exe"),
    (unpack.nuitka_exe, "DOCUTRACEX_NUITKA_EXTRACTOR", "nuitka-extractor", "nuitka-extractor.exe"),
]

@pytest.fixture()
def box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(unpack, "_tools_dir", lambda: tmp_path / "tools")
    monkeypatch.setattr(unpack.shutil, "which", lambda n: None)
    monkeypatch.setattr(unpack, "_install_dirs", lambda: [tmp_path / "pf"])
    for _, env, *_ in TOOLS:
        monkeypatch.delenv(env, raising=False)
    return tmp_path

def _touch(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")
    return p

@pytest.mark.parametrize("fn, env, sub, exe", TOOLS)
def test_lookup_only_uses_tools_folder(box: Path, monkeypatch: pytest.MonkeyPatch, fn, env, sub, exe):
    assert fn() is None
    # System installation, PATH and environment override are deliberately ignored.
    _touch(box / "pf" / exe)
    shim = _touch(box / "shim" / exe)
    monkeypatch.setattr(unpack.shutil, "which", lambda n: str(shim))
    pinned = _touch(box / "pinned" / exe)
    monkeypatch.setenv(env, str(pinned))
    assert fn() is None
    bundled = _touch(box / "tools" / sub / exe)
    assert fn() == bundled

def test_upx_not_found_message_says_where(box: Path, tmp_path: Path) -> None:
    res = unpack._unpack_upx(tmp_path / "x.exe", tmp_path / "out")
    assert res["status"] == "not_provisioned"
    assert "tools/upx" in res["detail"]
