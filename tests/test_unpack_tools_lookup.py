"""PE unpacker tools (UPX, 7-Zip, innoextract, DIE, nuitka-extractor) are found where an analyst box
already has them — DOCUTRACEX_* → tools/<tool>/ → PATH → Program Files / Chocolatey — not only in tools/."""

from __future__ import annotations

from pathlib import Path

import pytest

from docutracex.parsers import unpack

TOOLS = [  # (function, env var, tools/ subfolder, executable name, install subfolder)
    (unpack.upx_exe, "DOCUTRACEX_UPX", "upx", "upx.exe", "upx"),
    (unpack.sevenzip_exe, "DOCUTRACEX_7Z", "7zip", "7z.exe", "7-Zip"),
    (unpack.innoextract_exe, "DOCUTRACEX_INNOEXTRACT", "innoextract", "innoextract.exe", "innoextract"),
    (unpack.die_exe, "DOCUTRACEX_DIEC", "die", "diec.exe", "die"),
    (unpack.nuitka_exe, "DOCUTRACEX_NUITKA_EXTRACTOR", "nuitka-extractor", "nuitka-extractor.exe",
     "nuitka-extractor"),
]


@pytest.fixture()
def box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty machine: no tools/, nothing on the PATH, no install folders."""
    monkeypatch.setattr(unpack, "_tools_dir", lambda: tmp_path / "tools")
    monkeypatch.setattr(unpack.shutil, "which", lambda n: None)
    monkeypatch.setattr(unpack, "_install_dirs", lambda: [tmp_path / "pf", tmp_path / "choco"])
    for _, env, *_ in TOOLS:
        monkeypatch.delenv(env, raising=False)
    return tmp_path


def _touch(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")
    return p


@pytest.mark.parametrize("fn, env, sub, exe, inst", TOOLS)
def test_lookup_order(box: Path, monkeypatch: pytest.MonkeyPatch, fn, env, sub, exe, inst) -> None:  # noqa: ANN001
    assert fn() is None                                          # nothing anywhere
    installed = _touch(box / "pf" / inst / exe)
    assert fn() == installed                                     # Program Files\<tool>\
    shim = box / "choco" / exe
    monkeypatch.setattr(unpack.shutil, "which", lambda n: str(shim) if n == exe else None)
    assert fn() == shim                                          # on the PATH (Chocolatey shim)
    bundled = _touch(box / "tools" / sub / exe)
    assert fn() == bundled                                       # tools/<tool>/ wins over the system
    pinned = _touch(box / "pinned" / exe)
    monkeypatch.setenv(env, str(pinned))
    assert fn() == pinned                                        # the variable wins over everything


def test_upx_not_found_message_says_where(box: Path, tmp_path: Path) -> None:
    res = unpack._unpack_upx(tmp_path / "x.exe", tmp_path / "out")
    assert res["status"] == "not_provisioned"
    assert "PATH" in res["detail"] and "DOCUTRACEX_UPX" in res["detail"]
