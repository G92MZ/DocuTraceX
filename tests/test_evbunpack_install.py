"""evbunpack left PyPI: the installer falls back to its pinned GitHub source."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import setup_portable_python as spp  # noqa: E402


def test_falls_back_to_the_pinned_source(monkeypatch) -> None:  # noqa: ANN001
    installed: list[str] = []
    calls: list[list[str]] = []

    class R:
        def __init__(self, rc: int, err: str = "") -> None:
            self.returncode, self.stderr, self.stdout = rc, err, ""

    def run(cmd, **kw):  # noqa: ANN001, ANN003, ANN202
        calls.append(cmd)
        if cmd[-1] == "evbunpack":                       # the index has no such package
            return R(1, "ERROR: No matching distribution found for evbunpack")
        installed.append("evbunpack")
        return R(0)
    monkeypatch.setattr(spp.subprocess, "run", run)
    monkeypatch.setattr(spp, "_portable_present", lambda: True)
    monkeypatch.setattr(spp, "_portable_python", lambda: Path("python"))
    monkeypatch.setattr(spp, "_portable_import_ok", lambda m: bool(installed))
    assert spp.install_evbunpack() is True
    assert calls[0][-1] == "evbunpack" and calls[1][-1] == spp.EVBUNPACK_SRC
    assert spp.EVBUNPACK_SRC.startswith("evbunpack @ https://github.com/mos9527/evbunpack/archive/")


def test_installed_already_does_nothing(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(spp, "_portable_import_ok", lambda m: True)
    monkeypatch.setattr(spp.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran pip")))
    assert spp.install_evbunpack() is True
