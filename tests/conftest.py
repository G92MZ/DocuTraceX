"""Test session setup: unpack the samples (samples/samples.zip, password
"infected") next to it, so tests can open them by name. The unpacked copies are
git-ignored; they are refreshed whenever the archive is newer."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "samples" / "samples.zip"


def pytest_configure(config) -> None:  # noqa: ARG001
    if not ARCHIVE.is_file():
        return
    marker = ROOT / "samples" / "sample.docm"
    if marker.is_file() and marker.stat().st_mtime >= ARCHIVE.stat().st_mtime:
        return
    sys.path.insert(0, str(ROOT / "scripts"))
    import zipcrypto

    zipcrypto.extract(ARCHIVE, ROOT / "samples")
