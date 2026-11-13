"""Test session setup: unpack the samples (samples/samples.zip, password
"infected") next to it, so tests can open them by name. The unpacked copies are
git-ignored; they are refreshed whenever the archive is newer."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Tests check behaviour, not limits: run the analysis time limits unscaled (the
# app's default factor is 5), so a test with an endless-loop script stays fast.
os.environ.setdefault("DOCUTRACEX_TIMEOUT_FACTOR", "1")
# Most tests exercise YARA / ML / C2 through a full analysis: keep them automatic
# there (in the app they are on demand; test_ondemand_modules covers that).
os.environ.setdefault("DOCUTRACEX_AUTO_MODULES", "yara,ml,c2")
# The API is behind a sign-in: tests call it directly (test_auth turns this off to
# exercise the real gate). Only honoured while pytest is loaded.
os.environ.setdefault("DOCUTRACEX_TEST_NO_AUTH", "1")

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "samples" / "samples.zip"

# The sample generator ships encrypted (scripts/make_samples.zip): load it in
# memory once, so the tests' ``import make_samples`` finds it.
sys.path.insert(0, str(ROOT / "scripts"))
import samplegen  # noqa: E402

samplegen.load()


def pytest_configure(config) -> None:  # noqa: ARG001
    if not ARCHIVE.is_file():
        # gmzpt
        return
    marker = ROOT / "samples" / "word/sample.docm"
    if marker.is_file() and marker.stat().st_mtime >= ARCHIVE.stat().st_mtime:
        return
    sys.path.insert(0, str(ROOT / "scripts"))
    import zipcrypto

    zipcrypto.extract(ARCHIVE, ROOT / "samples")
