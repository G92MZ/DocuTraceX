"""Native library wiring (bundled under tools/).

Currently: the native libmagic used by python-magic on Windows. The DLL and its
compiled magic database live under ``tools/libmagic/`` (provisioned by
scripts/setup_portable_python.py). Before importing ``magic`` we add that folder
to the DLL search path and point ``MAGIC`` at the database, so the bundled
libmagic is found without any system install.

On Linux/macOS this is a no-op: libmagic comes from the system package.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .config import settings
from .logging_config import get_logger

log = get_logger(__name__)

_setup_done = False


def libmagic_dir() -> Path | None:
    """Return tools/libmagic if it contains the bundled DLL, else None."""
    d = settings.tools_dir / "libmagic"
    if (d / "libmagic.dll").is_file() or (d / "magic1.dll").is_file():
        return d
    return None


def magic_db() -> Path | None:
    d = settings.tools_dir / "libmagic"
    mgc = d / "magic.mgc"
    return mgc if mgc.is_file() else None


def setup_libmagic() -> None:
    """Make the bundled libmagic discoverable before ``import magic``. Idempotent."""
    global _setup_done
    if _setup_done:
        return
    _setup_done = True

    mgc = magic_db()
    if mgc and not os.environ.get("MAGIC"):
        os.environ["MAGIC"] = str(mgc)

    if sys.platform.startswith("win"):
        d = libmagic_dir()
        if d:
            try:
                os.add_dll_directory(str(d))  # Python 3.8+ on Windows
            except (OSError, AttributeError):
                pass
            # Also prepend to PATH as a fallback for ctypes lookup.
            os.environ["PATH"] = str(d) + os.pathsep + os.environ.get("PATH", "")
            log.info("Bundled libmagic wired from %s", d)


def subprocess_env() -> dict[str, str]:
    """Environment for a child interpreter so it, too, finds bundled libmagic."""
    env = dict(os.environ)
    mgc = magic_db()
    if mgc:
        env.setdefault("MAGIC", str(mgc))
    d = libmagic_dir()
    if d and sys.platform.startswith("win"):
        env["PATH"] = str(d) + os.pathsep + env.get("PATH", "")
    return env
