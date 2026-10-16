"""Application configuration — all paths resolved relative to the app root.

No absolute, machine-specific paths. The app root is the repository/distribution
root (the parent of the ``docutracex`` package). ``tools/`` and ``cases/`` hang
off it, matching the portable layout described in the README.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# <app_root>/docutracex/config.py  ->  <app_root>
APP_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    """Runtime settings. Paths are relative to APP_ROOT unless overridden by env."""

    app_root: Path = APP_ROOT
    tools_dir: Path = APP_ROOT / "tools"
    cases_dir: Path = APP_ROOT / "cases"
    # Uploaded/registered YARA rules + config.
    yara_dir: Path = Path(os.environ.get("DOCUTRACEX_YARA_DIR") or APP_ROOT / "yara")
    # gmzpt
    host: str = os.environ.get("DOCUTRACEX_HOST", "127.0.0.1")
    port: int = int(os.environ.get("DOCUTRACEX_PORT", "8000"))
    log_level: str = os.environ.get("DOCUTRACEX_LOG_LEVEL", "INFO")

    def ensure_dirs(self) -> None:
        """Create the writable working directories if they do not exist yet."""
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.yara_dir.mkdir(parents=True, exist_ok=True)

    def portable_python(self) -> Path | None:
        """Locate the bundled portable Python interpreter under ``tools/``.

        Order: the ``DOCUTRACEX_PYTHON`` env var (explicit path), then common
        layouts under ``tools/python/``. Returns None if none is bundled (the
        app then falls back to the current interpreter). The exact portable
        layout is decided in the runtime phase; discovery is deliberately loose.
        """
        env = os.environ.get("DOCUTRACEX_PYTHON")
        if env and Path(env).is_file():
            return Path(env)
        base = self.tools_dir / "python"
        candidates = [
            base / "python.exe",
            base / "python3.exe",
            base / "bin" / "python3",
            base / "bin" / "python",
            base / "python",
            base / "python3",
        ]
        for c in candidates:
            if c.is_file():
                return c
        for pattern in ("python*/python.exe", "python*/bin/python3", "python*/bin/python"):
            for p in sorted(self.tools_dir.glob(pattern)):
                if p.is_file():
                    return p
        return None

    def pypy_python(self) -> Path | None:
        """The PyPy 2.7 interpreter under ``tools/pypy/`` (only for ViperMonkey,
        whose code is Python 2). ``DOCUTRACEX_PYPY`` overrides the location."""
        env = os.environ.get("DOCUTRACEX_PYPY")
        if env and Path(env).is_file():
            return Path(env)
        base = self.tools_dir / "pypy"
        for c in (base / "pypy.exe", base / "bin" / "pypy", base / "bin" / "pypy2"):
            if c.is_file():
                return c
        return None


settings = Settings()
