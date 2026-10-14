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


@dataclass(frozen=True)
class Settings:
    """Runtime settings. Paths are relative to APP_ROOT unless overridden by env."""

    app_root: Path = APP_ROOT
    tools_dir: Path = APP_ROOT / "tools"
    cases_dir: Path = APP_ROOT / "cases"
    host: str = os.environ.get("DOCUTRACEX_HOST", "127.0.0.1")
    port: int = int(os.environ.get("DOCUTRACEX_PORT", "8000"))
    log_level: str = os.environ.get("DOCUTRACEX_LOG_LEVEL", "INFO")

    def ensure_dirs(self) -> None:
        """Create the writable working directories if they do not exist yet."""
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self.tools_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
