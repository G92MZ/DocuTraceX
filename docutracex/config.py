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

    def node_executable(self) -> Path | None:
        """Portable Node.js under ``tools/node/`` (for webcrack — JS
        deobfuscation). ``DOCUTRACEX_NODE`` overrides the location; a Node on
        PATH is a last resort (handled by the caller, not here)."""
        env = os.environ.get("DOCUTRACEX_NODE")
        if env and Path(env).is_file():
            return Path(env)
        base = self.tools_dir / "node"
        for c in (base / "node.exe", base / "bin" / "node", base / "node"):
            if c.is_file():
                return c
        for pattern in ("node*/bin/node", "node*/node.exe"):
            for p in sorted(base.glob(pattern)) + sorted(self.tools_dir.glob(pattern)):
                if p.is_file():
                    return p
        return None

    def webcrack_dir(self) -> Path | None:
        """The webcrack install under ``tools/webcrack/`` (its node_modules).
        ``DOCUTRACEX_WEBCRACK`` overrides the location."""
        env = os.environ.get("DOCUTRACEX_WEBCRACK")
        base = Path(env) if env else self.tools_dir / "webcrack"
        return base if (base / "node_modules" / "webcrack").is_dir() else None

    def pwsh_executable(self) -> Path | None:
        """Portable PowerShell Core under ``tools/pwsh/`` (for the box-ps
        PowerShell sandbox). ``DOCUTRACEX_PWSH`` overrides the location."""
        env = os.environ.get("DOCUTRACEX_PWSH")
        if env and Path(env).is_file():
            return Path(env)
        base = self.tools_dir / "pwsh"
        for c in (base / "pwsh.exe", base / "pwsh", base / "bin" / "pwsh"):
            if c.is_file():
                return c
        return None

    def boxps_script(self) -> Path | None:
        """box-ps entry script under ``tools/boxps/`` (GPL-3.0, provisioned at
        setup, never shipped). ``DOCUTRACEX_BOXPS`` overrides the location."""
        env = os.environ.get("DOCUTRACEX_BOXPS")
        base = Path(env) if env else self.tools_dir / "boxps"
        for c in (base / "box-ps.ps1", base / "BoxPS.ps1"):
            if c.is_file():
                return c
        return None

    def pycdc_executable(self) -> Path | None:
        """Portable pycdc (Decompyle++) under ``tools/pycdc/`` — optional .pyc
        decompiler (MIT, built from source at setup). ``DOCUTRACEX_PYCDC``
        overrides the location. Absent → the Python engine falls back to
        bytecode disassembly + string mining."""
        env = os.environ.get("DOCUTRACEX_PYCDC")
        if env and Path(env).is_file():
            return Path(env)
        base = self.tools_dir / "pycdc"
        for c in (base / "pycdc.exe", base / "pycdc", base / "bin" / "pycdc",
                  base / "build" / "pycdc"):
            if c.is_file():
                return c
        return None

    def java_executable(self) -> Path | None:
        """A JVM to run CFR with: a portable one under ``tools/jre/`` if present,
        else ``JAVA_HOME``/``java`` or ``java`` on PATH. ``DOCUTRACEX_JAVA``
        overrides. Used only by the optional Java decompiler."""
        import shutil

        env = os.environ.get("DOCUTRACEX_JAVA")
        if env and Path(env).is_file():
            return Path(env)
        for c in (self.tools_dir / "jre" / "bin" / "java.exe",
                  self.tools_dir / "jre" / "bin" / "java"):
            if c.is_file():
                return c
        jh = os.environ.get("JAVA_HOME")
        if jh:
            for c in (Path(jh) / "bin" / "java.exe", Path(jh) / "bin" / "java"):
                if c.is_file():
                    return c
        found = shutil.which("java")
        return Path(found) if found else None

    def cfr_jar(self) -> Path | None:
        """CFR decompiler jar under ``tools/cfr/`` (MIT, downloaded at setup).
        ``DOCUTRACEX_CFR`` overrides. Absent (or no JVM) → the Java engine falls
        back to constant-pool mining."""
        env = os.environ.get("DOCUTRACEX_CFR")
        if env and Path(env).is_file():
            return Path(env)
        base = self.tools_dir / "cfr"
        if base.is_dir():
            for p in sorted(base.glob("cfr*.jar")):
                if p.is_file():
                    return p
        return None


settings = Settings()
