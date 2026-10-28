"""Run an external analysis tool and keep what it printed.

Every external tool (oletools CLIs, Didier scripts, peepdf, pcodedmp,
ViperMonkey...) goes through :func:`run`: a separate process, a hard time limit,
bounded output and an environment that silences harmless library noise. The
returned record is stored as-is in the module result, so the analyst can always
see the exact command and its raw output next to the findings derived from it.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any
from .config import tmo

OUTPUT_BOUND = 60000


def env() -> dict[str, str]:
    """Environment for tool subprocesses (bundled libmagic, quiet warnings)."""
    from . import native, quiet

    # gmzpt
    e = native.subprocess_env()
    e["PYTHONWARNINGS"] = quiet.WARNINGS_FILTER
    e["PYTHONIOENCODING"] = "utf-8"
    return e


def run(cmd: list[str], shown: str, timeout: int = tmo(180), cwd: Path | None = None,
        bound: int = OUTPUT_BOUND, extra_env: dict[str, str] | None = None,
        input_text: str | None = None) -> dict[str, Any]:
    """Run ``cmd``; return {command, returncode, output, stderr, duration_s, ...}.

    ``shown`` is the human-readable command stored for the UI (tool name and the
    file name, not full local paths). Never raises.
    """
    e = env()
    if extra_env:
        e.update(extra_env)
    t0 = time.perf_counter()
    rec: dict[str, Any] = {"command": shown}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, env=e,
                              cwd=str(cwd) if cwd else None, input=input_text,
                              stdin=None if input_text is not None else subprocess.DEVNULL)
        out = proc.stdout or ""
        rec.update(returncode=proc.returncode, output=out[:bound],
                   output_truncated=len(out) > bound,
                   stderr=(proc.stderr or "")[-4000:] or None)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        rec.update(error=f"timed out after {timeout}s", timed_out=True, output=out[:bound])
    except Exception as exc:  # noqa: BLE001
        rec["error"] = str(exc)
    rec["duration_s"] = round(time.perf_counter() - t0, 2)
    return rec


def package_root() -> str:
    """Directory containing the ``docutracex`` package (for PYTHONPATH)."""
    return str(Path(__file__).resolve().parent.parent)


def with_package_path(e: dict[str, str] | None = None) -> dict[str, str]:
    e = dict(e or {})
    root = package_root()
    cur = e.get("PYTHONPATH") or os.environ.get("PYTHONPATH")
    e["PYTHONPATH"] = root + (os.pathsep + cur if cur else "")
    return e
