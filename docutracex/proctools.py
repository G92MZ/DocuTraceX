"""Run an external tool with a HARD time limit, killing its whole process tree.

Why not plain ``subprocess.run(..., capture_output=True, timeout=...)``:
standalone tools built with PyInstaller *onefile* (floss.exe, capa.exe, diec
helpers...) are a bootloader that starts a CHILD process doing the real work.
On timeout, ``subprocess.run`` kills only the bootloader; the child keeps
running and keeps the inherited stdout/stderr pipe handles open — and on
Windows ``subprocess.run`` then calls ``communicate()`` with NO timeout, so it
blocks until that orphan finishes (or forever). Result: the analysis "hangs".

Here:
- output goes to temporary FILES, not pipes, so an orphan can never block us;
- on timeout the whole tree is killed (``taskkill /T /F`` on Windows, the
  process group elsewhere);
- the tool runs in its own process group (Windows) / session (POSIX).

Never raises: returns a record {rc, out, err, timed_out, duration_s, error}.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .logging_config import get_logger

log = get_logger(__name__)

_WIN = sys.platform.startswith("win")
_OUT_CAP = 64 * 1024 * 1024   # never read more than this from a tool's stdout


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill ``proc`` and every process it started."""
    try:
        if _WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not kill process tree %s: %s", proc.pid, exc)
    try:
        proc.kill()
    except Exception:  # noqa: BLE001
        pass
    try:
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001
        pass


def _read(f: Any, limit: int) -> str:
    try:
        f.seek(0)
        return f.read(limit).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def run_bounded(cmd: list[str], timeout: int, cwd: Path | None = None,
                env: dict[str, str] | None = None) -> dict[str, Any]:
    """Run ``cmd`` with a hard ``timeout`` (seconds). See the module docstring."""
    t0 = time.perf_counter()
    rec: dict[str, Any] = {"rc": None, "out": "", "err": "", "timed_out": False}
    kw: dict[str, Any] = {}
    if _WIN:
        kw["creationflags"] = (getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                               | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    else:
        kw["start_new_session"] = True
    with tempfile.TemporaryFile() as fo, tempfile.TemporaryFile() as fe:
        try:
            proc = subprocess.Popen(cmd, stdout=fo, stderr=fe, stdin=subprocess.DEVNULL,
                                    cwd=str(cwd) if cwd else None, env=env, **kw)
        except Exception as exc:  # noqa: BLE001
            rec["error"] = str(exc)
            rec["duration_s"] = round(time.perf_counter() - t0, 2)
            return rec
        try:
            rec["rc"] = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rec["timed_out"] = True
            log.warning("%s timed out after %ss — killing its process tree (pid %s)",
                        Path(cmd[0]).name, timeout, proc.pid)
            _kill_tree(proc)
        except Exception as exc:  # noqa: BLE001
            rec["error"] = str(exc)
            _kill_tree(proc)
        rec["out"] = _read(fo, _OUT_CAP)
        rec["err"] = _read(fe, 1024 * 1024)[-4000:]
    rec["duration_s"] = round(time.perf_counter() - t0, 2)
    return rec
