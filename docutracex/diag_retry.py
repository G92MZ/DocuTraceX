"""Retry one component's installation from the Diagnostics tab.

Runs ``scripts/setup_portable_python.py --component NAME`` (or a pip install
for an app dependency) in a background process, one at a time, and keeps its
output so the UI can show progress and refresh the checks when it ends.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SETUP = ROOT / "scripts" / "setup_portable_python.py"
# Must match COMPONENTS in scripts/setup_portable_python.py.
COMPONENTS = ("portable", "tool-deps", "didier", "officemalscanner", "ipdb", "chromium",
              "vipermonkey", "webcrack", "boxps", "pycdc", "cfr", "floss", "capa", "ember")
APP_DEP_PREFIX = "app-dep:"
_LOG_LINES = 400
_TIMEOUT = 3600

_lock = threading.Lock()
_job: dict[str, Any] = {}


def _command(component: str) -> list[str]:
    if component.startswith(APP_DEP_PREFIX):
        from .deps import APP_DEPS
        name = component[len(APP_DEP_PREFIX):]
        if name not in {d.pip_name for d in APP_DEPS}:
            raise ValueError(f"unknown app dependency {name!r}")
        return [sys.executable, "-m", "pip", "install", "--upgrade", name]
    if component not in COMPONENTS:
        raise ValueError(f"unknown component {component!r}")
    return [sys.executable, str(SETUP), "--component", component]


def status() -> dict[str, Any]:
    with _lock:
        if not _job:
            return {"state": "idle"}
        return {k: (list(v) if k == "log" else v) for k, v in _job.items() if k != "proc"}


def _run(cmd: list[str]) -> None:
    def add(line: str) -> None:
        with _lock:
            _job["log"].append(line.rstrip())
            del _job["log"][:-_LOG_LINES]

    rc: int | None = None
    try:
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", bufsize=1)
        with _lock:
            _job["proc"] = proc
        deadline = time.monotonic() + _TIMEOUT
        for line in proc.stdout or []:
            add(line)
            if time.monotonic() > deadline:
                proc.kill()
                add("[!] Timed out.")
                break
        rc = proc.wait()
    except Exception as exc:  # noqa: BLE001
        add(f"[!] Could not run the installer: {exc}")
    if rc == 0 and str(_job.get("component", "")).startswith(APP_DEP_PREFIX):
        add("[i] Restart DocuTraceX so the web app picks it up.")
    with _lock:
        _job.pop("proc", None)
        _job.update(state="done" if rc == 0 else "failed", returncode=rc, finished=time.time())


def start(component: str) -> dict[str, Any]:
    """Start a retry; raises ValueError for an unknown component and
    RuntimeError while another retry is still running."""
    cmd = _command(component)
    with _lock:
        if _job.get("state") == "running":
            raise RuntimeError(f"'{_job['component']}' is still being installed")
        _job.clear()
        _job.update(component=component, state="running", started=time.time(), log=[], returncode=None)
    threading.Thread(target=_run, args=(cmd,), daemon=True, name=f"diag-retry-{component}").start()
    return status()
