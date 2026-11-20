"""One memory-heavy job at a time.

FLOSS and capa build a vivisect analysis of the whole binary in memory: several GB each
on a large one. Run side by side (FLOSS and capa of the same binary, FLOSS tight on its
priority functions, a Deep FLOSS, another case's) they can use up the machine's RAM.
Background jobs take a slot here first and wait (shown as *queued* in Tasks) until one is
free. ``DOCUTRACEX_HEAVY_JOBS`` (default 1) sets how many run at once; 0 = no limit.
With psutil installed, a job that got its slot also waits (up to 10 min) while less than
``DOCUTRACEX_HEAVY_MIN_FREE_MB`` (default 1500) of RAM is free.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from typing import Any

from .logging_config import get_logger

log = get_logger(__name__)

SLOTS = int(os.environ.get("DOCUTRACEX_HEAVY_JOBS", "1") or 1)
MIN_FREE_MB = int(os.environ.get("DOCUTRACEX_HEAVY_MIN_FREE_MB", "1500") or 0)
MEMORY_WAIT_S = 600

_cond = threading.Condition()
_running = 0


def _free_mb() -> float | None:
    try:
        import psutil
        return psutil.virtual_memory().available / 2**20
    except Exception:  # noqa: BLE001  (optional)
        return None


def acquire(cancel: threading.Event, on_wait: Callable[[str], None] | None = None,
            slots: int | None = None) -> bool:
    """Wait for a slot (and some free RAM). False when cancelled while waiting."""
    global _running
    n = SLOTS if slots is None else slots
    told = False
    with _cond:
        while n > 0 and _running >= n:
            if not told and on_wait is not None:
                on_wait("waiting: FLOSS / capa use a lot of memory, one runs at a time")
                told = True
            _cond.wait(1)
            if cancel.is_set():
                return False
        _running += 1
    end = time.monotonic() + MEMORY_WAIT_S
    while MIN_FREE_MB and (free := _free_mb()) is not None and free < MIN_FREE_MB and time.monotonic() < end:
        if on_wait is not None:
            on_wait(f"waiting for free memory: {int(free)} MB free, {MIN_FREE_MB} MB wanted")
        if cancel.wait(5):
            release()
            return False
    return True


def release() -> None:
    global _running
    with _cond:
        _running = max(0, _running - 1)
        _cond.notify_all()


def running() -> int:
    return _running


def run(task: Any, cancel: threading.Event, label: str, fn: Callable[[], dict[str, Any]],
        progress: Callable[[], str] | None = None) -> dict[str, Any]:
    """``fn()`` (a FLOSS / capa run) for a background task: queued until a slot is free,
    then running with a heartbeat in Tasks. ``{"status": "cancelled"}`` when cancelled
    while waiting."""
    from . import tasks
    m = tasks.manager

    def wait_note(msg: str) -> None:
        m.set_background_state(task, tasks.QUEUED)
        m.set_step_detail(task, f"{label} · {msg}")
    if not acquire(cancel, wait_note):
        return {"status": "cancelled", "detail": f"{label} cancelled by the analyst (while waiting)"}
    m.set_background_state(task, tasks.RUNNING)
    t0, done = time.monotonic(), threading.Event()

    def beat() -> None:
        while not done.wait(5) and not cancel.is_set():
            s = int(time.monotonic() - t0)
            try:
                p = progress() if progress else ""
            except Exception:  # noqa: BLE001
                p = ""
            m.set_step_detail(task, f"{label} running · {s // 60}m {s % 60:02d}s" + (f" · {p}" if p else ""))
    threading.Thread(target=beat, name="heavy-heartbeat", daemon=True).start()
    try:
        return fn()
    finally:
        done.set()
        release()
