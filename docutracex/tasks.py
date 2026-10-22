"""In-app task manager and analysis queue (the Tasks tab).

A few analyses run at once (``settings.max_concurrent_analyses``, default 2);
the rest wait in a FIFO queue, drained by a small pool of daemon workers — so a
batch upload of many files is processed a couple at a time. Each task carries a
live state (queued, running,
cancelling, cancelled, completed, failed), a coarse phase and an
optional progress (``None`` means *unknown*, deliberately distinct from 0%).

A failed task never blocks the independent ones behind it (each run is wrapped).
When a run finishes, an attempt record is appended to the case's
``results/tasks.json`` and the previous consolidated results are snapshotted
under ``results/history/`` so nothing is overwritten. Marks live in their own
file keyed by stable finding ids, so they are preserved across re-runs with no
extra work here.
"""

from __future__ import annotations

import itertools
import queue
import shutil
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import settings
from .logging_config import get_logger
from .storage import CasePaths, read_json, write_json

log = get_logger(__name__)

# Live states.
QUEUED, RUNNING, CANCELLING, CANCELLED = "queued", "running", "cancelling", "cancelled"
COMPLETED, FAILED = "completed", "failed"
_ACTIVE = {QUEUED, RUNNING, CANCELLING}
_FINAL_FROM_SUMMARY = {"completed": COMPLETED, "error": FAILED}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _elapsed(start: str, end: str) -> float | None:
    try:
        s = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
        e = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
        return round((e - s).total_seconds(), 1)
    except (ValueError, TypeError):
        return None


@dataclass
class Task:
    id: str
    type: str               # "analyze" | "rerun" | "rerun_module" | "netcheck"
    analysis_id: str
    filename: str
    target: str = "full"    # "full" or a module name
    state: str = QUEUED
    phase: str = ""
    progress: float | None = None     # None = unknown (not 0%)
    created_utc: str = field(default_factory=_now)
    started_utc: str | None = None
    finished_utc: str | None = None
    duration_s: float | None = None
    error: str | None = None
    counts: dict[str, Any] = field(default_factory=dict)
    steps: list[dict[str, Any]] = field(default_factory=list)
    cases_dir: str | None = None
    params: dict[str, Any] = field(default_factory=dict)   # netcheck: kind/target/...

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "analysis_id": self.analysis_id,
            "filename": self.filename, "target": self.target, "state": self.state,
            "phase": self.phase, "progress": self.progress,
            "created_utc": self.created_utc, "started_utc": self.started_utc,
            "finished_utc": self.finished_utc, "duration_s": self.duration_s,
            "error": self.error, "counts": self.counts, "steps": self.steps,
            "params": {k: v for k, v in self.params.items() if k in ("kind", "target", "check_id", "form")},
        }


def _snapshot_history(paths: CasePaths) -> None:
    """Copy the current consolidated results aside so a re-run can't lose them."""
    summary = paths.summary
    if not summary.exists():
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = paths.results_dir / "history" / stamp
    try:
        dest.mkdir(parents=True, exist_ok=True)
        for name in ("summary.json", "findings.json"):
            src = paths.results_dir / name
            # k: MH22fELbKP
            if src.exists():
                shutil.copy2(src, dest / name)
    except OSError as exc:  # noqa: BLE001
        log.warning("Could not snapshot history for %s: %s", paths.root.name, exc)


def _append_attempt(paths: CasePaths, task: Task) -> None:
    data = read_json(paths.tasks)
    if not isinstance(data, dict) or "attempts" not in data:
        data = {"attempts": []}
    data["attempts"].append({
        "attempt": len(data["attempts"]) + 1,
        "task_id": task.id, "type": task.type, "target": task.target,
        "state": task.state, "started_utc": task.started_utc,
        "finished_utc": task.finished_utc, "duration_s": task.duration_s,
        "error": task.error, "counts": task.counts,
    })
    data["updated_utc"] = _now()
    try:
        write_json(paths.tasks, data)
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not append attempt for %s: %s", paths.root.name, exc)


class TaskManager:
    """Thread-safe FIFO queue of analysis tasks, drained by a small pool of
    daemon workers. ``settings.max_concurrent_analyses`` (default 2) analyses
    run at once; the rest wait in the queue — so a batch upload of many files is
    processed a few at a time instead of all at once or strictly one by one."""

    def __init__(self, max_workers: int | None = None) -> None:
        self._lock = threading.Lock()
        self._tasks: dict[str, Task] = {}
        self._order: list[str] = []
        self._queue: queue.Queue[str] = queue.Queue()
        self._cancel: set[str] = set()
        self._counter = itertools.count(1)
        self._workers: list[threading.Thread] = []
        self._max_workers = max_workers

    def _worker_count(self) -> int:
        if self._max_workers is not None:        # pinned (tests)
            return max(1, min(8, int(self._max_workers)))
        try:
            from . import appsettings
            return appsettings.analysis_concurrency()
        except Exception:  # noqa: BLE001
            return max(1, min(8, int(settings.max_concurrent_analyses)))

    def _ensure_workers(self) -> None:
        """Spawn workers up to the current concurrency (called on submit and when
        the setting is raised). Shrinking is handled by workers exiting in _run."""
        with self._lock:
            self._workers = [w for w in self._workers if w.is_alive()]
            while len(self._workers) < self._worker_count():
                w = threading.Thread(target=self._run, name=f"dtx-task-worker-{len(self._workers) + 1}",
                                     daemon=True)
                self._workers.append(w)
                w.start()

    def reconcile(self) -> int:
        """Apply a changed concurrency setting now: top up the pool (increase);
        a decrease takes effect as running workers finish. Returns the target."""
        self._ensure_workers()
        return self._worker_count()

    def submit(self, type: str, analysis_id: str, filename: str, target: str = "full",
               cases_dir: Path | None = None, params: dict[str, Any] | None = None) -> Task:
        self._ensure_workers()
        with self._lock:
            tid = f"task-{next(self._counter):04d}"
            task = Task(id=tid, type=type, analysis_id=analysis_id, filename=filename,
                        target=target or "full",
                        cases_dir=str(cases_dir) if cases_dir else None, params=dict(params or {}))
            self._tasks[tid] = task
            self._order.append(tid)
        self._queue.put(tid)
        log.info("Queued %s task %s for case %s (target=%s)", type, tid, analysis_id, target)
        return task

    def cancel(self, tid: str) -> bool:
        with self._lock:
            task = self._tasks.get(tid)
            if task is None:
                return False
            if task.state == QUEUED:
                task.state = CANCELLED
                task.finished_utc = _now()
                self._cancel.add(tid)
                return True
            if task.state == RUNNING:
                task.state = CANCELLING  # cooperative; best effort
                self._cancel.add(tid)
                return True
            return False

    def get(self, tid: str) -> dict[str, Any] | None:
        with self._lock:
            task = self._tasks.get(tid)
            return task.public() if task else None

    def list(self, analysis_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            tasks = [self._tasks[i] for i in reversed(self._order)]
        if analysis_id:
            tasks = [t for t in tasks if t.analysis_id == analysis_id]
        return [t.public() for t in tasks]

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values() if t.state in _ACTIVE)

    # --- worker --------------------------------------------------------------

    def _run(self) -> None:
        me = threading.current_thread()
        while True:
            tid = self._queue.get()
            try:
                self._process(tid)
            except Exception as exc:  # noqa: BLE001  (never let one task kill the worker)
                log.exception("Task %s crashed: %s", tid, exc)
                with self._lock:
                    t = self._tasks.get(tid)
                    if t and t.state in _ACTIVE:
                        t.state = FAILED
                        t.error = str(exc)
                        t.finished_utc = _now()
            finally:
                self._queue.task_done()
            # Honour a lowered concurrency setting: a surplus worker retires.
            with self._lock:
                self._workers = [w for w in self._workers if w.is_alive()]
                if me in self._workers and len(self._workers) > self._worker_count():
                    self._workers.remove(me)
                    return

    def _process(self, tid: str) -> None:
        with self._lock:
            task = self._tasks.get(tid)
            if task is None:
                return
            if tid in self._cancel and task.state == CANCELLED:
                self._cancel.discard(tid)
                return
            task.state = RUNNING
            task.started_utc = _now()
            task.phase = "network check" if task.type == "netcheck" else "analyzing"
            task.progress = None  # unknown, not 0%
            cases_dir = Path(task.cases_dir) if task.cases_dir else settings.cases_dir

        from . import analyze

        # rev: AeWckx3pKh
        paths = CasePaths(task.analysis_id, cases_dir=cases_dir)
        if task.type == "netcheck":
            # tag: gmzpt
            self._process_netcheck(task, paths)
            return
        module = None if task.target in ("", "full") else task.target
        if module or task.type != "analyze":
            _snapshot_history(paths)  # re-run: keep the previous results

        error = None
        try:
            analyze.run_analysis(paths.root, module=module)
        except Exception as exc:  # noqa: BLE001
            error = str(exc)

        summary = read_json(paths.summary) or {}
        with self._lock:
            task.finished_utc = _now()
            task.duration_s = _elapsed(task.started_utc or task.finished_utc, task.finished_utc)
            task.counts = summary.get("counts", {})
            task.steps = summary.get("steps", [])
            task.phase = "done"
            if tid in self._cancel:
                task.state = CANCELLED
                self._cancel.discard(tid)
            elif error:
                task.state = FAILED
                task.error = error
            else:
                task.state = _FINAL_FROM_SUMMARY.get(summary.get("state", "completed"), COMPLETED)
        _append_attempt(paths, task)
        log.info("Task %s finished: %s (%.1fs)", tid, task.state, task.duration_s or 0.0)

    def _process_netcheck(self, task: Task, paths: CasePaths) -> None:
        from . import netcheck

        error = None
        try:
            netcheck.run_task(paths.root, task.params)
        except Exception as exc:  # noqa: BLE001
            error = str(exc)[:500]
        summary = read_json(paths.summary) or {}
        with self._lock:
            task.finished_utc = _now()
            task.duration_s = _elapsed(task.started_utc or task.finished_utc, task.finished_utc)
            task.counts = summary.get("counts", {})
            task.steps = [_netcheck_step(task, error)]
            task.phase = "done"
            task.state = FAILED if error else COMPLETED
            task.error = error
            self._cancel.discard(task.id)
        _append_attempt(paths, task)
        log.info("Network check %s finished: %s", task.id, task.state)


def _netcheck_step(task: Task, error: str | None) -> dict[str, Any]:
    p = task.params
    what = p.get("target") or p.get("check_id", "")
    if p.get("kind") == "submit":
        what = f"form #{int(p.get('form', 0)) + 1} of {p.get('check_id')}"
    return {"step": f"netcheck: {p.get('kind')} {what}"[:200], "status": "error" if error else "ok",
            "note": error, "duration_s": task.duration_s}


# Process-wide singleton: one shared queue drained by a small worker pool.
manager = TaskManager()
