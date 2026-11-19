"""FLOSS of a large binary in the background.

On a large, code-dense binary FLOSS (decoded + stack strings; tight strings are
for Deep FLOSS) can take half an hour or more. Holding the whole case for it is
the wrong trade: the case's own binary (above ``DOCUTRACEX_FLOSS_BACKGROUND_MB``,
2 MB by default) gets FLOSS as a background job instead. The case finishes with
everything else; the job is listed in Tasks (time running, Cancel); when it ends
its strings land in the Binary tab, in Code → Strings (with their function) and
— the case's IOCs and findings recomputed — in IOCs and Findings. Marks stay.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .logging_config import get_logger

log = get_logger(__name__)


def start(root: Path, path: Path, name: str, sha256: str) -> dict[str, Any]:
    """Start FLOSS on ``path`` (the case's own binary) as a background task. Returns the
    placeholder record the Binary tab shows until it ends."""
    from . import tasks
    from .parsers import pe as pe_mod

    def run(task: Any, cancel: Any) -> str:
        import time as _t
        t0 = _t.monotonic()

        def beat() -> None:
            while not cancel.wait(5) and task.state == tasks.RUNNING and not done[0]:
                s = int(_t.monotonic() - t0)
                tasks.manager.set_step_detail(task, f"FLOSS running · {s // 60}m {s % 60:02d}s")
        import threading
        done = [False]
        threading.Thread(target=beat, name="flossbg-heartbeat", daemon=True).start()
        try:
            rec = pe_mod.floss_record(path, cancel=cancel)
        finally:
            done[0] = True
        if rec.get("status") == "cancelled" or cancel.is_set():
            _apply(root, sha256, {"status": "cancelled", "detail": "FLOSS cancelled by the analyst"}, task, None)
            return "cancelled"
        tasks.manager.set_step_detail(task, "FLOSS done · waiting for the case's other tasks to write its results")
        if not _wait_for_placeholder(root, task.id, cancel) or not tasks.manager.hold_case(task, cancel):
            return "cancelled before writing its results"
        n = _apply(root, sha256, rec, task, path)
        return f"{n} string(s)" if rec.get("status") == "ok" else str(rec.get("detail") or rec.get("status"))

    t = tasks.manager.start_background("floss", root.name, name, "floss (background)", run,
                                       step=f"FLOSS · {name} (background)", cases_dir=root.parent)
    return {"status": "running", "background": True, "task_id": t.id, "tight_skipped": True,
            "detail": "large binary: FLOSS runs in the background (Tasks); its strings, IOCs and findings "
                      "are added to the case when it ends"}


def _wait_for_placeholder(root: Path, tid: str, cancel: Any, limit_s: float = 6 * 3600) -> bool:
    """The analysis that started the job writes its result (with this job's placeholder)
    when it ends: wait for it, so the strings are not written before — and then lost."""
    import time as _t

    from .storage import read_json
    end = _t.monotonic() + limit_s
    f = root / "results" / "msi.json"
    while _t.monotonic() < end:
        res = read_json(f) or {}
        if any((it.get("floss") or {}).get("task_id") == tid for it in res.get("items") or []):
            return True
        if cancel.wait(1):
            return False
    return True


def _apply(root: Path, sha256: str, rec: dict[str, Any], task: Any, path: Path | None) -> int:
    """Write a background FLOSS record into the case: Binary tab (msi item), Code →
    Strings (code / golang result), then IOCs and findings recomputed."""
    from .analyze import _recompute_derived
    from .parsers import pe as pe_mod
    from .storage import CasePaths, read_json, write_subresult
    paths = CasePaths(root.name, cases_dir=root.parent)
    strings = list(rec.pop("strings", []) or [])
    res = read_json(paths.subresult("msi")) or {}
    tid = getattr(task, "id", None)
    item = next((it for it in res.get("items") or [] if (it.get("floss") or {}).get("task_id") == tid), None) \
        or ((res.get("items") or [None])[0])
    if item is not None:
        rec = {k: v for k, v in rec.items() if k != "located"}
        rec["background"] = True
        if rec.get("status") == "ok":
            rec["tight_skipped"] = True
            rec["note"] = ("ran in the background (large binary); tight strings skipped — Deep FLOSS (Code view) "
                           "runs them on every function")
        item["floss"] = rec
        if strings:
            item["floss_strings"] = strings[:pe_mod._FLOSS_MAX_STRINGS]
            c = rec.get("counts") or {}
            fnd = pe_mod._finding("pe_floss_strings", "info",
                                  f"FLOSS extracted {len(strings)} string(s): {c.get('static', 0)} static, "
                                  f"{c.get('decoded', 0)} decoded, {c.get('stack', 0)} stack, "
                                  f"{c.get('tight', 0)} tight (background run)", item.get("location") or root.name)
            for lst in (item.setdefault("findings", []), res.setdefault("findings", [])):
                if not any(f.get("rule") == "pe_floss_strings" for f in lst):
                    lst.append(fnd)
        write_subresult(paths, "msi", res)
    if rec.get("status") != "ok":
        return 0
    added = 0
    try:                                   # Code → Strings, with the function each one is in
        from .codeanalysis import case as code_case
        for mode in ("native", "go"):
            if code_case.load(paths.root, sha256, mode) is not None:
                added = code_case.merge_full_floss(paths.root, sha256, mode, {**rec, "located": rec.get("located")
                                                                             or []}, label="background run",
                                                   refresh=False)
                break
    except Exception as exc:  # noqa: BLE001
        log.warning("background FLOSS: code strings not merged for %s: %s", sha256[:12], exc)
    try:
        _recompute_derived(paths)
    except Exception as exc:  # noqa: BLE001
        log.warning("background FLOSS: IOCs / findings not recomputed for %s: %s", root.name, exc)
    return len(strings) or added


def start_priority(root: Path, path: Path, name: str, sha256: str, mode: str, addrs: list[int]) -> str:
    """FLOSS tight strings on the code analysis' priority functions of the case's own large
    binary, as a background task: merged into Code → Strings (with their function) and the
    IOCs / findings when it ends. Returns the task id."""
    from . import tasks
    from .codeanalysis import case as code_case
    from .parsers import pe as pe_mod

    def run(task: Any, cancel: Any) -> str:
        import threading
        import time as _t
        t0, done = _t.monotonic(), [False]

        def beat() -> None:
            while not cancel.wait(5) and not done[0]:
                s = int(_t.monotonic() - t0)
                tasks.manager.set_step_detail(task, f"FLOSS tight on {len(addrs)} function(s) · {s // 60}m {s % 60:02d}s")
        threading.Thread(target=beat, name="flossbg-tight-heartbeat", daemon=True).start()
        try:
            rec = pe_mod.tight_on_functions(path, addrs, cancel=cancel)
        finally:
            done[0] = True
        status = "cancelled" if (cancel.is_set() or rec.get("status") == "cancelled") else rec.get("status")
        located = [dict(s, kind="tight") for s in rec.get("located") or [] if s.get("kind") == "tight"]
        if status != "cancelled":
            tasks.manager.set_step_detail(task, "FLOSS done · waiting for the case's other tasks to write its results")
        if not _wait_for_code(root, sha256, mode, task.id, cancel) or not tasks.manager.hold_case(task, cancel):
            return "cancelled before writing its results"
        added = 0
        if status == "ok" and located:
            added = code_case.merge_full_floss(root, sha256, mode, {"located": located},
                                               label="priority functions, background", refresh=True)
        with code_case._write_lock:                       # the placeholder → the outcome
            full = code_case.load(root, sha256, mode)
            if full is not None:
                full["floss_priority"] = {"status": status, "detail": str(rec.get("detail") or "")[:300],
                                          "functions": len(addrs), "strings": len(located), "background": True,
                                          "added": added}
                code_case.result_file(root, sha256, mode).write_text(json.dumps(full), encoding="utf-8")
        return f"{len(located)} tight string(s), {added} new" if status == "ok" else str(status)

    t = tasks.manager.start_background("floss", root.name, name, "floss tight (background)", run,
                                       step=f"FLOSS tight · {name} · priority functions (background)",
                                       cases_dir=root.parent)
    return t.id


def _wait_for_code(root: Path, sha256: str, mode: str, tid: str, cancel: Any, limit_s: float = 6 * 3600) -> bool:
    """The code analysis writes its result (with this job's placeholder) at the end of its
    step: wait for it, so the merged strings are not overwritten."""
    import time as _t

    from .codeanalysis import case as code_case
    end = _t.monotonic() + limit_s
    while _t.monotonic() < end:
        full = code_case.load(root, sha256, mode) or {}
        if (full.get("floss_priority") or {}).get("task_id") == tid:
            return True
        if cancel.wait(1):
            return False
    return True
