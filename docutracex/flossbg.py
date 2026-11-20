"""FLOSS of a large binary in the background.

On a large, code-dense binary FLOSS (decoded + stack strings; tight strings are
for Deep FLOSS) can take half an hour or more. Holding the whole case for it is
the wrong trade: the case's own binary (above ``DOCUTRACEX_FLOSS_BACKGROUND_MB``,
2 MB by default) gets FLOSS as a background job instead. The case finishes with
everything else; the job is listed in Tasks (time running, Cancel); when it ends
its strings land in the Binary tab, in Code → Strings (with their function) and
— the case's IOCs and findings recomputed — in IOCs and Findings. Marks stay.

capa of the same binary goes to the background too (``start_capa``) unless its
result is cached: its capabilities and ATT&CK techniques reach the Binary tab
and the findings when it ends.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from .logging_config import get_logger

log = get_logger(__name__)


# The analysis may run in a child process (the portable Python), which ends with it — and
# would take its background jobs along. There, a job is only *requested* (a provisional id
# in its placeholder, the request in results/background_requests.json); the web service
# starts it when the child ends (``launch_deferred``) and puts the real task id in place.
DEFER_ENV = "DOCUTRACEX_DEFER_BACKGROUND"
REQUESTS = "background_requests.json"
_req_lock = threading.Lock()


def _deferred() -> bool:
    return os.environ.get(DEFER_ENV) == "1"


def _request(root: Path, kind: str, **args: Any) -> str:
    from .storage import read_json, write_json
    f = root / "results" / REQUESTS
    with _req_lock:
        reqs = read_json(f) or []
        pid = f"pending-{kind}-{len(reqs) + 1}"
        reqs.append({"kind": kind, "id": pid, **args})
        f.parent.mkdir(parents=True, exist_ok=True)
        write_json(f, reqs)
    return pid


def clear_requests(root: Path) -> None:
    (Path(root) / "results" / REQUESTS).unlink(missing_ok=True)


# Jobs running now, per case (results/background_running.json): a restart of the app ends
# them, and on the next start ``recover_interrupted`` marks what they left as interrupted.
RUNNING = "background_running.json"


def _track(root: Path, tid: str, kind: str, sha256: str, mode: str | None = None) -> None:
    from .storage import read_json, write_json
    f = Path(root) / "results" / RUNNING
    with _req_lock:
        cur = read_json(f) or {}
        cur[tid] = {"kind": kind, "sha256": sha256, "mode": mode}
        f.parent.mkdir(parents=True, exist_ok=True)
        write_json(f, cur)


def _untrack(root: Path, tid: str) -> None:
    from .storage import read_json, write_json
    f = Path(root) / "results" / RUNNING
    with _req_lock:
        cur = read_json(f) or {}
        cur.pop(tid, None)
        if cur:
            write_json(f, cur)
        else:
            f.unlink(missing_ok=True)


def _launch(root: Path, kind: str, sha256: str, name: str, target: str, step: str, run: Any,
            task_id: str | None, mode: str | None = None) -> str:
    """start_background, tracked in the case until the job ends (any way)."""
    from . import tasks
    tid = task_id or tasks.manager.new_id()
    _track(root, tid, kind, sha256, mode)

    def tracked(task: Any, cancel: Any) -> Any:
        try:
            return run(task, cancel)
        finally:
            _untrack(root, tid)
    try:
        tasks.manager.start_background(kind if kind != "priority" else "floss", root.name, name, target, tracked,
                                       step=step, cases_dir=root.parent, task_id=tid)
    except Exception:
        _untrack(root, tid)
        raise
    return tid


INTERRUPTED = "the app restarted while it ran in the background: re-run the analysis to run it again"


def recover_interrupted(cases_dir: Path) -> int:
    """On start: background jobs a restart ended leave their placeholders "running" for
    ever. Mark them interrupted (Binary tab, Code → Strings). Jobs live in this process are
    left alone. Returns how many were marked."""
    from . import tasks
    from .storage import CasePaths, read_json, write_json, write_subresult
    live = {t["id"] for t in tasks.manager.list() if t.get("background")
            and t.get("state") in ("queued", "running", "cancelling")}
    n = 0
    for f in sorted(Path(cases_dir).glob(f"*/results/{RUNNING}")):
        root = f.parent.parent
        try:
            with _req_lock:
                cur = read_json(f) or {}
                gone = {tid: r for tid, r in cur.items() if tid not in live}
                if not gone:
                    continue
                paths = CasePaths(root.name, cases_dir=root.parent)
                res = read_json(paths.subresult("msi")) or {}
                changed = False
                for it in res.get("items") or []:
                    for key in ("floss", "capa", "vivisect_full"):
                        rec = it.get(key) or {}
                        if rec.get("task_id") in gone and rec.get("status") == "running":
                            it[key] = {"status": "interrupted", "background": True, "task_id": rec["task_id"],
                                       "detail": INTERRUPTED}
                            changed, n = True, n + 1
                if changed:
                    write_subresult(paths, "msi", res)
                from .codeanalysis import case as code_case
                for tid, r in gone.items():
                    if r.get("kind") != "priority":
                        continue
                    with code_case._write_lock:
                        full = code_case.load(root, r["sha256"], r.get("mode") or "native")
                        fp = (full or {}).get("floss_priority") or {}
                        if fp.get("task_id") == tid and fp.get("status") == "background":
                            fp.update(status="interrupted", detail=INTERRUPTED)
                            code_case.result_file(root, r["sha256"], r.get("mode") or "native").write_text(
                                json.dumps(full), encoding="utf-8")
                            n += 1
                rest = {tid: r for tid, r in cur.items() if tid in live}
                if rest:
                    write_json(f, rest)
                else:
                    f.unlink(missing_ok=True)
            (root / "results" / REQUESTS).unlink(missing_ok=True)
        except Exception as exc:  # noqa: BLE001
            log.warning("interrupted background jobs not marked for %s: %s", root.name, exc)
    return n


def launch_deferred(root: Path) -> list[str]:
    """In the web service, after the analysis' child process ended: give the jobs it
    requested their task ids, put them in the placeholders, then start the jobs (in that
    order, so a job never writes before its placeholder is updated). Returns the ids."""
    from . import tasks
    from .storage import CasePaths, read_json, write_subresult
    root = Path(root)
    f = root / "results" / REQUESTS
    reqs = [r for r in read_json(f) or [] if r.get("kind") in ("floss", "capa", "priority", "complete")]
    f.unlink(missing_ok=True)
    if not reqs:
        return []
    ids = {r["id"]: tasks.manager.new_id() for r in reqs}
    try:
        paths = CasePaths(root.name, cases_dir=root.parent)
        res = read_json(paths.subresult("msi")) or {}
        changed = False
        for it in res.get("items") or []:
            for key in ("floss", "capa", "vivisect_full"):
                rec = it.get(key) or {}
                if rec.get("task_id") in ids:
                    rec["task_id"], changed = ids[rec["task_id"]], True
        if changed:
            write_subresult(paths, "msi", res)
        from .codeanalysis import case as code_case
        for r in reqs:
            if r["kind"] != "priority":
                continue
            with code_case._write_lock:
                full = code_case.load(root, r["sha256"], r["mode"])
                if full is not None and (full.get("floss_priority") or {}).get("task_id") == r["id"]:
                    full["floss_priority"]["task_id"] = ids[r["id"]]
                    code_case.result_file(root, r["sha256"], r["mode"]).write_text(json.dumps(full),
                                                                                   encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        log.warning("background placeholders not updated for %s: %s", root.name, exc)
    started = []
    for r in reqs:
        tid, path = ids[r["id"]], Path(r["path"])
        try:
            if r["kind"] == "floss":
                _start_floss(root, path, r["name"], r["sha256"], task_id=tid)
            elif r["kind"] == "capa":
                _start_capa(root, path, r["name"], r["sha256"], r.get("loc") or r["name"], task_id=tid)
            elif r["kind"] == "complete":
                _start_complete(root, path, r["name"], r["sha256"], r.get("loc") or r["name"],
                                [ids.get(x, x) for x in r.get("after") or []], task_id=tid)
            else:
                _start_priority(root, path, r["name"], r["sha256"], r["mode"], list(r["addrs"]), task_id=tid)
            started.append(tid)
        except Exception as exc:  # noqa: BLE001
            log.warning("background %s not started for %s: %s", r["kind"], root.name, exc)
    return started


def start(root: Path, path: Path, name: str, sha256: str) -> dict[str, Any]:
    """Start FLOSS on ``path`` (the case's own binary) as a background task (or request it,
    in the analysis' child process). Returns the placeholder record the Binary tab shows
    until it ends."""
    tid = _request(root, "floss", path=str(path), name=name, sha256=sha256) if _deferred() \
        else _start_floss(root, path, name, sha256)
    return {"status": "running", "background": True, "task_id": tid, "tight_skipped": True,
            "detail": "large binary: FLOSS runs in the background (Tasks); its strings, IOCs and findings "
                      "are added to the case when it ends"}


def _start_floss(root: Path, path: Path, name: str, sha256: str,
                 task_id: str | None = None) -> str:
    from . import tasks
    from .parsers import pe as pe_mod

    def run(task: Any, cancel: Any) -> str:
        from . import heavyjobs
        rec = heavyjobs.run(task, cancel, "FLOSS", lambda: pe_mod.floss_record(path, cancel=cancel, fast=True),
                            progress=lambda: pe_mod.live_progress(path, "floss"))
        if rec.get("status") == "cancelled" or cancel.is_set():
            _apply(root, sha256, {"status": "cancelled", "detail": "FLOSS cancelled by the analyst"}, task, None)
            return "cancelled"
        tasks.manager.set_step_detail(task, "FLOSS done · waiting for the case's other tasks to write its results")
        if not _wait_for_placeholder(root, task.id, cancel) or not tasks.manager.hold_case(task, cancel):
            return "cancelled before writing its results"
        n = _apply(root, sha256, rec, task, path)
        return f"{n} string(s)" if rec.get("status") == "ok" else str(rec.get("detail") or rec.get("status"))

    return _launch(root, "floss", sha256, name, "floss (background)", f"FLOSS · {name} (background)", run, task_id)


def _wait_for_placeholder(root: Path, tid: str, cancel: Any, limit_s: float = 6 * 3600,
                          key: str = "floss") -> bool:
    """The analysis that started the job writes its result (with this job's placeholder)
    when it ends: wait for it, so the strings are not written before — and then lost."""
    import time as _t

    from .storage import read_json
    end = _t.monotonic() + limit_s
    f = root / "results" / "msi.json"
    while _t.monotonic() < end:
        res = read_json(f) or {}
        if any((it.get(key) or {}).get("task_id") == tid for it in res.get("items") or []):
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


def start_capa(root: Path, path: Path, name: str, sha256: str, loc: str) -> dict[str, Any]:
    """Start capa on ``path`` (the case's own binary) as a background task (or request it,
    in the analysis' child process). Returns the placeholder record the Binary tab shows
    until it ends."""
    tid = _request(root, "capa", path=str(path), name=name, sha256=sha256, loc=loc) if _deferred() \
        else _start_capa(root, path, name, sha256, loc)
    return {"status": "running", "background": True, "task_id": tid, "capabilities": [],
            "detail": "large binary: capa runs in the background (Tasks); its capabilities and ATT&CK "
                      "techniques are added to the case when it ends"}


def _start_capa(root: Path, path: Path, name: str, sha256: str, loc: str,
                task_id: str | None = None) -> str:
    from . import tasks
    from .parsers import pe as pe_mod

    def run(task: Any, cancel: Any) -> str:
        from . import heavyjobs
        rec = heavyjobs.run(task, cancel, "capa", lambda: pe_mod._capa_only(path, cancel=cancel, fast=True),
                            progress=lambda: pe_mod.live_progress(path, "capa"))
        if rec.get("status") == "cancelled" or cancel.is_set():
            _apply_capa(root, {"status": "cancelled", "detail": "capa cancelled by the analyst"}, task, loc, sha256)
            return "cancelled"
        tasks.manager.set_step_detail(task, "capa done · waiting for the case's other tasks to write its results")
        if not _wait_for_placeholder(root, task.id, cancel, key="capa") or not tasks.manager.hold_case(task, cancel):
            return "cancelled before writing its results"
        n = _apply_capa(root, rec, task, loc, sha256)
        return f"{n} capabilit(ies)" if rec.get("status") == "ok" else str(rec.get("detail") or rec.get("status"))

    return _launch(root, "capa", sha256, name, "capa (background)", f"capa · {name} (background)", run, task_id)


def _apply_capa(root: Path, rec: dict[str, Any], task: Any, loc: str, sha256: str = "") -> int:
    """Write a background capa record into the case: Binary tab (msi item) and its
    capability findings; the code analysis' capabilities contrasted with it again (capa
    column, capa only, no duplicate findings); then the case's findings recomputed."""
    from .analyze import _recompute_derived
    from .parsers import pe as pe_mod
    from .storage import CasePaths, read_json, write_subresult
    paths = CasePaths(root.name, cases_dir=root.parent)
    res = read_json(paths.subresult("msi")) or {}
    tid = getattr(task, "id", None)
    item = next((it for it in res.get("items") or [] if (it.get("capa") or {}).get("task_id") == tid), None)
    if item is None:
        return 0
    rec = dict(rec, background=True)
    item["capa"] = rec
    new = pe_mod.capa_findings(rec, item.get("location") or loc)
    if new:
        for lst in (item.setdefault("findings", []), res.setdefault("findings", [])):
            seen = {(f.get("rule"), f.get("detail")) for f in lst}
            lst.extend(f for f in new if (f.get("rule"), f.get("detail")) not in seen)
    write_subresult(paths, "msi", res)
    if rec.get("status") == "ok" and sha256:
        try:
            from .codeanalysis import case as code_case
            code_case.recontrast_capa(root, sha256, rec)
        except Exception as exc:  # noqa: BLE001
            log.warning("background capa: code capabilities not contrasted for %s: %s", sha256[:12], exc)
    try:
        _recompute_derived(paths)
    except Exception as exc:  # noqa: BLE001
        log.warning("background capa: findings not recomputed for %s: %s", root.name, exc)
    return len(rec.get("capabilities") or [])


def start_complete(root: Path, path: Path, name: str, sha256: str, loc: str, after: list[str]) -> dict[str, Any]:
    """After the fast FLOSS / capa of a large binary (``after``: their task ids): the complete
    vivisect analysis in the background, then FLOSS and capa on it, and what they find that
    the fast runs missed is added to the case. Returns the placeholder (``vivisect_full``)."""
    after = [a for a in after if a]
    tid = _request(root, "complete", path=str(path), name=name, sha256=sha256, loc=loc, after=after) \
        if _deferred() else _start_complete(root, path, name, sha256, loc, after)
    return {"status": "running", "background": True, "task_id": tid,
            "detail": "the fast analysis is shown first; the complete one runs after it in the background "
                      "and adds what it finds"}


def _start_complete(root: Path, path: Path, name: str, sha256: str, loc: str, after: list[str],
                    task_id: str | None = None) -> str:
    from . import heavyjobs, tasks
    from .parsers import pe as pe_mod

    def run(task: Any, cancel: Any) -> str:
        # after the fast runs (the slots are not first come, first served)
        tasks.manager.set_background_state(task, tasks.QUEUED)
        tasks.manager.set_step_detail(task, "complete analysis · waiting for the fast FLOSS / capa to end")
        while any((tasks.manager.get(a) or {}).get("state") in ("queued", "running", "cancelling") for a in after):
            if cancel.wait(2):
                _apply_complete(root, None, None, task, loc, sha256, cancelled=True)
                return "cancelled"
        floss = heavyjobs.run(task, cancel, "complete analysis · FLOSS",
                              lambda: pe_mod.floss_record(path, cancel=cancel),
                              progress=lambda: pe_mod.live_progress(path, "floss"))
        capa = None
        if not cancel.is_set():
            capa = heavyjobs.run(task, cancel, "complete analysis · capa",
                                 lambda: pe_mod._capa_only(path, cancel=cancel),
                                 progress=lambda: pe_mod.live_progress(path, "capa"))
        if cancel.is_set():
            _apply_complete(root, None, None, task, loc, sha256, cancelled=True)
            return "cancelled"
        tasks.manager.set_step_detail(task, "complete analysis done · waiting to write its results")
        if not _wait_for_placeholder(root, task.id, cancel, key="vivisect_full") \
                or not tasks.manager.hold_case(task, cancel):
            return "cancelled before writing its results"
        added = _apply_complete(root, floss, capa, task, loc, sha256)
        return f"+{added['strings']} string(s), +{added['capabilities']} capabilit(ies)"

    return _launch(root, "complete", sha256, name, "complete analysis (background)",
                   f"complete analysis · {name} (background)", run, task_id)


def _apply_complete(root: Path, floss: dict[str, Any] | None, capa: dict[str, Any] | None, task: Any,
                    loc: str, sha256: str, cancelled: bool = False) -> dict[str, int]:
    """Add what the complete analysis found and the fast one missed: FLOSS strings (Binary
    tab, Code → Strings with their function), capa capabilities (+ findings, Code →
    Capabilities contrast); then the case's IOCs and findings recomputed."""
    from .analyze import _recompute_derived
    from .parsers import pe as pe_mod
    from .storage import CasePaths, read_json, write_subresult
    paths = CasePaths(root.name, cases_dir=root.parent)
    res = read_json(paths.subresult("msi")) or {}
    tid = getattr(task, "id", None)
    item = next((it for it in res.get("items") or [] if (it.get("vivisect_full") or {}).get("task_id") == tid), None)
    added = {"strings": 0, "capabilities": 0}
    if item is None:
        return added
    if cancelled:
        item["vivisect_full"] = {"status": "cancelled", "background": True, "task_id": tid,
                                 "detail": "complete analysis cancelled: the results are the fast analysis'"}
        write_subresult(paths, "msi", res)
        return added
    floss, capa = dict(floss or {}), dict(capa or {})
    new_strings = [x for x in (floss.pop("strings", None) or []) if isinstance(x, str)]
    have = set(item.get("floss_strings") or [])
    extra = [x for x in new_strings if x not in have]
    if extra:
        item["floss_strings"] = (list(item.get("floss_strings") or []) + extra)[:pe_mod._FLOSS_MAX_STRINGS]
        added["strings"] = len(extra)
    if floss.get("status") == "ok":
        fl = item.get("floss") or {}
        if fl.get("status") != "ok":            # the fast run failed: the complete one stands in for it
            fl = {k: v for k, v in floss.items() if k not in ("located", "strings")}
            fl["background"] = True
            fl["tight_skipped"] = True
            c = fl.get("counts") or {}
            fnd = pe_mod._finding("pe_floss_strings", "info",
                                  f"FLOSS extracted {len(new_strings)} string(s): {c.get('static', 0)} static, "
                                  f"{c.get('decoded', 0)} decoded, {c.get('stack', 0)} stack, "
                                  f"{c.get('tight', 0)} tight (complete analysis)", item.get("location") or loc)
            for lst in (item.setdefault("findings", []), res.setdefault("findings", [])):
                if not any(f.get("rule") == "pe_floss_strings" for f in lst):
                    lst.append(fnd)
        fl["completed"] = {"strings_added": len(extra), "counts": floss.get("counts") or {}}
        item["floss"] = fl
    if capa.get("status") == "ok":
        cur = item.get("capa") or {}
        names = {c.get("name") for c in cur.get("capabilities") or []}
        more = [c for c in capa.get("capabilities") or [] if c.get("name") not in names]
        if cur.get("status") != "ok":
            cur = {k: v for k, v in capa.items()}
            more = list(capa.get("capabilities") or [])
        else:
            cur["capabilities"] = list(cur.get("capabilities") or []) + more
        cur["completed"] = {"capabilities_added": len(more)}
        item["capa"] = cur
        added["capabilities"] = len(more)
        fnd = pe_mod.capa_findings({"capabilities": more}, item.get("location") or loc)
        if fnd:
            for lst in (item.setdefault("findings", []), res.setdefault("findings", [])):
                seen = {(f.get("rule"), f.get("detail")) for f in lst}
                lst.extend(f for f in fnd if (f.get("rule"), f.get("detail")) not in seen)
    item["vivisect_full"] = {
        "status": "ok" if floss.get("status") == "ok" or capa.get("status") == "ok" else
                  (floss.get("status") or capa.get("status") or "error"),
        "background": True, "task_id": tid, "strings_added": added["strings"],
        "capabilities_added": added["capabilities"],
        "detail": "; ".join(x for x in (f"FLOSS: {floss.get('detail') or floss.get('status')}" if floss else "",
                                        f"capa: {capa.get('detail') or capa.get('status')}" if capa else "") if x)[:400]}
    write_subresult(paths, "msi", res)
    if floss.get("status") == "ok":
        try:                                   # Code → Strings, with their function
            from .codeanalysis import case as code_case
            for mode in ("native", "go"):
                if code_case.load(paths.root, sha256, mode) is not None:
                    code_case.merge_full_floss(paths.root, sha256, mode, {**floss, "located": floss.get("located") or []},
                                               label="complete analysis", refresh=False)
                    break
        except Exception as exc:  # noqa: BLE001
            log.warning("complete analysis: code strings not merged for %s: %s", sha256[:12], exc)
    if capa.get("status") == "ok":
        try:
            from .codeanalysis import case as code_case
            code_case.recontrast_capa(root, sha256, item["capa"])
        except Exception as exc:  # noqa: BLE001
            log.warning("complete analysis: code capabilities not contrasted for %s: %s", sha256[:12], exc)
    try:
        _recompute_derived(paths)
    except Exception as exc:  # noqa: BLE001
        log.warning("complete analysis: IOCs / findings not recomputed for %s: %s", root.name, exc)
    return added


def start_priority(root: Path, path: Path, name: str, sha256: str, mode: str, addrs: list[int]) -> str:
    """FLOSS tight strings on the code analysis' priority functions of the case's own large
    binary, as a background task (or requested, in the analysis' child process): merged into
    Code → Strings (with their function) and the IOCs / findings when it ends. Returns the
    task id (provisional when requested)."""
    if _deferred():
        return _request(root, "priority", path=str(path), name=name, sha256=sha256, mode=mode,
                        addrs=[int(a) for a in addrs])
    return _start_priority(root, path, name, sha256, mode, addrs)


def _start_priority(root: Path, path: Path, name: str, sha256: str, mode: str, addrs: list[int],
                    task_id: str | None = None) -> str:
    from . import tasks
    from .codeanalysis import case as code_case
    from .parsers import pe as pe_mod

    def run(task: Any, cancel: Any) -> str:
        from . import heavyjobs
        def tight() -> dict[str, Any]:          # a first look: on the fast analysis when there is one
            tok = pe_mod._vivfast.set(pe_mod.fast_capable())
            try:
                return pe_mod.tight_on_functions(path, addrs, cancel=cancel)
            finally:
                pe_mod._vivfast.reset(tok)
        rec = heavyjobs.run(task, cancel, f"FLOSS tight on {len(addrs)} function(s)", tight,
                            progress=lambda: pe_mod.live_progress(path, "floss"))
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

    return _launch(root, "priority", sha256, name, "floss tight (background)",
                   f"FLOSS tight · {name} · priority functions (background)", run, task_id, mode)


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
