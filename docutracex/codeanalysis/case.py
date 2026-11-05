"""Code analysis wired into a case.

* Go objects (Confirmed / Likely): names from the own pclntab parser (GoReSym
  output as fallback), run from ``golang.analyze_case``; the summary goes into
  each object of golang.json.
* Native PE / ELF / Mach-O objects that are not Go and not .NET: the ``code``
  module (code.json), same engine with Rizin's own analysis.

The full result of every object is ``<case>/code/<sha256>.<mode>.json``; the UI
reads it through the API. One code analysis at a time (a lock under the cases
folder), limited objects per case, and never a failure of the case.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

CODE_DIR = "code"
MAX_OBJECT_SIZE = 64 * 1024 * 1024


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def enabled() -> bool:
    return os.environ.get("DOCUTRACEX_CODE_AUTO", "1").strip().lower() not in ("0", "false", "no", "off")


def max_objects() -> int:
    return max(0, _env_int("DOCUTRACEX_CODE_OBJECTS", 3))


def lock_path(root: Path) -> Path:
    return root.parent / ".code-analysis.lock"


def result_file(root: Path, sha256: str, mode: str) -> Path:
    if not sha256 or any(c not in "0123456789abcdef" for c in sha256) or mode not in ("go", "native"):
        raise ValueError("bad code result id")
    return root / CODE_DIR / f"{sha256}.{mode}.json"


def is_dotnet(data: bytes) -> bool:
    """PE with a CLR (COM descriptor) data directory."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return False
    e = int.from_bytes(data[0x3C:0x40], "little")
    if data[e:e + 4] != b"PE\0\0":
        return False
    opt = e + 24
    magic = int.from_bytes(data[opt:opt + 2], "little")
    dd = opt + (96 if magic == 0x10B else 112)
    n = int.from_bytes(data[dd - 4:dd], "little")
    if n <= 14:
        return False
    va = int.from_bytes(data[dd + 14 * 8:dd + 14 * 8 + 4], "little")
    sz = int.from_bytes(data[dd + 14 * 8 + 4:dd + 14 * 8 + 8], "little")
    return bool(va and sz)


def go_names(data: bytes, ident: dict[str, Any], goresym_raw: Path | None = None) -> list[dict[str, Any]]:
    """Function names + ranges of a Go binary: own pclntab parser first, the
    GoReSym output (UserFunctions / StdFunctions) as fallback."""
    from ..golang import binfmt, detect
    fns: list[dict[str, Any]] = []
    pcln = ident.get("_pcln")
    if pcln:
        try:
            fns = detect.function_table(data, pcln, binfmt.parse(data))
        except Exception as exc:  # noqa: BLE001
            log.warning("own Go function table failed: %s", exc)
    if not fns and goresym_raw is not None and goresym_raw.is_file():
        try:
            d = json.loads(goresym_raw.read_text(encoding="utf-8"))
            for key in ("UserFunctions", "StdFunctions"):
                for f in d.get(key) or []:
                    if f.get("Start") and f.get("FullName"):
                        fns.append({"name": f["FullName"], "start": int(f["Start"]), "end": int(f.get("End") or f["Start"] + 1)})
        except (OSError, ValueError, TypeError):
            pass
    out = []
    for f in fns:
        n = f["name"]
        out.append({"name": n, "start": f["start"], "end": f["end"],
                    "user": "." in n and not n.startswith(detect.NOT_USER), "named": True})
    return out


CACHE_DIR = ".code-cache"
CACHE_MAX_MB = _env_int("DOCUTRACEX_CODE_CACHE_MB", 2048)


def _cache_on() -> bool:
    return os.environ.get("DOCUTRACEX_CODE_CACHE", "1").strip().lower() not in ("0", "false", "no", "off")


def _cache_key(sha256: str, mode: str) -> str:
    """Same binary + same engine + same limits → same result: reuse it."""
    from . import BUDGET_S, DECOMPILE_N, ENGINE_VERSION, INVENTORY_MAX, MAX_S, MEM_MB
    sig = hashlib.sha256(f"{ENGINE_VERSION}|{BUDGET_S}|{MAX_S}|{MEM_MB}|{DECOMPILE_N}|{INVENTORY_MAX}".encode()).hexdigest()[:12]
    return f"{sha256}.{mode}.{sig}.json"


def _cache_get(root: Path, sha256: str, mode: str) -> Path | None:
    if not _cache_on():
        return None
    p = root.parent / CACHE_DIR / _cache_key(sha256, mode)
    return p if p.is_file() else None


def _cache_put(root: Path, sha256: str, mode: str, src: Path) -> None:
    """Keep the raw engine result (before the per-case enrichment) for other cases; oldest out first."""
    if not _cache_on():
        return
    import shutil
    d = root.parent / CACHE_DIR
    try:
        d.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, d / _cache_key(sha256, mode))
        files = sorted(d.glob("*.json"), key=lambda x: x.stat().st_mtime)
        total = sum(f.stat().st_size for f in files)
        while files and total > CACHE_MAX_MB * 1024 * 1024:
            f = files.pop(0)
            total -= f.stat().st_size
            f.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("code-analysis cache: %s", exc)


def analyze_object(root: Path, path: Path, sha256: str, mode: str, names: list[dict[str, Any]] | None,
                   progress=None) -> dict[str, Any]:
    from . import analyze, available
    out = result_file(root, sha256, mode)
    hit = _cache_get(root, sha256, mode)
    if hit is not None:                                        # analysed before in another case: no Rizin run
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            full = json.loads(hit.read_text(encoding="utf-8"))
            s = dict(full.get("summary") or {})
            s["cached"] = True
            full["summary"] = s
            out.write_text(json.dumps(full), encoding="utf-8")
            hit.touch()
            s["sha256"] = sha256
            s["mode"] = mode
            return s
        except (OSError, ValueError) as exc:
            log.warning("code-analysis cache unreadable (%s): analysing again", exc)
    if not available():
        return {"status": "unavailable",
                "detail": "Rizin + rz-ghidra not provisioned: Diagnostics → Retry (rizin), or "
                          "scripts/setup_portable_python.py --component rizin"}
    try:
        s = analyze(path, mode=mode, names=names, out_file=out, lock_path=lock_path(root), progress=progress)
    except TimeoutError as exc:
        return {"status": "skipped", "detail": str(exc)}
    except Exception as exc:  # noqa: BLE001
        log.warning("code analysis failed on %s: %s", path.name, exc)
        return {"status": "failed", "detail": str(exc)[:300]}
    if s.get("status") == "ok":                                # partial results are not reused: they may finish next time
        _cache_put(root, sha256, mode, out)
    s["sha256"] = sha256
    s["mode"] = mode
    return s


def analyze_native_case(root: Path, original: Path, nested_tree: list[dict[str, Any]],
                        go_shas: set[str] | None = None) -> dict[str, Any]:
    """The ``code`` module: native (non-Go, non-.NET) PE / ELF / Mach-O objects."""
    from .. import golang
    from . import available
    res: dict[str, Any] = {"module": "code", "objects": [], "warnings": [], "status": "ok"}
    if not available():
        res["status"] = "unavailable"
        res["warnings"].append("Rizin + rz-ghidra not provisioned: Diagnostics → Retry (rizin)")
        return res
    seen: set[str] = set(go_shas or ())
    done = 0
    for t in golang.targets(root, original, nested_tree):
        p: Path = t["path"]
        try:
            if p.stat().st_size > MAX_OBJECT_SIZE:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        sha = hashlib.sha256(data).hexdigest()
        if sha in seen:
            continue
        seen.add(sha)
        item = {"label": t["label"], "stored_path": t["stored_path"], "original": bool(t.get("original")),
                "sha256": sha, "size": len(data)}
        if t.get("clean_child"):
            item["code"] = {"status": "skipped", "clean_child": t["clean_child"],
                            "detail": f"padded / packed: analysed in its clean child {t['clean_child']}"}
            res["objects"].append(item)
            continue
        if is_dotnet(data):
            item["code"] = {"status": "skipped", "detail": ".NET assembly: native code analysis does not apply"}
            res["objects"].append(item)
            continue
        if done >= max_objects():
            item["code"] = {"status": "skipped", "detail": f"only {max_objects()} objects per case are analysed"}
            res["objects"].append(item)
            continue
        done += 1
        item["code"] = analyze_object(root, p, sha, "native", None)
        if item["code"].get("status") in ("ok", "partial"):
            try:
                res.setdefault("_children", []).extend(enrich(root, p, data, sha, "native", item))
                res.setdefault("findings", []).extend(item.pop("findings", None) or [])
            except Exception as exc:  # noqa: BLE001
                log.warning("resources / strings step failed on %s: %s", item["label"], exc)
        res["objects"].append(item)
    if not res["objects"]:
        res["status"] = "empty"
    return res


# --- views for the API ----------------------------------------------------------

_LIGHT = ("addr", "name", "size", "blocks", "complexity", "loops", "score", "rank", "categories", "reasons",
          "user", "named", "decompiled", "decompile_note", "instructions", "xor_ops", "traits",
          "indirect_calls")


def load(root: Path, sha256: str, mode: str) -> dict[str, Any] | None:
    f = result_file(root, sha256, mode)
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def overview(full: dict[str, Any]) -> dict[str, Any]:
    """Everything but the per-function bodies (the Functions / Strings / APIs lists)."""
    fns = full.get("functions") or []
    by_addr = {f["addr"]: f["name"] for f in fns}
    light = []
    for f in fns:
        x = {k: f.get(k) for k in _LIGHT}
        x["callers"] = len(f.get("callers") or [])
        x["callees"] = len([c for c in f.get("calls") or [] if c in by_addr]) or len(f.get("callee_names") or [])
        x["strings"] = len(f.get("strings") or [])
        light.append(x)
    strings = [dict(x, source=x.get("source") or "code") for x in full.get("strings") or []]
    strings += full.get("floss") or []
    for g in (full.get("garble") or {}).get("strings") or []:
        strings.append({"value": g["value"][:500], "function": g["function"], "source": "Garble (emulated)",
                        "addr": g["addr"]})
    for pt in (full.get("crypto") or {}).get("plaintexts") or []:
        if pt.get("text"):
            strings.append({"value": pt["text"][:500], "function": pt["function"], "source": "decrypted",
                            "addr": pt.get("data_va")})
    return {"summary": full.get("summary") or {}, "functions": light, "strings": strings,
            "crypto": full.get("crypto") or {}, "capabilities": full.get("capabilities") or {},
            "garble": full.get("garble") or {},
            "floss_priority": full.get("floss_priority"), "floss_full": full.get("floss_full"),
            "apis": full.get("apis") or [], "resources": full.get("resources") or {},
            "dependencies": full.get("dependencies")}


def function_view(full: dict[str, Any], addr: int) -> dict[str, Any] | None:
    fns = full.get("functions") or []
    by_addr = {f["addr"]: f for f in fns}
    f = by_addr.get(addr)
    if f is None:
        return None
    out = dict(f)
    out["callers"] = [{"addr": a, "name": by_addr[a]["name"] if a in by_addr else f"{a:#x}"}
                      for a in f.get("callers") or []][:300]
    known = [{"addr": a, "name": by_addr[a]["name"]} for a in f.get("calls") or [] if a in by_addr]
    out["callees"] = known
    out["callee_names"] = f.get("callee_names") or []
    out["interface_targets"] = [{"addr": t, "name": by_addr[t]["name"] if t in by_addr else n}
                                for ic in full.get("interface_calls") or [] if ic["from"] == addr
                                for t, n in zip(ic["targets"], ic["methods"])][:100]
    out["spawns"] = [{"addr": a, "name": by_addr[a]["name"] if a in by_addr else f"{a:#x}"} for a in f.get("spawns") or []]
    out["decompiled"] = (full.get("decompiled") or {}).get(str(addr))
    out["ops"] = (full.get("disasm") or {}).get(str(addr))
    out.pop("calls", None)
    return out


def locate(root: Path, original: Path, nested_tree: list[dict[str, Any]], sha256: str) -> Path | None:
    from .. import golang
    for t in golang.targets(root, original, nested_tree):
        try:
            if hashlib.sha256(t["path"].read_bytes()).hexdigest() == sha256:
                return t["path"]
        except OSError:
            continue
    return None


def decompile_on_demand(root: Path, path: Path, sha256: str, mode: str, addr: int) -> dict[str, Any]:
    from . import decompile_one
    full = load(root, sha256, mode)
    if full is None:
        raise FileNotFoundError("no code analysis for this object")
    names = None
    if mode == "go":
        from ..golang import detect
        data = path.read_bytes()
        names = go_names(data, detect.identify(data))
    r = decompile_one(path, addr, mode=mode, names=names, lock_path=lock_path(root))
    if r.get("status") == "ok" or r.get("ops"):
        _merge(root, sha256, mode, {addr: r if r.get("status") == "ok" else {"ops": r["ops"]}})
    return r


# --- "Decompile all" in the background ----------------------------------------------
# One job per binary: chunks of functions decompiled in one Rizin session each,
# saved after every chunk (the Code view shows them as they land). The state is
# kept in memory and in <sha>.<mode>.batch.json, so the UI can be left and
# re-opened; a single on-demand decompile still interleaves between chunks.
import threading as _threading  # noqa: E402

BATCH_CHUNK = 5
BATCH_MAX = 400
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = _threading.Lock()
_write_lock = _threading.Lock()


def _batch_file(root: Path, sha256: str, mode: str) -> Path:
    return result_file(root, sha256, mode).with_suffix(".batch.json")


def batch_targets(full: dict[str, Any], which: str) -> list[int]:
    """Functions without pseudocode: ``large`` = the ones the automatic pass
    left for on demand (too large / pass stopped), ``all`` = every program
    function still without pseudocode, by priority."""
    fns = [f for f in full.get("functions") or [] if f.get("user") and not f.get("decompiled")]
    if which == "large":
        fns = [f for f in fns if f.get("decompile_note")]
    fns.sort(key=lambda f: (f.get("rank") or 10 ** 6))
    return [f["addr"] for f in fns][:BATCH_MAX]


def batch_status(root: Path, sha256: str, mode: str) -> dict[str, Any]:
    key = str(_batch_file(root, sha256, mode))
    with _jobs_lock:
        job = _jobs.get(key)
        if job:
            return {k: v for k, v in job.items() if not k.startswith("_")}
    try:
        st = json.loads(_batch_file(root, sha256, mode).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"state": "idle"}
    if st.get("state") in ("running", "cancelling"):
        st["state"] = "interrupted"          # the app restarted under it
    return st


def _save_batch(root: Path, sha256: str, mode: str, job: dict[str, Any]) -> None:
    try:
        _batch_file(root, sha256, mode).write_text(
            json.dumps({k: v for k, v in job.items() if not k.startswith("_")}), encoding="utf-8")
    except OSError:
        pass


def _merge(root: Path, sha256: str, mode: str, results: dict[int, dict[str, Any]]) -> None:
    with _write_lock:
        full = load(root, sha256, mode)
        if full is None:
            return
        for addr, r in results.items():
            if r.get("status") == "ok":
                full.setdefault("decompiled", {})[str(addr)] = {"code": r["code"], "status": "ok", "on_demand": True}
                for f in full.get("functions") or []:
                    if f["addr"] == addr:
                        f["decompiled"] = True
            elif r.get("status") == "failed":
                full.setdefault("decompiled", {}).setdefault(str(addr), {"status": "failed", "detail": r.get("detail", "")})
            if r.get("ops") and str(addr) not in (full.get("disasm") or {}):
                full.setdefault("disasm", {})[str(addr)] = r["ops"]
        result_file(root, sha256, mode).write_text(json.dumps(full), encoding="utf-8")


def start_batch(root: Path, path: Path, sha256: str, mode: str, which: str = "large") -> dict[str, Any]:
    from . import decompile_many
    full = load(root, sha256, mode)
    if full is None:
        raise FileNotFoundError("no code analysis for this object")
    key = str(_batch_file(root, sha256, mode))
    with _jobs_lock:
        cur = _jobs.get(key)
        if cur and cur["state"] in ("running", "cancelling"):
            return {k: v for k, v in cur.items() if not k.startswith("_")}
        todo = batch_targets(full, which)
        job: dict[str, Any] = {"state": "running" if todo else "completed", "which": which, "total": len(todo),
                               "done": 0, "ok": 0, "failed": 0, "current": None, "started": time.time(),
                               "finished": None if todo else time.time(), "error": None, "_cancel": False}
        _jobs[key] = job
    _save_batch(root, sha256, mode, job)
    if not todo:
        return {k: v for k, v in job.items() if not k.startswith("_")}

    def run() -> None:
        try:
            names = _go_names_for(path, mode)
            for i in range(0, len(todo), BATCH_CHUNK):
                if job["_cancel"]:
                    job["state"] = "cancelled"
                    break
                chunk = todo[i:i + BATCH_CHUNK]
                job["current"] = [hex(a) for a in chunk]
                res = decompile_many(path, chunk, mode=mode, names=names, lock_path=lock_path(root))
                _merge(root, sha256, mode, res)
                job["done"] += len(chunk)
                job["ok"] += sum(1 for r in res.values() if r.get("status") == "ok")
                job["failed"] += sum(1 for r in res.values() if r.get("status") != "ok")
                _save_batch(root, sha256, mode, job)
            else:
                job["state"] = "completed"
        except Exception as exc:  # noqa: BLE001  (a failed batch never takes the app down)
            log.warning("decompile-all failed on %s: %s", sha256[:12], exc)
            job["state"], job["error"] = "failed", str(exc)[:300]
        job["current"], job["finished"] = None, time.time()
        _save_batch(root, sha256, mode, job)

    _threading.Thread(target=run, name=f"decompile-all-{sha256[:8]}", daemon=True).start()
    return {k: v for k, v in job.items() if not k.startswith("_")}


def cancel_batch(root: Path, sha256: str, mode: str) -> dict[str, Any]:
    key = str(_batch_file(root, sha256, mode))
    with _jobs_lock:
        job = _jobs.get(key)
        if job and job["state"] == "running":
            job["_cancel"] = True
            job["state"] = "cancelling"
    return batch_status(root, sha256, mode)


def _go_names_for(path: Path, mode: str) -> list[dict[str, Any]] | None:
    if mode != "go":
        return None
    from ..golang import detect
    data = path.read_bytes()
    return go_names(data, detect.identify(data))


def cfg_on_demand(root: Path, path: Path, sha256: str, mode: str, addr: int) -> dict[str, Any]:
    """CFG of one function, computed once and kept in the result file."""
    from . import cfg_one
    full = load(root, sha256, mode)
    if full is None:
        raise FileNotFoundError("no code analysis for this object")
    cached = (full.get("cfg") or {}).get(str(addr))
    if cached:
        return cached
    r = cfg_one(path, addr, mode=mode, names=_go_names_for(path, mode), lock_path=lock_path(root))
    if r.get("status") == "ok":
        full.setdefault("cfg", {})[str(addr)] = r
        result_file(root, sha256, mode).write_text(json.dumps(full), encoding="utf-8")
    return r


SENSITIVE = ("network", "exec", "process", "persistence", "crypto")


def itab_calls(full: dict[str, Any], reader, names: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Go interface calls resolved statically. A method call through an
    interface loads an itab {inter, _type, hash, _, fun[]} and calls one of its
    ``fun`` slots through a register; when a function with indirect calls
    points at such an itab, its slots are the concrete methods it may call."""
    starts = {n["start"]: n["name"] for n in names}
    out = []
    for f in full.get("functions") or []:
        if not f.get("indirect_calls"):
            continue
        for a, _n in f.get("data_refs") or []:
            head = reader.at(a, 16)
            if len(head) < 16:
                continue
            inter, typ = int.from_bytes(head[:8], "little"), int.from_bytes(head[8:], "little")
            if not inter or not typ or not reader.at(inter, 8) or not reader.at(typ, 8):
                continue
            targets = []
            for i in range(32):
                w = reader.at(a + 0x18 + 8 * i, 8)
                v = int.from_bytes(w, "little") if len(w) == 8 else 0
                if v not in starts:
                    break
                targets.append(v)
            if targets:
                out.append({"from": f["addr"], "itab": a, "targets": targets,
                            "methods": [starts[t] for t in targets]})
    return out[:2000]


def graph(full: dict[str, Any], max_paths: int = 25) -> dict[str, Any]:
    """The program call graph: analysed functions as nodes, direct calls and
    goroutine launches as edges, the calls into sensitive library code as leaf
    nodes, the roots (entry / init / uncalled program code) and the shortest
    path from a root to every sensitive function."""
    from collections import deque

    from .priority import CATEGORIES
    fns = full.get("functions") or []
    mode = (full.get("summary") or {}).get("mode", "native")
    by = {f["addr"]: f for f in fns}
    crypto_fns = {x["name"] for x in (full.get("crypto") or {}).get("functions") or []}
    crypto_fns |= {x["function"] for x in (full.get("crypto") or {}).get("plaintexts") or []}
    nodes = [{"id": f["addr"], "name": f["name"], "score": f.get("score", 0),
              "categories": (f.get("categories") or []) + (["crypto"] if f["name"] in crypto_fns
                                                           and "crypto" not in (f.get("categories") or []) else []),
              "traits": f.get("traits") or [], "user": f.get("user", True), "indirect": f.get("indirect_calls", 0)}
             for f in fns]
    edges = []
    ext: dict[str, dict[str, Any]] = {}
    for f in fns:
        for c in f.get("calls") or []:
            if c in by and c != f["addr"]:
                edges.append({"from": f["addr"], "to": c, "kind": "call"})
        for c in f.get("spawns") or []:
            if c in by:
                edges.append({"from": f["addr"], "to": c, "kind": "goroutine"})
    for ic in full.get("interface_calls") or []:              # possible targets of an interface call
        for t in ic["targets"]:
            if t in by and t != ic["from"]:
                edges.append({"from": ic["from"], "to": t, "kind": "interface"})
    for f in fns:
        known = {by[c]["name"] for c in f.get("calls") or [] if c in by}
        for n in f.get("callee_names") or []:
            if n in known:
                continue
            low = n.lower()
            cats = [k for k, c in CATEGORIES.items()
                    if (mode == "go" and n.startswith(c.get("go", ()))) or
                    (low.startswith("imp.") and any(a in low for a in c.get("api", ())))]
            if cats:
                key = "ext:" + n
                ext.setdefault(key, {"id": key, "name": n, "score": 0, "categories": cats, "traits": ["library"],
                                     "user": False, "external": True})
                edges.append({"from": f["addr"], "to": key, "kind": "call"})
    nodes += list(ext.values())
    callers: dict[Any, set] = {}
    for e in edges:
        callers.setdefault(e["to"], set()).add(e["from"])
    roots = [f["addr"] for f in fns if {"entry", "init"} & set(f.get("traits") or [])]
    roots += [f["addr"] for f in fns if f.get("user") and f["addr"] not in callers and f["addr"] not in roots]
    adj: dict[Any, list] = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])
    prev: dict[Any, Any] = {r: None for r in roots}
    q = deque(roots)
    while q:
        u = q.popleft()
        for v in adj.get(u, []):
            if v not in prev:
                prev[v] = u
                q.append(v)
    targets = [n for n in nodes if set(n["categories"]) & set(SENSITIVE)]
    targets.sort(key=lambda n: (not n.get("external", False), -n["score"]))
    paths = []
    for t in targets:
        if t["id"] not in prev:
            paths.append({"target": t["id"], "path": None, "note": "not reached from an entry point (indirect call, "
                                                                    "callback or interface method?)"})
        else:
            p, cur = [], t["id"]
            while cur is not None:
                p.append(cur)
                cur = prev[cur]
            paths.append({"target": t["id"], "path": p[::-1]})
        if len(paths) >= max_paths:
            break
    return {"nodes": nodes, "edges": edges, "roots": roots, "paths": paths,
            "unresolved": sum(f.get("indirect_calls", 0) for f in fns)}


# --- phase 6: FLOSS strings per function, embedded resources, IOCs ---------------

def _paths(root: Path):
    from ..storage import CasePaths
    return CasePaths(root.name, cases_dir=root.parent)


def binary_item(root: Path, stored_path: str, original: bool) -> dict[str, Any]:
    """The binary-module item (FLOSS, capa…) of one object: from the case
    (original) or from its nested view."""
    from ..storage import read_json
    try:
        paths = _paths(root)
    except Exception:  # noqa: BLE001
        return {}
    mods: dict[str, Any] = {}
    if original:
        mods = {"msi": read_json(paths.subresult("msi")) or {}}
    else:
        def find(nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
            for n in nodes or []:
                if n.get("stored_path") == stored_path:
                    return n
                hit = find(n.get("children") or [])
                if hit:
                    return hit
            return None
        node = find((read_json(paths.subresult("nested")) or {}).get("tree") or [])
        if node and node.get("view_id"):
            from ..nested import view_path
            mods = (read_json(view_path(paths, node["view_id"])) or {}).get("modules") or {}
    for it in (mods.get("msi") or {}).get("items") or []:
        if it.get("floss") or it.get("capa"):
            return it
    return {}


def floss_located(root: Path, stored_path: str, original: bool) -> list[dict[str, Any]]:
    """FLOSS decoded / stack / tight strings (with their function) of one object."""
    return (binary_item(root, stored_path, original).get("floss") or {}).get("located") or []


def attach_floss(full: dict[str, Any], located: list[dict[str, Any]]) -> int:
    """Put FLOSS strings on the function that builds / decodes them."""
    fns = sorted(full.get("functions") or [], key=lambda f: f["addr"])
    starts = [f["addr"] for f in fns]
    import bisect
    n = 0
    out = []
    for s in located:
        fva = s.get("function") or s.get("routine")
        fn = None
        if isinstance(fva, int) and fns:
            i = bisect.bisect_right(starts, fva) - 1
            if i >= 0 and fva < fns[i]["addr"] + max(fns[i].get("size") or 1, 1):
                fn = fns[i]
        rec = {"value": s["string"], "source": f"FLOSS {s.get('kind', '')}", "function": fn["name"] if fn else "",
               "addr": fva}
        out.append(rec)
        if fn is not None:
            fn.setdefault("floss", []).append({"value": s["string"], "kind": s.get("kind", "")})
            n += 1
    full["floss"] = out[:5000]
    return n


def priority_functions(full: dict[str, Any], limit: int) -> list[int]:
    """The functions most likely to build or decode strings: the analyst's code
    (not runtime / library) with loops or XOR, best ranked first."""
    fns = [f for f in full.get("functions") or []
           if f.get("user") is not False and ((f.get("loops") or 0) > 0 or (f.get("xor_ops") or 0) > 0)]
    fns.sort(key=lambda f: (-(1 if (f.get("xor_ops") or 0) > 0 and (f.get("loops") or 0) > 0 else 0),
                            f.get("rank") or 10 ** 6))
    return [int(f["addr"]) for f in fns[:limit] if isinstance(f.get("addr"), int)]


def priority_tight(root: Path, path: Path, full: dict[str, Any], item: dict[str, Any]) -> list[dict[str, Any]]:
    """When FLOSS skipped tight strings on a large file, run them on the
    priority functions only. Returns located strings (kind ``tight (priority)``)."""
    floss = binary_item(root, item.get("stored_path") or "", bool(item.get("original"))).get("floss") or {}
    if not floss.get("tight_skipped"):
        return []
    from ..parsers import pe as _pe
    addrs = priority_functions(full, _pe.PRIORITY_TIGHT_MAX)
    rec = _pe.tight_on_functions(path, addrs)
    located = [dict(s, kind="tight (priority functions)") for s in rec.pop("located", None) or []
               if s.get("kind") == "tight"]
    full["floss_priority"] = {"status": rec.get("status"), "detail": rec.get("detail", ""),
                              "functions": len(addrs), "strings": len(located), "cached": bool(rec.get("cached"))}
    return located


def _floss_job_file(root: Path, sha256: str, mode: str) -> Path:
    return result_file(root, sha256, mode).with_suffix(".floss.json")


def full_floss_status(root: Path, sha256: str, mode: str) -> dict[str, Any]:
    key = str(_floss_job_file(root, sha256, mode))
    with _jobs_lock:
        job = _jobs.get(key)
        if job:
            return dict(job)
    try:
        st = json.loads(_floss_job_file(root, sha256, mode).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"state": "idle"}
    if st.get("state") == "running":
        st["state"] = "interrupted"
    return st


def merge_full_floss(root: Path, sha256: str, mode: str, rec: dict[str, Any]) -> int:
    """Adds the strings of a full FLOSS run the code result does not have yet
    (tight strings of a large file, mostly) to the Strings list and to their
    function. Returns how many were added."""
    with _write_lock:
        full = load(root, sha256, mode)
        if full is None:
            return 0
        have = {(x.get("value"), x.get("addr")) for x in full.get("floss") or []}
        new = [dict(s, kind=f"{s.get('kind', '')} (full run)") for s in rec.get("located") or []
               if (s.get("string"), s.get("function") or s.get("routine")) not in have]
        tmp = {"functions": full.get("functions") or []}      # same function dicts: linked in place
        attach_floss(tmp, new)
        full["floss"] = ((full.get("floss") or []) + tmp["floss"])[:5000]
        full["floss_full"] = {"status": rec.get("status"), "detail": rec.get("detail", ""), "added": len(new)}
        result_file(root, sha256, mode).write_text(json.dumps(full), encoding="utf-8")
        return len(new)


def start_full_floss(root: Path, path: Path, sha256: str, mode: str) -> dict[str, Any]:
    """Full FLOSS (tight strings on every function) in the background, for a
    large file whose automatic run skipped them."""
    from ..parsers import pe as _pe
    if load(root, sha256, mode) is None:
        raise FileNotFoundError("no code analysis for this object")
    f = _floss_job_file(root, sha256, mode)
    key = str(f)
    with _jobs_lock:
        cur = _jobs.get(key)
        if cur and cur["state"] == "running":
            return dict(cur)
        job: dict[str, Any] = {"state": "running", "started": time.time(), "finished": None, "added": 0,
                               "detail": "", "error": None}
        _jobs[key] = job

    def save() -> None:
        try:
            f.write_text(json.dumps(job), encoding="utf-8")
        except OSError:
            pass
    save()

    def run() -> None:
        try:
            rec = _pe.full_floss(path)
            if rec.get("status") != "ok":
                job["state"], job["error"] = "failed", str(rec.get("detail") or rec.get("status"))[:300]
            else:
                job["added"] = merge_full_floss(root, sha256, mode, rec)
                job["detail"] = rec.get("detail", "")
                job["state"] = "completed"
        except Exception as exc:  # noqa: BLE001
            log.warning("full FLOSS failed on %s: %s", sha256[:12], exc)
            job["state"], job["error"] = "failed", str(exc)[:300]
        job["finished"] = time.time()
        save()

    _threading.Thread(target=run, name=f"floss-full-{sha256[:8]}", daemon=True).start()
    return dict(job)


RES_DIR = "code_resources"
MAX_CHILDREN = 60


def enrich(root: Path, path: Path, data: bytes, sha256: str, mode: str, item: dict[str, Any], *,
           names: list[dict[str, Any]] | None = None, buildinfo: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Phase 6 on one analysed object: FLOSS strings per function, embedded
    resources (go:embed, certificates / keys, compressed data) written under
    ``extracted/code_resources/`` for the nested analysis, the declared vs
    recovered Go dependencies and the code strings as IOC sources. Returns the
    nested children to analyse ({path, filename, origin, recipe, source})."""
    from ..golang import binfmt
    from . import resources
    full = load(root, sha256, mode)
    if full is None:
        return []
    label = item.get("label") or path.name
    try:
        located = list(floss_located(root, item.get("stored_path") or "", bool(item.get("original"))))
        try:
            located += priority_tight(root, path, full, item)
        except Exception as exc:  # noqa: BLE001
            log.warning("FLOSS tight on priority functions failed on %s: %s", label, exc)
        n = attach_floss(full, located)
    except Exception as exc:  # noqa: BLE001
        log.warning("FLOSS linking failed on %s: %s", label, exc)
        n = 0
    try:
        binf = binfmt.parse(data)
        res = resources.scan(data, binf, mode)
    except Exception as exc:  # noqa: BLE001
        log.warning("resource scan failed on %s: %s", label, exc)
        res = {"embed": [], "certificates": [], "compressed": []}
    out_dir = root / "extracted" / RES_DIR / sha256[:12]
    children: list[dict[str, Any]] = []

    def keep(raw: bytes, name: str, origin: str, recipe: list[str]) -> str:
        safe = re.sub(r"[^\w.\-]+", "_", name).strip("._")[:80] or "blob"
        fn = f"{hashlib.sha256(raw).hexdigest()[:8]}_{safe}"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / fn).write_bytes(raw)
        except OSError:
            return ""
        rel = (out_dir / fn).relative_to(root).as_posix()
        if len(children) < MAX_CHILDREN:
            children.append({"path": str(out_dir / fn), "filename": fn, "origin": origin, "recipe": recipe,
                             "source": "code-resources"})
        return rel
    for fs in res["embed"]:
        for f in fs["files"]:
            raw = f.pop("data", b"")
            if raw and not f["dir"]:
                f["stored_path"] = keep(raw, f["name"].rsplit("/", 1)[-1], f"go:embed {f['name']} in {label}",
                                        ["go-embed", f["name"]])
    for c in res["compressed"]:
        raw = c.pop("data", b"")
        if raw and c["decompressed_size"] >= 1024:
            c["stored_path"] = keep(raw, f"{c['type']}_{c['offset']:x}.bin",
                                    f"{c['type']} stream at 0x{c['offset']:x} in {label}", ["decompress", c["type"]])
    full["resources"] = res
    # phase 8: algorithms, crypto functions, key material, static decryption
    try:
        from . import _Reader
        from . import crypto as _crypto
        cr = _crypto.analyze(full, data, binf, _Reader(data), names, mode)
        for pt in cr["plaintexts"]:
            raw = pt["plaintext"]
            if len(raw) >= 1024 or raw[:2] == b"MZ" or raw[:4] == b"\x7fELF":
                pt["stored_path"] = keep(raw, f"decrypted_{pt['data_va']:x}.bin",
                                         f"{pt['method']} in {pt['function']} ({label})", ["crypto", pt["method"]])
        full["crypto"] = _crypto.jsonable(cr)
    except Exception as exc:  # noqa: BLE001
        log.warning("crypto step failed on %s: %s", label, exc)
        full["crypto"] = {"algorithms": [], "constants": [], "functions": [], "keys": [], "plaintexts": [],
                          "not_recoverable": [], "error": str(exc)[:300]}
    # interface calls: an itab loaded before an indirect call gives its concrete methods
    if mode == "go":
        try:
            from . import _Reader
            full["interface_calls"] = itab_calls(full, _Reader(data), names or [])
        except Exception as exc:  # noqa: BLE001
            log.warning("interface resolution failed on %s: %s", label, exc)
    # phase 7: Garble literal strings, rebuilt by emulating only their decoding closures
    try:
        from . import garble as _garble
        full["garble"] = _garble.recover(full, data, binfmt.parse(data), names or [], mode)
        by_name = {f["name"]: f for f in full.get("functions") or []}
        for g in full["garble"].get("strings") or []:
            fn = by_name.get(g["function"])
            if fn is not None:
                fn.setdefault("floss", []).append({"value": g["value"], "kind": "Garble, emulated"})
    except Exception as exc:  # noqa: BLE001
        log.warning("Garble step failed on %s: %s", label, exc)
        full["garble"] = {"status": "failed", "detail": str(exc)[:300], "strings": []}
    # phase 9: capabilities from correlated evidence, contrasted with capa
    try:
        from . import capabilities as _caps
        capa = binary_item(root, item.get("stored_path") or "", bool(item.get("original"))).get("capa")
        full["capabilities"] = _caps.analyze(full, graph(full), capa)
        item["findings"] = _caps.findings(full["capabilities"], label)
    except Exception as exc:  # noqa: BLE001
        log.warning("capabilities step failed on %s: %s", label, exc)
        full["capabilities"] = {"capabilities": [], "error": str(exc)[:300]}
    summary = {"floss_linked": n, "floss": len(full.get("floss") or []),
               "floss_priority_tight": (full.get("floss_priority") or {}).get("strings"),
               "embed_files": sum(len(fs["files"]) for fs in res["embed"]),
               "certificates": sum(1 for c in res["certificates"] if not c.get("private")),
               "private_keys": sum(1 for c in res["certificates"] if c.get("private")),
               "compressed": len(res["compressed"]),
               "crypto_algorithms": len(full["crypto"]["algorithms"]), "crypto_functions": len(full["crypto"]["functions"]),
               "keys": len(full["crypto"]["keys"]), "decrypted": len(full["crypto"]["plaintexts"]),
               "capabilities": len(full["capabilities"].get("capabilities") or []),
               "garble_strings": len((full.get("garble") or {}).get("strings") or []),
               "capabilities_high": sum(1 for c in full["capabilities"].get("capabilities") or []
                                        if c["confidence"] == "high")}
    if mode == "go":
        from . import resources as _r
        fnames = [x["name"] for x in names or []]
        full["dependencies"] = _r.go_dependencies(buildinfo, fnames)
        summary["deps_without_code"] = len(full["dependencies"]["without_code"])
        summary["undeclared_packages"] = len(full["dependencies"]["undeclared"])
    result_file(root, sha256, mode).write_text(json.dumps(full), encoding="utf-8")
    item.setdefault("code", {})["resources"] = summary
    # strings the code uses (and FLOSS recovered) → the IOC extractor, with their function
    src = []
    for s in (full.get("strings") or [])[:3000]:
        src.append({"location": f"{label} › {s.get('function') or ''}", "text": s.get("value") or ""})
    for s in (full.get("floss") or [])[:3000]:
        src.append({"location": f"{label} › {s.get('function') or 'FLOSS'} ({s.get('source')})", "text": s["value"]})
    for g in (full.get("garble") or {}).get("strings") or []:
        src.append({"location": f"{label} › {g['function']} (Garble literal, emulated)", "text": g["value"]})
    for pt in full["crypto"]["plaintexts"]:
        if pt.get("text"):
            src.append({"location": f"{label} › {pt['function']} (decrypted: {pt['method']})", "text": pt["text"]})
    for c in res["certificates"]:
        if c.get("subject"):
            src.append({"location": f"{label} › certificate @0x{c['offset']:x}", "text": f"{c['subject']} {c['issuer']}"})
    item["ioc_sources"] = [x for x in src if x["text"].strip()]
    return children
