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


def analyze_object(root: Path, path: Path, sha256: str, mode: str, names: list[dict[str, Any]] | None,
                   progress=None) -> dict[str, Any]:
    from . import analyze, available
    if not available():
        return {"status": "unavailable",
                "detail": "Rizin + rz-ghidra not provisioned: Diagnostics → Retry (rizin), or "
                          "scripts/setup_portable_python.py --component rizin"}
    out = result_file(root, sha256, mode)
    try:
        s = analyze(path, mode=mode, names=names, out_file=out, lock_path=lock_path(root), progress=progress)
    except TimeoutError as exc:
        return {"status": "skipped", "detail": str(exc)}
    except Exception as exc:  # noqa: BLE001
        log.warning("code analysis failed on %s: %s", path.name, exc)
        return {"status": "failed", "detail": str(exc)[:300]}
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
        res["objects"].append(item)
    if not res["objects"]:
        res["status"] = "empty"
    return res


# --- views for the API ----------------------------------------------------------

_LIGHT = ("addr", "name", "size", "blocks", "complexity", "loops", "score", "rank", "categories", "reasons",
          "user", "named", "decompiled", "decompile_note", "instructions", "xor_ops")


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
    return {"summary": full.get("summary") or {}, "functions": light, "strings": full.get("strings") or [],
            "apis": full.get("apis") or []}


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
    if r.get("status") == "ok":
        full.setdefault("decompiled", {})[str(addr)] = {"code": r["code"], "status": "ok", "on_demand": True}
        for f in full.get("functions") or []:
            if f["addr"] == addr:
                f["decompiled"] = True
    if r.get("ops") and str(addr) not in (full.get("disasm") or {}):
        full.setdefault("disasm", {})[str(addr)] = r["ops"]
    result_file(root, sha256, mode).write_text(json.dumps(full), encoding="utf-8")
    return r
