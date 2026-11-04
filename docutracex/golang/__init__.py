"""Go Malware Intelligence — static analysis of Go binaries.

Phase 1 (this module): identify every Go binary of a case — the original and
every nested object (unpacked, extracted, dropped) — with the own parser
(BuildInfo, pclntab, moduledata, build IDs, runtime, stripped / packed /
Garble traits) contrasted with GoReSym when it is provisioned.

Rules for the whole module: nothing in the sample is executed or emulated; a
failing or missing tool is a warning and the rest carries on; every result
keeps its source and offset; per-object size and time limits; one analysis
per distinct SHA-256.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

MAX_OBJECTS = 200
MAX_SIZE = 256 * 1024 * 1024
NATIVE_MAGICS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                 b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe")
GORESYM_FROM = ("Confirmed", "Likely", "Suspected", "Inconclusive")


def _native(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return any(head.startswith(m) for m in NATIVE_MAGICS)


def targets(root: Path, original: Path, nested_tree: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The original and every nested PE / ELF / Mach-O object (unique by path)."""
    out: list[dict[str, Any]] = []
    if _native(original):
        try:
            rel = original.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = ""
        out.append({"label": original.name, "path": original, "stored_path": rel, "chain": "", "original": True})
    seen: set[str] = set()

    def walk(nodes: list[dict[str, Any]], chain: str) -> None:
        for n in nodes or []:
            name = n.get("filename") or ""
            here = f"{chain} › {name}" if chain else name
            sp = n.get("stored_path") or ""
            p = root / sp if sp else None
            if p is not None and sp not in seen and p.is_file() and _native(p):
                seen.add(sp)
                out.append({"label": f"nested › {here}", "path": p, "stored_path": sp, "chain": here})
            walk(n.get("children") or [], here)

    walk(nested_tree, "")
    return out[:MAX_OBJECTS]


def _findings(item: dict[str, Any]) -> list[dict[str, Any]]:
    r, loc = item["result"], item["label"]
    st = r.get("state")
    if st not in ("Confirmed", "Likely", "Suspected", "Inconclusive"):
        return []
    tr = r.get("traits") or {}
    fmt = (r.get("binary") or {})
    extra = []
    if tr.get("stripped"):
        extra.append("stripped")
    if tr.get("packed"):
        extra.append("packed")
    if tr.get("garble"):
        extra.append("Garble-style names")
    detail = (f"Go binary ({st}): {r.get('go_version') or 'version unknown'}, "
              f"{fmt.get('format', '').upper()} {fmt.get('arch', '')}"
              + (f", module {(r.get('buildinfo') or {}).get('path')}" if (r.get("buildinfo") or {}).get("path") else "")
              + (f" — {', '.join(extra)}" if extra else ""))
    out = [{"tool": "golang", "rule": "go:identified", "severity": "info", "detail": detail, "location": loc,
            "evidence": "; ".join(e["detail"] + (f" @ {e['offset_hex']}" if e.get("offset_hex") else "")
                                  for e in r.get("evidence") or [])[:1500]}]
    if tr.get("garble"):
        g = tr["garble"]
        out.append({"tool": "golang", "rule": "go:garble", "severity": "medium",
                    "detail": f"Go binary with Garble-style obfuscated package names ({int(g['random_package_share'] * 100)}% of user functions)",
                    "location": loc, "evidence": ", ".join(g.get("examples") or [])})
    if tr.get("metadata_altered"):
        out.append({"tool": "golang", "rule": "go:metadata_altered", "severity": "low",
                    "detail": f"Go metadata incomplete or altered: {tr['metadata_altered']}", "location": loc,
                    "evidence": ""})
    return out


def _code_phase(root: Path, res: dict[str, Any], go: list[dict[str, Any]], raw_dir: Path,
                paths: dict[str, Path]) -> None:
    """Phases 3-4: functions, priority, decompilation (Rizin + rz-ghidra) of
    every distinct Go object, within the per-binary budget."""
    from ..codeanalysis import available
    from ..codeanalysis import case as code_case
    if not go or not code_case.enabled():
        return
    if not available():
        res["warnings"].append("Rizin + rz-ghidra not provisioned: no functions / decompilation "
                               "(Diagnostics → Retry, or scripts/setup_portable_python.py --component rizin)")
        return
    done = 0
    for o in go:
        if o.get("duplicate_of"):
            continue
        r = o["result"]
        if done >= code_case.max_objects():
            o["code"] = {"status": "skipped", "detail": f"only {code_case.max_objects()} Go objects per case are analysed"}
            continue
        p = paths.get(o.get("sha256") or "")
        if p is None or not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        gr_raw = raw_dir / ((r.get("goresym") or {}).get("raw_file") or "-")
        names = code_case.go_names(data, r, gr_raw)
        if not names:
            o["code"] = {"status": "skipped", "detail": "no Go function table could be read (pclntab missing or altered)"}
            continue
        done += 1
        o["code"] = code_case.analyze_object(root, p, o["sha256"], "go", names)
        o["code"]["functions_total"] = len(names)
        if o["code"].get("status") in ("ok", "partial"):
            try:
                res.setdefault("_children", []).extend(code_case.enrich(
                    root, p, data, o["sha256"], "go", o, names=names, buildinfo=r.get("buildinfo")))
            except Exception as exc:  # noqa: BLE001
                log.warning("Go resources / strings step failed on %s: %s", o.get("label"), exc)


def analyze_case(root: Path, original: Path, nested_tree: list[dict[str, Any]]) -> dict[str, Any]:
    from . import detect, goresym

    res: dict[str, Any] = {"module": "golang", "phase": "identification", "objects": [], "findings": [],
                           "warnings": [], "status": "ok"}
    gr_exe = goresym.executable()
    if gr_exe is None:
        res["warnings"].append("GoReSym not provisioned: identification uses the own parser only "
                               "(Diagnostics → Retry, or scripts/setup_portable_python.py --component goresym)")
    raw_dir = root / "raw" / "golang"
    cache: dict[str, dict[str, Any]] = {}
    paths_by_sha: dict[str, Path] = {}
    tgts = targets(root, original, nested_tree)
    res["objects_scanned"] = len(tgts)
    for t in tgts:
        p: Path = t["path"]
        item: dict[str, Any] = {"label": t["label"], "stored_path": t["stored_path"],
                                "original": bool(t.get("original"))}
        try:
            size = p.stat().st_size
            if size > MAX_SIZE:
                item["result"] = {"state": "Inconclusive", "score": 0, "reason": f"larger than {MAX_SIZE >> 20} MB"}
                res["objects"].append(item)
                continue
            data = p.read_bytes()
        except OSError as exc:
            item["result"] = {"state": "Inconclusive", "score": 0, "reason": f"unreadable: {exc}"}
            res["objects"].append(item)
            continue
        sha = hashlib.sha256(data).hexdigest()
        item["sha256"] = sha
        paths_by_sha.setdefault(sha, p)
        if sha in cache:                               # the same binary twice in the case
            item["result"] = cache[sha]
            item["duplicate_of"] = next(o["label"] for o in res["objects"] if o.get("sha256") == sha)
            res["objects"].append(item)
            continue
        t0 = time.perf_counter()
        try:
            r = detect.identify(data)
        except Exception as exc:  # noqa: BLE001  (a malformed binary never breaks the case)
            log.warning("Go identification failed on %s: %s", p.name, exc)
            r = {"state": "Inconclusive", "score": 0, "reason": f"parser error: {exc}", "evidence": []}
        r["duration_s"] = round(time.perf_counter() - t0, 3)
        if gr_exe is not None and r.get("state") in GORESYM_FROM:
            gr = goresym.analyze(p, raw_dir, sha)
            r["goresym"] = gr
            if gr.get("available") and not gr.get("error"):
                r["contrast"] = goresym.compare(r, gr)
                if r["state"] != "Confirmed" and gr.get("pclntab") and gr.get("version"):
                    r["state"] = "Confirmed"
                    r["confirmed_by"] = "GoReSym"
            elif gr.get("error"):
                res["warnings"].append(f"GoReSym failed on {t['label']}: {gr['error']}")
        cache[sha] = r
        item["result"] = r
        res["objects"].append(item)
        res["findings"].extend(_findings(item))
    go = [o for o in res["objects"] if (o.get("result") or {}).get("state") in ("Confirmed", "Likely")]
    _code_phase(root, res, go, raw_dir, paths_by_sha)
    for o in res["objects"]:
        (o.get("result") or {}).pop("_pcln", None)        # internal: parser state for the function table
    res["counts"] = {"objects": len(res["objects"]), "go": len(go), "findings": len(res["findings"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
