"""Read-only tools over DocuTraceX cases, shared by the AI chat and the MCP server.

Every tool only *reads* what the analysis already produced (manifest, summary,
consolidated findings with their marks, IOCs, module sub-results, network
checks). None can create, change or delete anything, and none touches the
network. Outputs are bounded so they fit in a model's context.

Tools:
  - list_cases()                                   cases, newest first
  - case_summary(case_id)                          file, type, hashes, counts, modules
  - get_findings(case_id, severity?, source?, mark?, contains?, limit?)
  - get_iocs(case_id, type?, contains?, limit?)
  - get_module(case_id, module, max_chars?)        a module's raw result (trimmed)
  - get_network_checks(case_id)                    URL/domain/IP checks (condensed)
  - search_case(case_id, q, limit?)                text search across everything
  Code and stages (what the deep analyses produced, beyond the module summaries):
  - list_code_objects(case_id)                     binaries analysed as code (native / Go / .NET)
  - list_functions(case_id, object, category?, name?, limit?)   functions / methods by priority
  - get_function(case_id, object, function, max_chars?)          pseudocode / IL calls, disassembly,
                                                                 callers / callees, strings
  - get_decrypted(case_id, limit?)                 everything decrypted statically, with how
  - get_nested_tree(case_id, max_depth?)           the chain of extracted / hidden / decrypted stages
  - get_ml(case_id)                                ML scores, similar objects in other cases, chain
  - query_registry(case_id, sql?, q?, key?, limit?) the case's registry database (hives / .reg):
                                                   read-only SQL, text search or one key's contents
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .config import settings
from .storage import CasePaths, read_json

MAX_ITEMS = 100
MAX_CHARS = 20000
_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

TOOLS_DOC = [
    ("list_cases()", "cases, newest first (id, file, type, state, counts)"),
    ("case_summary(case_id)", "file, detected type, hashes, counts, modules run, steps"),
    ("get_findings(case_id, severity?, source?, mark?, contains?, limit?)", "consolidated findings with evidence and analyst marks"),
    ("get_iocs(case_id, type?, contains?, limit?)", "URLs, domains, IPs, hashes with provenance"),
    ("get_module(case_id, module, max_chars?)", "raw result of one module (olevba, pdf, email, rtf…), trimmed"),
    ("get_network_checks(case_id)", "URL/domain/IP checks: redirects, forms, cloaking, WHOIS age, ASN…"),
    ("search_case(case_id, q, limit?)", "text search across findings, IOCs and every module result"),
    ("list_code_objects(case_id)", "binaries analysed as code: native (Rizin + rz-ghidra), Go, .NET (CIL)"),
    ("list_functions(case_id, object, category?, name?, limit?)", "functions / .NET methods sorted by priority, with behaviour"),
    ("get_function(case_id, object, function, max_chars?)", "one function: pseudocode or IL calls, disassembly, callers, callees, strings"),
    ("get_decrypted(case_id, limit?)", "strings / configs / resources / stages decrypted statically, with the routine and method"),
    ("get_nested_tree(case_id, max_depth?)", "extracted, unpacked, hidden and decrypted stages with how each was obtained"),
    ("get_ml(case_id)", "ML scores, unusual-for-the-model flags, similar objects in other cases, highest score of the chain"),
    ("query_registry(case_id, sql?, q?, key?, src?, limit?)", "registry hives / .reg of the case: read-only SQL over sources, keys, vals; text search; one key's subkeys and values"),
]


def _cases_dir() -> Path:
    return settings.cases_dir


def _paths(case_id: str) -> CasePaths:
    if not _ID.match(case_id or ""):
        raise ValueError("invalid case_id")
    paths = CasePaths(case_id, cases_dir=_cases_dir())
    if not paths.manifest.is_file():
        raise ValueError(f"case not found: {case_id}")
    return paths


def _clip(s: Any, n: int = 600) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + f"… (+{len(s) - n} chars)"


def list_cases() -> dict[str, Any]:
    from . import cases as case_service

    out = []
    for c in case_service.list_cases(cases_dir=_cases_dir())[:MAX_ITEMS]:
        paths = CasePaths(c["analysis_id"], cases_dir=_cases_dir())
        summary = read_json(paths.summary) or {}
        out.append({"case_id": c["analysis_id"], "file": c.get("filename"), "created_utc": c.get("created_utc"),
                    "detected": c.get("detected_mime") or c.get("mime"), "state": c.get("state"),
                    "counts": summary.get("counts", {})})
    return {"cases": out, "count": len(out)}


def case_summary(case_id: str) -> dict[str, Any]:
    paths = _paths(case_id)
    m = read_json(paths.manifest) or {}
    s = read_json(paths.summary) or {}
    orig = m.get("original", {})
    # c9omYR6Yrv
    fmt = m.get("format", {})
    return {"case_id": case_id, "file": orig.get("filename"), "size_bytes": orig.get("size_bytes"),
            "hashes": orig.get("hashes") or {k: orig.get(k) for k in ("md5", "sha1", "sha256") if orig.get(k)},
            "declared_extension": orig.get("declared_extension"),
            "detected": {"mime": (fmt.get("detected") or {}).get("mime"), "name": (fmt.get("detected") or {}).get("name"),
                         "match": (fmt.get("discrepancy") or {}).get("status")},
            "state": m.get("state"), "counts": s.get("counts", {}), "modules_run": s.get("modules_run", []),
            "steps": [{k: st.get(k) for k in ("step", "status", "findings", "note")} for st in s.get("steps", [])][:60]}


def get_findings(case_id: str, severity: str | None = None, source: str | None = None, mark: str | None = None,
                 contains: str | None = None, limit: int = 60) -> dict[str, Any]:
    from . import marks as marks_service

    paths = _paths(case_id)
    marked = marks_service.apply(marks_service.case_findings(paths), marks_service.read_marks(paths))
    items = marked["findings"]
    if severity:
        items = [f for f in items if f.get("severity") == severity.lower()]
    if source:
        items = [f for f in items if source.lower() in (f.get("source") or "").lower()]
    if mark:
        items = [f for f in items if ((f.get("mark") or {}).get("state") or "unreviewed") == mark]
    if contains:
        q = contains.lower()
        items = [f for f in items if q in json.dumps(f, ensure_ascii=False).lower()]
    items = sorted(items, key=lambda f: _SEV_ORDER.get(f.get("severity"), 9))
    lim = max(1, min(int(limit or 60), MAX_ITEMS))
    return {"total": len(items), "returned": min(len(items), lim), "findings": [
        {"id": f.get("id"), "severity": f.get("severity"), "source": f.get("source"), "rule": f.get("rule"),
         "detail": _clip(f.get("detail"), 400), "location": _clip(f.get("location"), 200),
         "evidence": _clip(f.get("evidence"), 500),
         "mark": (f.get("mark") or {}).get("state", "unreviewed"), "comment": (f.get("mark") or {}).get("comment")}
        for f in items[:lim]]}


def get_iocs(case_id: str, type: str | None = None, contains: str | None = None, limit: int = 100) -> dict[str, Any]:
    paths = _paths(case_id)
    items = (read_json(paths.subresult("iocs")) or {}).get("iocs", [])
    if type:
        items = [i for i in items if i.get("type") == type]
    if contains:
        items = [i for i in items if contains.lower() in str(i.get("value", "")).lower()]
    lim = max(1, min(int(limit or 100), MAX_ITEMS * 2))
    return {"total": len(items), "iocs": [
        {"type": i.get("type"), "value": i.get("value"), "count": i.get("count"),
         "seen_in": sorted({f"{o.get('module')}/{o.get('location')}" for o in i.get("occurrences", [])})[:6]}
        for i in items[:lim]]}


def get_module(case_id: str, module: str, max_chars: int = MAX_CHARS) -> dict[str, Any]:
    paths = _paths(case_id)
    if not _ID.match(module or ""):
        raise ValueError("invalid module name")
    data = read_json(paths.subresult(module))
    if data is None:
        available = sorted(p.stem for p in paths.results_dir.glob("*.json"))
        return {"error": f"module {module!r} has no result in this case", "available": available}
    if module == "ml":
        from .ml import family_info
        data = family_info.enrich(data)          # what each family is, and how sure the model is
    text = json.dumps(data, ensure_ascii=False, default=str)
    n = max(1000, min(int(max_chars or MAX_CHARS), 60000))
    return {"module": module, "size_chars": len(text), "truncated": len(text) > n, "json": text[:n]}


def get_network_checks(case_id: str) -> dict[str, Any]:
    paths = _paths(case_id)
    net = read_json(paths.subresult("netcheck")) or {}
    out = []
    for c in net.get("checks", []):
        rec: dict[str, Any] = {"kind": c.get("kind"), "target": c.get("target"), "checked_utc": c.get("checked_utc"),
                               "via": c.get("via"),
                               "findings": [f"{f.get('severity')} {f.get('rule')}: {_clip(f.get('detail'), 200)}"
                                            for f in c.get("findings", [])][:30]}
        if c.get("views"):  # URL checks, and the website of a checked domain
            views = {}
            for name, v in (c.get("views") or {}).items():
                # c9omYR6Yrv
                pg = v.get("page") or {}
                # gmzpt
                views[name] = {"status": v.get("status"), "final_url": v.get("final_url"),
                               "hops": [f"{h.get('status')} {h.get('url')}" for h in v.get("hops", [])],
                               "title": pg.get("title"), "brands": pg.get("brands"),
                               "forms": [{"method": f.get("method"), "action": f.get("action"),
                                          "password": f.get("has_password")} for f in pg.get("forms", [])],
                               "download": (v.get("download") or {}).get("filename")}
            rec["views"] = views
            rec["submissions"] = [{"action": s.get("action"), "status": (s.get("view") or {}).get("status"),
                                   "final_url": (s.get("view") or {}).get("final_url"),
                                   "title": ((s.get("view") or {}).get("page") or {}).get("title")}
                                  for s in c.get("submissions", [])]
        if c.get("kind") != "url":
            rec["data"] = c.get("data", {})
        out.append(rec)
    return {"checks": out, "count": len(out)}


def search_case(case_id: str, q: str, limit: int = 40) -> dict[str, Any]:
    """Case-insensitive substring search over every JSON result of the case."""
    paths = _paths(case_id)
    if not q or len(q) < 2:
        raise ValueError("q must have at least 2 characters")
    needle = q.lower()
    hits: list[dict[str, Any]] = []
    lim = max(1, min(int(limit or 40), MAX_ITEMS))
    for p in sorted(paths.results_dir.glob("*.json")):
        if len(hits) >= lim:
            break
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = text.lower()
        start = 0
        while len(hits) < lim:
            i = low.find(needle, start)
            if i < 0:
                break
            hits.append({"module": p.stem, "context": text[max(0, i - 160): i + len(q) + 160].replace("\\n", " ")})
            start = i + len(needle)
    return {"q": q, "hits": hits, "returned": len(hits)}


# --- code, stages, decryption, ML ---------------------------------------------------
def _code_files(paths: CasePaths) -> list[tuple[str, str, Path]]:
    """(sha256, mode, file) of every code-analysis result of the case."""
    out = []
    d = paths.root / "code"
    for f in sorted(d.glob("*.json")) if d.is_dir() else []:
        parts = f.name.split(".")
        if len(parts) == 3 and parts[1] in ("go", "native") and len(parts[0]) == 64:
            out.append((parts[0], parts[1], f))
    return out


def _labels(paths: CasePaths) -> dict[str, str]:
    lab: dict[str, str] = {}
    for mod in ("golang", "code", "dotnet"):
        for o in (read_json(paths.subresult(mod)) or {}).get("objects") or []:
            if o.get("sha256") and o.get("label"):
                lab.setdefault(o["sha256"], o["label"])
    return lab


def list_code_objects(case_id: str) -> dict[str, Any]:
    """Every binary of the case analysed as code, with the id to use as ``object``."""
    paths = _paths(case_id)
    lab = _labels(paths)
    objs = []
    for sha, mode, f in _code_files(paths):
        full = read_json(f) or {}
        sm = full.get("summary") or {}
        fns = full.get("functions") or []
        objs.append({"object": sha[:16], "engine": "Go" if mode == "go" else "native (Rizin + rz-ghidra)",
                     "label": lab.get(sha, ""), "functions": len(fns),
                     "decompiled": sum(1 for x in fns if x.get("decompiled")),
                     "top": [x.get("name") for x in fns[:5]], "summary": {k: sm.get(k) for k in list(sm)[:8]}})
    for o in (read_json(paths.subresult("dotnet")) or {}).get("objects") or []:
        r = o.get("result") or {}
        if not r or r.get("error") or o.get("duplicate"):
            continue
        cil = r.get("cil") or {}
        objs.append({"object": (o.get("sha256") or "")[:16], "engine": ".NET (CIL)", "label": o.get("label", ""),
                     "assembly": (r.get("assembly") or {}).get("name"), "methods": cil.get("methods"),
                     "methods_of_interest": len(cil.get("interesting") or []),
                     "decrypted_strings": len(cil.get("decrypted") or []),
                     "obfuscators": [x.get("name") for x in r.get("obfuscators") or []]})
    return {"objects": objs, "hint": "pass 'object' (the sha256 prefix shown) to list_functions / get_function"}


def _pick(paths: CasePaths, obj: str) -> tuple[str, Any]:
    """('code', full code result) or ('dotnet', dotnet object) for an object id / label."""
    q = (obj or "").lower().strip()
    if not q:
        raise ValueError("object is required (see list_code_objects)")
    lab = _labels(paths)
    for sha, mode, f in _code_files(paths):
        if sha.startswith(q) or (len(q) >= 3 and q in lab.get(sha, "").lower()):
            return "code", read_json(f) or {}
    for o in (read_json(paths.subresult("dotnet")) or {}).get("objects") or []:
        if (o.get("sha256") or "").startswith(q) or (len(q) >= 3 and q in (o.get("label") or "").lower()):
            if o.get("result"):
                return "dotnet", o
    raise ValueError(f"no code object matches {obj!r} (see list_code_objects)")


def list_functions(case_id: str, object: str, category: str | None = None, name: str | None = None,
                   limit: int = 40) -> dict[str, Any]:
    """Functions (native / Go) or methods of interest (.NET), most interesting first."""
    paths = _paths(case_id)
    kind, data = _pick(paths, object)
    lim = max(1, min(int(limit or 40), MAX_ITEMS))
    cat = (category or "").lower()
    nm = (name or "").lower()
    out = []
    if kind == "code":
        for f in data.get("functions") or []:
            if cat and cat not in [c.lower() for c in f.get("categories") or []]:
                continue
            if nm and nm not in (f.get("name") or "").lower():
                continue
            out.append({"rank": f.get("rank"), "name": f.get("name"), "addr": hex(f["addr"]), "score": f.get("score"),
                        "categories": f.get("categories"), "traits": f.get("traits"), "size": f.get("size"),
                        "decompiled": bool(f.get("decompiled")), "why": (f.get("reasons") or [])[:4]})
            if len(out) >= lim:
                break
    else:
        for m in ((data.get("result") or {}).get("cil") or {}).get("interesting") or []:
            if cat and cat not in [c.lower() for c in m.get("categories") or []]:
                continue
            if nm and nm not in (m.get("method") or "").lower():
                continue
            out.append({"name": m.get("method"), "score": m.get("score"), "categories": m.get("categories"),
                        "il_bytes": m.get("size"), "calls": (m.get("calls") or [])[:10], "strings": (m.get("strings") or [])[:6]})
            if len(out) >= lim:
                break
    return {"object": object, "kind": kind, "functions": out, "returned": len(out),
            "hint": "get_function(case_id, object, function=<name or 0xaddr>) for the code of one"}


def get_function(case_id: str, object: str, function: str, max_chars: int = 12000) -> dict[str, Any]:
    """One function: pseudocode (when decompiled), disassembly, callers / callees, strings;
    for .NET: the framework calls, the literals it loads, static arrays and what was decrypted."""
    paths = _paths(case_id)
    kind, data = _pick(paths, object)
    budget = max(1000, min(int(max_chars or 12000), MAX_CHARS))
    q = (function or "").strip()
    if kind == "code":
        from .codeanalysis import case as code_case
        fns = data.get("functions") or []
        f = None
        if q.lower().startswith("0x"):
            try:
                a = int(q, 16)
                f = next((x for x in fns if x["addr"] == a), None)
            except ValueError:
                f = None
        if f is None:
            f = next((x for x in fns if x.get("name") == q), None) or \
                next((x for x in fns if q.lower() in (x.get("name") or "").lower()), None)
        if f is None:
            raise ValueError(f"no function {function!r} in {object} (see list_functions)")
        v = code_case.function_view(data, f["addr"]) or {}
        dec = (v.get("decompiled") or {})
        code = dec.get("code") if dec.get("status") == "ok" else None
        ops = v.get("ops") or []
        asm = "\n".join(f"{o.get('offset', 0):#x}  {o.get('disasm') or o.get('opcode') or ''}" for o in ops[:400])
        out = {"name": v.get("name"), "addr": hex(v.get("addr", 0)), "rank": v.get("rank"), "score": v.get("score"),
               "categories": v.get("categories"), "traits": v.get("traits"), "why": v.get("reasons"),
               "callers": [c["name"] for c in v.get("callers") or []][:30],
               "callees": [c["name"] for c in v.get("callees") or []][:30] + (v.get("callee_names") or [])[:30],
               "strings": [s.get("value") if isinstance(s, dict) else s for s in (v.get("strings") or [])][:40]}
        if code:
            out["pseudocode"] = _clip(code, int(budget * 0.7))
        else:
            out["pseudocode"] = None
            out["note"] = (dec.get("detail") or f.get("decompile_note")
                           or "not decompiled: use the Code view (Decompile / Decompile all) and ask again")
        out["disassembly"] = _clip(asm, budget - len(out.get("pseudocode") or ""))
        return out
    r = data.get("result") or {}
    cil = r.get("cil") or {}
    m = next((x for x in cil.get("interesting") or [] if x.get("method") == q), None) or \
        next((x for x in cil.get("interesting") or [] if q.lower() in (x.get("method") or "").lower()), None)
    if m is None:
        raise ValueError(f"no method {function!r} among the methods of interest of {object}")
    dec = [d for d in cil.get("decrypted") or [] if m["method"] in (d.get("decryptor"), d.get("caller"))]
    return {"name": m["method"], "categories": m.get("categories"), "il_bytes": m.get("size"), "score": m.get("score"),
            "calls": m.get("calls"), "strings": m.get("strings"), "static_arrays": m.get("arrays"),
            "decrypted": [{"plain": _clip(d["output"], 400), "encrypted": _clip(d["input"], 120), "how": d["how"],
                           "decryptor": d["decryptor"], "caller": d["caller"]} for d in dec[:30]],
            "note": "IL is summarised (calls and literals), not decompiled to C#"}


def get_decrypted(case_id: str, limit: int = 80) -> dict[str, Any]:
    """Everything the analyses decrypted or decoded statically, with the routine used."""
    paths = _paths(case_id)
    lim = max(1, min(int(limit or 80), 200))
    out: list[dict[str, Any]] = []
    for o in (read_json(paths.subresult("dotnet")) or {}).get("objects") or []:
        r = o.get("result") or {}
        for d in (r.get("cil") or {}).get("decrypted") or []:
            out.append({"where": o.get("label"), "kind": ".NET string", "plain": _clip(d.get("output"), 400),
                        "how": d.get("how"), "routine": d.get("decryptor"), "used_by": d.get("caller")})
        for x in r.get("resources") or []:
            if x.get("decrypted"):
                out.append({"where": o.get("label"), "kind": ".NET resource", "plain": f"{x['name']} → {x['decrypted'].get('type')}"
                            f" ({x['decrypted'].get('size')} bytes)", "how": x["decrypted"].get("how")})
            for e in x.get("entries") or []:
                if e.get("stego"):
                    out.append({"where": o.get("label"), "kind": "hidden in Bitmap pixels",
                                "plain": f"{x['name']} › {e['name']} → {e['stego'].get('type')} ({e['stego'].get('size')} bytes)",
                                "how": e["stego"].get("how")})
    for sha, mode, f in _code_files(paths):
        full = read_json(f) or {}
        for pt in (full.get("crypto") or {}).get("plaintexts") or []:
            out.append({"where": sha[:16], "kind": f"{mode} crypto", "plain": _clip(pt.get("text") or pt.get("summary"), 400),
                        "how": pt.get("how") or pt.get("algorithm"), "routine": pt.get("function")})
        for g in (full.get("garble") or {}).get("strings") or []:
            out.append({"where": sha[:16], "kind": "Garble literal (emulated)", "plain": _clip(g.get("value"), 400),
                        "routine": g.get("function")})

    def walk(nodes: list[dict[str, Any]], chain: str) -> None:
        for n in nodes or []:
            here = f"{chain} › {n.get('filename', '')}" if chain else n.get("filename", "")
            if n.get("decrypted_from") or n.get("stego"):
                out.append({"where": here, "kind": "stage", "plain": f"{n.get('kind')} {n.get('format') or ''}".strip(),
                            "how": n.get("decrypted_from") or (n.get("stego") or {}).get("how"),
                            "recipe": " → ".join(n.get("recipe") or [])})
            walk(n.get("children") or [], here)
    walk((read_json(paths.subresult("nested")) or {}).get("tree") or [], "")
    for c in (read_json(paths.subresult("c2")) or {}).get("configs") or []:
        if c.get("decrypted_statically"):
            out.append({"where": c.get("object"), "kind": f"C2 config ({c.get('family')})",
                        "plain": ", ".join(c.get("c2") or []), "how": c.get("method")})
    return {"items": out[:lim], "returned": min(len(out), lim), "total": len(out)}


def get_nested_tree(case_id: str, max_depth: int = 6) -> dict[str, Any]:
    """The chain of children: extracted, unpacked, hidden and decrypted stages."""
    paths = _paths(case_id)
    depth_cap = max(1, min(int(max_depth or 6), 12))
    count = [0]

    def node(n: dict[str, Any], d: int) -> dict[str, Any]:
        count[0] += 1
        out = {"file": n.get("filename"), "kind": n.get("kind"), "format": n.get("format"),
               "sha256": (n.get("sha256") or "")[:16], "findings": len(n.get("findings") or []),
               "high": sum(1 for f in n.get("findings") or [] if f.get("severity") == "high")}
        if n.get("decrypted_from"):
            out["obtained"] = n["decrypted_from"]
        if n.get("recipe"):
            out["recipe"] = " → ".join(n["recipe"])
        if n.get("stego"):
            out["hidden_payload"] = n["stego"]
        kids = n.get("children") or []
        if kids and d < depth_cap and count[0] < 300:
            out["children"] = [node(k, d + 1) for k in kids[:60]]
        elif kids:
            out["children_not_shown"] = len(kids)
        return out
    tree = (read_json(paths.subresult("nested")) or {}).get("tree") or []
    return {"tree": [node(n, 1) for n in tree[:80]], "nodes_shown": count[0]}


def get_ml(case_id: str) -> dict[str, Any]:
    """ML results: score and verdict per object, unusual-for-the-model flag, similar
    objects in other cases, highest score of the chain."""
    paths = _paths(case_id)
    ml = read_json(paths.subresult("ml")) or {}
    items = []
    for x in ml.get("items") or []:
        a = x.get("atypicality") or {}
        items.append({"object": x.get("label"), "model": x.get("model"), "score": x.get("score"),
                      "verdict": x.get("verdict"), "status": x.get("status"),
                      "unusual_for_model": a.get("atypical"), "unusual_features": a.get("examples"),
                      "top_features": [f"{t.get('plain') or t.get('feature')} ({t.get('contribution', 0):+.2f})"
                                       for t in (x.get("top_features") or [])[:6]],
                      "family_guess": [(f.get("name"), f.get("confidence")) for f in ((x.get("labels") or {}).get("family") or [])[:3]],
                      "similar": [{"similarity": s.get("similarity"), "case": s.get("case"), "object": s.get("label"),
                                   "same_file": s.get("same_file")} for s in x.get("similar") or []]})
    return {"chain": ml.get("chain"), "items": items[:60],
            "note": "complementary indicator, not a verdict; results are not findings until marked"}


def query_registry(case_id: str, sql: str | None = None, q: str | None = None, key: str | None = None,
                   src: int = 0, limit: int = 200) -> dict[str, Any]:
    """The case's registry database: ``sql`` (one read-only SELECT over sources, keys, vals),
    ``q`` (text search in key paths, value names and data) or ``key`` (its subkeys and values);
    with none of them, the sources and the schema."""
    from .registry import remote, store
    paths = _paths(case_id)
    db = store.db_path(paths.root)
    if not db.is_file():
        return {"error": "this case has no registry data (no hive / .reg was analysed)"}
    if not remote.available():
        return {"error": "DuckDB is not installed"}
    limit = max(1, min(int(limit or 200), 1000))
    if sql:
        res = remote.call("user_query", path=db, sql=sql, limit=limit)
    elif q:
        res = remote.call("search", path=db, q=q, where="any", src=int(src or 0), regex=False, limit=limit, offset=0)
    elif key:
        res = remote.call("children", path=db, src=int(src or 1), key=key)
        res["subkeys"] = res["subkeys"][:limit]
        res["values"] = [{**v, "data": _clip(v.get("data"), 2000)} for v in res["values"][:limit]]
        return res
    else:
        res = remote.call("query", path=db, sql="SELECT * FROM sources ORDER BY id", limit=100)
        res["schema"] = {"sources": "id, label, file, kind (hive|reg), hive_type, mount, keys, vals, logs, error",
                         "keys": "src, path, parent, name, last_write, subkeys, nvalues, op (delete = .reg removal)",
                         "vals": 'src, "key", name, type, data (text), size, raw (bytes of binary values), op',
                         "catalog": 'src, category, description, comment, batch, "key", name, type, data, last_write '
                                    '(RECmd batch files: what each key means; rows without name are the keys)',
                         "artifacts": 'src, plugin, ts, "key", summary, entry (JSON) — regipy plugins: user_assist, '
                                      'shimcache, amcache, background_activity_moderator, ntuser_shellbag_plugin, usbstor_plugin…'}
        return res
    res["rows"] = [[_clip(c, 1000) if isinstance(c, str) else c for c in r] for r in res["rows"]]
    return res


TOOLS = {
    "list_cases": list_cases, "case_summary": case_summary, "get_findings": get_findings, "get_iocs": get_iocs,
    "get_module": get_module, "get_network_checks": get_network_checks, "search_case": search_case,
    "list_code_objects": list_code_objects, "list_functions": list_functions, "get_function": get_function,
    "get_decrypted": get_decrypted, "get_nested_tree": get_nested_tree, "get_ml": get_ml,
    "query_registry": query_registry,
}


def run_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    fn = TOOLS.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return fn(**{k: v for k, v in (args or {}).items() if v is not None})
    except TypeError as exc:
        return {"error": f"bad arguments: {exc}"}
    except Exception as exc:  # noqa: BLE001  (returned to the model)
        return {"error": str(exc)}


# OpenAI function-calling schema for the same tools.
_CASE = {"case_id": {"type": "string", "description": "Case id (e.g. 20261016-001929-60fd220f)."}}
SCHEMAS = [
    {"type": "function", "function": {"name": "list_cases", "description": "List the cases (newest first).",
                                      "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "case_summary", "description": "Summary of a case: file, detected type, hashes, counts, modules and steps.",
                                      "parameters": {"type": "object", "properties": _CASE, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "get_findings",
                                      "description": "Consolidated findings (severity, source tool, rule, detail, location, evidence, analyst mark). Sorted high→info.",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE,
                                          "severity": {"type": "string", "enum": ["high", "medium", "low", "info"]},
                                          "source": {"type": "string", "description": "Tool/module, e.g. olevba, rtf, mailrules, netcheck."},
                                          "mark": {"type": "string", "enum": ["unreviewed", "true_positive", "false_positive", "suspicious", "informational"]},
                                          "contains": {"type": "string", "description": "Substring filter."},
                                          "limit": {"type": "integer"}}, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "get_iocs", "description": "IOCs of a case with where they were seen.",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE, "type": {"type": "string", "enum": ["url", "domain", "ipv4", "ipv6", "hash_like"]},
                                          "contains": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "get_module",
                                      "description": "Raw JSON result of one module (ooxml, word, excel, oletools, vbatools, vipermonkey, officerules, pdf, pdftools, email, mailrules, javascript, rtf, nested, netcheck, yara, ml, c2…), trimmed.",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE, "module": {"type": "string"}, "max_chars": {"type": "integer"}},
                                          "required": ["case_id", "module"]}}},
    {"type": "function", "function": {"name": "get_network_checks", "description": "Results of the URL/domain/IP network checks of a case.",
                                      "parameters": {"type": "object", "properties": _CASE, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "search_case", "description": "Text search across every result of a case (findings, IOCs, module outputs).",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE, "q": {"type": "string"}, "limit": {"type": "integer"}},
                                          "required": ["case_id", "q"]}}},
    {"type": "function", "function": {"name": "list_code_objects",
                                      "description": "Binaries of the case analysed as code (native with Rizin + rz-ghidra, Go, .NET CIL) and the 'object' id to use with list_functions / get_function.",
                                      "parameters": {"type": "object", "properties": _CASE, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "list_functions",
                                      "description": "Functions (native / Go) or .NET methods of interest of one object, most interesting first, with behaviour categories (network, crypto, injection, persistence, loader…).",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE, "object": {"type": "string", "description": "sha256 prefix or label from list_code_objects."},
                                          "category": {"type": "string", "description": "e.g. network, crypto, injection, persistence, loader, stego."},
                                          "name": {"type": "string", "description": "Substring of the function name."},
                                          "limit": {"type": "integer"}}, "required": ["case_id", "object"]}}},
    {"type": "function", "function": {"name": "get_function",
                                      "description": "One function: pseudocode (if decompiled), disassembly, callers, callees and strings; for .NET the framework calls, literals, static arrays and the strings it decrypts.",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE, "object": {"type": "string"},
                                          "function": {"type": "string", "description": "Name (or part) or address like 0x401000."},
                                          "max_chars": {"type": "integer"}}, "required": ["case_id", "object", "function"]}}},
    {"type": "function", "function": {"name": "get_decrypted",
                                      "description": "Everything decrypted or decoded statically in the case (.NET strings and resources, Bitmap payloads, Go/native crypto, Garble literals, decrypted stages, C2 configs), with the routine used.",
                                      "parameters": {"type": "object", "properties": {**_CASE, "limit": {"type": "integer"}}, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "get_nested_tree",
                                      "description": "Tree of extracted, unpacked, hidden and decrypted stages, with how each was obtained (recipe) and its findings.",
                                      "parameters": {"type": "object", "properties": {**_CASE, "max_depth": {"type": "integer"}}, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "get_ml",
                                      "description": "Machine Learning: score and verdict per object, unusual-for-the-model flag, top features, similar objects in other cases and the highest score of the chain.",
                                      "parameters": {"type": "object", "properties": _CASE, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "query_registry",
                                      "description": "Registry hives / .reg files of the case, loaded in a database. No other argument: sources and schema. "
                                                     "sql: one read-only SELECT over sources(id, label, kind, hive_type, mount…), keys(src, path, parent, name, last_write…), "
                                                     "vals(src, \"key\", name, type, data, size, raw), catalog(src, category, description, \"key\", name, data…: what each key means) "
                                                     "and artifacts(src, plugin, ts, \"key\", summary, entry JSON: UserAssist, ShimCache, BAM, ShellBags, USB…); "
                                                     "q: text search; key: subkeys and values of one key path (with src).",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE, "sql": {"type": "string"}, "q": {"type": "string"},
                                          "key": {"type": "string", "description": "Full key path, e.g. HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."},
                                          "src": {"type": "integer", "description": "Source id (from the sources list)."},
                                          "limit": {"type": "integer"}}, "required": ["case_id"]}}},
]
