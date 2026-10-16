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


TOOLS = {
    "list_cases": list_cases, "case_summary": case_summary, "get_findings": get_findings, "get_iocs": get_iocs,
    "get_module": get_module, "get_network_checks": get_network_checks, "search_case": search_case,
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
                                      "description": "Raw JSON result of one module (ooxml, word, excel, oletools, vbatools, vipermonkey, officerules, pdf, pdftools, email, mailrules, javascript, rtf, nested, netcheck, yara…), trimmed.",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE, "module": {"type": "string"}, "max_chars": {"type": "integer"}},
                                          "required": ["case_id", "module"]}}},
    {"type": "function", "function": {"name": "get_network_checks", "description": "Results of the URL/domain/IP network checks of a case.",
                                      "parameters": {"type": "object", "properties": _CASE, "required": ["case_id"]}}},
    {"type": "function", "function": {"name": "search_case", "description": "Text search across every result of a case (findings, IOCs, module outputs).",
                                      "parameters": {"type": "object", "properties": {
                                          **_CASE, "q": {"type": "string"}, "limit": {"type": "integer"}},
                                          "required": ["case_id", "q"]}}},
]
