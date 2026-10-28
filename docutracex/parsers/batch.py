"""Batch / cmd: collect .bat / .cmd scripts, deobfuscate and analyse them.

Batch is a common first stage (a .bat attachment, or a .cmd dropped by a macro)
that launches PowerShell or a LOLBin behind caret/``set`` obfuscation. This
module gathers the batch a case carries, runs it through the static batch
deobfuscator (``bat_deobf``), applies the shared behaviour rules and exposes the
recovered script in its own Components tab, dumping the full text to
``extracted/code/batch/``. The PowerShell it launches is mined separately by the
powershell module. Nothing is executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import bat_deobf, javascript, script_rules

_MAX_ITEMS = 60
_MAX_FILES = 300
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_CODE = 300_000
_KEEP_CODE = 60_000
_BAT_EXT = {".bat", ".cmd"}


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "batch", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


def static_hits(code: str) -> list[dict[str, Any]]:
    return script_rules.scan(code, script_rules.BAT)


def collect(original: Path, extracted_dir: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(origin: str, location: str, code: str) -> None:
        if code and code.strip():
            items.append({"origin": origin, "location": location, "code": code[:_MAX_FILE_BYTES]})

    paths: list[Path] = []
    if extracted_dir.is_dir():
        from ..codefiles import input_files
        paths = input_files(extracted_dir, _MAX_FILES)
    if original.is_file():
        paths.append(original)
    for p in paths:
        if p.suffix.lower() not in _BAT_EXT:
            continue
        try:
            text = p.read_bytes()[:_MAX_FILE_BYTES].decode("utf-8", "replace")
        except OSError:
            continue
        try:
            rel = p.relative_to(extracted_dir.parent).as_posix()
        except ValueError:
            rel = p.name
        add(f"file:{rel}", f"file:{rel}", text)

    seen: set[str] = set()
    uniq = []
    for it in items:
        key = it["code"].strip()
        if key and key not in seen:
            seen.add(key)
            uniq.append(it)
    return uniq[:_MAX_ITEMS]


def analyze(original: Path, extracted_dir: Path, modules: dict[str, Any] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "batch", "status": "ok", "scripts": [], "findings": []}
    for i, it in enumerate(collect(original, extracted_dir), 1):
        full = it["code"] or ""
        orig_code = full[:_MAX_CODE]
        loc = it["location"]

        deob = bat_deobf.deobfuscate(full)
        deob_full = deob["code"]
        code = deob_full[:_MAX_CODE] if deob["changed"] else orig_code

        hits = static_hits(code)
        mets = javascript.metrics(code)
        script = {"id": i, "kind": "batch", "origin": it["origin"], "location": loc,
                  "size": len(full), "code": code[:_KEEP_CODE], "code_truncated": len(deob_full) > _KEEP_CODE,
                  "code_is_deobfuscated": deob["changed"],
                  "original_code": orig_code[:_KEEP_CODE] if deob["changed"] else "",
                  "original_truncated": deob["changed"] and len(full) > _KEEP_CODE,
                  "deob_methods": deob["methods"], "deob_schemes": [],
                  "deob_size": len(deob_full) if deob["changed"] else 0,
                  "hits": hits, "metrics": mets, "_full_code": full}
        if deob["changed"]:
            script["_full_deob"] = deob_full
        res["scripts"].append(script)

        by_rule: dict[str, list[dict[str, Any]]] = {}
        for h in hits:
            by_rule.setdefault(h["rule"], []).append(h)
        for rule, hs in by_rule.items():
            res["findings"].append(_finding(rule, hs[0]["severity"], f"[{it['origin']}] {hs[0]['label']}", loc,
                                            "\n".join(f"line {h['line_no']}: {h['line']}" for h in hs[:5])))
        chain = script_rules.risk_escalation(hits)
        if chain:
            res["findings"].append(_finding(chain["rule"], chain["severity"],
                                            f"[{it['origin']}] {chain['label']}", loc, chain["detail"]))
        if deob["changed"]:
            methods = ", ".join(deob["methods"]) or "static decoding"
            res["findings"].append(_finding("bat_deobfuscated", "medium",
                                            f"[{it['origin']}] batch deobfuscated before analysis ({methods})",
                                            loc, (code[:600] or "").strip()))
    res["counts"] = {"findings": len(res["findings"]), "scripts": len(res["scripts"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
