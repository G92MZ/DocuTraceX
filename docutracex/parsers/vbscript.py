"""VBScript: collect .vbs / .vbe and HTA/WSF VBScript blocks, decode & deobfuscate.

The JS sandbox is a *JScript* engine and ViperMonkey is *VBA*, so standalone
VBScript (in HTA/WSF or dropped .vbs/.vbe) was never decoded. This module:

- extracts VBScript from ``.vbs``, ``.vbe`` (Microsoft Script Encoder — same
  scheme as the ``.jse`` we already decode, via Didier Stevens' decode-vbe.py),
  and ``<script language="VBScript">`` blocks of HTA / WSF / HTML;
- applies a basic static string deobfuscator (``Chr``/``ChrW`` char codes,
  ``&`` concatenation, ``StrReverse``, and unwrapping ``Execute`` /
  ``ExecuteGlobal`` / ``Eval`` of a string literal);

and exposes the result in its own tab, dumping the full source to
``extracted/code/vbscript/``. Nothing is executed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import javascript

_MAX_ITEMS = 60
_MAX_FILES = 300
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_CODE = 300_000
_KEEP_CODE = 60_000
_MAX_PASSES = 25

_SCRIPT_TAG = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_HTML_EXT = {".hta", ".htm", ".html", ".wsf", ".wsc", ".sct", ".mht", ".mhtml"}

PATTERNS: list[tuple[str, str, str, str]] = [
    ("vbs_exec", "high", r"(?i)\bExecuteGlobal\b|\bExecute\b|\bEval\b", "executes a dynamic string"),
    ("vbs_shell", "high", r"(?i)WScript\.Shell|Shell\.Application|\.Run\s*\(|\.Exec\s*\(|\.ShellExecute\s*\(",
     "runs commands (WScript.Shell/Run)"),
    ("vbs_activex", "high", r"(?i)CreateObject\s*\(|GetObject\s*\(", "creates/uses a COM object"),
    ("vbs_download", "high", r"(?i)MSXML2\.(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP|ADODB\.Stream",
     "network request / stream"),
    ("vbs_file", "high", r"(?i)Scripting\.FileSystemObject|\.SaveToFile\s*\(|\.CreateTextFile\s*\(|\.WriteLine\b",
     "writes files"),
    ("vbs_lolbin", "high", r"(?i)powershell|cmd(?:\.exe)?\s*/c|mshta|regsvr32|rundll32|certutil|bitsadmin|wmic|schtasks",
     "invokes a LOLBin / shell"),
    ("vbs_obfusc", "medium", r"(?i)StrReverse\s*\(|Chr[W]?\s*\(|&\s*H[0-9a-fA-F]{2}", "obfuscation primitives"),
]


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "vbscript", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


# --- deobfuscation ------------------------------------------------------------

_VSTR = r'"(?:[^"]|"")*"'


def _vstr_value(lit: str) -> str:
    return lit[1:-1].replace('""', '"')


def _as_vstr(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _t_chr(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(r"(?i)Chr[W]?\s*\(\s*(&H[0-9a-fA-F]+|\d{1,7})\s*\)")

    def repl(m: re.Match) -> str:
        nonlocal n
        tok = m.group(1)
        try:
            val = int(tok[2:], 16) if tok[:2].lower() == "&h" else int(tok)
            ch = chr(val & 0x10FFFF)
        except ValueError:
            return m.group(0)
        n += 1
        return _as_vstr(ch)

    return rx.sub(repl, code), n


def _t_concat(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(rf"({_VSTR})\s*&\s*({_VSTR})")
    while True:
        def repl(m: re.Match) -> str:
            nonlocal n
            n += 1
            return _as_vstr(_vstr_value(m.group(1)) + _vstr_value(m.group(2)))

        new = rx.sub(repl, code)
        if new == code:
            break
        code = new
    return code, n


def _t_strreverse(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(rf"(?i)StrReverse\s*\(\s*({_VSTR})\s*\)")

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return _as_vstr(_vstr_value(m.group(1))[::-1])

    return rx.sub(repl, code), n


def _t_unwrap_exec(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(rf"(?i)(?:ExecuteGlobal|Execute|Eval)\s*\(?\s*({_VSTR})\s*\)?")

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return "\n" + _vstr_value(m.group(1)) + "\n"

    return rx.sub(repl, code), n


_TRANSFORMS = [("chr-code", _t_chr), ("concat-&", _t_concat),
               ("StrReverse", _t_strreverse), ("unwrap-Execute/Eval", _t_unwrap_exec)]


def deobfuscate(code: str) -> dict[str, Any]:
    original = code or ""
    cur = original
    methods: list[str] = []
    for _ in range(_MAX_PASSES):
        before = cur
        for name, fn in _TRANSFORMS:
            try:
                new, cnt = fn(cur)
            except Exception:  # noqa: BLE001
                continue
            if cnt and new != cur:
                cur = new
                if name not in methods:
                    methods.append(name)
        if cur == before:
            break
    return {"changed": cur.strip() != original.strip(), "code": cur, "methods": methods}


def static_hits(code: str) -> list[dict[str, Any]]:
    hits = []
    lines = code.splitlines() or [""]
    for rule, sev, rx, label in PATTERNS:
        r = re.compile(rx)
        for no, ln in enumerate(lines, 1):
            if r.search(ln):
                hits.append({"rule": rule, "severity": sev, "label": label, "line_no": no,
                             "line": ln.strip()[:300]})
                if sum(1 for h in hits if h["rule"] == rule) >= 5:
                    break
    return sorted(hits, key=lambda h: (h["line_no"], h["rule"]))


# --- extraction ---------------------------------------------------------------

def _vbscript_from_html(html: str) -> list[str]:
    out: list[str] = []
    for attrs, code in _SCRIPT_TAG.findall(html):
        if re.search(r"(?i)vbscript|vbs", attrs) and code.strip():
            out.append(re.sub(r"^\s*<!\[CDATA\[|\]\]>\s*$", "", code.strip()))
    return out


def collect(original: Path, extracted_dir: Path, modules: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(origin: str, location: str, code: str, note: str = "") -> None:
        if code and code.strip():
            it = {"origin": origin, "location": location, "code": code[:_MAX_FILE_BYTES]}
            if note:
                it["note"] = note
            items.append(it)

    paths: list[Path] = []
    if extracted_dir.is_dir():
        paths = [p for p in sorted(extracted_dir.rglob("*")) if p.is_file()][:_MAX_FILES]
    if original.is_file():
        paths.append(original)
    for p in paths:
        ext = p.suffix.lower()
        try:
            rel = p.relative_to(extracted_dir.parent).as_posix()
        except ValueError:
            rel = p.name
        if ext == ".vbe":
            dec = javascript._decode_jse(p)
            if dec.strip():
                add(f"file:{rel}", f"file:{rel}", dec, "decoded from Script Encoder (.vbe)")
            continue
        if ext == ".vbs":
            try:
                add(f"file:{rel}", f"file:{rel}", p.read_bytes()[:_MAX_FILE_BYTES].decode("utf-8", "replace"))
            except OSError:
                pass
            continue
        if ext in _HTML_EXT:
            try:
                text = p.read_bytes()[:_MAX_FILE_BYTES].decode("utf-8", "replace")
            except OSError:
                continue
            if "#@~^" in text[:4096]:  # encoded VBScript inside HTML
                dec = javascript._decode_jse(p)
                if dec.strip():
                    add(f"file:{rel}", f"file:{rel}", dec, "decoded from Script Encoder")
            for code in _vbscript_from_html(text):
                add(f"file:{rel}", f"file:{rel}", code)

    # Email HTML body VBScript blocks.
    email = modules.get("email") or {}
    for code in _vbscript_from_html(email.get("html_source_sample") or ""):
        add("email HTML body", "body:vbscript", code)

    seen: set[str] = set()
    uniq = []
    for it in items:
        key = it["code"].strip()
        if key and key not in seen:
            seen.add(key)
            uniq.append(it)
    return uniq[:_MAX_ITEMS]


def analyze(original: Path, extracted_dir: Path, modules: dict[str, Any]) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "vbscript", "status": "ok", "scripts": [], "findings": []}
    for i, it in enumerate(collect(original, extracted_dir, modules), 1):
        full = it["code"] or ""
        orig_code = full[:_MAX_CODE]
        loc = it["location"]

        deob = deobfuscate(full)
        deob_full = deob["code"]
        code = deob_full[:_MAX_CODE] if deob["changed"] else orig_code

        hits = static_hits(code)
        mets = javascript.metrics(code)
        script = {"id": i, "kind": "vbscript", "origin": it["origin"], "location": loc, "note": it.get("note"),
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
        if deob["changed"]:
            methods = ", ".join(deob["methods"]) or "static decoding"
            res["findings"].append(_finding("vbs_deobfuscated", "medium",
                                            f"[{it['origin']}] VBScript deobfuscated before analysis ({methods})",
                                            loc, (code[:600] or "").strip()))
    res["counts"] = {"findings": len(res["findings"]), "scripts": len(res["scripts"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
