"""PowerShell: collect the commands a case carries and deobfuscate them.

PowerShell is the usual second stage of maldocs but, until now, DocuTraceX only
*detected* it (in VBA ``Shell`` calls, DDE links and the JS sandbox command
log) — it was never decoded. This module gathers every PowerShell command it
can see, from:

- dropped ``.ps1`` / ``.psm1`` / ``.psd1`` files and ``.bat`` / ``.cmd`` lines;
- VBA source and the olevba decoded strings (``oletools``);
- ViperMonkey emulated actions (``vipermonkey``);
- the STPyV8 sandbox command log and decoded strings (``javascript``);
- DDE links (``msodde``) and Office field commands;

runs each through the layered deobfuscator (``ps_deobf``) and exposes the
recovered command in its own Components tab, dumping the full text to
``extracted/code/powershell/``. Nothing is executed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import boxps, javascript, ps_deobf, script_rules

_MAX_SANDBOX_RUNS = 12          # cap box-ps invocations per case (each is slow)

_MAX_ITEMS = 60
_MAX_FILES = 300
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_CODE = 300_000
_KEEP_CODE = 60_000
_PS_FILE_EXT = {".ps1", ".psm1", ".psd1"}
_SHELL_FILE_EXT = {".bat", ".cmd"}

# Behaviour patterns live in the shared catalogue (script_rules).

# A powershell.exe invocation taken to the end of the line / statement.
_INVOKE = re.compile(
    r"(?i)(?:^|[\s\"'`&|=(;,>])((?:[a-z]:\\[^\s\"']*\\)?(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,8000})"
)
# Lines/fragments that are clearly PowerShell even without the word powershell.
_PS_MARKER = re.compile(
    r"(?i)(?:-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|FromBase64String|DownloadString|DownloadFile|"
    r"Invoke-Expression|\bIEX\b|Invoke-WebRequest|Net\.WebClient|New-Object\s+[A-Za-z.]*Net)"
)


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "powershell", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


def static_hits(code: str) -> list[dict[str, Any]]:
    """Behaviour hits from the shared catalogue (PowerShell rules)."""
    return script_rules.scan(code, script_rules.PS)


def _candidates(text: str, whole: bool) -> list[str]:
    """PowerShell command strings inside a text blob. ``whole`` means the blob
    IS a PowerShell script (a .ps1); otherwise mine invocations and markers."""
    if not text or not text.strip():
        return []
    if whole:
        return [text]
    out: list[str] = []
    for m in _INVOKE.finditer(text):
        out.append(m.group(1).strip())
    if not out:
        # Dropped script body with no explicit powershell.exe — mine marker lines.
        for ln in text.splitlines():
            if _PS_MARKER.search(ln):
                out.append(ln.strip())
    return out


def _sources_from_modules(modules: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(origin, location, text) blobs that may hold PowerShell."""
    blobs: list[tuple[str, str, str]] = []

    ole = modules.get("oletools") or {}
    if ole.get("code_text"):
        blobs.append(("VBA source", "vba", ole["code_text"]))
    for link in ole.get("dde_links") or []:
        blobs.append(("DDE link", "dde", str(link)))
    olevba = ((ole.get("tools") or {}).get("olevba") or {})
    for enc, dec in (olevba.get("decoded_strings") or {}).get("base64", []) or []:
        blobs.append(("VBA decoded string", "vba", str(dec)))

    vmon = modules.get("vipermonkey") or {}
    for act in vmon.get("actions") or []:
        if isinstance(act, dict):
            txt = " ".join(str(act.get(k, "")) for k in ("action", "params", "description"))
            blobs.append(("ViperMonkey action", "vipermonkey", txt))

    js = modules.get("javascript") or {}
    for sc in js.get("scripts") or []:
        if not isinstance(sc, dict):
            continue
        loc = sc.get("location") or "javascript"
        for e in (sc.get("sandbox") or {}).get("log") or []:
            if e.get("kind") in ("call", "activex"):
                blobs.append(("JS sandbox command", loc, " ".join(e.get("args") or [])))

        for d in sc.get("decoded") or []:
            blobs.append(("JS decoded string", loc, str(d.get("decoded") or "")))
        if sc.get("code_is_deobfuscated"):
            blobs.append(("deobfuscated JS", loc, sc.get("code") or ""))

    # Commands launched by VBScript / batch (WScript.Shell.Run "powershell …",
    # cmd /c powershell …): their recovered code is mined for PowerShell.
    for name in ("vbscript", "batch"):
        for sc in (modules.get(name) or {}).get("scripts") or []:
            if isinstance(sc, dict):
                blobs.append((f"{name} command", sc.get("location") or name,
                              str(sc.get("code") or "")))

    for name in ("word", "excel", "powerpoint", "rtf"):
        mod = modules.get(name) or {}
        for f in mod.get("findings") or []:
            ev = str(f.get("evidence") or "")
            if _PS_MARKER.search(ev) or re.search(r"(?i)powershell", ev):
                blobs.append((f"{name} field", name, ev))

    # Shortcuts and MSI installers surface their launched command in `_full_code`
    # (and per-item): give any PowerShell there a real layered-deobfuscation tab.
    for name in ("shortcut", "msi"):
        mod = modules.get(name) or {}
        for it in mod.get("items") or []:
            cmd = str(it.get("_full_code") or it.get("command") or "")
            if cmd and re.search(r"(?i)powershell|pwsh", cmd):
                blobs.append((f"{name} command", it.get("file") or name, cmd))
    return blobs


def collect(original: Path, extracted_dir: Path, modules: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(origin: str, location: str, command: str) -> None:
        if command and command.strip():
            items.append({"origin": origin, "location": location, "code": command[:_MAX_FILE_BYTES]})

    # Dropped files.
    paths: list[Path] = []
    if extracted_dir.is_dir():
        paths = [p for p in sorted(extracted_dir.rglob("*")) if p.is_file()][:_MAX_FILES]
    if original.is_file():
        paths.append(original)
    for p in paths:
        ext = p.suffix.lower()
        if ext not in _PS_FILE_EXT and ext not in _SHELL_FILE_EXT:
            continue
        try:
            text = p.read_bytes()[:_MAX_FILE_BYTES].decode("utf-8", "replace")
        except OSError:
            continue
        try:
            rel = p.relative_to(extracted_dir.parent).as_posix()
        except ValueError:
            rel = p.name
        for cmd in _candidates(text, whole=(ext in _PS_FILE_EXT)):
            add(f"file:{rel}", f"file:{rel}", cmd)

    # Mined from other modules' results.
    for origin, location, text in _sources_from_modules(modules):
        for cmd in _candidates(text, whole=False):
            add(origin, location, cmd)

    # De-duplicate by command text, and drop a command already contained in a
    # longer one (the JS sandbox logs the same stage as XOR result and as Run).
    seen: set[str] = set()
    uniq = []
    for it in items:
        key = it["code"].strip()
        if key and key not in seen:
            seen.add(key)
            uniq.append(it)
    keys = [it["code"].strip() for it in uniq]
    uniq = [it for i, it in enumerate(uniq)
            if not any(i != j and keys[i] != keys[j] and keys[i] in keys[j] for j in range(len(keys)))]
    return uniq[:_MAX_ITEMS]


def analyze(original: Path, extracted_dir: Path, modules: dict[str, Any]) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "powershell", "status": "ok", "scripts": [], "findings": []}
    sandbox_on = boxps.boxps_status().get("available", False)
    res["sandbox_available"] = sandbox_on
    sandbox_runs = 0
    for i, it in enumerate(collect(original, extracted_dir, modules), 1):
        full = it["code"] or ""
        orig_code = full[:_MAX_CODE]
        loc = it["location"]

        deob = ps_deobf.deobfuscate(full)
        deob_full = deob["code"]
        code = deob_full[:_MAX_CODE] if deob["changed"] else orig_code

        hits = static_hits(code)
        mets = javascript.metrics(code)
        script = {"id": i, "kind": "powershell", "origin": it["origin"], "location": loc,
                  "size": len(full), "code": code[:_KEEP_CODE], "code_truncated": len(deob_full) > _KEEP_CODE,
                  "code_is_deobfuscated": deob["changed"],
                  "original_code": orig_code[:_KEEP_CODE] if deob["changed"] else "",
                  "original_truncated": deob["changed"] and len(full) > _KEEP_CODE,
                  "deob_methods": deob["methods"], "deob_schemes": [],
                  "deob_size": len(deob_full) if deob["changed"] else 0,
                  "hits": hits, "metrics": mets, "_full_code": full}
        if deob["changed"]:
            script["_full_deob"] = deob_full

        # box-ps behavioural sandbox: emulate the (deobfuscated) command and
        # record what it would do. Capped per case; each run is slow.
        if sandbox_on and sandbox_runs < _MAX_SANDBOX_RUNS and code.strip():
            sandbox_runs += 1
            sb = boxps.analyze(code, loc)
            script["sandbox"] = {"available": sb.get("available"), "actions": sb.get("actions", [])[:50],
                                 "iocs": sb.get("iocs", [])[:50], "error": sb.get("error")}
            if sb.get("layers") and not deob["changed"]:
                script["sandbox_layers"] = sb["layers"][:_KEEP_CODE]
            for f in sb.get("findings", []):
                f["detail"] = f"[{it['origin']}] {f['detail']}"
                res["findings"].append(f)
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
            res["findings"].append(_finding("ps_deobfuscated", "medium",
                                            f"[{it['origin']}] PowerShell deobfuscated before analysis ({methods})",
                                            loc, (code[:600] or "").strip()))
    res["counts"] = {"findings": len(res["findings"]), "scripts": len(res["scripts"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
