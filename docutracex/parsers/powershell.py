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

import base64

import re
from pathlib import Path
from typing import Any

from . import boxps, javascript, ps_deobf, script_rules

_MAX_SANDBOX_RUNS = 12          # cap box-ps invocations per case (each is slow)

_MAX_ITEMS = 5000              # scripts analysed per file (every one, in practice)
_MAX_FILES = 300
_MAX_FILE_BYTES = 64 * 1024 * 1024    # a loader carrying a whole PE in a literal (tens of MB seen)
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


# Invoke-Obfuscation tricks ps_deobf resolves (method name -> description).
_INVOKE_OBF = {
    "env-var-slice": "'iex' sliced from $env:ComSpec/$PSHome/$ShellId",
    "reverse-string": "reversed strings",
    "numeric-char-codes": "octal/binary/hex char codes split and re-joined",
    "replace-chain": "-replace/.Replace chains",
    "command-lookup": "wildcard command lookup (gcm *ke-e*)",
    "alias": "aliased Invoke-Expression",
    "scriptblock": "[ScriptBlock]::Create / InvokeScript",
}


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


def collect(original: Path, extracted_dir: Path, modules: dict[str, Any],
            fallback: bool = False, fallback_text: str | None = None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(origin: str, location: str, command: str) -> None:
        if command and command.strip():
            items.append({"origin": origin, "location": location, "code": command[:_MAX_FILE_BYTES]})

    # Dropped files.
    paths: list[Path] = []
    if extracted_dir.is_dir():
        from ..codefiles import input_files
        paths = input_files(extracted_dir, _MAX_FILES)
    if original.is_file():
        paths.append(original)
    for p in paths:
        ext = p.suffix.lower()
        is_original_fallback = fallback and p == original
        if ext not in _PS_FILE_EXT and ext not in _SHELL_FILE_EXT and not is_original_fallback:
            continue
        if is_original_fallback and fallback_text is not None:
            text = fallback_text[:_MAX_FILE_BYTES]
        else:
            try:
                text = p.read_bytes()[:_MAX_FILE_BYTES].decode("utf-8", "replace")
            except OSError:
                continue
        try:
            rel = p.relative_to(extracted_dir.parent).as_posix()
        except ValueError:
            rel = p.name
        for cmd in _candidates(text, whole=(ext in _PS_FILE_EXT or is_original_fallback)):
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


_HOSTS = (r"aspnet_compiler|RegAsm|RegSvcs|MSBuild|InstallUtil|vbc|csc|jsc|AppLaunch|CasPol|aspnet_regbrowsers|"
          r"aspnet_regiis|aspnet_wp|AddInProcess(?:32)?|Microsoft\.Workflow\.Compiler|ilasm|dfsvc|svchost|explorer")
_SHAPES = (
    # (rule, severity, label, [regex that must ALL be found in the script])
    ("ps_process_watch_loop", "high",
     "waits in a loop until a process is not running, then acts (re-injects when the host dies) · T1055",
     [r"(?i)while\s*\(\s*\$true\s*\)|for\s*\(\s*;\s*;\s*\)|do\s*\{", r"(?i)Get-Process|\bgps\b|Win32_Process",
      r"(?i)Start-Sleep|Thread\]::Sleep"]),
    ("ps_reflective_invoke", "high",
     "loads an assembly from bytes and calls one of its methods by name (reflective loader) · T1620",
     [r"(?i)(?:Reflection\.Assembly\]::Load|\.Load\s*\(\s*\$)", r"(?i)\.GetMethod\s*\(|\.GetType\s*\(|EntryPoint",
      r"(?i)\.Invoke\s*\("]),
    ("ps_reflective_host_injection", "high",
     "hands a payload to a loaded assembly together with a .NET / Windows host binary (process hollowing) · T1055.012",
     [r"(?i)\.Invoke\s*\(", r"(?i)(?:" + _HOSTS + r")\.exe", r"(?i)Reflection\.Assembly\]::Load|\[byte\[\]\]"]),
    ("ps_layered_loader_integrity", "medium",
     "multi-layer loader: decrypts, checks the integrity of the result (hash) and runs it · T1027",
     [r"(?i)SHA256|ComputeHash", r"(?i)CreateDecryptor|TransformFinalBlock|CryptoStream",
      r"(?i)ScriptBlock\]::Create|Invoke-Expression|\biex\b|Reflection\.Assembly\]::Load"]),
)


def _loader_shapes(code: str) -> list[tuple[str, str, str, str]]:
    """Loader behaviours that only show across the script (several constructs together)."""
    head = code[:4_000_000]
    out = []
    for rule, sev, label, rxs in _SHAPES:
        ms = [re.search(rx, head) for rx in rxs]
        if all(ms):
            ev = "\n".join(head[max(0, m.start() - 40):m.end() + 60].replace("\r", "").replace("\n", " ")[:200] for m in ms)
            out.append((rule, sev, label, ev))
    return out


def _resolve(code: str, deob: str | None, loc: str) -> dict[str, Any] | None:
    """The static evaluator's result for one script (resolve.report.run)."""
    from ..resolve import ps_eval, report
    return report.run(ps_eval.resolve, code, loc, "ps", deob)


def analyze(original: Path, extracted_dir: Path, modules: dict[str, Any],
            fallback: bool = False, fallback_text: str | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "powershell", "status": "ok", "scripts": [], "findings": []}
    sandbox_on = boxps.boxps_status().get("available", False)
    res["sandbox_available"] = sandbox_on
    sandbox_runs = 0
    for i, it in enumerate(collect(original, extracted_dir, modules, fallback=fallback, fallback_text=fallback_text), 1):
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
                  "decoded_stages": [({"recipe": st["recipe"], "text": st["text"][:400_000]} if "text" in st else
                                      {"recipe": st["recipe"], "data_b64": base64.b64encode(st["data"][:8_000_000]).decode()})
                                     for st in deob.get("stages") or []],
                  "deob_size": len(deob_full) if deob["changed"] else 0,
                  "hits": hits, "metrics": mets, "_full_code": full}
        if deob["changed"]:
            script["_full_deob"] = deob_full

        # static resolution: the script's values and operations followed to what it runs, loads
        # or writes (here-strings → base64 → AES → GZip → ScriptBlock, a PE handed to a loader…)
        resolved = _resolve(full, deob_full if deob["changed"] else None, loc)
        if resolved:
            from ..resolve import report
            script["decoded_stages"] = report.merge(resolved["stages"], script["decoded_stages"])
            script["resolution"] = resolved["summary"]
            for f in resolved["findings"]:
                res["findings"].append(_finding(f["rule"], f["severity"], f"[{it['origin']}] {f['detail']}", loc,
                                                f.get("evidence", "")))

        # box-ps behavioural sandbox: emulate the (deobfuscated) command and
        # record what it would do. Capped per case; each run is slow.
        from .. import appsettings
        if sandbox_on and sandbox_runs < _MAX_SANDBOX_RUNS and code.strip() and \
                appsettings.sandbox_wanted(script.get("resolution"), deob["changed"] or len(deob["methods"]) > 0):
            sandbox_runs += 1
            sb = boxps.analyze(code, loc)
            script["sandbox"] = {"available": sb.get("available"), "actions": sb.get("actions", [])[:50],
                                 "iocs": sb.get("iocs", [])[:50], "error": sb.get("error")}
            if sb.get("layers") and not deob["changed"]:
                script["sandbox_layers"] = sb["layers"][:_KEEP_CODE]
            # what box-ps saw, next to the static result; its deobfuscated layers go to Nested too
            layers = (sb.get("layers") or "").strip()
            known = {(st.get("text") or "").strip() for st in script["decoded_stages"]}
            if layers and layers not in known and layers != full.strip() and layers != deob_full.strip():
                script["decoded_stages"].append({"recipe": ["sandbox (box-ps)", "layers"], "text": layers[:400_000],
                                                 "ext": ".ps1", "sink": "box-ps"})
            ev = [{"kind": "behaviour", "what": ", ".join(a.get("behaviours") or [])[:120], "detail": a.get("line", "")}
                  for a in sb.get("actions") or [] if a.get("behaviours")]
            ev += [{"kind": "network", "what": "indicator", "detail": i} for i in sb.get("iocs") or []]
            if layers:
                ev.insert(0, {"kind": "runs code", "what": "deobfuscated layers", "detail": layers[:300], "size": len(layers)})
            if ev:
                script.setdefault("resolution", {"stages": [], "downloads": [], "unresolved": [], "steps": []})[
                    "sandbox"] = {"tool": "box-ps", "events": ev[:60]}
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
        for rule, sev, label, ev in _loader_shapes(full if len(full) < 8_000_000 else code):
            res["findings"].append(_finding(rule, sev, f"[{it['origin']}] {label}", loc, ev))
        chain = script_rules.risk_escalation(hits)
        if chain:
            res["findings"].append(_finding(chain["rule"], chain["severity"],
                                            f"[{it['origin']}] {chain['label']}", loc, chain["detail"]))
        if deob["changed"]:
            methods = ", ".join(deob["methods"]) or "static decoding"
            res["findings"].append(_finding("ps_deobfuscated", "medium",
                                            f"[{it['origin']}] PowerShell deobfuscated before analysis ({methods})",
                                            loc, (code[:600] or "").strip()))
            io = [m for m in deob["methods"] if m in _INVOKE_OBF]
            if len(io) >= 2:
                res["findings"].append(_finding(
                    "ps_invoke_obfuscation", "high",
                    f"[{it['origin']}] Invoke-Obfuscation-style launcher (T1027.010): "
                    + ", ".join(_INVOKE_OBF[m] for m in io) + " — resolved statically",
                    loc, (it["code"][:400] or "").strip()))
    res["counts"] = {"findings": len(res["findings"]), "scripts": len(res["scripts"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
