"""JavaScript extraction and analysis across every family.

Collects the scripts a case carries, wherever they are:
- PDF: /JS literal/hex strings (pdf parser) and /JS streams (resolved here);
- email: <script> blocks, on*= handlers and javascript: links of the HTML body;
- extracted files: attachments, OLE Package objects, PDF embedded files, nested
  children and ViperMonkey artifacts — .js, .jse (Script Encoder, decoded with
  Didier Stevens' decode-vbe.py), .wsf, .hta, .html/.htm/.svg/.mht...;
- VBA: JScript handed to ScriptControl (``.Language = "JScript"`` + AddCode).

Each script gets a static analysis — dangerous APIs with the exact lines,
obfuscation metrics, simple decoding (base64, %xx/%u, \\x, fromCharCode),
pretty-printing — and a run in the STPyV8 sandbox (js_sandbox.py: separate
process, time limit, only recording host stubs) that unfolds eval/Function
layers and records what the script would do. Nothing touches the host.
"""

from __future__ import annotations

import base64
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .. import quiet, toolrun
from ..logging_config import get_logger
from . import script_rules
from .didier import didier_dir
from ..config import tmo

log = get_logger(__name__)

_MAX_SCRIPTS = 60
_MAX_FILES = 300
_MAX_FILE_BYTES = 5 * 1024 * 1024
# tag: AeWckx3pKh
_MAX_CODE = 300_000
_MAX_TECH = 8_000_000      # technique detectors are linear; bound only pathological inputs
_KEEP_CODE = 60_000
_SANDBOX_TIMEOUT = tmo(15)
_SANDBOX_OUTPUT = 64 * 1024 * 1024
_PARALLEL_SCRIPTS = 3        # scripts analysed at once (sandbox/webcrack are separate processes)
_SCRIPT_EXT = {".js", ".mjs", ".jse", ".wsf", ".hta", ".html", ".htm", ".shtml", ".xhtml", ".svg",
               ".mht", ".mhtml", ".xsl", ".sct", ".wsc"}

# Behaviour patterns live in the shared catalogue (script_rules); this module
# keeps only the JS-specific noise rule used to drop single-hit medium findings.
_MEDIUM_ONLY_IS_NOISE = {"js_redirect"}


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "javascript", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


# --- extraction ---------------------------------------------------------------------

_SCRIPT_TAG = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_HANDLER = re.compile(r"\bon[a-z]{3,20}\s*=\s*(\"[^\"]{1,4000}\"|'[^']{1,4000}')", re.IGNORECASE)
_JS_LINK = re.compile(r"href\s*=\s*[\"']\s*javascript:([^\"']{1,4000})", re.IGNORECASE)


def scripts_from_html(html: str) -> list[str]:
    """Inline <script> code (not src=), event handlers and javascript: links."""
    out: list[str] = []
    for attrs, code in _SCRIPT_TAG.findall(html):
        lang = re.search(r"language\s*=\s*[\"']?([\w.]+)", attrs, re.IGNORECASE)
        if lang and "vb" in lang.group(1).lower():
            continue  # VBScript blocks (HTA) are not JavaScript
        if code.strip():
            out.append(code)
    handlers = [h[1:-1] for h in _HANDLER.findall(html)]
    links = _JS_LINK.findall(html)
    extra = handlers + links
    if extra:
        out.append("\n".join(extra))
    return out


def _decode_jse(path: Path) -> str:
    script = didier_dir() / "decode-vbe.py"
    if not script.is_file():
        return ""
    # Fed through stdin: decode-vbe.py reads files as bytes and then applies a
    # str regex (TypeError on Python 3), while stdin is read as text.
    try:
        text = path.read_bytes()[:_MAX_FILE_BYTES].decode("latin-1")
    except OSError:
        return ""
    rec = toolrun.run(quiet.python_tool_cmd(str(script), [], script=True),
                      f"decode-vbe.py < {path.name}", timeout=tmo(60), extra_env=toolrun.with_package_path(),
                      input_text=text)
    out = rec.get("output") or ""
    return "" if out.strip() == "No encoded script found!" else out


def decode_mht(raw: bytes) -> str:
    """Return the HTML of an MHT/MHTML (MIME) container, decoding quoted-printable
    and base64 parts so scripts hidden by MIME encoding become visible."""
    try:
        import email
        msg = email.message_from_bytes(raw)
        parts: list[str] = []
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype in ("text/html", "text/plain", "application/octet-stream") or "html" in ctype:
                payload = part.get_payload(decode=True)
                if payload:
                    parts.append(payload.decode("utf-8", "replace"))
        if parts:
            return "\n".join(parts)
    except Exception:  # noqa: BLE001
        pass
    try:
        import quopri
        return quopri.decodestring(raw).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return raw.decode("utf-8", "replace")


def _from_file(path: Path, rel: str) -> list[dict[str, Any]]:
    ext = path.suffix.lower()
    try:
        raw = path.read_bytes()[:_MAX_FILE_BYTES]
    except OSError:
        return []
    if ext in (".mht", ".mhtml"):
        html = decode_mht(raw)
        items = [{"kind": "mht", "code": code, "origin": rel, "location": f"file:{rel}"}
                 for code in scripts_from_html(html)]
        return items
    text = raw.decode("utf-8", "replace")
    if ext not in _SCRIPT_EXT:
        head = text[:65536].lower()
        if "<script" not in head and "<html" not in head:
            return []
        ext = ".html"
    items: list[dict[str, Any]] = []
    if ext == ".jse" or "#@~^" in text[:4096]:
        dec = _decode_jse(path)
        if dec.strip():
            items.append({"kind": "jscript-encoded", "code": dec, "note": "decoded from Script Encoder (.jse)"})
    elif ext == ".js":
        items.append({"kind": "jscript/js", "code": text})
    elif ext in (".wsf", ".wsc", ".sct"):
        for attrs, code in _SCRIPT_TAG.findall(text):
            if not re.search(r"vbscript", attrs, re.IGNORECASE) and code.strip():
                items.append({"kind": "wsf-jscript", "code": re.sub(r"^\s*<!\[CDATA\[|\]\]>\s*$", "", code.strip())})
    else:
        for code in scripts_from_html(text):
            items.append({"kind": "hta" if ext == ".hta" else ("svg" if ext == ".svg" else "html"), "code": code})
    for it in items:
        it["origin"] = rel
        it["location"] = f"file:{rel}"
    return items


def _pdf_streams(original: Path) -> list[str]:
    # bhd1Sl5iFX
    """JavaScript held in streams referenced by /JS n 0 R (pypdf, best effort)."""
    out: list[str] = []
    try:
        data = original.read_bytes()[:30 * 1024 * 1024]
        refs = {(int(a), int(b)) for a, b in re.findall(rb"/JS\s+(\d+)\s+(\d+)\s+R", data)}
        if not refs:
            return out
        from pypdf import PdfReader
        from pypdf.generic import IndirectObject
        reader = PdfReader(str(original), strict=False)
        for num, gen in sorted(refs)[:_MAX_SCRIPTS]:
            try:
                obj = IndirectObject(num, gen, reader).get_object()
                code = obj.get_data() if hasattr(obj, "get_data") else str(obj)
                if isinstance(code, bytes):
                    code = code.decode("utf-16") if code[:2] in (b"\xfe\xff", b"\xff\xfe") else code.decode("latin-1")
                if code.strip():
                    out.append(code)
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return out


def _vba_jscript(modules: list[dict[str, Any]]) -> list[str]:
    out = []
    for m in modules or []:
        code = m.get("code") or ""
        if re.search(r"\.Language\s*=\s*\"JScript\"", code, re.IGNORECASE):
            parts = re.findall(r"\.(?:AddCode|ExecuteStatement|Eval)\s*\(?\s*\"((?:[^\"]|\"\")*)\"", code, re.IGNORECASE)
            if parts:
                out.append("\n".join(p.replace('""', '"') for p in parts))
    return out


def collect(original: Path, extracted_dir: Path, modules: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    pdf = modules.get("pdf") or {}
    for i, j in enumerate(pdf.get("javascript") or []):
        items.append({"kind": "pdf", "code": j.get("code") or "", "origin": "PDF /JS string",
                      "location": f"pdf:js#{i + 1}"})
    if pdf:
        known = {j.get("code") for j in pdf.get("javascript") or []}
        for i, code in enumerate(_pdf_streams(original)):
            if code not in known:
                items.append({"kind": "pdf", "code": code, "origin": "PDF /JS stream",
                              "location": f"pdf:js-stream#{i + 1}"})
    email = modules.get("email") or {}
    for i, code in enumerate(scripts_from_html(email.get("html_source_sample") or "")):
        items.append({"kind": "html", "code": code, "origin": "email HTML body", "location": f"body:script#{i + 1}"})
    olevba = ((modules.get("oletools") or {}).get("tools") or {}).get("olevba") or {}
    for code in _vba_jscript(olevba.get("modules") or []):
        items.append({"kind": "vba-jscript", "code": code, "origin": "JScript inside VBA (ScriptControl)",
                      "location": "vba"})
    if extracted_dir.is_dir():
        from ..codefiles import input_files
        files = input_files(extracted_dir, _MAX_FILES)
        for p in files:
            rel = p.relative_to(extracted_dir.parent).as_posix()
            items += _from_file(p, rel)
    # Standalone script/HTML files analysed directly (e.g. a .hta uploaded as a case).
    if original.suffix.lower() in _SCRIPT_EXT:
        items += _from_file(original, original.name)
    seen: set[str] = set()
    uniq = []
    for it in items:
        key = it["code"].strip()
        if key and key not in seen:
            seen.add(key)
            uniq.append(it)
    return uniq[:_MAX_SCRIPTS]


# --- analysis ------------------------------------------------------------------------

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def metrics(code: str) -> dict[str, Any]:
    lines = code.splitlines() or [""]
    longest = max(len(ln) for ln in lines)
    escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}", code))
    long_strings = len(re.findall(r"[\"'][A-Za-z0-9+/=]{120,}[\"']|[\"'][0-9a-fA-F]{120,}[\"']", code))
    idents = re.findall(r"\b(?:var|let|const|function)\s+(_0x[0-9a-f]+|[A-Za-z_$][\w$]{0,40})", code)
    weird = sum(1 for i in idents if i.startswith("_0x") or (len(i) > 8 and not re.search(r"[aeiou]", i, re.I)))
    score = 0
    score += 2 if longest > 2000 else (1 if longest > 500 else 0)
    score += 2 if escapes > 200 else (1 if escapes > 30 else 0)
    score += 2 if long_strings >= 2 else (1 if long_strings else 0)
    score += 1 if _entropy(code) > 5.3 else 0
    score += 2 if idents and weird / max(1, len(idents)) > 0.5 else 0
    return {"length": len(code), "lines": len(lines), "longest_line": longest, "escapes": escapes,
            "long_strings": long_strings, "entropy": round(_entropy(code), 2),
            "identifiers": len(idents), "random_identifiers": weird, "obfuscation_score": score}


def decode_strings(code: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []

    def printable(s: str) -> bool:
        return bool(s) and sum(ch.isprintable() or ch in "\r\n\t" for ch in s) / len(s) > 0.9

    for m in re.finditer(r"[\"']([A-Za-z0-9+/]{40,}={0,2})[\"']", code):
        try:
            dec = base64.b64decode(m.group(1) + "===").decode("utf-8")
        except Exception:  # noqa: BLE001
            try:
                dec = base64.b64decode(m.group(1) + "===").decode("utf-16-le")
            except Exception:  # noqa: BLE001
                continue
        if printable(dec):
            out.append({"method": "base64", "encoded": m.group(1)[:120], "decoded": dec[:2000]})
    for m in re.finditer(r"unescape\s*\(\s*[\"']((?:%u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}|[^\"'%]){8,})[\"']", code):
        enc = m.group(1)
        dec = re.sub(r"%u([0-9a-fA-F]{4})", lambda x: chr(int(x.group(1), 16)), enc)
        dec = re.sub(r"%([0-9a-fA-F]{2})", lambda x: chr(int(x.group(1), 16)), dec)
        out.append({"method": "unescape", "encoded": enc[:120], "decoded": dec[:2000]})
    for m in re.finditer(r"String\.fromCharCode\s*\(\s*((?:\d{1,5}\s*,\s*){3,}\d{1,5})\s*\)", code):
        try:
            dec = "".join(chr(int(x)) for x in m.group(1).split(","))
            out.append({"method": "fromCharCode", "encoded": m.group(1)[:120], "decoded": dec[:2000]})
        except ValueError:
            pass
    for m in re.finditer(r"[\"']((?:\\x[0-9a-fA-F]{2}){8,})[\"']", code):
        dec = bytes.fromhex(m.group(1).replace("\\x", "")).decode("latin-1")
        out.append({"method": "\\x escapes", "encoded": m.group(1)[:120], "decoded": dec[:2000]})
    seen: set[str] = set()
    return [d for d in out if not (d["decoded"] in seen or seen.add(d["decoded"]))][:40]


def static_hits(code: str) -> list[dict[str, Any]]:
    """Behaviour hits from the shared catalogue (JScript/JavaScript rules)."""
    return script_rules.scan(code, script_rules.JS)


def _pretty(code: str) -> str:
    try:
        import jsbeautifier
        return jsbeautifier.beautify(code[:200_000])
    except Exception:  # noqa: BLE001
        return code


def sandbox(code: str) -> dict[str, Any]:
    from .. import js_sandbox

    rec = toolrun.run([sys.executable, "-m", "docutracex.js_sandbox"], "js_sandbox (STPyV8)",
                      timeout=_SANDBOX_TIMEOUT, extra_env=toolrun.with_package_path(),
                      input_text=code,
                      # the event log is the result (dropped files whole): the
                      # generic 60 KB tool-output bound would cut events off
                      bound=_SANDBOX_OUTPUT)
    res = js_sandbox.parse_output(rec.get("output") or "", timed_out=bool(rec.get("timed_out")))
    if rec.get("error") and not rec.get("timed_out"):
        res["error"] = rec["error"]
    return res


def _sandbox_findings(sb: dict[str, Any], loc: str, out: list[dict[str, Any]]) -> None:
    logs = sb.get("log") or []
    layers = [e for e in logs if e["kind"] == "layer"]
    if layers:
        out.append(_finding("js_deobfuscated_layers", "medium",
                            f"Sandbox unfolded {len(layers)} dynamic code layer(s) (eval/Function/document.write)",
                            loc, (layers[-1]["args"] or [""])[0][:600]))
    cmds = [e for e in logs if e["kind"] == "call" and re.search(r"\.(Run|Exec|ShellExecute|Create)$", e["name"])]
    if cmds:
        out.append(_finding("js_sandbox_command", "high",
                            "Sandbox: the script tries to run a command",
                            loc, "\n".join(f"{e['name']}({', '.join(e['args'])})" for e in cmds[:5])))
    ax = [e for e in logs if e["kind"] == "activex"]
    # rev: gmzpt
    if ax:
        # gmzpt
        out.append(_finding("js_sandbox_activex", "high",
                            f"Sandbox: creates COM objects {', '.join(sorted({e['args'][0] for e in ax if e['args']})[:6])}",
                            loc, "\n".join(f"{e['name']}({', '.join(e['args'])})" for e in ax[:8])))
    urls = [e for e in logs if e["kind"] == "url" or (e["kind"] == "call" and re.search(r"\.(Open|launchURL|getURL)$", e["name"]))]
    if urls:
        out.append(_finding("js_sandbox_network", "high",
                            "Sandbox: the script opens/navigates to URLs",
                            loc, "\n".join(f"{e['name']} {' '.join(e['args'])}" for e in urls[:8])))
    dom = [e["name"] for e in logs if e["kind"] == "dom"]
    if "new Blob" in dom and ("URL.createObjectURL" in dom or "msSaveOrOpenBlob" in dom):
        out.append(_finding("js_sandbox_smuggling", "high",
                            "Sandbox: builds a Blob and triggers a download (HTML smuggling)", loc,
                            "\n".join(f"{e['name']} {' '.join(e['args'])}" for e in logs if e["kind"] == "dom")[:800]))
    exports = [e for e in logs if e["name"] == "this.exportDataObject"]
    if exports:
        out.append(_finding("pdf_js_export_launch", "high", "Sandbox: PDF script exports (and may launch) an attachment",
                            loc, "\n".join(" ".join(e["args"]) for e in exports[:5])))


def analyze(original: Path, extracted_dir: Path, modules: dict[str, Any],
            run_sandbox: bool = True) -> dict[str, Any]:
    from . import js_deobf, js_techniques, js_webcrack

    res: dict[str, Any] = {"module": "javascript", "status": "ok", "scripts": [], "findings": []}
    items = list(enumerate(collect(original, extracted_dir, modules), 1))

    def one(i: int, it: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        out_scripts: list[dict[str, Any]] = []
        out_findings: list[dict[str, Any]] = []
        full = it["code"] or ""           # complete original source (dumped whole)
        orig_code = full[:_MAX_CODE]      # bounded original for metrics / display
        loc = it["location"]

        # --- deobfuscation FIRST: everything below analyses the clean artifact.
        # webcrack (Node) flattens obfuscator.io string-array/rotator and bundle
        # obfuscation when provisioned; the pure-Python cascade then peels any
        # remaining decode/eval layers. webcrack runs top-level only (one Node
        # process per child would be heavy) and degrades gracefully when absent.
        # webcrack (Node) only for obfuscator.io / bundles: all it adds there.
        wc = (js_webcrack.deobfuscate(full) if run_sandbox and js_webcrack.needs_webcrack(full)
              else {"changed": False, "code": full})
        base = wc["code"] if wc.get("changed") else full
        deob = js_deobf.deobfuscate(base)
        deob_full = deob["code"]
        changed = bool(wc.get("changed")) or deob["changed"]
        deob_methods = (["webcrack"] if wc.get("changed") else []) + deob["methods"]
        code = deob_full[:_MAX_CODE] if changed else orig_code

        hits = static_hits(code)
        mets = metrics(orig_code)          # how obfuscated the ORIGINAL was
        mets_deob = metrics(code) if changed else None
        decoded = decode_strings(code)
        # The STPyV8 sandbox is skipped on nested children (run_sandbox=False):
        # the static deobfuscation still runs, which is what nested needs.
        # The sandbox runs the WHOLE (deobfuscated) script: a copy cut at the
        # display/metrics limit ends mid-statement and V8 rejects it with a
        # SyntaxError before running anything.
        sb = (sandbox(js_techniques.instrument(deob_full if changed else full)) if run_sandbox
              else {"log": [], "error": None, "available": None, "timed_out": False})
        # Techniques read the whole original too (a cut string literal would
        # also hide an escape block or a payload array).
        techniques = (js_techniques.static_techniques(full[:_MAX_TECH], mets["obfuscation_score"])
                      + js_techniques.from_sandbox(sb))
        script = {"id": i, "kind": it["kind"], "origin": it["origin"], "location": loc, "note": it.get("note"),
                  "size": len(full), "code": code[:_KEEP_CODE], "code_truncated": len(deob_full) > _KEEP_CODE,
                  "code_is_deobfuscated": changed,
                  "original_code": orig_code[:_KEEP_CODE] if changed else "",
                  "original_truncated": changed and len(full) > _KEEP_CODE,
                  "deob_methods": deob_methods, "deob_layers": deob["layers"], "deob_schemes": deob["schemes"],
                  "deob_size": len(deob_full) if changed else 0,
                  "pretty": _pretty(code)[:_KEEP_CODE] if metrics(code)["longest_line"] > 200 else "",
                  "hits": hits, "metrics": mets, "metrics_deob": mets_deob, "decoded": decoded, "sandbox": sb,
                  "techniques": techniques,
                  "_full_code": full}
        if changed:
            script["_full_deob"] = deob_full
        out_scripts.append(script)
        by_rule: dict[str, list[dict[str, Any]]] = {}
        for h in hits:
            by_rule.setdefault(h["rule"], []).append(h)
        for rule, hs in by_rule.items():
            if rule in _MEDIUM_ONLY_IS_NOISE and len(by_rule) == 1:
                continue
            out_findings.append(_finding(rule, hs[0]["severity"], f"[{it['origin']}] {hs[0]['label']}", loc,
                                            "\n".join(f"line {h['line_no']}: {h['line']}" for h in hs[:5])))
        if mets["obfuscation_score"] >= 4:
            out_findings.append(_finding("js_obfuscated", "medium" if mets["obfuscation_score"] < 6 else "high",
                                            f"[{it['origin']}] Heavily obfuscated script (score {mets['obfuscation_score']})",
                                            loc, f"longest line {mets['longest_line']}, {mets['escapes']} escapes, "
                                                 f"entropy {mets['entropy']}, {mets['long_strings']} long encoded strings"))
        if changed:
            methods = ", ".join(deob_methods) or "static decoding"
            scheme_note = f"; packer scheme(s): {', '.join(deob['schemes'])}" if deob["schemes"] else ""
            out_findings.append(_finding("js_deobfuscated", "medium",
                                            f"[{it['origin']}] Deobfuscated before analysis ({methods}){scheme_note} — "
                                            f"findings below are from the recovered payload",
                                            loc, (code[:600] or "").strip()))
        elif deob["schemes"]:
            out_findings.append(_finding("js_obfuscated", "high",
                                            f"[{it['origin']}] Obfuscation scheme detected ({', '.join(deob['schemes'])}) — "
                                            f"left for the sandbox to unfold", loc, deob["schemes"][0]))
        _sandbox_findings(sb, loc, out_findings)
        for t in techniques:
            if t["severity"] == "info":
                continue
            where = "resolved in the sandbox" if t["phase"] == "sandbox" else "static"
            out_findings.append(_finding(f"js_{t['id']}", t["severity"],
                                            f"[{it['origin']}] {t['name']} ({where})", loc, t["evidence"]))
        return out_scripts, out_findings

    # Scripts are analysed in parallel (webcrack and the STPyV8 sandbox are
    # separate processes), results kept in their original order; each finished
    # script is reported to the Tasks tab as "script N/M".
    from ..analyze import step_progress_reporter
    progress = step_progress_reporter()
    results: dict[int, tuple[list, list]] = {}
    if items:
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed

        done = 0
        done_lock = threading.Lock()
        workers = max(1, min(_PARALLEL_SCRIPTS, len(items))) if run_sandbox else 1
        progress(f"script 0/{len(items)}")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(one, i, it): i for i, it in items}
            for fut in as_completed(futs):
                i = futs[fut]
                try:
                    results[i] = fut.result()
                except Exception as exc:  # noqa: BLE001  (one script must not sink the rest)
                    results[i] = ([], [_finding("js_analysis_error", "info", f"Script {i} could not be analysed: {exc}",
                                                "javascript")])
                with done_lock:
                    done += 1
                    progress(f"script {done}/{len(items)}")
    for i in sorted(results):
        res["scripts"].extend(results[i][0])
        res["findings"].extend(results[i][1])
    res["counts"] = {"findings": len(res["findings"]), "scripts": len(res["scripts"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
