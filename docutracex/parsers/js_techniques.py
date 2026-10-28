"""Obfuscation techniques confirmed in a JavaScript/JScript sample.

Static side (this module, on the ORIGINAL code): each detector returns a
technique with concrete evidence — functions, line numbers, counts — so the
analyst sees *how* the script is obfuscated, not just a score:

1. arithmetic_literals   numbers written as arithmetic ``(57+48)``
2. escape_block          a massive ``\\xNN`` / ``\\uNNNN`` literal, its variable and lines
3. xor_decryptor         a custom XOR routine (``^`` + charCodeAt + fromCharCode)
4. iife_string           an IIFE invoked with a long string argument
5. fromcharcode_arith    ``String.fromCharCode`` fed with arithmetic
6. payload_key_decryptor numeric payload array + hard-coded key + decryptor
7. fake_header           a legitimate-looking header/comment over obfuscated code

Sandbox side (``from_sandbox``): what the STPyV8 run *resolved* — anti-sandbox
timing (WScript.Sleep, time-delta reads), strings built by fromCharCode, XOR
routine results and a dropped script/PowerShell payload.
"""

from __future__ import annotations

import re
from typing import Any

_MAX_EVIDENCE = 600


def _line_of(code: str, pos: int) -> int:
    return code.count("\n", 0, pos) + 1


def _lines(nums: list[int], limit: int = 12) -> str:
    u = sorted(set(nums))
    s = ", ".join(map(str, u[:limit]))
    return s + (f" … (+{len(u) - limit})" if len(u) > limit else "")


def _tech(tid: str, name: str, severity: str, evidence: str, phase: str = "static",
          **extra: Any) -> dict[str, Any]:
    return {"id": tid, "name": name, "severity": severity, "phase": phase,
            "evidence": evidence[:_MAX_EVIDENCE], **extra}


# --- static detectors --------------------------------------------------------

_ARITH = re.compile(r"\(\s*\d+\s*[-+*]\s*\d+(?:\s*[-+*]\s*\d+)*\s*\)")


def _arithmetic_literals(code: str) -> dict | None:
    ms = list(_ARITH.finditer(code))
    if len(ms) < 8:
        return None
    lines = [_line_of(code, m.start()) for m in ms]
    sample = ", ".join(m.group(0) for m in ms[:6])
    return _tech("arithmetic_literals", "Numbers hidden as arithmetic", "medium",
                 f"{len(ms)} arithmetic literals, e.g. {sample}; lines {_lines(lines)}",
                 count=len(ms), lines=sorted(set(lines))[:50])


# A string literal, in linear time: each step is either one escape (``\\.``)
# or one plain char — never two ways to match the same text, so an unclosed
# string (a script cut at a size limit) cannot trigger exponential backtracking.
# The \\xNN / \\uNNNN escapes are counted afterwards with _ESC_ONE.
_ESC_LIT = re.compile(r"""(["'])((?:\\.|(?!\1)[^\\\n])*)\1""")
_ESC_ONE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
_VAR_BEFORE = re.compile(r"(?:\b(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*(?:=|:)\s*$")


def _escape_blocks(code: str) -> list[dict]:
    out = []
    for m in _ESC_LIT.finditer(code):
        n = len(_ESC_ONE.findall(m.group(2)))
        if n < 40:
            continue
        before = code[max(0, m.start() - 80):m.start()]
        vm = _VAR_BEFORE.search(before)
        var = vm.group(1) if vm else "(inline)"
        a, b = _line_of(code, m.start()), _line_of(code, m.end())
        out.append(_tech("escape_block", "Massive hex/unicode escape block", "medium",
                         f"variable {var}: {n} escape sequences, lines {a}-{b}: {m.group(0)[:80]}…",
                         variable=var, escapes=n, lines=[a, b]))
    return out[:5]


_FUNC_DECL = re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{")
_VAR_FUNC = re.compile(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\(([^)]*)\)\s*\{")


def _body(code: str, brace: int, limit: int = 4000) -> str:
    depth, i = 0, brace
    end = min(len(code), brace + limit)
    while i < end:
        c = code[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return code[brace:i + 1]
        i += 1
    return code[brace:end]


def xor_functions(code: str) -> list[dict]:
    """Custom XOR decryptors: a function whose body XORs char codes."""
    out = []
    for rx in (_FUNC_DECL, _VAR_FUNC):
        for m in rx.finditer(code):
            body = _body(code, m.end() - 1)
            if re.search(r"[^\^]\^[^\^=]", body) and "charCodeAt" in body and "fromCharCode" in body:
                out.append({"name": m.group(1), "params": [p.strip() for p in m.group(2).split(",") if p.strip()],
                            "line": _line_of(code, m.start()), "declared": rx is _FUNC_DECL,
                            "keyed": bool(re.search(r"%\s*[A-Za-z_$][\w$]*\.length", body))})
    return out


_IIFE_STR = re.compile(r"\}\s*\)?\s*\(\s*(['\"])((?:\\.|(?!\1)[^\\\n]){80,}?)\1\s*\)")


def _iife_string(code: str) -> dict | None:
    m = _IIFE_STR.search(code)
    if not m:
        return None
    return _tech("iife_string", "IIFE invoked with an encoded string", "medium",
                 f"line {_line_of(code, m.start())}: function invoked immediately with a "
                 f"{len(m.group(2))}-char string argument: {m.group(2)[:60]}…",
                 lines=[_line_of(code, m.start())])


_FCC = re.compile(r"String\.fromCharCode\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)")


def _fromcharcode_arith(code: str) -> dict | None:
    hits = [m for m in _FCC.finditer(code) if re.search(r"\d\s*[-+*^%]\s*\d|[\w)\]]\s*[-+^%]\s*\d", m.group(1))]
    if not hits:
        return None
    lines = [_line_of(code, m.start()) for m in hits]
    return _tech("fromcharcode_arith", "String.fromCharCode with arithmetic", "medium",
                 f"{len(hits)} call(s), lines {_lines(lines)}: {hits[0].group(0)[:120]}",
                 count=len(hits), lines=sorted(set(lines))[:50])


_NUM_ARRAY = re.compile(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[\s*(\d+\s*(?:,\s*\d+\s*){19,})\]")
_KEY_STR = re.compile(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"])([^'\"\n]{3,64})\2")


def _payload_trio(code: str, xors: list[dict]) -> dict | None:
    arr = _NUM_ARRAY.search(code)
    if not arr or not xors:
        return None
    calls = " ".join(m.group(1) for x in xors
                     for m in re.finditer(rf"\b{re.escape(x['name'])}\s*\(([^()]*)\)", code))
    keys = [k for k in _KEY_STR.finditer(code)
            if re.search(rf"\b{re.escape(k.group(1))}\b\s*(?:\.length|\.charCodeAt)", code)
            or re.search(rf"\b{re.escape(k.group(1))}\b", calls)]
    if not keys:
        return None
    n = arr.group(2).count(",") + 1
    k = keys[0]
    return _tech("payload_key_decryptor", "Encrypted payload array + hard-coded key + decryptor", "high",
                 f"array {arr.group(1)} ({n} numbers, line {_line_of(code, arr.start())}), "
                 f"key {k.group(1)} = \"{k.group(3)}\" (line {_line_of(code, k.start())}), "
                 f"decryptor {xors[0]['name']}() (line {xors[0]['line']})",
                 array=arr.group(1), key=k.group(3), decryptor=xors[0]["name"])


_HEADER = re.compile(r"^\s*(/\*[\s\S]{0,600}?\*/|(?://[^\n]*\n){1,8})")
_LEGIT = re.compile(r"(?i)jquery|bootstrap|lodash|angular|react|copyright|\(c\)|©|@license|licensed under|"
                    r"microsoft corporation|google llc|all rights reserved|mit license|version \d")


def _fake_header(code: str, score: int, others: int = 0) -> dict | None:
    m = _HEADER.match(code)
    if not m or (score < 4 and others < 2) or not _LEGIT.search(m.group(1)):
        return None
    head = " ".join(m.group(1).split())[:160]
    return _tech("fake_header", "Legitimate-looking header over obfuscated code", "medium",
                 f"header claims \"{head}\" but the code that follows is obfuscated "
                 f"(score {score}, {others} other technique(s))")


def static_techniques(code: str, obfuscation_score: int = 0) -> list[dict[str, Any]]:
    code = code or ""
    out: list[dict[str, Any]] = []
    t = _arithmetic_literals(code)
    if t:
        out.append(t)
    out += _escape_blocks(code)
    xors = xor_functions(code)
    for x in xors[:4]:
        out.append(_tech("xor_decryptor", "Custom XOR decryption routine", "high",
                         f"function {x['name']}({', '.join(x['params'])}) at line {x['line']} XORs char codes"
                         + (" with a repeating key" if x["keyed"] else ""), function=x["name"], lines=[x["line"]]))
    t = _iife_string(code)
    if t:
        out.append(t)
    t = _fromcharcode_arith(code)
    if t:
        out.append(t)
    t = _payload_trio(code, xors)
    if t:
        out.append(t)
    t = _fake_header(code, obfuscation_score, len(out))
    if t:
        out.append(t)
    return out


# --- sandbox-side instrumentation and techniques ---------------------------

def instrument(code: str) -> str:
    """Wrap the XOR routines declared with ``function NAME`` so the sandbox logs
    what they return (declarations are hoisted, so the wrapper is in place
    before the script calls them)."""
    names = [x["name"] for x in xor_functions(code) if x["declared"]][:8]
    if not names:
        return code
    wrap = "".join(
        f"try{{(function(){{var o={n};{n}=function(){{var r=o.apply(this,arguments);"
        f"_dtx_log('xor','{n}',String(r));return r;}};}})();}}catch(e){{}}\n" for n in names)
    return wrap + code


_SCRIPTY = re.compile(r"(?i)powershell|\biex\b|invoke-expression|-enc(?:odedcommand)?\b|frombase64string|"
                      r"wscript\.shell|cmd(?:\.exe)?\s+/[ck]|activexobject|downloadstring|new-object\s+net\.webclient|"
                      r"\$env:|start-process|<script|\beval\s*\(")


def from_sandbox(sb: dict[str, Any]) -> list[dict[str, Any]]:
    logs = (sb or {}).get("log") or []
    out: list[dict[str, Any]] = []
    sleeps = [e for e in logs if e["name"].endswith("WScript.Sleep")]
    timing = [e for e in logs if e["kind"] == "timing"]
    if sleeps or len(timing) >= 2:
        bits = []
        if sleeps:
            bits.append("WScript.Sleep(" + ", ".join((e["args"] or ["?"])[0] for e in sleeps[:5]) + ")")
        if len(timing) >= 2:
            bits.append(f"{len(timing)} clock reads ({', '.join(sorted({e['name'] for e in timing}))}) — time-delta check")
        out.append(_tech("antisandbox_timing", "Anti-sandbox timing", "medium", "; ".join(bits), phase="sandbox"))
    fcc = [e["args"][0] for e in logs if e["kind"] == "fromcharcode" and e.get("args")]
    if fcc:
        out.append(_tech("fromcharcode_resolved", "Strings resolved via fromCharCode", "info",
                         f"{len(fcc)} string(s): " + " | ".join(s[:80] for s in fcc[:5]), phase="sandbox",
                         strings=fcc[:20]))
    xr = [e for e in logs if e["kind"] == "xor"]
    if xr:
        out.append(_tech("xor_resolved", "XOR routine results", "high",
                         " | ".join(f"{e['name']}() → {(e['args'] or [''])[0][:120]}" for e in xr[:4]),
                         phase="sandbox", results=[(e["args"] or [""])[0] for e in xr[:10]]))
    payloads = [(e["kind"], e["name"], (e["args"] or [""])[0]) for e in logs
                if e["kind"] in ("layer", "xor", "fromcharcode") and e.get("args") and _SCRIPTY.search(e["args"][0])]
    if payloads:
        kind, name, text = max(payloads, key=lambda p: len(p[2]))
        out.append(_tech("dropped_payload", "Decrypted script / PowerShell payload", "high",
                         f"from {name} ({kind}): {text[:400]}", phase="sandbox", payload=text))
    return out
