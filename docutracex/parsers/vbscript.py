"""VBScript: collect .vbs / .vbe and HTA/WSF VBScript blocks, decode & deobfuscate.

The JS sandbox is a *JScript* engine and ViperMonkey is *VBA*, so standalone
VBScript (in HTA/WSF or dropped .vbs/.vbe) was never decoded. This module:

- extracts VBScript from ``.vbs``, ``.vbe`` (Microsoft Script Encoder — same
  scheme as the ``.jse`` we already decode, via Didier Stevens' decode-vbe.py),
  and ``<script language="VBScript">`` blocks of HTA / WSF / HTML;
- applies a static deobfuscator: ``Chr``/``ChrW`` with arithmetic or ``Xor``,
  ``&`` concatenation, ``StrReverse``, ``Replace``/``Mid``/``Join(Array())``,
  ``s = s & "…"`` accumulation, **XOR decryptor loops** (char, hex-pair or
  array data; numeric or string key) and unwrapping ``Execute`` /
  ``ExecuteGlobal`` / ``Eval`` of a literal or of a variable holding one;
- when PyPy 2.7 + ViperMonkey are provisioned, *emulates* the script (nothing
  real runs: ViperMonkey is an interpreter written in Python);

and exposes the result in its own tab, dumping the full source to
``extracted/code/vbscript/``.
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path
from typing import Any

from . import javascript, script_rules

_MAX_ITEMS = 60
_MAX_FILES = 300
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_CODE = 300_000
_KEEP_CODE = 60_000
_MAX_PASSES = 25

_SCRIPT_TAG = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_HTML_EXT = {".hta", ".htm", ".html", ".wsf", ".wsc", ".sct", ".mht", ".mhtml"}

# Behaviour patterns live in the shared catalogue (script_rules).


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "vbscript", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


# --- deobfuscation ------------------------------------------------------------

_VSTR = r'"(?:[^"]|"")*"'


def _vstr_value(lit: str) -> str:
    return lit[1:-1].replace('""', '"')


def _as_vstr(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


_NUM_TOK = r"(?:&H[0-9a-fA-F]+&?|&O[0-7]+&?|\d+(?:\.\d+)?)"
_ARITH = (r"(?:\s|" + _NUM_TOK + r"|[-+*/\\()]|\bXor\b|\bMod\b|\bAnd\b|\bOr\b|\bNot\b)+")


def vb_eval(expr: str) -> int | None:
    """Integer value of a VBScript arithmetic expression made only of numeric
    literals (&H.., &O.., decimal) and + - * / \\ Mod Xor And Or Not."""
    if not re.fullmatch(r"(?i)" + _ARITH, expr or ""):
        return None
    py = re.sub(r"(?i)&H([0-9a-f]+)&?", lambda m: str(int(m.group(1), 16)), expr)
    py = re.sub(r"(?i)&O([0-7]+)&?", lambda m: str(int(m.group(1), 8)), py)
    for vb, op in ((r"\bXor\b", "^"), (r"\bMod\b", "%"), (r"\bAnd\b", "&"), (r"\bOr\b", "|"),
                   (r"\bNot\b", "~"), (r"\\", "//")):
        py = re.sub("(?i)" + vb, f" {op} ", py)
    if len(py) > 300 or "**" in py:
        return None
    try:
        val = eval(py, {"__builtins__": {}}, {})  # noqa: S307 - digits and operators only
    except Exception:  # noqa: BLE001
        return None
    return int(round(val)) if isinstance(val, (int, float)) else None


def _sub_outside(rx: re.Pattern, repl: Any, code: str) -> str:
    """``rx.sub`` skipping matches that start inside a string literal: a layer
    still quoted is data until Execute unwraps it."""
    if not rx.search(code):
        return code
    spans = [(m.start(), m.end()) for m in re.finditer(_VSTR, code)]
    starts = [a for a, _ in spans]
    out, last = [], 0
    for m in rx.finditer(code):
        i = bisect.bisect_right(starts, m.start()) - 1
        if i >= 0 and spans[i][0] < m.start() < spans[i][1]:
            continue
        out += [code[last:m.start()], repl(m)]
        last = m.end()
    out.append(code[last:])
    return "".join(out)


def _t_chr(code: str) -> tuple[str, int]:
    """``Chr(72)``, ``ChrW(&H48)``, ``Chr(77 Xor 5)``, ``Chr(150-78)`` and
    ``CLng("&H48")`` → literals."""
    n = 0
    rx = re.compile(r"(?i)\bChr[WB]?\s*\(\s*(" + _ARITH + r")\)")
    conv = re.compile(r'(?i)\bC(?:Lng|Int|Byte|Dbl)\s*\(\s*"\s*(&H[0-9a-fA-F]+|&O[0-7]+|\d+)\s*"\s*\)')

    def repl(m: re.Match) -> str:
        nonlocal n
        val = vb_eval(m.group(1))
        if val is None or not 0 <= val <= 0x10FFFF:
            return m.group(0)
        n += 1
        return _as_vstr(chr(val))

    def cnv(m: re.Match) -> str:
        nonlocal n
        val = vb_eval(m.group(1))
        if val is None:
            return m.group(0)
        n += 1
        return str(val)

    code = _sub_outside(conv, cnv, code)
    return _sub_outside(rx, repl, code), n


def _t_concat(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(rf"({_VSTR})\s*&\s*({_VSTR})")
    while True:
        def repl(m: re.Match) -> str:
            nonlocal n
            n += 1
            return _as_vstr(_vstr_value(m.group(1)) + _vstr_value(m.group(2)))

        new = _sub_outside(rx, repl, code)
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

    return _sub_outside(rx, repl, code), n


def _t_unwrap_exec(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(rf"(?im)\b(?:ExecuteGlobal|Execute|Eval)\b[ \t]*(?:\([ \t]*({_VSTR})[ \t]*\)|({_VSTR}))"
                    r"(?=[ \t]*(?:$|:|'))")

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return "\n" + _vstr_value(m.group(1) or m.group(2)) + "\n"

    return _sub_outside(rx, repl, code), n


def _t_string_funcs(code: str) -> tuple[str, int]:
    """String built-ins applied to literals: Replace, Mid, Left, Right, LCase,
    UCase, Trim, Join(Array(...)), Space."""
    n = 0
    V = _VSTR
    N = r"(\d{1,6})"

    def done(v: str) -> str:
        nonlocal n
        n += 1
        return _as_vstr(v)

    rules: list[tuple[str, Any]] = [
        (rf"(?i)\bReplace\s*\(\s*({V})\s*,\s*({V})\s*,\s*({V})\s*(?:,\s*\d+\s*,\s*-?\d+\s*(?:,\s*(\d)\s*)?)?\)",
         lambda m: m.group(0) if not _vstr_value(m.group(2)) else done(
             re.sub(re.escape(_vstr_value(m.group(2))), lambda _x: _vstr_value(m.group(3)), _vstr_value(m.group(1)),
                    flags=re.I if m.group(4) == "1" else 0))),
        (rf"(?i)\bMid\s*\(\s*({V})\s*,\s*{N}\s*(?:,\s*{N}\s*)?\)",
         lambda m: done(_vstr_value(m.group(1))[int(m.group(2)) - 1:
                                                 (int(m.group(2)) - 1 + int(m.group(3))) if m.group(3) else None])),
        (rf"(?i)\bLeft\s*\(\s*({V})\s*,\s*{N}\s*\)", lambda m: done(_vstr_value(m.group(1))[:int(m.group(2))])),
        (rf"(?i)\bRight\s*\(\s*({V})\s*,\s*{N}\s*\)",
         lambda m: done(_vstr_value(m.group(1))[-int(m.group(2)):] if int(m.group(2)) else "")),
        (rf"(?i)\bLCase\s*\(\s*({V})\s*\)", lambda m: done(_vstr_value(m.group(1)).lower())),
        (rf"(?i)\bUCase\s*\(\s*({V})\s*\)", lambda m: done(_vstr_value(m.group(1)).upper())),
        (rf"(?i)\bTrim\s*\(\s*({V})\s*\)", lambda m: done(_vstr_value(m.group(1)).strip(" "))),
        (rf"(?i)\bSpace\s*\(\s*{N}\s*\)", lambda m: done(" " * min(int(m.group(1)), 1000))),
        (rf"(?i)\bJoin\s*\(\s*Array\s*\(\s*((?:{V}\s*,\s*)*{V})\s*\)\s*(?:,\s*({V})\s*)?\)",
         lambda m: done((_vstr_value(m.group(2)) if m.group(2) else " ").join(
             _vstr_value(x) for x in re.findall(V, m.group(1))))),
    ]
    for rx, fn in rules:
        code = _sub_outside(re.compile(rx), fn, code)
    return code, n


def _t_accumulate(code: str) -> tuple[str, int]:
    """``s = "ab"`` followed by ``s = s & "cd"`` lines → ``s = "abcd"``."""
    rx = re.compile(rf"(?im)^([ \t]*)(\w+)[ \t]*=[ \t]*({_VSTR})[ \t]*\r?\n[ \t]*\2[ \t]*=[ \t]*\2[ \t]*&[ \t]*({_VSTR})[ \t]*$")
    n = 0
    while True:
        new, k = rx.subn(lambda m: f"{m.group(1)}{m.group(2)} = "
                         + _as_vstr(_vstr_value(m.group(3)) + _vstr_value(m.group(4))), code)
        if not k:
            return code, n
        n += k
        code = new


def _assignments(code: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for m in re.finditer(r"(?im)^[ \t]*(?:Dim[ \t]+\w+[ \t]*:[ \t]*)?(\w+)[ \t]*=[ \t]*("
                         + _VSTR + r"(?=[ \t]*$)|.+?)[ \t]*$", code):
        out.setdefault(m.group(1).lower(), []).append(m.group(2))
    return out


def _single_value(assigns: dict[str, list[str]], var: str) -> str | None:
    """The one literal a variable is set to (ignoring ``= ""`` resets)."""
    vals = [v for v in assigns.get(var.lower(), []) if v != '""']
    if len(vals) == 1 and re.fullmatch(_VSTR, vals[0]):
        return _vstr_value(vals[0])
    return None


def _t_exec_var(code: str) -> tuple[str, int]:
    """``Execute s`` / ``ExecuteGlobal(s)`` / ``Eval(s)`` where ``s`` holds one
    literal → the code itself, inline."""
    rx = re.compile(r"(?im)\b(?:ExecuteGlobal|Execute|Eval)\b[ \t]*\(?[ \t]*([A-Za-z_]\w*)[ \t]*\)?[ \t]*$")
    if not rx.search(code):
        return code, 0
    assigns = _assignments(code)
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        val = _single_value(assigns, m.group(1))
        if val is None or not val.strip():
            return m.group(0)
        n += 1
        return "\n" + val + "\n"

    return _sub_outside(rx, repl, code), n


_FOR = re.compile(r"(?ims)^[ \t]*For[ \t]+(?:Each[ \t]+(\w+)[ \t]+In[ \t]+(\w+)|(\w+)[ \t]*=[ \t]*([01])[ \t]+To[ \t]+"
                  r"(?:Len|UBound|LenB)\(\s*(\w+)\s*\)(?:[ \t]*-[ \t]*1)?(?:[ \t]+Step[ \t]+(\d))?)[ \t]*(?::|\r?\n)"
                  r"(.{0,600}?)(?:^|:)[ \t]*Next\b[^\n]*")


def _printable(text: str) -> float:
    return sum(c.isprintable() or c in "\r\n\t" for c in text) / max(len(text), 1)


def _t_xor_loop(code: str) -> tuple[str, int]:
    """Classic decryptor loops, evaluated statically::

        For i = 1 To Len(enc)            ' or Step 2 over hex pairs,
          s = s & Chr(Asc(Mid(enc, i, 1)) Xor 23)   ' or a string key,
        Next                             ' or For Each b In Array(...)

    The loop is replaced by ``s = "<plaintext>"`` (a later pass inlines
    ``Execute s``). Only kept when the result is printable text."""
    if not re.search(r"(?i)\bXor\b", code) or not _FOR.search(code):
        return code, 0
    assigns = _assignments(code)
    n = 0

    def data_of(var: str) -> list[int] | str | None:
        val = _single_value(assigns, var)
        if val is not None:
            return val
        arr = [v for v in assigns.get(var.lower(), []) if re.match(r"(?i)Array\s*\(", v)]
        if len(arr) == 1:
            nums = [vb_eval(x) for x in re.findall(r"&H[0-9a-fA-F]+|\d+", arr[0])]
            if nums and None not in nums:
                return nums  # type: ignore[return-value]
        return None

    def key_of(body: str, data_var: str) -> list[int] | None:
        xm = re.search(r"(?i)Xor\s*\(?\s*(Asc[BW]?\s*\(\s*Mid\s*\(\s*(\w+)|&H[0-9a-fA-F]+|\d+|\w+)", body)
        if not xm:
            return None
        tok, kvar = xm.group(1), xm.group(2)
        if kvar and kvar.lower() != data_var.lower():
            kv = _single_value(assigns, kvar)
            return [ord(c) for c in kv] if kv else None
        num = vb_eval(tok)
        if num is not None:
            return [num]
        vals = assigns.get(tok.lower(), [])
        if len(vals) == 1:
            num = vb_eval(vals[0])
            if num is not None:
                return [num]
            kv = _single_value(assigns, tok)
            if kv:
                return [ord(c) for c in kv]
        return None

    def repl(m: re.Match) -> str:
        nonlocal n
        each_var, each_src, idx, start, len_var, step, body = m.groups()
        data_var = each_src or len_var
        if not re.search(r"(?i)\bChr[WB]?\b", body) or not re.search(r"(?i)\bXor\b", body):
            return m.group(0)
        om = re.search(r"(?i)(\w+)\s*=\s*\1\s*&\s*Chr", body)
        data = data_of(data_var)
        if not om or data is None:
            return m.group(0)
        key = key_of(body.replace(f"Mid({data_var}", "Mid(§"), data_var)
        if not key:
            return m.group(0)
        if isinstance(data, str):
            if step == "2" or re.search(r'(?i)"&H"\s*&\s*Mid', body):
                try:
                    vals = [int(data[i:i + 2], 16) for i in range(0, len(data) - 1, 2)]
                except ValueError:
                    return m.group(0)
            else:
                vals = [ord(c) for c in data]
        else:
            vals = list(data)
        best = None
        for off in range(len(key)):
            try:
                out = "".join(chr((v ^ key[(i + off) % len(key)]) & 0x10FFFF) for i, v in enumerate(vals))
            except ValueError:
                continue
            score = _printable(out)
            if best is None or score > best[0]:
                best = (score, out)
        if best is None or best[0] < 0.95 or not best[1].strip():
            return m.group(0)
        n += 1
        return f"{om.group(1)} = {_as_vstr(best[1])}"

    return _sub_outside(_FOR, repl, code), n


_TRANSFORMS = [("chr-code", _t_chr), ("concat-&", _t_concat),
               ("StrReverse", _t_strreverse), ("string-functions", _t_string_funcs),
               ("accumulated-strings", _t_accumulate), ("xor-loop", _t_xor_loop),
               ("unwrap-Execute/Eval", _t_unwrap_exec), ("execute-variable", _t_exec_var)]


def deobfuscate(code: str) -> dict[str, Any]:
    original = (code or "").replace("\r\n", "\n")
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
    """Behaviour hits from the shared catalogue (VBScript rules)."""
    return script_rules.scan(code, script_rules.VBS)


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
        from ..codefiles import input_files
        paths = input_files(extracted_dir, _MAX_FILES)
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
                raw = p.read_bytes()[:_MAX_FILE_BYTES]
            except OSError:
                continue
            text = (javascript.decode_mht(raw) if ext in (".mht", ".mhtml")
                    else raw.decode("utf-8", "replace"))
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


_MAX_EMULATED = 3


def _emulate(res: dict[str, Any], extracted_dir: Path) -> None:
    """Emulate standalone VBScript with ViperMonkey (when PyPy 2.7 is provisioned):
    it runs the language for real — loops, functions, Split/Execute chains —
    where the static deobfuscator only folds patterns. Its actions, IOCs and
    dropped files become findings of this tab (tool ``vipermonkey``)."""
    from ..config import settings
    from . import vipermonkey
    if not res["scripts"] or settings.pypy_python() is None:
        return
    import tempfile
    emul = []
    for sc in res["scripts"][:_MAX_EMULATED]:
        with tempfile.TemporaryDirectory(prefix="dtx_vbs_") as tmp:
            src = Path(tmp) / f"script{sc['id']}.vbs"
            src.write_text(sc.get("_full_code") or sc["code"], encoding="utf-8", errors="replace")
            try:
                vm = vipermonkey.analyze(src, extracted_dir)
            except Exception as exc:  # noqa: BLE001
                emul.append({"script": sc["id"], "error": str(exc)[:300]})
                continue
        if not vm.get("available"):
            return
        emul.append({"script": sc["id"], "origin": sc["origin"], "status": vm.get("status"),
                     "actions": vm.get("actions", [])[:200], "potential_iocs": vm.get("potential_iocs", []),
                     "artifacts": vm.get("artifacts", [])})
        sc["emulation"] = {"actions": len(vm.get("actions") or []), "artifacts": vm.get("artifacts") or []}
        for f in vm.get("findings") or []:
            res["findings"].append({**f, "detail": f"[{sc['origin']}] " + f["detail"].replace("macro", "VBScript"),
                                    "location": sc["location"]})
    if emul:
        res["emulation"] = emul


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
        chain = script_rules.risk_escalation(hits)
        if chain:
            res["findings"].append(_finding(chain["rule"], chain["severity"],
                                            f"[{it['origin']}] {chain['label']}", loc, chain["detail"]))
        if deob["changed"]:
            methods = ", ".join(deob["methods"]) or "static decoding"
            res["findings"].append(_finding("vbs_deobfuscated", "medium",
                                            f"[{it['origin']}] VBScript deobfuscated before analysis ({methods})",
                                            loc, (code[:600] or "").strip()))
    _emulate(res, extracted_dir)
    res["counts"] = {"findings": len(res["findings"]), "scripts": len(res["scripts"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
