"""Static VBA string resolver — a deobfuscate-first fallback for VBA.

ViperMonkey *emulates* VBA and resolves obfuscation into concrete actions, but
it only runs on the PyPy 2.7 portable and can fail or be absent. This module is
a pure-Python static fallback: it resolves the string tricks maldoc VBA leans
on so that the detector (and the IOC scan) see the real strings even when no
emulator ran:

- ``Chr(65)`` / ``ChrW(65)`` / ``Chr(&H41)`` char codes;
- ``"a" & "b"`` and ``"a" + "b"`` concatenation;
- ``StrReverse("...")``;
- ``Replace("...", "x", "y")`` with literal arguments.

``deobfuscate(code)`` returns ``{changed, code, methods}``. Nothing is executed.
"""

from __future__ import annotations

import re
from typing import Any

_MAX_PASSES = 25
_MAX_BYTES = 2_000_000

# VBA string literal: "..."" ..." (doubled quote escapes the quote).
_VSTR = r'"(?:[^"]|"")*"'


def _val(lit: str) -> str:
    return lit[1:-1].replace('""', '"')


def _lit(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _t_chr(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(r"(?i)\bChr[W$]?\s*\(\s*(&H[0-9a-fA-F]+|\d{1,7})\s*\)")

    def repl(m: re.Match) -> str:
        nonlocal n
        tok = m.group(1)
        try:
            v = int(tok[2:], 16) if tok[:2].lower() == "&h" else int(tok)
            ch = chr(v & 0x10FFFF)
        except ValueError:
            return m.group(0)
        n += 1
        return _lit(ch)

    return rx.sub(repl, code), n


def _t_concat(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(rf"({_VSTR})\s*[&+]\s*({_VSTR})")
    while True:
        def repl(m: re.Match) -> str:
            nonlocal n
            n += 1
            return _lit(_val(m.group(1)) + _val(m.group(2)))

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
        return _lit(_val(m.group(1))[::-1])

    return rx.sub(repl, code), n


def _t_replace(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(rf"(?i)\bReplace\s*\(\s*({_VSTR})\s*,\s*({_VSTR})\s*,\s*({_VSTR})\s*\)")

    def repl(m: re.Match) -> str:
        nonlocal n
        src, find, rep = _val(m.group(1)), _val(m.group(2)), _val(m.group(3))
        if not find:
            return m.group(0)
        n += 1
        return _lit(src.replace(find, rep))

    return rx.sub(repl, code), n


_TRANSFORMS = [("chr-code", _t_chr), ("concat", _t_concat),
               ("StrReverse", _t_strreverse), ("Replace", _t_replace)]

# rule, severity, regex, label — hits surfaced from the RESOLVED source.
PATTERNS: list[tuple[str, str, str, str]] = [
    ("vba_deobf_lolbin", "high",
     r"(?i)powershell|cmd(?:\.exe)?\s*/c|mshta|regsvr32|rundll32|certutil|bitsadmin|wmic|schtasks|msiexec",
     "resolved string invokes a LOLBin / shell"),
    ("vba_deobf_url", "high", r"(?i)https?://[^\s\"']{4,}|ftp://[^\s\"']{4,}",
     "resolved string contains a URL"),
    ("vba_deobf_download", "high",
     r"(?i)MSXML2\.|WinHttp|XMLHTTP|ADODB\.Stream|URLDownloadToFile|DownloadString|Net\.WebClient",
     "resolved string downloads / writes"),
    ("vba_deobf_shell", "high", r"(?i)WScript\.Shell|Shell\.Application|\.ShellExecute|CreateObject\s*\(",
     "resolved string runs a command / COM object"),
]


def static_hits(code: str) -> list[dict[str, Any]]:
    hits = []
    lines = code.splitlines() or [""]
    for rule, sev, rx, label in PATTERNS:
        r = re.compile(rx)
        for ln in lines:
            if r.search(ln):
                hits.append({"rule": rule, "severity": sev, "label": label, "line": ln.strip()[:300]})
                break
    return hits


def deobfuscate(code: str) -> dict[str, Any]:
    original = code or ""
    cur = original
    methods: list[str] = []
    cap = max(_MAX_BYTES, len(original) + 1)
    for _ in range(_MAX_PASSES):
        if len(cur) > cap:
            break
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
