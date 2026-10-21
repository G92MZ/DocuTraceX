"""Batch / cmd deobfuscator (static, pure-Python).

Windows batch malware hides its real command behind a handful of native tricks:

- caret escaping / line continuation (``p^o^w^e^r^shell``, ``^`` at end of line);
- ``set`` indirection (``set a=power`` … ``%a%shell``);
- variable substring and replace expansion (``%cmd:~6,11%``, ``%x:AA=%``);
- delayed expansion (``!var!`` under ``setlocal EnableDelayedExpansion``);
- doubled/quoted variable noise.

This resolves those statically so the recovered command can be analysed and the
PowerShell it usually launches can be mined. Nothing is executed.
"""

from __future__ import annotations

import re
from typing import Any

_MAX_PASSES = 40
_SET = re.compile(r'(?im)^[\s@]*set\s+(?:/a\s+)?"?([A-Za-z_][\w#@$]*)=([^"\r\n]*)"?\s*$')
_VAR_PCT = re.compile(r"%([A-Za-z_][\w#@$]*)((?::~[\-\d, ]+|:[^%=]*=[^%]*)?)%")
_VAR_BANG = re.compile(r"!([A-Za-z_][\w#@$]*)((?::~[\-\d, ]+|:[^!=]*=[^!]*)?)!")


def _strip_carets(code: str) -> tuple[str, int]:
    n = 0
    # Line continuation: a caret at end of line joins the next line.
    joined, c = re.subn(r"\^\r?\n", "", code)
    n += c
    # ^^ -> ^ (escaped caret), guarded so the next step doesn't eat it.
    joined = joined.replace("^^", "\x00CARET\x00")
    # ^X -> X for any other escaped character.
    joined, c = re.subn(r"\^(.)", r"\1", joined)
    n += c
    joined = joined.replace("\x00CARET\x00", "^")
    return joined, n


def _expand_token(name: str, modifier: str, env: dict[str, str]) -> str | None:
    """Resolve %VAR%, %VAR:~s,l% or %VAR:find=repl% from ``env`` (case-insensitive)."""
    val = env.get(name.lower())
    if val is None:
        return None
    if not modifier:
        return val
    if modifier.startswith(":~"):  # substring
        nums = [p.strip() for p in modifier[2:].split(",")]
        try:
            start = int(nums[0])
            if start < 0:
                start = max(0, len(val) + start)
            if len(nums) > 1 and nums[1] != "":
                length = int(nums[1])
                return val[start:start + length] if length >= 0 else val[start:len(val) + length]
            return val[start:]
        except (ValueError, IndexError):
            return None
    if modifier.startswith(":") and "=" in modifier:  # search & replace
        find, _, repl = modifier[1:].partition("=")
        if find:
            return val.replace(find, repl)
    return val


def _collect_env(code: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for m in _SET.finditer(code):
        env[m.group(1).lower()] = m.group(2)
    return env


def _substitute(code: str, env: dict[str, str]) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        out = _expand_token(m.group(1), m.group(2), env)
        if out is None:
            return m.group(0)
        n += 1
        return out

    code = _VAR_PCT.sub(repl, code)
    code = _VAR_BANG.sub(repl, code)
    return code, n


def deobfuscate(code: str) -> dict[str, Any]:
    original = code or ""
    cur = original
    methods: list[str] = []
    for _ in range(_MAX_PASSES):
        before = cur
        new, c = _strip_carets(cur)
        if c and new != cur:
            cur = new
            if "caret-escape" not in methods:
                methods.append("caret-escape")
        env = _collect_env(cur)
        if env:
            new, c = _substitute(cur, env)
            if c and new != cur:
                cur = new
                if "set-var expansion" not in methods:
                    methods.append("set-var expansion")
        if cur == before:
            break
    return {"changed": cur.strip() != original.strip(), "code": cur, "methods": methods}
