"""Batch / cmd deobfuscator (static, pure-Python).

Windows batch malware hides its real command behind a handful of native tricks:

- caret escaping / line continuation (``p^o^w^e^r^shell``, ``^`` at end of line);
- ``set`` indirection (``set a=power`` … ``%a%shell``);
- variable substring and replace expansion (``%cmd:~6,11%``, ``%x:AA=%``);
- delayed expansion (``!var!`` under ``setlocal EnableDelayedExpansion``);
- doubled/quoted variable noise;
- DOSfuscation (Daniel Bohannon): characters sliced out of built-in variables
  (``%COMSPEC:~-16,1%``, ``%PUBLIC:~5,1%``…), inline ``set`` chains inside
  ``cmd /V /C "…&&…"``, ``call set`` with doubled percents, ``%v:*x=%``,
  ``""`` inside words, and FOR-loop encodings — a string rebuilt by index
  (``for %%i in (3,0,7…) do set r=!r!!s:~%%i,1!``) or reversed
  (``for /L %%i in (N,-1,0) …``).

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
_SET_INLINE = re.compile(r'(?i)(?:&&?|\(|/[cr]\s*"?)\s*set\s+(?!/[ap]\b)"?([A-Za-z_][\w#@$]*)=([^"&|\r\n)]*)"?')

# Built-in variables on a stock Windows 10/11 x64 host. DOSfuscation slices
# characters out of these; they are only used with a :~ or := modifier, so a
# plain %TEMP% in a command stays as written.
_BUILTIN = {
    "comspec": r"C:\WINDOWS\system32\cmd.exe",
    "windir": r"C:\WINDOWS", "systemroot": r"C:\WINDOWS",
    "public": r"C:\Users\Public",
    "programdata": r"C:\ProgramData", "allusersprofile": r"C:\ProgramData",
    "programfiles": r"C:\Program Files", "programfiles(x86)": r"C:\Program Files (x86)",
    "commonprogramfiles": r"C:\Program Files\Common Files",
    "commonprogramfiles(x86)": r"C:\Program Files (x86)\Common Files",
    "programw6432": r"C:\Program Files",
    "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    "os": "Windows_NT", "processor_architecture": "AMD64", "systemdrive": "C:",
    "psmodulepath": r"C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules",
}
_VAR_BUILTIN = re.compile(r"(?i)%(" + "|".join(re.escape(k) for k in sorted(_BUILTIN, key=len, reverse=True))
                          + r")(:~[\-\d, ]+|:[^%=]*=[^%]*)%")


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
        if find.startswith("*") and len(find) > 1:      # %v:*abc=X%: up to the first abc
            i = val.lower().find(find[1:].lower())
            return repl + val[i + len(find) - 1:] if i >= 0 else val
        if find:
            return re.sub(re.escape(find), lambda _m: repl, val, flags=re.IGNORECASE)
    return val


def _collect_env(code: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for m in _SET.finditer(code):
        env[m.group(1).lower()] = m.group(2)
    for m in _SET_INLINE.finditer(code):
        env.setdefault(m.group(1).lower(), m.group(2))
    return env


def _builtin(code: str) -> tuple[str, int]:
    """``%COMSPEC:~-16,1%`` etc. from stock built-in values (unless the script
    sets the variable itself)."""
    own = _collect_env(code)
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        name = m.group(1).lower()
        if name in own:
            return m.group(0)
        out = _expand_token(name, m.group(2), _BUILTIN)
        if out is None:
            return m.group(0)
        n += 1
        return out

    return _VAR_BUILTIN.sub(repl, code), n


_CALL_SET = re.compile(r"(?im)^([\s@]*)call\s+(set\s+[^\r\n]*)$")


def _call_set(code: str) -> tuple[str, int]:
    """``call set x=%%y:~2,5%%`` → ``set x=%y:~2,5%`` (the second expansion)."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        if "%%" not in m.group(2):
            return m.group(0)
        n += 1
        return m.group(1) + m.group(2).replace("%%", "%")

    return _CALL_SET.sub(repl, code), n


_FOR_ENC = re.compile(
    r'(?i)for\s+(/L\s+)?%%?(\w)\s+in\s*\(([-\d,;\s]+)\)\s*do\s*(?:@?\s*call\s+)?set\s+"?(\w+)='
    r'(?:(?P<pre>[!%]\4[!%])[!%](\w+):~%%?\2,1[!%]|[!%](\w+):~%%?\2,1[!%](?P<post>[!%]\4[!%]))"?')


def _for_decode(code: str) -> tuple[str, int]:
    """FOR-loop encodings: a string rebuilt from a char set by an index list, or
    reversed with ``for /L``. The loop becomes ``set r=<result>``."""
    env = _collect_env(code)
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        is_l, _var, nums, out_var = m.group(1), m.group(2), m.group(3), m.group(4)
        src_var = m.group(6) or m.group(8)
        src = env.get(src_var.lower())
        if src is None:
            return m.group(0)
        try:
            vals = [int(x) for x in re.split(r"[,;\s]+", nums.strip()) if x]
        except ValueError:
            return m.group(0)
        if is_l:
            if len(vals) != 3 or vals[1] == 0:
                return m.group(0)
            start, step, end = vals
            idx = list(range(start, end + (1 if step > 0 else -1), step))[:20000]
        else:
            idx = vals
        try:
            chars = [src[i] for i in idx]
        except IndexError:
            return m.group(0)
        built = "".join(chars) if m.group("pre") else "".join(reversed(chars))
        n += 1
        return f'set "{out_var}={built}"'

    return _FOR_ENC.sub(repl, code), n


def _quote_noise(code: str) -> tuple[str, int]:
    """``po""wer""shell`` → ``powershell`` (cmd drops empty quote pairs in words)."""
    return re.subn(r'(?<=[A-Za-z0-9.\\])""(?=[A-Za-z0-9.\\])', "", code)


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
        for name, fn in (("call-set", _call_set), ("for-loop decode", _for_decode),
                         ("builtin-var slicing", _builtin), ("quote noise", _quote_noise)):
            new, c = fn(cur)
            if c and new != cur:
                cur = new
                if name not in methods:
                    methods.append(name)
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
