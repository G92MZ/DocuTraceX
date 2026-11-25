"""A command line a script launches, followed to what it runs next.

Every evaluator hands the commands its script starts (``WScript.Shell.Run``, ``subprocess``,
``os.system``, ``Start-Process``, a batch line…) to :func:`launch`, which recognises the launchers
loaders chain and reports what they lead to:

- ``powershell -EncodedCommand <base64>`` / ``-Command "…"`` → a PowerShell stage (``.ps1``);
- ``mshta "javascript:…"`` / ``"vbscript:…"`` → a JScript / VBScript stage; ``mshta <url>`` → a
  download run as an HTA;
- ``certutil -urlcache -f <url> <file>``, ``bitsadmin /transfer … <url> <file>``, ``curl -o`` /
  ``wget -O``, ``Invoke-WebRequest`` → a download saved to that file;
- ``certutil -decode <in> <out>`` → a step (the file it decodes is resolved by the batch engine);
- ``cmd /c "a & b"`` → each command in turn.

Nothing is run: the stages go to :class:`.sinks.Sinks` like any other.
"""

from __future__ import annotations

import re
import shlex

from . import transforms as T
from .sinks import Sinks
from .value import Value

_PS = re.compile(r"(?i)(?:^|[\s\"'\\/&|(])(?:powershell|pwsh)(?:\.exe)?(?=[\s\"']|$)")
_ENC = re.compile(r"(?i)\s[-/]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc\w*)?\s+[\"']?([A-Za-z0-9+/=]{12,})")
_CMDARG = re.compile(r"(?is)\s[-/]c(?:o|om|omm|omma|omman|ommand)?\s+(.+)$")
_MSHTA = re.compile(r"(?i)\bmshta(?:\.exe)?\s+[\"']?((?:javascript|vbscript|about):.+|https?://\S+)")
_CERTUTIL_DL = re.compile(r"(?i)\bcertutil(?:\.exe)?\b.*?-urlcache\b.*?(https?://[^\s\"']+)(?:[\s\"']+([^\s\"']+))?")
_BITS = re.compile(r"(?i)\bbitsadmin(?:\.exe)?\b.*?/transfer\b.*?(https?://[^\s\"']+)\s+[\"']?([^\s\"']+)")
_CURL = re.compile(r"(?i)\b(?:curl|wget)(?:\.exe)?\b(.*)")
_URL = re.compile(r"https?://[^\s\"'<>|&^]+", re.I)
_CMDC = re.compile(r"(?is)^\s*[\"']?(?:%comspec%|(?:[a-z]:\\[^\"']*\\)?cmd(?:\.exe)?)[\"']?\s+/[ck]\s+(.+)$")


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def launch(sinks: Sinks, cmd: str, recipe: tuple[str, ...] = (), line: int | None = None,
           via: str = "command", depth: int = 0) -> bool:
    """Follow ``cmd``; True when it led to a stage or a download."""
    cmd = (cmd or "").strip()
    if not cmd or depth > 4:
        return False
    sinks.step(line, f"{via} launches", Value("str", cmd[:300], recipe))
    m = _CMDC.match(cmd)
    if m:
        inner = _unquote(m.group(1))
        hit = False
        for part in re.split(r"\s*(?:&&|\|\||&)\s*", inner):
            hit = launch(sinks, part, recipe, line, "cmd /c", depth + 1) or hit
        return hit
    if _PS.search(cmd):
        e = _ENC.search(cmd)
        if e:
            try:
                code = T.as_text(T.b64decode(e.group(1)), "utf-16-le")
            except T.TransformError:
                code = ""
            if code.strip():
                _stage(sinks, code, recipe + ("base64 (-EncodedCommand)", "utf-16"), "powershell -EncodedCommand", line, ".ps1")
                return True
        c = _CMDARG.search(cmd)
        if c:
            code = _unquote(c.group(1))
            if len(code) >= 12:
                _stage(sinks, code, recipe, "powershell -Command", line, ".ps1")
                return True
    m = _MSHTA.search(cmd)
    if m:
        arg = _unquote(m.group(1)).rstrip("\"'")
        low = arg.lower()
        if low.startswith(("javascript:", "vbscript:")):
            lang, _, code = arg.partition(":")
            _stage(sinks, code, recipe, f"mshta {lang.lower()}:", line, ".js" if lang.lower() == "javascript" else ".vbs")
            return True
        if low.startswith("http"):
            sinks.download(Value("str", arg, recipe), "mshta", "runs it as an HTA (mshta)", line)
            return True
    m = _CERTUTIL_DL.search(cmd)
    if m:
        sinks.download(Value("str", m.group(1), recipe), "certutil -urlcache", "saves it", line, m.group(2) or "")
        return True
    m = _BITS.search(cmd)
    if m:
        sinks.download(Value("str", m.group(1), recipe), "bitsadmin /transfer", "saves it", line, m.group(2))
        return True
    m = _CURL.search(cmd)
    if m and _URL.search(m.group(1)):
        args = m.group(1)
        try:
            toks = shlex.split(args, posix=False)
        except ValueError:
            toks = args.split()
        dest = ""
        for i, t in enumerate(toks):
            if t in ("-o", "-O", "--output", "--output-document") and i + 1 < len(toks):
                dest = _unquote(toks[i + 1])
        url = _URL.search(args).group(0)
        sinks.download(Value("str", url, recipe), cmd.split()[0].rsplit("\\", 1)[-1], "saves it" if dest else "returns it",
                       line, dest)
        return True
    return False


def _stage(sinks: Sinks, code: str, recipe: tuple[str, ...], sink: str, line: int | None, ext: str) -> None:
    n = len(sinks.stages)
    sinks.exec_(Value("str", code, recipe), sink, line)
    if len(sinks.stages) > n:
        sinks.stages[-1].ext = ext
