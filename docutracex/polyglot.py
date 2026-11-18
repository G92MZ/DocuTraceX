"""HTML polyglots: a page that is also a program in another language.

A lure ships one file that a browser shows as an HTML page (an "install notes"
page, an invoice) and an interpreter runs as code: the HTML is hidden where that
language ignores it — inside a string or a comment — and the code sits around it.

    '''<html> … </html>'''            Python   (pythonw.exe notes.html)
    <# <html> … </html> #>            PowerShell
    <!-- : batch … -->  <html>…       batch + HTA / WSF hybrid
    /* <html> … </html> */            JavaScript / JScript (node, wscript //E:jscript)
    --[[ <html> … ]]                  Lua
    =begin <html> =end                Ruby
    =pod … =cut  /  __END__ <html>    Perl
    #cs <html> #ce                    AutoIt
    /* … */  (AutoHotkey syntax)      AutoHotkey
    if 0 { <html> }                   Tcl
    : <<'X' <html> X                  shell
    <?php … ?> inside a page          PHP (only when the PHP itself is suspicious)

``detect`` finds the construct, checks the code outside the HTML really is that
language (and is not itself HTML — an ordinary page with a script is not a
polyglot) and returns that code, with the HTML replaced by a short placeholder,
so it can be analysed by its language like any other child (layers peeled, byte
arrays carved…). Pure text processing: nothing is run.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

MAX_SIZE = 96 * 1024 * 1024          # a polyglot can carry a whole PE as an escaped/encoded string
_NEAR_START = 512                    # the hiding construct opens the file (a browser shows the page)
MARKUP_EXT = {".html", ".htm", ".hta", ".xhtml", ".shtml", ".svg", ".mht", ".mhtml", ".xht"}

_TAG = re.compile(r"<(!doctype\s+html|html|head|body|div|p|table|span|style|title|meta|a|img|h[1-6]|br|"
                  r"form|iframe|ul|li|section|header|footer|button|input|link|center|font|b|strong)\b", re.I)


def _html_tags(s: str) -> int:
    return len({m.group(1).lower() for m in _TAG.finditer(s[:400_000])})


def _is_html(s: str) -> bool:
    return _html_tags(s) >= 2


# Code that is more than a page: decoding, executing, native calls, launching.
_SUSPICIOUS = re.compile(
    r"\b(exec|eval|compile|marshal|b64decode|b32decode|a85decode|base64|zlib|lzma|bz2|gzip|decompress|"
    r"ctypes|CFUNCTYPE|VirtualAlloc|VirtualProtect|CreateThread|RtlMoveMemory|WriteProcessMemory|"
    r"FromBase64String|IEX|Invoke-Expression|Invoke-WebRequest|DownloadString|DownloadFile|WebClient|"
    r"Add-Type|Start-Process|DllCall|DllStructCreate|Execute|ShellExecute|ActiveXObject|WScript|"
    r"Shell\.Application|GetObject|mshta|rundll32|regsvr32|certutil|bitsadmin|powershell|cscript|wscript|"
    r"loadstring|os\.execute|io\.popen|system|popen|subprocess|socket|urllib|requests|curl|wget|"
    r"gzinflate|str_rot13|shell_exec|passthru|assert|create_function|unpack|chmod|nohup|"
    r"child_process|require\(['\"](?:child_process|ffi|ffi-napi)['\"]\)|fromCharCode|atob)\b"
    r"|\[::-1\]|%~f0|%~dpnx0", re.I)


def suspicious_tokens(code: str) -> list[str]:
    seen: dict[str, None] = {}
    for m in _SUSPICIOUS.finditer(code[:2_000_000]):
        seen.setdefault(m.group(0).lower(), None)
        if len(seen) >= 12:
            break
    return list(seen)


def _text(data: bytes) -> str | None:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace").lstrip("﻿")


def _placeholder(n: int) -> str:
    return f"<HTML page: {n} characters hidden here>"


def _cut(text: str, spans: list[tuple[int, int, str, str]]) -> str:
    """Text with each (start, end, open, close) span's inside replaced by a placeholder."""
    out, pos = [], 0
    for a, b, op, cl in sorted(spans):
        out.append(text[pos:a])
        out.append(op + _placeholder(b - a - len(op) - len(cl)) + cl)
        pos = b
    out.append(text[pos:])
    return "".join(out)


def _first(text: str) -> int:
    """Offset of the first non-blank character."""
    return len(text) - len(text.lstrip())


# ── per-language detectors: (outside code, how the HTML is hidden) or None ──

_PY_STR = re.compile(r"(?<![\w'\"])([rRbBuU]{0,2})('''|\"\"\")")


def _python(text: str, markup: bool) -> tuple[str, str] | None:
    spans, pos = [], 0
    while len(spans) < 64:
        m = _PY_STR.search(text, pos)
        if not m:
            break
        q = m.group(2)
        end = text.find(q, m.end())
        if end < 0:
            break
        body = text[m.end():end]
        if _is_html(body) and (markup or m.start() - _first(text) <= _NEAR_START):
            spans.append((m.start(), end + 3, m.group(1) + q, q))
        pos = end + 3
    if not spans:
        return None
    outside = _cut(text, spans)
    try:
        tree = ast.parse(outside)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    real = [n for n in tree.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
    if not real:
        return None
    return outside, "inside a triple-quoted string"


def _block(text: str, markup: bool, opener: str, closer: str, markers: re.Pattern[str],
           *, line_start: bool = False) -> str | None:
    """Generic block-comment hiding: ``opener … closer`` holds the HTML and the code
    outside carries the language's markers and is not HTML itself."""
    spans, pos = [], 0
    op_re = re.compile((r"(?m)^[ \t]*" if line_start else "") + opener)
    cl_re = re.compile((r"(?m)^[ \t]*" if line_start else "") + closer)
    while len(spans) < 64:
        m = op_re.search(text, pos)
        if not m:
            break
        c = cl_re.search(text, m.end())
        if not c:
            break
        body = text[m.end():c.start()]
        if _is_html(body) and (markup or m.start() - _first(text) <= _NEAR_START):
            spans.append((m.start(), c.end(), m.group(0), c.group(0)))
        pos = c.end()
    if not spans:
        return None
    outside = _cut(text, spans)
    rest = outside
    for a, b, op, cl in spans:      # what is left once the placeholders are gone
        rest = rest.replace(op + _placeholder(b - a - len(op) - len(cl)) + cl, "")
    if len(rest.strip()) < 12 or _is_html(rest) or not markers.search(rest):
        return None
    return outside


_PS = re.compile(r"\$\w+\s*=|\bIEX\b|Invoke-\w+|\[(?:System\.)?\w+(?:\.\w+)*\]::|-join\b|\bparam\s*\(|"
                 r"\bfunction\s+[\w-]+\s*\{|\bAdd-Type\b|\bNew-Object\b|\bStart-Process\b|\bWrite-Host\b", re.I)
_JS = re.compile(r"\bfunction\s*\w*\s*\(|\bvar\s+\w+|\blet\s+\w+|\bconst\s+\w+|new\s+ActiveXObject|"
                 r"\bWScript\.|\beval\s*\(|\brequire\s*\(|=>|\bGetObject\s*\(")
_AHK = re.compile(r"(?im)^\s*(?:#NoEnv|#SingleInstance|#Persistent|Run\s*,|RunWait\s*,|DllCall\s*\(|"
                  r"FileInstall\s*,|SendInput|URLDownloadToFile|\w+\s*:=)")
_LUA = re.compile(r"\blocal\s+\w+|\bfunction\s+[\w.:]+\s*\(|\bload(?:string)?\s*\(|\brequire\s*[\(\"']|"
                  r"\bos\.execute\b|\bio\.\w+|\bstring\.(?:char|byte|sub)\b|\bend\b")
_RUBY = re.compile(r"(?m)^\s*(?:require\s|def\s|puts\s|class\s|module\s)|\beval\s*\(|\bsystem\s*\(|"
                   r"\bBase64\.|\bIO\.\w+|\bFile\.\w+|`[^`]+`|\.unpack\b")
_PERL = re.compile(r"\buse\s+(?:strict|warnings|MIME::Base64|Socket|IO::)|\bmy\s+[\$@%]\w+|\beval\s*[\({]|"
                   r"\bsystem\s*\(|\bunpack\s*\(|\bprint\s+|\bsub\s+\w+\s*\{|\bopen\s*\(")
_AU3 = re.compile(r"(?im)^\s*(?:Local|Global|Dim)\s+\$\w+|\bDllCall\s*\(|\bRun\s*\(|\bShellExecute\s*\(|"
                  r"\bExecute\s*\(|\bFileInstall\s*\(|^\s*Func\s+\w+|\bBinaryToString\s*\(|#include\s*<")
_TCL = re.compile(r"(?m)^\s*(?:set\s+\w+|proc\s+\w+|puts\s|package\s+require|exec\s|eval\s|source\s)")
_SH = re.compile(r"(?m)^\s*(?:#!/|curl\s|wget\s|chmod\s|base64\s+-d|bash\s|sh\s|python3?\s|nohup\s|"
                 r"echo\s|export\s|\w+=)")
_BAT = re.compile(r"(?im)^\s*(?:@?echo\s+off|exit\s+/b|set\s+\w|start\s|mshta|cscript|wscript|"
                  r"powershell|call\s|goto\s|if\s|for\s)")


def _batch(text: str) -> tuple[str, str] | None:
    """``<!-- :`` hybrid: batch runs the lines up to ``-->`` (``<!--`` is a label line
    for cmd), then mshta / cscript re-open the same file as HTA / WSF."""
    lines = text.splitlines(keepends=True)
    i = next((k for k, ln in enumerate(lines[:20]) if ln.strip()), None)
    if i is None or not re.match(r"\s*<!--\s*:", lines[i]):
        return None
    end = next((k for k in range(i + 1, min(len(lines), i + 4000)) if "-->" in lines[k]), None)
    if end is None:
        return None
    code = "".join(lines[i + 1:end])
    after = "".join(lines[end + 1:])
    if not _BAT.search(code) or not (_is_html(after) or re.search(r"<(?:job|script|hta:application)\b", after, re.I)):
        return None
    return code, "after a batch block that cmd runs before the page (<!-- : hybrid)"


_PHP = re.compile(r"<\?php\b(.*?)(?:\?>|\Z)", re.S | re.I)


def _php(text: str) -> tuple[str, str] | None:
    blocks = [m.group(1) for m in _PHP.finditer(text[:MAX_SIZE])][:64]
    if not blocks or not _is_html(_PHP.sub("", text[:400_000])):
        return None
    code = "<?php\n" + "\n// ---\n".join(b.strip() for b in blocks) + "\n"
    if not re.search(r"\b(eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|"
                     r"shell_exec|system|passthru|exec|popen|proc_open|preg_replace\s*\(\s*['\"].*/e)\b", code, re.I):
        return None                      # an ordinary PHP template
    return code, "in PHP blocks that the server runs inside the page"


# (language, extension, detector) in the order they are tried
def _detectors(markup: bool) -> list[tuple[str, str, Any]]:
    def blk(op: str, cl: str, mk: re.Pattern[str], how: str, **kw: Any):  # noqa: ANN202
        def run(t: str) -> tuple[str, str] | None:
            out = _block(t, markup, op, cl, mk, **kw)
            return (out, how) if out is not None else None
        return run
    return [
        ("Python", "py", lambda t: _python(t, markup)),
        ("batch", "bat", _batch),
        ("PowerShell", "ps1", blk(r"<#", r"#>", _PS, "inside a <# … #> block comment")),
        ("AutoIt", "au3", blk(r"#(?:cs|comments-start)\b", r"#(?:ce|comments-end)\b", _AU3,
                              "inside a #cs … #ce block comment", line_start=True)),
        ("Lua", "lua", blk(r"--\[(=*)\[", r"\](=*)\]", _LUA, "inside a --[[ … ]] block comment")),
        ("Ruby", "rb", blk(r"=begin\b", r"=end\b", _RUBY, "inside a =begin … =end block comment", line_start=True)),
        ("Perl", "pl", blk(r"=(?:pod|head\d|begin|for|item|over)\b", r"=cut\b", _PERL,
                           "inside POD documentation (=pod … =cut)", line_start=True)),
        ("Perl", "pl", lambda t: _after_end(t, _PERL, markup)),
        ("Ruby", "rb", lambda t: _after_end(t, _RUBY, markup)),
        ("JavaScript", "js", blk(r"/\*", r"\*/", _JS, "inside a /* … */ block comment")),
        ("AutoHotkey", "ahk", blk(r"/\*", r"\*/", _AHK, "inside a /* … */ block comment", line_start=True)),
        ("Tcl", "tcl", blk(r"if\s+0\s*\{", r"\}", _TCL, "inside an if 0 { … } block", line_start=True)),
        ("shell", "sh", lambda t: _heredoc(t, markup)),
        ("PHP", "php", _php),
    ]


def _after_end(text: str, markers: re.Pattern[str], markup: bool) -> tuple[str, str] | None:
    """Perl / Ruby stop reading at ``__END__`` / ``__DATA__``: the page goes after it.
    (A browser shows the code as text before the page — still a working lure.)"""
    m = re.search(r"(?m)^__(?:END|DATA)__\s*$", text)
    if not m or not _is_html(text[m.end():]):
        return None
    code = text[:m.start()]
    if len(code.strip()) < 12 or _is_html(code) or not markers.search(code):
        return None
    return code + m.group(0) + "\n" + _placeholder(len(text) - m.end()) + "\n", "after __END__ / __DATA__"


def _heredoc(text: str, markup: bool) -> tuple[str, str] | None:
    m = re.search(r"(?m)^\s*:\s*<<-?\s*['\"]?(\w+)['\"]?\s*$", text)
    if not m or not (markup or m.start() - _first(text) <= _NEAR_START):
        return None
    c = re.compile(rf"(?m)^\s*{re.escape(m.group(1))}\s*$").search(text, m.end())
    if not c or not _is_html(text[m.end():c.start()]):
        return None
    out = text[:m.end()] + "\n" + _placeholder(c.start() - m.end()) + "\n" + text[c.start():]
    rest = text[:m.start()] + text[c.end():]
    if len(rest.strip()) < 12 or _is_html(rest) or not _SH.search(rest):
        return None
    return out, "inside a : <<'EOF' … EOF here-document"


def detect(data: bytes, name: str = "") -> dict[str, Any] | None:
    """The language the page is also written in, the code outside the HTML and how
    the HTML is hidden; ``None`` when the file is not an HTML polyglot."""
    if not data or len(data) > MAX_SIZE:
        return None
    text = _text(data)
    if text is None or not _is_html(text):
        return None
    markup = Path(name).suffix.lower() in MARKUP_EXT
    for lang, ext, fn in _detectors(markup):
        try:
            got = fn(text)
        except (RecursionError, MemoryError, re.error):
            got = None
        if got:
            code, how = got
            sus = suspicious_tokens(code)
            return {"language": lang, "ext": ext, "how": how, "code": code,
                    "lines": code.count("\n") + 1, "suspicious": sus,
                    "html_chars": len(text) - len(code)}
    return None


def finding(rec: dict[str, Any], where: str) -> dict[str, Any]:
    lang, sus = rec["language"], rec["suspicious"]
    detail = (f"HTML page that is also a {lang} program: the page is hidden {rec['how']} and the "
              f"{lang} code around it runs when the file is given to the interpreter "
              f"({rec['lines']} line(s) extracted and analysed as a child)")
    if sus:
        detail += f" — the code uses {', '.join(sus[:8])}"
    head = "\n".join(ln for ln in rec["code"].splitlines() if ln.strip())[:1500]
    return {"tool": "polyglot", "rule": f"polyglot_html_{rec['ext']}",
            "severity": "high" if sus else "medium", "detail": detail,
            "location": where, "evidence": head}


def child_name(name: str, rec: dict[str, Any]) -> str:
    stem = Path(name).stem or "page"
    return f"{stem}.polyglot.{rec['ext']}"


def write_child(rec: dict[str, Any], name: str, out_dir: Path) -> dict[str, Any] | None:
    """Write the extracted code as a file the nested analysis takes as a child."""
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        fn = child_name(name, rec)
        p = out_dir / fn
        p.write_text(rec["code"], encoding="utf-8")
    except OSError:
        return None
    return {"path": str(p), "filename": fn,
            "origin": f"{rec['language']} code of the HTML polyglot {name} (page hidden {rec['how']})"}
