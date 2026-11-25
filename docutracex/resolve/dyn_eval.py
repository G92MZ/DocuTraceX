"""PHP, Perl, Ruby, Lua and AutoHotkey, evaluated statically: what a dropper or webshell computes.

One small interpreter serves the five: each language is a **profile** (how its strings, comments,
variables and blocks are written, which operator concatenates, how a method is called) plus its
**library** (the functions droppers use, mapped to :mod:`.transforms`, and the calls that matter:
evaluate, run a command, write a file, download). Nothing runs: the source is tokenised, parsed and
walked here, with budgets.

- PHP: ``eval`` / ``assert`` / ``create_function`` / ``preg_replace('/…/e')`` /
  ``call_user_func`` / variable functions (``$f = 'base'.'64_decode'; $f(…)``), ``base64_decode``,
  ``gzinflate`` / ``gzuncompress`` / ``gzdecode``, ``str_rot13``, ``strrev``, ``hex2bin``,
  ``convert_uudecode``, ``openssl_decrypt``, ``pack``; ``system`` / ``exec`` / ``shell_exec`` /
  ``passthru`` / backticks; ``file_put_contents`` / ``fwrite``; ``file_get_contents(url)`` / ``curl``.
- Perl: ``eval``, ``decode_base64``, ``pack`` / ``unpack`` (``H*``, ``C*``, ``u``, ``m``),
  ``uncompress`` / ``memGunzip``, ``s///`` / ``tr///``, ``reverse`` / ``join`` / ``map``; ``system`` /
  ``exec`` / backticks / ``qx``; ``open`` + ``print``; ``LWP`` ``get`` / ``getstore``.
- Ruby: ``eval`` / ``instance_eval``, ``Base64.decode64``, ``Zlib::Inflate.inflate``,
  ``pack`` / ``unpack``, ``reverse`` / ``gsub`` / ``tr``; ``system`` / backticks / ``%x()``,
  ``File.write``, ``Net::HTTP.get`` / ``URI.open``.
- Lua: ``load`` / ``loadstring`` (+ ``()``), ``string.char`` / ``byte``, ``:reverse()``, ``gsub``,
  ``table.concat``, ``bit32.bxor`` / ``~``; ``os.execute`` / ``io.popen``; ``io.open():write``.
- AutoHotkey: ``Run`` / ``ComObjCreate("WScript.Shell").Run``, ``UrlDownloadToFile``,
  ``FileAppend``, ``Chr`` / ``SubStr`` / ``StrReplace``, ``DllCall`` (``VirtualAlloc`` + ``NumPut``).

XOR / add / subtract loops are named in the recipe; what reaches an "evaluate" call is a stage,
evaluated in turn; commands are followed by :mod:`.commands`.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
import time
import urllib.parse
from typing import Any, Callable

from . import commands
from . import transforms as T
from .js_eval import JSStr, rec, step, tag
from .sinks import Sinks
from .value import Value

MAX_STEPS = 4_000_000
MAX_SECONDS = 30.0
MAX_LOOP = 2_000_000
MAX_DEPTH = 12
MAX_CALL_DEPTH = 80
MAX_STR = 64 * 1024 * 1024


class Unk:
    def __init__(self, why: str, recipe: tuple[str, ...] = (), quiet: bool = False) -> None:
        self.why, self.recipe, self.quiet = why, recipe, quiet

    def __repr__(self) -> str:
        return f"<unknown: {self.why}>"


class RList(list):
    recipe: tuple[str, ...] = ()


class Func:
    def __init__(self, name: str, params: list, body: Any, src: str, expr: bool = False, closure: Any = None) -> None:
        self.name, self.params, self.body, self.src, self.expr, self.closure = name, params, body, src, expr, closure


class Native:
    def __init__(self, name: str, fn: Callable[..., Any]) -> None:
        self.name, self.fn = name, fn


class Obj:
    """A library object (a file handle, a cipher, a COM object…)."""

    def __init__(self, kind: str, **st: Any) -> None:
        self.kind, self.st = kind, st


class _Return(Exception):
    def __init__(self, v: Any) -> None:
        self.v = v


class _Break(Exception):
    pass


class _Next(Exception):
    pass


class _Die(Exception):
    pass


class Limit(Exception):
    pass


# --- profiles ---------------------------------------------------------------------------------
class Profile:
    name = ""
    lang = ""
    sigil_vars = False            # $x is a variable (PHP, Perl)
    concat = (".",)               # string concatenation operators
    member = ("->",)              # member / method access
    newline_ends = False          # a newline ends a statement
    end_blocks = False            # blocks close with "end" (Ruby, Lua)
    line_comments: tuple[str, ...] = ("#",)
    block_comments: tuple[tuple[str, str], ...] = ()
    interpolate = True            # "…" strings interpolate variables
    case_insensitive_funcs = False


class PHP(Profile):
    name, lang = "php", "PHP"
    sigil_vars = True
    concat = (".",)
    member = ("->", "::")
    line_comments = ("//", "#")
    block_comments = (("/*", "*/"),)
    case_insensitive_funcs = True


class Perl(Profile):
    name, lang = "perl", "Perl"
    sigil_vars = True
    concat = (".",)
    member = ("->", "::")
    line_comments = ("#",)
    block_comments = (("\n=", "\n=cut"),)


class Ruby(Profile):
    name, lang = "ruby", "Ruby"
    concat = ()
    member = (".", "::", "&.")
    newline_ends = True
    end_blocks = True
    line_comments = ("#",)
    block_comments = (("=begin", "=end"),)


class Lua(Profile):
    name, lang = "lua", "Lua"
    concat = ("..",)
    member = (".", ":")
    newline_ends = False
    end_blocks = True
    line_comments = ("--",)
    block_comments = (("--[[", "]]"),)
    interpolate = False


class AHK(Profile):
    name, lang = "ahk", "AutoHotkey"
    concat = (".",)
    member = (".",)
    newline_ends = True
    line_comments = (";",)
    block_comments = (("/*", "*/"),)
    interpolate = False
    case_insensitive_funcs = True


PROFILES = {"PHP": PHP, "Perl": Perl, "Ruby": Ruby, "Lua": Lua, "AutoHotkey": AHK}


# --- tokens ------------------------------------------------------------------------------------
class Tok:
    __slots__ = ("k", "v", "line", "raw")

    def __init__(self, k: str, v: Any, line: int, raw: str = "") -> None:
        self.k, self.v, self.line, self.raw = k, v, line, raw

    def __repr__(self) -> str:
        return f"{self.k}:{self.v!r}"


_OPS = ["<=>", "**=", "...", "<<=", ">>=", "===", "!==", "//=", "..=", "||=", "&&=",
        "->", "=>", "::", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", ".=",
        "%=", "^=", "|=", "&=", "<<", ">>", "**", "..", "=~", "!~", "~=", "//", "<>", "?:", "??", ":=", "&.",
        "+", "-", "*", "/", "%", "^", "|", "&", "~", "!", "=", "<", ">", "?", ":", ";", ",", ".", "(", ")",
        "[", "]", "{", "}", "@", "\\", "#"]

_ESC = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'", "$": "$", "e": "\x1b",
        "a": "\a", "b": "\b", "f": "\f", "v": "\v", "@": "@", "`": "`", "{": "{", "#": "#"}


def _unescape(s: str, lua: bool = False, ahk: bool = False) -> str:
    """The escapes of a double-quoted string (C style; Lua's \\ddd is decimal)."""
    out = []
    i = 0
    n = len(s)
    esc = "`" if ahk else "\\"
    while i < n:
        c = s[i]
        if c != esc or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        d = s[i + 1]
        if d == "x" and not ahk:
            m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:])
            if m:
                out.append(chr(int(m.group(0), 16)))
                i += 2 + m.end()
                continue
        if d == "u" and not ahk:
            m = re.match(r"\{([0-9a-fA-F]+)\}|([0-9a-fA-F]{4})", s[i + 2:])
            if m:
                cp = int(m.group(1) or m.group(2), 16)
                out.append(chr(cp).encode("utf-8").decode("latin-1") if cp > 0xFF else chr(cp))
                i += 2 + m.end()
                continue
        if d.isdigit() and not ahk:
            m = re.match(r"\d{1,3}", s[i + 1:]) if lua else re.match(r"[0-7]{1,3}", s[i + 1:])
            if m:
                out.append(chr(int(m.group(0), 10 if lua else 8) & 0xFF))
                i += 1 + m.end()
                continue
        if lua and d == "z":
            i += 2
            while i < n and s[i] in " \t\r\n":
                i += 1
            continue
        if ahk:
            out.append({"n": "\n", "t": "\t", "r": "\r", "`": "`", ";": ";", "%": "%", '"': '"', ",": ","}.get(d, d))
        else:
            out.append(_ESC.get(d, "\\" + d))
        i += 2
    return "".join(out)


def tokenize(src: str, prof: type[Profile]) -> list[Tok]:  # noqa: C901, PLR0912, PLR0915
    out: list[Tok] = []
    i = 0
    line = 1
    n = len(src)
    pname = prof.name

    def add(k: str, v: Any, raw: str = "") -> None:
        out.append(Tok(k, v, line, raw))

    def prev_allows_regex() -> bool:
        if not out:
            return True
        p = out[-1]
        return p.k == "op" and p.v not in (")", "]", "}") or (p.k == "id" and p.v in ("split", "grep", "if", "unless",
                                                                                       "and", "or", "not", "return", "when"))

    while i < n:
        c = src[i]
        if c == "\n":
            if prof.newline_ends:
                if out and not (out[-1].k == "op" and out[-1].v in (",", "(", "[", "{", ".", "+", "-", "*", "&&", "||",
                                                                     "\\", "=", "|", "..", "=>")):
                    add("nl", "\n")
            line += 1
            i += 1
            continue
        if c in " \t\r\f\v":
            i += 1
            continue
        # PHP open / close tags
        if pname == "php":
            if src.startswith("<?php", i):
                i += 5
                continue
            if src.startswith("<?=", i):
                i += 3
                add("id", "echo")
                continue
            if src.startswith("<?", i):
                i += 2
                continue
            if src.startswith("?>", i):
                add("op", ";")
                j = src.find("<?", i + 2)
                html = src[i + 2:j if j >= 0 else n]
                line += html.count("\n")
                if html.strip():
                    add("id", "echo")
                    add("str", html)
                    add("op", ";")
                i = j if j >= 0 else n
                continue
        # comments
        hit = False
        for a, b in prof.block_comments:
            if src.startswith(a, i) and (a != "\n=" or True):
                if a == "\n=" and not (i == 0 or src[i - 1] == "\n"):
                    continue
                j = src.find(b, i + len(a))
                j = n if j < 0 else j + len(b)
                line += src.count("\n", i, j)
                i = j
                hit = True
                break
        if hit:
            continue
        if pname == "lua" and src.startswith("--[", i):
            m = re.match(r"--\[(=*)\[", src[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = src.find(close, i)
                j = n if j < 0 else j + len(close)
                line += src.count("\n", i, j)
                i = j
                continue
        if pname == "perl" and src.startswith("__END__", i) or pname == "perl" and src.startswith("__DATA__", i):
            break
        if pname == "ahk" and c == "#" and (not out or out[-1].k == "nl" or i == 0 or src[i - 1] == "\n"):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        for lc in prof.line_comments:
            if src.startswith(lc, i) and not (lc == "#" and pname == "php" and src.startswith("#[", i)):
                if lc == ";" and i > 0 and src[i - 1] not in " \t\n":
                    continue
                j = src.find("\n", i)
                i = n if j < 0 else j
                hit = True
                break
        if hit:
            continue
        # heredocs
        if pname in ("php", "perl", "ruby") and src.startswith("<<", i):
            m = (re.match(r"<<<\s*(['\"]?)([A-Za-z_]\w*)\1\r?\n", src[i:]) if pname == "php"
                 else re.match(r"<<([~-]?)(['\"]?)([A-Za-z_]\w*)\2", src[i:]))
            if m:
                tag_ = m.group(2) if pname == "php" else m.group(3)
                raw_q = (m.group(1) == "'") if pname == "php" else (m.group(2) == "'")
                if pname == "php":
                    body_start = i + m.end()
                else:
                    nl = src.find("\n", i)
                    body_start = nl + 1 if nl >= 0 else n
                em = re.compile(rf"(?m)^[ \t]*{re.escape(tag_)}\b;?").search(src, body_start)
                body = src[body_start:em.start() if em else n]
                if pname != "php":
                    # the rest of the heredoc's own line still has to be read: splice the body out
                    rest_line_end = src.find("\n", i)
                    rest = src[i + m.end():rest_line_end if rest_line_end >= 0 else n]
                    after = em.end() if em else n
                    if pname == "ruby" and m.group(1) == "~":
                        ind = min((len(x) - len(x.lstrip()) for x in body.splitlines() if x.strip()), default=0)
                        body = "\n".join(x[ind:] for x in body.split("\n"))
                    line += src.count("\n", i, after)
                    add("str", body if raw_q else ("\x00interp\x00" + body))
                    src = src[:i] + "\x00" * 0 + rest + "\n" + src[after:]
                    n = len(src)
                    i = i
                    continue
                if body.endswith("\n"):
                    body = body[:-1]
                add("str", body if raw_q else ("\x00interp\x00" + body))
                line += src.count("\n", i, em.end() if em else n)
                i = em.end() if em else n
                continue
        # strings
        if c in "'\"`":
            j = i + 1
            buf = []
            while j < n and src[j] != c:
                if src[j] == "\\" and pname != "ahk" and j + 1 < n:
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                if pname == "ahk" and src[j] == "`" and j + 1 < n:
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                if pname == "ahk" and c == '"' and src[j] == '"' and j + 1 < n and src[j + 1] == '"':
                    buf.append('`"')
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            body = "".join(buf)
            line += body.count("\n")
            i = j + 1
            if c == "'" and pname in ("php", "perl", "ruby"):
                add("str", body.replace("\\'", "'").replace("\\\\", "\\"))
            elif c == "`" and pname in ("php", "perl", "ruby"):
                add("cmd", "\x00interp\x00" + body)
            elif c == '"' and prof.interpolate:
                add("str", "\x00interp\x00" + body)
            else:
                add("str", _unescape(body, lua=pname == "lua", ahk=pname == "ahk"))
            continue
        # Lua long strings
        if pname == "lua" and c == "[":
            m = re.match(r"\[(=*)\[", src[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = src.find(close, i + m.end())
                j = n if j < 0 else j
                body = src[i + m.end():j]
                if body.startswith("\n"):
                    body = body[1:]
                line += src.count("\n", i, j)
                add("str", body)
                i = j + len(close)
                continue
        # Perl / Ruby quote-like operators: q qq qw qx m s tr y / %q %Q %w %x
        if pname in ("perl", "ruby"):
            if pname == "perl":
                m = re.match(r"(qq|qw|qx|q|m|s|tr|y)\s*([^\w\s])", src[i:]) if (i == 0 or not (src[i - 1].isalnum() or src[i - 1] in "_$@%")) else None
            else:
                m = re.match(r"%([qQwWxi]?)([^\w\s])", src[i:]) if prev_allows_regex() or (out and out[-1].k in ("op", "nl")) else None
            if m:
                kind = m.group(1)
                op = m.group(2)
                close = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(op, op)
                j, body = _delimited(src, i + m.end(), op, close)
                if j is not None:
                    if kind in ("s", "tr", "y") and pname == "perl":
                        if close != op:
                            k = j
                            while k < n and src[k] in " \t":
                                k += 1
                            op2 = src[k] if k < n else op
                            close2 = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(op2, op2)
                            j2, body2 = _delimited(src, k + 1, op2, close2)
                        else:
                            j2, body2 = _delimited(src, j, op, close)
                        if j2 is not None:
                            fm = re.match(r"[a-z]*", src[j2:])
                            add("subst", (kind, body, body2, fm.group(0)))
                            line += src.count("\n", i, j2)
                            i = j2 + fm.end()
                            continue
                    fm = re.match(r"[a-z]*", src[j:])
                    line += src.count("\n", i, j)
                    if kind in ("q",) or (pname == "ruby" and kind == "q"):
                        add("str", body)
                    elif kind in ("qq", "Q", ""):
                        add("str", "\x00interp\x00" + body)
                    elif kind in ("qw", "w", "W", "i"):
                        add("qw", body.split())
                    elif kind in ("qx", "x"):
                        add("cmd", "\x00interp\x00" + body)
                    elif kind == "m":
                        add("regex", (body, fm.group(0)))
                    i = j + (fm.end() if kind == "m" else 0)
                    continue
            # a bare /regex/
            if c == "/" and prev_allows_regex():
                j, body = _delimited(src, i + 1, "/", "/")
                if j is not None and "\n" not in body:
                    fm = re.match(r"[a-z]*", src[j:])
                    add("regex", (body, fm.group(0)))
                    i = j + fm.end()
                    continue
        if pname == "php" and c == "/" and False:
            pass
        # numbers
        m = re.match(r"0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*\.\d+(?:[eE][+-]?\d+)?|\d[\d_]*(?:[eE][+-]?\d+)?|\.\d+", src[i:])
        if m and not (c == "." and out and out[-1].k in ("str", "var", "id") and prof.name in ("php", "perl")):
            t = m.group(0).replace("_", "")
            if t.lower().startswith("0x"):
                v: Any = int(t, 16)
            elif t.lower().startswith("0b"):
                v = int(t[2:], 2)
            elif re.fullmatch(r"0[0-7]+", t) and pname in ("php", "perl"):
                v = int(t, 8)
            elif re.search(r"[.eE]", t):
                v = float(t)
            else:
                v = int(t)
            add("num", v)
            i += m.end()
            continue
        # variables / identifiers
        if prof.sigil_vars and c in ("$@%" if pname == "perl" else "$") and i + 1 < n and (src[i + 1].isalpha() or src[i + 1] in "_{:" or
                                                             (c == "$" and src[i + 1] in "$#") or (c == "@" and src[i + 1] == "_")):
            if c == "%" and out and out[-1].k in ("var", "num", "str") and src[i + 1] != "{":
                pass
            else:
                m = re.match(r"[$@%](?:\$|#)?(\{[A-Za-z_][\w:]*\}|[A-Za-z_][\w]*(?:::\w+)*|_)", src[i:])
                if m:
                    nm = m.group(1).strip("{}")
                    sig = c if c != "$" or src[i + 1] not in "#" else "$#"
                    if c == "$" and src[i + 1] == "$":
                        add("op", "$$")
                        i += 1
                        continue
                    add("var", (sig, nm))
                    i += m.end()
                    continue
        if pname == "ruby" and c in "@$" and i + 1 < n and (src[i + 1].isalpha() or src[i + 1] in "_@"):
            m = re.match(r"[@$]@?[A-Za-z_]\w*", src[i:])
            add("id", m.group(0))
            i += m.end()
            continue
        if pname == "ruby" and c == ":" and i + 1 < n and (src[i + 1].isalpha() or src[i + 1] == "_") and \
                not (out and out[-1].k == "op" and out[-1].v == "?"):
            m = re.match(r":[A-Za-z_]\w*[?!]?", src[i:])
            if not (i > 0 and src[i - 1] == ":"):
                add("str", m.group(0)[1:])
                i += m.end()
                continue
        if c.isalpha() or c == "_":
            m = re.match(r"[A-Za-z_]\w*[?!]?" if pname == "ruby" else r"[A-Za-z_]\w*", src[i:])
            word = m.group(0)
            i += m.end()
            if pname == "ahk" and i < n and src[i] == "," and word.lower() in _AHK_COMMANDS:
                # v1 command syntax: Run, target  → Run("target")
                j = src.find("\n", i)
                j = n if j < 0 else j
                argtext = src[i + 1:j]
                add("ahkcmd", (word, argtext))
                i = j
                continue
            add("id", word)
            continue
        if pname == "ahk" and c == "%":
            m = re.match(r"%([A-Za-z_]\w*)%", src[i:])
            if m:
                add("id", m.group(1))
                i += m.end()
                continue
        for op in _OPS:
            if src.startswith(op, i):
                add("op", op)
                i += len(op)
                break
        else:
            i += 1
    add("nl", "\n")
    add("eof", None)
    return out


_AHK_COMMANDS = {"run", "runwait", "urldownloadtofile", "fileappend", "filedelete", "msgbox", "sleep", "filecopy",
                 "regwrite", "regread", "envget", "stringreplace", "fileread", "filemove", "process", "send"}


def _delimited(src: str, start: int, op: str, close: str) -> tuple[int | None, str]:
    depth = 1
    j = start
    n = len(src)
    while j < n:
        ch = src[j]
        if ch == "\\" and j + 1 < n:
            j += 2
            continue
        if ch == close and (op == close or depth == 1):
            return j + 1, src[start:j]
        if ch == close:
            depth -= 1
        elif ch == op and op != close:
            depth += 1
        j += 1
    return None, ""


# --- parser --------------------------------------------------------------------------------------
_BIN = {
    "or": 1, "xor": 1, "and": 2, "not": 3, "??": 4, "?": 5, "||": 6, "//": 6, "&&": 7, "|": 8, "^": 9, "&": 10,
    "==": 11, "!=": 11, "===": 11, "!==": 11, "<>": 11, "~=": 11, "<=>": 11, "=~": 11, "!~": 11,
    "<": 12, ">": 12, "<=": 12, ">=": 12, "lt": 12, "gt": 12, "le": 12, "ge": 12, "eq": 11, "ne": 11,
    "..": 13, "...": 13, "<<": 14, ">>": 14, "+": 15, "-": 15, ".": 15, "x": 16, "*": 16, "/": 16, "%": 16,
    "mod": 16, "**": 18,
}
_ASSIGN = {"=", "+=", "-=", "*=", "/=", ".=", "..=", "%=", "^=", "|=", "&=", "<<=", ">>=", "**=", "||=", "&&=", "//=",
           "??=", ":="}


class Parser:
    def __init__(self, toks: list[Tok], prof: type[Profile]) -> None:
        self.t = toks
        self.i = 0
        self.p = prof

    def peek(self, k: int = 0) -> Tok:
        return self.t[min(self.i + k, len(self.t) - 1)]

    def next(self) -> Tok:
        t = self.t[self.i]
        self.i = min(self.i + 1, len(self.t) - 1)
        return t

    def isop(self, *v: str, k: int = 0) -> bool:
        t = self.peek(k)
        return t.k == "op" and t.v in v

    def isid(self, *v: str, k: int = 0) -> bool:
        t = self.peek(k)
        return t.k == "id" and t.v in v

    def eat(self, *v: str) -> bool:
        if self.isop(*v) or self.isid(*v):
            self.next()
            return True
        return False

    def expect(self, v: str) -> None:
        if not self.eat(v):
            raise SyntaxError(f"line {self.peek().line}: expected {v!r}, got {self.peek()}")

    def skip_sep(self) -> None:
        while self.peek().k == "nl" or self.isop(";"):
            self.next()

    # statements
    def program(self) -> list:
        out = []
        while True:
            self.skip_sep()
            if self.peek().k == "eof":
                return out
            st = self.safe_stmt()
            if st is not None:
                out.append(st)

    def safe_stmt(self) -> Any:
        start = self.i
        line = self.peek().line
        try:
            return self.stmt()
        except (SyntaxError, IndexError, RecursionError) as exc:
            # skip to the end of the statement
            self.i = max(self.i, start + 1)
            while self.peek().k not in ("eof", "nl") and not self.isop(";", "}"):
                self.next()
            if self.isop("}") and self.i == start:
                self.next()
            return ("error", line, str(exc)[:200])

    def block(self) -> list:
        """``{ … }`` or a statement list up to end / else / elsif / elseif (keyword blocks)."""
        if self.isop("{") and not self.p.end_blocks:
            self.next()
            out = []
            while True:
                self.skip_sep()
                if self.isop("}"):
                    self.next()
                    return out
                if self.peek().k == "eof":
                    return out
                st = self.safe_stmt()
                if st is not None:
                    out.append(st)
        if self.p.end_blocks:
            out = []
            while True:
                self.skip_sep()
                if self.isid("end", "else", "elsif", "elseif", "when", "rescue", "ensure", "until") or self.peek().k == "eof":
                    return out
                if self.isop("}"):
                    return out
                st = self.safe_stmt()
                if st is not None:
                    out.append(st)
        st = self.safe_stmt()
        return [st] if st is not None else []

    def end_kw(self) -> None:
        self.skip_sep()
        self.eat("end")

    def stmt(self) -> Any:  # noqa: C901, PLR0911, PLR0912, PLR0915
        t = self.peek()
        line = t.line
        p = self.p.name
        if t.k == "ahkcmd":
            self.next()
            word, argtext = t.v
            args = [("ahkarg", a.strip()) for a in _split_ahk_args(argtext)]
            return ("expr", line, ("call", ("name", word), args))
        if t.k == "id":
            w = t.v
            wl = w.lower()
            if wl in ("function", "sub", "def", "func") and (self.peek(1).k == "id" or (p == "lua" and self.peek(1).k == "id")):
                return self.funcdef()
            if p == "lua" and wl == "local" and self.isid("function", k=1):
                self.next()
                return self.funcdef()
            if p == "ahk" and self.peek(1).k == "op" and self.peek(1).v == "(" and self._ahk_funcdef():
                return self.funcdef(ahk=True)
            if wl in ("if", "unless") and p != "ahk" or (p == "ahk" and wl == "if"):
                return self.if_stmt()
            if wl == "while" or wl == "until":
                self.next()
                c = self.cond_expr()
                self.eat("do")
                body = self.block()
                if self.p.end_blocks:
                    self.end_kw()
                return ("while", line, ("not", c) if wl == "until" else c, body)
            if wl == "for" or wl == "foreach":
                return self.for_stmt()
            if wl == "do" and self.p.end_blocks:
                self.next()
                body = self.block()
                self.end_kw()
                return ("block", line, body)
            if wl == "do" and p in ("php", "perl"):
                self.next()
                if self.isop("{"):
                    body = self.block()
                    if self.eat("while"):
                        c = self.cond_expr()
                        return ("dowhile", line, body, c)
                    return ("block", line, body)
                self.i -= 1
            if wl == "loop" and p == "ahk":
                self.next()
                cnt = None
                if self.eat(","):
                    cnt = self.expr()
                elif self.peek().k not in ("nl",) and not self.isop("{"):
                    cnt = self.expr()
                body = self.block()
                return ("ahkloop", line, cnt, body)
            if wl == "repeat" and p == "lua":
                self.next()
                body = self.block()
                self.expect("until")
                c = self.expr()
                return ("dowhile", line, body, ("not", c))
            if wl == "begin" and p == "ruby":
                self.next()
                body = self.block()
                while self.isid("rescue", "ensure", "else"):
                    self.next()
                    if self.peek().k != "nl":
                        try:
                            self.expr()
                        except SyntaxError:
                            pass
                    self.block()
                self.end_kw()
                return ("block", line, body)
            if wl == "try" and p in ("php", "ahk"):
                self.next()
                body = self.block()
                while self.isid("catch", "finally"):
                    self.next()
                    if self.isop("("):
                        self.paren_skip()
                    self.block()
                return ("block", line, body)
            if wl == "return":
                self.next()
                if self.peek().k in ("nl", "eof") or self.isop(";", "}") or self.isid("end"):
                    return self.modifiers(("return", line, None))
                return self.modifiers(("return", line, self.expr_list()))
            if wl in ("break", "last", "exit") and not (p == "php" and wl == "exit" and self.isop("(", k=1)):
                self.next()
                if wl == "exit" and p in ("perl", "ruby", "php", "ahk", "lua"):
                    while self.peek().k not in ("nl", "eof") and not self.isop(";", "}"):
                        self.next()
                    return ("die", line)
                return self.modifiers(("break", line))
            if wl in ("continue", "next"):
                self.next()
                return self.modifiers(("continue", line))
            if wl in ("use", "require", "require_once", "include", "include_once", "import", "package", "namespace",
                      "global", "static", "local", "my", "our", "declare") and p in ("php", "perl", "ruby", "lua", "ahk"):
                if wl in ("my", "our", "local", "static", "global") or (wl in ("require", "include", "require_once",
                                                                               "include_once") and p in ("php", "lua", "ruby")):
                    pass
                else:
                    while self.peek().k not in ("nl", "eof") and not self.isop(";"):
                        self.next()
                    return None
            if wl in ("class", "module") and p in ("ruby", "php"):
                self.next()
                self.next()
                while not self.isop("{") and self.peek().k not in ("nl", "eof"):
                    self.next()
                body = self.block()
                if self.p.end_blocks:
                    self.end_kw()
                return ("block", line, body)
            if wl == "switch" and p == "php":
                self.next()
                subj = self.paren_expr()
                return self.php_switch(line, subj)
            if wl == "case" and p == "ruby":
                return self.ruby_case()
        if t.k == "op" and t.v == "{":
            return ("block", line, self.block())
        e = self.expr_list()
        st = ("expr", line, e)
        return self.modifiers(st)

    def _ahk_funcdef(self) -> bool:
        # name(params) {   — on the same or the next line
        j = self.i + 2
        depth = 1
        while j < len(self.t) and depth:
            if self.t[j].k == "op" and self.t[j].v == "(":
                depth += 1
            elif self.t[j].k == "op" and self.t[j].v == ")":
                depth -= 1
            j += 1
        while j < len(self.t) and self.t[j].k == "nl":
            j += 1
        return j < len(self.t) and self.t[j].k == "op" and self.t[j].v == "{"

    def modifiers(self, st: tuple) -> tuple:
        """Perl / Ruby statement modifiers: ``stmt if cond``, ``unless``, ``while``, ``for``."""
        if self.p.name in ("perl", "ruby") and self.isid("if", "unless", "while", "until", "foreach", "for"):
            w = self.next().v
            c = self.expr()
            if w in ("if", "unless"):
                return ("if", st[1], [(c if w == "if" else ("not", c), [st])], None)
            if w in ("while", "until"):
                return ("while", st[1], c if w == "while" else ("not", c), [st])
            return ("foreach", st[1], ("var", ("$", "_")), None, c, [st])
        return st

    def paren_skip(self) -> None:
        depth = 0
        while self.peek().k != "eof":
            t = self.next()
            if t.k == "op" and t.v == "(":
                depth += 1
            elif t.k == "op" and t.v == ")":
                depth -= 1
                if depth <= 0:
                    return

    def paren_expr(self) -> Any:
        self.expect("(")
        e = self.expr_list()
        self.expect(")")
        return e

    def cond_expr(self) -> Any:
        if self.p.name in ("php", "perl") or (self.p.name == "ahk" and self.isop("(")):
            if self.isop("("):
                return self.paren_expr()
        return self.expr()

    def if_stmt(self) -> Any:
        line = self.peek().line
        w = self.next().v
        branches = []
        c = self.cond_expr()
        if w == "unless":
            c = ("not", c)
        self.eat("then")
        if self.p.name == "php" and self.isop(":"):
            self.next()
            body = self._until_kw(("elseif", "else", "endif"))
        else:
            body = self.block()
        branches.append((c, body))
        els = None
        while True:
            save = self.i
            self.skip_sep()
            if self.isid("elseif", "elsif") or (self.isid("else") and self.isid("if", k=1) and not self.p.end_blocks):
                if self.isid("else"):
                    self.next()
                self.next()
                c = self.cond_expr()
                self.eat("then")
                if self.p.name == "php" and self.isop(":"):
                    self.next()
                    branches.append((c, self._until_kw(("elseif", "else", "endif"))))
                else:
                    branches.append((c, self.block()))
                continue
            if self.isid("else"):
                self.next()
                if self.p.name == "php" and self.isop(":"):
                    self.next()
                    els = self._until_kw(("endif",))
                else:
                    els = self.block()
                continue
            self.i = save
            break
        if self.p.end_blocks:
            self.end_kw()
        elif self.p.name == "php":
            self.skip_sep()
            if not self.eat("endif"):
                pass
        return ("if", line, branches, els)

    def _until_kw(self, kws: tuple[str, ...]) -> list:
        out = []
        while True:
            self.skip_sep()
            if self.isid(*kws) or self.peek().k == "eof":
                if self.isid("endif", "endwhile", "endfor", "endforeach"):
                    self.next()
                return out
            st = self.safe_stmt()
            if st is not None:
                out.append(st)

    def for_stmt(self) -> Any:  # noqa: C901
        line = self.peek().line
        w = self.next().v
        p = self.p.name
        if p == "lua":
            names = [self.next().v]
            while self.eat(","):
                names.append(self.next().v)
            if self.eat("="):
                a = self.expr()
                self.expect(",")
                b = self.expr()
                s = self.expr() if self.eat(",") else ("num", 1)
                self.eat("do")
                body = self.block()
                self.end_kw()
                return ("numfor", line, names[0], a, b, s, body)
            self.expect("in")
            it = self.expr_list()
            self.eat("do")
            body = self.block()
            self.end_kw()
            return ("foreach", line, ("name", names[-1]), ("name", names[0]) if len(names) > 1 else None, it, body)
        if p == "ruby":
            name = self.next().v
            self.expect("in")
            it = self.expr()
            self.eat("do")
            body = self.block()
            self.end_kw()
            return ("foreach", line, ("name", name), None, it, body)
        if p == "ahk":
            k = self.next().v
            v = None
            if self.eat(","):
                v = self.next().v
            self.expect("in")
            it = self.expr()
            body = self.block()
            return ("foreach", line, ("name", v or k), ("name", k) if v else None, it, body)
        if p == "perl" and (self.peek().k == "var" or self.isid("my")):
            self.eat("my")
            var = self.primary()
            seq = self.paren_expr()
            body = self.block()
            return ("foreach", line, var, None, seq, body)
        if p == "perl" and self.isop("("):
            # for (init; cond; step)  or  foreach (list)
            save = self.i
            self.next()
            depth = 1
            semis = 0
            while depth and self.peek().k != "eof":
                tk = self.next()
                if tk.k == "op" and tk.v == "(":
                    depth += 1
                elif tk.k == "op" and tk.v == ")":
                    depth -= 1
                elif tk.k == "op" and tk.v == ";" and depth == 1:
                    semis += 1
            self.i = save
            if semis == 0:
                seq = self.paren_expr()
                body = self.block()
                return ("foreach", line, ("var", ("$", "_")), None, seq, body)
        # C style: for (init; cond; step) / PHP foreach ($a as $k => $v)
        self.expect("(")
        if w == "foreach" and p == "php":
            seq = self.expr()
            self.expect("as")
            a = self.expr()
            k = None
            if self.eat("=>"):
                k, a = a, self.expr()
            self.expect(")")
            body = self._until_kw(("endforeach",)) if self.eat(":") else self.block()
            return ("foreach", line, a, k, seq, body)
        init = None if self.isop(";") else self.expr_list()
        self.expect(";")
        cond = None if self.isop(";") else self.expr_list()
        self.expect(";")
        stp = None if self.isop(")") else self.expr_list()
        self.expect(")")
        body = self._until_kw(("endfor",)) if self.eat(":") else self.block()
        return ("cfor", line, init, cond, stp, body)

    def funcdef(self, ahk: bool = False) -> Any:
        line = self.peek().line
        if not ahk:
            self.next()
        name = self.next().v
        while self.isop(".", ":", "::") and self.peek(1).k == "id":
            self.next()
            name = self.next().v
        params: list = []
        if self.isop("("):
            self.next()
            while not self.isop(")") and self.peek().k != "eof":
                if self.isop("&", "*", "...", "&&"):
                    self.next()
                    continue
                t = self.next()
                if t.k == "var":
                    pname = t.v[1]
                elif t.k == "id" and t.v.lower() in ("byref", "array", "string", "int", "callable", "self", "?"):
                    continue
                else:
                    pname = t.v if t.k == "id" else str(t.v)
                default = None
                if self.eat("=", ":="):
                    default = self.expr()
                params.append((pname, default))
                self.eat(",")
            self.expect(")")
        if self.p.name == "php" and self.isop(":"):
            self.next()
            self.next()
        if self.p.name == "perl" and self.isop("(") is False:
            pass
        body = self.block()
        if self.p.end_blocks:
            self.end_kw()
        return ("func", line, name, params, body)

    def php_switch(self, line: int, subj: Any) -> Any:
        self.expect("{")
        cases: list = []
        cur: list | None = None
        while not self.isop("}") and self.peek().k != "eof":
            self.skip_sep()
            if self.eat("case"):
                v = self.expr()
                self.eat(":") or self.eat(";")
                cur = []
                cases.append((v, cur))
            elif self.eat("default"):
                self.eat(":")
                cur = []
                cases.append((None, cur))
            elif self.isop("}"):
                break
            else:
                st = self.safe_stmt()
                if st is not None and cur is not None:
                    cur.append(st)
        self.expect("}")
        return ("switch", line, subj, cases)

    def ruby_case(self) -> Any:
        line = self.next().line
        subj = self.expr()
        cases = []
        self.skip_sep()
        while self.eat("when"):
            v = self.expr()
            self.eat("then")
            cases.append((v, self.block()))
        if self.eat("else"):
            cases.append((None, self.block()))
        self.end_kw()
        return ("switch", line, subj, cases)

    # expressions
    def expr_list(self) -> Any:
        e = self.expr()
        if self.isop(",") and self.p.name in ("perl", "lua", "ruby") and not getattr(self, "_in_args", False):
            items = [e]
            while self.eat(","):
                if self.peek().k in ("nl", "eof") or self.isop(";", ")"):
                    break
                items.append(self.expr())
            if self.isop("=") and self.p.name in ("lua", "ruby"):
                self.next()
                rhs = self.expr_list()
                return ("massign", items, rhs)
            return ("list", items)
        return e

    def expr(self, minp: int = 0) -> Any:  # noqa: C901, PLR0912
        left = self.unary()
        while True:
            t = self.peek()
            op = t.v if t.k == "op" else (t.v if t.k == "id" and t.v in ("and", "or", "not", "x", "lt", "gt", "le",
                                                                         "ge", "eq", "ne", "mod", "xor") else None)
            if op is None:
                return left
            if self.p.name == "lua" and op == "~":
                op = "~"
            if op in _ASSIGN:
                if minp > 0:
                    return left
                self.next()
                right = self.expr()
                return ("assign", op, left, right)
            if op == "?" and minp <= 5:
                self.next()
                if self.isop(":"):
                    self.next()
                    b = self.expr(5)
                    left = ("elvis", left, b)
                    continue
                a = self.expr(5)
                self.expect(":")
                b = self.expr(5)
                left = ("cond", left, a, b)
                continue
            if op == "x" and self.p.name != "perl":
                return left
            if op in ("mod", "xor") and self.p.name not in ("lua", "ahk", "php"):
                return left
            if op in (".", ) and op not in self.p.concat:
                return left
            if op == "~" and self.p.name == "lua":
                prec = 9
            elif op in ("lt", "gt", "le", "ge", "eq", "ne") and self.p.name != "perl":
                return left
            else:
                prec = _BIN.get(op)
            if prec is None or prec < minp:
                return left
            if op == "not":
                return left
            self.next()
            if op in ("=~", "!~") and self.peek().k in ("subst", "regex"):
                r = self.next()
                left = ("match", op, left, r.v, r.k)
                continue
            right_min = prec if op in ("**", "..") else prec + 1
            right = self.expr(right_min)
            left = ("bin", op, left, right)

    def unary(self) -> Any:
        t = self.peek()
        if t.k == "op" and t.v in ("!", "-", "+", "~", "\\", "@", "&") or (t.k == "id" and t.v in ("not",)):
            self.next()
            if t.v == "@" and self.p.name == "php":
                return self.unary()
            if t.v == "\\":
                return self.unary()
            if t.v == "&" and self.p.name in ("php", "perl", "ruby"):
                return self.unary()
            return ("un", t.v, self.unary())
        if t.k == "op" and t.v in ("++", "--"):
            self.next()
            target = self.unary()
            return ("assign", "+=" if t.v == "++" else "-=", target, ("num", 1))
        if t.k == "op" and t.v == "#" and self.p.name == "lua":
            self.next()
            return ("len", self.unary())
        e = self.postfix(self.primary())
        if self.isop("++", "--") and self.p.name != "lua":
            op = self.next().v
            return ("postinc", "+=" if op == "++" else "-=", e)
        return e

    def args(self, close: str = ")") -> list:
        out = []
        saved = getattr(self, "_in_args", False)
        self._in_args = True
        try:
            while not self.isop(close) and self.peek().k != "eof":
                while self.peek().k == "nl":
                    self.next()
                if self.isop(close):
                    break
                if self.isop("...", "*", "**") and self.p.name in ("php", "ruby"):
                    self.next()
                e = self.expr()
                if self.isop("=>") or (self.p.name == "ruby" and self.isop(":") and e[0] == "name"):
                    self.next()
                    v = self.expr()
                    e = ("pair", e, v)
                out.append(e)
                while self.peek().k == "nl":
                    self.next()
                if not self.eat(","):
                    break
            self.expect(close)
        finally:
            self._in_args = saved
        return out

    def postfix(self, e: Any) -> Any:  # noqa: C901, PLR0912
        while True:
            t = self.peek()
            if t.k == "op" and t.v == "(":
                self.next()
                e = ("call", e, self.args(")"))
            elif t.k == "op" and t.v == "[":
                self.next()
                if self.isop("]"):
                    self.next()
                    e = ("push", e)
                    continue
                idx = self.expr_list()
                self.expect("]")
                e = ("index", e, idx)
            elif t.k == "op" and t.v == "{" and self.p.name == "perl" and e[0] in ("var", "index", "member"):
                self.next()
                if self.peek().k == "id" and self.isop("}", k=1):
                    key: Any = ("str", self.next().v)
                else:
                    key = self.expr()
                self.expect("}")
                e = ("index", e, key)
            elif t.k == "op" and t.v in self.p.member and (self.peek(1).k in ("id", "var") or self.isop("(", "[", "{", k=1)):
                self.next()
                if self.p.name in ("perl", "php") and self.isop("[", "{", "("):
                    continue
                nt = self.next()
                name: Any = nt.v if nt.k == "id" else ("dyn", nt)
                if self.p.name == "php" and nt.k == "var":
                    name = ("dyn", ("var", nt.v))
                if self.isop("("):
                    self.next()
                    args = self.args(")")
                    e = ("mcall", e, name, args, t.v)
                elif self.p.name == "ruby" and (self.isop("{") or self.isid("do")):
                    e = ("mcall", e, name, [], t.v)
                elif self.p.name == "ruby" and self._ruby_cmd_args():
                    e = ("mcall", e, name, self._ruby_noparen_args(), t.v)
                elif self.p.name == "lua" and self.peek().k == "str":
                    e = ("mcall", e, name, [("str", self.next().v)], t.v)
                elif t.v == ":" and self.p.name == "lua":
                    e = ("mcall", e, name, [], t.v)
                else:
                    e = ("member", e, name, t.v)
            elif t.k == "op" and t.v in ("{",) and self.p.name == "ruby" and e[0] in ("mcall", "name", "call"):
                # a block: x.each { |c| … }
                self.next()
                params = self._block_params()
                body = []
                while not self.isop("}") and self.peek().k != "eof":
                    self.skip_sep()
                    if self.isop("}"):
                        break
                    st = self.safe_stmt()
                    if st is not None:
                        body.append(st)
                self.expect("}")
                e = ("rblock", e, params, body)
            elif self.isid("do") and self.p.name == "ruby" and e[0] in ("mcall", "name", "call"):
                self.next()
                params = self._block_params()
                body = self.block()
                self.end_kw()
                e = ("rblock", e, params, body)
            elif t.k == "str" and self.p.name == "lua" and e[0] in ("name", "member"):
                self.next()
                e = ("call", e, [("strlit", t.v)])
            else:
                return e

    def _block_params(self) -> list:
        params = []
        if self.isop("|"):
            self.next()
            while not self.isop("|") and self.peek().k != "eof":
                tk = self.next()
                if tk.k == "id":
                    params.append(tk.v)
            self.expect("|")
        return params

    def _ruby_cmd_args(self) -> bool:
        t = self.peek()
        return t.k in ("str", "num", "var") or (t.k == "id" and t.v not in ("do", "end", "if", "unless", "then", "and",
                                                                          "or", "while", "until", "rescue"))

    def _ruby_noparen_args(self) -> list:
        args = [self.expr()]
        while self.eat(","):
            args.append(self.expr())
        return args

    def primary(self) -> Any:  # noqa: C901, PLR0911, PLR0912
        t = self.next()
        p = self.p.name
        if t.k == "num":
            return ("num", t.v)
        if t.k == "str":
            if t.v.startswith("\x00interp\x00"):
                return ("interp", t.v[len("\x00interp\x00"):], t.line)
            return ("str", t.v)
        if t.k == "cmd":
            return ("backtick", t.v[len("\x00interp\x00"):], t.line)
        if t.k == "qw":
            return ("array", [("str", x) for x in t.v])
        if t.k == "regex":
            return ("regex", t.v[0], t.v[1])
        if t.k == "subst":
            return ("subst_bare", t.v)
        if t.k == "var":
            sig, name = t.v
            if p == "php" and self.isop("("):
                return ("var", (sig, name))
            return ("var", (sig, name))
        if t.k == "op":
            if t.v == "(":
                if self.isop(")"):
                    self.next()
                    return ("array", [])
                saved = getattr(self, "_in_args", False)
                self._in_args = False
                try:
                    e = self.expr_list()
                finally:
                    self._in_args = saved
                self.expect(")")
                return ("paren", e)
            if t.v == "[":
                return ("array", self.args("]"))
            if t.v == "{" and p in ("lua", "perl", "ruby", "ahk", "php"):
                return self.table()
            if t.v == "$$" and p in ("php",):
                inner = self.primary()
                return ("varvar", inner)
            if t.v == "$" and p == "php" and self.isop("{"):
                self.next()
                e = self.expr()
                self.expect("}")
                return ("varvar", e)
            if t.v == "::" and p == "ruby":
                return self.primary()
            if t.v == "-" :
                return ("un", "-", self.unary())
        if t.k == "id":
            w = t.v
            wl = w.lower()
            if wl in ("true",):
                return ("const", True)
            if wl in ("false",):
                return ("const", False)
            if wl in ("null", "nil", "undef", "none"):
                return ("const", None)
            if wl in ("function", "func", "fn", "sub", "lambda", "proc") and (self.isop("(", "{") or p == "perl"):
                return self.anon_func(wl)
            if wl == "new" and p in ("php", "ahk"):
                cls = self.next()
                args = self.args(")") if self.eat("(") else []
                return ("new", cls.v if cls.k == "id" else "?", args)
            if wl in ("array", "list") and p == "php" and self.isop("("):
                self.next()
                return ("array", self.args(")"))
            if wl == "my" or wl == "our" or wl == "local":
                if self.isop("("):
                    self.next()
                    items = self.args(")")
                    return ("list", items)
                return self.primary()
            if p == "perl" and wl in ("print", "printf", "say") and (
                    (self.peek().k == "var" and self.peek(1).k in ("str", "var", "num", "id")) or
                    (self.peek().k == "id" and self.peek().v.isupper() and self.peek(1).k in ("str", "var", "num")) or
                    (self.isop("{") and self.peek(1).k == "var" and self.isop("}", k=2))):
                if self.isop("{"):
                    self.next()
                    fh = self.primary()
                    self.next()
                else:
                    fh = self.primary()
                return ("call", ("name", w), [fh] + self._perl_list())
            if p == "perl" and wl in _PERL_LISTOPS and not self.isop("(", "=>", ",") and not self.isop("->"):
                # a list operator without parentheses: print decode_base64 $x;
                if self.peek().k in ("nl", "eof") or self.isop(";", ")", "}") or self.isid("if", "unless", "or", "and"):
                    return ("call", ("name", w), [])
                if wl in ("map", "grep", "sort") and self.isop("{"):
                    blk = self.table_or_block()
                    self.eat(",")
                    rest = self._perl_list()
                    return ("call", ("name", w), [blk] + rest)
                return ("call", ("name", w), self._perl_list(single=wl in _PERL_UNARY))
            if p == "ruby" and self._ruby_cmd_args() and wl in _RUBY_CMDS:
                return ("call", ("name", w), self._ruby_noparen_args())
            if p == "lua" and self.peek().k == "str" and self.peek().line == t.line:
                return ("name", w)
            return ("name", w)
        raise SyntaxError(f"line {t.line}: unexpected {t}")

    def _perl_list(self, single: bool = False) -> list:
        if single:
            return [self.expr(13)]
        items = []
        saved = getattr(self, "_in_args", False)
        self._in_args = True
        try:
            while True:
                if self.peek().k in ("nl", "eof") or self.isop(";", ")", "}") or self.isid("if", "unless", "or", "and"):
                    break
                items.append(self.expr(3))
                if not self.eat(","):
                    break
        finally:
            self._in_args = saved
        return items

    def table_or_block(self) -> Any:
        self.expect("{")
        body = []
        while not self.isop("}") and self.peek().k != "eof":
            self.skip_sep()
            if self.isop("}"):
                break
            st = self.safe_stmt()
            if st is not None:
                body.append(st)
        self.expect("}")
        return ("perlblock", body)

    def table(self) -> Any:
        items: list = []
        saved = getattr(self, "_in_args", False)
        self._in_args = True
        try:
            while not self.isop("}") and self.peek().k != "eof":
                while self.peek().k == "nl":
                    self.next()
                if self.isop("}"):
                    break
                if self.isop("["):
                    self.next()
                    k = self.expr()
                    self.expect("]")
                    self.expect("=")
                    items.append(("pair", k, self.expr()))
                elif self.peek().k == "id" and self.isop("=", ":", k=1) and not self.isop("==", k=1):
                    k = ("str", self.next().v)
                    self.next()
                    items.append(("pair", k, self.expr()))
                else:
                    e = self.expr()
                    if self.eat("=>"):
                        e = ("pair", e, self.expr())
                    items.append(e)
                while self.peek().k == "nl":
                    self.next()
                if not (self.eat(",") or self.eat(";")):
                    break
            self.expect("}")
        finally:
            self._in_args = saved
        return ("table", items)

    def anon_func(self, kind: str) -> Any:
        params: list = []
        if self.isop("("):
            self.next()
            while not self.isop(")") and self.peek().k != "eof":
                t = self.next()
                if t.k == "var":
                    params.append((t.v[1], None))
                elif t.k == "id":
                    params.append((t.v, None))
                self.eat(",")
            self.expect(")")
        if self.isid("use"):
            self.next()
            self.paren_skip()
        if self.isop("=>"):
            self.next()
            return ("lambda", params, self.expr(), True)
        if self.p.name == "lua":
            body = self.block()
            self.end_kw()
            return ("lambda", params, body, False)
        body = self.block() if self.isop("{") else []
        if self.p.name == "ruby" and kind in ("lambda", "proc") and self.isop("{"):
            pass
        return ("lambda", params, body, False)


def _split_ahk_args(s: str) -> list[str]:
    out, buf, esc = [], [], False
    for ch in s:
        if esc:
            buf.append(ch)
            esc = False
            continue
        if ch == "`":
            esc = True
            buf.append(ch)
            continue
        if ch == ",":
            out.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    out.append("".join(buf))
    return out


_PERL_LISTOPS = {"print", "printf", "say", "eval", "system", "exec", "decode_base64", "encode_base64", "die", "warn",
                 "push", "unshift", "join", "split", "reverse", "map", "grep", "sort", "pack", "unpack", "chr", "ord",
                 "lc", "uc", "length", "open", "close", "unlink", "chomp", "chop", "return", "uncompress",
                 "memGunzip", "memgunzip", "sprintf", "keys", "values", "defined", "scalar", "hex", "oct", "getstore",
                 "get", "sleep", "chmod", "mkdir", "binmode", "substr", "index", "abs", "int", "fork", "wait"}
_PERL_UNARY = {"chr", "ord", "lc", "uc", "length", "defined", "scalar", "hex", "oct", "decode_base64", "encode_base64",
               "uncompress", "memGunzip", "memgunzip", "chomp", "chop", "keys", "values", "abs", "int", "sleep"}
_RUBY_CMDS = {"puts", "print", "eval", "system", "exec", "require", "p", "instance_eval", "class_eval", "load",
              "raise", "spawn", "sleep", "exit"}


# --- values -----------------------------------------------------------------------------------------
def s_(v: Any) -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else ""
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() and abs(v) < 1e15 else repr(v)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("latin-1")
    if isinstance(v, list):
        return "".join(s_(x) for x in v)
    if isinstance(v, dict):
        return "Array"
    if isinstance(v, Unk):
        return f"<{v.why}>"
    return str(v)


def n_(v: Any) -> int | float:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return v
    if v is None:
        return 0
    if isinstance(v, str):
        m = re.match(r"\s*([+-]?(?:0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+))", v)
        if not m:
            return 0
        t = m.group(1)
        if t.lower().lstrip("+-").startswith("0x"):
            return int(t, 16)
        return float(t) if re.search(r"[.eE]", t) else int(t)
    if isinstance(v, (list, dict)):
        return len(v)
    return 0


def truthy(v: Any) -> bool:
    if isinstance(v, Unk):
        return False
    if v is None or v is False:
        return False
    if isinstance(v, str):
        return v not in ("", "0")
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, (list, dict)):
        return bool(v)
    return True


def lat(b: bytes) -> str:
    return b.decode("latin-1")


def raw(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    s = s_(v)
    try:
        return s.encode("latin-1")
    except UnicodeEncodeError:
        return s.encode("utf-8")


def text(v: Any) -> str:
    """A byte string (Latin-1) as the text it encodes (UTF-8 when it is)."""
    b = raw(v)
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


class Scope:
    __slots__ = ("vars", "parent")

    def __init__(self, parent: "Scope | None" = None) -> None:
        self.vars: dict[str, Any] = {}
        self.parent = parent

    def find(self, k: str) -> "Scope | None":
        s: Scope | None = self
        while s is not None:
            if k in s.vars:
                return s
            s = s.parent
        return None


# --- the interpreter ----------------------------------------------------------------------------------
class Interp:  # noqa: PLR0904
    def __init__(self, sinks: Sinks, source: str, prof: type[Profile]) -> None:
        self.sinks = sinks
        self.source = source
        self.top = source
        self.p = prof
        self.g = Scope()
        self.funcs: dict[str, Func] = {}
        self.steps = 0
        self.t0 = time.monotonic()
        self.depth = 0
        self.call_depth = 0
        self.errors: list[str] = []
        self.ran: set[str] = set()
        self.tracked: dict[str, Any] = {}
        self.files: dict[int, Obj] = {}
        self.lib = _library(self)

    # -- running ---------------------------------------------------------------------------------
    def parse(self, code: str) -> list:
        return Parser(tokenize(code, self.p), self.p).program()

    def run(self, code: str) -> None:
        try:
            prog = self.parse(code)
        except (SyntaxError, RecursionError, IndexError) as exc:
            self.errors.append(f"not parsed: {exc}"[:300])
            return
        try:
            self.hoist(prog)
            self.block(prog, self.g, top=True)
        except (Limit, _Die, _Return, _Break, _Next):
            pass
        for h in list(self.files.values()):
            self.flush(h)
        self.computed_values()

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise Limit("steps")
        if not self.steps & 0x3FFF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise Limit("time")

    def hoist(self, stmts: list) -> None:
        for st in stmts:
            if st and st[0] == "func":
                _, _line, name, params, body = st
                self.funcs[self.fkey(name)] = Func(name, params, body, self.source)
            elif st and st[0] == "block":
                self.hoist(st[2])

    def fkey(self, name: str) -> str:
        return name.lower() if self.p.case_insensitive_funcs else name

    def line_text(self, line: int | None) -> str:
        lines = self.source.splitlines()
        return lines[line - 1].strip()[:200] if line and 0 < line <= len(lines) else ""

    # -- statements ---------------------------------------------------------------------------------
    def block(self, stmts: list, sc: Scope, top: bool = False) -> None:
        for st in stmts:
            if st is None:
                continue
            try:
                self.stmt(st, sc)
            except (Limit, _Die, _Return, _Break, _Next, RecursionError):
                raise
            except Exception as exc:  # noqa: BLE001
                if top:
                    self.errors.append(f"line {st[1]}: {type(exc).__name__}: {exc}"[:300])
                    continue
                raise

    def stmt(self, st: tuple, sc: Scope) -> None:  # noqa: C901, PLR0912
        self.tick()
        k = st[0]
        line = st[1]
        self.cur_line = line
        if k == "expr":
            self.eval(st[2], sc)
        elif k == "if":
            for c, body in st[2]:
                v = self.eval(c, sc)
                if isinstance(v, Unk):
                    for b in [body] + ([st[3]] if st[3] else []):
                        try:
                            self.block(b, sc)
                        except _Die:
                            self.sinks.step(line, "exits only when a machine check fails (followed on)",
                                            Value("str", self.line_text(line)))
                        except (Limit, _Return, _Break, _Next):
                            raise
                        except Exception:  # noqa: BLE001
                            pass
                    return
                if truthy(v):
                    self.block(body, sc)
                    return
            if st[3]:
                self.block(st[3], sc)
        elif k == "while":
            self.loop(lambda: self.eval(st[2], sc), st[3], sc, line)
        elif k == "dowhile":
            self.loop(lambda: self.eval(st[3], sc), st[2], sc, line, first=True)
        elif k == "cfor":
            _, _, init, cond, stp, body = st
            if init is not None:
                self.eval(init, sc)
            self.loop(lambda: True if cond is None else self.eval(cond, sc), body, sc, line,
                      after=(lambda: self.eval(stp, sc)) if stp is not None else None)
        elif k == "numfor":
            _, _, name, a, b, s, body = st
            i, hi, stp = n_(self.eval(a, sc)), n_(self.eval(b, sc)), n_(self.eval(s, sc))
            if stp == 0:
                return
            sub = Scope(sc)
            box = {"i": i}

            def cond() -> bool:
                return box["i"] <= hi if stp > 0 else box["i"] >= hi

            def before() -> None:
                sub.vars[name] = box["i"]

            def after() -> None:
                box["i"] = box["i"] + stp
            self.loop(cond, body, sub, line, after=after, before=before)
        elif k == "foreach":
            _, _, var, key, seq, body = st
            coll = self.eval(seq, sc)
            if isinstance(coll, Unk):
                return
            items = self.items(coll)
            tg = self.loop_targets(body)
            before = [(t, op, rec(self.lookup(src, sc))) for t, src, op in tg]
            n = 0
            try:
                for kk, vv in items:
                    n += 1
                    if n > MAX_LOOP:
                        break
                    if key is not None:
                        self.assign(key, kk, sc)
                    self.assign(var, vv, sc)
                    try:
                        self.block(body, sc)
                    except _Next:
                        continue
            except _Break:
                pass
            self.loop_after(before, sc)
        elif k == "ahkloop":
            cnt = self.eval(st[2], sc) if st[2] is not None else 3
            total = int(n_(cnt)) if not isinstance(cnt, Unk) else 3
            box = {"i": 0}

            def c2() -> bool:
                box["i"] += 1
                sc.vars["a_index"] = box["i"]
                return box["i"] <= total
            self.loop(c2, st[3], sc, line)
        elif k == "block":
            self.block(st[2], sc)
        elif k == "func":
            _, _, name, params, body = st
            self.funcs[self.fkey(name)] = Func(name, params, body, self.source)
        elif k == "return":
            raise _Return(self.eval(st[2], sc) if st[2] is not None else None)
        elif k == "break":
            raise _Break()
        elif k == "continue":
            raise _Next()
        elif k == "die":
            raise _Die()
        elif k == "switch":
            subj = self.eval(st[2], sc)
            hit = False
            try:
                for v, body in st[3]:
                    if not hit:
                        if v is None:
                            hit = True
                        else:
                            cv = self.eval(v, sc)
                            hit = s_(cv) == s_(subj) if not isinstance(cv, Unk) else False
                    if hit:
                        self.block(body, sc)
                        if self.p.name == "ruby":
                            break
            except _Break:
                pass
        elif k == "error":
            self.errors.append(f"line {line}: not parsed: {st[2]}"[:300])

    def loop(self, cond: Callable[[], Any], body: list, sc: Scope, line: int | None,
             after: Callable[[], Any] | None = None, first: bool = False,
             before: Callable[[], Any] | None = None) -> None:
        tg = self.loop_targets(body)
        pre = [(t, self.resolve_label(op, sc), rec(self.lookup(src, sc))) for t, src, op in tg]
        n = 0
        cap = MAX_LOOP
        try:
            while n < cap:
                n += 1
                if not (first and n == 1):
                    c = cond()
                    if isinstance(c, Unk):
                        if n > 3:
                            break
                    elif not truthy(c):
                        break
                if before:
                    before()
                try:
                    self.block(body, sc)
                except _Next:
                    pass
                if after:
                    after()
        except _Break:
            pass
        self.loop_after(pre, sc)

    # the operation a loop applies, named in the recipe of what it builds
    def loop_targets(self, body: Any) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []

        def vname(e: Any) -> str | None:
            if isinstance(e, tuple) and e:
                if e[0] == "var":
                    return e[1][1]
                if e[0] == "name":
                    return e[1]
            return None

        def srcs(e: Any, tgt: str) -> str:
            found = ""

            def w(x: Any) -> None:
                nonlocal found
                if found:
                    return
                if isinstance(x, tuple) and x:
                    if x[0] == "index":
                        nm = vname(x[1])
                        if nm and nm != tgt:
                            found = nm
                            return
                    if x[0] in ("call", "mcall"):
                        fn = x[1]
                        name = fn[1] if fn[0] == "name" else (x[2] if x[0] == "mcall" and isinstance(x[2], str) else "")
                        if str(name).lower() in ("substr", "sub", "byte", "ord", "charat", "chr", "mid", "substring"):
                            target = x[1] if x[0] == "mcall" else (x[2][0] if x[2] else None)
                            nm = vname(target) if target is not None else None
                            if nm and nm != tgt:
                                found = nm
                                return
                    for y in x[1:]:
                        w(y)
                elif isinstance(x, list):
                    for y in x:
                        w(y)
            w(e)
            return found

        def visit(x: Any) -> None:
            if isinstance(x, list):
                for y in x:
                    visit(y)
                return
            if not isinstance(x, tuple) or not x:
                return
            if x[0] == "assign":
                op, lhs, rhs = x[1], x[2], x[3]
                t = vname(lhs)
                if t and op in (".=", "..=", "+="):
                    s = srcs(rhs, t)
                    if s:
                        out.append((t, s, self.op_label(rhs, s)))
                elif t and op == "=" and isinstance(rhs, tuple) and rhs[0] == "bin" and rhs[1] in (".", "..", "+") \
                        and vname(rhs[2]) == t:
                    s = srcs(rhs[3], t)
                    if s:
                        out.append((t, s, self.op_label(rhs[3], s)))
                elif lhs[0] == "index" and vname(lhs[1]):
                    a = vname(lhs[1])
                    if op in ("^=", "-=", "+="):
                        out.append((a, a, self.op_label(rhs, a, op[0])))
                    else:
                        s = srcs(rhs, "")
                        if s:
                            out.append((a, s, self.op_label(rhs, s)))
            for y in x[1:]:
                if isinstance(y, (list, tuple)):
                    visit(y)
        visit(body)
        return out

    def op_label(self, e: Any, src: str, op: str = "") -> str:
        ops: list[tuple] = []

        def w(x: Any) -> None:
            if isinstance(x, tuple) and x:
                if x[0] == "bin" and x[1] in ("^", "~", "-", "+", "xor"):
                    ops.append(x)
                if x[0] in ("call", "mcall"):
                    fn = x[1]
                    nm = fn[1] if fn[0] == "name" else ""
                    if str(nm).lower() in ("bxor", "bitxor", "bit32.bxor") or (fn[0] == "member" and fn[2] == "bxor"):
                        ops.append(("bin", "^", x[2][0] if x[2] else None, x[2][1] if len(x[2]) > 1 else None))
                for y in x[1:]:
                    w(y)
            elif isinstance(x, list):
                for y in x:
                    w(y)
        if op:
            ops.append(("bin", op, None, e))
        w(e)

        def has_src(x: Any) -> bool:
            if isinstance(x, tuple) and x:
                if x[0] == "var" and x[1][1] == src or x[0] == "name" and x[1] == src:
                    return True
                return any(has_src(y) for y in x[1:])
            if isinstance(x, list):
                return any(has_src(y) for y in x)
            return False

        def names(x: Any) -> list[str]:
            out: list[str] = []

            def nw(y: Any) -> None:
                if isinstance(y, tuple) and y:
                    if y[0] == "var":
                        out.append(y[1][1])
                    elif y[0] == "name" and y[1].lower() not in ("strlen", "length", "len", "ord", "chr", "substr",
                                                                 "i", "j", "string", "byte", "sub"):
                        out.append(y[1])
                    for z in y[1:]:
                        nw(z)
                elif isinstance(y, list):
                    for z in y:
                        nw(z)
            nw(x)
            return [n for n in out if n not in (src, "i", "j", "k_", "idx")]
        for want, lab in (("^", "xor"), ("~", "xor"), ("xor", "xor"), ("-", "sub"), ("+", "add")):
            for x in ops:
                if x[1] != want:
                    continue
                if x[2] is not None and not has_src(x):
                    continue
                for side in (x[3], x[2]):
                    if side is None or has_src(side):
                        continue
                    if side[0] == "num":
                        return f"{lab}(0x{int(side[1]):x})" if lab == "xor" else f"{lab}({int(side[1])})"
                    if lab != "xor" and side[0] in ("name", "var"):
                        return f"{lab}({side[1] if side[0] == 'name' else side[1][1]})"
                    if lab == "xor":
                        nm = names(side)
                        return f"xor(key {nm[0]})" if nm else "xor(…)"
        return "char codes"

    def resolve_label(self, lab: str, sc: Scope | None) -> str:
        """``sub(k)`` → ``sub(7)`` when ``k`` holds a number."""
        m = re.fullmatch(r"(sub|add)\((\w+)\)", lab or "")
        if m and not m.group(2).isdigit() and sc is not None:
            v = self.lookup(m.group(2), sc)
            if isinstance(v, int) and not isinstance(v, bool):
                return f"{m.group(1)}({v})"
        return lab

    def loop_after(self, pre: list, sc: Scope) -> None:
        done = set()
        for tgt, op, r in pre:
            if tgt in done:
                continue
            v = self.lookup(tgt, sc)
            if isinstance(v, (str, list)) and len(v) >= 16:
                done.add(tgt)
                nv = tag(v, r + (op,)) if isinstance(v, str) else v
                if isinstance(v, list):
                    try:
                        v.recipe = r + (op,)
                    except AttributeError:
                        pass
                s = sc.find(tgt) or self.g
                s.vars[tgt] = nv
                self.sinks.step(None, f"{tgt} = loop {op}", self.to_value(nv))

    # -- names ----------------------------------------------------------------------------------------
    def lookup(self, name: str, sc: Scope) -> Any:
        s = sc.find(name)
        if s is not None:
            return s.vars[name]
        if name in self.g.vars:
            return self.g.vars[name]
        return None

    def set_name(self, name: str, v: Any, sc: Scope, local: bool = False) -> None:
        v = self.label(name, v)
        if local:
            sc.vars[name] = v
            return
        s = sc.find(name)
        (s or sc).vars[name] = v

    def label(self, name: str, v: Any) -> Any:
        if isinstance(v, str) and not rec(v) and len(v) >= 16:
            v = tag(v, (f"literal {name}",))
        elif isinstance(v, list) and not rec(v) and len(v) >= 16 and all(isinstance(x, (int, float)) for x in v[:32]):
            v = RList(v)
            v.recipe = (f"number array {name}",)
        elif isinstance(v, str) and rec(v) and len(v) >= 16 and not rec(v)[-1].startswith(("literal", "number array")):
            self.sinks.step(getattr(self, "cur_line", None), f"{name} =", self.to_value(v))
        if isinstance(v, (str, list)) and len(v) >= 40:
            self.tracked[name] = v
        return v

    def var_key(self, e: tuple, sc: Scope) -> str | None:
        if e[0] == "var":
            sig, nm = e[1]
            return ("@" if sig == "@" and self.p.name == "perl" else "%" if sig == "%" and self.p.name == "perl" else "") + nm
        if e[0] == "name":
            return e[1].lower() if self.p.name == "ahk" else e[1]
        if e[0] == "varvar":
            v = self.eval(e[1], sc)
            return s_(v) if not isinstance(v, Unk) else None
        return None

    def assign(self, target: tuple, v: Any, sc: Scope, op: str = "=") -> None:  # noqa: C901
        k = target[0]
        if k in ("var", "name", "varvar"):
            key = self.var_key(target, sc)
            if key is None:
                return
            if k == "var" and target[1][0] == "@" and self.p.name == "perl" and not isinstance(v, list):
                v = RList([v]) if v is not None else RList()
            self.set_name(key, v, sc)
        elif k == "index":
            base = self.eval(target[1], sc)
            if base is None:
                base = {} if self.p.name in ("php", "lua", "ahk") else RList()
                self.assign(target[1], base, sc)
            idx = self.eval(target[2], sc)
            if isinstance(idx, Unk):
                return
            self.set_index(base, idx, v)
        elif k == "push":
            base = self.eval(target[1], sc)
            if base is None:
                base = RList()
                self.assign(target[1], base, sc)
            if isinstance(base, list):
                base.append(v)
            elif isinstance(base, dict):
                base[len(base)] = v
        elif k == "member":
            obj = self.eval(target[1], sc)
            if isinstance(obj, dict):
                obj[target[2] if isinstance(target[2], str) else "?"] = v
            elif isinstance(obj, Obj):
                obj.st[str(target[2]).lower()] = v
        elif k in ("list", "array", "paren"):
            items = target[1] if k != "paren" else ([target[1]] if target[1][0] != "list" else target[1][1])
            vals = list(v) if isinstance(v, list) else (list(v.values()) if isinstance(v, dict) else [v])
            for i, t in enumerate(items):
                self.assign(t, vals[i] if i < len(vals) else None, sc)

    def set_index(self, base: Any, idx: Any, v: Any) -> None:
        if isinstance(base, list):
            i = int(n_(idx))
            if self.p.name == "lua":
                i -= 1
            if i < 0:
                i += len(base)
            if 0 <= i < MAX_LOOP:
                while len(base) <= i:
                    base.append(None)
                base[i] = v
        elif isinstance(base, dict):
            base[self.dkey(idx)] = v

    def dkey(self, k: Any) -> Any:
        if isinstance(k, float) and k.is_integer():
            return int(k)
        if isinstance(k, str) and re.fullmatch(r"-?\d+", k) and self.p.name == "php":
            return int(k)
        return k

    # -- expressions -------------------------------------------------------------------------------------
    def eval(self, e: Any, sc: Scope) -> Any:  # noqa: C901, PLR0911, PLR0912
        self.tick()
        k = e[0]
        if k == "num":
            return e[1]
        if k in ("str", "strlit"):
            return e[1]
        if k == "ahkarg":
            s = e[1]
            if s.startswith("% "):
                try:
                    return self.eval(Parser(tokenize(s[2:], self.p), self.p).expr(), sc)
                except Exception:  # noqa: BLE001
                    return s[2:]
            parts = re.split(r"%([A-Za-z_]\w*)%", s)
            if len(parts) == 1:
                return _unescape(s, ahk=True)
            out = []
            r: tuple = ()
            for i_, part in enumerate(parts):
                if i_ % 2:
                    v = self.lookup(part.lower(), sc)
                    if isinstance(v, Unk):
                        return v
                    r = r or rec(v)
                    out.append(s_(v))
                else:
                    out.append(_unescape(part, ahk=True))
            res = "".join(out)
            return tag(res, r) if r and len(res) >= 16 else res
        if k == "const":
            return e[1]
        if k == "interp":
            return self.interp(e[1], sc)
        if k == "var":
            key = self.var_key(e, sc)
            v = self.lookup(key, sc)
            if v is None and self.p.name == "php" and key in ("_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_FILES"):
                return Unk(f"the web request (${key})")
            if v is None and self.p.name == "perl" and e[1][0] == "$" and e[1][1] in ("_",):
                return self.lookup("_", sc)
            if v is None and e[1][0] == "$#":
                arr = self.lookup("@" + e[1][1], sc)
                return len(arr) - 1 if isinstance(arr, list) else -1
            return v
        if k == "varvar":
            key = self.var_key(e, sc)
            return self.lookup(key, sc) if key else Unk("a variable named at run time")
        if k == "name":
            nm = e[1]
            key = nm.lower() if self.p.name == "ahk" else nm
            s = sc.find(key)
            if s is not None:
                return s.vars[key]
            if key in self.g.vars:
                return self.g.vars[key]
            f = self.funcs.get(self.fkey(nm))
            if f is not None:
                if self.p.name in ("perl", "ruby"):
                    return self.call_func(f, [], sc)
                return f
            lib = self.lib_get(nm)
            if lib is not None:
                if self.p.name in ("perl", "ruby") and isinstance(lib, Native):
                    return lib.fn([], e, sc)
                return lib
            if self.p.name == "php":
                return nm                       # a bare word: a constant / function name as text
            return None
        if k == "paren":
            return self.eval(e[1], sc)
        if k == "list":
            vals = [self.eval(x, sc) for x in e[1]]
            return RList(vals)
        if k == "array":
            out_l: list = []
            out_d: dict = {}
            is_d = False
            for x in e[1]:
                if x[0] == "pair":
                    is_d = True
                    out_d[self.dkey(self.eval(x[1], sc))] = self.eval(x[2], sc)
                else:
                    v = self.eval(x, sc)
                    if self.p.name == "perl" and isinstance(v, list):
                        out_l.extend(v)
                    else:
                        out_l.append(v)
                    out_d[len(out_d)] = v
            return out_d if is_d else RList(out_l)
        if k == "table":
            d: dict = {}
            n = 1 if self.p.name == "lua" else 0
            seq = True
            for x in e[1]:
                if x[0] == "pair":
                    seq = False
                    kv = self.eval(x[1], sc)
                    d[self.dkey(kv) if not isinstance(kv, Unk) else "?"] = self.eval(x[2], sc)
                else:
                    d[n] = self.eval(x, sc)
                    n += 1
            if seq and self.p.name in ("lua", "perl") and d:
                lst = RList(d.values())
                return lst if self.p.name == "lua" else d
            return d
        if k == "assign":
            return self.eval_assign(e, sc)
        if k == "postinc":
            old = self.eval(e[2], sc)
            self.assign(e[2], (n_(old) + (1 if e[1] == "+=" else -1)), sc)
            return old
        if k == "massign":
            vals = self.eval(e[2], sc)
            vs = list(vals) if isinstance(vals, list) else [vals]
            for i, t in enumerate(e[1]):
                self.assign(t, vs[i] if i < len(vs) else None, sc)
            return vals
        if k == "bin":
            return self.binop(e[1], e[2], e[3], sc)
        if k == "un":
            v = self.eval(e[2], sc)
            if isinstance(v, Unk):
                return v
            op = e[1]
            if op in ("!", "not"):
                return not truthy(v)
            if op == "-":
                return -n_(v)
            if op == "+":
                return n_(v)
            if op == "~":
                return ~int(n_(v))
            return v
        if k == "len":
            v = self.eval(e[1], sc)
            return len(v) if isinstance(v, (str, list, dict)) else 0
        if k == "cond":
            c = self.eval(e[1], sc)
            return self.eval(e[2] if truthy(c) else e[3], sc)
        if k == "elvis":
            a = self.eval(e[1], sc)
            return a if truthy(a) else self.eval(e[2], sc)
        if k == "index":
            base = self.eval(e[1], sc)
            idx = self.eval(e[2], sc)
            return self.index(base, idx)
        if k == "member":
            obj = self.eval(e[1], sc)
            name = e[2] if isinstance(e[2], str) else None
            return self.member(obj, name, e, sc)
        if k == "call":
            return self.call(e, sc)
        if k == "mcall":
            return self.mcall(e, sc)
        if k == "rblock":
            return self.rblock(e, sc)
        if k == "lambda":
            params, body, is_expr = e[1], e[2], e[3]
            return Func("anonymous", params, body, self.source, expr=is_expr, closure=sc)
        if k == "perlblock":
            return Func("block", [], e[1], self.source, closure=sc)
        if k == "backtick":
            cmd = self.interp(e[1], sc)
            self.launch(cmd, "backticks", e[2])
            return Unk("the output of a command")
        if k == "match":
            return self.perl_match(e, sc)
        if k == "regex":
            return ("re", e[1], e[2])
        if k == "subst_bare":
            return self.perl_match(("match", "=~", ("var", ("$", "_")), e[1], "subst"), sc)
        if k == "new":
            return self.new(e[1], [self.eval(a, sc) for a in e[2]], sc)
        if k == "push":
            return self.eval(e[1], sc)
        if k == "pair":
            return self.eval(e[2], sc)
        if k == "error":
            return None
        raise TypeError(f"{k} not followed")

    def eval_assign(self, e: tuple, sc: Scope) -> Any:
        op, lhs, rhs = e[1], e[2], e[3]
        if op in ("=", ":="):
            v = self.eval(rhs, sc)
            if lhs[0] == "var" and lhs[1][0] == "@" and self.p.name == "perl" and isinstance(v, list):
                v = RList(v)
            if self.p.name == "lua" and lhs[0] == "name" and isinstance(v, list) and lhs[1]:
                pass
            self.assign(lhs, v, sc)
            return v
        cur = self.eval(lhs, sc)
        if op in ("||=", "//=", "??="):
            if truthy(cur) if op == "||=" else cur is not None:
                return cur
            v = self.eval(rhs, sc)
        elif op == "&&=":
            if not truthy(cur):
                return cur
            v = self.eval(rhs, sc)
        else:
            bop = {".=": ".", "..=": "..", "+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%", "^=": "^",
                   "|=": "|", "&=": "&", "<<=": "<<", ">>=": ">>", "**=": "**"}[op]
            r = self.eval(rhs, sc)
            if bop == "+" and self.p.name == "ruby" and isinstance(cur, str):
                bop = "."
            if bop == "+" and self.p.name == "ruby" and isinstance(cur, list):
                v = RList(cur + (list(r) if isinstance(r, list) else [r]))
                self.assign(lhs, v, sc)
                return v
            v = self.value_bin(bop, cur, r)
        self.assign(lhs, v, sc)
        return v

    def interp(self, s: str, sc: Scope) -> str:
        """``"…"`` with escapes and variables (``$x``, ``{$x}``, ``${x}``, ``#{expr}``, ``@{[…]}``)."""
        p = self.p.name
        out: list[str] = []
        r: tuple = ()
        i = 0
        n = len(s)
        buf: list[str] = []

        def flush() -> None:
            if buf:
                out.append(_unescape("".join(buf)))
                buf.clear()
        while i < n:
            c = s[i]
            if c == "\\" and i + 1 < n:
                buf.append(s[i:i + 2])
                i += 2
                continue
            if p == "ruby" and s.startswith("#{", i):
                j, body = _delimited(s, i + 2, "{", "}")
                if j is not None:
                    flush()
                    try:
                        v = self.eval(Parser(tokenize(body, self.p), self.p).expr_list(), sc)
                    except Exception:  # noqa: BLE001
                        v = ""
                    r = r or rec(v)
                    out.append(s_(v))
                    i = j
                    continue
            if p in ("php", "perl") and c in "$@" and i + 1 < n:
                m = (re.match(r"\{\$([A-Za-z_]\w*)((?:\[[^\]]*\]|->\w+)*)\}", s[i + 1:]) if c == "$" and p == "php" and s[i + 1] == "{"
                     else None)
                if s[i:i + 2] == "{$" and p == "php":
                    m = None
                m2 = re.match(r"\$\{?([A-Za-z_]\w*)\}?((?:\[[^\]]+\])?)" if c == "$" else r"@\{?([A-Za-z_]\w*)\}?", s[i:])
                if m2:
                    flush()
                    nm = m2.group(1)
                    key = ("@" + nm) if c == "@" else nm
                    v = self.lookup(key, sc)
                    if m2.lastindex and m2.lastindex >= 2 and m2.group(2):
                        try:
                            idx = m2.group(2)[1:-1].strip("'\"")
                            v = self.index(v, int(idx) if idx.isdigit() else self.lookup(idx.lstrip("$"), sc) if idx.startswith("$") else idx)
                        except Exception:  # noqa: BLE001
                            pass
                    if isinstance(v, list) and c == "@":
                        v = " ".join(s_(x) for x in v)
                    r = r or rec(v)
                    out.append(s_(v) if v is not None else "")
                    i += m2.end()
                    continue
            if p == "php" and s.startswith("{$", i):
                j, body = _delimited(s, i + 1, "{", "}")
                if j is not None:
                    flush()
                    try:
                        v = self.eval(Parser(tokenize("<?php " + body[:-1] + ";" if False else "<?php " + body + ";", self.p), self.p).expr(), sc)
                    except Exception:  # noqa: BLE001
                        v = ""
                    out.append(s_(v))
                    i = j
                    continue
            buf.append(c)
            i += 1
        flush()
        res = "".join(out)
        return tag(res, r) if r and len(res) >= 16 else res

    def binop(self, op: str, a: Any, b: Any, sc: Scope) -> Any:
        if op in ("&&", "and"):
            x = self.eval(a, sc)
            return self.eval(b, sc) if truthy(x) else x
        if op in ("||", "or"):
            x = self.eval(a, sc)
            return x if truthy(x) else self.eval(b, sc)
        if op == "//":
            if self.p.name == "perl":
                x = self.eval(a, sc)
                return x if x is not None else self.eval(b, sc)
        if op == "??":
            x = self.eval(a, sc)
            return x if x is not None else self.eval(b, sc)
        return self.value_bin(op, self.eval(a, sc), self.eval(b, sc))

    def value_bin(self, op: str, a: Any, b: Any) -> Any:  # noqa: C901, PLR0911, PLR0912
        if isinstance(a, Unk) or isinstance(b, Unk):
            u = a if isinstance(a, Unk) else b
            return Unk(u.why, u.recipe)
        p = self.p.name
        if op in (".", "..") and (p != "lua" or op == ".."):
            if op == ".." and p == "ruby":
                return RList(range(int(n_(a)), int(n_(b)) + 1))
            sa, sb = s_(a), s_(b)
            if len(sa) + len(sb) > MAX_STR:
                raise Limit("string size")
            out = sa + sb
            ra, rb = rec(a), rec(b)
            r = ra if (ra and (len(sa) >= len(sb) or not rb)) else rb
            return tag(out, r) if r else out
        if op == "..." and p == "ruby":
            return RList(range(int(n_(a)), int(n_(b))))
        if op == "+" and (p == "ruby" and (isinstance(a, str) or isinstance(a, list))):
            if isinstance(a, list):
                return RList(list(a) + (list(b) if isinstance(b, list) else [b]))
            return self.value_bin(".", a, b)
        if op == "x" and p == "perl":
            if isinstance(a, list):
                return RList(list(a) * int(n_(b)))
            return s_(a) * min(int(n_(b)), MAX_STR // max(1, len(s_(a))))
        if op == "*" and p == "ruby" and isinstance(a, str):
            return a * int(n_(b))
        if op in ("==", "!=", "===", "!==", "<>", "~=", "eq", "ne", "<", ">", "<=", ">=", "lt", "gt", "le", "ge", "<=>"):
            if op in ("eq", "ne", "lt", "gt", "le", "ge") or (isinstance(a, str) and isinstance(b, str) and
                                                               not (p in ("php", "perl", "ahk") and _numeric(a) and _numeric(b))):
                x, y = s_(a), s_(b)
            else:
                x, y = n_(a), n_(b)
            if op in ("===", "!==") and type(a) is not type(b) and not (isinstance(a, str) and isinstance(b, str)):
                return op == "!=="
            return {"==": x == y, "===": x == y, "eq": x == y, "!=": x != y, "!==": x != y, "<>": x != y,
                    "~=": x != y, "ne": x != y, "<": x < y, "lt": x < y, ">": x > y, "gt": x > y, "<=": x <= y,
                    "le": x <= y, ">=": x >= y, "ge": x >= y, "<=>": (x > y) - (x < y)}[op]
        x, y = n_(a), n_(b)
        if op == "+":
            return _norm(x + y)
        if op == "-":
            return _norm(x - y)
        if op == "*":
            return _norm(x * y)
        if op == "/":
            if y == 0:
                return Unk("a division by zero")
            if p == "ruby" and isinstance(x, int) and isinstance(y, int):
                return x // y
            if p == "lua" and op == "//":
                return x // y
            return _norm(x / y)
        if op in ("%", "mod"):
            if y == 0:
                return 0
            if p in ("php", "ahk") or (p == "perl"):
                xi, yi = int(x), int(y)
                r = abs(xi) % abs(yi)
                return r if xi >= 0 else -r
            return _norm(x % y)
        if op == "**":
            try:
                return _norm(x ** y)
            except (OverflowError, ZeroDivisionError):
                return 0
        if op == "^" and p == "lua":
            try:
                return _norm(float(x) ** y)
            except (OverflowError, ZeroDivisionError):
                return 0
        if op in ("^", "~", "xor"):
            if p == "php" and isinstance(a, str) and isinstance(b, str):
                ba, bb = raw(a), raw(b)
                out = bytes(p1 ^ p2 for p1, p2 in zip(ba, bb))
                return lat(out)
            if p == "perl" and isinstance(a, str) and isinstance(b, str) and not (_numeric(a) and _numeric(b)):
                ba, bb = raw(a), raw(b)
                return lat(bytes(p1 ^ p2 for p1, p2 in zip(ba, bb)))
            return int(x) ^ int(y)
        if op == "&":
            return int(x) & int(y)
        if op == "|":
            return int(x) | int(y)
        if op == "<<":
            if p == "ruby" and isinstance(a, (str, list)):
                if isinstance(a, list):
                    a.append(b)
                    return a
                return self.value_bin(".", a, b)
            return int(x) << (int(y) & 63)
        if op == ">>":
            return int(x) >> (int(y) & 63)
        raise TypeError(op)

    def items(self, coll: Any) -> list[tuple[Any, Any]]:
        if isinstance(coll, dict):
            return list(coll.items())
        if isinstance(coll, list):
            base = 1 if self.p.name == "lua" else 0
            return [(i + base, v) for i, v in enumerate(coll)]
        if isinstance(coll, str):
            return [(i, c) for i, c in enumerate(coll)]
        if isinstance(coll, Func):
            # a Lua iterator (string.gmatch, pairs over a generator): its values
            out = []
            for _ in range(MAX_LOOP):
                v = self.call_func(coll, [], None)
                if v is None or (isinstance(v, list) and (not v or v[0] is None)):
                    break
                out.append((v[0], v[1]) if isinstance(v, list) and len(v) > 1 else (v, v))
            return out
        return []

    def index(self, base: Any, idx: Any) -> Any:
        if isinstance(base, Unk):
            return base
        if isinstance(idx, Unk):
            return idx
        if isinstance(base, str):
            if isinstance(idx, list) and self.p.name == "ruby":
                return base[int(n_(idx[0])):int(n_(idx[0])) + int(n_(idx[1]))] if len(idx) > 1 else None
            i = int(n_(idx))
            if self.p.name == "lua":
                return None
            if -len(base) <= i < len(base):
                return base[i]
            return None
        if isinstance(base, list):
            if isinstance(idx, list) and self.p.name == "ruby" and len(idx) == 2:
                a = int(n_(idx[0]))
                return RList(base[a:a + int(n_(idx[1]))])
            i = int(n_(idx))
            if self.p.name == "lua":
                i -= 1
            if -len(base) <= i < len(base):
                return base[i]
            return None
        if isinstance(base, dict):
            return base.get(self.dkey(idx))
        if isinstance(base, Obj):
            return base.st.get(s_(idx).lower())
        return None

    def member(self, obj: Any, name: str | None, e: tuple, sc: Scope) -> Any:
        if isinstance(obj, Unk):
            return obj
        if name is None:
            return Unk("a member named at run time")
        if isinstance(obj, dict):
            if name in obj:
                return obj[name]
        if isinstance(obj, Obj):
            got = obj.st.get(name.lower())
            if got is not None:
                return got
            return self.obj_member(obj, name, [], e, sc)
        if self.p.name in ("ruby", "lua", "ahk") and isinstance(obj, (str, list, dict, int, float)):
            return self.method(obj, name, [], e, sc)
        # a module path: Lua string.char, Ruby Base64.decode64, Perl MIME::Base64::decode
        if e[1][0] in ("name", "member"):
            path = self.path_of(e)
            lib = self.lib_get(path)
            if lib is not None:
                if self.p.name == "ruby" and isinstance(lib, Native):
                    return lib.fn([], e, sc)
                return lib
            return Obj("module", path=path)
        return None

    def path_of(self, e: tuple) -> str:
        if e[0] == "name":
            return e[1]
        if e[0] == "member":
            return self.path_of(e[1]) + "." + (e[2] if isinstance(e[2], str) else "?")
        if e[0] == "mcall":
            return self.path_of(e[1]) + "." + (e[2] if isinstance(e[2], str) else "?")
        return "?"

    def lib_get(self, name: str) -> Any:
        key = name.replace("::", ".").replace("->", ".")
        if self.p.case_insensitive_funcs:
            key = key.lower()
        return self.lib.get(key) or self.lib.get(key.rsplit(".", 1)[-1] if self.p.name in ("perl",) else "\x00")

    # -- calls ------------------------------------------------------------------------------------------------
    def callee_name(self, fn: Any) -> str:
        if fn[0] == "name":
            return fn[1]
        if fn[0] in ("member", "mcall"):
            return self.path_of(fn)
        if fn[0] == "var":
            return "$" + fn[1][1]
        return "?"

    def call(self, e: tuple, sc: Scope) -> Any:
        fn = e[1]
        argsx = e[2]
        line = getattr(self, "cur_line", None)
        if fn[0] in ("name", "member") :
            name = self.callee_name(fn)
            f = self.funcs.get(self.fkey(name)) if fn[0] == "name" else None
            if f is None and fn[0] == "name":
                s = sc.find(name) or (self.g if name in self.g.vars else None)
                if s is not None:
                    return self.invoke(s.vars[name], argsx, sc, e)
            if f is not None:
                return self.call_func(f, self.eval_args(argsx, sc), sc)
            lib = self.lib_get(name)
            if lib is None and fn[0] == "member":
                obj = self.eval(fn[1], sc)
                if isinstance(obj, (Obj, str, list, dict)) and not (isinstance(obj, Obj) and obj.kind == "module"):
                    return self.call_method(obj, fn[2] if isinstance(fn[2], str) else "?", argsx, sc, e)
            if lib is not None:
                return self.invoke(lib, argsx, sc, e)
            if fn[0] == "name" and self.p.name == "php" and name.lower() in ("eval", "assert", "die", "exit", "isset",
                                                                              "empty", "unset", "echo", "print", "list"):
                pass
            self.unknown_call(name, argsx, sc, line)
            return Unk(f"the result of {name}() ({_LIB})", quiet=True)
        callee = self.eval(fn, sc)
        return self.invoke(callee, argsx, sc, e)

    def unknown_call(self, name: str, argsx: list, sc: Scope, line: int | None) -> None:
        for a in argsx:
            try:
                self.eval(a, sc)
            except Exception:  # noqa: BLE001
                pass

    def invoke(self, callee: Any, argsx: list, sc: Scope, e: tuple) -> Any:
        line = getattr(self, "cur_line", None)
        if isinstance(callee, Func):
            return self.call_func(callee, self.eval_args(argsx, sc), sc)
        if isinstance(callee, Native):
            return callee.fn(self.eval_args(argsx, sc), e, sc)
        if isinstance(callee, str) and self.p.name in ("php", "perl"):
            # a variable function: $f = 'base'.'64_decode'; $f($x)
            f = self.funcs.get(self.fkey(callee))
            if f is not None:
                return self.call_func(f, self.eval_args(argsx, sc), sc)
            lib = self.lib_get(callee)
            if lib is not None:
                self.sinks.step(line, f"calls {callee} (a name built at run time)", Value("str", callee))
                self.called_as = (callee, self.src_of(e))
                try:
                    return self.invoke(lib, argsx, sc, e)
                finally:
                    self.called_as = None
            return Unk(f"the result of {callee}()", quiet=True)
        if isinstance(callee, Unk):
            if not callee.quiet:
                self.sinks.unresolved_(self.line_text(line), callee.why, "the function it calls is computed at run time", line)
            return Unk(f"the result of a call to {callee.why}")
        if isinstance(callee, list) and self.p.name == "php" and len(callee) == 2:
            return self.call_method(callee[0], s_(callee[1]), argsx, sc, e)
        return None

    def src_of(self, e: tuple) -> str:
        return ""

    def eval_args(self, argsx: list, sc: Scope) -> list:
        out = []
        for a in argsx:
            v = self.eval(a, sc)
            if self.p.name == "perl" and isinstance(v, list) and a[0] in ("var", "call", "paren", "list") and \
                    not (a[0] == "var" and a[1][0] == "$"):
                out.extend(v)
            else:
                out.append(v)
        return out

    def call_func(self, f: Func, args: list, sc: Scope | None) -> Any:
        if self.call_depth >= MAX_CALL_DEPTH:
            raise Limit("call depth")
        new = Scope(f.closure if f.closure is not None else (self.g if self.p.name != "ahk" else self.g))
        if self.p.name == "php" and f.closure is None:
            new = Scope(None)
        for i, (pn, default) in enumerate(f.params):
            new.vars[pn if self.p.name != "ahk" else pn.lower()] = args[i] if i < len(args) else (
                self.eval(default, new) if default is not None else None)
        if self.p.name == "perl":
            new.vars["@_"] = RList(args)
            if args:
                new.vars["_"] = args[0]
        if self.p.name in ("lua",):
            new.vars["..."] = RList(args[len(f.params):])
        saved = self.source
        self.source = f.src
        self.call_depth += 1
        try:
            if f.expr:
                return self.eval(f.body, new)
            last = None
            for st in f.body:
                if st is None:
                    continue
                self.stmt(st, new)
                if st[0] == "expr":
                    last = self.last_value(st, new)
            return last if self.p.name in ("perl", "ruby") else None
        except _Return as r:
            v = r.v
            if isinstance(v, list) and v.__class__ is RList and len(v) == 1 and self.p.name in ("lua", "ruby", "perl"):
                return v[0]
            return v
        finally:
            self.call_depth -= 1
            self.source = saved

    def last_value(self, st: tuple, sc: Scope) -> Any:
        """Perl / Ruby return their last expression's value: re-read cheaply when it is a name."""
        e = st[2]
        if e[0] in ("var", "name", "str", "num", "interp"):
            return self.eval(e, sc)
        return getattr(self, "_last", None)

    def call_method(self, obj: Any, name: str, argsx: list, sc: Scope, e: tuple) -> Any:
        args = self.eval_args(argsx, sc)
        if isinstance(obj, Obj):
            return self.obj_member(obj, name, args, e, sc)
        return self.method(obj, name, args, e, sc)

    def mcall(self, e: tuple, sc: Scope) -> Any:
        _, objx, name, argsx, sep = e
        if isinstance(name, tuple):
            nv = self.eval(name[1], sc) if name[0] == "dyn" else None
            if isinstance(nv, Unk):
                self.sinks.unresolved_(self.line_text(getattr(self, "cur_line", None)), nv.why,
                                       "the method it calls is named at run time", getattr(self, "cur_line", None))
                return Unk(f"the result of a method named from {nv.why}")
            name = s_(nv)
        path = self.path_of(objx) + "." + name if objx[0] in ("name", "member") else None
        if path is not None:
            obj_name = objx[1] if objx[0] == "name" else None
            known = obj_name is not None and (sc.find(obj_name) or obj_name in self.g.vars)
            if not known:
                lib = self.lib_get(path)
                if lib is not None:
                    return self.invoke(lib, argsx, sc, e)
        obj = self.eval(objx, sc)
        if isinstance(obj, Unk):
            self.eval_args(argsx, sc)
            if obj.why.startswith("the content downloaded from "):
                return Unk(obj.why, obj.recipe)
            return Unk(obj.why, obj.recipe, obj.quiet)
        if isinstance(obj, dict) and name in obj and isinstance(obj[name], (Func, Native)):
            args = self.eval_args(argsx, sc)
            if sep == ":":
                args = [obj] + args
            f = obj[name]
            return self.call_func(f, args, sc) if isinstance(f, Func) else f.fn(args, e, sc)
        if isinstance(obj, Obj) and obj.kind == "module":
            lib = self.lib_get(obj.st["path"] + "." + name)
            if lib is not None:
                return self.invoke(lib, argsx, sc, e)
            self.eval_args(argsx, sc)
            return Unk(f"{obj.st['path']}.{name}() ({_LIB})", quiet=True)
        return self.call_method(obj, name, argsx, sc, e)

    def rblock(self, e: tuple, sc: Scope) -> Any:
        """A Ruby block: ``x.map { |c| … }``, ``each_char``, ``each``…"""
        target, params, body = e[1], e[2], e[3]
        blk = Func("block", [(p_, None) for p_ in params], body, self.source, closure=sc)
        if target[0] == "mcall":
            _, objx, name, argsx, _sep = target
            obj = self.eval(objx, sc)
            args = self.eval_args(argsx, sc)
            return self.method(obj, name if isinstance(name, str) else "?", args, e, sc, block=blk)
        if target[0] == "name":
            lib = self.lib_get(target[1])
            if isinstance(lib, Native):
                return lib.fn([blk], e, sc)
        return None

    def block_value(self, f: Func, args: list) -> Any:
        """A block / lambda's value: its last expression."""
        new = Scope(f.closure)
        for i, (pn, _d) in enumerate(f.params):
            new.vars[pn] = args[i] if i < len(args) else None
        if self.p.name == "perl":
            new.vars["_"] = args[0] if args else None
        if f.expr:
            return self.eval(f.body, new)
        last = None
        try:
            for st in f.body:
                if st is None:
                    continue
                if st[0] == "expr":
                    last = self.eval(st[2], new)
                else:
                    self.stmt(st, new)
        except _Return as r:
            return r.v
        except _Next:
            pass
        return last

    # -- the library --------------------------------------------------------------------------------------------
    def method(self, obj: Any, name: str, args: list, e: tuple, sc: Scope, block: Func | None = None) -> Any:
        return _methods(self, obj, name, args, block)

    def obj_member(self, obj: Obj, name: str, args: list, e: tuple, sc: Scope) -> Any:
        return _obj_member(self, obj, name, args)

    def new(self, cls: str, args: list, sc: Scope) -> Any:
        c = cls.lower()
        if c in ("com", "comobject", "comobjcreate"):
            return Obj("com", progid=s_(args[0]) if args else "")
        return Obj("object", cls=cls)

    # -- sinks ---------------------------------------------------------------------------------------------------
    def to_value(self, v: Any) -> Value:
        r = rec(v)
        if isinstance(v, Unk):
            return Value.unknown(v.why, r)
        if isinstance(v, (bytes, bytearray)):
            return Value("bytes", bytes(v), r)
        if isinstance(v, str):
            return Value("str", v, r)
        if isinstance(v, list) and v and all(isinstance(x, (int, float)) for x in v[:64]):
            try:
                return Value("bytes", bytes(int(x) & 0xFF for x in v), r)
            except (TypeError, ValueError):
                pass
        return Value("obj", None, r)

    def run_code(self, code: Any, sink: str, sc: Scope | None = None, lang: str | None = None) -> Any:
        line = getattr(self, "cur_line", None)
        ca = getattr(self, "called_as", None)
        if ca:
            sink = f"{sink} (called as {ca[0]})"
        if isinstance(code, Unk):
            self.sinks.exec_(Value.unknown(code.why), sink, line)
            return Unk(f"the result of code computed from {code.why}")
        src = text(code)
        self.sinks.exec_(Value("str", src, rec(code)), sink, line)
        if lang is not None and lang != self.p.name:
            if self.sinks.stages and self.sinks.stages[-1].data == src:
                self.sinks.stages[-1].ext = lang
            return None
        h = hashlib.sha256(src.encode("utf-8", "replace")).hexdigest()
        if self.depth >= MAX_DEPTH or h in self.ran:
            return None
        self.ran.add(h)
        try:
            body = src
            if self.p.name == "php" and "<?" not in body[:200]:
                body = "<?php " + body
            prog = self.parse(body)
        except (SyntaxError, RecursionError, IndexError) as exc:
            self.errors.append(f"line {line}: {sink} of code that does not parse: {exc}"[:300])
            return None
        self.depth += 1
        self.sinks.depth = self.depth
        saved = self.source
        self.source = src
        try:
            self.hoist(prog)
            self.block(prog, sc or self.g, top=True)
        except _Return as r:
            return r.v
        finally:
            self.source = saved
            self.depth -= 1
            self.sinks.depth = self.depth
        return None

    def launch(self, cmd: Any, via: str, line: int | None = None) -> Any:
        line = line or getattr(self, "cur_line", None)
        if isinstance(cmd, Unk):
            if cmd.why.startswith("the content downloaded from "):
                self.sinks.exec_(Value.unknown(cmd.why), via, line)
            elif not cmd.quiet:
                self.sinks.unresolved_(self.line_text(line), cmd.why, "the command it runs is computed at run time", line)
            return Unk("the output of a command")
        c = text(cmd)
        if re.search(r"(?i)\b(?:powershell|pwsh|mshta|certutil|bitsadmin|cmd(?:\.exe)?\s+/[ck]|wscript|cscript|rundll32|regsvr32)\b", c):
            if commands.launch(self.sinks, c, rec(cmd), line, via):
                return Unk("the output of a command")
        else:
            from . import sh_eval
            sh_eval.run_command(self.sinks, c, rec(cmd), line, via)
        # a file it downloaded before, run now
        for d in self.sinks.downloads:
            dest = (d.get("saved_to") or "").lower()
            if dest and dest in c.lower() and "runs it" not in d["use"]:
                d["use"] += f", then runs it ({c.strip()[:80]})"
        return Unk("the output of a command")

    def download(self, url: Any, method: str, use: str = "returns it to the script", dest: str = "") -> Unk:
        line = getattr(self, "cur_line", None)
        if isinstance(url, Unk):
            self.sinks.download(Value.unknown(url.why), method, use, line, dest)
            return Unk(f"the content downloaded from <{url.why}>")
        u = text(url)
        self.sinks.download(Value("str", u, rec(url)), method, use, line, dest)
        return Unk(f"the content downloaded from {u}")

    def write(self, path: Any, data: Any, sink: str) -> None:
        line = getattr(self, "cur_line", None)
        p = text(path) if not isinstance(path, Unk) else f"<{path.why}>"
        if isinstance(data, Unk):
            if not self.sinks._downloaded(Value.unknown(data.why), f"saves it to {p}"):
                if not data.quiet:
                    self.sinks.unresolved_(self.line_text(line), data.why, f"what it writes to {p} is not in the script", line)
            for d in self.sinks.downloads:
                if data.why.endswith(d["url"]):
                    d["saved_to"] = p
            return
        b = raw(data) if not isinstance(data, list) else bytes(int(n_(x)) & 0xFF for x in data)
        self.sinks.write(Value("bytes", b, rec(data)), p, sink, line)

    def flush(self, h: Obj) -> None:
        if h.st.get("flushed") or h.kind != "file" or "w" not in h.st.get("mode", "") and "a" not in h.st.get("mode", ""):
            return
        h.st["flushed"] = True
        data = h.st.get("data")
        if data is None:
            return
        if isinstance(data, Unk) or (isinstance(data, str) and data):
            self.write(h.st["path"], data, h.st.get("sink", "write"))

    def computed_values(self) -> None:
        from . import langdetect
        seen: set[int] = set()
        for name, v in list(self.g.vars.items()) + list(self.tracked.items()):
            if id(v) in seen or not isinstance(v, (str, list)) or len(v) < 40:
                continue
            seen.add(id(v))
            r = rec(v)
            ops = [x for x in r if not x.startswith(("literal", "number array"))]
            if not ops:
                continue
            if isinstance(v, list):
                if not all(isinstance(x, (int, float)) for x in v[:64]):
                    continue
                b = bytes(int(n_(x)) & 0xFF for x in v)
            else:
                b = raw(v)
            if any(st.recipe[:len(r)] == r and len(st.recipe) > len(r) for st in self.sinks.stages):
                continue
            kind = T.magic(b)
            if not kind and T.is_text(b):
                txt = text(b)
                if txt in self.source:
                    continue
                if langdetect.languages(txt):
                    self.sinks.exec_(Value("str", txt, r), f"value of {name} (computed, not run here)")
                    continue
                if re.search(r"(?i)\bhttps?://|\b\d{1,3}(?:\.\d{1,3}){3}\b", txt):
                    self.sinks.value_(Value("str", txt, r), f"value of {name} (decoded text with IOCs)")
                continue
            if kind:
                self.sinks.load(Value("bytes", b, r), f"value of {name} (computed, not run here)")

    # -- Perl regexes ---------------------------------------------------------------------------------------------
    def perl_match(self, e: tuple, sc: Scope) -> Any:
        _, op, target, spec, kind = e
        v = self.eval(target, sc)
        if isinstance(v, Unk):
            return v
        s = s_(v)
        if kind == "subst":
            k, pat, rep, flags = spec
            if k in ("tr", "y"):
                src, dst = _tr_expand(pat), _tr_expand(rep)
                if "d" in flags:
                    table = {ord(c): (dst[i] if i < len(dst) else None) for i, c in enumerate(src)}
                else:
                    dst = dst or src
                    table = {ord(c): dst[min(i, len(dst) - 1)] for i, c in enumerate(src)}
                out = s.translate(table)
                label = f"tr/{pat[:12]}/{rep[:12]}/"
            else:
                try:
                    rx = re.compile(pat, (re.I if "i" in flags else 0) | (re.S if "s" in flags else 0) | (re.M if "m" in flags else 0))
                except re.error:
                    return v
                if "e" in flags:
                    def fe(m: re.Match) -> str:
                        sub = Scope(sc)
                        for gi, g in enumerate(m.groups(), 1):
                            sub.vars[str(gi)] = g or ""
                        try:
                            return s_(self.eval(Parser(tokenize(rep, self.p), self.p).expr(), sub))
                        except Exception:  # noqa: BLE001
                            return m.group(0)
                    out = rx.sub(fe, s, count=0 if "g" in flags else 1)
                else:
                    rep2 = re.sub(r"\$(\d)", r"\\\1", rep)
                    rep2 = re.sub(r"\$\{(\d)\}", r"\\\1", rep2)
                    try:
                        out = rx.sub(_unescape(rep2.replace("\\\\", "\x00")).replace("\x00", "\\\\"), s, count=0 if "g" in flags else 1)
                    except (re.error, IndexError):
                        out = s
                label = f"s/{pat[:12]}/{rep[:12]}/"
            if "r" not in flags:
                newv = tag(out, rec(v) + ((label,) if len(out) >= 16 and out != s else ())) if len(out) >= 16 else out
                self.assign(target, newv, sc)
                return 1
            return out
        pat, flags = spec
        try:
            m = re.search(pat, s, re.I if "i" in flags else 0)
        except re.error:
            return False
        if m:
            for gi, g in enumerate(m.groups(), 1):
                self.g.vars[str(gi)] = g or ""
        return bool(m) if op == "=~" else not m


_LIB = "not defined in the script (a library)"


def _numeric(s: str) -> bool:
    return bool(re.fullmatch(r"\s*[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\s*", s))


def _norm(n: float | int) -> float | int:
    if isinstance(n, float) and n.is_integer() and abs(n) < 2 ** 53:
        return int(n)
    return n


def _tr_expand(s: str) -> str:
    out = []
    i = 0
    s = _unescape(s)
    while i < len(s):
        if i + 2 < len(s) and s[i + 1] == "-":
            a, b = ord(s[i]), ord(s[i + 2])
            out.extend(chr(c) for c in range(a, b + 1))
            i += 3
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


# --- pack / unpack ------------------------------------------------------------------------------------
def pack(fmt: str, args: list) -> str:
    out = bytearray()
    ai = 0
    for m in re.finditer(r"([aAZbBhHcCsSlLqQnNvVjJfdwUxuMm])(\*|\d+)?", fmt.replace(" ", "")):
        c, cnt = m.group(1), m.group(2)
        if c in "aAZ":
            s = raw(args[ai]) if ai < len(args) else b""
            ai += 1
            out += s if cnt in (None, "*") else s[:int(cnt)].ljust(int(cnt), b"\x00" if c != "A" else b" ")
        elif c in "hH":
            s = s_(args[ai]) if ai < len(args) else ""
            ai += 1
            if cnt not in (None, "*"):
                s = s[:int(cnt)]
            if c == "h":
                s = "".join(s[k + 1] + s[k] if k + 1 < len(s) else "0" + s[k] for k in range(0, len(s), 2))
            s = re.sub(r"[^0-9a-fA-F]", "", s)
            out += bytes.fromhex(s + ("0" if len(s) % 2 else ""))
        elif c in "cCU":
            n = len(args) - ai if cnt == "*" else int(cnt or 1)
            for _ in range(n):
                v = int(n_(args[ai])) if ai < len(args) else 0
                ai += 1
                out += chr(v).encode("utf-8") if c == "U" else bytes([v & 0xFF])
        elif c in "nNvVsSlLqQjJ":
            n = len(args) - ai if cnt == "*" else int(cnt or 1)
            size, order = {"n": (2, "big"), "N": (4, "big"), "v": (2, "little"), "V": (4, "little"),
                           "s": (2, "little"), "S": (2, "little"), "l": (4, "little"), "L": (4, "little"),
                           "q": (8, "little"), "Q": (8, "little"), "j": (8, "little"), "J": (8, "little")}[c]
            for _ in range(n):
                v = int(n_(args[ai])) if ai < len(args) else 0
                ai += 1
                out += (v & ((1 << (8 * size)) - 1)).to_bytes(size, order)
        elif c == "x":
            out += b"\x00" * int(cnt or 1) if cnt != "*" else b""
        elif c == "u":
            s = raw(args[ai]) if ai < len(args) else b""
            ai += 1
            import binascii
            out += b"".join(binascii.b2a_uu(s[k:k + 45]) for k in range(0, len(s), 45))
        elif c == "m":
            s = raw(args[ai]) if ai < len(args) else b""
            ai += 1
            out += base64.b64encode(s) + (b"" if cnt == "0" else b"\n")
    return lat(bytes(out))


def unpack(fmt: str, data: Any) -> RList:
    b = raw(data)
    out = RList()
    pos = 0
    for m in re.finditer(r"([aAZbBhHcCsSlLqQnNvVjJUxum@])(\*|\d+)?", fmt.replace(" ", "")):
        c, cnt = m.group(1), m.group(2)
        if c in "aAZ":
            n = len(b) - pos if cnt in ("*", None) and cnt == "*" else int(cnt or 1)
            out.append(lat(b[pos:pos + n]))
            pos += n
        elif c in "hH":
            rest = b[pos:]
            hx = rest.hex()
            if c == "h":
                hx = "".join(hx[k + 1] + hx[k] for k in range(0, len(hx), 2))
            n = len(hx) if cnt == "*" else int(cnt or 1)
            out.append(hx[:n])
            pos += (n + 1) // 2
        elif c in "cCU":
            n = len(b) - pos if cnt == "*" else int(cnt or 1)
            for k in range(n):
                if pos >= len(b):
                    break
                v = b[pos]
                out.append(v - 256 if c == "c" and v > 127 else v)
                pos += 1
        elif c in "nNvVsSlLqQ":
            size, order, signed = {"n": (2, "big", False), "N": (4, "big", False), "v": (2, "little", False),
                                   "V": (4, "little", False), "s": (2, "little", True), "S": (2, "little", False),
                                   "l": (4, "little", True), "L": (4, "little", False), "q": (8, "little", True),
                                   "Q": (8, "little", False)}[c]
            n = (len(b) - pos) // size if cnt == "*" else int(cnt or 1)
            for _ in range(n):
                if pos + size > len(b):
                    break
                out.append(int.from_bytes(b[pos:pos + size], order, signed=signed))
                pos += size
        elif c == "u":
            import binascii
            res = bytearray()
            for ln in b[pos:].split(b"\n"):
                if ln.strip():
                    try:
                        res += binascii.a2b_uu(ln)
                    except binascii.Error:
                        pass
            out.append(lat(bytes(res)))
            pos = len(b)
        elif c == "m":
            try:
                out.append(lat(T.b64decode(b[pos:])))
            except T.TransformError:
                out.append("")
            pos = len(b)
        elif c == "x":
            pos += int(cnt or 1)
    return out


# --- the library: functions, methods, objects ------------------------------------------------------------
def _library(it: Interp) -> dict[str, Any]:  # noqa: C901, PLR0915
    L: dict[str, Any] = {}
    p = it.p.name

    def reg(names: str, fn: Callable[..., Any]) -> None:
        for nm in names.split():
            L[nm.lower() if it.p.case_insensitive_funcs else nm] = Native(nm, fn)

    def a(args: list, i: int, d: Any = None) -> Any:
        return args[i] if len(args) > i else d

    def guard(fn: Callable[..., Any]) -> Callable[..., Any]:
        def g(args: list, e: tuple, sc: Scope) -> Any:
            for x in args:
                if isinstance(x, Unk):
                    return Unk(x.why, x.recipe)
            return fn(args, e, sc)
        return g

    def dec(label: str, f: Callable[[bytes], bytes]) -> Callable[..., Any]:
        def g(args: list, e: tuple, sc: Scope) -> Any:
            v = a(args, 0, "")
            if isinstance(v, Unk):
                return Unk(v.why, v.recipe + (label,))
            try:
                out = f(raw(v))
            except (T.TransformError, ValueError) as exc:
                it.errors.append(f"line {getattr(it, 'cur_line', '?')}: {label}: {exc}"[:200])
                return "" if p == "php" else None
            return step(v, label, lat(out))
        return g

    # -- decoders (shared by every language under its own names)
    b64 = dec("base64", lambda b: T.b64decode(b))
    inflate = dec("inflate", T.inflate)
    zlib_ = dec("zlib", T.zlib_decompress)
    gunzip = dec("gzip", T.gunzip)
    anyz = dec("decompress", T.decompress_any)
    hex_ = dec("hex", T.hexdecode)
    rot13 = guard(lambda args, e, sc: step(args[0], "rot13", T.rot(s_(args[0]), 13)))
    rev = guard(lambda args, e, sc: step(args[0], "reverse", s_(args[0])[::-1]) if len(s_(args[0])) >= 16 else s_(args[0])[::-1])
    uu = dec("uudecode", lambda b: _uudecode(b))
    urld = guard(lambda args, e, sc: step(args[0], "url decode", urllib.parse.unquote_to_bytes(s_(args[0])).decode("latin-1")))
    chr_ = guard(lambda args, e, sc: chr(int(n_(a(args, 0, 0))) & 0xFF))
    ord_ = guard(lambda args, e, sc: ord(s_(a(args, 0, ""))[0]) if s_(a(args, 0, "")) else 0)

    if p == "php":
        reg("base64_decode", b64)
        reg("base64_encode", guard(lambda args, e, sc: base64.b64encode(raw(args[0])).decode()))
        reg("gzinflate", inflate)
        reg("gzuncompress", zlib_)
        reg("gzdecode", gunzip)
        reg("zlib_decode", anyz)
        reg("str_rot13", rot13)
        reg("strrev", rev)
        reg("hex2bin", hex_)
        reg("pack", guard(lambda args, e, sc: step(args[1] if len(args) > 1 else "", f"pack({s_(args[0])})",
                                                    pack(s_(args[0]), args[1:]))))
        reg("unpack", guard(lambda args, e, sc: {i + 1: v for i, v in enumerate(unpack(s_(args[0]), args[1]))}))
        reg("bin2hex", guard(lambda args, e, sc: raw(args[0]).hex()))
        reg("convert_uudecode", uu)
        reg("urldecode rawurldecode", urld)
        reg("html_entity_decode htmlspecialchars_decode", guard(lambda args, e, sc: __import__("html").unescape(s_(args[0]))))
        reg("chr", chr_)
        reg("ord", ord_)
        reg("strlen", guard(lambda args, e, sc: len(s_(a(args, 0, "")))))
        reg("count sizeof", guard(lambda args, e, sc: len(a(args, 0, [])) if isinstance(a(args, 0), (list, dict)) else 1))
        reg("substr", guard(lambda args, e, sc: _substr(s_(args[0]), args[1:], it)))
        reg("str_replace str_ireplace", guard(lambda args, e, sc: _str_replace(it, args, e)))
        reg("implode join", guard(lambda args, e, sc: _implode(it, args)))
        reg("explode", guard(lambda args, e, sc: RList(s_(args[1]).split(s_(args[0]))) if s_(args[0]) else RList([s_(args[1])])))
        reg("str_split", guard(lambda args, e, sc: RList(_chunks(s_(args[0]), int(n_(a(args, 1, 1)))))))
        reg("strtolower", guard(lambda args, e, sc: it_keep(args[0], s_(args[0]).lower())))
        reg("strtoupper", guard(lambda args, e, sc: it_keep(args[0], s_(args[0]).upper())))
        reg("trim", guard(lambda args, e, sc: it_keep(args[0], s_(args[0]).strip())))
        reg("ltrim", guard(lambda args, e, sc: s_(args[0]).lstrip()))
        reg("rtrim chop", guard(lambda args, e, sc: s_(args[0]).rstrip()))
        reg("str_repeat", guard(lambda args, e, sc: s_(args[0]) * min(int(n_(args[1])), MAX_STR // max(1, len(s_(args[0]))))))
        reg("strpos stripos", guard(lambda args, e, sc: (lambda r: r if r >= 0 else False)(s_(args[0]).find(s_(args[1])))))
        reg("intval", guard(lambda args, e, sc: int(n_(args[0])) if len(args) < 2 else int(s_(args[0]) or "0", int(n_(args[1])))))
        reg("hexdec", guard(lambda args, e, sc: int(re.sub(r"[^0-9a-fA-F]", "", s_(args[0])) or "0", 16)))
        reg("dechex", guard(lambda args, e, sc: format(int(n_(args[0])), "x")))
        reg("octdec", guard(lambda args, e, sc: int(re.sub(r"[^0-7]", "", s_(args[0])) or "0", 8)))
        reg("bindec", guard(lambda args, e, sc: int(re.sub(r"[^01]", "", s_(args[0])) or "0", 2)))
        reg("sprintf", guard(lambda args, e, sc: _sprintf(s_(args[0]), args[1:])))
        reg("array_reverse", guard(lambda args, e, sc: it_keep_list(args[0], RList(reversed(list(args[0].values()) if isinstance(args[0], dict) else list(args[0]))), "reverse")))
        reg("array_map", lambda args, e, sc: _array_map(it, args, sc))
        reg("array_merge", guard(lambda args, e, sc: RList(x for arr in args for x in (arr.values() if isinstance(arr, dict) else arr))))
        reg("array_keys", guard(lambda args, e, sc: RList(args[0].keys() if isinstance(args[0], dict) else range(len(args[0])))))
        reg("array_values", guard(lambda args, e, sc: RList(args[0].values() if isinstance(args[0], dict) else args[0])))
        reg("range", guard(lambda args, e, sc: RList(_range(args))))
        reg("in_array", guard(lambda args, e, sc: args[0] in (args[1].values() if isinstance(args[1], dict) else args[1])))
        reg("is_array", lambda args, e, sc: isinstance(a(args, 0), (list, dict)))
        reg("isset", lambda args, e, sc: all(x is not None for x in args))
        reg("empty", lambda args, e, sc: not truthy(a(args, 0)))
        reg("function_exists", lambda args, e, sc: True)
        reg("defined define ini_set set_time_limit error_reporting ignore_user_abort header ob_start session_start "
            "ob_end_clean ob_get_clean ob_end_flush flush date_default_timezone_set unset setcookie",
            lambda args, e, sc: True)
        reg("md5", guard(lambda args, e, sc: hashlib.md5(raw(args[0])).hexdigest()))  # noqa: S324
        reg("sha1", guard(lambda args, e, sc: hashlib.sha1(raw(args[0])).hexdigest()))  # noqa: S324
        reg("str_pad", guard(lambda args, e, sc: s_(args[0]).ljust(int(n_(args[1])), s_(a(args, 2, " "))[:1] or " ")))
        reg("ucfirst", guard(lambda args, e, sc: s_(args[0])[:1].upper() + s_(args[0])[1:]))
        reg("eval", lambda args, e, sc: it.run_code(a(args, 0, ""), "eval", sc))
        reg("assert", lambda args, e, sc: it.run_code(a(args, 0, ""), "assert", sc) if isinstance(a(args, 0), (str, Unk)) else True)
        reg("create_function", lambda args, e, sc: _create_function(it, args, sc))
        reg("call_user_func", lambda args, e, sc: _call_value(it, a(args, 0), args[1:], e, sc))
        reg("call_user_func_array", lambda args, e, sc: _call_value(it, a(args, 0), list(a(args, 1, []) or []), e, sc))
        reg("preg_replace", lambda args, e, sc: _preg_replace(it, args, sc))
        reg("preg_replace_callback", lambda args, e, sc: _preg_replace_cb(it, args, sc))
        reg("system exec shell_exec passthru popen proc_open pcntl_exec",
            lambda args, e, sc: it.launch(a(args, 0, ""), it.callee_name(e[1]) if e[0] == "call" else "system"))
        reg("file_get_contents fopen readfile file", lambda args, e, sc: _php_open(it, args, e))
        reg("file_put_contents", lambda args, e, sc: it.write(a(args, 0, ""), a(args, 1, ""), "file_put_contents") or len(s_(a(args, 1, ""))))
        reg("fwrite fputs", lambda args, e, sc: _fwrite(it, args))
        reg("fclose", lambda args, e, sc: it.flush(args[0]) if args and isinstance(args[0], Obj) else True)
        reg("curl_init", lambda args, e, sc: Obj("curl", url=a(args, 0)))
        reg("curl_setopt", lambda args, e, sc: _curl_setopt(args))
        reg("curl_exec", lambda args, e, sc: it.download(args[0].st.get("url", "") if args and isinstance(args[0], Obj) else "", "curl_exec"))
        reg("fsockopen stream_socket_client socket_connect", lambda args, e, sc: _socket(it, args, e))
        reg("openssl_decrypt", lambda args, e, sc: _openssl_decrypt(it, args))
        reg("mcrypt_decrypt", lambda args, e, sc: Unk("mcrypt_decrypt (not followed)"))
        reg("gzopen", lambda args, e, sc: Unk("a gzip file on the server"))
        reg("move_uploaded_file", lambda args, e, sc: it.write(a(args, 1, ""), Unk("an uploaded file (the web request)"), "move_uploaded_file") or True)
        reg("str_shuffle rand mt_rand random_int uniqid time microtime", lambda args, e, sc: Unk("a random / time value", quiet=True))
        reg("getenv", lambda args, e, sc: Unk(f"the environment variable {s_(a(args, 0, ''))}"))
        reg("echo print print_r var_dump printf die exit", lambda args, e, sc: _php_echo(it, args, e))
        reg("include include_once require require_once", lambda args, e, sc: _php_include(it, a(args, 0, ""), sc))
    if p == "perl":
        reg("decode_base64 MIME.Base64.decode_base64 MIME.Base64.decode", b64)
        reg("encode_base64", guard(lambda args, e, sc: base64.b64encode(raw(args[0])).decode() + "\n"))
        reg("uncompress Compress.Zlib.uncompress", zlib_)
        reg("memGunzip memgunzip Compress.Zlib.memGunzip", gunzip)
        reg("inflate", inflate)
        reg("pack", guard(lambda args, e, sc: step(args[1] if len(args) > 1 else "", f"pack({s_(args[0])})", pack(s_(args[0]), args[1:]))))
        reg("unpack", guard(lambda args, e, sc: _unpack_step(args)))
        reg("chr", chr_)
        reg("ord", ord_)
        reg("hex", guard(lambda args, e, sc: int(re.sub(r"[^0-9a-fA-F]", "", s_(args[0])) or "0", 16)))
        reg("oct", guard(lambda args, e, sc: int(s_(args[0]), 0) if s_(args[0]).startswith(("0x", "0b", "0o")) else int(s_(args[0]) or "0", 8)))
        reg("length", guard(lambda args, e, sc: len(s_(a(args, 0, sc.vars.get("_") or "")))))
        reg("lc", guard(lambda args, e, sc: s_(args[0]).lower()))
        reg("uc", guard(lambda args, e, sc: s_(args[0]).upper()))
        reg("substr", guard(lambda args, e, sc: _substr(s_(args[0]), args[1:], it)))
        reg("index", guard(lambda args, e, sc: s_(args[0]).find(s_(args[1]))))
        reg("join", guard(lambda args, e, sc: _implode(it, args)))
        reg("split", guard(lambda args, e, sc: _perl_split(args)))
        reg("reverse", guard(lambda args, e, sc: _perl_reverse(args)))
        reg("map", lambda args, e, sc: _perl_map(it, args, sc))
        reg("grep", lambda args, e, sc: RList(x for x in args[1:] if truthy(it.block_value(args[0], [x]))) if args and isinstance(args[0], Func) else RList())
        reg("sort", guard(lambda args, e, sc: RList(sorted(args, key=s_))))
        reg("scalar", lambda args, e, sc: len(a(args, 0, [])) if isinstance(a(args, 0), list) else a(args, 0))
        reg("sprintf", guard(lambda args, e, sc: _sprintf(s_(args[0]), args[1:])))
        reg("push", lambda args, e, sc: _perl_push(it, e, args, sc))
        reg("chomp chop", lambda args, e, sc: 1)
        reg("defined", lambda args, e, sc: a(args, 0) is not None)
        reg("eval", lambda args, e, sc: it.run_code(a(args, 0, sc.vars.get("_", "")), "eval", sc)
            if not isinstance(a(args, 0), Func) else it.block_value(args[0], []))
        reg("system exec", lambda args, e, sc: it.launch(" ".join(s_(x) for x in args) if not any(isinstance(x, Unk) for x in args)
                                                           else next(x for x in args if isinstance(x, Unk)), it.callee_name(e[1])))
        reg("open", lambda args, e, sc: _perl_open(it, e, args, sc))
        reg("print printf say", lambda args, e, sc: _perl_print(it, e, args, sc))
        reg("close", lambda args, e, sc: [it.flush(h) for h in list(it.files.values())] and 1)
        reg("binmode unlink chmod mkdir sleep die warn exit fork wait waitpid local select", lambda args, e, sc: 1)
        reg("get LWP.Simple.get", lambda args, e, sc: it.download(a(args, 0, ""), "LWP get"))
        reg("getstore LWP.Simple.getstore mirror", lambda args, e, sc: it.download(a(args, 0, ""), "LWP getstore", "saves it",
                                                                                     s_(a(args, 1, ""))) and 200)
        reg("IO.Socket.INET.new", lambda args, e, sc: _socket(it, args, e))
        reg("keys", guard(lambda args, e, sc: RList(args[0].keys()) if isinstance(a(args, 0), dict) else RList()))
        reg("values", guard(lambda args, e, sc: RList(args[0].values()) if isinstance(a(args, 0), dict) else RList()))
    if p == "ruby":
        reg("Base64.decode64 Base64.strict_decode64 Base64.urlsafe_decode64", b64)
        reg("Base64.encode64 Base64.strict_encode64", guard(lambda args, e, sc: base64.b64encode(raw(args[0])).decode()))
        reg("Zlib.Inflate.inflate Zlib.inflate", anyz)
        reg("Zlib.gunzip", gunzip)
        reg("eval instance_eval class_eval module_eval binding.eval Kernel.eval TOPLEVEL_BINDING.eval",
            lambda args, e, sc: it.run_code(a(args, 0, ""), "eval", sc))
        reg("system exec spawn Kernel.system Kernel.exec Process.spawn IO.popen Open3.capture2 Open3.capture3 Open3.popen3",
            lambda args, e, sc: it.launch(" ".join(s_(x) for x in args if not isinstance(x, dict)) if not any(isinstance(x, Unk) for x in args)
                                          else next(x for x in args if isinstance(x, Unk)), it.callee_name(e[1]) if e[0] in ("call", "mcall") else "system"))
        reg("File.write File.binwrite IO.write IO.binwrite", lambda args, e, sc: it.write(a(args, 0, ""), a(args, 1, ""), "File.write") or 1)
        reg("File.open", lambda args, e, sc: _file_open(it, args, sc, e))
        reg("Net.HTTP.get URI.open open Net.HTTP.get_response OpenURI.open_uri", lambda args, e, sc: it.download(a(args, 0, ""), "Net::HTTP / open-uri"))
        reg("URI URI.parse", lambda args, e, sc: a(args, 0))
        reg("require require_relative load puts print p sleep raise exit at_exit", lambda args, e, sc: None)
        reg("ENV.fetch", lambda args, e, sc: Unk(f"the environment variable {s_(a(args, 0, ''))}"))
    if p == "lua":
        reg("load loadstring dofile_string", lambda args, e, sc: _lua_load(it, args, sc))
        reg("string.char", guard(lambda args, e, sc: _char_codes(args)))
        reg("string.byte", guard(lambda args, e, sc: _lua_byte(args)))
        reg("string.reverse", rev)
        reg("string.sub", guard(lambda args, e, sc: _lua_sub(s_(args[0]), args[1:])))
        reg("string.len", guard(lambda args, e, sc: len(s_(args[0]))))
        reg("string.rep", guard(lambda args, e, sc: _rep(s_(args[0]), int(n_(args[1])))))
        reg("string.gsub", lambda args, e, sc: _lua_gsub(it, args, sc))
        reg("string.format", guard(lambda args, e, sc: _sprintf(s_(args[0]), args[1:])))
        reg("string.upper", guard(lambda args, e, sc: s_(args[0]).upper()))
        reg("string.lower", guard(lambda args, e, sc: s_(args[0]).lower()))
        reg("string.gmatch", lambda args, e, sc: _lua_gmatch(args))
        reg("table.concat", guard(lambda args, e, sc: _implode(it, [a(args, 1, ""), args[0]])))
        reg("table.insert", lambda args, e, sc: (args[0].append(args[-1]) if isinstance(args[0], list) else None))
        reg("tonumber", guard(lambda args, e, sc: int(s_(args[0]), int(n_(args[1]))) if len(args) > 1 else n_(args[0])))
        reg("tostring", guard(lambda args, e, sc: s_(args[0])))
        reg("bit32.bxor bit.bxor", guard(lambda args, e, sc: _red(args, lambda x, y: x ^ y)))
        reg("bit32.band bit.band", guard(lambda args, e, sc: _red(args, lambda x, y: x & y)))
        reg("bit32.bor bit.bor", guard(lambda args, e, sc: _red(args, lambda x, y: x | y)))
        reg("os.execute io.popen", lambda args, e, sc: it.launch(a(args, 0, ""), it.callee_name(e[1]) if e[0] == "call" else "os.execute"))
        reg("io.open", lambda args, e, sc: _file_open(it, args, sc, e))
        reg("pairs ipairs", lambda args, e, sc: a(args, 0))
        reg("print require pcall error assert select type setmetatable getmetatable rawget rawset", lambda args, e, sc: a(args, 0) if e[1][1] in ("assert", "pcall") else None)
        reg("http.request socket.http.request", lambda args, e, sc: it.download(a(args, 0, ""), "http.request"))
        reg("os.getenv", lambda args, e, sc: Unk(f"the environment variable {s_(a(args, 0, ''))}"))
    if p == "ahk":
        reg("chr", chr_)
        reg("asc ord", ord_)
        reg("substr", guard(lambda args, e, sc: _ahk_substr(s_(args[0]), args[1:])))
        reg("strlen", guard(lambda args, e, sc: len(s_(args[0]))))
        reg("strreplace", guard(lambda args, e, sc: s_(args[0]).replace(s_(a(args, 1, "")), s_(a(args, 2, "")))))
        reg("strsplit", guard(lambda args, e, sc: RList(s_(args[0]).split(s_(a(args, 1, ""))) if s_(a(args, 1, "")) else list(s_(args[0])))))
        reg("format", guard(lambda args, e, sc: re.sub(r"\{(\d+)\}", lambda m: s_(args[int(m.group(1))]) if int(m.group(1)) < len(args) else "", s_(args[0]))))
        reg("run runwait", lambda args, e, sc: it.launch(a(args, 0, ""), "Run"))
        reg("urldownloadtofile", lambda args, e, sc: it.download(a(args, 0, ""), "UrlDownloadToFile", "saves it", s_(a(args, 1, ""))) and 0)
        reg("download", lambda args, e, sc: it.download(a(args, 0, ""), "Download", "saves it", s_(a(args, 1, ""))) and 0)
        reg("fileappend", lambda args, e, sc: it.write(a(args, 1, ""), a(args, 0, ""), "FileAppend") or 1)
        reg("comobjcreate comobject", lambda args, e, sc: Obj("com", progid=s_(a(args, 0, ""))))
        reg("dllcall", lambda args, e, sc: _ahk_dllcall(it, args))
        reg("numput", lambda args, e, sc: _ahk_numput(it, args))
        reg("varsetcapacity buffer", lambda args, e, sc: Obj("buffer", data=bytearray(min(int(n_(a(args, 1 if e[1][1].lower() == "varsetcapacity" else 0, 0))), MAX_STR))))
        reg("msgbox sleep tooltip traytip send sendinput fileread filedelete filecopy filemove regwrite exitapp", lambda args, e, sc: 1)
        reg("envget", lambda args, e, sc: Unk(f"the environment variable {s_(a(args, 0, ''))}"))
        reg("regread", lambda args, e, sc: Unk(f"the registry value {s_(a(args, 0, ''))}"))
    return L


def _rep(s: str, n: int) -> str:
    if len(s) * max(0, n) > MAX_STR:
        raise Limit("string size")
    return s * max(0, n)


def it_keep(src: Any, out: str) -> str:
    r = rec(src)
    return tag(out, r) if r and len(out) >= 16 else out


def it_keep_list(src: Any, out: RList, label: str) -> RList:
    out.recipe = rec(src) + ((label,) if len(out) >= 16 else ())
    return out


def _uudecode(b: bytes) -> bytes:
    import binascii
    out = bytearray()
    for ln in b.split(b"\n"):
        if ln.strip() and not ln.startswith((b"begin ", b"end")):
            try:
                out += binascii.a2b_uu(ln)
            except binascii.Error:
                pass
    return bytes(out)


def _substr(s: str, args: list, it: Interp) -> str:
    st = int(n_(args[0])) if args else 0
    if st < 0:
        st = max(0, len(s) + st)
    if len(args) > 1 and args[1] is not None:
        ln = int(n_(args[1]))
        out = s[st:st + ln] if ln >= 0 else s[st:len(s) + ln]
    else:
        out = s[st:]
    return out


def _chunks(s: str, n: int) -> list[str]:
    n = max(1, n)
    return [s[i:i + n] for i in range(0, len(s), n)]


def _range(args: list) -> list:
    a0, a1 = args[0], args[1] if len(args) > 1 else 0
    st = int(n_(args[2])) if len(args) > 2 else 1
    if isinstance(a0, str) and isinstance(a1, str) and len(a0) == 1 and len(a1) == 1 and not a0.isdigit():
        return [chr(c) for c in range(ord(a0), ord(a1) + 1, st)]
    lo, hi = int(n_(a0)), int(n_(a1))
    step_ = abs(st) or 1
    return list(range(lo, hi + 1, step_)) if lo <= hi else list(range(lo, hi - 1, -step_))


def _implode(it: Interp, args: list) -> Any:
    if len(args) == 1:
        sep, arr = "", args[0]
    else:
        sep, arr = args[0], args[1]
        if isinstance(sep, (list, dict)):
            sep, arr = arr, sep
    if it.p.name == "perl":
        sep, arr = args[0], RList(args[1:]) if len(args) > 2 or not isinstance(args[1] if len(args) > 1 else None, list) else args[1]
    items = list(arr.values()) if isinstance(arr, dict) else (list(arr) if isinstance(arr, list) else [arr])
    out = s_(sep).join(s_(x) for x in items)
    r = rec(arr)
    return tag(out, r) if r and len(out) >= 16 else out


def _str_replace(it: Interp, args: list, e: tuple) -> Any:
    find, rep, subj = args[0], args[1], args[2]
    s = s_(subj)
    finds = list(find.values()) if isinstance(find, dict) else (list(find) if isinstance(find, list) else [find])
    reps = list(rep.values()) if isinstance(rep, dict) else (list(rep) if isinstance(rep, list) else None)
    out = s
    for i, f in enumerate(finds):
        r = s_(reps[i]) if reps is not None and i < len(reps) else ("" if reps is not None else s_(rep))
        if s_(f):
            out = out.replace(s_(f), r) if "ireplace" not in it.callee_name(e[1]).lower() else re.sub(re.escape(s_(f)), lambda _m: r, out, flags=re.I)
    if len(s) >= 16 and out != s:
        return tag(out, rec(subj) + (f"replace({s_(finds[0])[:12]!r} → {s_(reps[0] if reps else rep)[:12]!r})",))
    return it_keep(subj, out)


def _sprintf(fmt: str, args: list) -> str:
    vals = iter(args)

    def rep(m: re.Match) -> str:
        if m.group(0) == "%%":
            return "%"
        spec = m.group(1) or ""
        conv = m.group(2)
        v = next(vals, "")
        try:
            if conv in "di":
                return ("%" + spec + "d") % int(n_(v))
            if conv in "xX":
                return ("%" + spec + conv) % int(n_(v))
            if conv == "c":
                return chr(int(n_(v)) & 0xFF)
            if conv in "fFeEgG":
                return ("%" + spec + conv) % float(n_(v))
            if conv == "o":
                return ("%" + spec + "o") % int(n_(v))
            if conv == "b":
                return format(int(n_(v)), "b")
            return ("%" + spec + "s") % s_(v)
        except (TypeError, ValueError):
            return s_(v)
    return re.sub(r"%%|%([-+ 0#]*\d*(?:\.\d+)?)([sdixXcfFeEgGob])", rep, fmt)


def _array_map(it: Interp, args: list, sc: Scope) -> Any:
    f, arr = args[0], args[1] if len(args) > 1 else []
    if isinstance(arr, Unk):
        return arr
    items = list(arr.values()) if isinstance(arr, dict) else list(arr)
    out = RList(_call_value(it, f, [x], None, sc) for x in items)
    if len(out) >= 16:
        out.recipe = rec(arr) + ((_fn_label(it, f),) if _fn_label(it, f) else ())
    return out


def _fn_label(it: Interp, f: Any) -> str:
    if isinstance(f, str):
        return {"chr": "char codes", "strrev": "reverse", "base64_decode": "base64", "ord": "", "trim": ""}.get(f.lower(), f)
    if isinstance(f, Func) and f.params:
        lab = it.op_label(f.body, f.params[0][0])
        return "" if lab == "char codes" else lab
    return ""


def _call_value(it: Interp, f: Any, args: list, e: Any, sc: Scope) -> Any:
    if isinstance(f, Func):
        if f.name == "anonymous" or f.closure is not None:
            return it.call_func(f, args, sc) if not f.expr else it.block_value(f, args)
        return it.call_func(f, args, sc)
    if isinstance(f, Native):
        return f.fn(args, ("call", ("name", f.name), []), sc)
    if isinstance(f, str):
        fn = it.funcs.get(it.fkey(f))
        if fn is not None:
            return it.call_func(fn, args, sc)
        lib = it.lib_get(f)
        if isinstance(lib, Native):
            it.sinks.step(getattr(it, "cur_line", None), f"calls {f} by name", Value("str", f))
            it.called_as = (f, "")
            try:
                return lib.fn(args, ("call", ("name", f), []), sc)
            finally:
                it.called_as = None
    if isinstance(f, Unk):
        it.sinks.unresolved_(it.line_text(getattr(it, "cur_line", None)), f.why, "the function it calls is named at run time",
                             getattr(it, "cur_line", None))
        return Unk(f"the result of a function named from {f.why}")
    return None


def _create_function(it: Interp, args: list, sc: Scope) -> Any:
    params, body = (args + ["", ""])[:2]
    if isinstance(body, Unk):
        return it.run_code(body, "create_function", sc)
    it.sinks.exec_(Value("str", text(body), rec(body)), "create_function", getattr(it, "cur_line", None))
    try:
        toks = tokenize("<?php function __cf(" + s_(params) + ") {" + text(body) + "}", it.p)
        prog = Parser(toks, it.p).program()
    except (SyntaxError, IndexError):
        return None
    for st in prog:
        if st and st[0] == "func":
            it.depth += 1
            f = Func("lambda", st[3], st[4], text(body))
            it.depth -= 1
            outer = it

            def run(a: list, e: tuple, s: Scope, f: Func = f) -> Any:
                outer.depth += 1
                outer.sinks.depth = outer.depth
                try:
                    return outer.call_func(f, a, s)
                finally:
                    outer.depth -= 1
                    outer.sinks.depth = outer.depth
            return Native("lambda", run)
    return None


def _php_regex(pat: str) -> tuple[re.Pattern | None, str]:
    if len(pat) < 2:
        return None, ""
    d = pat[0]
    close = {"(": ")", "{": "}", "[": "]", "<": ">"}.get(d, d)
    j = pat.rfind(close)
    if j <= 0:
        return None, ""
    body, flags = pat[1:j], pat[j + 1:]
    fl = (re.I if "i" in flags else 0) | (re.S if "s" in flags else 0) | (re.M if "m" in flags else 0) | (re.X if "x" in flags else 0)
    try:
        return re.compile(body, fl), flags
    except re.error:
        return None, flags


def _preg_replace(it: Interp, args: list, sc: Scope) -> Any:
    pat, rep, subj = (args + [None, None, None])[:3]
    if isinstance(subj, Unk) or isinstance(pat, Unk) or isinstance(rep, Unk):
        if isinstance(pat, str) and _php_regex(pat)[1] and "e" in _php_regex(pat)[1]:
            return it.run_code(rep if isinstance(rep, Unk) else subj, "preg_replace /e", sc)
        u = next(x for x in (pat, rep, subj) if isinstance(x, Unk))
        return Unk(u.why, u.recipe)
    rx, flags = _php_regex(s_(pat))
    if rx is None:
        return subj
    s = s_(subj)
    if "e" in flags:
        # the replacement is PHP code, run for each match (with \1… put in)
        out = []
        last = 0
        for m in rx.finditer(s):
            code = re.sub(r"\\(\d)|\$(\d)", lambda mm: (m.group(int(mm.group(1) or mm.group(2))) or ""), s_(rep))
            res = it.run_code(tag(code, rec(rep) or rec(subj)), "preg_replace /e", sc)
            out.append(s[last:m.start()] + s_(res if not isinstance(res, Unk) else ""))
            last = m.end()
        return "".join(out) + s[last:]
    r = re.sub(r"\$(\d+)|\$\{(\d+)\}", lambda m: "\\" + (m.group(1) or m.group(2)), s_(rep))
    try:
        out_s = rx.sub(r, s)
    except (re.error, IndexError):
        return subj
    if len(s) >= 16 and out_s != s:
        return tag(out_s, rec(subj) + (f"preg_replace({s_(pat)[:16]})",))
    return out_s


def _preg_replace_cb(it: Interp, args: list, sc: Scope) -> Any:
    pat, cb, subj = (args + [None, None, None])[:3]
    rx, _f = _php_regex(s_(pat))
    if rx is None or isinstance(subj, Unk):
        return subj
    return rx.sub(lambda m: s_(_call_value(it, cb, [RList([m.group(0), *[g or "" for g in m.groups()]])], None, sc)), s_(subj))


def _php_open(it: Interp, args: list, e: tuple) -> Any:
    path = args[0] if args else ""
    name = it.callee_name(e[1]).lower()
    if isinstance(path, str) and re.match(r"(?i)https?://|ftp://", path):
        return it.download(path, name)
    if isinstance(path, str) and path.startswith("php://input"):
        return Unk("the web request (php://input)")
    if isinstance(path, str) and path.startswith("data:"):
        m = re.match(r"data:[^,]*?(;base64)?,(.*)", path, re.S)
        if m:
            return lat(T.b64decode(m.group(2))) if m.group(1) else urllib.parse.unquote(m.group(2))
    if name == "fopen":
        mode = s_(args[1]) if len(args) > 1 else "r"
        if any(c in mode for c in "wax+"):
            h = Obj("file", path=s_(path), mode=mode, data="", sink="fwrite")
            it.files[id(h)] = h
            return h
    if isinstance(path, str) and (path == "__FILE__" or path.endswith(".php")) and path in ("__FILE__",):
        return tag(it.top, ("the script's own file",))
    if isinstance(path, Unk):
        return Unk(f"the content of a file or URL named by {path.why}")
    return Unk(f"the content of {s_(path)} (a file on the server)")


def _fwrite(it: Interp, args: list) -> Any:
    h = args[0] if args else None
    data = args[1] if len(args) > 1 else ""
    if isinstance(h, Obj) and h.kind == "file":
        if isinstance(data, Unk):
            h.st["data"] = data
        elif not isinstance(h.st.get("data"), Unk):
            h.st["data"] = it_keep(data, s_(h.st.get("data") or "") + s_(data)) if rec(data) else s_(h.st.get("data") or "") + s_(data)
            if rec(data) and not rec(h.st["data"]):
                h.st["data"] = tag(h.st["data"], rec(data))
        return len(s_(data)) if not isinstance(data, Unk) else 0
    if isinstance(h, Obj) and h.kind == "socket":
        return 0
    return 0


def _curl_setopt(args: list) -> bool:
    if len(args) >= 3 and isinstance(args[0], Obj) and s_(args[1]).upper() in ("CURLOPT_URL", "10002"):
        args[0].st["url"] = args[2]
    return True


def _socket(it: Interp, args: list, e: tuple) -> Obj:
    host = args[0] if args else ""
    port = args[1] if len(args) > 1 else ""
    if isinstance(host, dict):
        port = host.get("PeerPort", "")
        host = host.get("PeerAddr", "")
    h = s_(host) if not isinstance(host, Unk) else f"<{host.why}>"
    it.sinks.download(Value("str", f"tcp://{h}:{s_(port)}"), "socket", "connects to it (a reverse shell / C2)",
                      getattr(it, "cur_line", None))
    return Obj("socket", host=h)


def _openssl_decrypt(it: Interp, args: list) -> Any:
    data, method, key = (args + ["", "", ""])[:3]
    opts = int(n_(args[3])) if len(args) > 3 else 0
    iv = args[4] if len(args) > 4 else ""
    for x in (data, method, key, iv):
        if isinstance(x, Unk):
            return Unk(x.why, x.recipe)
    m = re.match(r"(?i)(aes|des-ede3|des|bf|rc4|chacha20)(?:-(\d+))?(?:-(cbc|ecb|ctr|cfb|ofb|gcm))?", s_(method))
    if not m:
        return False
    d = raw(data)
    if not opts & 1:
        try:
            d = T.b64decode(d)
        except T.TransformError:
            return False
    alg = {"des-ede3": "3des"}.get(m.group(1).lower(), m.group(1).lower())
    k = raw(key)
    bits = int(m.group(2)) if m.group(2) else (128 if alg == "aes" else 0)
    if alg == "aes":
        k = (k + b"\x00" * 32)[:bits // 8]
    try:
        out = T.rc4(d, k) if alg == "rc4" else T.decrypt(alg, d, k, raw(iv) or None, (m.group(3) or "cbc").lower(),
                                                          "none" if opts & 2 else "pkcs7")
    except T.TransformError as exc:
        it.errors.append(f"openssl_decrypt: {exc}")
        return False
    return tag(lat(out), rec(data) + ((("base64",) if not opts & 1 else ()) + (f"{s_(method).lower()}(key {len(k)} bytes)",)))


def _php_echo(it: Interp, args: list, e: tuple) -> Any:
    name = it.callee_name(e[1]).lower() if e[0] == "call" else ""
    if name in ("die", "exit"):
        raise _Die()
    return 1


def _php_include(it: Interp, path: Any, sc: Scope) -> Any:
    if isinstance(path, str) and path.startswith("data:"):
        m = re.match(r"data:[^,]*?(;base64)?,(.*)", path, re.S)
        if m:
            code = lat(T.b64decode(m.group(2))) if m.group(1) else urllib.parse.unquote(m.group(2))
            return it.run_code(step(path, "data: URI", code), "include data:", sc)
    if isinstance(path, str) and re.match(r"(?i)https?://|ftp://", path):
        return it.run_code(it.download(path, "include"), "include", sc)
    return True


def _unpack_step(args: list) -> Any:
    fmt, data = s_(args[0]), args[1] if len(args) > 1 else ""
    out = unpack(fmt, data)
    lab = {"m": "base64", "m0": "base64", "u": "uudecode", "H*": "hex", "h*": "hex (low nybble first)"}.get(fmt.strip())
    if lab and out and isinstance(out[0], str) and len(out[0]) >= 16:
        out[0] = step(data, lab, out[0])
    out.recipe = rec(data) + ((lab,) if lab else ())
    return out


def _perl_split(args: list) -> RList:
    pat, s = args[0], s_(args[1]) if len(args) > 1 else ""
    if isinstance(pat, tuple) and pat[0] == "re":
        if pat[1] == "":
            return RList(list(s))
        try:
            return RList(re.split(pat[1], s))
        except re.error:
            return RList([s])
    sp = s_(pat)
    if sp == "":
        return RList(list(s))
    if sp == " ":
        return RList(s.split())
    return RList(s.split(sp))


def _perl_reverse(args: list) -> Any:
    if len(args) == 1 and isinstance(args[0], str):
        return step(args[0], "reverse", args[0][::-1]) if len(args[0]) >= 16 else args[0][::-1]
    out = RList(reversed(args))
    out.recipe = rec(args[0]) if args else ()
    if len(args) == 1 and isinstance(args[0], list):
        out = RList(reversed(args[0]))
        out.recipe = rec(args[0]) + ("reverse",)
    elif len(out) >= 16:
        out.recipe = out.recipe + ("reverse",)
    return out


def _perl_map(it: Interp, args: list, sc: Scope) -> RList:
    if not args:
        return RList()
    f = args[0]
    items = args[1:]
    out = RList()
    for x in items:
        v = it.block_value(f, [x]) if isinstance(f, Func) else x
        if isinstance(v, list):
            out.extend(v)
        else:
            out.append(v)
    if len(out) >= 16:
        lab = it.op_label(f.body, "_") if isinstance(f, Func) else ""
        src_rec = rec(items[0]) if len(items) == 1 else ()
        out.recipe = src_rec + ((lab,) if lab and lab != "char codes" else ())
    return out


def _perl_push(it: Interp, e: tuple, args: list, sc: Scope) -> int:
    if e[0] == "call" and e[2] and e[2][0][0] == "var":
        key = it.var_key(e[2][0], sc)
        arr = it.lookup(key, sc)
        if not isinstance(arr, list):
            arr = RList()
            it.set_name(key, arr, sc)
        arr.extend(args[1:])
        return len(arr)
    return 0


def _perl_open(it: Interp, e: tuple, args: list, sc: Scope) -> Any:
    if not args:
        return 0
    mode, path = "", ""
    if len(args) >= 3:
        mode, path = s_(args[1]), args[2]
    elif len(args) == 2:
        spec = s_(args[1]) if not isinstance(args[1], Unk) else ""
        m = re.match(r"\s*(\+?[<>]{1,2}|\|)?\s*(.*?)\s*(\|)?\s*$", spec)
        mode, path = ((m.group(1) or "") + (m.group(3) or "")), m.group(2) if m else spec
    if "|" in mode:
        it.launch(path, "open (pipe)")
        h = Obj("file", path="pipe", mode="w", data=None, sink="pipe")
    else:
        h = Obj("file", path=s_(path), mode="w" if ">" in mode else "r", data="" if ">" in mode else None, sink="open + print")
    target = e[2][0] if e[0] == "call" and e[2] else None
    if target is not None:
        if target[0] == "name":
            it.g.vars["FH:" + target[1]] = h
        else:
            it.assign(target, h, sc)
    it.files[id(h)] = h
    return 1


def _perl_print(it: Interp, e: tuple, args: list, sc: Scope) -> Any:
    # print FH $data  /  print $fh $data  /  print {$fh} $data
    if e[0] == "call" and e[2]:
        first = e[2][0]
        h = None
        if first[0] == "name" and ("FH:" + first[1]) in it.g.vars:
            h = it.g.vars["FH:" + first[1]]
            args = args[1:]
        elif first[0] in ("var", "name") and isinstance(args[0] if args else None, Obj):
            h = args[0]
            args = args[1:]
        if h is not None and h.kind == "file":
            data = "".join(s_(x) for x in args if not isinstance(x, Unk))
            if any(isinstance(x, Unk) for x in args):
                h.st["data"] = next(x for x in args if isinstance(x, Unk))
            elif h.st.get("path") == "pipe":
                it.launch(tag(data, next((rec(x) for x in args if rec(x)), ())), "print to a command")
            else:
                r = next((rec(x) for x in args if rec(x)), ())
                cur = h.st.get("data") or ""
                h.st["data"] = tag(s_(cur) + data, rec(cur) or r)
    return 1


def _file_open(it: Interp, args: list, sc: Scope, e: tuple) -> Any:
    path = args[0] if args else ""
    mode = s_(args[1]) if len(args) > 1 else "r"
    if any(c in mode for c in "wa"):
        h = Obj("file", path=s_(path) if not isinstance(path, Unk) else f"<{path.why}>", mode=mode, data="", sink="File.open / io.open")
        it.files[id(h)] = h
        return h
    return Unk(f"the content of {s_(path)} (a file on the victim's machine)")


def _lua_load(it: Interp, args: list, sc: Scope) -> Any:
    code = args[0] if args else ""
    if isinstance(code, Func):
        # load(function) — pieces from a reader
        parts = []
        for _ in range(10000):
            v = it.call_func(code, [], sc)
            if not v:
                break
            parts.append(s_(v))
        code = "".join(parts)
    src = code
    outer = it

    def run(a: list, e: tuple, s: Scope) -> Any:
        return outer.run_code(src, "load", s)
    if isinstance(code, Unk):
        it.run_code(code, "load", sc)
        return Native("chunk", lambda a, e, s: None)
    # the chunk is reported when it is created; it runs when called
    line = getattr(it, "cur_line", None)
    if not isinstance(code, Unk):
        it.sinks.step(line, "load() builds a chunk", Value("str", text(code)[:200], rec(code)))
    return Native("chunk", run)


def _char_codes(args: list) -> Any:
    if len(args) == 1 and isinstance(args[0], list):
        args = list(args[0])
    out = "".join(chr(int(n_(x)) & 0xFF) for x in args)
    return tag(out, ("char codes",)) if len(out) >= 16 else out


def _lua_byte(args: list) -> Any:
    s = s_(args[0])
    i = int(n_(args[1])) if len(args) > 1 else 1
    j = int(n_(args[2])) if len(args) > 2 else i
    vals = [ord(c) for c in s[i - 1:j]]
    return vals[0] if len(vals) == 1 else RList(vals)


def _lua_sub(s: str, args: list) -> str:
    i = int(n_(args[0])) if args else 1
    j = int(n_(args[1])) if len(args) > 1 else -1
    n = len(s)
    if i < 0:
        i = max(1, n + i + 1)
    if j < 0:
        j = n + j + 1
    i = max(i, 1)
    return s[i - 1:j]


def _lua_pat(p: str) -> str:
    out = []
    i = 0
    while i < len(p):
        c = p[i]
        if c == "%" and i + 1 < len(p):
            d = p[i + 1]
            out.append({"a": "[A-Za-z]", "d": r"\d", "s": r"\s", "w": r"\w", "x": "[0-9A-Fa-f]", "l": "[a-z]",
                        "u": "[A-Z]", "p": r"[^\w\s]", "c": r"[\x00-\x1f]", ".": r"\.", "%": "%"}.get(d, re.escape(d)))
            i += 2
            continue
        if c == "-":
            out.append("*?")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _lua_gsub(it: Interp, args: list, sc: Scope) -> Any:
    s, pat, rep = (args + ["", "", ""])[:3]
    if isinstance(s, Unk):
        return s
    try:
        rx = re.compile(_lua_pat(s_(pat)))
    except re.error:
        return s

    def f(m: re.Match) -> str:
        if isinstance(rep, (Func, Native)):
            v = _call_value(it, rep, [m.group(1) if m.groups() else m.group(0)], None, sc)
            return s_(v) if v is not None else m.group(0)
        if isinstance(rep, dict):
            v = rep.get(m.group(0))
            return s_(v) if v is not None else m.group(0)
        return re.sub(r"%(\d)", lambda mm: m.group(int(mm.group(1))) if int(mm.group(1)) else m.group(0), s_(rep))
    out = rx.sub(f, s_(s))
    r = tag(out, rec(s) + ((f"gsub({s_(pat)[:12]})",) if out != s_(s) and len(out) >= 16 else ())) if (rec(s) or out != s_(s)) and len(out) >= 16 else out
    return RList([r, 0])


def _lua_gmatch(args: list) -> Any:
    s, pat = s_(args[0]), s_(args[1]) if len(args) > 1 else ""
    try:
        it_ = iter(re.finditer(_lua_pat(pat), s))
    except re.error:
        it_ = iter(())

    def nxt(a: list, e: tuple, sc: Scope) -> Any:
        m = next(it_, None)
        if m is None:
            return None
        return m.group(1) if m.groups() else m.group(0)
    return Native("gmatch", nxt)


def _red(args: list, f: Callable[[int, int], int]) -> int:
    r = int(n_(args[0]))
    for x in args[1:]:
        r = f(r, int(n_(x)))
    return r & 0xFFFFFFFF


def _ahk_substr(s: str, args: list) -> str:
    st = int(n_(args[0])) if args else 1
    if st <= 0:
        st = len(s) + st
    else:
        st -= 1
    if len(args) > 1:
        ln = int(n_(args[1]))
        return s[st:st + ln] if ln >= 0 else s[st:len(s) + ln]
    return s[st:]


def _ahk_dllcall(it: Interp, args: list) -> Any:
    fn = s_(args[0]).lower() if args else ""
    if any(x in fn for x in ("virtualalloc", "heapalloc")):
        h = Obj("buffer", data=bytearray(), alloc=True)
        it.ahk_mem = h
        return h
    if any(x in fn for x in ("rtlmovememory", "rtlcopymemory", "writeprocessmemory")):
        for x in args[1:]:
            if isinstance(x, (str, list)) and len(x) >= 32:
                it.sinks.load(it.to_value(x), f"DllCall {s_(args[0])}", line=getattr(it, "cur_line", None))
        return 0
    if any(x in fn for x in ("createthread", "callwindowproc", "enumwindows", "createremotethread")):
        mem = getattr(it, "ahk_mem", None)
        if mem is not None and mem.st["data"]:
            it.sinks.load(Value("bytes", bytes(mem.st["data"]), ("NumPut bytes",)), f"DllCall {s_(args[0])}",
                          line=getattr(it, "cur_line", None))
        return 0
    if "cryptstringtobinary" in fn:
        return 1
    if "urldownloadtofile" in fn:
        for x in args[1:]:
            if isinstance(x, str) and re.match(r"(?i)https?://", x):
                it.download(x, "URLDownloadToFile", "saves it")
        return 0
    return 0


def _ahk_numput(it: Interp, args: list) -> Any:
    # NumPut(value, address, offset, "UChar")  /  NumPut("UChar", value, address, offset) (v2)
    if args and isinstance(args[0], str) and args[0].lower() in ("uchar", "char", "uint", "int", "ptr", "ushort"):
        typ, val, addr, off = args[0], args[1] if len(args) > 1 else 0, args[2] if len(args) > 2 else None, args[3] if len(args) > 3 else 0
    else:
        val, addr = args[0] if args else 0, args[1] if len(args) > 1 else None
        off = args[2] if len(args) > 2 and not isinstance(args[2], str) else 0
        typ = next((x for x in args[2:] if isinstance(x, str)), "UPtr")
    buf = addr if isinstance(addr, Obj) else getattr(it, "ahk_mem", None)
    if buf is None or isinstance(val, Unk):
        return 0
    size = {"uchar": 1, "char": 1, "ushort": 2, "short": 2, "uint": 4, "int": 4}.get(s_(typ).lower(), 8)
    o = int(n_(off))
    d = buf.st["data"]
    if o + size > MAX_STR:
        return 0
    if len(d) < o + size:
        d.extend(b"\x00" * (o + size - len(d)))
    d[o:o + size] = (int(n_(val)) & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
    return o + size


# --- methods of values (Ruby / Lua / AutoHotkey objects) ---------------------------------------------------
def _methods(it: Interp, obj: Any, name: str, args: list, block: Func | None) -> Any:  # noqa: C901, PLR0911, PLR0912
    p = it.p.name
    if isinstance(obj, Unk):
        return obj
    nm = name.rstrip("!?")
    if isinstance(obj, str):
        s = obj
        if nm in ("reverse",):
            return step(s, "reverse", s[::-1]) if len(s) >= 16 else s[::-1]
        if nm in ("unpack", "unpack1"):
            out = _unpack_step([s_(args[0]) if args else "", s])
            return out[0] if nm == "unpack1" or (out and len(out) == 1 and isinstance(out[0], str)) else out
        if nm in ("gsub", "sub", "tr", "delete", "squeeze"):
            return _ruby_gsub(it, s, nm, args, block)
        if nm in ("chars", "each_char", "split"):
            if nm == "split" and args:
                sep = args[0]
                parts = s.split(s_(sep)) if s_(sep) else list(s)
                out = RList(parts)
            else:
                out = RList(list(s))
            out.recipe = rec(s)
            if block is not None:
                return _ruby_iter(it, out, "each", block)
            return out
        if nm in ("bytes", "each_byte"):
            out = RList(raw(s))
            out.recipe = rec(s)
            if block is not None:
                return _ruby_iter(it, out, "each", block)
            return out
        if nm in ("ord",):
            return ord(s[0]) if s else 0
        if nm in ("hex",):
            return int(re.sub(r"[^0-9a-fA-F]", "", s) or "0", 16)
        if nm in ("to_i",):
            return int(n_(s)) if not args else int(s or "0", int(n_(args[0])))
        if nm in ("to_s", "to_str", "b", "force_encoding", "dup", "freeze", "strip", "chomp", "encode", "scrub"):
            return it_keep(s, s.strip() if nm == "strip" else s)
        if nm in ("upcase", "upper"):
            return s.upper()
        if nm in ("downcase", "lower"):
            return s.lower()
        if nm in ("length", "size", "len"):
            return len(s)
        if nm == "sub" and p == "lua":
            return _lua_sub(s, args)
        if nm == "byte":
            return _lua_byte([s] + args)
        if nm == "rep":
            return _rep(s, int(n_(args[0])))
        if nm in ("gsub",) and p == "lua":
            return _lua_gsub(it, [s] + args, it.g)
        if nm == "format" and p == "lua":
            return _sprintf(s, args)
        if nm == "gmatch":
            return _lua_gmatch([s] + args)
        if nm == "each_slice" or nm == "scan":
            if nm == "scan" and args and isinstance(args[0], tuple):
                try:
                    return RList(re.findall(args[0][1], s))
                except re.error:
                    return RList()
            n = int(n_(args[0])) if args else 1
            out = RList(_chunks(s, n))
            return out
        if nm == "*":
            return s * int(n_(args[0]))
        if nm in ("pack",):
            return s
        if nm == "insert":
            return s
        return None
    if isinstance(obj, list):
        arr = obj
        if nm in ("pack",):
            out = pack(s_(args[0]) if args else "", list(arr))
            lab = {"m": "base64 encode", "H*": "hex", "C*": "char codes", "c*": "char codes", "U*": "char codes"}.get(s_(args[0]) if args else "", f"pack({s_(args[0]) if args else ''})")
            if lab == "hex" and arr and isinstance(arr[0], str):
                return step(arr[0], "hex", out) if len(out) >= 16 else out
            return tag(out, rec(arr) + (lab,)) if len(out) >= 16 else out
        if nm in ("join",):
            out = (s_(args[0]) if args else "").join(s_(x) for x in arr)
            return tag(out, rec(arr)) if rec(arr) and len(out) >= 16 else out
        if nm in ("reverse",):
            out = RList(reversed(arr))
            out.recipe = rec(arr) + (("reverse",) if len(arr) >= 16 else ())
            return out
        if nm in ("map", "collect", "each", "each_with_index", "select", "reject", "each_slice", "inject", "reduce", "sum"):
            return _ruby_iter(it, arr, nm, block, args)
        if nm in ("length", "size", "count"):
            return len(arr)
        if nm in ("first",):
            return arr[0] if arr else None
        if nm in ("last",):
            return arr[-1] if arr else None
        if nm in ("flatten", "compact", "to_a"):
            return RList(arr)
        if nm == "push" or nm == "<<":
            arr.extend(args)
            return arr
        return None
    if isinstance(obj, dict):
        if nm in ("each", "map"):
            return _ruby_iter(it, RList(RList([k, v]) for k, v in obj.items()), nm, block)
        if nm in ("keys",):
            return RList(obj.keys())
        if nm in ("values",):
            return RList(obj.values())
        if nm in ("concat",) and p == "lua":
            return _implode(it, [args[0] if args else "", obj])
        return obj.get(name)
    if isinstance(obj, (int, float)):
        if nm in ("chr",):
            return chr(int(obj) & 0xFF)
        if nm in ("to_s",):
            return format(int(obj), {2: "b", 8: "o", 16: "x"}.get(int(n_(args[0])), "d")) if args else s_(obj)
        if nm in ("times",) and block is not None:
            return _ruby_iter(it, RList(range(int(obj))), "each", block)
        if nm in ("^",):
            return int(obj) ^ int(n_(args[0]))
        return None
    if isinstance(obj, Obj):
        return _obj_member(it, obj, name, args)
    return None


def _ruby_iter(it: Interp, arr: list, nm: str, block: Func | None, args: list | None = None) -> Any:
    if block is None:
        return arr
    if nm in ("map", "collect"):
        out = RList(it.block_value(block, [x]) for x in list(arr))
        lab = it.op_label(block.body, block.params[0][0]) if block.params else ""
        lab = it.resolve_label(lab, block.closure)
        out.recipe = rec(arr) + ((lab,) if lab and lab != "char codes" and len(out) >= 16 else ())
        return out
    if nm in ("select", "reject"):
        return RList(x for x in arr if truthy(it.block_value(block, [x])) == (nm == "select"))
    if nm in ("inject", "reduce", "sum"):
        acc = args[0] if args else (0 if nm == "sum" else None)
        for x in arr:
            acc = it.block_value(block, [acc, x]) if acc is not None else x
        return acc
    tg = it.loop_targets(block.body)
    pre = [(t, op, rec(arr)) for t, _s, op in tg]
    for i, x in enumerate(list(arr)):
        it.block_value(block, [x, i] if nm == "each_with_index" else [x])
    if block.closure is not None:
        it.loop_after(pre, block.closure)
    return arr


def _ruby_gsub(it: Interp, s: str, nm: str, args: list, block: Func | None) -> Any:
    if nm in ("tr", "delete", "squeeze"):
        if nm == "tr" and len(args) >= 2:
            src, dst = _tr_expand(s_(args[0])), _tr_expand(s_(args[1]))
            table = {ord(c): dst[min(i, len(dst) - 1)] for i, c in enumerate(src)} if dst else {}
            out = s.translate(table)
            return tag(out, rec(s) + (f"tr({s_(args[0])[:12]} → {s_(args[1])[:12]})",)) if len(out) >= 16 else out
        if nm == "delete" and args:
            chars = set(_tr_expand(s_(args[0])))
            return "".join(c for c in s if c not in chars)
        return s
    pat = args[0] if args else ""
    rep = args[1] if len(args) > 1 else None
    rx = re.compile(pat[1]) if isinstance(pat, tuple) else re.compile(re.escape(s_(pat)))

    def f(m: re.Match) -> str:
        if block is not None:
            return s_(it.block_value(block, [m.group(0)]))
        if isinstance(rep, dict):
            return s_(rep.get(m.group(0), ""))
        return re.sub(r"\\(\d)", lambda mm: m.group(int(mm.group(1))) or "", s_(rep))
    out = rx.sub(f, s, count=0 if nm == "gsub" else 1)
    if len(s) >= 16 and out != s:
        return tag(out, rec(s) + (f"gsub({(pat[1] if isinstance(pat, tuple) else s_(pat))[:12]})",))
    return out


def _obj_member(it: Interp, obj: Obj, name: str, args: list) -> Any:
    nm = name.lower()
    if obj.kind == "file":
        if nm in ("write", "print", "puts", "<<", "syswrite"):
            for x in args:
                if isinstance(x, Unk):
                    obj.st["data"] = x
                elif not isinstance(obj.st.get("data"), Unk):
                    cur = obj.st.get("data") or ""
                    obj.st["data"] = tag(s_(cur) + s_(x) + ("\n" if nm == "puts" else ""), rec(cur) or rec(x))
            return obj
        if nm == "close":
            it.flush(obj)
            return True
        return None
    if obj.kind == "com":
        prog = s_(obj.st.get("progid", "")).lower()
        if nm in ("run", "exec") and "shell" in prog:
            return it.launch(args[0] if args else "", f"{obj.st.get('progid')}.{name}")
        if nm == "shellexecute":
            return it.launch(" ".join(s_(x) for x in args[:2]), "Shell.Application.ShellExecute")
        if nm == "open" and "http" in prog:
            obj.st["url"] = args[1] if len(args) > 1 else ""
            return None
        if nm == "send" and "http" in prog:
            it.download(obj.st.get("url", ""), obj.st.get("progid", "HTTP"))
            return None
        if nm in ("responsetext", "responsebody"):
            return Unk(f"the content downloaded from {s_(obj.st.get('url', ''))}")
        return None
    if obj.kind == "buffer":
        if nm in ("ptr", "size"):
            return obj
    return None


def resolve_lang(code: str, lang: str, location: str = "") -> Sinks:
    prof = PROFILES[lang]
    s = Sinks(prof.name if prof.name != "ahk" else "autohotkey")
    code = code.lstrip("\ufeff")
    it = Interp(s, code, prof)
    try:
        it.run(code)
    except RecursionError:
        it.errors.append("recursion")
    s.errors = it.errors  # type: ignore[attr-defined]
    s.stats = {"steps": it.steps, "seconds": round(time.monotonic() - it.t0, 2)}  # type: ignore[attr-defined]
    return s


def resolver(lang: str) -> Callable[[str, str], Sinks]:
    return lambda code, location="": resolve_lang(code, lang, location)
