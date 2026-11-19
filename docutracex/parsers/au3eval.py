"""Static string decryption for obfuscated AutoIt scripts.

Obfuscated AutoIt (DarkGate and other loaders, once AutoIt-Ripper has recovered the
script) hides every string — DLL and API names, URLs, IPs, the payload's key — behind
calls to the script's own decoder functions: ``F("C4B2CAC7…", "key")``. Those
functions are pure: loops, string slicing, character codes and bit arithmetic, wrapped
in junk (state machines, dead branches, ``Execute("StringLen('x')")``).

This module is a small **evaluator for that subset of AutoIt**, written in Python:
it parses the script's functions and runs a decoder on constant arguments — with no
access to anything outside its own values. Calls to the outside world never happen:
``DllCall`` returns zeros, ``Random`` its lower bound, macros fixed values; file,
registry, process and network functions are not implemented, and a function that
needs one is simply not decrypted. Every run has a step budget.

``deobfuscate(code)`` replaces every decoder call on literal arguments by the string
it returns (twice, for calls nested in calls), and lists what was recovered.
"""

from __future__ import annotations

import math
import re
from typing import Any

MAX_STEPS = 400_000          # per decoder call
MAX_DEPTH = 40
MAX_STR = 1 << 20
MAX_CALLS = 20_000           # decoder calls replaced per script
MAX_SCRIPT = 16 * 1024 * 1024
MAX_SECONDS = 90             # the whole script


class Unsupported(Exception):
    """Something outside the pure subset (or the budget): this call is not decrypted."""


class _Exit(Exception):
    def __init__(self, kind: str, n: int = 1, value: Any = None) -> None:
        self.kind, self.n, self.value = kind, n, value


# --------------------------------------------------------------------------- tokens

_TOK = re.compile(r"""
    (?P<ws>[ \t]+)
  | (?P<num>0[xX][0-9A-Fa-f]+|\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?|\d+(?:[eE][+-]?\d+)?)
  | (?P<str>"(?:[^"]|"")*"|'(?:[^']|'')*')
  | (?P<var>\$\w+)
  | (?P<mac>@\w+)
  | (?P<id>[A-Za-z_]\w*)
  | (?P<op>&=|\+=|-=|\*=|/=|==|<>|<=|>=|[-+*/^&=<>()\[\],?:.])
""", re.X)


def _tokens(line: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    while pos < len(line):
        m = _TOK.match(line, pos)
        if not m:
            if line[pos] == ";":
                break                                    # comment to end of line
            raise Unsupported(f"token at {line[pos:pos + 10]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        out.append((kind, m.group(0)))
    return out


def _lines(code: str) -> list[str]:
    """Logical lines: continuations (`` _``) joined, #cs/#ce blocks and directives dropped."""
    out, buf, skip = [], "", False
    for raw in code.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        s = raw.strip()
        low = s.lower()
        if low.startswith(("#cs", "#comments-start")):
            skip = True
            continue
        if low.startswith(("#ce", "#comments-end")):
            skip = False
            continue
        if skip:
            continue
        if s.startswith("#") and not buf:
            continue
        if s.endswith(" _") or s == "_":
            buf += s[:-1] + " "
            continue
        out.append(buf + s)
        buf = ""
    if buf:
        out.append(buf)
    return out


# --------------------------------------------------------------------------- expressions

class _P:
    """Recursive-descent parser over one line's tokens → a small tuple AST."""

    def __init__(self, toks: list[tuple[str, str]]) -> None:
        self.t, self.i = toks, 0

    def peek(self, k: int = 0) -> tuple[str, str] | None:
        j = self.i + k
        return self.t[j] if j < len(self.t) else None

    def take(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise Unsupported("unexpected end")
        self.i += 1
        return tok

    def is_op(self, v: str) -> bool:
        tok = self.peek()
        return tok is not None and tok[0] == "op" and tok[1] == v

    def is_kw(self, v: str) -> bool:
        tok = self.peek()
        return tok is not None and tok[0] == "id" and tok[1].lower() == v

    def expect(self, v: str) -> None:
        if not self.is_op(v):
            raise Unsupported(f"expected {v}")
        self.i += 1

    def expr(self) -> tuple:
        e = self.or_()
        if self.is_op("?"):
            self.i += 1
            a = self.expr()
            self.expect(":")
            b = self.expr()
            return ("?", e, a, b)
        return e

    def or_(self) -> tuple:
        e = self.and_()
        while self.is_kw("or"):
            self.i += 1
            e = ("or", e, self.and_())
        return e

    def and_(self) -> tuple:
        e = self.cmp()
        while self.is_kw("and"):
            self.i += 1
            e = ("and", e, self.cmp())
        return e

    def cmp(self) -> tuple:
        e = self.cat()
        while self.peek() and self.peek()[0] == "op" and self.peek()[1] in ("=", "==", "<>", "<", ">", "<=", ">="):
            op = self.take()[1]
            e = ("cmp", op, e, self.cat())
        return e

    def cat(self) -> tuple:
        e = self.add()
        while self.is_op("&"):
            self.i += 1
            e = ("&", e, self.add())
        return e

    def add(self) -> tuple:
        e = self.mul()
        while self.peek() and self.peek()[0] == "op" and self.peek()[1] in ("+", "-"):
            op = self.take()[1]
            e = (op, e, self.mul())
        return e

    def mul(self) -> tuple:
        e = self.pow()
        while self.peek() and self.peek()[0] == "op" and self.peek()[1] in ("*", "/"):
            op = self.take()[1]
            e = (op, e, self.pow())
        return e

    def pow(self) -> tuple:
        e = self.unary()
        while self.is_op("^"):
            self.i += 1
            e = ("^", e, self.unary())
        return e

    def unary(self) -> tuple:
        if self.is_op("-"):
            self.i += 1
            return ("neg", self.unary())
        if self.is_op("+"):
            self.i += 1
            return self.unary()
        if self.is_kw("not"):
            self.i += 1
            return ("not", self.unary())
        return self.postfix()

    def postfix(self) -> tuple:
        e = self.atom()
        while self.is_op("["):
            self.i += 1
            idx = self.expr()
            self.expect("]")
            e = ("idx", e, idx)
        return e

    def atom(self) -> tuple:
        kind, v = self.take()
        if kind == "num":
            return ("lit", _num(v))
        if kind == "str":
            q = v[0]
            return ("lit", v[1:-1].replace(q + q, q))
        if kind == "var":
            return ("var", v[1:].lower())
        if kind == "mac":
            return ("mac", v[1:].lower())
        if kind == "op" and v == "(":
            e = self.expr()
            self.expect(")")
            return e
        if kind == "op" and v == "[":                   # array literal [a, b, …]
            items = []
            while not self.is_op("]"):
                items.append(self.expr())
                if self.is_op(","):
                    self.i += 1
            self.expect("]")
            return ("arr", items)
        if kind == "id":
            low = v.lower()
            if low in ("true", "false"):
                return ("lit", low == "true")
            if low == "default":
                return ("lit", None)
            if self.is_op("("):
                self.i += 1
                args = []
                while not self.is_op(")"):
                    args.append(self.expr())
                    if self.is_op(","):
                        self.i += 1
                    elif not self.is_op(")"):
                        raise Unsupported("bad call")
                self.expect(")")
                return ("call", low, args)
            return ("lit", v)                           # bare word (a function name passed as a value)
        raise Unsupported(f"unexpected {v}")


def _num(v: str) -> int | float:
    if v[:2].lower() == "0x":
        n = int(v, 16)
        return n - (1 << 32) if len(v) <= 10 and n >= 1 << 31 else n   # 0xFFFFFFFF is -1 in AutoIt
    if any(c in v for c in ".eE"):
        return float(v)
    n = int(v)
    # a 32-bit token printed unsigned by the decompiler: 4294967196 is -100 in the compiled script
    return n - (1 << 32) if (1 << 31) <= n < (1 << 32) else n


def _expr(line_or_toks: Any) -> tuple:
    p = _P(line_or_toks if isinstance(line_or_toks, list) else _tokens(line_or_toks))
    e = p.expr()
    if p.peek() is not None:
        raise Unsupported("trailing tokens")
    return e


# --------------------------------------------------------------------------- statements

def _stmt(toks: list[tuple[str, str]]) -> tuple:
    """One simple statement (not a block opener)."""
    p = _P(toks)
    first = p.peek()
    if first is None:
        return ("nop",)
    if first[0] == "id":
        kw = first[1].lower()
        if kw in ("local", "global", "dim", "static", "const"):
            while p.peek() and p.peek()[0] == "id" and p.peek()[1].lower() in ("local", "global", "dim", "static", "const"):
                p.i += 1
            decls = []
            while p.peek() is not None:
                name = p.take()
                if name[0] != "var":
                    raise Unsupported("decl")
                dims = []
                while p.is_op("["):
                    p.i += 1
                    dims.append(p.expr() if not p.is_op("]") else ("lit", 0))
                    p.expect("]")
                init = None
                if p.is_op("="):
                    p.i += 1
                    init = p.expr()
                decls.append((name[1][1:].lower(), dims, init))
                if p.is_op(","):
                    p.i += 1
            return ("decl", decls)
        if kw == "return":
            p.i += 1
            return ("return", p.expr() if p.peek() is not None else ("lit", ""))
        if kw in ("exitloop", "continueloop"):
            p.i += 1
            n = p.expr() if p.peek() is not None else ("lit", 1)
            return (kw, n)
        if kw == "exit":
            raise Unsupported("Exit")
    if first[0] == "var":
        # assignment(s): $a = …, $a[i] = …, $a &= …; several on one line separated by commas
        assigns = []
        while p.peek() is not None:
            target = p.postfix()
            op = p.take()
            if op[0] != "op" or op[1] not in ("=", "&=", "+=", "-=", "*=", "/="):
                raise Unsupported("assignment")
            assigns.append((target, op[1], p.expr()))
            if p.is_op(","):
                p.i += 1
        return ("assign", assigns)
    e = p.expr()
    if p.peek() is not None:
        raise Unsupported("statement")
    return ("expr", e)


def _block(lines: list[str], i: int, ends: tuple[str, ...]) -> tuple[list, int, str]:
    """Statements from line ``i`` until one of ``ends`` (lower-case keywords); returns
    (statements, index of the end line, the end keyword)."""
    body: list = []
    while i < len(lines):
        line = lines[i]
        toks = _tokens(line)
        if not toks:
            i += 1
            continue
        head = toks[0][1].lower() if toks[0][0] == "id" else ""
        if head in ends:
            return body, i, head
        if head == "if":
            # If cond Then [stmt]  — single line when something follows Then
            j = next((k for k, t in enumerate(toks) if t[0] == "id" and t[1].lower() == "then"), None)
            if j is None:
                raise Unsupported("If without Then")
            cond = _expr(toks[1:j])
            if j + 1 < len(toks):
                body.append(("if", [(cond, [_stmt(toks[j + 1:])])], []))
                i += 1
                continue
            branches, other = [], []
            sub, i, end = _block(lines, i + 1, ("elseif", "else", "endif"))
            branches.append((cond, sub))
            while end == "elseif":
                t2 = _tokens(lines[i])
                j2 = next(k for k, t in enumerate(t2) if t[0] == "id" and t[1].lower() == "then")
                c2 = _expr(t2[1:j2])
                sub, i, end = _block(lines, i + 1, ("elseif", "else", "endif"))
                branches.append((c2, sub))
            if end == "else":
                other, i, end = _block(lines, i + 1, ("endif",))
            body.append(("if", branches, other))
            i += 1
            continue
        if head == "for":
            if any(t[0] == "id" and t[1].lower() == "in" for t in toks):
                k = next(k for k, t in enumerate(toks) if t[0] == "id" and t[1].lower() == "in")
                var = toks[1][1][1:].lower()
                seq = _expr(toks[k + 1:])
                sub, i, _ = _block(lines, i + 1, ("next",))
                body.append(("forin", var, seq, sub))
                i += 1
                continue
            var = toks[1][1][1:].lower()
            k_to = next(k for k, t in enumerate(toks) if t[0] == "id" and t[1].lower() == "to")
            k_step = next((k for k, t in enumerate(toks) if t[0] == "id" and t[1].lower() == "step"), None)
            start = _expr(toks[3:k_to])
            stop = _expr(toks[k_to + 1:k_step] if k_step else toks[k_to + 1:])
            step = _expr(toks[k_step + 1:]) if k_step else ("lit", 1)
            sub, i, _ = _block(lines, i + 1, ("next",))
            body.append(("for", var, start, stop, step, sub))
            i += 1
            continue
        if head == "while":
            cond = _expr(toks[1:])
            sub, i, _ = _block(lines, i + 1, ("wend",))
            body.append(("while", cond, sub))
            i += 1
            continue
        if head == "do":
            sub, i, _ = _block(lines, i + 1, ("until",))
            cond = _expr(_tokens(lines[i])[1:])
            body.append(("do", sub, cond))
            i += 1
            continue
        if head in ("switch", "select"):
            subject = _expr(toks[1:]) if head == "switch" else None
            endkw = "endswitch" if head == "switch" else "endselect"
            cases: list = []
            i += 1
            while i < len(lines) and not _tokens(lines[i]):
                i += 1
            while i < len(lines):
                t2 = _tokens(lines[i])
                h2 = t2[0][1].lower() if t2 and t2[0][0] == "id" else ""
                if h2 == endkw:
                    break
                if h2 != "case":
                    raise Unsupported("Switch body")
                if len(t2) > 1 and t2[1][0] == "id" and t2[1][1].lower() == "else":
                    conds = None
                else:
                    conds = []
                    p = _P(t2[1:])
                    while p.peek() is not None:
                        a = p.expr()
                        if p.is_kw("to"):
                            p.i += 1
                            conds.append(("range", a, p.expr()))
                        else:
                            conds.append(("eq", a))
                        if p.is_op(","):
                            p.i += 1
                sub, i, _ = _block(lines, i + 1, ("case", endkw))
                cases.append((conds, sub))
            body.append(("switch", subject, cases))
            i += 1
            continue
        if head in ("func", "endfunc"):
            raise Unsupported("nested Func")
        try:
            body.append(_stmt(toks))
        except Unsupported as exc:            # unreadable here: only a problem if this line runs
            body.append(("bad", str(exc)))
        i += 1
    if ends:
        raise Unsupported(f"missing {ends[0]}")
    return body, i, ""


_FUNC = re.compile(r"(?i)^func\s+(\w+)\s*\((.*)\)\s*$")


def parse_functions(code: str) -> dict[str, tuple[list, list, Any]]:
    """{name: (params [(name, byref, default)], body, error)} for every Func in the script;
    a function the parser cannot read keeps its error and is never evaluated."""
    lines = _lines(code)
    funcs: dict[str, tuple[list, list, Any]] = {}
    i = 0
    while i < len(lines):
        m = _FUNC.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1).lower()
        end = next((k for k in range(i + 1, len(lines)) if lines[k].strip().lower() == "endfunc"), len(lines))
        params = []
        try:
            for part in [x.strip() for x in m.group(2).split(",") if x.strip()]:
                byref = bool(re.match(r"(?i)byref\b", part))
                part = re.sub(r"(?i)^(?:byref|const)\s+", "", part)
                pn, _, dflt = part.partition("=")
                params.append((pn.strip().lstrip("$").lower(), byref, _expr(dflt.strip()) if dflt.strip() else None))
            body, _, _ = _block(lines[i + 1:end], 0, ())
            funcs[name] = (params, body, None)
        except (Unsupported, StopIteration, IndexError, RecursionError) as exc:
            funcs[name] = (params, [], str(exc) or exc.__class__.__name__)
        i = end + 1
    return funcs


# --------------------------------------------------------------------------- values

def _i32(v: Any) -> int:
    n = int(_numv(v)) & 0xFFFFFFFF
    return n - (1 << 32) if n >= 1 << 31 else n


def _numv(v: Any) -> int | float:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, bytes):
        return int.from_bytes(v[:8], "little") if v else 0
    if isinstance(v, str):
        m = re.match(r"\s*([+-]?(?:0[xX][0-9A-Fa-f]+|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+))", v)
        if not m:
            return 0
        s = m.group(1)
        if "0x" in s.lower():
            sign = -1 if s.startswith("-") else 1
            return sign * int(s.lstrip("+-"), 16)
        return float(s) if any(c in s for c in ".eE") else int(s)
    return 0


def _strv(v: Any) -> str:
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() and abs(v) < 1e15 else repr(v)
    if isinstance(v, bytes):
        return "0x" + v.hex().upper()
    if isinstance(v, list):
        return ""
    if v is None:
        return ""
    return str(v)


def _truth(v: Any) -> bool:
    if isinstance(v, str):
        return v != ""
    if isinstance(v, bytes):
        return len(v) > 0
    if isinstance(v, list):
        return False
    return bool(_numv(v))


def _norm(n: int | float) -> int | float:
    if isinstance(n, float) and n.is_integer() and abs(n) < 2 ** 53:
        return n
    return n


def _bin(v: Any) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        if v[:2].lower() == "0x" and re.fullmatch(r"0[xX](?:[0-9A-Fa-f]{2})*", v):
            return bytes.fromhex(v[2:])
        return v.encode("latin-1", "replace")
    n = _numv(v)
    if isinstance(n, float):
        import struct
        return struct.pack("<d", n)
    return (n & 0xFFFFFFFF).to_bytes(4, "little") if -2**31 <= n < 2**32 else (n & (2**64 - 1)).to_bytes(8, "little")


def _mid(s: str, start: Any, count: Any = -1) -> str:
    st = max(1, int(_numv(start)))
    c = int(_numv(count))
    return s[st - 1:] if c < 0 else s[st - 1:st - 1 + c]


def _instr(hay: str, needle: str, case: Any = 0, occ: Any = 1, start: Any = 1) -> int:
    if needle == "":
        return 0
    h, n = (hay, needle) if int(_numv(case)) == 1 else (hay.lower(), needle.lower())
    occ_n = int(_numv(occ)) or 1
    pos = max(0, int(_numv(start)) - 1)
    if occ_n < 0:
        idx = len(h)
        for _ in range(-occ_n):
            idx = h.rfind(n, 0, idx)
            if idx < 0:
                return 0
        return idx + 1
    idx = pos - 1
    for _ in range(occ_n):
        idx = h.find(n, idx + 1)
        if idx < 0:
            return 0
    return idx + 1


def _split(s: str, delims: str, flag: Any = 0) -> list:
    f = int(_numv(flag))
    if delims == "":
        parts = list(s)
    elif f & 1:                                          # whole string is the delimiter
        parts = s.split(delims)
    else:
        parts = re.split("[" + re.escape(delims) + "]", s)
    return parts if f & 2 else [len(parts), *parts]


def _round(v: Any, d: Any = 0) -> int | float:
    n, dd = float(_numv(v)), int(_numv(d))
    r = math.floor(abs(n) * 10 ** dd + 0.5) / 10 ** dd * (1 if n >= 0 else -1)
    return int(r) if dd == 0 else r


def _chr(v: Any) -> str:
    n = int(_numv(v))
    if not 0 <= n <= 0x10FFFF:
        raise Unsupported("Chr range")
    return chr(n)


_PURE = {
    "stringlen": lambda s: len(_strv(s)),
    "stringmid": lambda s, a, c=-1: _mid(_strv(s), a, c),
    "stringleft": lambda s, n: _strv(s)[:max(0, int(_numv(n)))],
    "stringright": lambda s, n: _strv(s)[-int(_numv(n)):] if int(_numv(n)) > 0 else "",
    "stringtrimleft": lambda s, n: _strv(s)[max(0, int(_numv(n))):],
    "stringtrimright": lambda s, n: _strv(s)[:-int(_numv(n))] if int(_numv(n)) > 0 else _strv(s),
    "stringreverse": lambda s: _strv(s)[::-1],
    "stringupper": lambda s: _strv(s).upper(),
    "stringlower": lambda s: _strv(s).lower(),
    "stringinstr": lambda h, n, c=0, o=1, st=1: _instr(_strv(h), _strv(n), c, o, st),
    "stringreplace": lambda s, a, b, *_: _strv(s).replace(_strv(a), _strv(b)) if not isinstance(a, (int, float))
    else _strv(s)[:int(a) - 1] + _strv(b) + _strv(s)[int(a) - 1 + len(_strv(b)):],
    "stringsplit": lambda s, d, f=0: _split(_strv(s), _strv(d), f),
    "stringstripws": lambda s, f=0: _strv(s).strip() if int(_numv(f)) & 3 == 3 else (
        _strv(s).lstrip() if int(_numv(f)) & 1 else (_strv(s).rstrip() if int(_numv(f)) & 2 else
                                                      re.sub(r"\s+", "", _strv(s)) if int(_numv(f)) & 8 else _strv(s))),
    "stringformat": lambda f, *a: _strv(f) % tuple(a) if a else _strv(f),
    "stringisdigit": lambda s: int(_strv(s).isdigit()),
    "stringisalnum": lambda s: int(_strv(s).isalnum()),
    "stringisalpha": lambda s: int(_strv(s).isalpha()),
    "stringisfloat": lambda s: int(bool(re.fullmatch(r"[+-]?\d*\.\d+", _strv(s)))),
    "stringisint": lambda s: int(bool(re.fullmatch(r"[+-]?\d+", _strv(s)))),
    "stringisxdigit": lambda s: int(bool(re.fullmatch(r"[0-9A-Fa-f]+", _strv(s)))),
    "stringisupper": lambda s: int(_strv(s).isupper()), "stringislower": lambda s: int(_strv(s).islower()),
    "stringisspace": lambda s: int(_strv(s).isspace()), "stringisascii": lambda s: int(_strv(s).isascii()),
    "stringcompare": lambda a, b, c=0: (_strv(a) > _strv(b)) - (_strv(a) < _strv(b)),
    "stringtoasciiarray": lambda s, *_: [ord(c) for c in _strv(s)],
    "stringfromasciiarray": lambda a, *_: "".join(chr(int(_numv(x))) for x in a),
    "stringaddcr": lambda s: _strv(s).replace("\n", "\r\n"),
    "stringtobinary": lambda s, f=1: _strv(s).encode("utf-16-le" if int(_numv(f)) == 2 else
                                                      ("utf-16-be" if int(_numv(f)) == 3 else
                                                       ("utf-8" if int(_numv(f)) == 4 else "latin-1")), "replace"),
    "binarytostring": lambda b, f=1: _bin(b).decode("utf-16-le" if int(_numv(f)) == 2 else
                                                     ("utf-16-be" if int(_numv(f)) == 3 else
                                                      ("utf-8" if int(_numv(f)) == 4 else "latin-1")), "replace"),
    "binary": lambda v: _bin(v), "binarylen": lambda v: len(_bin(v)),
    "binarymid": lambda v, a, c=-1: _bin(v)[int(_numv(a)) - 1:] if int(_numv(c)) < 0
    else _bin(v)[int(_numv(a)) - 1:int(_numv(a)) - 1 + int(_numv(c))],
    "isbinary": lambda v: int(isinstance(v, bytes)), "isstring": lambda v: int(isinstance(v, str)),
    "isnumber": lambda v: int(isinstance(v, (int, float)) and not isinstance(v, bool)),
    "isint": lambda v: int(isinstance(v, int) or (isinstance(v, float) and v.is_integer())),
    "isarray": lambda v: int(isinstance(v, list)), "isbool": lambda v: int(isinstance(v, bool)),
    "chr": _chr, "chrw": _chr,
    "asc": lambda s: ord(_strv(s)[0]) & 0xFF if _strv(s) else 0,
    "ascw": lambda s: ord(_strv(s)[0]) if _strv(s) else 0,
    "number": lambda v, *_: _numv(v), "int": lambda v, *_: int(_numv(v)),
    "string": lambda v: _strv(v),
    "dec": lambda s, *_: int(_strv(s), 16) if re.fullmatch(r"[0-9A-Fa-f]+", _strv(s)) else 0,
    "hex": lambda v, n=8: (_bin(v).hex().upper() if isinstance(v, bytes) else
                           format(_numv(v) & ((1 << (4 * int(_numv(n)))) - 1), f"0{int(_numv(n))}X")),
    "bitxor": lambda *a: _i32_red(a, lambda x, y: x ^ y), "bitand": lambda *a: _i32_red(a, lambda x, y: x & y),
    "bitor": lambda *a: _i32_red(a, lambda x, y: x | y), "bitnot": lambda v: _i32(~_i32(v)),
    "bitshift": lambda v, n: _i32(_i32(v) >> int(_numv(n))) if int(_numv(n)) >= 0
    else _i32(_i32(v) << -int(_numv(n))),
    "bitrotate": lambda v, n=1, s="W": _rot(v, n, _strv(s)),
    "mod": lambda a, b: _mod(a, b), "abs": lambda v: abs(_numv(v)), "round": _round,
    "floor": lambda v: math.floor(_numv(v)), "ceiling": lambda v: math.ceil(_numv(v)),
    "sqrt": lambda v: math.sqrt(_numv(v)) if _numv(v) >= 0 else 0,
    "exp": lambda v: math.exp(_numv(v)), "log": lambda v: math.log(_numv(v)) if _numv(v) > 0 else 0,
    "sin": lambda v: math.sin(_numv(v)), "cos": lambda v: math.cos(_numv(v)), "tan": lambda v: math.tan(_numv(v)),
    "ubound": lambda a, d=1: (len(a) if int(_numv(d)) == 1 else (len(a[0]) if a and isinstance(a[0], list) else 0))
    if isinstance(a, list) else 0,
    "random": lambda a=0, b=1, f=0: _numv(a),         # deterministic: the lower bound (junk only)
    "timerinit": lambda: 0, "timerdiff": lambda *_: 0, "sleep": lambda *_: 1,
    "consolewrite": lambda *_: 0, "seterror": lambda *_: 0, "setextended": lambda *_: 0,
    "isdeclared": lambda *_: 0, "isadmin": lambda: 0, "processexists": lambda *_: 0,
    "drivegetserial": lambda *_: "", "envget": lambda *_: "", "autoitsetoption": lambda *_: 0,
    "opt": lambda *_: 0, "ping": lambda *_: 0, "winexists": lambda *_: 0, "fileexists": lambda *_: 0,
    # never executed: an inert stand-in, so junk branches that call the API do not stop the decoder
    "dllcall": lambda *a: [0] * (max(1, len(a) // 2)),
    "dllstructcreate": lambda *_: [0], "dllstructgetdata": lambda *_: 0, "dllstructsetdata": lambda *_: 0,
    "dllstructgetptr": lambda *_: 0, "dllstructgetsize": lambda *_: 0, "dllopen": lambda *_: 1,
    "dllclose": lambda *_: 1,
}


def _i32_red(args: tuple, f: Any) -> int:
    vals = [_i32(a) for a in args]
    r = vals[0]
    for v in vals[1:]:
        r = _i32(f(r & 0xFFFFFFFF, v & 0xFFFFFFFF))
    return r


def _rot(v: Any, n: Any, size: str) -> int:
    bits = {"B": 8, "W": 16, "D": 32}.get(size.upper()[:1], 16)
    x, k = int(_numv(v)) & ((1 << bits) - 1), int(_numv(n)) % bits
    r = ((x << k) | (x >> (bits - k))) & ((1 << bits) - 1)
    return r - (1 << bits) if bits == 32 and r >= 1 << 31 else r


def _mod(a: Any, b: Any) -> int | float:
    x, y = _numv(a), _numv(b)
    if y == 0:
        return float("nan")
    r = math.fmod(x, y)
    return int(r) if isinstance(x, int) and isinstance(y, int) else r


_MACROS = {"crlf": "\r\n", "cr": "\r", "lf": "\n", "tab": "\t", "autoitx64": 0, "autoitpid": 0, "error": 0,
           "extended": 0, "osarch": "X86", "cpuarch": "X86", "osversion": "WIN_10", "autoitversion": "3.3.16.1",
           "compiled": 1, "numparams": 0, "scriptname": "", "scriptdir": "", "scriptfullpath": "",
           "tempdir": "", "appdatadir": "", "username": "", "computername": "", "sec": 0, "min": 0,
           "hour": 0, "mday": 1, "mon": 1, "year": 2026, "wday": 1, "yday": 1, "msec": 0, "ipaddress1": "",
           "desktopwidth": 1920, "desktopheight": 1080, "systemdir": "", "windowsdir": "", "homedrive": "",
           "programfilesdir": "", "startupdir": "", "localappdatadir": "", "commonfilesdir": "",
           "desktopdir": "", "mydocumentsdir": "", "oslang": "0409", "kblayout": "00000409", "muilang": "0409"}


# --------------------------------------------------------------------------- evaluator

class _Run:
    def __init__(self, funcs: dict[str, tuple[list, list, Any]]) -> None:
        self.funcs, self.steps, self.depth = funcs, 0, 0

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise Unsupported("step budget")

    def call(self, name: str, args: list[Any]) -> Any:
        if name in _PURE:
            try:
                r = _PURE[name](*args)
            except Unsupported:
                raise
            except Exception as exc:  # noqa: BLE001
                raise Unsupported(f"{name}: {exc}") from exc
            if isinstance(r, str) and len(r) > MAX_STR:
                raise Unsupported("string too long")
            return r
        if name == "execute":
            src = _strv(args[0]) if args else ""
            return self.eval(_expr(src), {})
        f = self.funcs.get(name)
        if f is None or f[2] is not None:
            raise Unsupported(f"function {name}")
        params, body, _ = f
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise Unsupported("depth")
        env: dict[str, Any] = {}
        for k, (pn, _byref, dflt) in enumerate(params):
            env[pn] = args[k] if k < len(args) else (self.eval(dflt, env) if dflt is not None else "")
        try:
            self.exec(body, env)
            return ""
        except _Exit as ex:
            if ex.kind == "return":
                return ex.value
            raise Unsupported("loop control outside a loop") from ex
        finally:
            self.depth -= 1

    # expressions
    def eval(self, e: tuple, env: dict[str, Any]) -> Any:
        self.tick()
        op = e[0]
        if op == "lit":
            return e[1]
        if op == "var":
            if e[1] not in env:
                return ""                                # undeclared (dead-branch junk reads them)
            return env[e[1]]
        if op == "mac":
            return _MACROS.get(e[1], "")
        if op == "call":
            return self.call(e[1], [self.eval(a, env) for a in e[2]])
        if op == "idx":
            base = self.eval(e[1], env)
            i = int(_numv(self.eval(e[2], env)))
            if isinstance(base, list) and 0 <= i < len(base):
                return base[i]
            if isinstance(base, str) and 0 <= i < len(base):
                return base[i]
            raise Unsupported("index")
        if op == "arr":
            return [self.eval(x, env) for x in e[1]]
        if op == "neg":
            return -_numv(self.eval(e[1], env))
        if op == "not":
            return not _truth(self.eval(e[1], env))
        if op == "and":
            return _truth(self.eval(e[1], env)) and _truth(self.eval(e[2], env))
        if op == "or":
            return _truth(self.eval(e[1], env)) or _truth(self.eval(e[2], env))
        if op == "?":
            return self.eval(e[2], env) if _truth(self.eval(e[1], env)) else self.eval(e[3], env)
        if op == "&":
            r = _strv(self.eval(e[1], env)) + _strv(self.eval(e[2], env))
            if len(r) > MAX_STR:
                raise Unsupported("string too long")
            return r
        if op == "cmp":
            return _compare(e[1], self.eval(e[2], env), self.eval(e[3], env))
        a, b = _numv(self.eval(e[1], env)), _numv(self.eval(e[2], env))
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op == "/":
            return a / b if b else float("inf")
        if op == "^":
            try:
                return a ** b
            except (OverflowError, ZeroDivisionError) as exc:
                raise Unsupported("pow") from exc
        raise Unsupported(f"op {op}")

    def assign(self, target: tuple, value: Any, env: dict[str, Any]) -> None:
        if target[0] == "var":
            env[target[1]] = value
            return
        if target[0] == "idx":
            base = self.eval(target[1], env)
            i = int(_numv(self.eval(target[2], env)))
            if isinstance(base, list) and 0 <= i < len(base):
                base[i] = value
                return
        raise Unsupported("assign target")

    # statements
    def exec(self, body: list, env: dict[str, Any]) -> None:
        for st in body:
            self.tick()
            kind = st[0]
            if kind == "nop":
                continue
            if kind == "bad":
                raise Unsupported(st[1])
            if kind == "expr":
                self.eval(st[1], env)
            elif kind == "assign":
                for target, op, ex in st[1]:
                    v = self.eval(ex, env)
                    if op != "=":
                        cur = self.eval(target, env)
                        if op == "&=":
                            v = _strv(cur) + _strv(v)
                            if len(v) > MAX_STR:
                                raise Unsupported("string too long")
                        elif op == "+=":
                            v = _numv(cur) + _numv(v)
                        elif op == "-=":
                            v = _numv(cur) - _numv(v)
                        elif op == "*=":
                            v = _numv(cur) * _numv(v)
                        elif op == "/=":
                            v = _numv(cur) / _numv(v) if _numv(v) else float("inf")
                    self.assign(target, v, env)
            elif kind == "decl":
                for name, dims, init in st[1]:
                    if init is not None:
                        env[name] = self.eval(init, env)
                    elif dims:
                        n = int(_numv(self.eval(dims[0], env)))
                        if n > 1_000_000:
                            raise Unsupported("array too big")
                        env[name] = ["" for _ in range(max(0, n))]
                    elif name not in env:
                        env[name] = ""
            elif kind == "return":
                raise _Exit("return", value=self.eval(st[1], env))
            elif kind in ("exitloop", "continueloop"):
                raise _Exit(kind, int(_numv(self.eval(st[1], env))) or 1)
            elif kind == "if":
                for cond, sub in st[1]:
                    if _truth(self.eval(cond, env)):
                        self.exec(sub, env)
                        break
                else:
                    self.exec(st[2], env)
            elif kind == "switch":
                self._switch(st, env)
            elif kind in ("for", "forin", "while", "do"):
                self._loop(st, env)
            else:
                raise Unsupported(kind)

    def _switch(self, st: tuple, env: dict[str, Any]) -> None:
        _k, subject, cases = st
        subj = self.eval(subject, env) if subject is not None else None
        for conds, sub in cases:
            if conds is None:
                self.exec(sub, env)
                return
            for c in conds:
                if subject is None:                       # Select: each Case is a condition
                    hit = _truth(self.eval(c[1], env))
                elif c[0] == "range":
                    lo, hi = _numv(self.eval(c[1], env)), _numv(self.eval(c[2], env))
                    hit = lo <= _numv(subj) <= hi
                else:
                    hit = _compare("=", subj, self.eval(c[1], env))
                if hit:
                    self.exec(sub, env)
                    return

    def _loop(self, st: tuple, env: dict[str, Any]) -> None:
        kind = st[0]

        def run(sub: list) -> str:
            try:
                self.exec(sub, env)
            except _Exit as ex:
                if ex.kind == "exitloop":
                    if ex.n > 1:
                        raise _Exit("exitloop", ex.n - 1) from None
                    return "break"
                if ex.kind == "continueloop":
                    if ex.n > 1:
                        raise _Exit("continueloop", ex.n - 1) from None
                    return "continue"
                raise
            return ""
        if kind == "for":
            _k, var, start, stop, step, sub = st
            i, hi, s = _numv(self.eval(start, env)), _numv(self.eval(stop, env)), _numv(self.eval(step, env))
            if s == 0:
                raise Unsupported("step 0")
            env[var] = i
            while (env[var] <= hi) if s > 0 else (env[var] >= hi):
                self.tick()
                if run(sub) == "break":
                    return
                env[var] = _numv(env[var]) + s
        elif kind == "forin":
            _k, var, seq, sub = st
            for item in list(self.eval(seq, env) or []):
                env[var] = item
                if run(sub) == "break":
                    return
        elif kind == "while":
            _k, cond, sub = st
            while _truth(self.eval(cond, env)):
                self.tick()
                if run(sub) == "break":
                    return
        elif kind == "do":
            _k, sub, cond = st
            while True:
                self.tick()
                if run(sub) == "break":
                    return
                if _truth(self.eval(cond, env)):
                    return


def _compare(op: str, a: Any, b: Any) -> bool:
    if op == "==":
        return _strv(a) == _strv(b)
    if isinstance(a, str) and isinstance(b, str):
        x, y = a.lower(), b.lower()
    elif isinstance(a, (int, float, bool)) or isinstance(b, (int, float, bool)):
        x, y = _numv(a), _numv(b)
    else:
        x, y = _strv(a).lower(), _strv(b).lower()
    return {"=": x == y, "<>": x != y, "<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]


# --------------------------------------------------------------------------- deobfuscation

_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def _literal_call_spans(code: str, names: set[str]) -> list[tuple[int, int, str, list[Any]]]:
    """Calls of user functions whose arguments are all literals: (start, end, name, args)."""
    out = []
    for m in _CALL.finditer(code):
        name = m.group(1).lower()
        if name not in names:
            continue
        line_start = code.rfind("\n", 0, m.start()) + 1
        if re.match(r"(?i)\s*func\b", code[line_start:m.start() + 1]):
            continue                                       # the definition itself
        # the argument list up to the matching ")" on the same logical line
        depth, i, in_str = 0, m.end() - 1, ""
        while i < len(code):
            c = code[i]
            if in_str:
                if c == in_str:
                    if i + 1 < len(code) and code[i + 1] == in_str:
                        i += 2
                        continue
                    in_str = ""
            elif c in "\"'":
                in_str = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            elif c == "\n":
                break
            i += 1
        if depth != 0 or i >= len(code):
            continue
        try:
            e = _expr(code[m.start():i + 1])
        except Unsupported:
            continue
        if e[0] != "call" or not all(_is_const(a) for a in e[2]):
            continue
        out.append((m.start(), i + 1, name, [_const(a) for a in e[2]]))
    return out


def _is_const(e: tuple) -> bool:
    return e[0] == "lit" or (e[0] == "neg" and _is_const(e[1])) or (
        e[0] in ("+", "-", "*", "&") and _is_const(e[1]) and _is_const(e[2]))


def _const(e: tuple) -> Any:
    return _Run({}).eval(e, {})


def _quote(s: str) -> str:
    return '"' + s.replace('"', '""') + '"'


def _readable(s: Any) -> bool:
    if not isinstance(s, str) or not s:
        return False
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok >= len(s) * 0.9


def deobfuscate(code: str) -> dict[str, Any]:
    """Decrypt the strings a script hides behind its own decoder functions.
    Returns {code, decoded: [{function, args, value}], functions: {name: count}}."""
    funcs = parse_functions(code)
    names = {n for n, f in funcs.items() if f[2] is None}
    decoded: list[dict[str, Any]] = []
    used: dict[str, int] = {}
    cache: dict[tuple, Any] = {}
    failed: set[tuple] = set()
    import time
    t0 = time.monotonic()
    for _round_ in range(3):                             # calls nested in calls become literals
        spans = _literal_call_spans(code, names)
        if not spans:
            break
        parts, last, changed = [], 0, 0
        for start, end, name, args in spans[:MAX_CALLS]:
            if start < last:
                continue
            key = (name, tuple(map(repr, args)))
            if key in failed:
                continue
            if time.monotonic() - t0 > MAX_SECONDS:
                break
            if key not in cache:
                try:
                    cache[key] = _Run(funcs).call(name, list(args))
                except (Unsupported, RecursionError, ValueError, OverflowError, ZeroDivisionError,
                        TypeError, IndexError, KeyError):
                    failed.add(key)
                    continue
            val = cache[key]
            if not _readable(val):
                continue
            parts.append(code[last:start])
            parts.append(_quote(val))
            last = end
            changed += 1
            used[name] = used.get(name, 0) + 1
            if len(decoded) < 5000:
                decoded.append({"function": name, "args": [a if isinstance(a, (int, float)) else str(a)[:80] for a in args],
                                "value": val[:400]})
        if not changed:
            break
        parts.append(code[last:])
        code = "".join(parts)
    return {"code": code, "decoded": decoded, "functions": used,
            "unparsed": sorted(n for n, f in funcs.items() if f[2] is not None)[:50]}
