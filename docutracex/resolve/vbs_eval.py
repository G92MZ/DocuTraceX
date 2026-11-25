"""VBScript (and VBA-style code), evaluated statically: what a dropper computes, without running it.

There is no VBScript engine here: the script is tokenised and parsed by this module and walked by
a small interpreter. It follows ``Dim`` / ``ReDim`` / ``Const``, assignments and ``Set``, the
script's ``Function`` / ``Sub`` (``ByRef`` / ``ByVal``, the function name as its return value),
``If`` / ``Select Case``, ``For`` / ``For Each`` / ``Do`` / ``While`` loops, ``With``, arrays,
``On Error Resume Next`` and the built-in functions obfuscators use — ``Chr`` / ``ChrW`` / ``Asc``,
``Mid`` / ``Left`` / ``Right``, ``StrReverse``, ``Replace``, ``Split`` / ``Join``, ``Hex``,
``CLng`` / ``CInt``, ``Xor`` / ``And`` / ``Mod`` arithmetic.

What reaches ``Execute`` / ``ExecuteGlobal`` / ``Eval`` runs next (it is evaluated here too, a later
stage). COM objects are the same ones the JScript evaluator follows (:mod:`.js_eval`):
``WScript.Shell`` (``Run`` / ``Exec`` / ``RegRead`` / ``ExpandEnvironmentStrings``),
``Scripting.FileSystemObject``, ``ADODB.Stream``, MSXML ``bin.base64`` / ``bin.hex``,
``MSXML2.XMLHTTP`` / ``WinHttpRequest``, ``Shell.Application``, WMI ``Win32_Process.Create`` —
so bytes saved to disk are written files, commands are followed (:mod:`.commands`), downloads are
reported and a name read from the victim's machine is a dynamic call not resolved.

Bounded: steps, time, loop iterations, call depth and inline nesting.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from typing import Any, Callable

from . import js_eval as J
from . import transforms as T
from .sinks import Sinks
from .value import Value

MAX_STEPS = 6_000_000
MAX_SECONDS = 30.0
MAX_LOOP = 3_000_000
MAX_DEPTH = 12
MAX_CALL_DEPTH = 80
MAX_STR = 64 * 1024 * 1024

Unk = J.Unk
rec = J.rec
tag = J.tag
step = J.step


_MEM_APIS = {"rtlmovememory", "copymemory", "writeprocessmemory", "rtlcopymemory", "movememory",
             "ntwritevirtualmemory", "createthread", "createremotethread", "enumsystemcodepagesa",
             "enumdatetimeformatsa", "callwindowproca", "enumwindows"}


class _Empty:
    def __repr__(self) -> str:
        return "Empty"

    def __bool__(self) -> bool:
        return False


EMPTY = _Empty()


class _NullT:
    def __repr__(self) -> str:
        return "Null"


NULL = _NullT()


class _NothingT:
    def __repr__(self) -> str:
        return "Nothing"


NOTHING = _NothingT()


class VArr(list):
    """A VBScript array (lists of lists for more dimensions)."""
    recipe: tuple[str, ...] = ()


class Proc:
    def __init__(self, name: str, params: list[tuple[str, bool, Any]], body: list, is_func: bool, src: str) -> None:
        self.name, self.params, self.body, self.is_func, self.src = name, params, body, is_func, src


class Ref:
    """``GetRef("name")``."""

    def __init__(self, proc: Proc) -> None:
        self.proc = proc


class _Exit(Exception):
    def __init__(self, kind: str) -> None:
        self.kind = kind


class _Quit(Exception):
    pass


class Limit(Exception):
    pass


class VBError(Exception):
    pass


# --- tokens ------------------------------------------------------------------------------------
_TOK = re.compile(r"""
    (?P<ws>[ \t\f\v]+)
  | (?P<cont>[ \t]*_[ \t]*\r?\n)
  | (?P<nl>\r\n|\r|\n|:)
  | (?P<comment>'[^\r\n]*|(?i:\bREM\b)[^\r\n]*)
  | (?P<str>"(?:[^"\r\n]|"")*")
  | (?P<date>\#[^#\r\n]{1,40}\#)
  | (?P<hex>&[Hh][0-9A-Fa-f]+&?)
  | (?P<oct>&[Oo]?[0-7]+&?)
  | (?P<num>(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?[#!@&%]?)
  | (?P<id>\[[^\]\r\n]+\]|[A-Za-z_][A-Za-z0-9_]*[$%&!#@]?)
  | (?P<op><>|<=|>=|=<|=>|[-+*/\\^&=<>(),.;])
""", re.X)


class Tok:
    __slots__ = ("kind", "val", "line", "low")

    def __init__(self, kind: str, val: Any, line: int) -> None:
        self.kind, self.val, self.line = kind, val, line
        self.low = val.lower() if isinstance(val, str) and kind == "id" else None

    def __repr__(self) -> str:
        return f"{self.kind}:{self.val!r}"


def tokenize(src: str) -> list[Tok]:
    out: list[Tok] = []
    pos = 0
    line = 1
    n = len(src)
    while pos < n:
        m = _TOK.match(src, pos)
        if not m:
            # an unknown character: skip it
            if src[pos] == "\n":
                line += 1
            pos += 1
            continue
        k = m.lastgroup
        v = m.group(k)
        if k == "cont":
            line += 1
        elif k == "nl":
            out.append(Tok("nl", v, line))
            if v != ":":
                line += 1 if v in ("\n", "\r\n", "\r") else 0
        elif k == "str":
            out.append(Tok("str", v[1:-1].replace('""', '"'), line))
        elif k == "hex":
            x = int(v[2:].rstrip("&"), 16)
            if len(v.rstrip("&")) <= 6 and x > 0x7FFF and not v.endswith("&"):
                x -= 0x10000
            elif x > 0x7FFFFFFF:
                x -= 0x100000000
            out.append(Tok("num", x, line))
        elif k == "oct":
            s = v[1:].lstrip("Oo").rstrip("&")
            out.append(Tok("num", int(s, 8) if s else 0, line))
        elif k == "num":
            s = v.rstrip("#!@&%")
            out.append(Tok("num", int(s) if re.fullmatch(r"\d+", s) else float(s), line))
        elif k == "id":
            out.append(Tok("id", v.strip("[]").rstrip("$%&!#@") if not v.startswith("[") else v[1:-1], line))
        elif k == "op":
            out.append(Tok("op", {"=<": "<=", "=>": ">="}.get(v, v), line))
        elif k == "date":
            out.append(Tok("str", v[1:-1], line))
        pos = m.end()
    out.append(Tok("nl", "\n", line))
    out.append(Tok("eof", None, line))
    return out


# --- parser ------------------------------------------------------------------------------------
_KEYWORDS_END = {"end", "else", "elseif", "next", "loop", "wend", "case"}


class Parser:
    def __init__(self, toks: list[Tok], src: str) -> None:
        self.t = toks
        self.i = 0
        self.src = src

    # helpers
    def peek(self, k: int = 0) -> Tok:
        return self.t[min(self.i + k, len(self.t) - 1)]

    def next(self) -> Tok:
        tok = self.t[self.i]
        self.i = min(self.i + 1, len(self.t) - 1)
        return tok

    def is_id(self, *words: str, k: int = 0) -> bool:
        tok = self.peek(k)
        return tok.kind == "id" and tok.low in words

    def is_op(self, *ops: str, k: int = 0) -> bool:
        tok = self.peek(k)
        return tok.kind == "op" and tok.val in ops

    def eat_id(self, *words: str) -> bool:
        if self.is_id(*words):
            self.next()
            return True
        return False

    def eat_op(self, op: str) -> bool:
        if self.is_op(op):
            self.next()
            return True
        return False

    def expect_op(self, op: str) -> None:
        if not self.eat_op(op):
            raise SyntaxError(f"line {self.peek().line}: expected {op!r}, got {self.peek()}")

    def end_stmt(self) -> bool:
        return self.peek().kind in ("nl", "eof")

    def skip_nl(self) -> None:
        while self.peek().kind == "nl":
            self.next()

    def to_eol(self) -> None:
        while self.peek().kind not in ("nl", "eof"):
            self.next()

    # program
    def program(self) -> list:
        return self.block(set())

    def block(self, stop: set[str]) -> list:
        out = []
        while True:
            self.skip_nl()
            tok = self.peek()
            if tok.kind == "eof":
                return out
            if tok.kind == "id" and tok.low in stop:
                return out
            if tok.kind == "id" and tok.low == "end" and "end" in stop:
                return out
            try:
                st = self.statement()
            except SyntaxError as exc:
                out.append(("error", tok.line, str(exc)))
                self.to_eol()
                continue
            if st is not None:
                out.append(st)

    def statement(self) -> Any:  # noqa: C901, PLR0911, PLR0912
        tok = self.peek()
        line = tok.line
        if tok.kind != "id" and not (tok.kind == "op" and tok.val == "."):
            self.to_eol()
            return ("error", line, f"unexpected {tok}")
        w = tok.low
        if w in ("public", "private") and self.is_id("function", "sub", "const", "property", "default", k=1):
            self.next()
            if self.is_id("default"):
                self.next()
            return self.statement()
        if w in ("dim", "public", "private", "static"):
            self.next()
            return ("dim", line, self.dim_list())
        if w == "redim":
            self.next()
            pres = self.eat_id("preserve")
            items = []
            while True:
                name = self.next().val
                bounds = []
                if self.eat_op("("):
                    bounds = self.args_until(")")
                items.append((name, bounds))
                if not self.eat_op(","):
                    break
            return ("redim", line, pres, items)
        if w == "const":
            self.next()
            items = []
            while True:
                name = self.next().val
                self.expect_op("=")
                items.append((name, self.expr()))
                if not self.eat_op(","):
                    break
            return ("const", line, items)
        if w == "set":
            self.next()
            target = self.postfix(self.primary())
            self.expect_op("=")
            return ("assign", line, target, self.expr())
        if w == "let":
            self.next()
            return self.statement()
        if w == "call":
            self.next()
            e = self.postfix(self.primary())
            return ("callstmt", line, e, None)
        if w == "if":
            return self.if_stmt()
        if w == "for":
            return self.for_stmt()
        if w == "do":
            return self.do_stmt()
        if w == "while":
            self.next()
            cond = self.expr()
            body = self.block({"wend"})
            self.eat_id("wend")
            return ("while", line, cond, body)
        if w == "select":
            return self.select_stmt()
        if w in ("function", "sub", "property"):
            return self.proc_stmt()
        if w == "exit":
            self.next()
            kind = self.next().low or ""
            return ("exit", line, kind)
        if w == "on":
            self.next()
            self.eat_id("error")
            if self.eat_id("resume"):
                self.eat_id("next")
                return ("onerror", line, True)
            if self.eat_id("goto"):
                self.next()
                return ("onerror", line, False)
            self.to_eol()
            return None
        if w == "with":
            self.next()
            obj = self.expr()
            body = self.block({"end"})
            self.eat_id("end")
            self.eat_id("with")
            return ("with", line, obj, body)
        if w == "class":
            self.next()
            name = self.next().val
            body = self.block({"end"})
            self.eat_id("end")
            self.eat_id("class")
            return ("class", line, name, body)
        if w == "option":
            self.to_eol()
            return None
        if w in ("randomize", "erase", "stop", "attribute", "declare", "goto", "resume", "debug"):
            self.to_eol()
            return None
        if w in ("end",):
            self.next()
            if self.peek().kind in ("nl", "eof"):
                return ("quit", line)
            self.to_eol()
            return None
        # an assignment or a call
        target = self.postfix(self.primary())
        if self.eat_op("="):
            return ("assign", line, target, self.expr())
        if self.end_stmt() or self.is_id("else"):
            return ("callstmt", line, target, None)
        args = self.call_args_noparen()
        return ("callstmt", line, target, args)

    def dim_list(self) -> list:
        items = []
        while True:
            name = self.next().val
            bounds = None
            if self.eat_op("("):
                bounds = self.args_until(")")
            if self.eat_id("as"):
                self.eat_id("new")
                self.next()
            items.append((name, bounds))
            if not self.eat_op(","):
                break
        return items

    def call_args_noparen(self) -> list:
        args = []
        while True:
            if self.is_op(","):
                args.append(("missing",))
            else:
                args.append(self.expr())
            if not self.eat_op(","):
                break
            if self.end_stmt():
                args.append(("missing",))
                break
        return args

    def args_until(self, close: str) -> list:
        args = []
        if self.eat_op(close):
            return args
        while True:
            if self.is_op(",", close):
                args.append(("missing",))
            else:
                if self.is_id("byval", "byref"):
                    self.next()
                args.append(self.expr())
            if self.eat_op(","):
                continue
            self.expect_op(close)
            return args

    def if_stmt(self) -> Any:
        line = self.next().line
        cond = self.expr()
        if not self.eat_id("then"):
            raise SyntaxError(f"line {line}: If without Then")
        if self.peek().kind == "nl" and self.peek().val != ":":
            branches = [(cond, self.block({"elseif", "else", "end"}))]
            els = None
            while True:
                if self.eat_id("elseif"):
                    c = self.expr()
                    self.eat_id("then")
                    branches.append((c, self.block({"elseif", "else", "end"})))
                    continue
                if self.eat_id("else"):
                    els = self.block({"end"})
                    continue
                if self.eat_id("end"):
                    self.eat_id("if")
                break
            return ("if", line, branches, els)
        # single-line If: statements separated by ':' up to the end of the line (Else on the line)
        then = self.inline_stmts()
        els = None
        if self.eat_id("else"):
            els = self.inline_stmts()
        if self.is_id("end") and self.is_id("if", k=1):
            self.next()
            self.next()
        return ("if", line, [(cond, then)], els)

    def inline_stmts(self) -> list:
        out = []
        while True:
            while self.is_op(":") or (self.peek().kind == "nl" and self.peek().val == ":"):
                self.next()
            if self.peek().kind in ("nl", "eof") or self.is_id("else") or (self.is_id("end") and self.is_id("if", k=1)):
                return out
            st = self.statement()
            if st is not None:
                out.append(st)
            if self.peek().kind == "nl" and self.peek().val == ":":
                continue
            return out

    def for_stmt(self) -> Any:
        line = self.next().line
        if self.eat_id("each"):
            var = self.next().val
            self.eat_id("in")
            coll = self.expr()
            body = self.block({"next"})
            self.eat_id("next")
            if self.peek().kind == "id":
                self.next()
            return ("foreach", line, var, coll, body)
        var = self.next().val
        self.expect_op("=")
        a = self.expr()
        self.eat_id("to")
        b = self.expr()
        s = self.expr() if self.eat_id("step") else None
        body = self.block({"next"})
        self.eat_id("next")
        if self.peek().kind == "id" and not self.peek().low in _KEYWORDS_END:
            self.next()
        return ("for", line, var, a, b, s, body)

    def do_stmt(self) -> Any:
        line = self.next().line
        pre = None
        if self.is_id("while", "until"):
            kind = self.next().low
            pre = (kind, self.expr())
        body = self.block({"loop"})
        self.eat_id("loop")
        post = None
        if self.is_id("while", "until"):
            kind = self.next().low
            post = (kind, self.expr())
        return ("do", line, pre, post, body)

    def select_stmt(self) -> Any:
        line = self.next().line
        self.eat_id("case")
        subject = self.expr()
        cases = []
        els = None
        while True:
            self.skip_nl()
            if self.eat_id("case"):
                if self.eat_id("else"):
                    els = self.block({"case", "end"})
                    continue
                conds = []
                while True:
                    if self.eat_id("is"):
                        op = self.next().val
                        conds.append(("is", op, self.expr()))
                    else:
                        a = self.expr()
                        if self.eat_id("to"):
                            conds.append(("range", a, self.expr()))
                        else:
                            conds.append(("eq", a))
                    if not self.eat_op(","):
                        break
                cases.append((conds, self.block({"case", "end"})))
                continue
            if self.eat_id("end"):
                self.eat_id("select")
            break
        return ("select", line, subject, cases, els)

    def proc_stmt(self) -> Any:
        tok = self.next()
        line = tok.line
        kind = tok.low
        if kind == "property":
            self.next()                                   # Get / Let / Set
        name = self.next().val
        params = []
        if self.eat_op("("):
            while not self.eat_op(")"):
                byval = False
                opt = False
                while self.is_id("byval", "byref", "optional", "paramarray"):
                    w = self.next().low
                    byval = byval or w == "byval"
                    opt = opt or w == "optional"
                pname = self.next().val
                if self.eat_op("("):
                    self.expect_op(")")
                if self.eat_id("as"):
                    self.next()
                default = None
                if self.eat_op("="):
                    default = self.expr()
                params.append((pname, byval, default))
                self.eat_op(",")
                if self.peek().kind == "eof":
                    break
        if self.eat_id("as"):
            self.next()
        start = self.i
        body = self.block({"end"})
        self.eat_id("end")
        self.next() if self.peek().kind == "id" else None
        del start
        return ("proc", line, name, params, body, kind in ("function", "property"))

    # expressions: Imp < Eqv < Xor < Or < And < Not < comparison < & < + - < Mod < \\ < * / < unary - < ^
    def expr(self) -> Any:
        return self.binlevel(0)

    _LEVELS = [("imp",), ("eqv",), ("xor",), ("or",), ("and",)]

    def binlevel(self, lvl: int) -> Any:
        if lvl < len(self._LEVELS):
            a = self.binlevel(lvl + 1)
            while self.is_id(*self._LEVELS[lvl]):
                op = self.next().low
                a = ("bin", op, a, self.binlevel(lvl + 1))
            return a
        return self.not_expr()

    def not_expr(self) -> Any:
        if self.eat_id("not"):
            return ("un", "not", self.not_expr())
        return self.compare()

    def compare(self) -> Any:
        a = self.concat()
        while self.is_op("=", "<>", "<", ">", "<=", ">=") or self.is_id("is", "like"):
            op = self.next()
            a = ("bin", op.val if op.kind == "op" else op.low, a, self.concat())
        return a

    def concat(self) -> Any:
        a = self.additive()
        while self.is_op("&"):
            self.next()
            a = ("bin", "&", a, self.additive())
        return a

    def additive(self) -> Any:
        a = self.modulo()
        while self.is_op("+", "-"):
            op = self.next().val
            a = ("bin", op, a, self.modulo())
        return a

    def modulo(self) -> Any:
        a = self.intdiv()
        while self.is_id("mod"):
            self.next()
            a = ("bin", "mod", a, self.intdiv())
        return a

    def intdiv(self) -> Any:
        a = self.mult()
        while self.is_op("\\"):
            self.next()
            a = ("bin", "\\", a, self.mult())
        return a

    def mult(self) -> Any:
        a = self.unary()
        while self.is_op("*", "/"):
            op = self.next().val
            a = ("bin", op, a, self.unary())
        return a

    def unary(self) -> Any:
        if self.is_op("-"):
            self.next()
            return ("un", "-", self.unary())
        if self.is_op("+"):
            self.next()
            return self.unary()
        return self.power()

    def power(self) -> Any:
        a = self.postfix(self.primary())
        while self.is_op("^"):
            self.next()
            b = self.unary_pow()
            a = ("bin", "^", a, b)
        return a

    def unary_pow(self) -> Any:
        if self.is_op("-"):
            self.next()
            return ("un", "-", self.unary_pow())
        return self.postfix(self.primary())

    def primary(self) -> Any:
        tok = self.peek()
        if tok.kind == "num":
            self.next()
            return ("num", tok.val)
        if tok.kind == "str":
            self.next()
            return ("str", tok.val, tok.line)
        if tok.kind == "op" and tok.val == "(":
            self.next()
            e = self.expr()
            self.expect_op(")")
            return ("paren", e)
        if tok.kind == "op" and tok.val == ".":
            self.next()
            name = self.next().val
            return ("withmember", name)
        if tok.kind == "id":
            self.next()
            w = tok.low
            if w == "new":
                return ("new", self.next().val)
            if w in ("true", "false"):
                return ("const", w == "true")
            if w == "nothing":
                return ("const", NOTHING)
            if w == "empty":
                return ("const", EMPTY)
            if w == "null":
                return ("const", NULL)
            return ("id", tok.val, tok.line)
        raise SyntaxError(f"line {tok.line}: unexpected {tok}")

    def postfix(self, e: Any) -> Any:
        while True:
            if self.is_op("(") :
                self.next()
                e = ("call", e, self.args_until(")"))
            elif self.is_op(".") and self.peek(1).kind == "id":
                self.next()
                e = ("member", e, self.next().val)
            else:
                return e


# --- values --------------------------------------------------------------------------------------
def vb_str(v: Any) -> str:
    if isinstance(v, str):
        return v
    if v is EMPTY or v is None:
        return ""
    if v is NULL:
        return ""
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 1e15:
            return str(int(v))
        return repr(v)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("latin-1")
    if isinstance(v, Unk):
        return f"<{v.why}>"
    if isinstance(v, list):
        raise VBError("Type mismatch (an array as text)")
    return J.to_str(v)


def vb_num(v: Any) -> float | int:
    if isinstance(v, bool):
        return -1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if v is EMPTY or v is None:
        return 0
    if isinstance(v, str):
        t = v.strip()
        if not t:
            raise VBError("Type mismatch")
        if re.fullmatch(r"&[Hh][0-9A-Fa-f]+", t):
            return int(t[2:], 16)
        try:
            f = float(t)
        except ValueError as exc:
            raise VBError(f"Type mismatch: {t[:20]!r}") from exc
        return int(f) if f.is_integer() and "." not in t and "e" not in t.lower() else f
    raise VBError("Type mismatch")


def vb_int(v: Any) -> int:
    n = vb_num(v)
    if isinstance(n, float):
        # banker's rounding, as CLng / CInt do
        return int(round(n))
    return n


def vb_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, Unk):
        return False
    if v is EMPTY or v is NULL:
        return False
    if isinstance(v, str):
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
    return vb_num(v) != 0


def is_numeric(v: Any) -> bool:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return True
    if isinstance(v, str):
        try:
            float(v.strip())
            return bool(v.strip())
        except ValueError:
            return False
    return False


class Scope:
    __slots__ = ("vars", "parent", "proc", "resume")

    def __init__(self, parent: "Scope | None" = None, proc: Proc | None = None) -> None:
        self.vars: dict[str, Any] = {}
        self.parent = parent
        self.proc = proc
        self.resume = False


# --- the interpreter -------------------------------------------------------------------------------
class Interp:  # noqa: PLR0904
    def __init__(self, sinks: Sinks, source: str) -> None:
        self.sinks = sinks
        self.source = source
        self.top_source = source
        self.g = Scope()
        self.procs: dict[str, Proc] = {}
        self.steps = 0
        self.t0 = time.monotonic()
        self.depth = 0
        self.call_depth = 0
        self.errors: list[str] = []
        self.ran: set[str] = set()
        self.tracked: dict[str, Any] = {}
        self.with_stack: list[Any] = []
        self.loaded: set[int] = set()
        # the COM objects are those of the JScript evaluator (one implementation of WScript.Shell,
        # ADODB.Stream, MSXML, XMLHTTP, FileSystemObject…)
        self.com = J.Interp(sinks, source)
        self.com.script_path = "C:\\Users\\Public\\script.vbs"
        self.com.top_source = source
        self.builtins = self._builtins()

    # -- running ----------------------------------------------------------------------------------
    def parse(self, code: str) -> list:
        return Parser(tokenize(code), code).program()

    def run(self, code: str) -> None:
        try:
            prog = self.parse(code)
        except (SyntaxError, RecursionError) as exc:
            self.errors.append(f"not parsed: {exc}"[:300])
            return
        try:
            self.hoist(prog)
            self.block(prog, self.g, top=True)
        except (Limit, _Quit, _Exit):
            pass
        for h in self.com.streams:
            self.com._flush_text(h, None)
        self.computed_values()

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise Limit("steps")
        if not self.steps & 0x3FFF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise Limit("time")

    def hoist(self, stmts: list) -> None:
        for st in stmts:
            if st[0] == "proc":
                _, _line, name, params, body, is_func = st
                self.procs[name.lower()] = Proc(name, params, body, is_func, self.source)
            elif st[0] == "class":
                self.hoist([s for s in st[3] if s[0] == "proc"])

    def text_of(self, line: int | None) -> str:
        lines = self.source.splitlines()
        return lines[line - 1].strip()[:200] if line and 0 < line <= len(lines) else ""

    # -- statements -----------------------------------------------------------------------------------
    def block(self, stmts: list, sc: Scope, top: bool = False) -> None:
        for st in stmts:
            try:
                self.stmt(st, sc)
            except (Limit, _Quit, _Exit, RecursionError):
                raise
            except (VBError, J._Throw, Exception) as exc:  # noqa: BLE001
                if sc.resume or top:
                    if not sc.resume:
                        self.errors.append(f"line {st[1]}: {type(exc).__name__}: {exc}"[:300])
                    continue
                raise

    def stmt(self, st: tuple, sc: Scope) -> None:  # noqa: C901, PLR0912, PLR0915
        self.tick()
        kind = st[0]
        line = st[1]
        if kind == "assign":
            v = self.eval(st[3], sc)
            self.assign(st[2], v, sc, line)
        elif kind == "callstmt":
            self.call_stmt(st[2], st[3], sc, line)
        elif kind == "dim":
            for name, bounds in st[2]:
                low = name.lower()
                if bounds:
                    self.declare(low, self.make_array([vb_int(self.eval(b, sc)) for b in bounds]), sc)
                elif bounds == []:
                    self.declare(low, VArr(), sc)
                elif low not in sc.vars:
                    self.declare(low, EMPTY, sc)
        elif kind == "redim":
            for name, bounds in st[3]:
                dims = [vb_int(self.eval(b, sc)) for b in bounds]
                new = self.make_array(dims)
                low = name.lower()
                if st[2]:
                    old = self.lookup_var(low, sc)
                    if isinstance(old, list) and len(dims) == 1:
                        for i in range(min(len(old), len(new))):
                            new[i] = old[i]
                        try:
                            new.recipe = rec(old)
                        except AttributeError:
                            pass
                self.set_var(low, new, sc, line)
        elif kind == "const":
            for name, e in st[2]:
                self.declare(name.lower(), self.eval(e, sc), sc)
        elif kind == "if":
            for cond, body in st[2]:
                c = self.eval(cond, sc)
                if isinstance(c, Unk):
                    # depends on the machine: both ways (a check that would quit is followed on)
                    for b in [body] + ([st[3]] if st[3] else []):
                        try:
                            self.block(b, sc)
                        except _Quit:
                            self.sinks.step(line, "quits only when a machine check fails (followed on)",
                                            Value("str", self.text_of(line)))
                        except (_Exit, Limit):
                            raise
                        except Exception:  # noqa: BLE001
                            pass
                    return
                if vb_bool(c):
                    self.block(body, sc)
                    return
            if st[3]:
                self.block(st[3], sc)
        elif kind == "for":
            self.for_loop(st, sc)
        elif kind == "foreach":
            _, _, var, coll, body = st
            items = self.iterate(self.eval(coll, sc))
            before = self._loop_before(body, sc)
            try:
                for it in items:
                    self.set_var(var.lower(), it, sc, line)
                    self.block(body, sc)
            except _Exit as e:
                if e.kind != "for":
                    raise
            self._loop_after(before, sc)
        elif kind == "do":
            self.do_loop(st, sc)
        elif kind == "while":
            self.do_loop(("do", line, ("while", st[2]), None, st[3]), sc)
        elif kind == "select":
            subj = self.eval(st[2], sc)
            for conds, body in st[3]:
                if any(self.case_match(subj, c, sc) for c in conds):
                    self.block(body, sc)
                    return
            if st[4]:
                self.block(st[4], sc)
        elif kind == "proc":
            pass                                            # hoisted
        elif kind == "exit":
            raise _Exit(st[2])
        elif kind == "onerror":
            sc.resume = st[2]
        elif kind == "with":
            self.with_stack.append(self.eval(st[2], sc))
            try:
                self.block(st[3], sc)
            finally:
                self.with_stack.pop()
        elif kind == "quit":
            raise _Quit()
        elif kind == "class":
            pass
        elif kind == "error":
            self.errors.append(f"line {line}: not parsed: {st[2]}"[:300])

    def case_match(self, subj: Any, c: tuple, sc: Scope) -> bool:
        if c[0] == "eq":
            return vb_bool(self.binop("=", subj, self.eval(c[1], sc)))
        if c[0] == "range":
            return vb_bool(self.binop(">=", subj, self.eval(c[1], sc))) and vb_bool(self.binop("<=", subj, self.eval(c[2], sc)))
        return vb_bool(self.binop(c[1], subj, self.eval(c[2], sc)))

    def make_array(self, dims: list[int]) -> VArr:
        if not dims:
            return VArr()
        n = dims[0] + 1
        if n < 0 or n > MAX_LOOP:
            raise VBError("array too large")
        if len(dims) == 1:
            return VArr([EMPTY] * n)
        return VArr(self.make_array(dims[1:]) for _ in range(n))

    def for_loop(self, st: tuple, sc: Scope) -> None:
        _, line, var, a, b, s, body = st
        low = var.lower()
        start, end = self.eval(a, sc), self.eval(b, sc)
        stp = self.eval(s, sc) if s is not None else 1
        if isinstance(start, Unk) or isinstance(end, Unk) or isinstance(stp, Unk):
            self.set_var(low, start if not isinstance(start, Unk) else 0, sc, line)
            try:
                for _ in range(3):
                    self.block(body, sc)
            except _Exit as e:
                if e.kind != "for":
                    raise
            return
        i, end, stp = vb_num(start), vb_num(end), vb_num(stp)
        if stp == 0:
            return
        before = self._loop_before(body, sc)
        n = 0
        try:
            while (i <= end) if stp > 0 else (i >= end):
                n += 1
                if n > MAX_LOOP:
                    break
                self.set_var(low, i, sc, line, quiet=True)
                self.block(body, sc)
                cur = self.lookup_var(low, sc)
                i = vb_num(cur) + stp
            self.set_var(low, i, sc, line, quiet=True)
        except _Exit as e:
            if e.kind != "for":
                raise
        self._loop_after(before, sc)

    def do_loop(self, st: tuple, sc: Scope) -> None:
        _, line, pre, post, body = st

        def ok(cond: tuple | None) -> bool | None:
            if cond is None:
                return True
            v = self.eval(cond[1], sc)
            if isinstance(v, Unk):
                return None
            b = vb_bool(v)
            return b if cond[0] == "while" else not b
        before = self._loop_before(body, sc)
        forever = pre is None and post is None
        has_exit = self._has_exit(body)
        cap = 3 if forever and not has_exit else MAX_LOOP
        n = 0
        try:
            while n < cap:
                n += 1
                r = ok(pre)
                if r is False or (r is None and n > 3):
                    break
                self.block(body, sc)
                r = ok(post)
                if r is False or (r is None and n > 3):
                    break
        except _Exit as e:
            if e.kind != "do":
                raise
        self._loop_after(before, sc)

    def _has_exit(self, body: list) -> bool:
        def walk(x: Any) -> bool:
            if isinstance(x, tuple):
                if x and x[0] in ("exit", "quit"):
                    return True
                return any(walk(y) for y in x)
            if isinstance(x, list):
                return any(walk(y) for y in x)
            return False
        return walk(body)

    # the operation a loop applies, named in the recipe of what it builds
    def _loop_targets(self, body: list) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []

        def ids(e: Any) -> list[str]:
            found: list[str] = []

            def w(x: Any) -> None:
                if isinstance(x, tuple) and x:
                    if x[0] == "id":
                        found.append(x[1].lower())
                    for y in x[1:]:
                        w(y)
                elif isinstance(x, list):
                    for y in x:
                        w(y)
            w(e)
            return found

        def src_of(e: Any, target: str) -> str:
            found = ""

            def w(x: Any) -> None:
                nonlocal found
                if found or not isinstance(x, tuple) or not x:
                    if isinstance(x, list):
                        for y in x:
                            w(y)
                    return
                if x[0] == "call" and isinstance(x[1], tuple) and x[1][0] == "id":
                    fn = x[1][1].lower()
                    if fn in ("mid", "midb", "mid$") and x[2] and isinstance(x[2][0], tuple) and x[2][0][0] == "id" \
                            and x[2][0][1].lower() != target:
                        found = x[2][0][1].lower()
                        return
                    if fn not in self.builtins and fn not in self.procs and fn != target:
                        found = fn                               # an array indexed in the loop
                        return
                for y in x[1:]:
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
                tgt, val = x[2], x[3]
                if tgt[0] == "id":
                    t = tgt[1].lower()
                    if val[0] == "bin" and val[1] in ("&", "+") and val[2][0] == "id" and val[2][1].lower() == t:
                        s = src_of(val[3], t)
                        if s:
                            out.append((t, s, self.op_label(val[3], s)))
                elif tgt[0] == "call" and tgt[1][0] == "id":
                    a = tgt[1][1].lower()
                    s = src_of(val, "")
                    if s:
                        out.append((a, s, self.op_label(val, s)))
            for y in x[2:]:
                if isinstance(y, list):
                    visit(y)
                elif isinstance(y, tuple) and y and y[0] in ("if", "for", "foreach", "do", "while", "select", "with"):
                    visit(y)
            if x[0] == "if":
                for _c, b in x[2]:
                    visit(b)
                if x[3]:
                    visit(x[3])
        visit(body)
        return out

    def op_label(self, e: Any, src: str) -> str:
        ops: list[tuple] = []

        def w(x: Any) -> None:
            if isinstance(x, tuple) and x:
                if x[0] == "bin" and x[1] in ("xor", "-", "+"):
                    ops.append(x)
                for y in x[1:]:
                    w(y)
            elif isinstance(x, list):
                for y in x:
                    w(y)
        w(e)

        def has_src(x: Any) -> bool:
            if isinstance(x, tuple) and x:
                if x[0] == "id" and x[1].lower() == src:
                    return True
                return any(has_src(y) for y in x[1:])
            if isinstance(x, list):
                return any(has_src(y) for y in x)
            return False

        def key_of(x: tuple) -> str:
            if x[0] == "num":
                return f"0x{int(x[1]):x}"
            if x[0] == "paren":
                return key_of(x[1])
            names = []

            def nw(y: Any) -> None:
                if isinstance(y, tuple) and y:
                    if y[0] == "id" and y[1].lower() not in ("mid", "asc", "ascw", "ascb", "len", "i", "j", "chr", "chrw",
                                                               "cint", "clng", "cbyte", "mod"):
                        names.append(y[1])
                    for z in y[1:]:
                        nw(z)
                elif isinstance(y, list):
                    for z in y:
                        nw(z)
            nw(x)
            return f"key {names[0]}" if names else "…"
        for want, name in (("xor", "xor"), ("-", "sub"), ("+", "add")):
            for x in ops:
                if x[1] != want or not has_src(x):
                    continue
                for side in (x[3], x[2]):
                    if has_src(side):
                        continue
                    if want != "xor":
                        if side[0] == "num":
                            return f"{name}({int(side[1])})"
                        if side[0] == "id":
                            return f"{name}({side[1]})"
                        continue
                    return f"xor({key_of(side)})"

        def calls(x: Any) -> set[str]:
            out: set[str] = set()
            if isinstance(x, tuple) and x:
                if x[0] == "call" and isinstance(x[1], tuple) and x[1][0] == "id":
                    out.add(x[1][1].lower())
                for y in x[1:]:
                    out |= calls(y)
            elif isinstance(x, list):
                for y in x:
                    out |= calls(y)
            return out
        return "char codes" if calls(e) & {"chr", "chrw", "chrb", "chr$"} else "concat"

    def _loop_before(self, body: list, sc: Scope) -> list:
        out = []
        for tgt, src, op in self._loop_targets(body):
            m = re.fullmatch(r"(sub|add)\((\w+)\)", op)
            if m and not m.group(2).isdigit():
                n = self.lookup_var(m.group(2).lower(), sc, quiet=True)
                if isinstance(n, int) and not isinstance(n, bool):
                    op = f"{m.group(1)}({n})"
            out.append((tgt, op, rec(self.lookup_var(src, sc, quiet=True))))
        return out

    def _loop_after(self, before: list, sc: Scope) -> None:
        done = set()
        for tgt, op, r in before:
            if tgt in done:
                continue
            v = self.lookup_var(tgt, sc, quiet=True)
            if isinstance(v, (str, list, bytearray)) and len(v) >= 16:
                done.add(tgt)
                nv = tag(v, r + (op,)) if not isinstance(v, VArr) else v
                if isinstance(v, VArr):
                    try:
                        v.recipe = r + (op,)
                    except AttributeError:
                        pass
                self.set_var(tgt, nv, sc, None, quiet=True)
                self.sinks.step(None, f"{tgt} = loop {op}", self.to_value(nv))

    # -- names -------------------------------------------------------------------------------------------
    def find_scope(self, low: str, sc: Scope) -> Scope | None:
        if low in sc.vars:
            return sc
        if low in self.g.vars:
            return self.g
        return None

    def lookup_var(self, low: str, sc: Scope, quiet: bool = False) -> Any:
        s = self.find_scope(low, sc)
        if s is not None:
            return s.vars[low]
        return EMPTY

    def declare(self, low: str, v: Any, sc: Scope) -> None:
        sc.vars[low] = v

    def set_var(self, low: str, v: Any, sc: Scope, line: int | None, quiet: bool = False) -> None:
        if not quiet:
            v = self._label(low, v, line)
        s = self.find_scope(low, sc)
        if s is None:
            s = sc if sc.proc is not None else self.g
        s.vars[low] = v

    def _label(self, name: str, v: Any, line: int | None) -> Any:
        if isinstance(v, str) and not rec(v) and len(v) >= 16:
            v = tag(v, (f"literal {name}",))
        elif isinstance(v, list) and not rec(v) and len(v) >= 16 and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in v[:32]):
            try:
                v.recipe = (f"number array {name}",)
            except AttributeError:
                pass
        elif isinstance(v, (str, bytearray)) and rec(v) and len(v) >= 16 and not rec(v)[-1].startswith(("literal", "number array")):
            self.sinks.step(line, f"{name} =", self.to_value(v))
        if isinstance(v, (str, bytearray, list)) and len(v) >= 40:
            self.tracked[name] = v
        return v

    # -- assignment ------------------------------------------------------------------------------------
    def assign(self, target: tuple, v: Any, sc: Scope, line: int | None) -> None:
        k = target[0]
        if k == "id":
            low = target[1].lower()
            if sc.proc is not None and low == sc.proc.name.lower():
                sc.vars["\x00ret"] = v
                return
            self.set_var(low, v, sc, line)
        elif k == "call":
            base = target[1]
            idx = [self.eval(a, sc) for a in target[2]]
            if base[0] == "id":
                low = base[1].lower()
                arr = self.lookup_var(low, sc)
                if isinstance(arr, list):
                    self.set_index(arr, idx, v)
                    return
                if isinstance(arr, J.Host):
                    self.com_set_default(arr, idx, v)
                    return
            obj = self.eval(base, sc)
            if isinstance(obj, list):
                self.set_index(obj, idx, v)
            elif isinstance(obj, J.Host):
                self.com_set_default(obj, idx, v)
        elif k == "member":
            obj = self.eval(target[1], sc)
            self.put(obj, target[2], v, line)
        elif k == "withmember":
            if self.with_stack:
                self.put(self.with_stack[-1], target[1], v, line)
        elif k == "paren":
            self.assign(target[1], v, sc, line)

    def com_set_default(self, h: J.Host, idx: list, v: Any) -> None:
        if h.kind == "Dictionary" and idx:
            h.st["d"][vb_str(idx[0])] = v

    def set_index(self, arr: list, idx: list, v: Any) -> None:
        a = arr
        for j, i in enumerate(idx):
            n = vb_int(i)
            if n < 0:
                raise VBError("Subscript out of range")
            if j == len(idx) - 1:
                if isinstance(a, bytearray):
                    a[n] = vb_int(v) & 0xFF
                    return
                while len(a) <= n:
                    if len(a) > MAX_LOOP:
                        raise VBError("Subscript out of range")
                    a.append(EMPTY)
                a[n] = v
                return
            a = a[n]

    def put(self, obj: Any, name: str, v: Any, line: int | None) -> None:
        if isinstance(obj, J.Host):
            self.com.host_set(obj, name, v, line)
        elif isinstance(obj, dict):
            obj[name.lower()] = v

    # -- calls ------------------------------------------------------------------------------------------
    def call_stmt(self, target: tuple, args: list | None, sc: Scope, line: int | None) -> None:
        if args is None:
            if target[0] == "call":
                self.eval_call(target[1], target[2], sc, line, stmt=True)
            else:
                self.eval_call(target, [], sc, line, stmt=True)
            return
        # "foo (a), b" / "foo a, b": a call without parentheses
        if target[0] == "call" and target[1][0] in ("id", "member", "withmember") and False:
            pass
        self.eval_call(target, args, sc, line, stmt=True)

    def eval_args(self, args: list, sc: Scope) -> list:
        out = []
        for a in args:
            if a[0] == "missing":
                out.append(EMPTY)
            else:
                out.append(self.eval(a, sc))
        return out

    def eval_call(self, callee: tuple, args: list, sc: Scope, line: int | None, stmt: bool = False) -> Any:  # noqa: C901
        k = callee[0]
        if k == "id":
            name = callee[1]
            low = name.lower()
            # a variable: an array index or a COM object's default member
            s = self.find_scope(low, sc)
            if s is not None and low not in self.procs:
                v = s.vars[low]
                if isinstance(v, list) and args:
                    return self.index(v, self.eval_args(args, sc))
                if isinstance(v, J.Host) and args:
                    return self.com_default(v, self.eval_args(args, sc), line)
                if isinstance(v, Ref):
                    return self.call_proc(v.proc, args, sc, line)
                if isinstance(v, Unk):
                    if not args:
                        return v
                    if not v.quiet:
                        self.sinks.unresolved_(self.text_of(line), v.why, "the function it calls is computed at run time", line)
                    return Unk(f"the result of {name}")
                if not args:
                    return v
                if isinstance(v, str) and args:
                    raise VBError(f"Type mismatch: '{name}'")
            if low in self.procs:
                return self.call_proc(self.procs[low], args, sc, line)
            if low in self.builtins:
                return self.builtins[low](self.eval_args(args, sc), line, sc)
            if low in ("wscript", "wsh"):
                return self.com.builtins["WScript"]
            if low in _MEM_APIS:
                self.api_load(name, args, sc, line)
                return 0
            if low == "err":
                return self.err()
            if not args:
                return EMPTY
            return Unk(f"'{name}' (not defined in the script)", quiet=True)
        if k in ("member", "withmember"):
            obj = self.eval(callee[1], sc) if k == "member" else (self.with_stack[-1] if self.with_stack else EMPTY)
            name = callee[2] if k == "member" else callee[1]
            if isinstance(obj, Unk):
                if not obj.quiet:
                    self.sinks.unresolved_(self.text_of(line), obj.why, "the object it calls is computed at run time", line)
                return Unk(f"the result of .{name}", quiet=obj.quiet)
            vals = self.eval_args(args, sc)
            return self.member_call(obj, name, vals, line)
        if k == "call":
            base = self.eval_call(callee[1], callee[2], sc, line)
            vals = self.eval_args(args, sc)
            if isinstance(base, list):
                return self.index(base, vals)
            if isinstance(base, J.Host):
                return self.com_default(base, vals, line)
            return base
        if k == "paren":
            return self.eval(callee[1], sc)
        return self.eval(callee, sc)

    def api_load(self, name: str, args: list, sc: Scope, line: int | None) -> None:
        """A Declare'd memory API (RtlMoveMemory, WriteProcessMemory…) fed from an array or a
        string of the script: those bytes are loaded (a shellcode runner)."""
        for a in args:
            base = a
            while base[0] in ("call", "paren"):
                base = base[1]
            if base[0] != "id":
                continue
            v = self.lookup_var(base[1].lower(), sc)
            raw = J.bin_of(v) if isinstance(v, (list, str, bytearray)) else None
            if raw and len(raw) >= 64 and id(v) not in self.loaded:
                self.loaded.add(id(v))
                self.sinks.load(Value("bytes", raw, rec(v)), f"{name} (Declare'd API)", line=line)

    def member_call(self, obj: Any, name: str, vals: list, line: int | None) -> Any:
        if isinstance(obj, J.Host):
            m = self.com.host_get(obj, name, None)
            if isinstance(m, (J.Native, J.JSFunc)):
                return self.from_js(self.com.invoke(m, obj, [self.to_js(x) for x in vals], None))
            if isinstance(m, J.Host) and vals:
                return self.com_default(m, vals, line)
            if isinstance(m, list) and vals:
                return self.index(m, vals)
            return self.from_js(m)
        if isinstance(obj, dict):
            return obj.get(name.lower(), EMPTY)
        if obj is EMPTY or obj is NOTHING:
            raise VBError(f"Object required: '{name}'")
        return EMPTY

    def com_default(self, h: J.Host, vals: list, line: int | None) -> Any:
        if h.kind == "callable":
            return self.from_js(h.st["fn"](J.UNDEF, [self.to_js(x) for x in vals], None))
        if h.kind == "Dictionary":
            return h.st["d"].get(vb_str(vals[0]) if vals else "", EMPTY)
        return EMPTY

    def to_js(self, v: Any) -> Any:
        if v is EMPTY:
            return J.UNDEF
        if v is NULL or v is NOTHING:
            return None
        return v

    def from_js(self, v: Any) -> Any:
        if v is J.UNDEF:
            return EMPTY
        if v is None:
            return NULL
        if isinstance(v, J.JSArr):
            out = VArr(v)
            try:
                out.recipe = rec(v)
            except AttributeError:
                pass
            return out
        return v

    def index(self, arr: list, idx: list) -> Any:
        a: Any = arr
        for i in idx:
            if isinstance(i, Unk):
                return Unk(i.why)
            n = vb_int(i)
            if not isinstance(a, (list, bytearray)) or not 0 <= n < len(a):
                raise VBError("Subscript out of range")
            a = a[n]
        return a

    def call_proc(self, p: Proc, args: list, sc: Scope, line: int | None) -> Any:
        if self.call_depth >= MAX_CALL_DEPTH:
            raise VBError("Out of stack space")
        new = Scope(None, p)
        byref: list[tuple[str, tuple]] = []
        for i, (pname, byval, default) in enumerate(p.params):
            low = pname.lower()
            if i < len(args) and args[i][0] != "missing":
                a = args[i]
                new.vars[low] = self.eval(a, sc)
                if not byval and a[0] == "id":
                    byref.append((low, a))
            else:
                new.vars[low] = self.eval(default, sc) if default is not None else EMPTY
        new.vars["\x00ret"] = EMPTY
        saved = self.source
        self.source = p.src
        self.call_depth += 1
        try:
            self.block(p.body, new)
        except _Exit as e:
            if e.kind not in ("function", "sub", "property"):
                raise
        finally:
            self.call_depth -= 1
            self.source = saved
        for low, a in byref:
            s = self.find_scope(a[1].lower(), sc)
            if s is not None and a[1].lower() in s.vars:
                s.vars[a[1].lower()] = new.vars.get(low, EMPTY)
        return new.vars.get("\x00ret", EMPTY)

    # -- expressions ---------------------------------------------------------------------------------------
    def eval(self, e: tuple, sc: Scope) -> Any:  # noqa: C901, PLR0911
        self.tick()
        k = e[0]
        if k == "num":
            return e[1]
        if k == "str":
            return e[1]
        if k == "const":
            return e[1]
        if k == "paren":
            return self.eval(e[1], sc)
        if k == "id":
            return self.eval_call(e, [], sc, e[2])
        if k == "call":
            return self.eval_call(e[1], e[2], sc, self._line_of(e))
        if k == "member":
            obj = self.eval(e[1], sc)
            if isinstance(obj, Unk):
                return Unk(obj.why, obj.recipe, obj.quiet)
            return self.member_call(obj, e[2], [], None)
        if k == "withmember":
            obj = self.with_stack[-1] if self.with_stack else EMPTY
            return self.member_call(obj, e[1], [], None)
        if k == "bin":
            op = e[1]
            if op in ("and", "or"):
                a = self.eval(e[2], sc)
                b = self.eval(e[3], sc)
                return self.binop(op, a, b)
            return self.binop(op, self.eval(e[2], sc), self.eval(e[3], sc))
        if k == "un":
            v = self.eval(e[2], sc)
            if isinstance(v, Unk):
                return Unk(v.why)
            if e[1] == "-":
                n = vb_num(v)
                return -n
            if isinstance(v, bool):
                return not v
            return ~vb_int(v)
        if k == "new":
            return {"__class__": e[1]}
        if k == "missing":
            return EMPTY
        raise VBError(f"{k} not followed")

    @staticmethod
    def _line_of(e: Any) -> int | None:
        while isinstance(e, tuple) and e:
            if e[0] in ("id", "str") and len(e) > 2:
                return e[2]
            if e[0] in ("call", "member", "paren"):
                e = e[1]
                continue
            return None
        return None

    def binop(self, op: str, a: Any, b: Any) -> Any:  # noqa: C901, PLR0911, PLR0912
        if isinstance(a, Unk) or isinstance(b, Unk):
            u = a if isinstance(a, Unk) else b
            return Unk(u.why, u.recipe if op in ("&", "+") else ())
        if op == "&":
            sa, sb = vb_str(a), vb_str(b)
            if len(sa) + len(sb) > MAX_STR:
                raise Limit("string size")
            out = sa + sb
            ra, rb = rec(a), rec(b)
            r = ra if (ra and (len(sa) >= len(sb) or not rb)) else rb
            return tag(out, r) if r else out
        if op == "+":
            if isinstance(a, str) and isinstance(b, str):
                return self.binop("&", a, b)
            if a is EMPTY and isinstance(b, str):
                return b
            if b is EMPTY and isinstance(a, str):
                return a
            return self.num(vb_num(a) + vb_num(b))
        if op in ("=", "<>", "<", ">", "<=", ">="):
            if a is NULL or b is NULL:
                return NULL
            if isinstance(a, str) and isinstance(b, str):
                x, y = str(a), str(b)
            elif isinstance(a, str) and not is_numeric(a) or isinstance(b, str) and not is_numeric(b):
                x, y = vb_str(a), vb_str(b)
            else:
                x, y = vb_num(a), vb_num(b)
            return {"=": x == y, "<>": x != y, "<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]
        if op == "is":
            return a is b
        if op == "like":
            pat = "^" + re.escape(vb_str(b)).replace(r"\*", ".*").replace(r"\?", ".").replace(r"\#", r"\d") + "$"
            return bool(re.match(pat, vb_str(a), re.I))
        if op in ("and", "or", "xor", "eqv", "imp"):
            if isinstance(a, bool) and isinstance(b, bool):
                return {"and": a and b, "or": a or b, "xor": a != b, "eqv": a == b, "imp": (not a) or b}[op]
            x, y = vb_int(a), vb_int(b)
            return {"and": x & y, "or": x | y, "xor": x ^ y, "eqv": ~(x ^ y), "imp": (~x) | y}[op]
        x, y = vb_num(a), vb_num(b)
        if op == "-":
            return self.num(x - y)
        if op == "*":
            return self.num(x * y)
        if op == "/":
            if y == 0:
                raise VBError("Division by zero")
            return self.num(x / y)
        if op == "\\":
            yi = vb_int(y)
            if yi == 0:
                raise VBError("Division by zero")
            xi = vb_int(x)
            q = abs(xi) // abs(yi)
            return q if (xi >= 0) == (yi >= 0) else -q
        if op == "mod":
            yi = vb_int(y)
            if yi == 0:
                raise VBError("Division by zero")
            xi = vb_int(x)
            r = abs(xi) % abs(yi)
            return r if xi >= 0 else -r
        if op == "^":
            try:
                return self.num(x ** y)
            except (OverflowError, ZeroDivisionError) as exc:
                raise VBError("Overflow") from exc
        raise VBError(op)

    @staticmethod
    def num(n: float | int) -> float | int:
        if isinstance(n, float) and n.is_integer() and abs(n) < 2 ** 53:
            return int(n)
        return n

    def iterate(self, v: Any) -> list:
        if isinstance(v, (list, bytearray)):
            return list(v)
        if isinstance(v, J.Host):
            if v.kind == "Dictionary":
                return list(v.st["d"].keys())
            if v.kind in ("Enumerator",):
                return list(v.st.get("items", []))
            return []
        if isinstance(v, Unk):
            return []
        return []

    def err(self) -> J.Host:
        h = J.Host("COM", progid="Err")
        h.props.update({"Number": 0, "number": 0, "Description": "", "description": ""})
        return h

    # -- Execute / Eval ---------------------------------------------------------------------------------------
    def execute(self, code: Any, sink: str, line: int | None, sc: Scope, want: bool = False) -> Any:
        if isinstance(code, Unk):
            self.sinks.exec_(Value.unknown(code.why), sink, line)
            return Unk(f"the result of code computed from {code.why}")
        text = vb_str(code)
        if want:
            # Eval: an expression (no stage for a plain constant / name)
            try:
                toks = tokenize(text)
                p = Parser(toks, text)
                e = p.expr()
                if p.peek().kind in ("nl", "eof"):
                    if len(text) >= 12:
                        self.sinks.exec_(Value("str", text, rec(code)), sink, line)
                    return self.eval(e, sc)
            except (SyntaxError, IndexError):
                pass
        self.sinks.exec_(Value("str", text, rec(code)), sink, line)
        h = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if self.depth >= MAX_DEPTH or h in self.ran:
            return EMPTY
        self.ran.add(h)
        try:
            prog = self.parse(text)
        except (SyntaxError, RecursionError) as exc:
            self.errors.append(f"line {line}: {sink} of code that does not parse: {exc}"[:300])
            return EMPTY
        self.depth += 1
        self.sinks.depth = self.depth
        saved = self.source
        self.source = text
        try:
            self.hoist(prog)
            self.block(prog, self.g if sink.startswith("ExecuteGlobal") else sc, top=True)
        finally:
            self.source = saved
            self.depth -= 1
            self.sinks.depth = self.depth
        return EMPTY

    # -- built-in functions --------------------------------------------------------------------------------
    def _builtins(self) -> dict[str, Callable[..., Any]]:  # noqa: C901, PLR0915
        B: dict[str, Callable[..., Any]] = {}

        def unk_guard(fn: Callable[..., Any]) -> Callable[..., Any]:
            def g(a: list, line: int | None, sc: Scope) -> Any:
                for x in a:
                    if isinstance(x, Unk):
                        return Unk(x.why, x.recipe)
                return fn(a, line, sc)
            return g

        def reg(name: str, keep_unk: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
            def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
                B[name] = fn if keep_unk else unk_guard(fn)
                return fn
            return deco

        def a_(a: list, i: int, d: Any = EMPTY) -> Any:
            return a[i] if len(a) > i and a[i] is not EMPTY else d

        @reg("chr")
        def _chr(a: list, line: Any, sc: Any) -> Any:
            n = vb_int(a_(a, 0, 0))
            if not -32768 <= n <= 65535:
                raise VBError("Invalid procedure call (Chr)")
            return chr(n & 0xFFFF if n >= 0 else (n + 65536))
        B["chrw"] = B["chr"]
        B["chrb"] = B["chr"]
        B["chr$"] = B["chr"]

        @reg("asc")
        def _asc(a: list, line: Any, sc: Any) -> Any:
            s = vb_str(a_(a, 0, ""))
            if not s:
                raise VBError("Invalid procedure call (Asc)")
            return ord(s[0])
        B["ascw"] = B["asc"]
        B["ascb"] = B["asc"]

        @reg("mid")
        def _mid(a: list, line: Any, sc: Any) -> Any:
            s = a_(a, 0, "")
            if isinstance(s, (bytes, bytearray)):
                s2 = bytes(s).decode("latin-1")
            else:
                s2 = vb_str(s)
            st = vb_int(a_(a, 1, 1))
            if st < 1:
                raise VBError("Invalid procedure call (Mid)")
            out = s2[st - 1:] if len(a) < 3 or a[2] is EMPTY else s2[st - 1:st - 1 + max(0, vb_int(a[2]))]
            return self.keep(s, out)
        B["midb"] = B["mid"]
        B["mid$"] = B["mid"]

        @reg("left")
        def _left(a: list, line: Any, sc: Any) -> Any:
            s = vb_str(a_(a, 0, ""))
            return self.keep(a[0], s[:max(0, vb_int(a_(a, 1, 0)))])

        @reg("right")
        def _right(a: list, line: Any, sc: Any) -> Any:
            s = vb_str(a_(a, 0, ""))
            n = max(0, vb_int(a_(a, 1, 0)))
            return self.keep(a[0], s[-n:] if n else "")
        B["left$"], B["right$"] = B["left"], B["right"]

        @reg("len")
        def _len(a: list, line: Any, sc: Any) -> Any:
            v = a_(a, 0, "")
            if isinstance(v, (bytes, bytearray)):
                return len(v)
            return len(vb_str(v))
        B["lenb"] = B["len"]

        @reg("instr")
        def _instr(a: list, line: Any, sc: Any) -> Any:
            if len(a) >= 3 and isinstance(a[0], (int, float)) and not isinstance(a[0], bool):
                start, s, sub = vb_int(a[0]), vb_str(a[1]), vb_str(a[2])
                ci = len(a) > 3 and vb_int(a[3]) == 1
            else:
                start, s, sub = 1, vb_str(a_(a, 0, "")), vb_str(a_(a, 1, ""))
                ci = False
            if ci:
                s, sub = s.lower(), sub.lower()
            return s.find(sub, max(0, start - 1)) + 1
        B["instrb"] = B["instr"]

        @reg("instrrev")
        def _instrrev(a: list, line: Any, sc: Any) -> Any:
            s, sub = vb_str(a_(a, 0, "")), vb_str(a_(a, 1, ""))
            return s.rfind(sub) + 1

        @reg("replace")
        def _replace(a: list, line: Any, sc: Any) -> Any:
            s, f, r = vb_str(a_(a, 0, "")), vb_str(a_(a, 1, "")), vb_str(a_(a, 2, ""))
            if not f:
                return s
            ci = len(a) > 5 and vb_int(a[5]) == 1
            cnt = vb_int(a[4]) if len(a) > 4 and a[4] is not EMPTY else -1
            if ci:
                out = re.sub(re.escape(f), lambda m: r, s, count=0 if cnt < 0 else cnt, flags=re.I)
            else:
                out = s.replace(f, r, cnt)
            if len(s) >= 16 and out != s:
                return tag(out, rec(a[0]) + (f"replace({f[:12]!r} → {r[:12]!r})",))
            return self.keep(a[0], out)

        @reg("strreverse")
        def _rev(a: list, line: Any, sc: Any) -> Any:
            s = vb_str(a_(a, 0, ""))
            return step(a[0], "reverse", s[::-1]) if len(s) >= 16 else s[::-1]

        @reg("split")
        def _split(a: list, line: Any, sc: Any) -> Any:
            s = vb_str(a_(a, 0, ""))
            d = vb_str(a[1]) if len(a) > 1 and a[1] is not EMPTY else " "
            out = VArr(s.split(d) if d else [s])
            out.recipe = rec(a[0])
            return out

        @reg("join")
        def _join(a: list, line: Any, sc: Any) -> Any:
            arr = a_(a, 0, VArr())
            d = vb_str(a[1]) if len(a) > 1 and a[1] is not EMPTY else " "
            out = d.join(vb_str(x) for x in arr)
            return tag(out, rec(arr)) if rec(arr) and len(out) >= 16 else out

        @reg("array")
        def _array(a: list, line: Any, sc: Any) -> Any:
            return VArr(a)

        @reg("ubound")
        def _ub(a: list, line: Any, sc: Any) -> Any:
            v = a_(a, 0, VArr())
            if not isinstance(v, (list, bytearray)):
                raise VBError("Type mismatch (UBound)")
            dim = vb_int(a_(a, 1, 1))
            for _ in range(dim - 1):
                v = v[0] if v else VArr()
            return len(v) - 1

        @reg("lbound")
        def _lb(a: list, line: Any, sc: Any) -> Any:
            return 0

        @reg("lcase")
        def _lc(a: list, line: Any, sc: Any) -> Any:
            return self.keep(a_(a, 0, ""), vb_str(a_(a, 0, "")).lower())

        @reg("ucase")
        def _uc(a: list, line: Any, sc: Any) -> Any:
            return self.keep(a_(a, 0, ""), vb_str(a_(a, 0, "")).upper())

        @reg("trim")
        def _trim(a: list, line: Any, sc: Any) -> Any:
            return self.keep(a_(a, 0, ""), vb_str(a_(a, 0, "")).strip(" "))
        B["ltrim"] = unk_guard(lambda a, l, s: vb_str(a_(a, 0, "")).lstrip(" "))
        B["rtrim"] = unk_guard(lambda a, l, s: vb_str(a_(a, 0, "")).rstrip(" "))
        B["space"] = unk_guard(lambda a, l, s: " " * min(vb_int(a_(a, 0, 0)), MAX_STR))
        B["string"] = unk_guard(lambda a, l, s: (vb_str(a[1])[:1] if isinstance(a[1], str) else chr(vb_int(a[1]))) * min(vb_int(a[0]), MAX_STR))

        @reg("cstr")
        def _cstr(a: list, line: Any, sc: Any) -> Any:
            return self.keep(a_(a, 0, ""), vb_str(a_(a, 0, "")))
        B["cint"] = unk_guard(lambda a, l, s: vb_int(a_(a, 0, 0)))
        B["clng"] = B["cint"]
        B["clnglng"] = B["cint"]
        B["cbyte"] = unk_guard(lambda a, l, s: vb_int(a_(a, 0, 0)) & 0xFF)
        B["cdbl"] = unk_guard(lambda a, l, s: float(vb_num(a_(a, 0, 0))))
        B["csng"] = B["cdbl"]
        B["ccur"] = B["cdbl"]
        B["cbool"] = unk_guard(lambda a, l, s: vb_bool(a_(a, 0, False)))
        B["int"] = unk_guard(lambda a, l, s: math.floor(vb_num(a_(a, 0, 0))))
        B["fix"] = unk_guard(lambda a, l, s: math.trunc(vb_num(a_(a, 0, 0))))
        B["abs"] = unk_guard(lambda a, l, s: abs(vb_num(a_(a, 0, 0))))
        B["sgn"] = unk_guard(lambda a, l, s: (vb_num(a_(a, 0, 0)) > 0) - (vb_num(a_(a, 0, 0)) < 0))
        B["sqr"] = unk_guard(lambda a, l, s: self.num(math.sqrt(vb_num(a_(a, 0, 0)))))
        B["round"] = unk_guard(lambda a, l, s: self.num(round(vb_num(a_(a, 0, 0)), vb_int(a_(a, 1, 0)))))
        B["hex"] = unk_guard(lambda a, l, s: format(vb_int(a_(a, 0, 0)) & 0xFFFFFFFF if vb_int(a_(a, 0, 0)) < 0 else vb_int(a_(a, 0, 0)), "X"))
        B["oct"] = unk_guard(lambda a, l, s: format(vb_int(a_(a, 0, 0)), "o"))
        B["val"] = unk_guard(lambda a, l, s: self._val(vb_str(a_(a, 0, ""))))
        B["isnumeric"] = unk_guard(lambda a, l, s: is_numeric(a_(a, 0, "")))
        B["isarray"] = lambda a, l, s: isinstance(a_(a, 0), list)
        B["isempty"] = lambda a, l, s: a_(a, 0, EMPTY) is EMPTY
        B["isnull"] = lambda a, l, s: a_(a, 0) is NULL
        B["isobject"] = lambda a, l, s: isinstance(a_(a, 0), (J.Host, dict))
        B["typename"] = lambda a, l, s: self._typename(a_(a, 0))
        B["vartype"] = lambda a, l, s: {"Empty": 0, "Null": 1, "Integer": 2, "Long": 3, "Double": 5, "String": 8,
                                         "Object": 9, "Boolean": 11, "Variant()": 8204}.get(self._typename(a_(a, 0)), 9)
        B["strcomp"] = unk_guard(lambda a, l, s: (lambda x, y: (x > y) - (x < y))(vb_str(a[0]), vb_str(a[1])))
        B["escape"] = unk_guard(lambda a, l, s: J.Interp.__dict__ and self.com.builtins["escape"].fn(J.UNDEF, [vb_str(a[0])], None))

        @reg("unescape")
        def _unesc(a: list, line: Any, sc: Any) -> Any:
            return self.com.builtins["unescape"].fn(J.UNDEF, [a[0]], None)
        B["filter"] = unk_guard(lambda a, l, s: VArr(x for x in a[0] if vb_str(a[1]) in vb_str(x)))
        for name in ("now", "date", "time", "timer", "day", "month", "year", "hour", "minute", "second",
                     "weekday", "dateadd", "datediff", "datepart", "dateserial", "timeserial", "cdate", "monthname",
                     "weekdayname", "formatdatetime"):
            B[name] = lambda a, l, s, _n=name: Unk("the current date")
        B["rnd"] = lambda a, l, s: Unk("a random number")
        B["randomize"] = lambda a, l, s: EMPTY
        B["msgbox"] = lambda a, l, s: 1
        B["inputbox"] = lambda a, l, s: Unk("what the user types")
        B["sgn"] = B["sgn"]
        B["exp"] = unk_guard(lambda a, l, s: self.num(math.exp(vb_num(a[0]))))
        B["log"] = unk_guard(lambda a, l, s: self.num(math.log(vb_num(a[0]))))
        B["atn"] = unk_guard(lambda a, l, s: self.num(math.atan(vb_num(a[0]))))
        B["sin"] = unk_guard(lambda a, l, s: self.num(math.sin(vb_num(a[0]))))
        B["cos"] = unk_guard(lambda a, l, s: self.num(math.cos(vb_num(a[0]))))
        B["scriptengine"] = lambda a, l, s: "VBScript"

        def _execute(name: str) -> Callable[..., Any]:
            def f(a: list, line: int | None, sc: Scope) -> Any:
                return self.execute(a[0] if a else "", self.called_as(name, line), line, sc, want=name == "Eval")
            return f
        B["execute"] = _execute("Execute")
        B["executeglobal"] = _execute("ExecuteGlobal")
        B["eval"] = _execute("Eval")

        def _getref(a: list, line: int | None, sc: Scope) -> Any:
            n = a[0] if a else ""
            if isinstance(n, Unk):
                self.sinks.unresolved_(self.text_of(line), n.why, "GetRef of a name computed at run time", line)
                return Unk(f"GetRef of {n.why}")
            p = self.procs.get(vb_str(n).lower())
            return Ref(p) if p else EMPTY
        B["getref"] = _getref

        def _create(a: list, line: int | None, sc: Scope) -> Any:
            p = a[0] if a else ""
            if isinstance(p, Unk):
                self.sinks.unresolved_(self.text_of(line), p.why, "the COM object it creates is named at run time", line)
                return Unk(f"a COM object named from {p.why}")
            return self.com.com(p, None)
        B["createobject"] = _create
        B["getobject"] = _create
        return B

    def called_as(self, name: str, line: int | None) -> str:
        src = self.text_of(line) if line else ""
        if src and not re.search(rf"(?i)\b{name}\b", src):
            return f"{name} (called as {src[:60]})"
        return name

    @staticmethod
    def _val(s: str) -> Any:
        m = re.match(r"\s*(&[Hh][0-9A-Fa-f]+|[+-]?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)", s)
        if not m:
            return 0
        t = m.group(1)
        return int(t[2:], 16) if t.startswith("&") else (float(t) if re.search(r"[.eE]", t) else int(t))

    def _typename(self, v: Any) -> str:
        if v is EMPTY:
            return "Empty"
        if v is NULL:
            return "Null"
        if v is NOTHING:
            return "Nothing"
        if isinstance(v, bool):
            return "Boolean"
        if isinstance(v, int):
            return "Long" if abs(v) > 32767 else "Integer"
        if isinstance(v, float):
            return "Double"
        if isinstance(v, str):
            return "String"
        if isinstance(v, list):
            return "Variant()"
        if isinstance(v, (bytes, bytearray)):
            return "Byte()"
        return "Object"

    def keep(self, src: Any, out: Any) -> Any:
        r = rec(src)
        if r and isinstance(out, (str, list, bytearray)) and len(out) >= 16:
            return tag(out, r)
        return out

    # -- the values a script computed ------------------------------------------------------------------------
    def to_value(self, v: Any) -> Value:
        return self.com.to_value(v)

    def computed_values(self) -> None:
        from . import langdetect
        seen: set[int] = set()
        for name, v in list(self.g.vars.items()) + list(self.tracked.items()):
            if id(v) in seen or not isinstance(v, (str, bytearray, list)) or len(v) < 40:
                continue
            seen.add(id(v))
            r = rec(v)
            ops = [x for x in r if not x.startswith(("literal", "number array"))]
            if not ops:
                continue
            raw = J.bin_of(v) if not isinstance(v, bytearray) else bytes(v)
            if raw is None:
                continue
            if any(st.recipe[:len(r)] == r and len(st.recipe) > len(r) for st in self.sinks.stages):
                continue
            kind = T.magic(raw)
            if not kind and isinstance(v, str) and T.is_text(raw):
                txt = str(v)
                if txt in self.source:
                    continue
                if langdetect.languages(txt):
                    self.sinks.exec_(Value("str", txt, r), f"value of {name} (computed, not run here)")
                    continue
                if re.search(r"(?i)\bhttps?://|\b\d{1,3}(?:\.\d{1,3}){3}\b", txt):
                    self.sinks.value_(Value("str", txt, r), f"value of {name} (decoded text with IOCs)")
                continue
            if kind:
                self.sinks.load(Value("bytes", raw, r), f"value of {name} (computed, not run here)")


def resolve(code: str, location: str = "vbscript") -> Sinks:
    """Evaluate a VBScript statically; its stages, downloads, unresolved calls and trace."""
    s = Sinks("vbscript")
    code = code.lstrip("\ufeff")
    it = Interp(s, code)
    try:
        it.run(code)
    except RecursionError:
        it.errors.append("recursion")
    s.errors = it.errors + it.com.errors  # type: ignore[attr-defined]
    s.stats = {"steps": it.steps, "seconds": round(time.monotonic() - it.t0, 2)}  # type: ignore[attr-defined]
    return s
