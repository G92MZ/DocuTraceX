"""PowerShell: tokens and syntax tree of the subset loaders are written in.

Not a full PowerShell grammar: enough to follow what a loader computes — variables,
here-strings, functions with parameters, .NET calls, operators (``-bxor``, ``-join``, ``-f``,
``-replace``…), loops and conditions, pipelines, script blocks and commands whose name is
computed (``& ("Inv"+"oke-Expression")``). Whatever it cannot parse becomes an ``unknown``
statement and the rest of the script is still read.

The tree is plain tuples: ``(kind, line, *fields)``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

KEYWORDS = {"if", "elseif", "else", "while", "do", "until", "for", "foreach", "in", "switch", "function",
            "filter", "param", "return", "break", "continue", "throw", "try", "catch", "finally", "trap",
            "begin", "process", "end", "exit", "class", "using", "dynamicparam"}

OPERATORS = {
    "and", "or", "xor", "not", "band", "bor", "bxor", "bnot", "shl", "shr", "join", "split", "isplit", "csplit",
    "replace", "ireplace", "creplace", "f", "eq", "ne", "gt", "ge", "lt", "le", "ieq", "ine", "igt", "ige", "ilt",
    "ile", "ceq", "cne", "cgt", "cge", "clt", "cle", "like", "notlike", "ilike", "clike", "match", "notmatch",
    "imatch", "cmatch", "contains", "notcontains", "icontains", "ccontains", "in", "notin", "is", "isnot", "as",
}
CMP_OPS = OPERATORS - {"and", "or", "xor", "not", "band", "bor", "bxor", "bnot", "shl", "shr", "f"}
BIT_OPS = {"band", "bor", "bxor", "shl", "shr"}


@dataclass
class Tok:
    kind: str           # VAR STR XSTR NUM NUMLIST TYPE WORD PARAM OP PUNCT NL EOF
    value: Any
    line: int
    sp: bool            # whitespace before it
    pos: int = 0


class ParseError(Exception):
    pass


_WS = re.compile(r"[ \t\f\v\u00a0\ufeff]+|`\r?\n")       # a backtick at the end of a line continues it
_COMMENT = re.compile(r"#[^\r\n]*")
_BLOCK_COMMENT = re.compile(r"<#.*?#>", re.S)
_NL = re.compile(r"\r?\n|\r")
_HERE = re.compile(r"@(['\"])[ \t]*\r?\n(.*?)\r?\n[ \t]*\1@", re.S)
_VAR = re.compile(r"\$(?:\{(?P<b>[^}]+)\}|(?P<n>(?:[A-Za-z_][\w]*:)?[A-Za-z_\d?^$][\w]*|[?^$_]))")
_NUM = re.compile(r"(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(?:[lL]|[dD])?(?:[kK][bB]|[mM][bB]|[gG][bB])?(?![\w])")
_NUMLIST = re.compile(r"(?:-?(?:0[xX][0-9A-Fa-f]+|\d{1,10})\s*,\s*(?:`?\r?\n\s*)?){31,}-?(?:0[xX][0-9A-Fa-f]+|\d{1,10})(?![\w.])")
_ATTRIBUTE = re.compile(r"\[\s*(?:Parameter|Validate\w*|Alias|Allow\w*|CmdletBinding|OutputType|SupportsWildcards|"
                        r"PSDefaultValue|Diagnostics\.CodeAnalysis\.\w+|System\.\w+Attribute)\s*\((?:[^()]|\([^()]*\))*\)\s*\]",
                        re.I)
_TYPE = re.compile(r"\[\s*([A-Za-z_][\w.`]*(?:\s*\[[\w.,\s\[\]]*\])*)\s*\]")
_WORD = re.compile(r"[A-Za-z_\u0080-\uffff](?:`(?=[\w-])|[\w\-\u0080-\uffff])*(?:\.[A-Za-z]\w*)*|[?%]")
_DASHWORD = re.compile(r"-([A-Za-z][\w]*)(:)?")
_PUNCT = ("+=", "-=", "*=", "/=", "%=", "++", "--", "..", "::", "$(", "@(", "@{", "&&", "||", "2>&1", "2>", ">>",
          "=", "+", "-", "*", "/", "%", "(", ")", "{", "}", "[", "]", ",", ";", ".", "|", "&", "!", ">", "<", "@")
_VALUE_END = {"VAR", "STR", "XSTR", "NUM", "NUMLIST", "TYPE"}


def _num_value(t: str) -> int | float:
    s = t.lower()
    mult = 1
    for suf, m in (("kb", 1024), ("mb", 1024 ** 2), ("gb", 1024 ** 3)):
        if s.endswith(suf):
            s, mult = s[:-2], m
    s = s.rstrip("ld")
    v: int | float = int(s, 16) if s.startswith("0x") else (float(s) if any(c in s for c in ".e") and not s.startswith("0x") else int(s))
    return v * mult


def tokenize(code: str) -> list[Tok]:
    out: list[Tok] = []
    i, n, line = 0, len(code), 1
    sp = True
    while i < n:
        m = _WS.match(code, i)
        if m:
            line += m.group(0).count("\n")
            i, sp = m.end(), True
            continue
        c = code[i]
        if code.startswith("<#", i):
            m = _BLOCK_COMMENT.match(code, i)
            end = m.end() if m else n
            line += code.count("\n", i, end)
            i, sp = end, True
            continue
        if c == "#":
            m = _COMMENT.match(code, i)
            i = m.end()
            continue
        m = _NL.match(code, i)
        if m:
            out.append(Tok("NL", None, line, sp, i))
            line += 1
            i, sp = m.end(), True
            continue
        start_line = line
        if c == "@" and i + 1 < n and code[i + 1] in "'\"":
            m = _HERE.match(code, i)
            if m:
                out.append(Tok("STR" if m.group(1) == "'" else "XSTR", m.group(2), start_line, sp, i))
                line += m.group(0).count("\n")
                i, sp = m.end(), False
                continue
        if c == "'" or c in "\u2018\u2019":
            j = i + 1
            buf = []
            while j < n:
                if code[j] in "'\u2018\u2019":
                    if j + 1 < n and code[j + 1] in "'\u2018\u2019":
                        buf.append("'")
                        j += 2
                        continue
                    break
                buf.append(code[j])
                j += 1
            s = "".join(buf)
            out.append(Tok("STR", s, start_line, sp, i))
            line += s.count("\n")
            i, sp = j + 1, False
            continue
        if c == '"' or c in "\u201c\u201d":
            j = i + 1
            while j < n:
                if code[j] == "`" and j + 1 < n:
                    j += 2
                    continue
                if code[j] in '"\u201c\u201d':
                    if j + 1 < n and code[j + 1] in '"\u201c\u201d':
                        j += 2
                        continue
                    break
                if code[j] == "$" and j + 1 < n and code[j + 1] == "(":
                    depth, j = 1, j + 2
                    while j < n and depth:
                        depth += {"(": 1, ")": -1}.get(code[j], 0)
                        j += 1
                    continue
                j += 1
            s = code[i + 1:j]
            out.append(Tok("XSTR", s, start_line, sp, i))
            line += s.count("\n")
            i, sp = j + 1, False
            continue
        if c == "$" and not code.startswith("$(", i):
            m = _VAR.match(code, i)
            if m:
                out.append(Tok("VAR", (m.group("b") or m.group("n")), line, sp, i))
                i, sp = m.end(), False
                continue
        if c.isdigit() or (c == "-" and i + 1 < n and code[i + 1].isdigit() and (
                not out or out[-1].kind in ("OP", "NL")
                or (out[-1].kind == "PUNCT" and out[-1].value in ("(", ",", "=", "@(", "[", "..", "+", "*", "/", "%", "{", ";")))):
            m = _NUMLIST.match(code, i)
            if m:
                vals = [int(x, 16) if x.lower().lstrip("-").startswith("0x") else int(x)
                        for x in re.findall(r"-?0[xX][0-9A-Fa-f]+|-?\d+", m.group(0))]
                out.append(Tok("NUMLIST", vals, line, sp, i))
                line += m.group(0).count("\n")
                i, sp = m.end(), False
                continue
            m = _NUM.match(code, i + 1 if c == "-" else i)
            if m:
                v = _num_value(m.group(0))
                out.append(Tok("NUM", -v if c == "-" else v, line, sp, i))
                i, sp = m.end(), False
                continue
        if c == "[":
            prev = out[-1] if out else None
            value_before = prev is not None and not prev.sp and (prev.kind in _VALUE_END or (prev.kind == "PUNCT" and prev.value in (")", "]", "}")) or prev.kind == "WORD")
            if not value_before:
                m = _ATTRIBUTE.match(code, i)
                if m:                                   # [Parameter(Mandatory)]: says nothing about values
                    line += m.group(0).count("\n")
                    i, sp = m.end(), True
                    continue
                m = _TYPE.match(code, i)
                if m and not re.fullmatch(r"\d+", m.group(1)):
                    out.append(Tok("TYPE", m.group(1).replace("`", "").replace(" ", ""), line, sp, i))
                    i, sp = m.end(), False
                    continue
        if c == "-" or c in "\u2013\u2014":
            m = _DASHWORD.match(code, i) if c == "-" else _DASHWORD.match("-" + code[i + 1:], 0)
            if m:
                w = m.group(1).lower()
                end = i + len(m.group(0)) - (0 if c == "-" else 0)
                if w in OPERATORS:
                    out.append(Tok("OP", w, line, sp, i))
                else:
                    out.append(Tok("PARAM", m.group(1), line, sp, i))
                i, sp = end, False
                continue
        if c in "%?" and (not out or out[-1].kind == "NL" or (out[-1].kind == "PUNCT" and out[-1].value in ("|", ";", "{", "("))) \
                and (i + 1 >= n or code[i + 1] in " \t{"):
            out.append(Tok("WORD", c, line, sp, i))          # ForEach-Object / Where-Object aliases
            i, sp = i + 1, False
            continue
        if c.isalpha() or c == "_" or ord(c) > 0x7F:
            m = _WORD.match(code, i)
            if m:
                w = m.group(0)
                # a word followed by .member is a type or a call target, keep the dot out
                if "." in w and not re.match(r"(?i)[a-z_][\w`-]*\.(?:exe|dll|ps1|bat|cmd|vbs|js|txt)$", w):
                    w = w.split(".", 1)[0]
                out.append(Tok("WORD", w, line, sp, i))           # backticks kept: resolve_name drops them
                i, sp = i + len(w), False
                continue
        for p in _PUNCT:
            if code.startswith(p, i):
                out.append(Tok("PUNCT", p, line, sp, i))
                i, sp = i + len(p), False
                break
        else:
            out.append(Tok("PUNCT", c, line, sp, i))
            i, sp = i + 1, False
    out.append(Tok("EOF", None, line, True, n))
    return out


# --- parser ---------------------------------------------------------------------------
_ASSIGN = {"=", "+=", "-=", "*=", "/=", "%="}
_STMT_END = {";", "}", ")"}


class Parser:
    def __init__(self, toks: list[Tok], code: str = "") -> None:
        self.t = toks
        self.i = 0
        self.code = code

    # -- helpers ------------------------------------------------------------------------
    @property
    def cur(self) -> Tok:
        return self.t[self.i]

    def peek(self, k: int = 1) -> Tok:
        return self.t[min(self.i + k, len(self.t) - 1)]

    def is_(self, kind: str, value: Any = None, tok: Tok | None = None) -> bool:
        t = tok or self.cur
        if t.kind != kind:
            return False
        if value is None:
            return True
        if isinstance(value, (set, tuple, frozenset)):
            return (t.value.lower() if isinstance(t.value, str) else t.value) in value
        return (t.value.lower() if isinstance(t.value, str) and kind == "WORD" else t.value) == value

    def eat(self, kind: str, value: Any = None) -> Tok:
        if not self.is_(kind, value):
            raise ParseError(f"line {self.cur.line}: expected {value or kind}, found {self.cur.value!r}")
        t = self.cur
        self.i += 1
        return t

    def accept(self, kind: str, value: Any = None) -> Tok | None:
        if self.is_(kind, value):
            t = self.cur
            self.i += 1
            return t
        return None

    def skip_nl(self) -> None:
        while self.cur.kind == "NL" or self.is_("PUNCT", ";"):
            self.i += 1

    def skip_newlines_only(self) -> None:
        while self.cur.kind == "NL":
            self.i += 1

    # -- statements ------------------------------------------------------------------------
    def program(self) -> list:
        body = self.statements(top=True)
        return body

    def statements(self, top: bool = False) -> list:
        out = []
        while True:
            self.skip_nl()
            if self.cur.kind == "EOF" or (not top and self.is_("PUNCT", "}")) or self.is_("PUNCT", ")"):
                if top and self.is_("PUNCT", (")", "}")):
                    self.i += 1                          # stray closer at top level: skip it
                    continue
                break
            start = self.i
            try:
                st = self.statement()
            except (ParseError, RecursionError, IndexError) as exc:
                self.i = max(self.i, start + 1)
                self._recover()
                st = ("unknown", self.t[start].line, str(exc))
            if st is not None:
                out.append(st)
        return out

    def _recover(self) -> None:
        depth = 0
        while self.cur.kind != "EOF":
            if self.is_("PUNCT", ("{", "(", "@(", "$(", "@{")):
                depth += 1
            elif self.is_("PUNCT", ("}", ")")):
                if depth == 0:
                    return
                depth -= 1
            elif depth == 0 and (self.cur.kind == "NL" or self.is_("PUNCT", ";")):
                return
            self.i += 1

    def block(self) -> list:
        self.skip_newlines_only()
        self.eat("PUNCT", "{")
        body = self.statements()
        self.eat("PUNCT", "}")
        return body

    def statement(self) -> Any:
        t = self.cur
        line = t.line
        if t.kind == "WORD" and t.value.lower() in KEYWORDS and not self.is_("PUNCT", "-", self.peek()):
            kw = t.value.lower()
            if kw in ("function", "filter"):
                self.i += 1
                name = self.cur.value
                self.i += 1
                params = []
                if self.is_("PUNCT", "("):
                    self.i += 1
                    params = self.param_list(")")
                body = self.block()
                params = params or self._body_params(body)
                return ("function", line, str(name), params, [s for s in body if s[0] != "param"])
            if kw == "param":
                self.i += 1
                self.skip_newlines_only()
                self.eat("PUNCT", "(")
                return ("param", line, self.param_list(")"))
            if kw == "if":
                return self.if_stmt()
            if kw == "while":
                self.i += 1
                self.eat("PUNCT", "(")
                cond = self.pipeline()
                self.skip_newlines_only()
                self.eat("PUNCT", ")")
                return ("while", line, cond, self.block())
            if kw == "do":
                self.i += 1
                body = self.block()
                self.skip_newlines_only()
                until = self.accept("WORD", "until") is not None
                if not until:
                    self.eat("WORD", "while")
                self.eat("PUNCT", "(")
                cond = self.pipeline()
                self.eat("PUNCT", ")")
                return ("do", line, body, cond, until)
            if kw == "for":
                self.i += 1
                self.eat("PUNCT", "(")
                init = None if self.is_("PUNCT", ";") else self.pipeline_stmt()
                self.accept("PUNCT", ";")
                cond = None if self.is_("PUNCT", ";") else self.pipeline()
                self.accept("PUNCT", ";")
                step = None if self.is_("PUNCT", ")") else self.pipeline_stmt()
                self.eat("PUNCT", ")")
                return ("for", line, init, cond, step, self.block())
            if kw == "foreach":
                self.i += 1
                self.eat("PUNCT", "(")
                var = self.eat("VAR").value
                self.eat("WORD", "in")
                seq = self.pipeline()
                self.eat("PUNCT", ")")
                return ("foreach", line, var, seq, self.block())
            if kw == "switch":
                return self.switch_stmt()
            if kw == "try":
                self.i += 1
                body = self.block()
                catches, fin = [], []
                while True:
                    self.skip_newlines_only()
                    if self.accept("WORD", "catch"):
                        while self.cur.kind == "TYPE" or self.is_("PUNCT", ","):
                            self.i += 1
                        catches.append(self.block())
                    elif self.accept("WORD", "finally"):
                        fin = self.block()
                    else:
                        break
                return ("try", line, body, catches, fin)
            if kw == "trap":
                self.i += 1
                if self.cur.kind == "TYPE":
                    self.i += 1
                self.block()
                return None
            if kw in ("return", "throw", "exit"):
                self.i += 1
                val = None if self.cur.kind in ("NL", "EOF") or self.is_("PUNCT", tuple(_STMT_END)) else self.pipeline()
                return (kw, line, val)
            if kw in ("break", "continue"):
                self.i += 1
                if self.cur.kind == "WORD" and not self.cur.sp is False:
                    pass
                return (kw, line)
            if kw in ("begin", "process", "end") and self.is_("PUNCT", "{", self.peek()):
                self.i += 1
                return ("block", line, self.block())
            if kw in ("using", "class", "dynamicparam"):
                self._recover()
                return None
        return self.pipeline_stmt()

    def _body_params(self, body: list) -> list:
        for s in body:
            if s[0] == "param":
                return s[2]
        return []

    def param_list(self, close: str) -> list:
        params = []
        while True:
            self.skip_nl()
            if self.accept("PUNCT", close):
                break
            typ = None
            while self.cur.kind == "TYPE":
                v = self.cur.value
                self.i += 1
                if self.is_("PUNCT", "("):                      # [Parameter(Mandatory)]
                    self._skip_group()
                    continue
                if not v.lower().startswith(("parameter", "validate", "alias", "allow", "cmdletbinding")):
                    typ = v
                self.skip_newlines_only()
            if self.cur.kind == "VAR":
                name = self.eat("VAR").value
                default = None
                if self.accept("PUNCT", "="):
                    default = self.expr(no_comma=True)
                params.append((name, typ, default))
            elif not self.accept("PUNCT", ","):
                self.i += 1
        return params

    def _skip_group(self) -> None:
        depth = 0
        while self.cur.kind != "EOF":
            if self.is_("PUNCT", ("(", "@(", "$(")):
                depth += 1
            elif self.is_("PUNCT", ")"):
                depth -= 1
                if depth == 0:
                    self.i += 1
                    return
            self.i += 1

    def if_stmt(self) -> Any:
        line = self.cur.line
        self.i += 1
        branches = []
        self.eat("PUNCT", "(")
        cond = self.pipeline()
        self.skip_newlines_only()
        self.eat("PUNCT", ")")
        branches.append((cond, self.block()))
        els = None
        while True:
            save = self.i
            self.skip_newlines_only()
            if self.accept("WORD", "elseif"):
                self.eat("PUNCT", "(")
                c = self.pipeline()
                self.skip_newlines_only()
                self.eat("PUNCT", ")")
                branches.append((c, self.block()))
            elif self.accept("WORD", "else"):
                els = self.block()
                break
            else:
                self.i = save
                break
        return ("if", line, branches, els)

    def switch_stmt(self) -> Any:
        line = self.cur.line
        self.i += 1
        while self.cur.kind == "PARAM":
            self.i += 1
        self.eat("PUNCT", "(")
        subj = self.pipeline()
        self.eat("PUNCT", ")")
        self.skip_newlines_only()
        self.eat("PUNCT", "{")
        cases = []
        while True:
            self.skip_nl()
            if self.accept("PUNCT", "}"):
                break
            if self.is_("WORD", "default"):
                self.i += 1
                cases.append((None, self.block()))
                continue
            if self.is_("PUNCT", "{"):
                key = ("sblock", self.cur.line, self.block())
            else:
                key = self.primary_or_word()
            cases.append((key, self.block()))
        return ("switch", line, subj, cases)

    def pipeline_stmt(self) -> Any:
        line = self.cur.line
        # assignment: <lvalue> = <statement>
        start = self.i
        if self.cur.kind in ("VAR", "TYPE") or self.is_("PUNCT", ("[", "(")):
            try:
                lhs = self.expr(no_comma=True, lvalue=True)
            except ParseError:
                lhs = None
            if lhs is not None and self.cur.kind == "PUNCT" and self.cur.value in _ASSIGN and _is_lvalue(lhs):
                op = self.cur.value
                self.i += 1
                self.skip_newlines_only()
                rhs = self._rhs()
                return ("assign", line, lhs, op, rhs)
            self.i = start
        p = self.pipeline()
        return ("expr", line, p)

    def _rhs(self) -> Any:
        t = self.cur
        if t.kind == "WORD" and t.value.lower() in ("if", "switch", "foreach", "for", "while", "do", "try"):
            return ("stmtexpr", t.line, self.statement())
        if t.kind == "VAR" or t.kind == "TYPE":
            save = self.i
            try:
                lhs = self.expr(no_comma=True, lvalue=True)
                if self.cur.kind == "PUNCT" and self.cur.value in _ASSIGN and _is_lvalue(lhs):
                    op = self.cur.value
                    self.i += 1
                    return ("chainassign", t.line, lhs, op, self._rhs())
            except ParseError:
                pass
            self.i = save
        return self.pipeline()

    def pipeline(self) -> Any:
        line = self.cur.line
        parts = [self.pipe_element()]
        while True:
            save = self.i
            self.skip_newlines_only()
            if self.accept("PUNCT", "|"):
                self.skip_newlines_only()
                parts.append(self.pipe_element())
            else:
                self.i = save
                break
        while self.is_("PUNCT", (">", ">>", "2>", "2>&1")):          # redirections: dropped
            self.i += 1
            if self.cur.kind in ("WORD", "STR", "XSTR", "VAR"):
                self.i += 1
        if self.is_("PUNCT", ("&&", "||")):
            op = self.cur.value
            self.i += 1
            return ("chain", line, parts[0] if len(parts) == 1 else ("pipe", line, parts), op, self.pipeline())
        return parts[0] if len(parts) == 1 else ("pipe", line, parts)

    def pipe_element(self) -> Any:
        t = self.cur
        if t.kind == "WORD" and t.value.lower() not in KEYWORDS:
            return self.command()
        if self.is_("PUNCT", ("&", ".")) and (self.peek().sp or self.peek().kind in ("STR", "XSTR", "VAR")
                                              or self.is_("PUNCT", ("(", "{", "$("), self.peek())
                                              or (self.peek().kind == "WORD" and t.value == "&")):
            return self.command()
        return self.expr()

    def command(self) -> Any:
        line = self.cur.line
        invoke = None
        if self.is_("PUNCT", ("&", ".")):
            invoke = self.cur.value
            self.i += 1
            if self.cur.kind == "WORD":
                name: Any = ("str", self.cur.line, self.cur.value)
                self.i += 1
            else:
                name = self.postfix()
        else:
            name = ("str", line, self.cur.value)
            self.i += 1
        args: list = []
        while True:
            c = self.cur
            if c.kind in ("NL", "EOF") or (c.kind == "PUNCT" and c.value in (";", "|", ")", "}", "&&", "||", ">", ">>", "2>", "2>&1")):
                break
            if c.kind == "PARAM":
                self.i += 1
                pname = c.value
                if self.is_("PUNCT", ":") and not self.cur.sp:
                    self.i += 1
                    args.append(("param", c.line, pname, self.cmd_arg()))
                else:
                    args.append(("param", c.line, pname, None))
                continue
            if c.kind == "OP" and c.sp:
                # "-f" etc. in command mode are parameters
                self.i += 1
                args.append(("param", c.line, c.value, None))
                continue
            args.append(self.cmd_arg())
        return ("command", line, name, args, invoke)

    def _glued_tail(self, j: int) -> bool:
        t = self.t[j] if j < len(self.t) else None
        return bool(t and not t.sp and (t.kind in ("WORD", "NUM") or (t.kind == "PUNCT" and t.value in ("\\", "/", ".", ":", "-"))
                                       and t.kind != "EOF"))

    def cmd_arg(self) -> Any:
        line = self.cur.line
        first = self.cmd_atom()
        items = [first]
        while self.is_("PUNCT", ",") :
            self.i += 1
            self.skip_newlines_only()
            items.append(self.cmd_atom())
        return items[0] if len(items) == 1 else ("array", line, items)

    _GLUE = (".", ":", "\\", "/", "-", "=", "*", "?", "@", "%", "+", "~", "!", "[", "]")

    def cmd_atom(self) -> Any:
        c = self.cur
        t = self.t
        if (c.kind == "VAR" and self.i + 2 < len(t) and t[self.i + 1].kind == "PUNCT" and t[self.i + 1].value == "."
                and not t[self.i + 1].sp and t[self.i + 2].kind == "WORD" and not t[self.i + 2].sp
                and not self._glued_tail(self.i + 3)):
            return self.postfix()                          # $d.Length: a member, as in argument mode
        if c.kind == "VAR" and self._glued_tail(self.i + 1):
            # $env:TEMP\x.exe: a variable glued to more text is one expandable argument
            j = self.i + 1
            while self._glued_tail(j):
                j += 1
            end = self.t[j].pos if j < len(self.t) else len(self.code)
            raw = self.code[c.pos:end] if self.code else ""
            self.i = j
            return ("xstr", c.line, raw)
        if c.kind == "PUNCT" and c.value in ("-", "+", "=", "*", "?", ".", "\\", "/", "~", "!", "%", ":") and \
                (self.peek().sp or self.peek().kind in ("NL", "EOF") or (self.peek().kind == "PUNCT" and self.peek().value in (";", "|", ")", "}"))):
            self.i += 1                                    # a lone symbol as an argument ("sv x -")
            return ("str", c.line, c.value)
        if c.kind == "WORD" or (c.kind == "PUNCT" and c.value in ("*", "?", ".", "\\", "/", "~") and not self.peek().sp
                                 and self.peek().kind in ("WORD", "PUNCT", "NUM")):
            # a bare word, possibly glued to more (a path: C:\x\y.exe, a URL)
            j = self.i
            parts = []
            while True:
                t = self.t[j]
                if j > self.i and t.sp:
                    break
                if t.kind in ("WORD", "NUM") or (t.kind == "PUNCT" and t.value in self._GLUE):
                    parts.append(str(t.value))
                    j += 1
                    continue
                break
            self.i = j
            return ("str", c.line, "".join(parts).replace("`", ""))
        if c.kind == "PUNCT" and c.value == "{":
            return ("sblock", c.line, self.block())
        return self.postfix()

    # -- expressions --------------------------------------------------------------------------
    def expr(self, no_comma: bool = False, lvalue: bool = False) -> Any:
        return self.logical(no_comma)

    def logical(self, nc: bool) -> Any:
        left = self.comparison(nc)
        while self.cur.kind == "OP" and self.cur.value in ("and", "or", "xor"):
            op = self.cur.value
            line = self.cur.line
            self.i += 1
            self.skip_newlines_only()
            left = ("bin", line, op, left, self.comparison(nc))
        return left

    def comparison(self, nc: bool) -> Any:
        left = self.bitwise(nc)
        while self.cur.kind == "OP" and self.cur.value in CMP_OPS:
            op = self.cur.value
            line = self.cur.line
            self.i += 1
            self.skip_newlines_only()
            left = ("bin", line, op, left, self.bitwise(nc))
        return left

    def bitwise(self, nc: bool) -> Any:
        left = self.additive(nc)
        while self.cur.kind == "OP" and self.cur.value in BIT_OPS:
            op = self.cur.value
            line = self.cur.line
            self.i += 1
            self.skip_newlines_only()
            left = ("bin", line, op, left, self.additive(nc))
        return left

    def additive(self, nc: bool) -> Any:
        left = self.mult(nc)
        while self.is_("PUNCT", ("+", "-")):
            op = self.cur.value
            line = self.cur.line
            self.i += 1
            self.skip_newlines_only()
            left = ("bin", line, op, left, self.mult(nc))
        return left

    def mult(self, nc: bool) -> Any:
        left = self.neg(nc)
        while self.is_("PUNCT", ("*", "/", "%")):
            op = self.cur.value
            line = self.cur.line
            self.i += 1
            left = ("bin", line, op, left, self.neg(nc))
        return left

    def neg(self, nc: bool) -> Any:
        if self.is_("PUNCT", "-"):
            line = self.cur.line
            self.i += 1
            return ("neg", line, self.neg(nc))
        if self.is_("PUNCT", "+") :
            self.i += 1
            return self.neg(nc)
        return self.format_(nc)

    def format_(self, nc: bool) -> Any:
        left = self.range_(nc)
        while self.cur.kind == "OP" and self.cur.value == "f":
            line = self.cur.line
            self.i += 1
            left = ("bin", line, "f", left, self.range_(nc))
        return left

    def range_(self, nc: bool) -> Any:
        left = self.unary(nc)
        if self.is_("PUNCT", ".."):
            line = self.cur.line
            self.i += 1
            return ("range", line, left, self.unary(nc))
        return left

    def unary(self, nc: bool) -> Any:
        if self.is_("PUNCT", "!") or (self.cur.kind == "OP" and self.cur.value in ("not", "bnot")):
            op = "not" if self.cur.value in ("!", "not") else "bnot"
            line = self.cur.line
            self.i += 1
            return ("unary", line, op, self.unary(nc))
        if self.is_("PUNCT", ("++", "--")):
            op = self.cur.value
            line = self.cur.line
            self.i += 1
            return ("preinc", line, op, self.unary(nc))
        return self.comma(nc)

    def comma(self, nc: bool) -> Any:
        line = self.cur.line
        if not nc and self.is_("PUNCT", ","):
            self.i += 1
            return ("array", line, [self.unary_split()])
        first = self.unary_split()
        if nc or not self.is_("PUNCT", ","):
            return first
        items = [first]
        while self.accept("PUNCT", ","):
            self.skip_newlines_only()
            items.append(self.unary_split())
        return ("array", line, items)

    def unary_split(self) -> Any:
        if self.cur.kind == "OP" and self.cur.value in ("split", "join") and (not self.t[self.i - 1:self.i] or self.t[self.i - 1].kind in ("PUNCT", "OP", "NL")):
            op = self.cur.value
            line = self.cur.line
            self.i += 1
            return ("unary", line, op, self.unary_split())
        return self.cast()

    def cast(self) -> Any:
        if self.cur.kind == "TYPE" and not self.is_("PUNCT", ("::", "."), self.peek()):
            nxt = self.peek()
            if nxt.kind in ("VAR", "STR", "XSTR", "NUM", "NUMLIST", "TYPE") or (nxt.kind == "PUNCT" and nxt.value in ("(", "@(", "$(", "@{", "-", "[")):
                t = self.cur
                self.i += 1
                return ("cast", t.line, t.value, self.cast())
        return self.postfix()

    def postfix(self) -> Any:
        node = self.primary()
        while True:
            c = self.cur
            if c.kind == "PUNCT" and c.value in (".", "::") and not c.sp:
                static = c.value == "::"
                self.i += 1
                if self.cur.kind == "WORD":
                    member: Any = ("str", self.cur.line, self.cur.value)
                    self.i += 1
                elif self.cur.kind in ("STR", "XSTR", "VAR"):
                    member = self.primary()
                elif self.is_("PUNCT", "("):
                    self.i += 1
                    member = self.pipeline()
                    self.eat("PUNCT", ")")
                else:
                    raise ParseError(f"line {c.line}: member name expected")
                if self.is_("PUNCT", "(") and not self.cur.sp:
                    args = self.call_args()
                    node = ("call", c.line, node, member, args, static)
                else:
                    node = ("member", c.line, node, member, static)
                continue
            if c.kind == "PUNCT" and c.value == "[" and not c.sp:
                self.i += 1
                self.skip_newlines_only()
                idx = self.expr()
                self.skip_newlines_only()
                self.eat("PUNCT", "]")
                node = ("index", c.line, node, idx)
                continue
            if c.kind == "PUNCT" and c.value in ("++", "--") and not c.sp:
                self.i += 1
                node = ("postinc", c.line, c.value, node)
                continue
            if c.kind == "PUNCT" and c.value == "(" and not c.sp and node[0] == "sblock_ref":
                node = ("callsb", c.line, node, self.call_args())
                continue
            break
        return node

    def call_args(self) -> list:
        self.eat("PUNCT", "(")
        args = []
        self.skip_newlines_only()
        if self.accept("PUNCT", ")"):
            return args
        while True:
            self.skip_newlines_only()
            args.append(self.expr(no_comma=True))
            self.skip_newlines_only()
            if self.accept("PUNCT", ","):
                continue
            self.eat("PUNCT", ")")
            return args

    def primary_or_word(self) -> Any:
        if self.cur.kind == "WORD":
            t = self.cur
            self.i += 1
            return ("str", t.line, t.value)
        return self.postfix()

    def primary(self) -> Any:
        t = self.cur
        k = t.kind
        if k == "VAR":
            self.i += 1
            return ("var", t.line, t.value)
        if k == "STR":
            self.i += 1
            return ("str", t.line, t.value)
        if k == "XSTR":
            self.i += 1
            return ("xstr", t.line, t.value)
        if k == "NUM":
            self.i += 1
            return ("num", t.line, t.value)
        if k == "NUMLIST":
            self.i += 1
            return ("numlist", t.line, t.value)
        if k == "TYPE":
            self.i += 1
            return ("type", t.line, t.value)
        if k == "WORD":
            # a bare word in an expression: a command in parentheses' place, or a string
            self.i += 1
            return ("str", t.line, t.value)
        if k == "PUNCT":
            v = t.value
            if v == "(":
                self.i += 1
                self.skip_nl()
                if self.accept("PUNCT", ")"):
                    return ("array", t.line, [])
                inner = self._paren_inner()
                self.skip_nl()
                self.eat("PUNCT", ")")
                return ("paren", t.line, inner)
            if v in ("$(", "@("):
                self.i += 1
                body = self.statements()
                self.eat("PUNCT", ")")
                return ("subexpr" if v == "$(" else "arrayexpr", t.line, body)
            if v == "@{":
                self.i += 1
                return self.hashtable(t.line)
            if v == "{":
                return ("sblock", t.line, self.block())
            if v in ("-", "+") and self.peek().kind == "NUM":
                self.i += 1
                n = self.eat("NUM").value
                return ("num", t.line, -n if v == "-" else n)
        raise ParseError(f"line {t.line}: unexpected {t.value!r}")

    def _paren_inner(self) -> Any:
        # (statement) — an assignment in parentheses yields its value
        t = self.cur
        if t.kind == "WORD" and t.value.lower() in ("if", "switch", "foreach", "for", "while", "do", "try"):
            return ("stmtexpr", t.line, self.statement())
        st = self.pipeline_stmt()
        return st[2] if st[0] == "expr" else ("stmtexpr", st[1], st)

    def hashtable(self, line: int) -> Any:
        items = []
        while True:
            self.skip_nl()
            if self.accept("PUNCT", "}"):
                break
            if self.cur.kind in ("WORD", "STR", "XSTR", "NUM"):
                key: Any = ("str", self.cur.line, str(self.cur.value))
                self.i += 1
            else:
                key = self.primary()
            self.eat("PUNCT", "=")
            self.skip_newlines_only()
            items.append((key, self.pipeline_stmt()))
        return ("hash", line, items)


def _is_lvalue(n: Any) -> bool:
    return n[0] in ("var", "index", "member") or (n[0] == "cast" and _is_lvalue(n[3]))


def parse(code: str) -> list:
    """The script's statements; what does not parse becomes an ``unknown`` statement."""
    return Parser(tokenize(code), code).program()
