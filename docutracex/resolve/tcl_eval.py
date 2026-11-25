"""Tcl, evaluated statically: what a script decodes and hands to ``eval`` / ``exec``.

Tcl is a command language: every line is a command whose words go through ``$var`` and
``[command]`` substitution (``{…}`` keeps a word literal, ``"…"`` substitutes in it). This evaluator
reads it that way and follows ``set`` / ``append`` / ``proc`` / ``if`` / ``foreach`` / ``for`` /
``while`` and the commands droppers use: ``binary decode base64 | hex``, ``binary format``,
``zlib decompress | inflate | gunzip``, ``string reverse | map | range``, ``encoding convertfrom``,
``format %c``, ``join`` / ``split`` / ``lmap``. What reaches ``eval`` / ``uplevel`` /
``interp eval`` / ``source`` is a stage (evaluated in turn); ``exec`` and ``open "|…"`` run commands
(:mod:`.commands` / the shell evaluator); ``http::geturl`` is a download; ``puts $fh`` writes. Nothing
runs.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from typing import Any

from . import transforms as T
from .js_eval import rec, tag
from .sinks import Sinks
from .value import Value

MAX_STEPS = 400_000
MAX_SECONDS = 20.0
MAX_LOOP = 200_000
MAX_DEPTH = 12
MAX_STR = 64 * 1024 * 1024


class Unk(str):
    """An unknown value (a str so it flows through words): ``why`` says what it depends on."""
    why: str = ""

    def __new__(cls, why: str) -> "Unk":
        o = super().__new__(cls, f"<{why}>")
        o.why = why
        return o


class _Ret(Exception):
    def __init__(self, v: str) -> None:
        self.v = v


class _Brk(Exception):
    pass


class _Cont(Exception):
    pass


class Limit(Exception):
    pass


def _latin(b: bytes) -> str:
    return b.decode("latin-1")


def _bytes(s: str) -> bytes:
    try:
        return s.encode("latin-1")
    except UnicodeEncodeError:
        return s.encode("utf-8")


def split_script(src: str) -> list[tuple[str, int]]:
    """Commands (newlines / ``;`` outside braces, brackets and quotes), with their line numbers."""
    out = []
    buf: list[str] = []
    depth_b = depth_k = 0
    q = False
    line = 1
    start = 1
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\" and i + 1 < n:
            if src[i + 1] == "\n":
                buf.append(" ")
                line += 1
                i += 2
                continue
            buf.append(src[i:i + 2])
            i += 2
            continue
        if c == "\n":
            line += 1
        if c == '"' and depth_b == 0:
            q = not q
        elif not q:
            if c == "{":
                depth_b += 1
            elif c == "}":
                depth_b -= 1
            elif c == "[" and depth_b == 0:
                depth_k += 1
            elif c == "]" and depth_b == 0 and depth_k:
                depth_k -= 1
        if c in "\n;" and depth_b <= 0 and depth_k <= 0 and not q:
            cmd = "".join(buf).strip()
            if cmd and not cmd.startswith("#"):
                out.append((cmd, start))
            buf = []
            start = line
            i += 1
            continue
        buf.append(c)
        i += 1
    cmd = "".join(buf).strip()
    if cmd and not cmd.startswith("#"):
        out.append((cmd, start))
    return out


class Interp:
    def __init__(self, sinks: Sinks, source: str) -> None:
        self.sinks = sinks
        self.source = source
        self.frames: list[dict[str, Any]] = [{}]
        self.procs: dict[str, tuple[list[str], str]] = {}
        self.steps = 0
        self.t0 = time.monotonic()
        self.errors: list[str] = []
        self.depth = 0
        self.ran: set[str] = set()
        self.line = 0
        self.chans: dict[str, dict[str, Any]] = {}

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise Limit("steps")
        if not self.steps & 0x3FF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise Limit("time")

    @property
    def vars(self) -> dict[str, Any]:
        return self.frames[-1]

    def run(self, src: str, top: bool = False) -> str:
        res = ""
        for cmd, ln in split_script(src):
            if top or self.depth == 0:
                self.line = ln
            try:
                res = self.command(cmd)
            except (_Ret, _Brk, _Cont, Limit):
                raise
            except Exception as exc:  # noqa: BLE001
                if top:
                    self.errors.append(f"line {ln}: {type(exc).__name__}: {exc}"[:300])
                    continue
                raise
        return res

    # -- words ----------------------------------------------------------------------------------
    def words(self, cmd: str) -> list[str]:  # noqa: C901
        out: list[str] = []
        i = 0
        n = len(cmd)
        while i < n:
            while i < n and cmd[i] in " \t\n\r":
                i += 1
            if i >= n:
                break
            if cmd.startswith("{*}", i):
                i += 3
                w = self.word(cmd, i)
                out.extend(self.as_list(w[1]))
                i = w[0]
                continue
            j, w = self.word(cmd, i)
            out.append(w)
            i = j
        return out

    def word(self, s: str, i: int) -> tuple[int, str]:
        n = len(s)
        if s[i] == "{":
            depth = 0
            for j in range(i, n):
                if s[j] == "\\":
                    continue
                if s[j] == "{" and (j == 0 or s[j - 1] != "\\"):
                    depth += 1
                elif s[j] == "}" and (j == 0 or s[j - 1] != "\\"):
                    depth -= 1
                    if depth == 0:
                        return j + 1, s[i + 1:j]
            return n, s[i + 1:]
        if s[i] == '"':
            j = i + 1
            buf = []
            while j < n and s[j] != '"':
                if s[j] == "\\" and j + 1 < n:
                    buf.append(s[j:j + 2])
                    j += 2
                    continue
                if s[j] == "[":
                    k = self._close_bracket(s, j)
                    buf.append(s[j:k])
                    j = k
                    continue
                buf.append(s[j])
                j += 1
            return j + 1, self.subst("".join(buf))
        j = i
        while j < n and s[j] not in " \t\n\r":
            if s[j] == "[":
                j = self._close_bracket(s, j)
                continue
            if s[j] == "\\" and j + 1 < n:
                j += 2
                continue
            j += 1
        return j, self.subst(s[i:j])

    @staticmethod
    def _close_bracket(s: str, j: int) -> int:
        depth = 0
        k = j
        q = False
        while k < len(s):
            c = s[k]
            if c == "\\":
                k += 2
                continue
            if c == '"' and depth > 0:
                q = not q
            elif not q:
                if c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
                    if depth == 0:
                        return k + 1
            k += 1
        return len(s)

    def subst(self, s: str) -> str:
        out: list[str] = []
        r: tuple = ()
        i = 0
        n = len(s)
        while i < n:
            c = s[i]
            if c == "\\" and i + 1 < n:
                m = re.match(r"\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|[0-7]{1,3}|.)", s[i:], re.S)
                e = m.group(1)
                if e[0] == "x":
                    out.append(chr(int(e[1:], 16)))
                elif e[0] == "u":
                    out.append(chr(int(e[1:], 16)))
                elif e[0].isdigit():
                    out.append(chr(int(e, 8)))
                else:
                    out.append({"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v"}.get(e, e))
                i += m.end()
                continue
            if c == "$":
                m = re.match(r"\$(\{([^}]*)\}|([A-Za-z0-9_:]+)(\(([^)]*)\))?)", s[i:])
                if m:
                    name = m.group(2) or m.group(3)
                    if m.group(5) is not None:
                        name = f"{name}({self.subst(m.group(5))})"
                    v = self.get(name)
                    r = r or rec(v)
                    out.append(v)
                    i += m.end()
                    continue
            if c == "[":
                k = self._close_bracket(s, i)
                self.depth += 1
                try:
                    v = self.run(s[i + 1:k - 1])
                finally:
                    self.depth -= 1
                r = r or rec(v)
                out.append(v)
                i = k
                continue
            out.append(c)
            i += 1
        if sum(len(x) for x in out) > MAX_STR:
            raise Limit("string size")
        res = "".join(out)
        u = next((x for x in out if isinstance(x, Unk)), None)
        if u is not None and len(out) == 1:
            return u
        return tag(res, r) if r and len(res) >= 16 else res

    def get(self, name: str) -> str:
        if name in self.vars:
            return self.vars[name]
        if name.startswith("::") and name[2:] in self.frames[0]:
            return self.frames[0][name[2:]]
        if name.startswith("env("):
            return Unk(f"the environment variable {name[4:-1]}")
        if name in ("argv", "argv0"):
            return ""
        return ""

    def as_list(self, s: str) -> list[str]:
        out = []
        i = 0
        n = len(s)
        while i < n:
            while i < n and s[i] in " \t\n\r":
                i += 1
            if i >= n:
                break
            if s[i] == "{":
                depth = 0
                for j in range(i, n):
                    if s[j] == "{":
                        depth += 1
                    elif s[j] == "}":
                        depth -= 1
                        if depth == 0:
                            out.append(s[i + 1:j])
                            i = j + 1
                            break
                else:
                    out.append(s[i + 1:])
                    i = n
                continue
            if s[i] == '"':
                j = s.find('"', i + 1)
                j = n if j < 0 else j
                out.append(s[i + 1:j])
                i = j + 1
                continue
            j = i
            while j < n and s[j] not in " \t\n\r":
                j += 1
            out.append(s[i:j])
            i = j
        return out

    @staticmethod
    def to_list(items: list[str]) -> str:
        return " ".join(("{" + x + "}") if (not x or re.search(r"[\s{}\"$\[\]\\;]", x)) else x for x in items)

    # -- commands ---------------------------------------------------------------------------------
    def command(self, cmd: str) -> str:  # noqa: C901, PLR0911, PLR0912, PLR0915
        self.tick()
        w = self.words(cmd)
        if not w:
            return ""
        name = w[0].lstrip(":")
        a = w[1:]
        if isinstance(w[0], Unk):
            self.sinks.unresolved_(cmd[:300], w[0].why, "the command's name is computed at run time", self.line)
            return Unk("the result of a command named at run time")
        if name in self.procs:
            params, body = self.procs[name]
            frame: dict[str, Any] = {}
            for k, p in enumerate(params):
                pl = self.as_list(p)
                pn = pl[0] if pl else p
                if pn == "args":
                    frame["args"] = self.to_list(a[k:])
                    break
                frame[pn] = a[k] if k < len(a) else (pl[1] if len(pl) > 1 else "")
            self.frames.append(frame)
            try:
                return self.run(body)
            except _Ret as r:
                return r.v
            finally:
                self.frames.pop()
        if name == "set":
            if len(a) >= 2:
                v = a[1]
                if isinstance(v, str) and not isinstance(v, Unk) and not rec(v) and len(v) >= 16:
                    v = tag(v, (f"literal {a[0]}",))
                elif rec(v) and len(v) >= 16:
                    self.sinks.step(self.line, f"{a[0]} =", self.val(v))
                self.vars[a[0]] = v
                return v
            return self.get(a[0]) if a else ""
        if name == "append":
            cur = self.get(a[0]) if a else ""
            if len(cur) + sum(len(x) for x in a[1:]) > MAX_STR:
                raise Limit("string size")
            v = cur + "".join(a[1:])
            v = tag(v, rec(cur) or next((rec(x) for x in a[1:] if rec(x)), ())) if (rec(cur) or any(rec(x) for x in a[1:])) else v
            self.vars[a[0]] = v
            return v
        if name == "incr":
            cur = int(self.get(a[0]) or 0) if str(self.get(a[0]) or "0").lstrip("-").isdigit() else 0
            v = str(cur + (int(a[1]) if len(a) > 1 else 1))
            self.vars[a[0]] = v
            return v
        if name in ("proc",) and len(a) >= 3:
            self.procs[a[0].lstrip(":")] = (self.as_list(a[1]), a[2])
            return ""
        if name == "return":
            raise _Ret(a[-1] if a else "")
        if name == "break":
            raise _Brk()
        if name == "continue":
            raise _Cont()
        if name == "if":
            return self.if_(a)
        if name == "foreach":
            return self.foreach(a)
        if name == "for" and len(a) >= 4:
            self.run(a[0])
            n = 0
            while n < MAX_LOOP and self.expr(a[1]) not in ("0", "", None):
                n += 1
                try:
                    self.run(a[3])
                except _Brk:
                    break
                except _Cont:
                    pass
                self.run(a[2])
            return ""
        if name == "while" and len(a) >= 2:
            n = 0
            while n < MAX_LOOP:
                c = self.expr(a[0])
                if c is None and n >= 3 or c in ("0", ""):
                    break
                n += 1
                try:
                    self.run(a[1])
                except _Brk:
                    break
                except _Cont:
                    pass
            return ""
        if name in ("eval", "uplevel", "namespace") or (name == "interp" and a[:1] == ["eval"]):
            if name == "namespace":
                if a[:1] == ["eval"] and len(a) >= 3:
                    return self.eval_code(" ".join(a[2:]), "namespace eval", rec(a[2]))
                return ""
            body = a[1:] if name == "interp" else (a[1:] if name == "uplevel" and a and re.fullmatch(r"#?\d+", a[0]) else a)
            if name == "interp":
                body = a[2:]
            code = " ".join(body)
            u = next((x for x in body if isinstance(x, Unk)), None)
            return self.eval_code(u if u is not None else code, name, next((rec(x) for x in body if rec(x)), ()))
        if name == "source":
            return ""
        if name == "exec":
            args = [x for x in a if x not in ("-ignorestderr", "--", "&")]
            u = next((x for x in args if isinstance(x, Unk)), None)
            if u is not None:
                self.sinks.unresolved_(cmd[:300], u.why, "the command it runs is computed at run time", self.line)
            else:
                from . import sh_eval
                import shlex
                line_ = " ".join(x if re.fullmatch(r"[\w@%+=:,./-]+", x) else shlex.quote(x) for x in args)
                sh_eval.run_command(self.sinks, line_, next((rec(x) for x in a if rec(x)), ()), self.line, "exec")
            return Unk("the output of a command")
        if name == "open" and a:
            if a[0].startswith("|"):
                from . import sh_eval
                sh_eval.run_command(self.sinks, a[0][1:].strip(), rec(a[0]), self.line, "open |")
                return "pipe1"
            ch = f"file{len(self.chans) + 3}"
            mode = a[1] if len(a) > 1 else "r"
            self.chans[ch] = {"path": a[0], "mode": mode, "data": "" if re.search(r"[wa]", mode) else None}
            return ch
        if name == "puts":
            args = [x for x in a if x != "-nonewline"]
            if len(args) >= 2 and args[0] in self.chans:
                c = self.chans[args[0]]
                if c["data"] is not None:
                    c["data"] = c["data"] + args[1] + ("" if "-nonewline" in a else "\n")
                    c["rec"] = c.get("rec") or rec(args[1])
            return ""
        if name == "close" and a and a[0] in self.chans:
            self.flush(a[0])
            return ""
        if name == "fconfigure" or name == "chan":
            return ""
        if name in ("http::geturl", "geturl"):
            url = a[0] if a else ""
            if isinstance(url, Unk):
                self.sinks.download(Value.unknown(url.why), "http::geturl", "returns it to the script", self.line)
            else:
                self.sinks.download(Value("str", url, rec(url)), "http::geturl", "returns it to the script", self.line)
            return f"httptok{abs(hash(url)) % 1000}"
        if name in ("http::data", "http::body"):
            return Unk("the content downloaded by http::geturl")
        if name == "socket":
            host = [x for x in a if not x.startswith("-")]
            if len(host) >= 2:
                self.sinks.download(Value("str", f"tcp://{host[0]}:{host[1]}"), "socket", "connects to it (a reverse shell / C2)", self.line)
            return "sock1"
        if name == "binary":
            return self.binary(a)
        if name == "zlib" and len(a) >= 2:
            op = a[0]
            fn = {"decompress": T.zlib_decompress, "inflate": T.inflate, "gunzip": T.gunzip}.get(op)
            if fn is None:
                return a[-1]
            if isinstance(a[1], Unk):
                return a[1]
            try:
                return tag(_latin(fn(_bytes(a[1]))), rec(a[1]) + (f"zlib {op}",))
            except T.TransformError as exc:
                self.errors.append(f"line {self.line}: zlib {op}: {exc}")
                return ""
        if name == "string":
            return self.string(a)
        if name == "encoding" and len(a) >= 3 and a[0] == "convertfrom":
            try:
                return _bytes(a[2]).decode({"unicode": "utf-16-le", "utf-8": "utf-8"}.get(a[1], a[1]), "replace")
            except LookupError:
                return a[2]
        if name == "format" and a:
            return self.format(a[0], a[1:])
        if name == "join":
            items = self.as_list(a[0]) if a else []
            out = (a[1] if len(a) > 1 else " ").join(items)
            return tag(out, rec(a[0])) if a and rec(a[0]) and len(out) >= 16 else out
        if name == "split":
            s = a[0] if a else ""
            seps = a[1] if len(a) > 1 else " \t\n"
            parts = list(s) if seps == "" else re.split("[" + re.escape(seps) + "]", s)
            return self.to_list(parts)
        if name in ("list",):
            return self.to_list(a)
        if name == "lindex" and len(a) >= 2:
            items = self.as_list(a[0])
            try:
                k = len(items) - 1 if a[1] == "end" else int(a[1])
                return items[k] if 0 <= k < len(items) else ""
            except ValueError:
                return ""
        if name == "llength":
            return str(len(self.as_list(a[0]))) if a else "0"
        if name == "lreverse":
            return self.to_list(list(reversed(self.as_list(a[0])))) if a else ""
        if name == "lappend" and a:
            items = self.as_list(self.get(a[0]))
            items.extend(a[1:])
            self.vars[a[0]] = self.to_list(items)
            return self.vars[a[0]]
        if name == "lmap" and len(a) >= 3:
            out = []
            for it in self.as_list(a[1]):
                self.vars[a[0]] = it
                out.append(self.run(a[2]))
            return self.to_list(out)
        if name == "expr":
            v = self.expr(" ".join(a))
            return v if v is not None else Unk("an expression not worked out")
        if name in ("package", "global", "variable", "upvar", "namespace", "after", "update", "catch", "puts",
                    "wm", "pack", "label", "button", "file", "info", "rename", "unset", "array", "regexp", "regsub",
                    "clock", "exit", "fileevent", "vwait"):
            if name == "catch" and a:
                try:
                    return self.run(a[0])
                except (_Ret, _Brk, _Cont):
                    return ""
            if name == "exit":
                raise _Ret("")
            if name == "file" and a[:1] == ["tempfile"]:
                return "/tmp/tcl0001"
            return ""
        return Unk(f"the result of {name}")

    def if_(self, a: list[str]) -> str:
        i = 0
        while i < len(a):
            cond = a[i]
            i += 1
            if i < len(a) and a[i] == "then":
                i += 1
            body = a[i] if i < len(a) else ""
            i += 1
            c = self.expr(cond)
            if c is None:
                self.run(body)
                rest = a[i:]
                for k, x in enumerate(rest):
                    if x not in ("else", "elseif", "then") and k % 2 == 1:
                        try:
                            self.run(x)
                        except (_Brk, _Cont):
                            pass
                return ""
            if c not in ("0", "", "false"):
                return self.run(body)
            if i < len(a) and a[i] == "elseif":
                i += 1
                continue
            if i < len(a) and a[i] == "else":
                return self.run(a[i + 1]) if i + 1 < len(a) else ""
            return ""
        return ""

    def foreach(self, a: list[str]) -> str:
        if len(a) < 3:
            return ""
        names = self.as_list(a[0])
        items = self.as_list(a[1])
        body = a[-1]
        k = 0
        n = 0
        while k < len(items) and n < MAX_LOOP:
            n += 1
            for nm in names:
                self.vars[nm] = items[k] if k < len(items) else ""
                k += 1
            try:
                self.run(body)
            except _Brk:
                break
            except _Cont:
                pass
        return ""

    def expr(self, e: str) -> str | None:
        s = self.subst(e)
        if isinstance(s, Unk) or "<" in s and re.search(r"<[^<>]*(the |a )", s):
            return None
        s2 = s.replace("&&", " and ").replace("||", " or ").replace("!", " not ").replace(" not =", "!=")
        if re.fullmatch(r"[\d\s+\-*/%()<>=!&|^~.a-z\"'\w]*", s2) and not re.search(r"__|import|lambda|open|exec|eval", s2):
            try:
                v = eval(re.sub(r"\beq\b", "==", re.sub(r"\bne\b", "!=", s2)), {"__builtins__": {}},  # noqa: S307
                         {"true": True, "false": False})
                return str(int(v)) if isinstance(v, bool) else str(v)
            except Exception:  # noqa: BLE001
                return None
        return None

    def binary(self, a: list[str]) -> str:
        if len(a) >= 3 and a[0] == "decode":
            kind, data = a[1], a[-1]
            if isinstance(data, Unk):
                return data
            try:
                if kind == "base64":
                    return tag(_latin(T.b64decode(data)), rec(data) + ("base64",))
                if kind == "hex":
                    return tag(_latin(T.hexdecode(data)), rec(data) + ("hex",))
                if kind == "uuencode":
                    import binascii
                    return _latin(b"".join(binascii.a2b_uu(x) for x in _bytes(data).split(b"\n") if x.strip()))
            except T.TransformError as exc:
                self.errors.append(f"line {self.line}: binary decode {kind}: {exc}")
                return ""
        if len(a) >= 3 and a[0] == "encode":
            return base64.b64encode(_bytes(a[-1])).decode() if a[1] == "base64" else _bytes(a[-1]).hex()
        if len(a) >= 2 and a[0] == "format":
            from .dyn_eval import pack
            fmt = a[1]
            vals: list[Any] = []
            for x in a[2:]:
                items = self.as_list(x)
                vals.extend(int(v, 0) if re.fullmatch(r"-?(0x)?[0-9a-fA-F]+", v) and not fmt.startswith(("H", "h", "a", "A")) else v
                            for v in (items if len(items) > 1 and fmt.lstrip("HhaA")[:1] not in ("",) else [x]))
            out = pack(fmt, vals)
            return tag(out, ((a[2] and rec(a[2])) or ()) + (f"binary format {fmt}",)) if len(out) >= 16 else out
        return ""

    def string(self, a: list[str]) -> str:
        if not a:
            return ""
        op = a[0]
        if op == "reverse" and len(a) >= 2:
            s = a[1]
            return tag(s[::-1], rec(s) + ("reverse",)) if len(s) >= 16 else s[::-1]
        if op == "map" and len(a) >= 3:
            pairs = self.as_list(a[-2])
            s = a[-1]
            out = []
            i = 0
            mp = list(zip(pairs[::2], pairs[1::2]))
            while i < len(s):
                for k, v in mp:
                    if k and s.startswith(k, i):
                        out.append(v)
                        i += len(k)
                        break
                else:
                    out.append(s[i])
                    i += 1
            res = "".join(out)
            return tag(res, rec(s) + (f"string map {a[-2][:16]}",)) if len(res) >= 16 and res != s else res
        if op == "range" and len(a) >= 4:
            s = a[1]
            st = int(a[2]) if a[2].lstrip("-").isdigit() else 0
            en = len(s) - 1 if a[3].startswith("end") else int(a[3])
            return s[st:en + 1]
        if op == "index" and len(a) >= 3:
            s = a[1]
            try:
                return s[int(a[2])]
            except (ValueError, IndexError):
                return ""
        if op == "length" and len(a) >= 2:
            return str(len(a[1]))
        if op in ("toupper", "tolower", "trim"):
            s = a[1] if len(a) > 1 else ""
            return s.upper() if op == "toupper" else s.lower() if op == "tolower" else s.strip()
        if op == "repeat" and len(a) >= 3:
            n = int(a[2]) if a[2].lstrip("-").isdigit() else 0
            if len(a[1]) * max(0, n) > MAX_STR:
                raise Limit("string size")
            return a[1] * max(0, n)
        return ""

    def format(self, fmt: str, vals: list[str]) -> str:
        it = iter(vals)

        def rep(m: re.Match) -> str:
            conv = m.group(2)
            if conv == "%":
                return "%"
            v = next(it, "")
            try:
                if conv == "c":
                    return chr(int(v, 0))
                if conv in "dxXo":
                    return ("%" + m.group(1) + conv) % int(v, 0)
            except ValueError:
                return ""
            return ("%" + m.group(1) + "s") % v
        out = re.sub(r"%([-+ 0#]*\d*(?:\.\d+)?)([sdxXoc%])", rep, fmt)
        return tag(out, ("char codes",)) if "%c" in fmt and len(out) >= 16 else out

    # -- stages -------------------------------------------------------------------------------------
    def val(self, v: str) -> Value:
        if isinstance(v, Unk):
            return Value.unknown(v.why)
        return Value("str", str(v), rec(v))

    def eval_code(self, code: str, sink: str, recipe: tuple = ()) -> str:
        if isinstance(code, Unk):
            self.sinks.exec_(Value.unknown(code.why), sink, self.line)
            return Unk(f"the result of code computed from {code.why}")
        self.sinks.exec_(Value("str", str(code), recipe or rec(code)), sink, self.line)
        h = hashlib.sha256(str(code).encode("utf-8", "replace")).hexdigest()
        if self.depth >= MAX_DEPTH or h in self.ran:
            return ""
        self.ran.add(h)
        self.depth += 1
        self.sinks.depth += 1
        try:
            return self.run(str(code), top=True)
        except _Ret as r:
            return r.v
        finally:
            self.depth -= 1
            self.sinks.depth -= 1

    def flush(self, ch: str) -> None:
        c = self.chans.get(ch)
        if c is None or c.get("flushed") or c["data"] is None:
            return
        c["flushed"] = True
        if c["data"]:
            self.sinks.write(Value("bytes", _bytes(c["data"]), tuple(c.get("rec") or ())), str(c["path"]), "puts", self.line)


def resolve(code: str, location: str = "tcl") -> Sinks:
    s = Sinks("tcl")
    it = Interp(s, code.lstrip("﻿"))
    try:
        it.run(code.lstrip("﻿"), top=True)
    except (Limit, _Ret, _Brk, _Cont):
        pass
    except RecursionError:
        it.errors.append("recursion")
    for ch in list(it.chans):
        it.flush(ch)
    s.errors = it.errors  # type: ignore[attr-defined]
    s.stats = {"steps": it.steps, "seconds": round(time.monotonic() - it.t0, 2)}  # type: ignore[attr-defined]
    return s
