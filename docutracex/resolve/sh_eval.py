"""Shell (sh / bash), evaluated statically: what a dropper decodes and pipes into a shell.

A script is read the way a POSIX shell reads it: words with their quotes (``'…'``, ``"…"``,
``$'…'``), variables (``$x``, ``${x:-d}``, ``${x//a/b}``, ``${x:o:l}``, ``${#x}``), command
substitution (``$(…)``, backticks), ``$((…))``, here-documents and here-strings, ``;`` / ``&&`` /
``||`` / ``|``, ``if`` / ``for`` / ``while`` / ``case`` and functions. Each command of a pipeline gets
the previous one's output, so the classic droppers are worked out:

``echo … | base64 -d | gunzip | sh``, ``printf '\\x…'``, ``xxd -r -p``, ``openssl enc -d -aes-256-cbc
-k …``, ``rev``, ``tr``, ``zcat`` / ``xz -d`` / ``bzip2 -d``, ``base32 -d``.

What reaches ``sh`` / ``bash`` / ``eval`` / ``sh -c`` is a stage (evaluated in turn); ``python -c`` /
``perl -e`` / ``php -r`` / ``node -e`` hand code to another language (a stage with its type); what
is written (``> file``, ``tee``, ``cat > f <<EOF``) is a written file; ``curl`` / ``wget`` are downloads
(``-o`` / ``-O``: saved, then run when ``chmod +x`` / ``./file`` follows); ``/dev/tcp/host/port`` is a
connection (a reverse shell). Nothing runs.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from typing import Any

from . import commands
from . import transforms as T
from .js_eval import rec, tag
from .sinks import Sinks
from .value import Value

MAX_STEPS = 400_000
MAX_SECONDS = 20.0
MAX_LOOP = 100_000
MAX_DEPTH = 12
MAX_OUT = 64 * 1024 * 1024

_SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh", "busybox"}
_INTERP = {"python": ".py", "python2": ".py", "python3": ".py", "perl": ".pl", "php": ".php", "ruby": ".rb",
           "node": ".js", "nodejs": ".js", "lua": ".lua", "pwsh": ".ps1", "powershell": ".ps1"}


def looks_like_shell(text: str) -> bool:
    return bool(re.search(r"(?m)(^#!\s*/(?:usr/)?bin/(?:env\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:ba)?sh\b|\bbase64\s+-d|\bchmod\s+\+x|"
                          r"\bwget\s|\bcurl\s|\bnohup\b|/dev/tcp/|\becho\s+[\"']?[A-Za-z0-9+/=]{40,})", text))


class Unk:
    def __init__(self, why: str) -> None:
        self.why = why


class _Ret(Exception):
    pass


class _Brk(Exception):
    pass


class Limit(Exception):
    pass


# --- reading words ---------------------------------------------------------------------------------
def _ansi(s: str) -> str:
    return re.sub(r"\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{4}|[0-7]{1,3}|[nrtabefv\\'\"])", lambda m: _esc1(m.group(1)), s)


def _esc1(e: str) -> str:
    if e[0] == "x":
        return chr(int(e[1:], 16))
    if e[0] == "u":
        return chr(int(e[1:], 16))
    if e[0].isdigit():
        return chr(int(e, 8) & 0xFF)
    return {"n": "\n", "r": "\r", "t": "\t", "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v"}.get(e, e)


def split_commands(src: str) -> list[tuple[str, int]]:
    """Top-level command lines with their line numbers (here-docs and compound blocks kept whole)."""
    out: list[tuple[str, int]] = []
    lines = src.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        start = i
        buf = lines[i]
        i += 1
        # continuation, open quotes, here-docs and compound commands
        while True:
            if buf.endswith("\\") and not buf.endswith("\\\\") and i < len(lines):
                buf = buf[:-1] + lines[i]
                i += 1
                continue
            hd = re.findall(r"<<-?\s*['\"]?([A-Za-z_]\w*)['\"]?", _strip_quoted(buf))
            if hd:
                for tagn in hd:
                    while i < len(lines) and lines[i].strip() != tagn:
                        buf += "\n" + lines[i]
                        i += 1
                    if i < len(lines):
                        buf += "\n" + lines[i]
                        i += 1
                break
            if _open_quote(buf) and i < len(lines):
                buf += "\n" + lines[i]
                i += 1
                continue
            if _depth(buf) > 0 and i < len(lines):
                buf += "\n" + lines[i]
                i += 1
                continue
            break
        if buf.strip():
            out.append((buf, start + 1))
    return out


def _strip_quoted(s: str) -> str:
    return re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", "''", s)


def _open_quote(s: str) -> bool:
    q = None
    i = 0
    while i < len(s):
        c = s[i]
        if q is None:
            if c == "\\":
                i += 2
                continue
            if c == "#" and (i == 0 or s[i - 1] in " \t;"):
                return False
            if c in "'\"`":
                q = c
        elif c == q:
            q = None
        elif c == "\\" and q != "'":
            i += 2
            continue
        i += 1
    return q is not None


_OPEN = re.compile(r"(?:^|[\s;&|(])(if|for|while|until|case|function)\b|\{\s*$|\(\)\s*\{|\$\(|\{(?=\s)")
_CLOSE = re.compile(r"(?:^|[\s;&|])(fi|done|esac)\b|(?:^|[\s;])\}|\)")


def _depth(s: str) -> int:
    t = _strip_quoted(re.sub(r"(?m)#.*$", "", s))
    opens = len(re.findall(r"(?:^|[\s;&|(])(?:if|for|while|until|case)\b", t))
    closes = len(re.findall(r"(?:^|[\s;&|])(?:fi|done|esac)\b", t))
    braces = t.count("{") - t.count("}")
    parens = t.count("$(") + t.count("(") - t.count("$(") - t.count(")")
    return opens - closes + max(0, braces) + max(0, parens)


class Word:
    """A word after expansion: its text and the recipe of what it came from."""

    def __init__(self, text: str, recipe: tuple[str, ...] = (), unk: str = "") -> None:
        self.text, self.recipe, self.unk = text, recipe, unk


class Interp:
    def __init__(self, sinks: Sinks, source: str) -> None:
        self.sinks = sinks
        self.source = source
        self.vars: dict[str, Any] = {"HOME": "$HOME", "PATH": "/usr/bin:/bin", "IFS": " \t\n", "PWD": "/tmp", "0": "script.sh"}
        self.funcs: dict[str, str] = {}
        self.files: dict[str, dict[str, Any]] = {}
        self.steps = 0
        self.t0 = time.monotonic()
        self.errors: list[str] = []
        self.depth = 0
        self.ran: set[str] = set()
        self.line = 0

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise Limit("steps")
        if not self.steps & 0x3FF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise Limit("time")

    # -- programs ------------------------------------------------------------------------------------
    def run(self, src: str, stdin: Any = None) -> Any:
        out: list = []
        for text_, ln in split_commands(src):
            self.line = ln if self.depth == 0 else self.line
            try:
                o = self.list_(text_, stdin)
                if o:
                    out.append(o)
            except (_Ret, _Brk):
                break
            except Limit:
                raise
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"line {ln}: {type(exc).__name__}: {exc}"[:300])
        return self._join(out)

    @staticmethod
    def _join(parts: list) -> Any:
        if any(isinstance(p, Unk) for p in parts):
            return next(p for p in parts if isinstance(p, Unk))
        if not parts:
            return b""
        out = b"".join(p if isinstance(p, bytes) else p.encode("latin-1", "replace") for p in parts)
        r = next((getattr(p, "recipe", ()) for p in parts if getattr(p, "recipe", ())), ())
        return _B(out, r)

    def list_(self, text_: str, stdin: Any = None) -> Any:
        """``a && b || c ; d`` (one command line) — compound commands first."""
        t = text_.strip()
        if not t or t.startswith("#"):
            return b""
        m = re.match(r"(?s)^(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\s*\)\s*\{(.*)\}\s*$", t) or \
            re.match(r"(?s)^function\s+([A-Za-z_][\w-]*)\s*\{(.*)\}\s*$", t)
        if m:
            self.funcs[m.group(1)] = m.group(2)
            return b""
        if re.match(r"if\b", t):
            return self.if_(t, stdin)
        if re.match(r"(for|while|until)\b", t):
            return self.loop(t, stdin)
        if re.match(r"case\b", t):
            return self.case(t, stdin)
        out: list = []
        last_ok = True
        first, nl, rest = t.partition("\n")
        if nl and re.search(r"<<-?\s*['\"]?[A-Za-z_]\w*", _strip_quoted(first)):
            # a here-document: its body belongs to the command that opens it
            parts = _split_ops(first)
            parts = [(c + ("\n" + rest if re.search(r"<<-?\s*['\"]?[A-Za-z_]", c) else ""), s) for c, s in parts]
        else:
            parts = _split_ops(t)
        for part, sep in parts:
            if sep == "&&" and not last_ok:
                continue
            if sep == "||" and last_ok:
                continue
            o = self.pipeline(part, stdin)
            last_ok = not isinstance(o, Fail)
            if o and not isinstance(o, Fail):
                out.append(o)
        return self._join(out)

    def if_(self, t: str, stdin: Any) -> Any:
        m = re.match(r"(?s)if\s+(.*?)\s*;?\s*then\b(.*)\bfi\s*$", t)
        if not m:
            return b""
        cond, rest = m.group(1), m.group(2)
        parts = re.split(r"(?s)\b(elif|else)\b", rest)
        then = parts[0]
        c = self.cond(cond)
        if c is True:
            return self.run(then, stdin)
        if c is None:
            # depends on the machine: both ways
            self.run(then, stdin)
            for k in range(1, len(parts), 2):
                body = parts[k + 1]
                if parts[k] == "elif":
                    mm = re.match(r"(?s)(.*?)\bthen\b(.*)", body)
                    body = mm.group(2) if mm else body
                self.run(body, stdin)
            return b""
        k = 1
        while k < len(parts):
            if parts[k] == "elif":
                mm = re.match(r"(?s)(.*?)\s*;?\s*then\b(.*)", parts[k + 1])
                if mm:
                    c2 = self.cond(mm.group(1))
                    if c2 is not False:
                        return self.run(mm.group(2), stdin)
            else:
                return self.run(parts[k + 1], stdin)
            k += 2
        return b""

    def cond(self, c: str) -> bool | None:
        c = c.strip().rstrip(";").strip()
        m = re.match(r"^(?:\[\[?|test)\s+(.*?)\s*\]?\]?$", c)
        if not m:
            o = self.list_(c)
            return None if isinstance(o, Unk) else not isinstance(o, Fail)
        expr = m.group(1).strip()
        neg = expr.startswith("! ")
        if neg:
            expr = expr[2:]
        ws = self.words(expr)
        if any(w.unk for w in ws):
            return None
        a = [w.text for w in ws]
        r: bool | None
        if len(a) == 2 and a[0] in ("-z", "-n"):
            r = (a[1] == "") if a[0] == "-z" else (a[1] != "")
        elif len(a) == 2 and a[0] in ("-f", "-e", "-d", "-x", "-s", "-r", "-w"):
            r = True if a[1] in self.files else None
        elif len(a) == 3 and a[1] in ("=", "==", "!="):
            r = (a[0] == a[2]) if a[1] != "!=" else (a[0] != a[2])
        elif len(a) == 3 and a[1] in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge"):
            try:
                x, y = int(a[0]), int(a[2])
            except ValueError:
                return None
            r = {"-eq": x == y, "-ne": x != y, "-lt": x < y, "-le": x <= y, "-gt": x > y, "-ge": x >= y}[a[1]]
        else:
            return None
        return (not r) if (neg and r is not None) else r

    def loop(self, t: str, stdin: Any) -> Any:
        m = re.match(r"(?s)for\s+(\w+)\s+in\s+(.*?)\s*;?\s*do\b(.*)\bdone\s*$", t)
        if m:
            items = [w.text for w in self.words(m.group(2), split=True) if not w.unk]
            out: list = []
            try:
                for it in items[:MAX_LOOP]:
                    self.vars[m.group(1)] = it
                    out.append(self.run(m.group(3), stdin))
            except _Brk:
                pass
            return self._join([o for o in out if o])
        m = re.match(r"(?s)for\s*\(\((.*?);(.*?);(.*?)\)\)\s*;?\s*do\b(.*)\bdone\s*$", t)
        if m:
            self.arith(m.group(1))
            n = 0
            out = []
            try:
                while n < MAX_LOOP and self.arith(m.group(2)) not in (0, None):
                    n += 1
                    out.append(self.run(m.group(4), stdin))
                    self.arith(m.group(3))
            except _Brk:
                pass
            return self._join([o for o in out if o])
        m = re.match(r"(?s)(while|until)\s+(.*?)\s*;?\s*do\b(.*)\bdone(.*)$", t)
        if m:
            n = 0
            try:
                while n < 3 or (n < MAX_LOOP and m.group(2).strip() not in ("true", ":", "[ 1 ]")):
                    n += 1
                    c = self.cond(m.group(2))
                    if c is None and n > 3:
                        break
                    if c is (m.group(1) == "until"):
                        break
                    self.run(m.group(3), stdin)
            except _Brk:
                pass
        return b""

    def case(self, t: str, stdin: Any) -> Any:
        m = re.match(r"(?s)case\s+(.*?)\s+in\b(.*)\besac\s*$", t)
        if not m:
            return b""
        w = self.words(m.group(1))
        subj = w[0].text if w and not w[0].unk else None
        for pm in re.finditer(r"(?s)\s*\(?([^)]*?)\)(.*?);;", m.group(2)):
            pats = [p.strip().strip("\"'") for p in pm.group(1).split("|")]
            if subj is None or any(re.fullmatch(re.escape(p).replace(r"\*", ".*").replace(r"\?", "."), subj) for p in pats):
                o = self.run(pm.group(2), stdin)
                if subj is not None:
                    return o
        return b""

    # -- pipelines ----------------------------------------------------------------------------------------
    def pipeline(self, text_: str, stdin: Any) -> Any:
        stages = _split_pipe(text_)
        data: Any = stdin
        for i, st in enumerate(stages):
            self.tick()
            data = self.simple(st, data, last=i == len(stages) - 1, piped=i > 0)
        return data

    def simple(self, cmd: str, stdin: Any, last: bool = True, piped: bool = False) -> Any:  # noqa: C901, PLR0911, PLR0912
        cmd = cmd.strip()
        if not cmd:
            return stdin
        if cmd.endswith("&"):
            cmd = cmd[:-1].strip()
        if cmd.startswith("(") and cmd.endswith(")"):
            return self.run(cmd[1:-1], stdin)
        if cmd.startswith("{") and cmd.endswith("}"):
            return self.run(cmd[1:-1], stdin)
        # here-doc / here-string
        here = None
        m = re.search(r"<<-?\s*(['\"]?)([A-Za-z_]\w*)\1[^\n]*\n(.*?)\n\s*\2\s*$", cmd, re.S)
        if m:
            body = m.group(3)
            here = _B(body.encode("latin-1", "replace") if m.group(1) else self.expand_text(body).encode("latin-1", "replace"))
            cmd = cmd[:m.start()] + cmd[m.end():] if m.end() < len(cmd) else cmd[:m.start()]
            cmd = cmd.split("\n", 1)[0]
        m = re.search(r"<<<\s*(.*)$", cmd)
        if m:
            w = self.words(m.group(1))
            here = Unk(w[0].unk) if w and w[0].unk else _B((" ".join(x.text for x in w) + "\n").encode("latin-1", "replace"),
                                                           w[0].recipe if w else ())
            cmd = cmd[:m.start()]
        # redirections
        out_path, append, in_path = "", False, ""
        for mm in list(re.finditer(r"(\d?)(>>|>|<)(?![&(])\s*(\"[^\"]*\"|'[^']*'|[^\s;|&<>]+)", _mask_quotes(cmd)))[::-1]:
            target = self.words(cmd[mm.start(3):mm.end(3)])
            tgt = target[0].text if target else ""
            if mm.group(2) == "<":
                in_path = tgt
            elif mm.group(1) in ("", "1") and tgt not in ("/dev/null",):
                out_path, append = tgt, mm.group(2) == ">>"
            cmd = cmd[:mm.start()] + cmd[mm.end():]
        if here is not None:
            stdin = here
        if in_path:
            stdin = self.read(in_path)
        words = self.words(cmd, split=True)
        if not words:
            return stdin
        # assignments
        while words and re.match(r"^[A-Za-z_]\w*=", words[0].text) and not words[0].unk_name:
            name, _, val = words[0].text.partition("=")
            w0 = words[0]
            self.vars[name] = Unk(w0.unk) if w0.unk else tag(val, w0.recipe) if w0.recipe else val
            words = words[1:]
        if not words:
            return b""
        name = words[0].text.rsplit("/", 1)[-1]
        args = words[1:]
        out = self.command(name, words[0], args, stdin, cmd)
        if out_path:
            self.write(out_path, out, append, name)
            return b""
        return out

    def command(self, name: str, w0: Word, args: list[Word], stdin: Any, cmd: str) -> Any:  # noqa: C901, PLR0911, PLR0912
        a = [w.text for w in args]
        unk = next((w.unk for w in [w0] + args if w.unk), "")
        if "/dev/tcp/" in cmd or "/dev/udp/" in cmd:
            m = re.search(r"/dev/(tcp|udp)/([^/\s]+)/(\d+)", cmd)
            if m:
                self.sinks.download(Value("str", f"{m.group(1)}://{m.group(2)}:{m.group(3)}"), "/dev/tcp",
                                    "connects to it (a reverse shell / C2)", self.line)
            return Unk("a network connection")
        if w0.unk:
            self.sinks.unresolved_(cmd.strip()[:300], w0.unk, "the command's name is computed at run time", self.line)
            return Unk("the output of a command named at run time")
        if name in self.funcs:
            saved = {k: self.vars.get(k) for k in [str(i) for i in range(1, 10)] + ["@"]}
            for i, x in enumerate(a, 1):
                self.vars[str(i)] = x
            self.vars["@"] = " ".join(a)
            try:
                return self.run(self.funcs[name], stdin)
            except _Ret:
                return b""
            finally:
                for k, v in saved.items():
                    if v is None:
                        self.vars.pop(k, None)
                    else:
                        self.vars[k] = v
        if name in ("echo",):
            flags = ""
            while a and re.fullmatch(r"-[neE]+", a[0]):
                flags += a.pop(0)[1:]
                args = args[1:]
            if unk:
                return Unk(unk)
            s = " ".join(a)
            if "e" in flags:
                s = _ansi(s)
            return _B((s + ("" if "n" in flags else "\n")).encode("latin-1", "replace"), next((w.recipe for w in args if w.recipe), ()))
        if name == "printf":
            if unk:
                return Unk(unk)
            if not a:
                return b""
            fmt = a[0]
            vals = a[1:]
            s = _printf(fmt, vals)
            r = ("printf escapes",) if re.search(r"\\x[0-9a-fA-F]|\\[0-7]{3}", fmt) else ()
            return _B(s.encode("latin-1", "replace"), (args[0].recipe or ()) + r if len(s) >= 16 else ())
        if name in ("cat",) and a:
            parts = [self.read(x) for x in a if not x.startswith("-")]
            return self._join(parts)
        if name in ("cat", "tee", "dd") and not a or name == "cat":
            if name == "tee":
                return stdin
            return stdin
        if name == "tee":
            for x in a:
                if not x.startswith("-"):
                    self.write(x, stdin, "-a" in a, "tee")
            return stdin
        if name in ("true", ":"):
            return b""
        if name == "false":
            return Fail()
        if name in ("export", "local", "declare", "readonly", "typeset"):
            for w in args:
                if "=" in w.text and not w.text.startswith("-"):
                    k, _, v = w.text.partition("=")
                    self.vars[k] = Unk(w.unk) if w.unk else (tag(v, w.recipe) if w.recipe else v)
            return b""
        if name == "unset":
            for x in a:
                self.vars.pop(x, None)
            return b""
        if name in ("return", "exit"):
            raise _Ret()
        if name == "break":
            raise _Brk()
        if name in ("set", "shift", "trap", "cd", "sleep", "umask", "ulimit", "alias", "shopt", "wait", "disown",
                    "mkdir", "rm", "kill", "pkill", "killall", "clear", "history", "unalias", "hash", "sync", "touch",
                    "chown", "systemctl", "service", "iptables", "ufw", "setenforce", "crontab", "ln", "cp", "mv",
                    "find", "grep", "ps", "id", "whoami", "uname", "hostname", "nproc", "free", "lscpu", "ls", "type",
                    "command", "which", "stat", "sudo", "su", "nice", "renice", "timeout"):
            if name in ("sudo", "nohup", "nice", "timeout", "command") and a:
                rest = cmd.split(None, 1)[1] if len(cmd.split(None, 1)) > 1 else ""
                if name == "timeout" and a:
                    rest = rest.split(None, 1)[1] if len(rest.split(None, 1)) > 1 else ""
                return self.pipeline(re.sub(r"^\s*-\S+\s+", "", rest), stdin)
            if name in ("cp", "mv") and len(a) >= 2:
                src = self.files.get(a[-2])
                if src is not None:
                    self.files[a[-1]] = dict(src, path=a[-1])
                    if name == "mv":
                        self.files.pop(a[-2], None)
            if name == "crontab":
                self.sinks.step(self.line, "crontab (persistence)", Value("str", cmd[:200]))
            return b""
        if name == "nohup" or name == "setsid" or name == "exec" and a:
            rest = cmd.split(None, 1)[1] if len(cmd.split(None, 1)) > 1 else ""
            return self.pipeline(rest, stdin)
        if name == "chmod":
            for x in a:
                f = self.files.get(x)
                if f is not None:
                    f["exec"] = True
                self._mark_dl(x, "makes it executable (chmod)")
            return b""
        if name in ("eval", "source", ".") and name == "eval":
            code = Unk(unk) if unk else _B(" ".join(a).encode("latin-1", "replace"), next((w.recipe for w in args if w.recipe), ()))
            return self.exec_code(code, "eval")
        if name in ("source", "."):
            data = self.read(a[0]) if a else b""
            return self.exec_code(data, f"source {a[0] if a else ''}")
        if name in _SHELLS:
            if "-c" in a:
                i = a.index("-c")
                if i + 1 < len(a):
                    w = args[i + 1]
                    code = Unk(w.unk) if w.unk else _B(w.text.encode("latin-1", "replace"), w.recipe)
                    return self.exec_code(code, f"{name} -c")
            files = [x for x in a if not x.startswith("-")]
            if files:
                f = self.files.get(files[0])
                if f is not None:
                    f["run"] = cmd.strip()[:120]
                    return self.exec_code(_B(f["data"], tuple(f["recipe"])) if isinstance(f["data"], bytes) else f["data"],
                                          f"{name} {files[0]}", already=True)
                self._mark_dl(files[0], f"runs it ({name})")
                return b""
            return self.exec_code(stdin, f"| {name}")
        if name in _INTERP:
            ext = _INTERP[name]
            flag = {"python": "-c", "python2": "-c", "python3": "-c", "perl": "-e", "php": "-r", "ruby": "-e",
                    "node": "-e", "nodejs": "-e", "lua": "-e", "pwsh": "-c", "powershell": "-c"}[name]
            if flag in a or (name == "perl" and "-E" in a):
                i = a.index(flag) if flag in a else a.index("-E")
                if i + 1 < len(a):
                    w = args[i + 1]
                    self.stage(Unk(w.unk) if w.unk else _B(w.text.encode("latin-1", "replace"), w.recipe), f"{name} {flag}", ext)
                    return Unk(f"the output of {name}")
            if name in ("pwsh", "powershell"):
                commands.launch(self.sinks, cmd, (), self.line, "shell")
                return Unk(f"the output of {name}")
            files = [x for x in a if not x.startswith("-")]
            if files and files[0] in self.files:
                self.files[files[0]]["run"] = cmd.strip()[:120]
                return Unk(f"the output of {name}")
            if not files and stdin is not None and not isinstance(stdin, bytes) or (not files and isinstance(stdin, bytes) and stdin):
                self.stage(stdin, f"| {name}", ext)
            return Unk(f"the output of {name}")
        # decoders
        if name in ("base64", "base32", "basenc") and ("-d" in a or "--decode" in a or "-D" in a):
            return self.decode(stdin, a, "base32" if name == "base32" else "base64",
                               T.b32decode if name == "base32" else lambda b: T.b64decode(b))
        if name in ("gunzip", "zcat", "gzip") and (name != "gzip" or "-d" in a or "-dc" in a or "-cd" in a):
            return self.decode(stdin, a, "gzip", T.gunzip)
        if name in ("xz", "unxz", "xzcat", "lzma", "unlzma") and (name not in ("xz", "lzma") or "-d" in a or "-dc" in a):
            return self.decode(stdin, a, "xz", T.unlzma)
        if name in ("bzip2", "bunzip2", "bzcat") and (name != "bzip2" or "-d" in a or "-dc" in a):
            return self.decode(stdin, a, "bzip2", T.bunzip2)
        if name == "xxd" and "-r" in a:
            return self.decode(stdin, a, "hex (xxd -r -p)" if "-p" in a or "-ps" in a else "xxd -r",
                               lambda b: T.hexdecode(re.sub(rb"(?m)^[0-9a-fA-F]+:\s|\s{2}.*$", b"", b) if b"-p" not in b"".join(x.encode() for x in a) else b))
        if name == "rev":
            if isinstance(stdin, Unk):
                return stdin
            lines = (stdin or b"").split(b"\n")
            out = b"\n".join(x[::-1] for x in lines)
            return _B(out, getattr(stdin, "recipe", ()) + ("rev",))
        if name == "tr":
            if isinstance(stdin, Unk) or len(a) < 1:
                return stdin
            if a[0] == "-d" and len(a) > 1:
                chars = set(_tr_set(a[1]))
                out = bytes(c for c in (stdin or b"") if chr(c) not in chars)
                return _B(out, getattr(stdin, "recipe", ()) + (f"tr -d {a[1][:12]}",))
            if len(a) >= 2:
                src, dst = _tr_set(a[0]), _tr_set(a[1])
                table = {ord(c): dst[min(i, len(dst) - 1)] for i, c in enumerate(src)} if dst else {}
                out = (stdin or b"").decode("latin-1").translate(table).encode("latin-1", "replace")
                return _B(out, getattr(stdin, "recipe", ()) + (f"tr {a[0][:12]} {a[1][:12]}",))
            return stdin
        if name == "openssl":
            return self.openssl(a, stdin)
        if name in ("cut", "head", "tail", "sed", "awk", "sort", "uniq", "wc"):
            if name == "sed" and a and isinstance(stdin, bytes):
                m = re.match(r"s(.)(.*?)\1(.*?)\1(g?)", a[-1] if not a[-1].startswith("-") else "")
                if m:
                    try:
                        out = re.sub(m.group(2), m.group(3).replace("\\", "\\\\").replace("&", "\\g<0>"),
                                     stdin.decode("latin-1"), count=0 if m.group(4) else 1)
                        return _B(out.encode("latin-1"), getattr(stdin, "recipe", ()) + (f"sed {a[-1][:16]}",))
                    except re.error:
                        return stdin
            return stdin
        # downloads
        if name in ("curl", "wget", "fetch", "lwp-download", "aria2c", "tftp", "ftpget", "busybox_wget"):
            return self.fetch(name, args, a, cmd)
        if w0.text.startswith(("./", "/tmp/", "/dev/shm/", "/var/tmp/", "~/", "$HOME/")) or w0.text in self.files \
                or name in self.files:
            path = w0.text
            f = self.files.get(path) or self.files.get(path.lstrip("./"))
            if f is not None:
                f["run"] = cmd.strip()[:120]
            else:
                self._mark_dl(path, f"runs it ({cmd.strip()[:60]})")
            return b""
        if "/dev/tcp/" in cmd or "/dev/udp/" in cmd:
            m = re.search(r"/dev/(tcp|udp)/([^/\s]+)/(\d+)", cmd)
            if m:
                self.sinks.download(Value("str", f"{m.group(1)}://{m.group(2)}:{m.group(3)}"), "/dev/tcp",
                                    "connects to it (a reverse shell / C2)", self.line)
            return Unk("a network connection")
        if name in ("nc", "ncat", "netcat", "socat", "telnet"):
            hosts = [x for x in a if not x.startswith("-")]
            if hosts:
                self.sinks.download(Value("str", f"tcp://{hosts[0]}:{hosts[1] if len(hosts) > 1 else '?'}"), name,
                                    "connects to it (a reverse shell / C2)" if "-e" in a or "exec" in cmd else "connects to it", self.line)
            return Unk("a network connection")
        if unk:
            return Unk(unk)
        return Unk(f"the output of {name}")

    def decode(self, stdin: Any, a: list[str], label: str, fn: Any) -> Any:
        files = [x for x in a if not x.startswith("-")]
        data = self.read(files[0]) if files else stdin
        if isinstance(data, Unk):
            return data
        try:
            out = fn(bytes(data or b""))
        except T.TransformError as exc:
            self.errors.append(f"line {self.line}: {label}: {exc}")
            return Fail()
        return _B(out, getattr(data, "recipe", ()) + (label,))

    def openssl(self, a: list[str], stdin: Any) -> Any:
        if not a:
            return stdin
        if a[0] in ("base64", "enc") and "-d" in a and a[0] == "base64" or (a[0] == "enc" and "-base64" in a and "-d" in a and not any(x.startswith("-aes") or x.startswith("-des") or x.startswith("-rc4") or x.startswith("-bf") for x in a)):
            return self.decode(stdin, [], "base64", lambda b: T.b64decode(b))
        if a[0] != "enc" and not a[0].startswith("-"):
            ciph = a[0]
        else:
            ciph = next((x[1:] for x in a if re.match(r"-(aes|des|rc4|bf|chacha|camellia)", x)), "")
        if "-d" not in a or not ciph:
            return stdin
        data = stdin
        files = [a[i + 1] for i, x in enumerate(a) if x == "-in" and i + 1 < len(a)]
        if files:
            data = self.read(files[0])
        if isinstance(data, Unk):
            return data
        d = bytes(data or b"")
        r = getattr(data, "recipe", ())
        if "-a" in a or "-base64" in a:
            try:
                d = T.b64decode(d)
            except T.TransformError:
                return Fail()
            r = r + ("base64",)
        m = re.match(r"(aes|des-ede3|des|rc4|chacha20)(?:-(\d+))?(?:-(cbc|ecb|ctr|cfb|ofb))?", ciph.lower())
        if not m:
            return Unk(f"openssl {ciph} (not followed)")
        alg = {"des-ede3": "3des"}.get(m.group(1), m.group(1))
        bits = int(m.group(2)) if m.group(2) else 128
        klen = bits // 8 if alg == "aes" else {"3des": 24, "des": 8, "rc4": 16, "chacha20": 32}[alg]
        ivlen = 16 if alg in ("aes", "chacha20") else (0 if alg == "rc4" else 8)
        kv = lambda flag: a[a.index(flag) + 1] if flag in a and a.index(flag) + 1 < len(a) else None  # noqa: E731
        try:
            if kv("-K"):
                key = bytes.fromhex(kv("-K"))
                iv = bytes.fromhex(kv("-iv")) if kv("-iv") else None
                desc = f"{ciph}(key -K)"
            else:
                pw = kv("-k") or (kv("-pass") or "").removeprefix("pass:")
                if not pw:
                    return Unk("an openssl password not in the script")
                salt = b""
                if d[:8] == b"Salted__":
                    salt, d = d[8:16], d[16:]
                md = "sha256" if "-md" not in a else (kv("-md") or "sha256")
                if "-pbkdf2" in a or "-iter" in a:
                    it = int(kv("-iter") or 10000)
                    km = hashlib.pbkdf2_hmac(md, pw.encode(), salt, it, klen + ivlen)
                else:
                    km = b""
                    prev = b""
                    while len(km) < klen + ivlen:
                        prev = hashlib.new(md, prev + pw.encode() + salt).digest()
                        km += prev
                key, iv = km[:klen], km[klen:klen + ivlen] or None
                desc = f"{ciph}(password {pw[:12]!r})"
            out = T.rc4(d, key) if alg == "rc4" else T.decrypt(alg, d, key, iv, m.group(3) or "cbc")
        except (T.TransformError, ValueError) as exc:
            self.errors.append(f"line {self.line}: openssl: {exc}")
            return Fail()
        return _B(out, r + (desc,))

    def fetch(self, name: str, args: list[Word], a: list[str], cmd: str) -> Any:
        url = next((w for w in args if re.match(r"(?i)(?:https?|ftp|tftp)://|[\w.-]+\.\w+/", w.text) and not w.text.startswith("-")), None)
        if url is None:
            url = next((w for w in args if w.unk), None)
        dest = ""
        for i, x in enumerate(a):
            if x in ("-o", "-O", "--output", "--output-document") and i + 1 < len(a):
                dest = a[i + 1]
            elif x.startswith("--output-document="):
                dest = x.split("=", 1)[1]
        if name == "wget" and not dest and "-O" not in a and url is not None and not url.unk:
            dest = url.text.rstrip("/").rsplit("/", 1)[-1]
        if name == "curl" and "-O" in a and url is not None and not url.unk:
            dest = url.text.rstrip("/").rsplit("/", 1)[-1]
        to_stdout = dest in ("-", "/dev/stdout") or (name == "curl" and not dest) or ("-qO-" in a or "-O-" in a)
        if url is None:
            return Unk(f"the output of {name}")
        if url.unk:
            self.sinks.download(Value.unknown(url.unk), name, "returns it to the script", self.line)
            return Unk(f"the content downloaded from <{url.unk}>")
        u = url.text if re.match(r"(?i)[a-z]+://", url.text) else "http://" + url.text
        self.sinks.download(Value("str", u, url.recipe), name, "returns it to the script" if to_stdout else "saves it",
                            self.line, "" if to_stdout else dest)
        return Unk(f"the content downloaded from {u}") if to_stdout else b""

    def _mark_dl(self, path: str, what: str) -> None:
        base = path.rstrip("/").rsplit("/", 1)[-1]
        for d in self.sinks.downloads:
            sv = (d.get("saved_to") or "").rsplit("/", 1)[-1]
            if sv and (sv == base) and what not in d["use"]:
                d["use"] += f", then {what}" if "makes it executable" not in what or "runs it" not in d["use"] else ""

    # -- stages ---------------------------------------------------------------------------------------------
    def exec_code(self, code: Any, sink: str, already: bool = False) -> Any:
        if isinstance(code, Unk):
            self.sinks.exec_(Value.unknown(code.why), sink, self.line)
            return Unk(f"the output of code computed from {code.why}")
        if code is None:
            return b""
        b = bytes(code)
        src = b.decode("utf-8", "replace") if not _latin_only(b) else b.decode("latin-1")
        if not already:
            self.sinks.exec_(Value("str", src, getattr(code, "recipe", ())), sink, self.line)
        h = hashlib.sha256(b).hexdigest()
        if self.depth >= MAX_DEPTH or h in self.ran:
            return b""
        self.ran.add(h)
        self.depth += 1
        self.sinks.depth = self.depth
        saved = self.source
        self.source = src
        try:
            return self.run(src)
        finally:
            self.source = saved
            self.depth -= 1
            self.sinks.depth = self.depth

    def stage(self, code: Any, sink: str, ext: str) -> None:
        if isinstance(code, Unk):
            self.sinks.exec_(Value.unknown(code.why), sink, self.line)
            return
        b = bytes(code or b"")
        if not b.strip():
            return
        n = len(self.sinks.stages)
        self.sinks.exec_(Value("str", b.decode("utf-8", "replace"), getattr(code, "recipe", ())), sink, self.line)
        if len(self.sinks.stages) > n:
            self.sinks.stages[-1].ext = ext

    def read(self, path: str) -> Any:
        if path in ("$0", "script.sh", self.vars.get("0")):
            return _B(self.source.encode("latin-1", "replace"), ("the script's own file",))
        f = self.files.get(path)
        if f is None:
            return Unk(f"the content of {path} (a file on the victim's machine)")
        return _B(f["data"], tuple(f["recipe"])) if isinstance(f["data"], bytes) else f["data"]

    def write(self, path: str, data: Any, append: bool, how: str) -> None:
        if isinstance(data, Fail):
            return
        if isinstance(data, Unk):
            self._downloaded_to(data, path)
            return
        b = bytes(data or b"")
        f = self.files.get(path)
        if f is None or not append or isinstance(f.get("data"), Unk):
            self.files[path] = {"path": path, "data": b, "recipe": list(getattr(data, "recipe", ()) or (f"{how} > {path.rsplit('/', 1)[-1]}",))}
        else:
            f["data"] = f["data"] + b

    def _downloaded_to(self, data: Unk, path: str) -> None:
        if data.why.startswith("the content downloaded from "):
            url = data.why[len("the content downloaded from "):]
            for d in self.sinks.downloads:
                if d["url"] == url:
                    d["saved_to"] = path
                    d["use"] = "saves it"
            self.files[path] = {"path": path, "data": data, "recipe": [], "dl": url}

    def finish(self) -> None:
        for f in self.files.values():
            d = f["data"]
            if isinstance(d, Unk):
                if f.get("run"):
                    for dl in self.sinks.downloads:
                        if dl.get("saved_to") == f["path"] and "runs it" not in dl["use"]:
                            dl["use"] += f", then runs it ({f['run'][:60]})"
                continue
            if not d or len(d.strip()) < 16 and not f.get("run"):
                continue
            sink = "writes" + (f" and runs ({f['run'][:80]})" if f.get("run") else "")
            self.sinks.write(Value("bytes", d, tuple(f["recipe"])), f["path"], sink, None)

    # -- words ---------------------------------------------------------------------------------------------
    def words(self, s: str, split: bool = False) -> list[Word]:  # noqa: C901, PLR0912
        out: list[Word] = []
        i = 0
        n = len(s)
        cur: list[str] = []
        recipe: tuple = ()
        unk = ""
        has = False
        unk_name = False

        def push() -> None:
            nonlocal cur, recipe, unk, has, unk_name
            if has:
                w = Word("".join(cur), recipe, unk)
                w.unk_name = unk_name  # type: ignore[attr-defined]
                out.append(w)
            cur, recipe, unk, has, unk_name = [], (), "", False, False
        while i < n:
            c = s[i]
            if c in " \t\n":
                push()
                i += 1
                continue
            if c == "#" and not has:
                j = s.find("\n", i)
                i = n if j < 0 else j
                continue
            has = True
            if c == "\\" and i + 1 < n:
                cur.append(s[i + 1])
                i += 2
                continue
            if c == "'":
                j = s.find("'", i + 1)
                j = n if j < 0 else j
                cur.append(s[i + 1:j])
                if j - i > 16 and not recipe:
                    recipe = ("literal",)
                i = j + 1
                continue
            if c == "$" and s.startswith("$'", i):
                j = i + 2
                while j < n and s[j] != "'":
                    j += 2 if s[j] == "\\" else 1
                cur.append(_ansi(s[i + 2:j]))
                recipe = recipe or ("$'…' escapes",)
                i = j + 1
                continue
            if c == '"':
                j = i + 1
                buf = []
                while j < n and s[j] != '"':
                    if s[j] == "\\" and j + 1 < n and s[j + 1] in '"\\$`\n':
                        buf.append(s[j + 1])
                        j += 2
                        continue
                    if s[j] == "$" or s[j] == "`":
                        k, val, r, u = self.dollar(s, j)
                        buf.append(val)
                        recipe = recipe or r
                        unk = unk or u
                        j = k
                        continue
                    buf.append(s[j])
                    j += 1
                cur.append("".join(buf))
                i = j + 1
                continue
            if c in "$`":
                k, val, r, u = self.dollar(s, i)
                if k == i:
                    cur.append(c)
                    i += 1
                    continue
                if u and not cur and not out:
                    unk_name = False
                cur.append(val)
                recipe = recipe or r
                unk = unk or u
                i = k
                continue
            cur.append(c)
            i += 1
        push()
        return out

    def dollar(self, s: str, i: int) -> tuple[int, str, tuple, str]:  # noqa: C901, PLR0911
        n = len(s)
        if s[i] == "`":
            j = s.find("`", i + 1)
            j = n if j < 0 else j
            o = self.subst(s[i + 1:j])
            return j + 1, *o
        if s.startswith("$((", i):
            j, body = _balanced(s, i + 2, "(", ")")
            v = self.arith(body[1:-1] if body.startswith("(") else body)
            return j + 1 if j < n and s[j] == ")" else j, str(v if v is not None else 0), (), ""
        if s.startswith("$(", i):
            j, body = _balanced(s, i + 1, "(", ")")
            o = self.subst(body)
            return j, *o
        if s.startswith("${", i):
            j = s.find("}", i)
            j = n if j < 0 else j
            v, r, u = self.param(s[i + 2:j])
            return j + 1, v, r, u
        m = re.match(r"\$([A-Za-z_]\w*|[0-9@*#?$!])", s[i:])
        if m:
            v, r, u = self.param(m.group(1))
            return i + m.end(), v, r, u
        return i, "", (), ""

    def subst(self, body: str) -> tuple[str, tuple, str]:
        self.depth += 1
        try:
            o = self.run(body)
        finally:
            self.depth -= 1
        if isinstance(o, Unk):
            return f"<{o.why}>", (), o.why
        if isinstance(o, Fail) or o is None:
            return "", (), ""
        txt = bytes(o).decode("latin-1").rstrip("\n")
        return txt, getattr(o, "recipe", ()), ""

    def param(self, spec: str) -> tuple[str, tuple, str]:  # noqa: C901, PLR0911
        m = re.match(r"^(#)?([A-Za-z_]\w*|[0-9@*#?$!])(.*)$", spec, re.S)
        if not m:
            return "", (), ""
        length, name, op = m.group(1), m.group(2), m.group(3)
        v = self.vars.get(name)
        if name in ("RANDOM", "$", "!"):
            v = "12345"
        if isinstance(v, Unk):
            return f"<{v.why}>", (), v.why
        if v is None:
            if name in ("USER", "HOSTNAME", "HOME"):
                return f"${name}", (), ""
            v = ""
        r = rec(v)
        s = str(v)
        if length:
            return str(len(s)), (), ""
        if not op:
            return s, r, ""
        if op.startswith((":-", "-")):
            d = op.split("-", 1)[1]
            return (s if s else self.expand_text(d)), r, ""
        if op.startswith((":=", ":+")):
            return (s if op[1] == "=" and s else (self.expand_text(op[2:]) if (op[1] == "+") == bool(s) else s)), r, ""
        mm = re.match(r"^:(-?\d+)(?::(-?\d+))?$", op)
        if mm:
            o = int(mm.group(1))
            if o < 0:
                o = max(0, len(s) + o)
            out = s[o:] if mm.group(2) is None else (s[o:o + int(mm.group(2))] if int(mm.group(2)) >= 0 else s[o:len(s) + int(mm.group(2))])
            return out, r, ""
        mm = re.match(r"^(//?)([^/]*)/?(.*)$", op, re.S)
        if mm:
            pat = _glob_re(mm.group(2))
            try:
                out = re.sub(pat, mm.group(3).replace("\\", "\\\\"), s, count=0 if mm.group(1) == "//" else 1)
            except re.error:
                out = s
            return out, r + ((f"${{…/{mm.group(2)[:8]}/{mm.group(3)[:8]}}}",) if out != s and len(out) >= 16 else ()), ""
        mm = re.match(r"^(##?|%%?)(.*)$", op, re.S)
        if mm:
            pat = _glob_re(mm.group(2), greedy=len(mm.group(1)) == 2)
            if mm.group(1).startswith("#"):
                m2 = re.match(pat, s)
                return (s[m2.end():] if m2 else s), r, ""
            for k in (range(len(s) + 1) if len(mm.group(1)) == 2 else range(len(s), -1, -1)):
                if re.fullmatch(pat, s[k:]):
                    return s[:k], r, ""
            return s, r, ""
        if op in ("^^", ",,"):
            return (s.upper() if op == "^^" else s.lower()), r, ""
        return s, r, ""

    def expand_text(self, s: str) -> str:
        out = []
        i = 0
        while i < len(s):
            if s[i] in "$`":
                k, v, _r, _u = self.dollar(s, i)
                if k > i:
                    out.append(v)
                    i = k
                    continue
            if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in "$`\\":
                out.append(s[i + 1])
                i += 2
                continue
            out.append(s[i])
            i += 1
        return "".join(out)

    def arith(self, e: str) -> int | None:
        e = e.strip()
        m = re.match(r"^([A-Za-z_]\w*)\s*([-+*/%^|&]?=)\s*(.*)$", e)
        if m and m.group(2) != "==":
            val = self.arith(m.group(3))
            if val is None:
                return None
            cur = int(str(self.vars.get(m.group(1), "0")) or "0") if str(self.vars.get(m.group(1), "0")).lstrip("-").isdigit() else 0
            op = m.group(2)[0]
            val = {"=": val, "+": cur + val, "-": cur - val, "*": cur * val, "/": cur // val if val else 0,
                   "%": cur % val if val else 0, "^": cur ^ val, "|": cur | val, "&": cur & val}[op]
            self.vars[m.group(1)] = str(val)
            return val
        m = re.match(r"^([A-Za-z_]\w*)(\+\+|--)$", e) or re.match(r"^(\+\+|--)([A-Za-z_]\w*)$", e)
        if m:
            nm = m.group(1) if m.group(1) not in ("++", "--") else m.group(2)
            op = m.group(2) if m.group(1) not in ("++", "--") else m.group(1)
            cur = int(str(self.vars.get(nm, "0")) or 0) if str(self.vars.get(nm, "0")).lstrip("-").isdigit() else 0
            self.vars[nm] = str(cur + (1 if op == "++" else -1))
            return cur

        def var(mm: re.Match) -> str:
            v = self.vars.get(mm.group(1), "0")
            return str(v) if str(v).lstrip("-").isdigit() else "0"
        x = re.sub(r"\$?\{?([A-Za-z_]\w*)\}?", var, e)
        x = re.sub(r"\b0[xX]([0-9a-fA-F]+)\b", lambda mm: str(int(mm.group(1), 16)), x)
        if not re.fullmatch(r"[\d\s+\-*/%()<>=!&|^~]*", x):
            return None
        x = x.replace("/", "//").replace("&&", " and ").replace("||", " or ")
        try:
            return int(eval(x, {"__builtins__": {}}, {}))  # noqa: S307  (digits and operators only, checked above)
        except Exception:  # noqa: BLE001
            return None


class _B(bytes):
    """Bytes with a recipe."""
    recipe: tuple = ()

    def __new__(cls, data: bytes, recipe: tuple = ()) -> "_B":
        o = super().__new__(cls, data)
        o.recipe = tuple(recipe)
        return o


class Fail(bytes):
    """A command that failed (for ``&&`` / ``||``)."""


def _latin_only(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def _mask_quotes(s: str) -> str:
    out = list(s)
    q = None
    for i, c in enumerate(s):
        if q is None and c in "'\"":
            q = c
            continue
        if q is not None:
            if c == q:
                q = None
            else:
                out[i] = "x"
    return "".join(out)


def _split_ops(s: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    buf: list[str] = []
    sep = ""
    q = None
    depth = 0
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if q:
            buf.append(c)
            if c == "\\" and q == '"' and i + 1 < n:
                buf.append(s[i + 1])
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c in "'\"`":
            q = c
            buf.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(s[i:i + 2])
            i += 2
            continue
        if c == "(" or (c == "{" and (i + 1 < n and s[i + 1] in " \n")):
            depth += 1
        elif (c == ")" or c == "}") and depth:
            depth -= 1
        if depth == 0:
            two = s[i:i + 2]
            if two in ("&&", "||"):
                out.append(("".join(buf), sep))
                buf, sep = [], two
                i += 2
                continue
            if c in ";\n" and not s[max(0, i - 1):i + 1].endswith(";;"):
                out.append(("".join(buf), sep))
                buf, sep = [], ";"
                i += 1
                continue
        buf.append(c)
        i += 1
    out.append(("".join(buf), sep))
    return [(c.strip(), sp) for c, sp in out if c.strip()]


def _split_pipe(s: str) -> list[str]:
    out = []
    buf: list[str] = []
    q = None
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            buf.append(c)
            if c == q:
                q = None
            elif c == "\\" and q == '"' and i + 1 < len(s):
                buf.append(s[i + 1])
                i += 1
            i += 1
            continue
        if c in "'\"`":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")" and depth:
            depth -= 1
        elif c == "|" and depth == 0 and s[i:i + 2] != "||" and (i == 0 or s[i - 1] != "|"):
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def _balanced(s: str, start: int, op: str, close: str) -> tuple[int, str]:
    depth = 0
    q = None
    for j in range(start, len(s)):
        c = s[j]
        if q:
            if c == q:
                q = None
            continue
        if c in "'\"":
            q = c
            continue
        if c == op:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return j + 1, s[start + 1:j]
    return len(s), s[start + 1:]


def _printf(fmt: str, vals: list[str]) -> str:
    out = []
    vi = 0
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c == "\\" and i + 1 < len(fmt):
            m = re.match(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|u[0-9a-fA-F]{4}|.)", fmt[i:])
            out.append(_esc1(m.group(1)))
            i += m.end()
            continue
        if c == "%" and i + 1 < len(fmt):
            m = re.match(r"%([-+ 0#]*\d*(?:\.\d+)?)([sdbxXoc%])", fmt[i:])
            if m:
                conv = m.group(2)
                v = vals[vi] if vi < len(vals) else ""
                if conv != "%":
                    vi += 1
                if conv == "%":
                    out.append("%")
                elif conv == "b":
                    out.append(_ansi(v))
                elif conv in "dxXo":
                    try:
                        out.append(("%" + m.group(1) + conv) % int(v or "0", 0))
                    except ValueError:
                        out.append("0")
                elif conv == "c":
                    out.append(v[:1])
                else:
                    out.append(("%" + m.group(1) + "s") % v)
                i += m.end()
                continue
        out.append(c)
        i += 1
    s = "".join(out)
    if vi and vi < len(vals):
        # printf reuses its format for the remaining arguments
        s += _printf(fmt, vals[vi:])
    return s


def _tr_set(s: str) -> str:
    classes = {"[:lower:]": "abcdefghijklmnopqrstuvwxyz", "[:upper:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
               "[:digit:]": "0123456789", "[:alpha:]": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
               "[:space:]": " \t\n\r\v\f"}
    for k, v in classes.items():
        s = s.replace(k, v)
    s = _ansi(s)
    out = []
    i = 0
    while i < len(s):
        if i + 2 < len(s) and s[i + 1] == "-":
            out.extend(chr(c) for c in range(ord(s[i]), ord(s[i + 2]) + 1))
            i += 3
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _glob_re(p: str, greedy: bool = True) -> str:
    out = []
    for c in p:
        if c == "*":
            out.append(".*" if greedy else ".*?")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
    return "".join(out)


def run_command(sinks: Sinks, cmd: str, recipe: tuple[str, ...] = (), line: int | None = None, via: str = "command") -> None:
    """A command line another language hands to a shell (``system``, ``os.execute``, backticks): its
    pipes, downloads and the code it runs, reported to the caller's sinks."""
    sinks.step(line, f"{via} runs", Value("str", cmd[:300], recipe))
    it = Interp(sinks, cmd)
    it.line = line or 0
    it.depth = sinks.depth
    try:
        it.run(cmd)
    except (Limit, _Ret, _Brk):
        pass
    except RecursionError:
        pass
    it.finish()


def resolve(code: str, location: str = "shell") -> Sinks:
    s = Sinks("shell")
    it = Interp(s, code.lstrip("\ufeff"))
    try:
        it.run(code.lstrip("\ufeff"))
    except (Limit, _Ret, _Brk):
        pass
    except RecursionError:
        it.errors.append("recursion")
    it.finish()
    s.errors = it.errors  # type: ignore[attr-defined]
    s.stats = {"steps": it.steps, "seconds": round(time.monotonic() - it.t0, 2)}  # type: ignore[attr-defined]
    return s


del base64
