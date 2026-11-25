"""Batch / cmd, evaluated statically: what a ``.bat`` builds and launches, without running it.

The script is walked line by line the way ``cmd.exe`` reads it: ``%var%`` expanded when a line is
read, ``!var!`` when a command runs, ``%var:~s,l%`` / ``%var:a=b%`` / ``set /a``, carets, ``&`` /
``&&`` / ``||`` / ``|``, parenthesised blocks, ``if`` / ``for`` (``/l``, lists, ``/f`` over text or a
file), ``goto`` / ``call :label``, ``call`` re-expansion and ``cmd /c "…"`` evaluated as a line of its
own. Files are kept in a virtual folder: ``echo … > x.vbs`` / ``>>``, ``type`` / ``more +N``,
``copy /b a+b c``, ``certutil -decode`` / ``-decodehex`` (the script's own file too: a base64 block
after the code), ``set /p v=<file``.

What it writes is a stage (a ``.vbs``, a ``.ps1``, an ``.exe`` decoded with certutil) with its
recipe; the commands it launches are followed by :mod:`.commands` (``powershell -enc`` / ``-c``,
``echo … | powershell -``, ``mshta``, ``certutil -urlcache``, ``bitsadmin``, ``curl``); a script it
wrote and then runs (``wscript x.vbs``, ``start x.exe``, ``call x.bat``) is said so. A command built
from something that only exists on the victim's machine (``for /f`` over a command's output, a
registry query, what the user types) is a dynamic call not resolved.

Bounded: lines executed, loop rounds, call depth and time.
"""

from __future__ import annotations

import re
import time
from typing import Any

from . import commands
from . import transforms as T
from .sinks import Sinks
from .value import Value

MAX_STEPS = 400_000
MAX_SECONDS = 20.0
MAX_LOOP = 100_000
MAX_CALL_DEPTH = 40
MAX_FILE = 64 * 1024 * 1024
SCRIPT_PATH = "C:\\Users\\Public\\script.bat"

ENV = {"comspec": "C:\\WINDOWS\\system32\\cmd.exe", "windir": "C:\\WINDOWS", "systemroot": "C:\\WINDOWS",
       "programdata": "C:\\ProgramData", "public": "C:\\Users\\Public", "os": "Windows_NT",
       "systemdrive": "C:", "programfiles": "C:\\Program Files", "programfiles(x86)": "C:\\Program Files (x86)",
       "allusersprofile": "C:\\ProgramData", "commonprogramfiles": "C:\\Program Files\\Common Files",
       "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
       "processor_architecture": "AMD64", "number_of_processors": "4", "random": "12345",
       "errorlevel": "0", "cd": "C:\\Users\\Public", "path": "C:\\WINDOWS\\system32;C:\\WINDOWS"}
ENV_MACHINE = ("temp", "tmp", "appdata", "localappdata", "userprofile", "username", "computername",
               "homepath", "userdomain", "homedrive", "logonserver", "date", "time")

_UNK = re.compile(r"\x01([^\x02]*)\x02")


def unk(why: str) -> str:
    return f"\x01{why}\x02"


def _split_top(line: str) -> list[tuple[str, str]]:
    """``a & b && c || d | e`` → [(cmd, separator-before)], outside quotes, parentheses and carets."""
    out: list[tuple[str, str]] = []
    buf: list[str] = []
    sep = ""
    q = False
    depth = 0
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == "^" and not q and i + 1 < n:
            buf.append(c + line[i + 1])
            i += 2
            continue
        if c == '"':
            q = not q
        elif not q:
            if c == "(":
                depth += 1
            elif c == ")" and depth:
                depth -= 1
            elif depth == 0 and c in "&|":
                two = line[i:i + 2]
                out.append(("".join(buf), sep))
                buf = []
                if two in ("&&", "||"):
                    sep = two
                    i += 2
                    continue
                sep = c
                i += 1
                continue
        buf.append(c)
        i += 1
    out.append(("".join(buf), sep))
    return [(c, s) for c, s in out if c.strip() or s]


def _strip_carets(s: str) -> str:
    out = []
    q = False
    i = 0
    while i < len(s):
        c = s[i]
        if c == '"':
            q = not q
        if c == "^" and not q and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _balance(s: str) -> int:
    d = 0
    q = False
    i = 0
    while i < len(s):
        c = s[i]
        if c == "^" and not q:
            i += 2
            continue
        if c == '"':
            q = not q
        elif not q:
            if c == "(":
                d += 1
            elif c == ")":
                d -= 1
        i += 1
    return d


class _Goto(Exception):
    def __init__(self, label: str) -> None:
        self.label = label


class _Exit(Exception):
    def __init__(self, b: bool) -> None:
        self.b = b


class Limit(Exception):
    pass


class Interp:
    def __init__(self, sinks: Sinks, source: str) -> None:
        self.sinks = sinks
        self.source = source
        self.env: dict[str, str] = dict(ENV)
        self.files: dict[str, dict[str, Any]] = {}
        self.steps = 0
        self.t0 = time.monotonic()
        self.errors: list[str] = []
        self.call_depth = 0
        self.ran: list[str] = []
        self.lines: list[tuple[int, str]] = []
        self.labels: dict[str, int] = {}

    # -- program -------------------------------------------------------------------------------
    def load(self, code: str) -> None:
        code = code.replace("\r\n", "\n").replace("\r", "\n")
        raw = code.split("\n")
        i = 0
        while i < len(raw):
            ln = i + 1
            text = raw[i]
            while text.endswith("^") and not text.endswith("^^") and i + 1 < len(raw):
                i += 1
                text = text[:-1] + raw[i]
            # a block: lines until the parentheses close
            if _balance(self._code_part(text)) > 0:
                parts = [text]
                bal = _balance(self._code_part(text))
                while bal > 0 and i + 1 < len(raw):
                    i += 1
                    parts.append(raw[i])
                    bal += _balance(self._code_part(raw[i]))
                text = "\n".join(parts)
            self.lines.append((ln, text))
            m = re.match(r"\s*:([^\s:+=;,]+)", text)
            if m and not text.lstrip().startswith("::"):
                self.labels.setdefault(m.group(1).lower(), len(self.lines) - 1)
            i += 1

    @staticmethod
    def _code_part(text: str) -> str:
        t = text.lstrip()
        if t.startswith("::") or re.match(r"(?i)@?rem(\s|$)", t):
            return ""
        return text

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise Limit("steps")
        if not self.steps & 0x3FF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise Limit("time")

    def run(self) -> None:
        self.run_from(0, [])
        self.finish()

    def run_from(self, pc: int, args: list[str]) -> None:
        visits: dict[int, int] = {}
        while 0 <= pc < len(self.lines):
            self.tick()
            ln, text = self.lines[pc]
            try:
                self.line(text, ln, args)
                pc += 1
            except _Goto as g:
                lab = g.label.lower().lstrip(":")
                if lab == "eof":
                    return
                if lab not in self.labels:
                    self.errors.append(f"line {ln}: goto to a missing label {g.label}")
                    return
                pc = self.labels[lab] + 1
                visits[pc] = visits.get(pc, 0) + 1
                if visits[pc] > 200:
                    return
            except _Exit as e:
                if e.b:
                    return
                raise

    # -- expansion ----------------------------------------------------------------------------------
    def expand(self, s: str, args: list[str], delayed: bool = False) -> str:
        if delayed:
            return re.sub(r"!([^!\r\n]+)!", lambda m: self._var(m.group(1), m.group(0), keep_unknown=False), s)

        # one left-to-right pass, as cmd.exe reads a line: %% → %, %0-%9 / %~f0 / %*, %var[:mod]%
        out: list[str] = []
        i = 0
        n = len(s)
        while i < n:
            c = s[i]
            if c != "%":
                out.append(c)
                i += 1
                continue
            if i + 1 < n and s[i + 1] == "%":
                out.append("%")
                i += 2
                continue
            m = re.match(r"%(~[a-z]*)?([0-9*])", s[i:])
            if m:
                out.append(self._arg(m.group(1) or "", m.group(2), args))
                i += m.end()
                continue
            j = s.find("%", i + 1)
            if j == -1 or "\n" in s[i:j]:
                out.append("%")
                i += 1
                continue
            out.append(self._var(s[i + 1:j], s[i:j + 1], keep_unknown=False))
            i = j + 1
        return "".join(out)

    def _arg(self, mods: str, d: str, args: list[str]) -> str:
        if d == "*":
            return " ".join(args)
        k = int(d)
        if k == 0:
            if "dp" in mods:
                return "C:\\Users\\Public\\"
            if "nx" in mods or mods == "~n":
                return "script.bat" if "x" in mods else "script"
            return SCRIPT_PATH
        v = args[k - 1] if k - 1 < len(args) else ""
        return v.strip('"') if mods else v

    def _var(self, spec: str, whole: str, keep_unknown: bool = True) -> str:
        m = re.match(r"([^:]+)(:.*)?$", spec)
        if not m:
            return whole
        name, mod = m.group(1), m.group(2) or ""
        low = name.lower()
        if low in self.env:
            val = self.env[low]
        elif low in ENV_MACHINE:
            if mod:
                return unk(f"a part of %{name.upper()}% on the victim's machine")
            return f"%{name.upper()}%"
        else:
            return whole if keep_unknown else ""
        if not mod:
            return val
        if mod.startswith(":~"):
            nums = [x.strip() for x in mod[2:].split(",")]
            try:
                start = int(nums[0])
                if start < 0:
                    start = max(0, len(val) + start)
                if len(nums) > 1 and nums[1] != "":
                    ln = int(nums[1])
                    return val[start:start + ln] if ln >= 0 else val[start:len(val) + ln]
                return val[start:]
            except ValueError:
                return whole
        if "=" in mod:
            find, _, repl = mod[1:].partition("=")
            if find.startswith("*") and len(find) > 1:
                j = val.lower().find(find[1:].lower())
                return repl + val[j + len(find) - 1:] if j >= 0 else val
            if find:
                return re.sub(re.escape(find), lambda _m: repl, val, flags=re.I)
        return val

    # -- one line ------------------------------------------------------------------------------------
    def line(self, text: str, ln: int, args: list[str]) -> None:
        t = text.strip()
        if not t or t.startswith("::") or t.startswith(":"):
            return
        t = t.lstrip("@").strip()
        if re.match(r"(?i)rem(\s|$)", t):
            return
        t = self.expand(t, args)
        self.commands(t, ln, args)

    def commands(self, t: str, ln: int, args: list[str]) -> None:
        parts = _split_top(t)
        i = 0
        last_ok = True
        while i < len(parts):
            cmd, sep = parts[i]
            if sep == "&&" and not last_ok:
                i += 1
                continue
            if sep == "||" and last_ok:
                i += 1
                continue
            # a pipe: what the left side prints goes to the right side's input
            if i + 1 < len(parts) and parts[i + 1][1] == "|":
                left_out = self.command(cmd, ln, args, capture=True)
                right = parts[i + 1][0]
                self.pipe(left_out, right, ln, args)
                i += 2
                continue
            r = self.command(cmd, ln, args)
            last_ok = r is not False
            i += 1

    def pipe(self, data: str | None, right: str, ln: int, args: list[str]) -> None:
        r = self.expand(_strip_carets(right.strip()), args, delayed=True)
        w = self._word(r)
        if data and w in ("powershell", "pwsh") and re.search(r"(?i)(?:^|\s)-(?:c(?:ommand)?\s+)?-(\s|$)|\s-\s*$|^\S+\s*$|-noni|-nop", r):
            self._ps_stage(data, (f"echo … | {w} -",), ln, "piped into powershell (stdin)")
            return
        if data and w in ("cmd",):
            for ln2 in data.splitlines():
                self.commands(self.expand(ln2, args), ln, args)
            return
        self.command(right, ln, args)

    @staticmethod
    def _word(cmd: str) -> str:
        m = re.match(r'\s*"?([^\s"]+)', cmd)
        if not m:
            return ""
        w = m.group(1).replace("/", "\\").rsplit("\\", 1)[-1].lower()
        return re.sub(r"\.(exe|com|bat|cmd)$", "", w)

    def command(self, cmd: str, ln: int, args: list[str], capture: bool = False) -> Any:  # noqa: C901, PLR0911, PLR0912
        self.tick()
        cmd = cmd.strip()
        if not cmd:
            return True
        cmd = cmd.lstrip("@").strip()
        # parenthesised group
        if cmd.startswith("(") and cmd.endswith(")"):
            out = []
            for sub in self._block_lines(cmd[1:-1]):
                r = self.command_line(sub, ln, args, capture)
                if capture and isinstance(r, str):
                    out.append(r)
            return "\r\n".join(out) if capture else True
        low = cmd.lower()
        if re.match(r"if\b", low):
            return self.if_(cmd[2:].strip(), ln, args, capture)
        if re.match(r"for\b", low):
            return self.for_(cmd, ln, args)
        # cmd /c "…": a line of its own (its !vars! expand as its own commands run)
        if self._word(_strip_carets(cmd)) == "cmd":
            m = re.search(r'(?is)\s/[ck]\s+(.*)$', cmd)
            if m:
                inner = m.group(1).strip()
                if len(inner) >= 2 and inner[0] == '"' and inner.endswith('"'):
                    inner = inner[1:-1]
                self.commands(inner, ln, args)
            return True
        # redirections
        cmd, out_path, append, in_path = self._redirects(cmd)
        out_path = self.expand(out_path, args, delayed=True) if out_path else ""
        in_path = self.expand(in_path, args, delayed=True) if in_path else ""
        cmd = self.expand(_strip_carets(cmd), args, delayed=True)
        w = self._word(cmd)
        rest = cmd.split(None, 1)[1] if len(cmd.split(None, 1)) > 1 else ""
        out: str | None = None
        if w in ("echo", "echo.", "echo:") or re.match(r"(?i)echo[.:(]", cmd):
            body = re.sub(r"(?i)^echo[.:(\s]?", "", cmd, count=1)
            if body.strip().lower() in ("on", "off") and not out_path:
                return True
            out = body.rstrip(" ") if out_path or capture else None
            if out is None:
                return True
        elif w == "set":
            self.set_(rest, ln, in_path)
            return True
        elif w in ("setlocal", "endlocal", "title", "color", "cls", "chcp", "pause", "timeout", "ping", "mode",
                   "prompt", "verify", "rem", "pushd", "popd", "cd", "chdir", "md", "mkdir", "attrib", "taskkill",
                   "tasklist", "choice", "shift", "ver", "vol", "netsh", "sc", "schtasks", "net", "whoami", "ipconfig",
                   "systeminfo", "tree", "dir", "label", "find", "findstr", "sort", "assoc", "ftype", "reg", "wmic"):
            if w in ("reg", "wmic", "schtasks", "sc", "net", "whoami", "systeminfo", "ipconfig", "find", "findstr"):
                self.sinks.step(ln, f"{w}", Value("str", cmd[:200]))
            if w == "reg" and " query" in cmd.lower():
                return unk(f"a registry query on the victim's machine ({cmd[:80]})") if capture else True
            return True
        elif w == "goto":
            raise _Goto(rest.strip().split()[0] if rest.strip() else "eof")
        elif w == "exit":
            raise _Exit("/b" in rest.lower())
        elif w == "call":
            r = rest.strip()
            if r.startswith(":"):
                lab = r.split()[0][1:].lower()
                if lab in self.labels and self.call_depth < MAX_CALL_DEPTH:
                    self.call_depth += 1
                    try:
                        self.run_from(self.labels[lab] + 1, self._args(r.split(None, 1)[1] if len(r.split(None, 1)) > 1 else ""))
                    finally:
                        self.call_depth -= 1
                return True
            # "call" expands the line once more (call set x=%%y%%)
            return self.command(self.expand(r, args), ln, args, capture)
        elif w in ("type", "more"):
            m = re.match(r"(?i)\s*(?:\+(\d+)\s+)?(.+)$", rest)
            skip = int(m.group(1)) if m and m.group(1) else 0
            path = m.group(2).strip().strip('"') if m else ""
            data = self.read(path)
            if data is None:
                return True
            out = "\n".join(data.replace("\r\n", "\n").split("\n")[skip:])
            rec = self._rec(path) + ((f"more +{skip}",) if skip else ())
            if out_path:
                self.store(out_path, out, append, rec, f"{w} {path}")
                return True
            return out if capture else True
        elif w == "copy" or w == "xcopy" or w == "move":
            self.copy(rest, w)
            return True
        elif w in ("del", "erase"):
            return True
        elif w == "ren" or w == "rename":
            p = re.findall(r'"[^"]+"|\S+', rest)
            if len(p) >= 2:
                src = self.files.pop(p[0].strip('"').lower(), None)
                if src is not None:
                    base = p[0].strip('"').rsplit("\\", 1)[0] + "\\" if "\\" in p[0] else ""
                    newp = base + p[1].strip('"')
                    src["path"] = newp
                    self.files[newp.lower()] = src
            return True
        elif w == "certutil":
            self.certutil(cmd, ln)
            return True
        elif w == "cmd":
            m = re.search(r'(?is)\s/[ck]\s+(.*)$', cmd)
            if m:
                inner = m.group(1).strip()
                if len(inner) >= 2 and inner[0] == '"' and inner[-1] == '"':
                    inner = inner[1:-1]
                if "/v" in cmd.lower()[:m.start()].lower():
                    pass
                self.commands(inner, ln, args)
            return True
        elif w == "start":
            r = re.sub(r'^\s*(?:"[^"]*"\s*)?', "", rest)
            r = re.sub(r"(?i)^(?:/(?:b|min|max|wait|high|low|normal|realtime|abovenormal|belownormal|separate|shared)\s+|/d\s+\S+\s+)+", "", r)
            return self.command(r, ln, args)
        elif w in ("wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec") or self._is_file_run(w, cmd):
            self.run_file(cmd, w, ln)
            return True
        else:
            if not self._launch(cmd, ln):
                self.run_file(cmd, w, ln, launch=False)
            return True
        if out is not None:
            if out_path:
                self.store(out_path, out, append, (), "echo")
                return True
            return out
        return True

    def command_line(self, sub: str, ln: int, args: list[str], capture: bool = False) -> Any:
        res: Any = True
        outs = []
        for one in self._block_lines(sub):
            for c, _sep in _split_top(one.strip()):
                r = self.command(c, ln, args, capture)
                if capture and isinstance(r, str):
                    outs.append(r)
                res = r
        return "\r\n".join(outs) if capture and outs else res

    @staticmethod
    def _block_lines(sub: str) -> list[str]:
        """The lines of a block, a nested ( … ) kept whole."""
        out: list[str] = []
        cur: list[str] = []
        bal = 0
        for line in sub.split("\n"):
            cur.append(line)
            bal += _balance(line)
            if bal <= 0:
                one = "\n".join(cur).strip()
                if one:
                    out.append(one)
                cur, bal = [], 0
        if cur and "\n".join(cur).strip():
            out.append("\n".join(cur).strip())
        return out

    def _is_file_run(self, w: str, cmd: str) -> bool:
        first = re.match(r'\s*"?([^"\s]+)', cmd)
        return bool(first and first.group(1).lower() in self.files)

    def _args(self, s: str) -> list[str]:
        return re.findall(r'"[^"]*"|\S+', s)

    def _redirects(self, cmd: str) -> tuple[str, str, bool, str]:
        out_path, append, in_path = "", False, ""
        # outside quotes: [n]>> file, [n]> file, < file
        pat = re.compile(r'(?<!\^)(\d?)(>>|>|<)\s*("[^"]*"|[^\s&|<>]+)')
        q = False
        res = []
        i = 0
        while i < len(cmd):
            c = cmd[i]
            if c == '"':
                q = not q
            if not q and c in "<>0123456789" and (c in "<>" or (i + 1 < len(cmd) and cmd[i + 1] in "<>")):
                m = pat.match(cmd, i)
                if m:
                    target = m.group(3).strip('"')
                    if m.group(2) == "<":
                        in_path = target
                    elif m.group(1) in ("", "1") and target.lower() not in ("nul", "&1", "&2"):
                        out_path, append = target, m.group(2) == ">>"
                    i = m.end()
                    continue
            res.append(c)
            i += 1
        return "".join(res).strip(), out_path, append, in_path

    # -- set --------------------------------------------------------------------------------------------
    def set_(self, rest: str, ln: int, in_path: str) -> None:
        r = rest.strip()
        m = re.match(r"(?i)/a\s+(.*)$", r)
        if m:
            self.set_a(m.group(1).strip().strip('"'))
            return
        m = re.match(r"(?i)/p\s+(.*)$", r)
        if m:
            name, _, _prompt = m.group(1).strip().strip('"').partition("=")
            if in_path:
                data = self.read(in_path)
                self.env[name.strip().lower()] = (data or "").replace("\r\n", "\n").split("\n")[0] if data is not None \
                    else unk(f"the first line of {in_path}")
            else:
                self.env[name.strip().lower()] = unk("what the user types")
            return
        if r.startswith('"'):
            end = r.rfind('"')
            r = r[1:end] if end > 0 else r[1:]
        if "=" not in r:
            return
        name, _, val = r.partition("=")
        name = name.strip().lower()
        if not name:
            return
        if val:
            self.env[name] = val
        else:
            self.env.pop(name, None)

    def set_a(self, expr: str) -> None:
        for part in expr.split(","):
            m = re.match(r"\s*([A-Za-z_][\w.$#@]*)\s*([-+*/%&|^]|<<|>>)?=(.*)$", part)
            if not m:
                continue
            name, op, rhs = m.group(1).lower(), m.group(2), m.group(3)
            v = self._arith(rhs)
            if v is None:
                continue
            if op:
                cur = self._arith(self.env.get(name, "0")) or 0
                v = {"+": cur + v, "-": cur - v, "*": cur * v, "/": int(cur / v) if v else 0, "%": cur % v if v else 0,
                     "&": cur & v, "|": cur | v, "^": cur ^ v, "<<": cur << v, ">>": cur >> v}[op]
            self.env[name] = str(v)

    def _arith(self, s: str) -> int | None:
        def var(m: re.Match) -> str:
            v = self.env.get(m.group(0).lower(), "0")
            return v if re.fullmatch(r"-?\d+", v.strip()) else "0"
        e = re.sub(r"(?<![0-9A-Fa-fxX])[A-Za-z_][\w.$#@]*", var, s)
        e = re.sub(r"\b0[xX]([0-9a-fA-F]+)\b", lambda m: str(int(m.group(1), 16)), e)
        e = re.sub(r"\b0([0-7]+)\b", lambda m: str(int(m.group(1), 8)), e)
        if not re.fullmatch(r"[\d\s+\-*/%()&|^<>~!]*", e):
            return None
        e = e.replace("/", "//")
        try:
            return int(eval(e, {"__builtins__": {}}, {}))  # noqa: S307  (digits and operators only, checked above)
        except Exception:  # noqa: BLE001
            return None

    # -- if / for ---------------------------------------------------------------------------------------
    def if_(self, rest: str, ln: int, args: list[str], capture: bool) -> Any:  # noqa: C901
        r = rest.strip()
        neg = False
        ci = False
        while True:
            m = re.match(r"(?i)(/i|not)\s+", r)
            if not m:
                break
            if m.group(1).lower() == "not":
                neg = not neg
            else:
                ci = True
            r = r[m.end():]
        cond: bool | None
        m = re.match(r"(?i)(exist|defined)\s+(\"[^\"]*\"|\S+)\s*", r)
        if m:
            what = m.group(2).strip('"')
            if m.group(1).lower() == "defined":
                cond = self.env.get(what.lower()) is not None
            else:
                cond = True if what.lower() in self.files else None
            body = r[m.end():]
        else:
            m = re.match(r"(?i)errorlevel\s+(\d+)\s*", r)
            if m:
                cond = int(m.group(1)) <= 0
                body = r[m.end():]
            else:
                m = re.match(r'(?i)("[^"]*"|[^\s=]+)\s*(==|\s(?:equ|neq|lss|leq|gtr|geq)\s)\s*("[^"]*"|\S+)\s*', r)
                if not m:
                    return True
                a, op, b = m.group(1), m.group(2).strip().lower(), m.group(3)
                a, b = self.expand(a, args, True), self.expand(b, args, True)
                if _UNK.search(a + b):
                    cond = None
                else:
                    if op == "==":
                        cond = (a.lower() == b.lower()) if ci else a == b
                    else:
                        x, y = a.strip('"'), b.strip('"')
                        try:
                            xi, yi = int(x), int(y)
                            cond = {"equ": xi == yi, "neq": xi != yi, "lss": xi < yi, "leq": xi <= yi,
                                    "gtr": xi > yi, "geq": xi >= yi}[op]
                        except ValueError:
                            cond = {"equ": x == y, "neq": x != y, "lss": x < y, "leq": x <= y, "gtr": x > y, "geq": x >= y}[op]
                body = r[m.end():]
        then, els = self._then_else(body)
        if cond is not None and neg:
            cond = not cond
        if cond is None:
            # depends on the machine: both ways
            for b in (then, els):
                if b:
                    try:
                        self.command_line(b, ln, args)
                    except _Exit:
                        pass
            return True
        b = then if cond else els
        if b:
            return self.command_line(b, ln, args, capture)
        return True

    @staticmethod
    def _then_else(body: str) -> tuple[str, str]:
        body = body.strip()
        if body.startswith("("):
            d = 0
            q = False
            for i, c in enumerate(body):
                if c == '"':
                    q = not q
                elif not q and c == "(":
                    d += 1
                elif not q and c == ")":
                    d -= 1
                    if d == 0:
                        then = body[1:i]
                        rest = body[i + 1:].strip()
                        m = re.match(r"(?i)else\s*(.*)$", rest, re.S)
                        els = m.group(1).strip() if m else ""
                        if els.startswith("(") and els.endswith(")"):
                            els = els[1:-1]
                        return then, els
            return body[1:], ""
        m = re.search(r"(?i)\s+else\s+", body)
        if m:
            return body[:m.start()], body[m.end():]
        return body, ""

    def for_(self, cmd: str, ln: int, args: list[str]) -> Any:  # noqa: C901
        m = re.match(r'(?is)for\s+(/[lfdr])?\s*(?:("[^"]*"|[^%\s]\S*)\s+)?%%?([A-Za-z])\s+in\s*\((.*?)\)\s*do\s+(.+)$', cmd)
        if not m:
            return True
        sw = (m.group(1) or "").lower()
        opts = (m.group(2) or "").strip('"')
        var = m.group(3)
        src = m.group(4).strip()
        body = m.group(5).strip()
        if body.startswith("(") and body.endswith(")"):
            body = body[1:-1]
        items: list[str] = []
        if sw == "/l":
            nums = [x for x in re.split(r"[,\s]+", src) if x]
            try:
                a, s, b = (int(x) for x in nums[:3])
            except ValueError:
                return True
            if s == 0:
                return True
            i = a
            while (i <= b) if s > 0 else (i >= b):
                items.append(str(i))
                i += s
                if len(items) > MAX_LOOP:
                    break
        elif sw == "/f":
            items = self._for_f(src, opts, var)
            if items is None:
                return True
        else:
            items = re.findall(r'"[^"]*"|[^\s,;=]+', src)
        vars_ = self._for_vars(opts, var) if sw == "/f" else [var]
        for it in items[:MAX_LOOP]:
            self.tick()
            line = body
            values = it if isinstance(it, list) else [it]
            for v, val in zip(vars_, values):
                line = re.sub(rf"%%~?{re.escape(v)}|%~?{re.escape(v)}(?![A-Za-z0-9])", lambda _m, val=val: val, line)
            for v in vars_[len(values):]:
                line = re.sub(rf"%%~?{re.escape(v)}", "", line)
            self.command_line(line, ln, args)
        return True

    @staticmethod
    def _for_vars(opts: str, var: str) -> list[str]:
        m = re.search(r"(?i)tokens=([\d,\-*]+)", opts)
        n = 1
        if m:
            spec = m.group(1)
            n = 0
            for part in spec.split(","):
                if "-" in part:
                    a, b = part.split("-")
                    n += int(b) - int(a) + 1
                elif part == "*":
                    n += 1
                elif part:
                    n += 1
            if spec.endswith("*") and not spec.endswith(",*"):
                n += 1
        return [chr(ord(var) + i) for i in range(max(1, n))]

    def _for_f(self, src: str, opts: str, var: str) -> list | None:
        if src.startswith("'") or src.startswith("`"):
            # a command's output: only the machine knows it
            self.env_for_unknown = True
            return [[unk(f"the output of {src.strip(chr(39) + '`')[:80]}")] * 8]
        if src.startswith('"'):
            text = src.strip('"')
        else:
            data = self.read(src.strip('"'))
            if data is None:
                return [[unk(f"the content of {src}")] * 8]
            text = data
        dm = re.search(r"(?i)delims=([^\"]*?)(?:\s+\w+=|$)", opts)
        delims = dm.group(1) if dm else " \t"
        tm = re.search(r"(?i)tokens=([\d,\-*]+)", opts)
        skip = re.search(r"(?i)skip=(\d+)", opts)
        lines = text.replace("\r\n", "\n").split("\n")[int(skip.group(1)) if skip else 0:]
        out = []
        for line in lines:
            if not line.strip():
                continue
            toks = [t for t in (re.split("[" + re.escape(delims) + "]+", line) if delims else [line]) if t != ""]
            if tm:
                want: list[int] = []
                rest = False
                for part in tm.group(1).split(","):
                    if "-" in part:
                        a, b = part.split("-")
                        want += list(range(int(a), int(b) + 1))
                    elif part == "*":
                        rest = True
                    elif part:
                        want.append(int(part))
                vals = [toks[i - 1] if i - 1 < len(toks) else "" for i in want]
                if rest or tm.group(1).endswith("*"):
                    vals.append(" ".join(toks[max(want or [0]):]))
                out.append(vals)
            else:
                out.append([toks[0] if toks else ""])
        return out

    # -- files ---------------------------------------------------------------------------------------------
    def norm(self, path: str) -> str:
        return path.strip().strip('"').lower()

    def read(self, path: str) -> str | None:
        p = self.norm(path)
        if p in (SCRIPT_PATH.lower(), "script.bat") or p.endswith("\\script.bat"):
            return self.source
        f = self.files.get(p)
        if f is None:
            return None
        d = f["data"]
        return d if isinstance(d, str) else d.decode("latin-1")

    def _rec(self, path: str) -> tuple[str, ...]:
        p = self.norm(path)
        if p in (SCRIPT_PATH.lower(), "script.bat"):
            return ("the script's own file",)
        f = self.files.get(p)
        return tuple(f["recipe"]) if f else ()

    def store(self, path: str, data: str | bytes, append: bool, recipe: tuple[str, ...], how: str) -> None:
        p = self.norm(path)
        f = self.files.get(p)
        if f is None or not append:
            f = self.files[p] = {"path": path.strip().strip('"'), "data": "" if isinstance(data, str) else b"",
                                 "recipe": recipe or (how,), "lines": 0}
        if isinstance(data, bytes):
            f["data"] = (f["data"].encode("latin-1") if isinstance(f["data"], str) else f["data"]) + data
        else:
            cur = f["data"]
            add = data + "\r\n"
            f["data"] = (cur + add) if isinstance(cur, str) else cur + add.encode("latin-1", "replace")
        f["lines"] += 1
        if len(f["data"]) > MAX_FILE:
            raise Limit("file size")
        if f["lines"] > 1 and recipe == () and how == "echo":
            f["recipe"] = (f"echo lines >> {f['path'].rsplit(chr(92), 1)[-1]}",)

    def copy(self, rest: str, w: str) -> None:
        r = re.sub(r"(?i)(^|\s)/[a-z](?=\s|$)", " ", rest)
        p = re.findall(r'"[^"]+"|[^\s"]+', r)
        if len(p) < 2:
            return
        srcs = [s.strip('"') for s in "".join(p[:-1]).split("+")] if "+" in "".join(p[:-1]) else [p[0].strip('"')]
        dst = p[-1].strip('"')
        datas = [self.read(s) for s in srcs]
        if any(d is None for d in datas):
            return
        data = "".join(datas)                   # type: ignore[arg-type]
        recipe = self._rec(srcs[0]) + ((f"copy /b {'+'.join(srcs)}",) if len(srcs) > 1 else ())
        self.files[self.norm(dst)] = {"path": dst, "data": data, "recipe": recipe, "lines": 1}
        if w == "move":
            for s in srcs:
                self.files.pop(self.norm(s), None)

    def certutil(self, cmd: str, ln: int) -> None:
        low = cmd.lower()
        if "-urlcache" in low or "/urlcache" in low or "-verifyctl" in low:
            commands.launch(self.sinks, cmd, (), ln, "certutil")
            return
        m = re.search(r'(?i)[-/](decode|decodehex)\s+(?:-f\s+)?("[^"]+"|\S+)\s+("[^"]+"|\S+)', cmd)
        if not m:
            return
        src, dst = m.group(2).strip('"'), m.group(3).strip('"')
        data = self.read(src)
        if data is None:
            self.sinks.step(ln, "certutil decodes a file not in the script", Value("str", src))
            return
        try:
            if m.group(1).lower() == "decode":
                body = re.search(r"-----BEGIN[^-]*-----(.*?)-----END[^-]*-----", data, re.S)
                text = body.group(1) if body else data
                out = T.b64decode(text)
                how = "base64 (certutil -decode)"
            else:
                hexs = re.sub(r"(?m)^[0-9a-fA-F]{4,8}\s", "", data)
                out = T.hexdecode(re.sub(r"[^0-9a-fA-F]", "", hexs))
                how = "hex (certutil -decodehex)"
        except T.TransformError as exc:
            self.errors.append(f"line {ln}: certutil: {exc}")
            return
        self.files[self.norm(dst)] = {"path": dst, "data": out, "recipe": self._rec(src) + (how,), "lines": 1}

    # -- launching ---------------------------------------------------------------------------------------------
    def _launch(self, cmd: str, ln: int) -> bool:
        u = _UNK.search(cmd)
        if u:
            self.sinks.unresolved_(cmd.replace("\x01", "<").replace("\x02", ">")[:300], u.group(1),
                                   "the command it runs is built from something not in the script", ln)
            return True
        if commands.launch(self.sinks, cmd, ("batch line",), ln, "batch"):
            return True
        # a file it downloaded before, run now
        for d in self.sinks.downloads:
            dest = (d.get("saved_to") or "").lower()
            if dest and dest in cmd.lower() and "runs it" not in d["use"]:
                d["use"] += f", then runs it ({cmd.strip()[:80]})"
                return True
        return False

    def _ps_stage(self, code: str, recipe: tuple[str, ...], ln: int, sink: str) -> None:
        n = len(self.sinks.stages)
        self.sinks.exec_(Value("str", code, recipe), sink, ln)
        if len(self.sinks.stages) > n:
            self.sinks.stages[-1].ext = ".ps1"

    def run_file(self, cmd: str, w: str, ln: int, launch: bool = True) -> None:
        """``wscript x.vbs`` / ``start x.exe`` / ``x.bat``: a file the script wrote is run."""
        if w in ("mshta", "rundll32", "regsvr32", "msiexec") and self._launch(cmd, ln):
            return
        for p, f in self.files.items():
            name = p.rsplit("\\", 1)[-1]
            if p in cmd.lower() or (name and re.search(rf"(?i)(^|[\s\\\"]){re.escape(name)}($|[\s\"])", cmd)):
                f["run"] = cmd.strip()[:200]
                self.sinks.step(ln, f"runs {f['path']}", Value("str", cmd[:200]))
                return
        if launch:
            self._launch(cmd, ln)
        else:
            self.sinks.step(ln, self._word(cmd) or "command", Value("str", cmd[:300]))

    def finish(self) -> None:
        """What the script wrote: its files, with their recipe (a script it then runs says so)."""
        for f in self.files.values():
            d = f["data"]
            if not d or (isinstance(d, str) and len(d.strip()) < 16 and not f.get("run")):
                continue
            sink = "writes" + (f" and runs ({f['run'][:80]})" if f.get("run") else "")
            v = Value("str", d, tuple(f["recipe"])) if isinstance(d, str) else Value("bytes", d, tuple(f["recipe"]))
            self.sinks.write(v, f["path"], sink, None)


def resolve(code: str, location: str = "batch") -> Sinks:
    """Evaluate a batch script statically; what it writes and launches, downloads and unresolved calls."""
    s = Sinks("batch")
    it = Interp(s, code.lstrip("\ufeff"))
    try:
        it.load(code.lstrip("\ufeff"))
        it.run()
    except (Limit, _Exit):
        it.finish()
    except RecursionError:
        it.errors.append("recursion")
    s.errors = it.errors  # type: ignore[attr-defined]
    s.stats = {"steps": it.steps, "seconds": round(time.monotonic() - it.t0, 2)}  # type: ignore[attr-defined]
    return s
