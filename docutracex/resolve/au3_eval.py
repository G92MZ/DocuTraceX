"""AutoIt, evaluated statically: the script run top to bottom on :mod:`..parsers.au3eval`'s evaluator.

``au3eval`` decrypts the strings a script hides behind its own decoder functions. Here the same
parser and evaluator run the script's **top-level code** too, with the calls that matter caught:

- ``Execute`` — the code it evaluates is a stage;
- ``Run`` / ``RunWait`` / ``ShellExecute(Wait)`` — commands followed by :mod:`.commands`;
- ``InetGet`` / ``InetRead`` / ``HttpGet`` — downloads (``InetGet`` saves to a path);
- ``FileWrite`` / ``FileWriteLine`` (with ``FileOpen``) — written files;
- ``DllStructSetData`` of binary data into a buffer (``VirtualAlloc`` / ``DllStructCreate``) and
  ``DllCall`` of ``CallWindowProc`` / ``CreateThread`` — the bytes are loaded (a shellcode runner);
- ``_Crypt_DecryptData`` (``CryptDeriveKey`` from the MD5 of the password, RC4 / AES / 3DES / DES)
  and ``BinaryToString`` / ``StringReverse`` / ``_Base64Decode``.

The recipe of each stage is read from the expression that built it (``$x = BinaryToString(…)`` →
``BinaryToString``), following the variables back to their literal. A value read from the victim's
machine (``RegRead``, ``EnvGet``, ``FileRead``, a macro like ``@ComputerName``) makes the call a
dynamic call not resolved. Nothing runs.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from ..parsers import au3eval as A
from . import commands
from . import transforms as T
from .sinks import Sinks
from .value import Value

MAX_STEPS = 3_000_000
MAX_SECONDS = 30.0

_CONSTS = {"calg_rc4": 0x6801, "calg_aes_128": 0x660E, "calg_aes_192": 0x660F, "calg_aes_256": 0x6610,
           "calg_3des": 0x6603, "calg_des": 0x6601, "calg_md5": 0x8003, "calg_sha1": 0x8004,
           "calg_userkey": 0, "mem_commit": 0x1000, "mem_reserve": 0x2000, "page_execute_readwrite": 0x40,
           "sw_hide": 0, "sw_show": 5, "fo_overwrite": 2, "fo_append": 1, "fo_binary": 16, "fo_read": 0,
           "inet_forcereload": 1, "stdout_child": 2, "stderr_child": 4}
_MACHINE = {"regread": "a registry value", "envget": "an environment variable", "fileread": "a file on the victim's machine",
            "filereadline": "a file on the victim's machine", "iniread": "an INI file on the victim's machine",
            "clipget": "the clipboard", "inputbox": "what the user types", "stdoutread": "a command's output",
            "inetread": "downloaded content", "ttcpreccv": "the network", "tcprecv": "the network",
            "drivegetserial": "the victim's disk serial", "random": "a random number"}
_MACROS_MACHINE = {"computername", "username", "ipaddress1", "logondomain", "osbuild", "cpuarch"}
_MACRO_PATHS = {"tempdir": "%TEMP%", "appdatadir": "%APPDATA%", "localappdatadir": "%LOCALAPPDATA%",
                "userprofiledir": "%USERPROFILE%", "windowsdir": "C:\\WINDOWS", "systemdir": "C:\\WINDOWS\\system32",
                "homedrive": "C:", "programfilesdir": "C:\\Program Files", "startupdir": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                "scriptdir": "C:\\Users\\Public", "desktopdir": "%USERPROFILE%\\Desktop", "mydocumentsdir": "%USERPROFILE%\\Documents"}
_DATA_ARG = {"filewrite": 1, "filewriteline": 1, "dllstructsetdata": 2, "_crypt_decryptdata": 0}
_STEP_NAMES = {"binarytostring": "BinaryToString", "stringreverse": "reverse", "_base64decode": "base64",
               "_crypt_decryptdata": "decrypt", "stringreplace": "replace", "stringtobinary": "StringToBinary",
               "_winapi_base64decode": "base64", "binary": "Binary", "stringfromasciiarray": "char codes",
               "_hextostring": "hex", "_stringtohex": "hex encode"}


class _Mem:
    """A buffer from VirtualAlloc / DllStructCreate."""

    def __init__(self, alloc: bool = False) -> None:
        self.alloc = alloc
        self.data = b""


class _File:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data: Any = ""
        self.recipe: tuple = ()


def _derive(password: bytes, alg: int) -> tuple[str, bytes, int]:
    """CryptDeriveKey(MD5(password)) the way AutoIt's ``_Crypt_DeriveKey`` calls it."""
    h = hashlib.md5(password).digest()  # noqa: S324  (the format's own KDF)
    base, klen, block = {0x6801: ("rc4", 16, 1), 0x660E: ("aes", 16, 16), 0x660F: ("aes", 24, 16),
                         0x6610: ("aes", 32, 16), 0x6603: ("3des", 24, 8), 0x6601: ("des", 8, 8)}.get(alg, ("rc4", 16, 1))
    if klen <= len(h):
        return base, h[:klen], block
    b1 = bytes(x ^ 0x36 for x in h.ljust(64, b"\x00"))
    b2 = bytes(x ^ 0x5C for x in h.ljust(64, b"\x00"))
    key = (hashlib.md5(b1).digest() + hashlib.md5(b2).digest())[:klen]  # noqa: S324
    return base, key, block


class Top(A._Run):  # noqa: SLF001
    def __init__(self, funcs: dict, sinks: Sinks, source: str) -> None:
        super().__init__(funcs)
        self.sinks = sinks
        self.source = source
        self.defs: dict[str, tuple] = {}
        self.env: dict[str, Any] = dict(_CONSTS)
        self.files: list[_File] = []
        self.mems: list[_Mem] = []
        self.loaded: set[bytes] = set()
        self.line = 0
        self.t0 = time.monotonic()
        self.total = 0
        self.errors: list[str] = []
        self.depth = 0

    def tick(self) -> None:
        self.total += 1
        if self.total > MAX_STEPS:
            raise A.Unsupported("step budget")
        if not self.total & 0x3FFF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise A.Unsupported("time budget")

    # -- recipes --------------------------------------------------------------------------------------
    def recipe(self, e: tuple, seen: frozenset = frozenset()) -> tuple[str, ...]:
        op = e[0]
        if op == "var":
            name = e[1]
            if name in seen or name not in self.defs:
                return (f"variable ${name}",) if name not in self.defs else ()
            src = self.recipe(self.defs[name], seen | {name})
            return src or (f"literal ${name}",)
        if op == "lit":
            return ()
        if op == "call":
            inner: tuple = ()
            for a in e[2][:1]:
                inner = self.recipe(a, seen)
            if not inner and len(e[2]) > 1:
                inner = self.recipe(e[2][0], seen)
            name = _STEP_NAMES.get(e[1])
            if e[1] == "_crypt_decryptdata":
                name = "decrypt (CryptDeriveKey)"
            if e[1] in self.funcs and not name:
                name = f"{e[1]}()"
            return inner + ((name,) if name else ())
        if op == "&":
            a, b = self.recipe(e[1], seen), self.recipe(e[2], seen)
            return a or b
        if op == "idx":
            return self.recipe(e[1], seen)
        return ()

    def why(self, e: tuple, seen: frozenset = frozenset()) -> str:
        """What an expression depends on, when that is the victim's machine."""
        op = e[0]
        if op == "call" and e[1] in _MACHINE:
            arg = ""
            if e[2] and e[2][0][0] == "lit":
                arg = f" {e[2][0][1]}"
            return _MACHINE[e[1]] + arg
        if op == "mac" and e[1] in _MACROS_MACHINE:
            return f"@{e[1]} on the victim's machine"
        if op == "var" and e[1] in self.defs and e[1] not in seen:
            return self.why(self.defs[e[1]], seen | {e[1]})
        for x in e[1:]:
            if isinstance(x, tuple) and x and isinstance(x[0], str):
                w = self.why(x, seen)
                if w:
                    return w
            elif isinstance(x, list):
                for y in x:
                    if isinstance(y, tuple):
                        w = self.why(y, seen)
                        if w:
                            return w
        return ""

    def eval(self, e: tuple, env: dict[str, Any]) -> Any:
        if e[0] == "mac" and e[1] in _MACRO_PATHS:
            return _MACRO_PATHS[e[1]]
        return super().eval(e, env)

    # -- the calls that matter -------------------------------------------------------------------------
    def call(self, name: str, args: list[Any]) -> Any:  # noqa: C901, PLR0911, PLR0912
        line = self.line
        if name == "execute":
            src = A._strv(args[0]) if args else ""  # noqa: SLF001
            if self.depth == 0 and src.strip():
                self.sinks.exec_(Value("str", src, self.cur_recipe), "Execute", line)
            try:
                self.depth += 1
                return self.eval(A._expr(src), self.env)  # noqa: SLF001
            except A.Unsupported:
                return ""
            finally:
                self.depth -= 1
        if name in ("run", "runwait", "shellexecute", "shellexecutewait"):
            parts = [A._strv(a) for a in args[:2] if A._strv(a)]  # noqa: SLF001
            cmd = " ".join(parts)
            if not commands.launch(self.sinks, cmd, self.cur_recipe, line, name):
                for d in self.sinks.downloads:
                    dest = (d.get("saved_to") or "").lower()
                    if dest and dest in cmd.lower() and "runs it" not in d["use"]:
                        d["use"] += f", then runs it ({name})"
                if len(cmd) > 100:
                    n = len(self.sinks.stages)
                    self.sinks.exec_(Value("str", cmd, self.cur_recipe), name, line)
                    if len(self.sinks.stages) > n:
                        self.sinks.stages[-1].ext = ".bat"
            return 1
        if name in ("inetget", "inetread", "_inetgetsource", "httpget", "_httprequest"):
            url = A._strv(args[0]) if args else ""  # noqa: SLF001
            dest = A._strv(args[1]) if name == "inetget" and len(args) > 1 else ""  # noqa: SLF001
            self.sinks.download(Value("str", url, self.cur_recipe), name, "saves it" if dest else "returns it to the script", line, dest)
            if name == "inetget":
                return 1
            raise A.Unsupported(f"downloaded:{url}")
        if name == "fileopen":
            f = _File(A._strv(args[0]) if args else "")  # noqa: SLF001
            self.files.append(f)
            return f
        if name in ("filewrite", "filewriteline"):
            target = args[0] if args else ""
            data = args[1] if len(args) > 1 else ""
            if not isinstance(target, _File):
                target = _File(A._strv(target))  # noqa: SLF001
                self.files.append(target)
            if isinstance(data, bytes):
                target.data = (target.data.encode("latin-1") if isinstance(target.data, str) else target.data) + data
            else:
                target.data = (target.data if isinstance(target.data, str) else target.data.decode("latin-1")) + A._strv(data) + ("\r\n" if name == "filewriteline" else "")  # noqa: SLF001
            target.recipe = target.recipe or self.cur_recipe
            return 1
        if name == "fileclose":
            return 1
        if name == "dllcall":
            fn = " ".join(A._strv(a).lower() for a in args[:3] if isinstance(a, str))  # noqa: SLF001
            if "virtualalloc" in fn:
                m = _Mem(alloc=True)
                self.mems.append(m)
                return [m, 0, 0, 0, 0]
            if any(x in fn for x in ("callwindowproc", "createthread", "enumwindows", "enumsystem", "createtimerqueue")):
                for m in self.mems:
                    if m.data and m.data not in self.loaded:
                        self.loaded.add(m.data)
                        self.sinks.load(Value("bytes", m.data, self.mem_recipe), f"DllCall {fn.split()[-1] if fn else ''}", line=line)
            if any(x in fn for x in ("rtlmovememory", "writeprocessmemory")):
                for a in args:
                    if isinstance(a, bytes) and len(a) >= 64 and a not in self.loaded:
                        self.loaded.add(a)
                        self.sinks.load(Value("bytes", a, self.cur_recipe), "DllCall RtlMoveMemory", line=line)
            return [0] * max(1, len(args) // 2)
        if name == "dllstructcreate":
            m = _Mem()
            for a in args[1:2]:
                if isinstance(a, list) and a and isinstance(a[0], _Mem):
                    m = a[0]
                elif isinstance(a, _Mem):
                    m = a
            self.mems.append(m)
            return m
        if name == "dllstructsetdata":
            m = args[0] if args else None
            data = args[2] if len(args) > 2 else (args[1] if len(args) > 1 else b"")
            if isinstance(m, _Mem) and isinstance(data, (bytes, str)):
                b = data if isinstance(data, bytes) else A._bin(data)  # noqa: SLF001
                if isinstance(data, bytes) or len(b) >= 64:
                    m.data = b
                    self.mem_recipe = self.cur_recipe
                    if len(b) >= 64 and T.magic(b) and b not in self.loaded:
                        self.loaded.add(b)
                        self.sinks.load(Value("bytes", b, self.cur_recipe), "DllStructSetData", line=line)
            return 1
        if name in ("dllstructgetptr",):
            return args[0] if args else 0
        if name == "_crypt_decryptdata":
            data = args[0] if args else b""
            key = args[1] if len(args) > 1 else ""
            alg = int(A._numv(args[2])) if len(args) > 2 else 0x6801  # noqa: SLF001
            b = A._bin(data) if not isinstance(data, bytes) else data  # noqa: SLF001
            pw = key if isinstance(key, bytes) else A._strv(key).encode("latin-1", "replace")  # noqa: SLF001
            base, k, _block = _derive(pw, alg)
            try:
                out = T.rc4(b, k) if base == "rc4" else T.decrypt(base, b, k, b"\x00" * _block, "cbc")
            except T.TransformError as exc:
                raise A.Unsupported(f"decrypt: {exc}") from exc
            return out
        if name in ("_crypt_startup", "_crypt_shutdown", "_crypt_destroykey"):
            return 1
        if name in ("_base64decode", "_winapi_base64decode"):
            try:
                return T.b64decode(A._strv(args[0]))  # noqa: SLF001
            except (T.TransformError, IndexError) as exc:
                raise A.Unsupported("base64") from exc
        if name == "_hextostring":
            return T.hexdecode(A._strv(args[0])).decode("latin-1")  # noqa: SLF001
        if name in _MACHINE and name not in ("random",):
            raise A.Unsupported(f"machine:{_MACHINE[name]}")
        if name == "tcpconnect":
            host, port = (A._strv(args[0]) if args else ""), (A._strv(args[1]) if len(args) > 1 else "")  # noqa: SLF001
            self.sinks.download(Value("str", f"tcp://{host}:{port}"), "TCPConnect", "connects to it (C2)", line)
            return 1
        if name in ("tcpstartup", "tcpsend", "processclose", "filedelete", "filecopy", "filemove", "dircreate",
                    "regwrite", "filesetattrib", "filecreateshortcut", "sleep", "msgbox", "tooltip", "traytip"):
            return 1
        if name in self.funcs and self.funcs[name][2] is None:
            return super().call(name, args)
        if name in A._PURE:  # noqa: SLF001
            return super().call(name, args)
        raise A.Unsupported(f"function {name}")

    # -- the top level --------------------------------------------------------------------------------
    def run_top(self, body: list, lines_of: list[int]) -> None:
        for k, st in enumerate(body):
            self.line = lines_of[k] if k < len(lines_of) else 0
            if st == ("bad", "Exit"):
                break                                    # Exit at the top level: nothing below runs
            try:
                self.top_stmt(st)
            except A._Exit:  # noqa: SLF001
                break
            except A.Unsupported as exc:
                self.unsupported(st, str(exc))
            except RecursionError:
                self.errors.append(f"line {self.line}: recursion")

    def top_stmt(self, st: tuple) -> None:
        kind = st[0]
        self.cur_recipe = ()
        if kind == "assign":
            for target, _op, ex in st[1]:
                if target[0] == "var":
                    self.defs[target[1]] = ex
            self.cur_recipe = self.recipe(st[1][-1][2])
            self.watch(st, lambda: self.exec([st], self.env))
            return
        if kind == "decl":
            for name, _dims, init in st[1]:
                if init is not None:
                    self.defs[name] = init
            self.watch(st, lambda: self.exec([st], self.env))
            return
        if kind == "expr":
            e = st[1]
            if e[0] == "call" and e[2]:
                k = _DATA_ARG.get(e[1], 0)
                arg = e[2][k] if k < len(e[2]) else e[2][0]
                self.cur_recipe = self.recipe(arg)
                w = self.why(arg) if e[1] in ("execute", "run", "runwait", "shellexecute", "shellexecutewait", "inetget",
                                              "dllcall", "filewrite") else ""
                if w:
                    self.sinks.unresolved_(self.text(), w, f"what {e[1]} gets is read at run time", self.line)
                    return
            self.exec([st], self.env)
            return
        if kind in ("if", "for", "forin", "while", "do", "switch"):
            self.exec([st], self.env)
            return
        if kind == "bad":
            self.errors.append(f"line {self.line}: not parsed: {st[1]}")
            return
        self.exec([st], self.env)

    def watch(self, st: tuple, fn: Any) -> None:
        try:
            fn()
        except A.Unsupported as exc:
            self.unsupported(st, str(exc))

    def unsupported(self, st: tuple, why: str) -> None:
        expr = self.sink_expr(st)
        if expr is None:
            return
        name, arg = expr
        w = self.why(arg) if arg is not None else ""
        if why.startswith("downloaded:"):
            url = why[len("downloaded:"):]
            for d in self.sinks.downloads:
                if d["url"] == url and name in ("execute",):
                    d["use"] = "runs it as code (Execute)"
            return
        if w:
            self.sinks.unresolved_(self.text(), w, f"what {name} gets is read at run time", self.line)

    def sink_expr(self, st: tuple) -> tuple[str, Any] | None:
        def find(e: Any) -> tuple[str, Any] | None:
            if isinstance(e, tuple) and e:
                if e[0] == "call" and e[1] in ("execute", "run", "runwait", "shellexecute", "dllcall", "inetget",
                                               "filewrite", "shellexecutewait"):
                    return e[1], (e[2][0] if e[2] else None)
                for x in e[1:]:
                    r = find(x)
                    if r:
                        return r
            elif isinstance(e, list):
                for x in e:
                    r = find(x)
                    if r:
                        return r
            return None
        return find(st)

    def text(self) -> str:
        lines = self.source.splitlines()
        return lines[self.line - 1].strip()[:200] if 0 < self.line <= len(lines) else ""

    def finish(self) -> None:
        for f in self.files:
            d = f.data
            if not d:
                continue
            b = d if isinstance(d, bytes) else d.encode("utf-8", "replace")
            self.sinks.write(Value("bytes", b, f.recipe), f.path, "FileWrite", None)
        for name, v in list(self.env.items()):
            if isinstance(v, bytes) and len(v) >= 64 and T.magic(v) and v not in self.loaded:
                r = self.recipe(self.defs[name]) if name in self.defs else ()
                if r:
                    self.loaded.add(v)
                    self.sinks.load(Value("bytes", v, r), f"value of ${name} (computed, not run here)")


def resolve(code: str, location: str = "autoit") -> Sinks:
    s = Sinks("autoit")
    t0 = time.monotonic()
    errors: list[str] = []
    try:
        funcs = A.parse_functions(code)
        raw = code.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        # top-level lines (Func … EndFunc removed), with their original line numbers
        top: list[str] = []
        nums: list[int] = []
        infunc = False
        buf, start = "", 0
        skip = False
        for k, line in enumerate(raw, 1):
            st = line.strip()
            low = st.lower()
            if low.startswith(("#cs", "#comments-start")):
                skip = True
                continue
            if low.startswith(("#ce", "#comments-end")):
                skip = False
                continue
            if skip or (st.startswith("#") and not buf):
                continue
            if re.match(r"(?i)^func\s+\w+", st):
                infunc = True
                continue
            if infunc:
                if low == "endfunc":
                    infunc = False
                continue
            if st.startswith(";") or not st:
                continue
            if st.endswith(" _"):
                if not buf:
                    start = k
                buf += st[:-1] + " "
                continue
            top.append(buf + st)
            nums.append(start if buf else k)
            buf = ""
        it = Top(funcs, s, code)
        # one statement per top-level line keeps line numbers (blocks span several)
        body: list = []
        body_lines: list[int] = []
        i = 0
        while i < len(top):
            try:
                sub, j, _ = A._block(top, i, ())  # noqa: SLF001
                body.extend(sub)
                body_lines.extend(nums[i:i + len(sub)] + [nums[-1]] * max(0, len(sub) - len(nums[i:i + len(sub)])))
                break
            except A.Unsupported as exc:
                errors.append(f"line {nums[i] if i < len(nums) else '?'}: {exc}")
                i += 1
        lines_of = _lines_of_statements(top, nums)
        it.run_top(body, lines_of if len(lines_of) == len(body) else body_lines)
        it.finish()
        errors.extend(it.errors)
        steps = it.total
    except (A.Unsupported, RecursionError) as exc:
        errors.append(str(exc))
        steps = 0
    s.errors = errors  # type: ignore[attr-defined]
    s.stats = {"steps": steps, "seconds": round(time.monotonic() - t0, 2)}  # type: ignore[attr-defined]
    return s


def _lines_of_statements(top: list[str], nums: list[int]) -> list[int]:
    """The line of each top-level statement (a block counts once, at its first line)."""
    out = []
    depth = 0
    opens = re.compile(r"(?i)^(if\b(?!.*\bthen\s+\S)|for\b|while\b|do\b|switch\b|select\b)")
    closes = re.compile(r"(?i)^(endif|next|wend|until|endswitch|endselect)\b")
    for k, line in enumerate(top):
        st = line.strip()
        if depth == 0:
            out.append(nums[k])
        if opens.match(st):
            depth += 1
        elif closes.match(st):
            depth = max(0, depth - 1)
    return out
