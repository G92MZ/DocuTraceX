"""JavaScript / JScript, evaluated statically: what a dropper computes, without running it.

The script is parsed with ``esprima`` (a JavaScript parser in pure Python) and walked by a small
interpreter — no JavaScript engine runs it. It follows variables and closures, the script's
functions (declarations, expressions, arrows, ``call`` / ``apply`` / ``bind``), arrays and objects,
loops and conditions, ``try`` / ``catch`` and the string and array methods obfuscators use, and the
calls droppers make, mapped to the shared operations (:mod:`.transforms`):

- browsers: ``atob`` / ``btoa``, ``unescape``, ``decodeURIComponent``, ``String.fromCharCode``,
  ``Uint8Array`` / ``TextDecoder``, ``fetch`` / ``XMLHttpRequest``, ``document.write``,
  ``location``, ``setTimeout(code)``;
- Windows Script Host: ``ActiveXObject`` / ``WScript.CreateObject`` — ``WScript.Shell`` (``Run``,
  ``Exec``, ``ExpandEnvironmentStrings``, ``RegRead``), ``Scripting.FileSystemObject``,
  ``ADODB.Stream``, MSXML ``bin.base64`` / ``bin.hex`` elements, ``MSXML2.XMLHTTP`` /
  ``WinHttpRequest``, ``Shell.Application.ShellExecute``;
- libraries: CryptoJS (AES with a passphrase or a key + IV, DES, TripleDES, RC4, encoders, hashes),
  pako (``inflate`` / ``ungzip``), Node (``Buffer``, ``zlib``, ``crypto.createDecipheriv``,
  ``child_process``, ``fs``, ``http(s).get``).

What reaches ``eval`` / ``Function`` / ``setTimeout`` runs next (it is evaluated here too, a later
stage); ``document.write`` writes HTML (a stage); bytes saved with ``ADODB.Stream`` /
``FileSystemObject`` / ``fs`` are written files; commands are followed by :mod:`.commands`
(``powershell -enc`` → a ``.ps1`` stage). Downloads are reported, never fetched. Names computed at
run time (``window['ev'+'al']``, ``[]['constructor']['constructor']``, ``this[x]``) are resolved;
one that depends on the victim's machine is a dynamic call not resolved.

Bounded: steps, time, loop iterations, call depth and inline nesting.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
import urllib.parse
from typing import Any, Callable

from . import commands
from . import transforms as T
from .sinks import Sinks
from .value import Value

MAX_STEPS = 8_000_000
MAX_SECONDS = 30.0
MAX_LOOP = 3_000_000
LOOP_STEPS = 1_500_000       # one loop's share: a longer one (a busy loop) is left to an emulator
MAX_DEPTH = 12
MAX_CALL_DEPTH = 80
MAX_STR = 64 * 1024 * 1024


# --- values ------------------------------------------------------------------------------------
class _Undef:
    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False


UNDEF = _Undef()


class JSStr(str):
    recipe: tuple[str, ...] = ()


class JSArr(list):
    recipe: tuple[str, ...] = ()


class JSBytes(bytearray):
    """A ``Uint8Array`` / ``Buffer`` (bytes)."""
    recipe: tuple[str, ...] = ()


class JSObj(dict):
    recipe: tuple[str, ...] = ()
    proto: "JSObj | None" = None
    cls: str = "Object"


class Unk:
    """A value that cannot be computed from the script: ``why`` says what it depends on."""

    def __init__(self, why: str, recipe: tuple[str, ...] = (), quiet: bool = False) -> None:
        self.why, self.recipe, self.quiet = why, recipe, quiet

    def __repr__(self) -> str:
        return f"<unknown: {self.why}>"


class JSFunc:
    def __init__(self, node: Any, closure: "Scope", src: str, name: str = "", arrow: bool = False,
                 this: Any = None) -> None:
        self.node, self.closure, self.src, self.name, self.arrow = node, closure, src, name, arrow
        self.bound_this = this
        self.bound_args: list = []
        self.props: dict[str, Any] = {}
        self.recipe: tuple[str, ...] = ()


class Native:
    def __init__(self, name: str, fn: Callable[..., Any], ctor: Callable[..., Any] | None = None,
                 props: dict[str, Any] | None = None) -> None:
        self.name, self.fn, self.ctor = name, fn, ctor
        self.props: dict[str, Any] = props or {}
        self.recipe: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return f"function {self.name}() {{ [native code] }}"


class Host:
    """An object of the environment (a COM object, ``document``, a CryptoJS WordArray…)."""

    def __init__(self, kind: str, **st: Any) -> None:
        self.kind = kind
        self.st: dict[str, Any] = st
        self.props: dict[str, Any] = {}
        self.recipe: tuple[str, ...] = st.pop("recipe", ())

    def __repr__(self) -> str:
        return f"[object {self.kind}]"


class Scope:
    __slots__ = ("vars", "parent", "func")

    def __init__(self, parent: "Scope | None" = None, func: bool = False) -> None:
        self.vars: dict[str, Any] = {}
        self.parent = parent
        self.func = func

    def find(self, name: str) -> "Scope | None":
        s: Scope | None = self
        while s is not None:
            if name in s.vars:
                return s
            s = s.parent
        return None


class _Break(Exception):
    def __init__(self, label: str | None = None) -> None:
        self.label = label


class _Continue(Exception):
    def __init__(self, label: str | None = None) -> None:
        self.label = label


class _Return(Exception):
    def __init__(self, value: Any) -> None:
        self.value = value


class _Throw(Exception):
    def __init__(self, value: Any) -> None:
        super().__init__(str(value)[:200])
        self.value = value


class _Quit(Exception):
    pass


class Limit(Exception):
    pass


def rec(v: Any) -> tuple[str, ...]:
    return getattr(v, "recipe", ()) or ()


def tag(v: Any, recipe: tuple[str, ...]) -> Any:
    if type(v) is str:
        v = JSStr(v)
    elif type(v) is list:
        v = JSArr(v)
    elif type(v) in (bytes, bytearray):
        v = JSBytes(v)
    try:
        v.recipe = tuple(recipe)[-40:]
    except AttributeError:
        pass
    return v


def step(src: Any, name: str, out: Any) -> Any:
    return tag(out, rec(src) + ((name,) if name else ()))


def is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def norm(n: float | int) -> float | int:
    if isinstance(n, float) and n.is_integer() and abs(n) < 2 ** 53 and not (n == 0 and math.copysign(1, n) < 0):
        return int(n)
    return n


def num_str(n: Any) -> str:
    if isinstance(n, int):
        return str(n)
    if n != n:
        return "NaN"
    if n in (math.inf, -math.inf):
        return "Infinity" if n > 0 else "-Infinity"
    if n.is_integer() and abs(n) < 1e21:
        return str(int(n))
    r = repr(n)
    if "e" in r:
        mant, ex = r.split("e")
        sign = "-" if ex.startswith("-") else "+"
        r = f"{mant}e{sign}{ex.lstrip('+-').lstrip('0') or '0'}"
    return r


def to_num(v: Any) -> float | int:
    if isinstance(v, bool):
        return int(v)
    if is_num(v):
        return v
    if v is None:
        return 0
    if v is UNDEF:
        return math.nan
    if isinstance(v, str):
        t = v.strip()
        if not t:
            return 0
        try:
            if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", t):
                return int(t, 16)
            if re.fullmatch(r"0[oO][0-7]+", t):
                return int(t[2:], 8)
            if re.fullmatch(r"0[bB][01]+", t):
                return int(t[2:], 2)
            if t in ("Infinity", "+Infinity"):
                return math.inf
            if t == "-Infinity":
                return -math.inf
            if re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?", t):
                return norm(float(t)) if re.search(r"[.eE]", t) else int(t)
        except ValueError:
            pass
        return math.nan
    if isinstance(v, list):
        if not v:
            return 0
        if len(v) == 1:
            return to_num(to_str(v[0]))
        return math.nan
    return math.nan


def to_int32(v: Any) -> int:
    n = to_num(v)
    if isinstance(n, float):
        if n != n or n in (math.inf, -math.inf):
            return 0
        n = int(n)
    n &= 0xFFFFFFFF
    return n - 0x100000000 if n & 0x80000000 else n


def to_uint32(v: Any) -> int:
    return to_int32(v) & 0xFFFFFFFF


def to_str(v: Any) -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return "null"
    if v is UNDEF:
        return "undefined"
    if isinstance(v, bool):
        return "true" if v else "false"
    if is_num(v):
        return num_str(v)
    if isinstance(v, JSBytes):
        return ",".join(str(b) for b in v)
    if isinstance(v, list):
        return ",".join("" if x is None or x is UNDEF else to_str(x) for x in v)
    if isinstance(v, JSFunc):
        a, b = v.node.range
        return v.src[a:b]
    if isinstance(v, Native):
        return repr(v)
    if isinstance(v, Host):
        if v.kind == "WordArray":
            return v.st["data"].hex()
        if v.kind == "RegExp":
            return f"/{v.st['source']}/{v.st['flags']}"
        if v.kind == "Error":
            return f"Error: {v.st.get('message', '')}"
        return f"[object {v.kind}]"
    if isinstance(v, JSObj):
        f = v.get("toString")
        if isinstance(f, (JSFunc, Native)) and f is not None:
            return "[object Object]"
        return "[object Object]"
    if isinstance(v, Unk):
        return f"<{v.why}>"
    return str(v)


def truthy(v: Any) -> bool:
    if v is None or v is UNDEF or v is False:
        return False
    if isinstance(v, bool):
        return v
    if is_num(v):
        return not (v == 0 or v != v)
    if isinstance(v, str):
        return len(v) > 0
    return True


def typeof(v: Any) -> str:
    if v is UNDEF:
        return "undefined"
    if v is None:
        return "object"
    if isinstance(v, bool):
        return "boolean"
    if is_num(v):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, (JSFunc, Native)):
        return "function"
    if isinstance(v, Unk):
        return "undefined"
    return "object"


def bin_of(v: Any) -> bytes | None:
    """A value as bytes, the way droppers mean it (a "binary string" is Latin-1)."""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, Host) and v.kind == "WordArray":
        return v.st["data"]
    if isinstance(v, str):
        try:
            return v.encode("latin-1")
        except UnicodeEncodeError:
            return v.encode("utf-8", "replace")
    if isinstance(v, list) and all(is_num(x) for x in v[:64]):
        try:
            return bytes(int(x) & 0xFF for x in v)
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def latin(b: bytes) -> str:
    return b.decode("latin-1")


def js_regex(source: str, flags: str) -> re.Pattern:
    s = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", source)
    s = s.replace("\\/", "/").replace("[^]", "[\\s\\S]")
    s = re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: "\\U%08x" % int(m.group(1), 16), s)
    s = re.sub(r"\$(?=\))", "$", s)
    fl = 0
    if "i" in flags:
        fl |= re.I
    if "m" in flags:
        fl |= re.M
    if "s" in flags:
        fl |= re.S
    return re.compile(s, fl)


ENV = {"COMSPEC": "C:\\WINDOWS\\system32\\cmd.exe", "WINDIR": "C:\\WINDOWS", "SYSTEMROOT": "C:\\WINDOWS",
       "PROGRAMDATA": "C:\\ProgramData", "PUBLIC": "C:\\Users\\Public", "OS": "Windows_NT",
       "SYSTEMDRIVE": "C:", "PROGRAMFILES": "C:\\Program Files", "ALLUSERSPROFILE": "C:\\ProgramData"}
ENV_MACHINE = {"USERNAME": "the victim's user name", "COMPUTERNAME": "the victim's computer name",
               "APPDATA": "the victim's AppData folder", "LOCALAPPDATA": "the victim's AppData folder",
               "TEMP": "the victim's TEMP folder", "TMP": "the victim's TEMP folder",
               "USERPROFILE": "the victim's profile folder", "HOMEPATH": "the victim's profile folder",
               "USERDOMAIN": "the victim's domain"}

_LIB_UNKNOWN = "not defined in the script (a library or the page)"


def _expand_env(s: str) -> str:
    return re.sub(r"%([A-Za-z_][\w()]*)%", lambda m: ENV.get(m.group(1).upper(), m.group(0)), s)


# --- the interpreter -----------------------------------------------------------------------------
class Interp:  # noqa: PLR0904
    script_path = "C:\\Users\\Public\\script.js"

    def __init__(self, sinks: Sinks, source: str) -> None:
        self.sinks = sinks
        self.source = source
        self.top_source = source
        self.gscope = Scope(func=True)
        self.steps = 0
        self.t0 = time.monotonic()
        self.depth = 0
        self.call_depth = 0
        self.errors: list[str] = []
        self.ran: set[str] = set()
        self.tracked: dict[str, Any] = {}
        self.last: Any = UNDEF
        self.streams: list[Host] = []
        self.glob = Host("global")
        self.builtins = self._builtins()

    # -- running ------------------------------------------------------------------------------
    def parse(self, code: str) -> Any:
        import esprima
        opts = {"loc": True, "range": True, "tolerant": True}
        try:
            return esprima.parseScript(code, opts)
        except Exception:  # noqa: BLE001
            alt = re.sub(r"\?\.(?!\d)", ".", code).replace("??", "||")
            alt = re.sub(r"^\s*#!.*", "", alt)
            alt = re.sub(r"/\*@cc_on|@\*/|@if\s*\([^)]*\)|@elif\s*\([^)]*\)|@else|@end", "", alt)
            if alt != code:
                return esprima.parseScript(alt, opts)
            raise

    def run(self, code: str) -> None:
        try:
            prog = self.parse(code)
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"not parsed: {exc}"[:300])
            return
        try:
            self.body(prog.body, self.gscope, top=True)
        except (Limit, _Quit, _Return, _Break, _Continue):
            pass
        except _Throw as e:
            self.errors.append(f"script stops: throws {to_str(e.value)[:120]}")
        for h in self.streams:
            self._flush_text(h, None)
        self.computed_values()

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise Limit("steps")
        if not self.steps & 0x3FFF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise Limit("time")

    def line(self, n: Any) -> int | None:
        loc = getattr(n, "loc", None)
        return loc.start.line if loc is not None else None

    def text(self, n: Any, cap: int = 200) -> str:
        r = getattr(n, "range", None)
        if not r:
            return ""
        return re.sub(r"\s+", " ", self.source[r[0]:r[1]])[:cap]

    # -- hoisting -------------------------------------------------------------------------------
    def hoist(self, stmts: list, scope: Scope) -> None:
        def walk(st: Any) -> None:
            if st is None:
                return
            t = st.type
            if t == "FunctionDeclaration" and st.id is not None:
                scope.vars[st.id.name] = JSFunc(st, scope, self.source, st.id.name)
            elif t == "VariableDeclaration" and st.kind == "var":
                for d in st.declarations:
                    for nm in self._pattern_names(d.id):
                        scope.vars.setdefault(nm, UNDEF)
            elif t == "BlockStatement":
                for s in st.body:
                    walk(s)
            elif t == "IfStatement":
                walk(st.consequent)
                walk(st.alternate)
            elif t in ("ForStatement",):
                if st.init is not None and st.init.type == "VariableDeclaration":
                    walk(st.init)
                walk(st.body)
            elif t in ("ForInStatement", "ForOfStatement"):
                if st.left.type == "VariableDeclaration":
                    walk(st.left)
                walk(st.body)
            elif t in ("WhileStatement", "DoWhileStatement", "LabeledStatement", "WithStatement"):
                walk(st.body)
            elif t == "TryStatement":
                walk(st.block)
                if st.handler is not None:
                    walk(st.handler.body)
                walk(st.finalizer)
            elif t == "SwitchStatement":
                for c in st.cases:
                    for s in c.consequent:
                        walk(s)
        for s in stmts:
            walk(s)

    def _pattern_names(self, p: Any) -> list[str]:
        if p is None:
            return []
        if p.type == "Identifier":
            return [p.name]
        if p.type == "ArrayPattern":
            return [n for e in p.elements for n in self._pattern_names(e)]
        if p.type == "ObjectPattern":
            return [n for pr in p.properties for n in self._pattern_names(getattr(pr, "value", None) or getattr(pr, "argument", None))]
        if p.type == "AssignmentPattern":
            return self._pattern_names(p.left)
        if p.type == "RestElement":
            return self._pattern_names(p.argument)
        return []

    # -- statements --------------------------------------------------------------------------------
    def body(self, stmts: list, scope: Scope, top: bool = False) -> None:
        self.hoist(stmts, scope)
        for st in stmts:
            if top:
                try:
                    self.stmt(st, scope)
                except (_Break, _Continue, _Return, Limit, _Quit):
                    raise
                except _Throw as e:
                    self.errors.append(f"line {self.line(st)}: throws {to_str(e.value)[:120]}")
                except RecursionError:
                    self.errors.append(f"line {self.line(st)}: recursion")
                except Exception as exc:  # noqa: BLE001
                    self.errors.append(f"line {self.line(st)}: {type(exc).__name__}: {exc}"[:300])
            else:
                self.stmt(st, scope)

    def stmt(self, st: Any, scope: Scope, label: str | None = None) -> None:  # noqa: C901, PLR0912
        self.tick()
        t = st.type
        if t == "ExpressionStatement":
            self.last = self.eval(st.expression, scope)
        elif t == "VariableDeclaration":
            for d in st.declarations:
                if d.init is None:
                    if st.kind != "var":
                        scope.vars[d.id.name if d.id.type == "Identifier" else "_"] = UNDEF
                    continue
                v = self.eval(d.init, scope, name_hint=d.id.name if d.id.type == "Identifier" else "")
                self.bind(d.id, v, scope, declare=True, line=self.line(d))
        elif t == "FunctionDeclaration":
            pass                                                 # hoisted
        elif t == "ReturnStatement":
            raise _Return(self.eval(st.argument, scope) if st.argument is not None else UNDEF)
        elif t == "IfStatement":
            c = self.eval(st.test, scope)
            if isinstance(c, Unk):
                # a condition that depends on the machine: both ways
                for b in (st.consequent, st.alternate):
                    if b is not None:
                        try:
                            self.stmt(b, scope)
                        except _Quit:
                            self.sinks.step(self.line(st), "quits only when a machine check fails (followed on)",
                                            Value("str", self.text(st.test, 120)))
                        except (_Throw, Exception) as exc:  # noqa: BLE001
                            if isinstance(exc, (Limit, _Return, _Break, _Continue)):
                                raise
                return
            if truthy(c):
                self.stmt(st.consequent, scope)
            elif st.alternate is not None:
                self.stmt(st.alternate, scope)
        elif t == "BlockStatement":
            self.hoist(st.body, scope)
            for s in st.body:
                self.stmt(s, scope)
        elif t == "ForStatement":
            self.loop_for(st, scope, label)
        elif t in ("WhileStatement", "DoWhileStatement"):
            self.loop_while(st, scope, label)
        elif t in ("ForInStatement", "ForOfStatement"):
            self.loop_forin(st, scope, label)
        elif t == "BreakStatement":
            raise _Break(st.label.name if st.label else None)
        elif t == "ContinueStatement":
            raise _Continue(st.label.name if st.label else None)
        elif t == "TryStatement":
            self.try_(st, scope)
        elif t == "ThrowStatement":
            raise _Throw(self.eval(st.argument, scope))
        elif t == "SwitchStatement":
            self.switch(st, scope, label)
        elif t == "LabeledStatement":
            try:
                self.stmt(st.body, scope, st.label.name)
            except _Break as b:
                if b.label != st.label.name:
                    raise
        elif t in ("EmptyStatement", "DebuggerStatement"):
            pass
        elif t == "WithStatement":
            self.stmt(st.body, scope)
        elif t == "ClassDeclaration":
            scope.vars[st.id.name] = self.make_class(st, scope)
        else:
            self.errors.append(f"line {self.line(st)}: {t} not followed")

    def try_(self, st: Any, scope: Scope) -> None:
        try:
            try:
                self.stmt(st.block, scope)
            except (Limit, _Quit, _Return, _Break, _Continue):
                raise
            except _Throw as e:
                if st.handler is None:
                    raise
                self._catch(st.handler, e.value, scope)
            except RecursionError:
                raise
            except Exception as exc:  # noqa: BLE001  (a TypeError of the script)
                if st.handler is None:
                    raise
                self._catch(st.handler, Host("Error", message=f"{type(exc).__name__}: {exc}"[:200]), scope)
        finally:
            if st.finalizer is not None:
                self.stmt(st.finalizer, scope)

    def _catch(self, h: Any, value: Any, scope: Scope) -> None:
        sc = Scope(scope)
        if h.param is not None:
            self.bind(h.param, value, sc, declare=True)
        self.stmt(h.body, sc)

    def switch(self, st: Any, scope: Scope, label: str | None) -> None:
        d = self.eval(st.discriminant, scope)
        matched = False
        try:
            for c in st.cases:
                if not matched:
                    if c.test is None:
                        continue
                    if self.strict_eq(d, self.eval(c.test, scope)):
                        matched = True
                if matched:
                    for s in c.consequent:
                        self.stmt(s, scope)
            if not matched:
                hit = False
                for c in st.cases:
                    if c.test is None:
                        hit = True
                    if hit:
                        for s in c.consequent:
                            self.stmt(s, scope)
        except _Break as b:
            if b.label not in (None, label):
                raise

    # -- loops ---------------------------------------------------------------------------------------
    def _has_break(self, n: Any) -> bool:
        found = False

        def visit(x: Any) -> None:
            nonlocal found
            if found or x is None or not hasattr(x, "type"):
                return
            if x.type in ("BreakStatement", "ReturnStatement", "ThrowStatement"):
                found = True
                return
            if x.type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
                return
            if x.type == "CallExpression" and self.text(x.callee, 40).lower() in ("wscript.quit",):
                found = True
                return
            for v in vars(x).values():
                if isinstance(v, list):
                    for i in v:
                        visit(i)
                elif hasattr(v, "type"):
                    visit(v)
        visit(n)
        return found

    def _iter_body(self, body: Any, scope: Scope, label: str | None) -> bool:
        """One round of a loop body; False when the loop breaks."""
        try:
            self.stmt(body, scope)
        except _Break as b:
            if b.label not in (None, label):
                raise
            return False
        except _Continue as c:
            if c.label not in (None, label):
                raise
        return True

    def loop_for(self, st: Any, scope: Scope, label: str | None) -> None:
        if st.init is not None:
            if st.init.type == "VariableDeclaration":
                self.stmt(st.init, scope)
            else:
                self.eval(st.init, scope)
        if self._fast_char_loop(st, scope):
            return
        before = self._loop_before(st.body, scope)
        cap = MAX_LOOP if (st.test is not None or self._has_break(st.body)) else 3
        n, start = 0, self.steps
        while n < cap:
            n += 1
            if self.steps - start > LOOP_STEPS:
                if self._loop_too_long(st, scope, n):
                    break
                start = float("inf")         # it builds a string / an array: the global budget applies
            if st.test is not None:
                c = self.eval(st.test, scope)
                if isinstance(c, Unk):
                    if n > 3:
                        break
                elif not truthy(c):
                    break
            if not self._iter_body(st.body, scope, label):
                break
            if st.update is not None:
                self.eval(st.update, scope)
        self._loop_after(before, scope)

    def loop_while(self, st: Any, scope: Scope, label: str | None) -> None:
        before = self._loop_before(st.body, scope)
        always = st.test.type == "Literal" or self.text(st.test, 20) in ("!![]", "!0", "true", "1")
        cap = 3 if (always and not self._has_break(st.body)) else MAX_LOOP
        n, start = 0, self.steps
        first = st.type == "DoWhileStatement"
        while n < cap:
            n += 1
            if self.steps - start > LOOP_STEPS:
                if self._loop_too_long(st, scope, n):
                    break
                start = float("inf")         # it builds a string / an array: the global budget applies
            if not first:
                c = self.eval(st.test, scope)
                if isinstance(c, Unk):
                    if n > 3:
                        break
                elif not truthy(c):
                    break
            first = False
            if not self._iter_body(st.body, scope, label):
                break
        self._loop_after(before, scope)

    def loop_forin(self, st: Any, scope: Scope, label: str | None) -> None:
        obj = self.eval(st.right, scope)
        if st.type == "ForInStatement":
            if isinstance(obj, (JSObj, dict)):
                items: list = list(obj.keys())
            elif isinstance(obj, (str, list, bytearray)):
                items = [str(i) for i in range(len(obj))]
            else:
                items = []
        else:
            items = list(self.iterate(obj))
        before = self._loop_before(st.body, scope)
        left = st.left.declarations[0].id if st.left.type == "VariableDeclaration" else st.left
        for n, it in enumerate(items):
            if n >= MAX_LOOP:
                break
            self.bind(left, it, scope, declare=st.left.type == "VariableDeclaration")
            if not self._iter_body(st.body, scope, label):
                break
        self._loop_after(before, scope)

    def _loop_too_long(self, st: Any, scope: Scope, rounds: int) -> bool:
        """A loop past its share of the step budget that only turns numbers (anti-emulation busy
        loops compute a key in millions of rounds): what it assigns becomes unknown and the rest of
        the script goes on. A loop that builds a string or an array (a long decoder) carries on."""
        names: list[str] = []

        def v(x: Any) -> None:
            if x is None or not hasattr(x, "type"):
                return
            if x.type == "AssignmentExpression" and x.left.type == "Identifier":
                names.append(x.left.name)
            elif x.type == "UpdateExpression" and x.argument.type == "Identifier":
                names.append(x.argument.name)
            for k, c in vars(x).items():
                if k in ("loc", "range"):
                    continue
                for y in (c if isinstance(c, list) else [c]):
                    if hasattr(y, "type"):
                        v(y)

        v(st.body)
        names = list(dict.fromkeys(names))
        vals = [self.lookup(nm, scope, quiet=True) for nm in names]
        if not names or any(not isinstance(x, (int, float, bool)) for x in vals):
            return False
        why = (f"a loop still running after {rounds:,} rounds that only computes numbers (a busy loop "
               "against emulators): its result is left to the sandbox")
        for nm in names:
            sc = scope.find(nm)
            if sc is not None:
                sc.vars[nm] = Unk(why)
        self.sinks.unresolved_(self.text(st, 160), ", ".join(names), why, self.line(st))
        return True

    # the operation a loop applies: named in the recipe of what it builds
    def _loop_targets(self, body: Any) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []

        def src_of(e: Any, target: str) -> str:
            found = ""

            def v(x: Any) -> None:
                nonlocal found
                if found or x is None or not hasattr(x, "type"):
                    return
                if x.type == "MemberExpression" and x.object.type == "Identifier" and x.object.name != target:
                    p = x.property
                    if x.computed or (p.type == "Identifier" and p.name in ("charCodeAt", "charAt", "substr", "substring", "slice")):
                        found = x.object.name
                        return
                for val in vars(x).values():
                    if isinstance(val, list):
                        for i in val:
                            v(i)
                    elif hasattr(val, "type"):
                        v(val)
            v(e)
            return found

        def visit(x: Any) -> None:
            if x is None or not hasattr(x, "type"):
                return
            if x.type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
                return
            if x.type == "AssignmentExpression":
                L = x.left
                if L.type == "Identifier" and (x.operator == "+=" or (
                        x.operator == "=" and x.right.type == "BinaryExpression" and x.right.operator == "+"
                        and x.right.left.type == "Identifier" and x.right.left.name == L.name)):
                    rhs = x.right if x.operator == "+=" else x.right.right
                    s = src_of(rhs, L.name)
                    if s:
                        out.append((L.name, s, self.op_label(rhs, s)))
                elif L.type == "MemberExpression" and L.computed and L.object.type == "Identifier":
                    a = L.object.name
                    if x.operator in ("^=", "-=", "+=", "&=", "|="):
                        out.append((a, a, self.op_label(x.right, a, x.operator[0])))
                    elif x.operator == "=":
                        s = src_of(x.right, "")
                        if s:
                            out.append((a, s, self.op_label(x.right, s)))
            if (x.type == "CallExpression" and x.callee.type == "MemberExpression" and not x.callee.computed
                    and x.callee.property.name == "push" and x.callee.object.type == "Identifier" and x.arguments):
                t = x.callee.object.name
                s = src_of(x.arguments[0], t)
                if s:
                    out.append((t, s, self.op_label(x.arguments[0], s)))
            for val in vars(x).values():
                if isinstance(val, list):
                    for i in val:
                        visit(i)
                elif hasattr(val, "type"):
                    visit(val)
        visit(body)
        return out

    def op_label(self, e: Any, src: str, op: str = "") -> str:
        """``xor(0x5a)``, ``xor(key k)``, ``sub(3)``… for the expression a loop / map applies."""
        ops: list[tuple[str, Any]] = []

        def v(x: Any) -> None:
            if x is None or not hasattr(x, "type"):
                return
            if x.type == "BinaryExpression" and x.operator in ("^", "-", "+"):
                ops.append((x.operator, x))
            for val in vars(x).values():
                if isinstance(val, list):
                    for i in val:
                        v(i)
                elif hasattr(val, "type"):
                    v(val)
        if op:
            ops.append((op, type("N", (), {"left": None, "right": e})()))
        v(e)

        def key_of(x: Any) -> str:
            if x is None:
                return ""
            if x.type == "Literal" and is_num(x.value):
                return f"0x{int(x.value):x}"
            if x.type == "UnaryExpression" and x.argument.type == "Literal" and is_num(x.argument.value):
                return f"{x.operator}{x.argument.value}"
            names = re.findall(r"[A-Za-z_$][\w$]*", self.text(x, 80))
            names = [n for n in names if n not in (src, "charCodeAt", "length", "i", "j", "idx", "String", "fromCharCode")]
            return f"key {names[0]}" if names else "…"
        for want, name in (("^", "xor"), ("-", "sub"), ("+", "add")):
            for o, x in ops:
                if o != want:
                    continue
                whole = self.text(x, 400) if x.left is not None else ""
                if x.left is not None and src not in re.findall(r"[A-Za-z_$][\w$]*", whole):
                    continue
                for side in (x.right, x.left):
                    if side is None:
                        continue
                    t = self.text(side, 200)
                    if src in re.findall(r"[A-Za-z_$][\w$]*", t):
                        continue
                    if want != "^" and not (side.type == "Literal" and is_num(side.value)):
                        continue
                    k = key_of(side)
                    if want != "^":
                        return f"{name}({int(side.value)})"
                    return f"xor({k})"
        t = self.text(e, 200)
        if "fromCharCode" in t:
            return "char codes"
        return "char loop"

    def _loop_before(self, body: Any, scope: Scope) -> list[tuple[str, str, str, tuple]]:
        out = []
        for tgt, src, op in self._loop_targets(body):
            sv = self.lookup(src, scope, quiet=True)
            out.append((tgt, src, op, rec(sv)))
        return out

    def _loop_after(self, before: list, scope: Scope) -> None:
        done = set()
        for tgt, _src, op, r in before:
            if tgt in done:
                continue
            v = self.lookup(tgt, scope, quiet=True)
            if isinstance(v, (str, list, bytearray)) and len(v) >= 16:
                done.add(tgt)
                nv = tag(v, r + (op,))
                s = scope.find(tgt)
                if s is not None:
                    s.vars[tgt] = nv
                self.sinks.step(None, f"{tgt} = loop {op}", self.to_value(nv))

    def _fast_char_loop(self, st: Any, scope: Scope) -> bool:
        """``for (i = 0; i < s.length; i++) r += String.fromCharCode(s.charCodeAt(i) ^ k…)``:
        the commonest decoder, done in one step (same result, without a million rounds)."""
        b = st.body
        if b.type == "BlockStatement":
            if len(b.body) != 1:
                return False
            b = b.body[0]
        if b.type != "ExpressionStatement" or b.expression.type != "AssignmentExpression":
            return False
        x = b.expression
        if not (x.operator == "+=" and x.left.type == "Identifier"):
            return False
        m = re.fullmatch(r"\s*(\w+)\s*<\s*(\w+)\.length\s*", self.text(st.test, 80) if st.test else "")
        u = self.text(st.update, 40) if st.update else ""
        if not m or not re.fullmatch(rf"\s*(?:{m.group(1)}\s*\+\+|\+\+\s*{m.group(1)}|{m.group(1)}\s*\+=\s*1)\s*", u):
            return False
        ivar, svar = m.group(1), m.group(2)
        i0 = self.lookup(ivar, scope, quiet=True)
        s = self.lookup(svar, scope, quiet=True)
        acc = self.lookup(x.left.name, scope, quiet=True)
        if i0 != 0 or not isinstance(s, str) or not isinstance(acc, str) or len(s) < 256:
            return False
        rhs = self.text(x.right, 400)
        if not re.match(r"String\.fromCharCode\(", rhs) or "charCodeAt" not in rhs:
            return False
        fast = self._vector_decode(rhs, ivar, svar, s, scope)
        if fast is not None:
            data, label = fast
            (scope.find(ivar) or scope).vars[ivar] = len(s)
            res = tag(acc + data, rec(s) + (label,))
            (scope.find(x.left.name) or scope).vars[x.left.name] = res
            self.sinks.step(self.line(st), f"{x.left.name} = loop {label}", self.to_value(res))
            return True
        # evaluate the body for each index with only the index changing: a closure over the rhs
        sc = Scope(scope)
        sc.vars[ivar] = 0
        out = []
        node = x.right
        n = len(s)
        if n > MAX_LOOP:
            return False
        for i in range(n):
            sc.vars[ivar] = i
            v = self.eval(node, sc)
            if not isinstance(v, str):
                return False
            out.append(v)
        s2 = scope.find(ivar)
        (s2 or scope).vars[ivar] = n
        tgt = scope.find(x.left.name) or scope
        label = self.op_label(x.right, svar)
        res = tag(acc + "".join(out), rec(s) + (label,))
        tgt.vars[x.left.name] = res
        self.sinks.step(self.line(st), f"{x.left.name} = loop {label}", self.to_value(res))
        return True

    def _vector_decode(self, rhs: str, i: str, s: str, data: str, scope: Scope) -> tuple[str, str] | None:
        """``String.fromCharCode(s.charCodeAt(i) ^ k.charCodeAt(i % k.length))`` / ``^ 0x5a`` /
        ``- 3`` / ``+ 3``, worked out on the whole string at once."""
        sp = r"\s*"
        src = rf"{re.escape(s)}{sp}\.{sp}charCodeAt{sp}\({sp}{re.escape(i)}{sp}\)"
        m = re.fullmatch(rf"String{sp}\.{sp}fromCharCode{sp}\({sp}\(?{sp}{src}{sp}\^{sp}(?:(\w+){sp}\.{sp}charCodeAt"
                         rf"{sp}\({sp}{re.escape(i)}{sp}%{sp}\1{sp}\.{sp}length{sp}\)|(0x[0-9a-fA-F]+|\d+)){sp}\)?{sp}\){sp}", rhs)
        codes = [ord(c) for c in data]
        if m:
            if m.group(1):
                key = self.lookup(m.group(1), scope, quiet=True)
                if not isinstance(key, str) or not key:
                    return None
                kc = [ord(c) for c in key]
                kl = len(kc)
                return "".join(chr((c ^ kc[j % kl]) & 0xFFFF) for j, c in enumerate(codes)), f"xor(key {m.group(1)})"
            n = int(m.group(2), 0)
            return "".join(chr((c ^ n) & 0xFFFF) for c in codes), f"xor(0x{n:x})"
        m = re.fullmatch(rf"String{sp}\.{sp}fromCharCode{sp}\({sp}\(?{sp}{src}{sp}([-+]){sp}(0x[0-9a-fA-F]+|\d+){sp}\)?{sp}\){sp}", rhs)
        if m:
            n = int(m.group(2), 0) * (1 if m.group(1) == "+" else -1)
            return "".join(chr((c + n) & 0xFFFF) for c in codes), f"{'add' if n > 0 else 'sub'}({abs(n)})"
        return None

    # -- names ---------------------------------------------------------------------------------------
    def lookup(self, name: str, scope: Scope, quiet: bool = False) -> Any:
        s = scope.find(name)
        if s is not None:
            return s.vars[name]
        if name in self.builtins:
            return self.builtins[name]
        if name in ("window", "self", "globalThis", "top", "parent", "this", "frames"):
            return self.glob
        if quiet:
            return UNDEF
        return Unk(f"'{name}' ({_LIB_UNKNOWN})", quiet=True)

    def assign_name(self, name: str, v: Any, scope: Scope, line: int | None = None, declare: bool = False) -> None:
        v = self._label(name, v, line)
        if declare:
            fs = scope
            scope.vars[name] = v
            return
        s = scope.find(name)
        fs = s if s is not None else self.gscope
        fs.vars[name] = v

    def _label(self, name: str, v: Any, line: int | None) -> Any:
        if isinstance(v, (str, bytearray)) and not rec(v) and len(v) >= 16:
            v = tag(v, (f"literal {name}",))
        elif isinstance(v, list) and not rec(v) and len(v) >= 16 and all(is_num(x) for x in v[:32]):
            v = tag(v, (f"number array {name}",))
        elif isinstance(v, (str, bytearray)) and rec(v) and len(v) >= 16 and not rec(v)[-1].startswith(("literal", "number array")):
            self.sinks.step(line, f"{name} =", self.to_value(v))
        if isinstance(v, (str, bytearray, list)) and len(v) >= 40:
            self.tracked[name] = v
        return v

    def bind(self, p: Any, v: Any, scope: Scope, declare: bool = False, line: int | None = None) -> None:
        t = p.type
        if t == "Identifier":
            self.assign_name(p.name, v, scope, line, declare)
        elif t == "AssignmentPattern":
            if v is UNDEF:
                v = self.eval(p.right, scope)
            self.bind(p.left, v, scope, declare, line)
        elif t == "ArrayPattern":
            items = list(self.iterate(v)) if not isinstance(v, Unk) else []
            for i, e in enumerate(p.elements):
                if e is None:
                    continue
                if e.type == "RestElement":
                    self.bind(e.argument, JSArr(items[i:]), scope, declare, line)
                    break
                self.bind(e, items[i] if i < len(items) else (v if isinstance(v, Unk) else UNDEF), scope, declare, line)
        elif t == "ObjectPattern":
            for pr in p.properties:
                if pr.type == "RestElement":
                    continue
                k = self.prop_key(pr, scope)
                self.bind(pr.value, self.get(v, k), scope, declare, line)
        elif t == "MemberExpression":
            o = self.eval(p.object, scope)
            k = self.member_key(p, scope)
            self.put(o, k, v, line)
        else:
            raise TypeError(f"cannot assign to {t}")

    # -- expressions -----------------------------------------------------------------------------------
    def eval(self, n: Any, scope: Scope, name_hint: str = "") -> Any:  # noqa: C901, PLR0911, PLR0912
        self.tick()
        t = n.type
        if t == "Literal":
            if getattr(n, "regex", None) is not None:
                return self.regexp(n.regex.pattern, n.regex.flags)
            v = n.value
            if isinstance(v, float):
                return norm(v)
            return v
        if t == "Identifier":
            if n.name == "undefined":
                return UNDEF
            if n.name == "NaN":
                return math.nan
            if n.name == "Infinity":
                return math.inf
            return self.lookup(n.name, scope)
        if t == "BinaryExpression":
            return self.binop(n.operator, self.eval(n.left, scope), self.eval(n.right, scope))
        if t == "LogicalExpression":
            a = self.eval(n.left, scope)
            if n.operator == "&&":
                return self.eval(n.right, scope) if truthy(a) else a
            if n.operator == "||":
                return a if truthy(a) else self.eval(n.right, scope)
            return a if a is not None and a is not UNDEF else self.eval(n.right, scope)
        if t == "UnaryExpression":
            return self.unary(n, scope)
        if t == "UpdateExpression":
            old = to_num(self.eval(n.argument, scope))
            new = norm(old + (1 if n.operator == "++" else -1))
            self.store(n.argument, new, scope)
            return new if n.prefix else old
        if t == "AssignmentExpression":
            return self.assign(n, scope)
        if t == "MemberExpression":
            o = self.eval(n.object, scope)
            k = self.member_key(n, scope)
            return self.get(o, k, n)
        if t in ("CallExpression", "NewExpression"):
            return self.call(n, scope, new=t == "NewExpression")
        if t == "ArrayExpression":
            out = JSArr()
            for e in n.elements:
                if e is None:
                    out.append(UNDEF)
                elif e.type == "SpreadElement":
                    out.extend(self.iterate(self.eval(e.argument, scope)))
                else:
                    out.append(self.eval(e, scope))
            return out
        if t == "ObjectExpression":
            o = JSObj()
            for pr in n.properties:
                if pr.type == "SpreadElement":
                    src = self.eval(pr.argument, scope)
                    if isinstance(src, dict):
                        o.update(src)
                    continue
                k = self.prop_key(pr, scope)
                if pr.kind in ("get", "set"):
                    continue
                o[k] = self.eval(pr.value, scope, name_hint=k)
            return o
        if t in ("FunctionExpression", "ArrowFunctionExpression"):
            f = JSFunc(n, scope, self.source, (n.id.name if getattr(n, "id", None) else name_hint),
                       arrow=t == "ArrowFunctionExpression")
            if f.arrow:
                f.bound_this = self.lookup("this", scope, quiet=True)
            return f
        if t == "ConditionalExpression":
            c = self.eval(n.test, scope)
            return self.eval(n.consequent if truthy(c) else n.alternate, scope)
        if t == "SequenceExpression":
            v: Any = UNDEF
            for e in n.expressions:
                v = self.eval(e, scope)
            return v
        if t == "ThisExpression":
            return self.lookup("this", scope)
        if t == "TemplateLiteral":
            parts = []
            for i, q in enumerate(n.quasis):
                parts.append(q.value.cooked or "")
                if i < len(n.expressions):
                    parts.append(to_str(self.prim(self.eval(n.expressions[i], scope))))
            return "".join(parts)
        if t == "TaggedTemplateExpression":
            tagf = self.eval(n.tag, scope)
            strs = JSArr(q.value.cooked for q in n.quasi.quasis)
            strs_raw = JSArr(q.value.raw for q in n.quasi.quasis)
            if isinstance(tagf, Native) and tagf.name == "String.raw":
                return "".join(s + (to_str(self.eval(e, scope)) if i < len(n.quasi.expressions) else "")
                               for i, (s, e) in enumerate(zip(strs_raw, list(n.quasi.expressions) + [None])))
            return self.invoke(tagf, UNDEF, [strs] + [self.eval(e, scope) for e in n.quasi.expressions], n)
        if t == "AwaitExpression":
            return self.eval(n.argument, scope)
        if t == "ClassExpression":
            return self.make_class(n, scope)
        if t == "SpreadElement":
            return self.eval(n.argument, scope)
        raise TypeError(f"{t} not followed")

    def regexp(self, source: str, flags: str) -> Host:
        try:
            pat = js_regex(source, flags)
        except re.error as exc:
            raise _Throw(Host("Error", message=f"bad regex: {exc}")) from exc
        return Host("RegExp", source=source, flags=flags, re=pat, lastIndex=0)

    def prop_key(self, pr: Any, scope: Scope) -> str:
        if pr.computed:
            return self.key_str(self.eval(pr.key, scope))
        k = pr.key
        if k.type == "Identifier":
            return k.name
        return to_str(norm(k.value) if isinstance(k.value, float) else k.value)

    def member_key(self, n: Any, scope: Scope) -> Any:
        if n.computed:
            k = self.eval(n.property, scope)
            return k if isinstance(k, Unk) or (is_num(k) and not isinstance(k, bool)) else self.key_str(k)
        return n.property.name

    def key_str(self, k: Any) -> Any:
        if isinstance(k, Unk):
            return k
        if is_num(k):
            return k
        return to_str(self.prim(k))

    def unary(self, n: Any, scope: Scope) -> Any:
        op = n.operator
        if op == "typeof":
            if n.argument.type == "Identifier" and scope.find(n.argument.name) is None \
                    and n.argument.name not in self.builtins:
                return "undefined"
            return typeof(self.eval(n.argument, scope))
        if op == "delete":
            if n.argument.type == "MemberExpression":
                o = self.eval(n.argument.object, scope)
                k = self.member_key(n.argument, scope)
                if isinstance(o, dict):
                    o.pop(self.key_str(k) if not isinstance(k, str) else k, None)
            return True
        v = self.eval(n.argument, scope)
        if isinstance(v, Unk) and op != "void":
            return Unk(v.why, v.recipe)
        if op == "!":
            return not truthy(v)
        if op == "-":
            return norm(-to_num(self.prim(v)))
        if op == "+":
            return to_num(self.prim(v))
        if op == "~":
            return ~to_int32(v)
        if op == "void":
            return UNDEF
        raise TypeError(op)

    def store(self, target: Any, v: Any, scope: Scope) -> None:
        if target.type == "Identifier":
            self.assign_name(target.name, v, scope, self.line(target))
        elif target.type == "MemberExpression":
            o = self.eval(target.object, scope)
            k = self.member_key(target, scope)
            self.put(o, k, v, self.line(target))
        else:
            self.bind(target, v, scope)

    def assign(self, n: Any, scope: Scope) -> Any:
        if n.operator == "=":
            hint = n.left.name if n.left.type == "Identifier" else ""
            v = self.eval(n.right, scope, name_hint=hint)
            if n.left.type in ("Identifier", "MemberExpression"):
                self.store(n.left, v, scope)
            else:
                self.bind(n.left, v, scope)
            return v
        op = n.operator[:-1]
        if op in ("&&", "||", "??"):
            cur = self.eval(n.left, scope)
            go = {"&&": truthy(cur), "||": not truthy(cur), "??": cur is None or cur is UNDEF}[op]
            if not go:
                return cur
            v = self.eval(n.right, scope)
        else:
            if n.left.type == "MemberExpression":
                o = self.eval(n.left.object, scope)
                k = self.member_key(n.left, scope)
                cur = self.get(o, k, n.left)
                v = self.binop(op, cur, self.eval(n.right, scope))
                self.put(o, k, v, self.line(n))
                return v
            cur = self.eval(n.left, scope)
            v = self.binop(op, cur, self.eval(n.right, scope))
        self.store(n.left, v, scope)
        return v

    def prim(self, v: Any) -> Any:
        """ToPrimitive (objects with their own toString / valueOf)."""
        if isinstance(v, JSObj):
            for m in ("valueOf", "toString"):
                f = self.find_prop(v, m)
                if isinstance(f, JSFunc):
                    r = self.call_func(f, v, [])
                    if not isinstance(r, (JSObj, JSArr)):
                        return r
            return "[object Object]"
        return v

    def binop(self, op: str, a: Any, b: Any) -> Any:  # noqa: C901, PLR0911, PLR0912
        if isinstance(a, Unk) or isinstance(b, Unk):
            u = a if isinstance(a, Unk) else b
            if op in ("===", "!==", "==", "!=", "<", ">", "<=", ">=", "instanceof", "in"):
                return Unk(u.why)
            return Unk(u.why, u.recipe)
        if op == "+":
            a, b = self.prim(a), self.prim(b)
            if isinstance(a, str) or isinstance(b, str) or isinstance(a, (list, bytearray, JSFunc, Native, Host)) \
                    or isinstance(b, (list, bytearray, JSFunc, Native, Host)):
                sa, sb = to_str(a), to_str(b)
                if len(sa) + len(sb) > MAX_STR:
                    raise Limit("string size")
                out = sa + sb
                ra, rb = rec(a), rec(b)
                r = ra if (ra and (len(sa) >= len(sb) or not rb)) else rb
                return tag(out, r) if r else out
            return norm(to_num(a) + to_num(b))
        if op in ("===", "!=="):
            e = self.strict_eq(a, b)
            return e if op == "===" else not e
        if op in ("==", "!="):
            e = self.loose_eq(a, b)
            return e if op == "==" else not e
        if op in ("<", ">", "<=", ">="):
            a, b = self.prim(a), self.prim(b)
            if isinstance(a, str) and isinstance(b, str):
                x, y = a, b
            else:
                x, y = to_num(a), to_num(b)
                if x != x or y != y:
                    return False
            return {"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]
        if op == "instanceof":
            if isinstance(b, Native):
                return (b.name == "Array" and isinstance(a, list)) or (b.name == "Object" and isinstance(a, (dict, list)))
            if isinstance(b, JSFunc) and isinstance(a, JSObj):
                return a.proto is b.props.get("prototype")
            return False
        if op == "in":
            k = self.key_str(a)
            if isinstance(b, dict):
                return to_str(k) in b
            if isinstance(b, list):
                return is_num(k) and 0 <= k < len(b)
            if isinstance(b, Host):
                return to_str(k) in b.props or b is self.glob and (self.gscope.find(to_str(k)) is not None)
            return False
        x, y = to_num(self.prim(a)), to_num(self.prim(b))
        if op == "-":
            return norm(x - y)
        if op == "*":
            return norm(x * y)
        if op == "/":
            if y == 0:
                return math.nan if x == 0 or x != x else math.copysign(math.inf, x) * (1 if str(y)[0] != "-" else -1)
            return norm(x / y)
        if op == "%":
            if y == 0 or x != x or y != y or x in (math.inf, -math.inf):
                return math.nan
            return norm(math.fmod(x, y))
        if op == "**":
            try:
                return norm(x ** y)
            except (OverflowError, ZeroDivisionError):
                return math.inf
        if op == "&":
            return to_int32(to_int32(x) & to_int32(y))
        if op == "|":
            return to_int32(to_int32(x) | to_int32(y))
        if op == "^":
            return to_int32(to_int32(x) ^ to_int32(y))
        if op == "<<":
            return to_int32(to_int32(x) << (to_uint32(y) & 31))
        if op == ">>":
            return to_int32(x) >> (to_uint32(y) & 31)
        if op == ">>>":
            return to_uint32(x) >> (to_uint32(y) & 31)
        raise TypeError(op)

    def strict_eq(self, a: Any, b: Any) -> bool:
        if is_num(a) and is_num(b):
            return a == b
        if isinstance(a, str) and isinstance(b, str):
            return str(a) == str(b)
        if isinstance(a, bool) or isinstance(b, bool):
            return type(a) is type(b) and a == b
        return a is b

    def loose_eq(self, a: Any, b: Any) -> bool:
        if (a is None or a is UNDEF) and (b is None or b is UNDEF):
            return True
        if a is None or a is UNDEF or b is None or b is UNDEF:
            return False
        if isinstance(a, str) and isinstance(b, str):
            return str(a) == str(b)
        if isinstance(a, (JSObj, JSArr, JSFunc, Native, Host, JSBytes)) and isinstance(b, (JSObj, JSArr, JSFunc, Native, Host, JSBytes)):
            return a is b
        a, b = self.prim(a), self.prim(b)
        if isinstance(a, (list,)):
            a = to_str(a)
        if isinstance(b, (list,)):
            b = to_str(b)
        if isinstance(a, str) and isinstance(b, str):
            return a == b
        return to_num(a) == to_num(b)

    def iterate(self, v: Any) -> Any:
        if isinstance(v, str):
            return list(v)
        if isinstance(v, (list, bytearray)):
            return list(v)
        if isinstance(v, dict):
            return list(v.values())
        if isinstance(v, Host) and v.kind in ("Map", "Set"):
            return list(v.st["items"])
        return []

    # -- properties ----------------------------------------------------------------------------------
    def find_prop(self, o: JSObj, k: str) -> Any:
        x: JSObj | None = o
        n = 0
        while x is not None and n < 50:
            if k in x:
                return x[k]
            x = x.proto
            n += 1
        return UNDEF

    def get(self, o: Any, k: Any, node: Any = None) -> Any:  # noqa: C901, PLR0911, PLR0912
        if isinstance(o, Unk):
            return Unk(o.why, o.recipe, o.quiet)
        if isinstance(k, Unk):
            return Unk(k.why)
        if o is None or o is UNDEF:
            raise _Throw(Host("Error", message=f"TypeError: cannot read '{to_str(k)}' of {to_str(o)}"))
        if isinstance(o, str):
            if is_num(k):
                return o[int(k)] if 0 <= k < len(o) and float(k).is_integer() else UNDEF
            if k == "length":
                return len(o)
            if isinstance(k, str) and k.isdigit():
                return o[int(k)] if int(k) < len(o) else UNDEF
            return self.method(o, k)
        if isinstance(o, (list, bytearray)):
            if is_num(k) or (isinstance(k, str) and k.isdigit()):
                i = int(k)
                if 0 <= i < len(o) and float(k).is_integer():
                    return o[i]
                return UNDEF
            if k == "length":
                return len(o)
            if isinstance(o, JSBytes) and k in ("buffer",):
                return o
            if isinstance(o, JSBytes) and k == "byteLength":
                return len(o)
            return self.method(o, k)
        if isinstance(o, JSObj):
            ks = to_str(k)
            v = self.find_prop(o, ks)
            if v is UNDEF:
                if ks in ("hasOwnProperty", "toString", "valueOf", "constructor", "keys"):
                    return self.method(o, ks)
            return v
        if isinstance(o, (JSFunc, Native)):
            ks = to_str(k)
            if ks in o.props:
                return o.props[ks]
            if ks == "prototype" and isinstance(o, JSFunc):
                p = o.props["prototype"] = JSObj()
                return p
            if isinstance(o, Native) and o.name in self.statics and ks in self.statics[o.name]:
                return self.statics[o.name][ks]
            return self.method(o, ks)
        if isinstance(o, Host):
            return self.host_get(o, to_str(k), node)
        if is_num(o) or isinstance(o, bool):
            return self.method(o, to_str(k))
        return UNDEF

    def put(self, o: Any, k: Any, v: Any, line: int | None = None) -> None:
        if isinstance(o, Unk):
            return
        if isinstance(k, Unk):
            self.sinks.unresolved_("a property with a computed name", k.why, "the name is not in the script", line)
            return
        if isinstance(o, (list, bytearray)) and (is_num(k) or (isinstance(k, str) and k.isdigit())):
            i = int(k)
            if i < 0 or i > MAX_LOOP:
                return
            if isinstance(o, bytearray):
                val = to_int32(v) & 0xFF
                if i < len(o):
                    o[i] = val
                else:
                    o.extend(b"\x00" * (i - len(o)))
                    o.append(val)
                return
            while len(o) <= i:
                o.append(UNDEF)
            o[i] = v
            return
        if isinstance(o, list) and k == "length":
            n = int(to_num(v))
            del o[n:]
            return
        if isinstance(o, JSObj):
            o[to_str(k)] = v
            return
        if isinstance(o, (JSFunc, Native)):
            o.props[to_str(k)] = v
            return
        if isinstance(o, Host):
            self.host_set(o, to_str(k), v, line)

    # -- calls -----------------------------------------------------------------------------------------
    def call(self, n: Any, scope: Scope, new: bool = False) -> Any:
        args: list = []
        for a in n.arguments:
            if a.type == "SpreadElement":
                args.extend(self.iterate(self.eval(a.argument, scope)))
            else:
                args.append(self.eval(a, scope))
        c = n.callee
        this: Any = UNDEF
        if c.type == "MemberExpression":
            this = self.eval(c.object, scope)
            k = self.member_key(c, scope)
            if isinstance(k, Unk):
                self.sinks.unresolved_(self.text(n), k.why, "the name of the method it calls is computed at run time",
                                       self.line(n))
                return Unk(f"the result of {self.text(c, 60)}")
            fn = self.get(this, k, c)
        else:
            fn = self.eval(c, scope)
        if new:
            return self.construct(fn, args, n)
        return self.invoke(fn, this, args, n)

    def called_as(self, name: str, node: Any) -> str:
        if node is None:
            return name
        c = getattr(node, "callee", None)
        src = self.text(c, 80) if c is not None else ""
        if src and src.replace(" ", "") not in (name, name.split(".")[-1]) and not src.endswith("." + name.split(".")[-1]):
            return f"{name} (called as {src})"
        return name

    def invoke(self, fn: Any, this: Any, args: list, node: Any = None) -> Any:
        if isinstance(fn, JSFunc):
            return self.call_func(fn, this, args)
        if isinstance(fn, Native):
            return fn.fn(this, args, node)
        if isinstance(fn, Unk):
            if not fn.quiet:
                self.sinks.unresolved_(self.text(node) if node is not None else "a call", fn.why,
                                       "the function it calls is computed at run time", self.line(node))
            return Unk(f"the result of {self.text(getattr(node, 'callee', None), 60) or 'a call'}", quiet=fn.quiet)
        if isinstance(fn, Host) and fn.kind == "callable":
            return fn.st["fn"](this, args, node)
        if fn is UNDEF or fn is None:
            name = self.text(getattr(node, "callee", None), 60)
            raise _Throw(Host("Error", message=f"TypeError: {name} is not a function"))
        raise _Throw(Host("Error", message=f"TypeError: {to_str(fn)[:40]} is not a function"))

    def call_func(self, f: JSFunc, this: Any, args: list) -> Any:
        if self.call_depth >= MAX_CALL_DEPTH:
            raise _Throw(Host("Error", message="RangeError: call depth"))
        node = f.node
        sc = Scope(f.closure, func=True)
        if f.bound_args:
            args = f.bound_args + list(args)
        if not f.arrow:
            sc.vars["this"] = f.bound_this if f.bound_this is not None else (this if this is not UNDEF else self.glob)
            sc.vars["arguments"] = JSArr(args)
        if f.name and node.type == "FunctionExpression" and getattr(node, "id", None) is not None:
            sc.vars.setdefault(f.name, f)
        for i, p in enumerate(node.params):
            if p.type == "RestElement":
                self.bind(p.argument, JSArr(args[i:]), sc, declare=True)
                break
            self.bind(p, args[i] if i < len(args) else UNDEF, sc, declare=True)
        saved = self.source
        self.source = f.src
        self.call_depth += 1
        try:
            if node.type == "ArrowFunctionExpression" and node.expression:
                return self.eval(node.body, sc)
            self.body(node.body.body, sc)
            return UNDEF
        except _Return as r:
            return r.value
        finally:
            self.call_depth -= 1
            self.source = saved

    def construct(self, fn: Any, args: list, node: Any) -> Any:
        if isinstance(fn, Native):
            if fn.ctor is not None:
                return fn.ctor(args, node)
            return fn.fn(UNDEF, args, node)
        if isinstance(fn, JSFunc):
            o = JSObj()
            proto = self.get(fn, "prototype")
            if isinstance(proto, JSObj):
                o.proto = proto
            r = self.call_func(fn, o, args)
            return r if isinstance(r, (JSObj, JSArr, Host, JSFunc)) else o
        if isinstance(fn, Unk):
            if not fn.quiet:
                self.sinks.unresolved_(self.text(node), fn.why, "the type it creates is computed at run time", self.line(node))
            return Unk(f"an object of {self.text(node.callee, 60)}", quiet=fn.quiet)
        if isinstance(fn, Host) and fn.kind == "callable":
            return fn.st["fn"](UNDEF, args, node)
        raise _Throw(Host("Error", message="TypeError: not a constructor"))

    def make_class(self, n: Any, scope: Scope) -> Any:
        ctor = None
        proto = JSObj()
        for m in n.body.body:
            if m.type != "MethodDefinition":
                continue
            name = m.key.name if m.key.type == "Identifier" else to_str(m.key.value)
            f = JSFunc(m.value, scope, self.source, name)
            if m.kind == "constructor":
                ctor = f
            elif not m.static:
                proto[name] = f
        if ctor is None:
            empty = self.parse("(function(){})").body[0].expression
            ctor = JSFunc(empty, scope, "(function(){})", n.id.name if n.id else "")
        ctor.props["prototype"] = proto
        return ctor

    # -- built-in methods ------------------------------------------------------------------------------
    def method(self, o: Any, name: str) -> Any:
        """``o.name`` for strings, arrays, numbers, functions and plain objects."""
        def m(fn: Callable[..., Any]) -> Native:
            return Native(name, lambda this, args, node: fn(this, args, node))
        if isinstance(o, str):
            f = self.string_method(name)
        elif isinstance(o, (list, bytearray)):
            f = self.array_method(name)
        elif isinstance(o, (JSFunc, Native)):
            f = self.func_method(name)
        elif is_num(o):
            f = self.number_method(name)
        elif isinstance(o, JSObj):
            f = {"hasOwnProperty": lambda this, a, n: to_str(a[0]) in this if a else False,
                 "toString": lambda this, a, n: "[object Object]",
                 "valueOf": lambda this, a, n: this}.get(name)
            if name == "constructor":
                return self.builtins["Object"]
        else:
            f = None
        if name == "constructor":
            if isinstance(o, str):
                return self.builtins["String"]
            if isinstance(o, list):
                return self.builtins["Array"]
            if isinstance(o, (JSFunc, Native)):
                return self.builtins["Function"]
            if is_num(o):
                return self.builtins["Number"]
        if f is None:
            return UNDEF
        return m(f)

    def string_method(self, name: str) -> Callable[..., Any] | None:  # noqa: C901
        def char_at(s: str, a: list, n: Any) -> Any:
            if a and isinstance(a[0], Unk):
                return Unk("a character picked at run time", quiet=True)
            i = to_num(a[0]) if a else 0
            i = 0 if i != i or i in (math.inf, -math.inf) else int(i)          # ToIntegerOrInfinity(NaN) = 0
            return s[i] if 0 <= i < len(s) else ""

        def code_at(s: str, a: list, n: Any) -> Any:
            i = to_num(a[0]) if a else 0
            i = 0 if i != i else int(i)
            return ord(s[i]) if 0 <= i < len(s) else math.nan

        def substr(s: str, a: list, n: Any) -> str:
            st = int(to_num(a[0])) if a else 0
            if st < 0:
                st = max(0, len(s) + st)
            ln = len(s) - st if len(a) < 2 or a[1] is UNDEF else max(0, int(to_num(a[1])))
            return self.keep(s, s[st:st + ln])

        def substring(s: str, a: list, n: Any) -> str:
            def c(x: Any) -> int:
                v = to_num(x)
                return 0 if v != v else max(0, min(len(s), int(v)))
            st = c(a[0]) if a else 0
            en = len(s) if len(a) < 2 or a[1] is UNDEF else c(a[1])
            if st > en:
                st, en = en, st
            return self.keep(s, s[st:en])

        def slice_(s: Any, a: list, n: Any) -> Any:
            ln = len(s)

            def c(x: Any, d: int) -> int:
                if x is UNDEF:
                    return d
                v = to_num(x)
                v = 0 if v != v else int(v) if v not in (math.inf, -math.inf) else (ln if v > 0 else -ln)
                return max(0, ln + v) if v < 0 else min(v, ln)
            st = c(a[0] if a else UNDEF, 0)
            en = c(a[1] if len(a) > 1 else UNDEF, ln)
            return self.keep(s, s[st:en])

        def split(s: str, a: list, n: Any) -> JSArr:
            sep = a[0] if a else UNDEF
            lim = int(to_num(a[1])) if len(a) > 1 and a[1] is not UNDEF else None
            if sep is UNDEF:
                out = [s]
            elif isinstance(sep, Host) and sep.kind == "RegExp":
                out = [x if x is not None else UNDEF for x in sep.st["re"].split(s)]
                if s == "":
                    out = []
            else:
                sp = to_str(sep)
                if sp == "":
                    out = list(s)
                else:
                    out = s.split(sp)
            if lim is not None:
                out = out[:lim]
            return tag(JSArr(out), rec(s))

        def replace(s: str, a: list, n: Any, every: bool = False) -> str:
            pat = a[0] if a else UNDEF
            rep = a[1] if len(a) > 1 else UNDEF
            if isinstance(pat, Host) and pat.kind == "RegExp":
                rx = pat.st["re"]
                count = 0 if ("g" in pat.st["flags"] or every) else 1
                desc = f"/{pat.st['source'][:30]}/"
            else:
                p = to_str(pat)
                rx = re.compile(re.escape(p))
                count = 0 if every else 1
                desc = repr(p[:30])

            def fn(m: re.Match) -> str:
                if isinstance(rep, (JSFunc, Native)):
                    groups = [g if g is not None else UNDEF for g in m.groups()]
                    return to_str(self.invoke(rep, UNDEF, [m.group(0), *groups, m.start(), s]))
                r = to_str(rep)
                if "$" not in r:
                    return r

                def sub(mm: re.Match) -> str:
                    g = mm.group(1)
                    if g == "$":
                        return "$"
                    if g == "&":
                        return m.group(0)
                    if g == "`":
                        return s[:m.start()]
                    if g == "'":
                        return s[m.end():]
                    if g.isdigit():
                        i = int(g)
                        if 0 < i <= len(m.groups()):
                            return m.group(i) or ""
                    return mm.group(0)
                return re.sub(r"\$(\$|&|`|'|\d{1,2})", sub, r)
            out = rx.sub(fn, s, count=count)
            if len(s) >= 16 and out != s:
                return tag(out, rec(s) + (f"replace({desc} → {to_str(rep)[:12]!r})" if not isinstance(rep, (JSFunc, Native))
                                          else f"replace({desc} → function)",))
            return self.keep(s, out)

        def index_of(s: str, a: list, n: Any) -> int:
            return s.find(to_str(a[0]) if a else "undefined", int(to_num(a[1])) if len(a) > 1 else 0)

        def last_index_of(s: str, a: list, n: Any) -> int:
            return s.rfind(to_str(a[0]) if a else "undefined")

        def match(s: str, a: list, n: Any) -> Any:
            p = a[0] if a else UNDEF
            if not (isinstance(p, Host) and p.kind == "RegExp"):
                p = self.regexp(re.escape(to_str(p)), "")
            rx = p.st["re"]
            if "g" in p.st["flags"]:
                out = [m.group(0) for m in rx.finditer(s)]
                return tag(JSArr(out), rec(s)) if out else None
            m = rx.search(s)
            if not m:
                return None
            r = JSArr([m.group(0), *[g if g is not None else UNDEF for g in m.groups()]])
            return r

        def rep(s: str, a: list, n: Any) -> str:
            k = int(to_num(a[0])) if a else 0
            if len(s) * k > MAX_STR:
                raise Limit("string size")
            return s * k

        table: dict[str, Callable[..., Any]] = {
            "charAt": char_at, "charCodeAt": code_at, "codePointAt": code_at,
            "substr": substr, "substring": substring, "slice": slice_, "split": split,
            "replace": replace, "replaceAll": lambda s, a, n: replace(s, a, n, True),
            "indexOf": index_of, "lastIndexOf": last_index_of,
            "includes": lambda s, a, n: to_str(a[0]) in s if a else False,
            "startsWith": lambda s, a, n: s.startswith(to_str(a[0])) if a else False,
            "endsWith": lambda s, a, n: s.endswith(to_str(a[0])) if a else False,
            "toUpperCase": lambda s, a, n: self.keep(s, s.upper()), "toLowerCase": lambda s, a, n: self.keep(s, s.lower()),
            "toLocaleUpperCase": lambda s, a, n: s.upper(), "toLocaleLowerCase": lambda s, a, n: s.lower(),
            "trim": lambda s, a, n: self.keep(s, s.strip()), "trimStart": lambda s, a, n: s.lstrip(),
            "trimEnd": lambda s, a, n: s.rstrip(),
            "concat": lambda s, a, n: self.keep(s, s + "".join(to_str(x) for x in a)),
            "toString": lambda s, a, n: s, "valueOf": lambda s, a, n: s,
            "match": match, "repeat": rep,
            "search": lambda s, a, n: (lambda m: m.start() if m else -1)(
                (a[0].st["re"] if a and isinstance(a[0], Host) and a[0].kind == "RegExp" else re.compile(re.escape(to_str(a[0]) if a else ""))).search(s)),
            "padStart": lambda s, a, n: s.rjust(int(to_num(a[0])), to_str(a[1])[:1] if len(a) > 1 else " "),
            "padEnd": lambda s, a, n: s.ljust(int(to_num(a[0])), to_str(a[1])[:1] if len(a) > 1 else " "),
            "normalize": lambda s, a, n: s, "localeCompare": lambda s, a, n: (s > to_str(a[0])) - (s < to_str(a[0])),
        }
        return table.get(name)

    def keep(self, src: Any, out: Any) -> Any:
        """A part of ``src`` keeps its recipe when it is still a payload."""
        r = rec(src)
        if r and isinstance(out, (str, list, bytearray)) and len(out) >= 16:
            return tag(out, r)
        return out

    def array_method(self, name: str) -> Callable[..., Any] | None:  # noqa: C901
        def fn_of(a: list) -> Any:
            return a[0] if a else UNDEF

        def map_(arr: list, a: list, n: Any) -> Any:
            f = fn_of(a)
            out = [self.invoke(f, UNDEF, [x, i, arr]) for i, x in enumerate(list(arr))]
            res = JSArr(out)
            op = self.fn_op(f)
            return tag(res, rec(arr) + ((op,) if op and len(arr) >= 16 else ())) if rec(arr) or (op and len(arr) >= 16) else res

        def foreach(arr: list, a: list, n: Any) -> Any:
            f = fn_of(a)
            before = []
            if isinstance(f, JSFunc):
                before = [(t, s, op, rec(arr)) for t, s, op in self._loop_targets(f.node.body)]
            for i, x in enumerate(list(arr)):
                self.invoke(f, UNDEF, [x, i, arr])
            if isinstance(f, JSFunc) and before:
                self._loop_after(before, f.closure)
            return UNDEF

        def filter_(arr: list, a: list, n: Any) -> Any:
            f = fn_of(a)
            return self.keep(arr, JSArr(x for i, x in enumerate(list(arr)) if truthy(self.invoke(f, UNDEF, [x, i, arr]))))

        def reduce_(arr: list, a: list, n: Any, right: bool = False) -> Any:
            f = fn_of(a)
            items = list(enumerate(arr))
            if right:
                items.reverse()
            if len(a) > 1:
                acc = a[1]
            else:
                if not items:
                    raise _Throw(Host("Error", message="TypeError: reduce of empty array"))
                acc = items.pop(0)[1]
            for i, x in items:
                acc = self.invoke(f, UNDEF, [acc, x, i, arr])
            op = self.fn_op(f)
            if isinstance(acc, (str, list)) and len(acc) >= 16 and (rec(arr) or op):
                acc = tag(acc, rec(arr) + ((op,) if op else ()))
            return acc

        def join(arr: list, a: list, n: Any) -> str:
            sep = "," if not a or a[0] is UNDEF else to_str(a[0])
            if isinstance(arr, bytearray):
                out = sep.join(str(x) for x in arr)
            else:
                out = sep.join("" if x is None or x is UNDEF else to_str(self.prim(x)) for x in arr)
            if len(out) > MAX_STR:
                raise Limit("string size")
            return tag(out, rec(arr)) if rec(arr) and len(out) >= 16 else out

        def reverse(arr: list, a: list, n: Any) -> Any:
            arr.reverse()
            if len(arr) >= 16:
                try:
                    arr.recipe = rec(arr) + ("reverse",)
                except AttributeError:
                    pass
            return arr

        def push(arr: list, a: list, n: Any) -> int:
            if isinstance(arr, bytearray):
                arr.extend(to_int32(x) & 0xFF for x in a)
            else:
                arr.extend(a)
            if len(arr) > MAX_LOOP:
                raise Limit("array size")
            return len(arr)

        def pop(arr: list, a: list, n: Any) -> Any:
            return arr.pop() if arr else UNDEF

        def shift(arr: list, a: list, n: Any) -> Any:
            return arr.pop(0) if arr else UNDEF

        def unshift(arr: list, a: list, n: Any) -> int:
            arr[0:0] = a
            return len(arr)

        def slice_(arr: list, a: list, n: Any) -> Any:
            ln = len(arr)

            def c(x: Any, d: int) -> int:
                if x is UNDEF:
                    return d
                v = int(to_num(x))
                return max(0, ln + v) if v < 0 else min(v, ln)
            st = c(a[0] if a else UNDEF, 0)
            en = c(a[1] if len(a) > 1 else UNDEF, ln)
            out = arr[st:en]
            out = JSBytes(out) if isinstance(arr, bytearray) else JSArr(out)
            return self.keep(arr, out)

        def splice(arr: list, a: list, n: Any) -> Any:
            ln = len(arr)
            st = int(to_num(a[0])) if a else 0
            st = max(0, ln + st) if st < 0 else min(st, ln)
            dc = ln - st if len(a) < 2 else max(0, min(int(to_num(a[1])), ln - st))
            removed = arr[st:st + dc]
            arr[st:st + dc] = a[2:]
            return JSArr(removed)

        def concat(arr: list, a: list, n: Any) -> Any:
            out = JSArr(arr)
            for x in a:
                out.extend(x if isinstance(x, list) else [x])
            return self.keep(arr, out)

        def index_of(arr: list, a: list, n: Any) -> int:
            x = a[0] if a else UNDEF
            for i, y in enumerate(arr):
                if self.strict_eq(x, y):
                    return i
            return -1

        def sort(arr: list, a: list, n: Any) -> Any:
            import functools
            if a and isinstance(a[0], (JSFunc, Native)):
                f = a[0]
                arr.sort(key=functools.cmp_to_key(lambda x, y: int(to_num(self.invoke(f, UNDEF, [x, y])) or 0)))
            else:
                arr.sort(key=lambda x: to_str(x))
            return arr

        def fill(arr: list, a: list, n: Any) -> Any:
            v = a[0] if a else UNDEF
            for i in range(len(arr)):
                arr[i] = (to_int32(v) & 0xFF) if isinstance(arr, bytearray) else v
            return arr

        def find(arr: list, a: list, n: Any, idx: bool = False) -> Any:
            f = fn_of(a)
            for i, x in enumerate(list(arr)):
                if truthy(self.invoke(f, UNDEF, [x, i, arr])):
                    return i if idx else x
            return -1 if idx else UNDEF

        def subarray(arr: Any, a: list, n: Any) -> Any:
            return slice_(arr, a, n)

        table: dict[str, Callable[..., Any]] = {
            "map": map_, "forEach": foreach, "filter": filter_, "reduce": reduce_,
            "reduceRight": lambda arr, a, n: reduce_(arr, a, n, True),
            "join": join, "reverse": reverse, "push": push, "pop": pop, "shift": shift, "unshift": unshift,
            "slice": slice_, "subarray": subarray, "splice": splice, "concat": concat, "indexOf": index_of,
            "includes": lambda arr, a, n: index_of(arr, a, n) >= 0, "sort": sort, "fill": fill,
            "find": find, "findIndex": lambda arr, a, n: find(arr, a, n, True),
            "some": lambda arr, a, n: any(truthy(self.invoke(a[0], UNDEF, [x, i, arr])) for i, x in enumerate(list(arr))),
            "every": lambda arr, a, n: all(truthy(self.invoke(a[0], UNDEF, [x, i, arr])) for i, x in enumerate(list(arr))),
            "toString": lambda arr, a, n: to_str(arr), "keys": lambda arr, a, n: JSArr(range(len(arr))),
            "flat": lambda arr, a, n: JSArr(y for x in arr for y in (x if isinstance(x, list) else [x])),
            "set": lambda arr, a, n: self._typed_set(arr, a),
        }
        return table.get(name)

    def _typed_set(self, arr: Any, a: list) -> Any:
        src = bin_of(a[0]) if a else b""
        off = int(to_num(a[1])) if len(a) > 1 else 0
        if isinstance(arr, bytearray) and src is not None:
            need = off + len(src)
            if need > len(arr):
                arr.extend(b"\x00" * (need - len(arr)))
            arr[off:need] = src
            try:
                arr.recipe = rec(a[0])
            except AttributeError:
                pass
        return UNDEF

    def fn_op(self, f: Any) -> str:
        if not isinstance(f, JSFunc):
            return ""
        node = f.node
        params = [p.name for p in node.params if p.type == "Identifier"]
        body = node.body
        if not params:
            return ""
        lab = self.op_label(body, params[0])
        return lab if lab not in ("char loop",) else ""

    def func_method(self, name: str) -> Callable[..., Any] | None:
        def call(f: Any, a: list, n: Any) -> Any:
            return self.invoke(f, a[0] if a else UNDEF, a[1:], n)

        def apply(f: Any, a: list, n: Any) -> Any:
            args = list(self.iterate(a[1])) if len(a) > 1 and isinstance(a[1], (list, bytearray)) else []
            if isinstance(f, Native) and f.name == "String.fromCharCode" and len(a) > 1:
                r = self.from_char_code(args)
                return tag(r, rec(a[1]) + ("char codes",)) if len(r) >= 16 else r
            return self.invoke(f, a[0] if a else UNDEF, args, n)

        def bind(f: Any, a: list, n: Any) -> Any:
            if isinstance(f, JSFunc):
                g = JSFunc(f.node, f.closure, f.src, f.name, f.arrow, a[0] if a else UNDEF)
                g.bound_args = f.bound_args + list(a[1:])
                return g
            return Native(getattr(f, "name", "bound"), lambda this, args, node: self.invoke(f, a[0] if a else UNDEF, list(a[1:]) + list(args), node))
        return {"call": call, "apply": apply, "bind": bind,
                "toString": lambda f, a, n: to_str(f)}.get(name)

    def number_method(self, name: str) -> Callable[..., Any] | None:
        def to_string(x: Any, a: list, n: Any) -> str:
            radix = int(to_num(a[0])) if a and a[0] is not UNDEF else 10
            if radix == 10 or not float(x).is_integer():
                return num_str(x)
            v = int(x)
            neg = v < 0
            v = abs(v)
            digits = "0123456789abcdefghijklmnopqrstuvwxyz"
            out = ""
            while True:
                out = digits[v % radix] + out
                v //= radix
                if not v:
                    break
            return ("-" if neg else "") + out
        return {"toString": to_string, "toFixed": lambda x, a, n: f"{x:.{int(to_num(a[0])) if a else 0}f}",
                "valueOf": lambda x, a, n: x}.get(name)

    def from_char_code(self, codes: list) -> str:
        if len(codes) > MAX_STR:
            raise Limit("string size")
        return "".join(chr(to_uint32(c) & 0xFFFF) for c in codes)

    # -- the global library ----------------------------------------------------------------------------
    def _builtins(self) -> dict[str, Any]:  # noqa: C901, PLR0915
        B: dict[str, Any] = {}

        def nat(name: str, fn: Callable[..., Any], ctor: Callable[..., Any] | None = None, **props: Any) -> Native:
            return Native(name, fn, ctor, props)

        def a0(a: list) -> Any:
            return a[0] if a else UNDEF

        # -- decoding
        def atob(this: Any, a: list, n: Any) -> Any:
            s = a0(a)
            if isinstance(s, Unk):
                return Unk(s.why, s.recipe + ("base64",))
            try:
                return step(s, "base64", latin(T.b64decode(to_str(s))))
            except T.TransformError as exc:
                raise _Throw(Host("Error", message=f"InvalidCharacterError: {exc}")) from exc

        def btoa(this: Any, a: list, n: Any) -> Any:
            return step(a0(a), "base64 encode", base64.b64encode(bin_of(to_str(a0(a))) or b"").decode())

        def unescape(this: Any, a: list, n: Any) -> Any:
            s = to_str(a0(a))
            out = re.sub(r"%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1) or m.group(2), 16)), s)
            return step(a0(a), "unescape", out) if out != s else s

        def uri_decode(this: Any, a: list, n: Any) -> Any:
            s = to_str(a0(a))
            try:
                out = urllib.parse.unquote(s, errors="strict")
            except UnicodeDecodeError as exc:
                raise _Throw(Host("Error", message="URIError: malformed URI")) from exc
            return step(a0(a), "url decode", out) if out != s else s

        def parse_int(this: Any, a: list, n: Any) -> Any:
            s = to_str(a0(a)).strip()
            radix = int(to_num(a[1])) if len(a) > 1 and a[1] is not UNDEF else 0
            sign = 1
            if s[:1] in "+-" and s:
                sign = -1 if s[0] == "-" else 1
                s = s[1:]
            if radix in (0, 16) and s[:2].lower() == "0x":
                s, radix = s[2:], 16
            radix = radix or 10
            if not 2 <= radix <= 36:
                return math.nan
            digits = "0123456789abcdefghijklmnopqrstuvwxyz"[:radix]
            m = 0
            while m < len(s) and s[m].lower() in digits:
                m += 1
            if m == 0:
                return math.nan
            return sign * int(s[:m], radix)

        def parse_float(this: Any, a: list, n: Any) -> Any:
            m = re.match(r"\s*([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)", to_str(a0(a)))
            return norm(float(m.group(1))) if m else math.nan

        B["atob"] = nat("atob", atob)
        B["btoa"] = nat("btoa", btoa)
        B["unescape"] = nat("unescape", unescape)
        B["escape"] = nat("escape", lambda t, a, n: urllib.parse.quote(to_str(a0(a)), safe="@*_+-./"))
        B["decodeURIComponent"] = nat("decodeURIComponent", uri_decode)
        B["decodeURI"] = nat("decodeURI", uri_decode)
        B["encodeURIComponent"] = nat("encodeURIComponent", lambda t, a, n: urllib.parse.quote(to_str(a0(a)), safe="!'()*-._~"))
        B["encodeURI"] = nat("encodeURI", lambda t, a, n: urllib.parse.quote(to_str(a0(a)), safe="!#$&'()*+,-./:;=?@_~"))
        B["parseInt"] = nat("parseInt", parse_int)
        B["parseFloat"] = nat("parseFloat", parse_float)
        B["isNaN"] = nat("isNaN", lambda t, a, n: to_num(a0(a)) != to_num(a0(a)))
        B["isFinite"] = nat("isFinite", lambda t, a, n: to_num(a0(a)) not in (math.inf, -math.inf) and to_num(a0(a)) == to_num(a0(a)))

        # -- constructors
        def from_char_code(this: Any, a: list, n: Any) -> Any:
            u = next((x for x in a if isinstance(x, Unk)), None)
            if u is not None:                 # a code not known statically: so is the text
                return Unk(u.why, u.recipe)
            out = self.from_char_code(a)
            return tag(out, ("char codes",)) if len(out) >= 16 else out

        def string_(this: Any, a: list, n: Any) -> Any:
            return to_str(self.prim(a0(a))) if a else ""
        B["String"] = nat("String", string_, None,
                          fromCharCode=nat("String.fromCharCode", from_char_code),
                          fromCodePoint=nat("String.fromCodePoint", lambda t, a, n: "".join(chr(int(to_num(x))) for x in a)),
                          raw=nat("String.raw", lambda t, a, n: ""))

        def array_(this: Any, a: list, n: Any) -> Any:
            if len(a) == 1 and is_num(a[0]):
                return JSArr([UNDEF] * min(int(a[0]), MAX_LOOP))
            return JSArr(a)
        B["Array"] = nat("Array", array_, lambda a, n: array_(UNDEF, a, n),
                         isArray=nat("Array.isArray", lambda t, a, n: isinstance(a0(a), list)),
                         **{"from": nat("Array.from", lambda t, a, n: self.array_from(a)),
                            "of": nat("Array.of", lambda t, a, n: JSArr(a))})
        B["Object"] = nat("Object", lambda t, a, n: a0(a) if a and isinstance(a0(a), (dict, list)) else JSObj(),
                          lambda a, n: JSObj(),
                          keys=nat("Object.keys", lambda t, a, n: JSArr(list(a0(a).keys()) if isinstance(a0(a), dict) else [str(i) for i in range(len(a0(a)))] if isinstance(a0(a), (list, str)) else [])),
                          values=nat("Object.values", lambda t, a, n: JSArr(self.iterate(a0(a)))),
                          entries=nat("Object.entries", lambda t, a, n: JSArr(JSArr([k, v]) for k, v in (a0(a).items() if isinstance(a0(a), dict) else []))),
                          assign=nat("Object.assign", lambda t, a, n: self._assign(a)),
                          defineProperty=nat("Object.defineProperty", lambda t, a, n: self._define(a)),
                          create=nat("Object.create", lambda t, a, n: self._create(a)),
                          freeze=nat("Object.freeze", lambda t, a, n: a0(a)),
                          getOwnPropertyNames=nat("Object.getOwnPropertyNames", lambda t, a, n: JSArr(list(a0(a).keys()) if isinstance(a0(a), dict) else [])),
                          prototype=JSObj())
        B["Number"] = nat("Number", lambda t, a, n: to_num(self.prim(a0(a))) if a else 0, None,
                          parseInt=nat("parseInt", parse_int), parseFloat=nat("parseFloat", parse_float),
                          isInteger=nat("Number.isInteger", lambda t, a, n: is_num(a0(a)) and float(a0(a)).is_integer()),
                          MAX_SAFE_INTEGER=2 ** 53 - 1)
        B["Boolean"] = nat("Boolean", lambda t, a, n: truthy(a0(a)))
        B["Function"] = nat("Function", lambda t, a, n: self.new_function(a, n), lambda a, n: self.new_function(a, n))
        B["eval"] = nat("eval", lambda t, a, n: self.do_eval(a0(a), self.called_as("eval", n), self.line(n), want=True))
        B["RegExp"] = nat("RegExp", lambda t, a, n: self.new_regexp(a), lambda a, n: self.new_regexp(a))
        B["Error"] = nat("Error", lambda t, a, n: Host("Error", message=to_str(a0(a)) if a else ""),
                         lambda a, n: Host("Error", message=to_str(a0(a)) if a else ""))
        for e in ("TypeError", "RangeError", "SyntaxError", "ReferenceError"):
            B[e] = B["Error"]
        B["Date"] = nat("Date", lambda t, a, n: Unk("the current date"),
                        lambda a, n: Host("Date", args=a), now=nat("Date.now", lambda t, a, n: Unk("the current date")))
        B["Math"] = self._math()
        B["JSON"] = Host("JSON")
        B["Symbol"] = nat("Symbol", lambda t, a, n: Host("Symbol"), iterator="@@iterator")
        B["Map"] = nat("Map", lambda t, a, n: Host("Map", items=[], d={}), lambda a, n: Host("Map", items=[], d={}))
        B["Set"] = nat("Set", lambda t, a, n: Host("Set", items=list(self.iterate(a0(a))) if a else []),
                       lambda a, n: Host("Set", items=list(dict.fromkeys(self.iterate(a0(a)))) if a else []))
        B["Promise"] = nat("Promise", lambda t, a, n: Host("Promise", value=UNDEF), lambda a, n: self._promise(a),
                           resolve=nat("Promise.resolve", lambda t, a, n: Host("Promise", value=a0(a))))
        for tname in ("Uint8Array", "Int8Array", "Uint8ClampedArray"):
            B[tname] = nat(tname, lambda t, a, n: self.typed_array(a), lambda a, n: self.typed_array(a),
                           **{"from": nat("Uint8Array.from", lambda t, a, n: self.typed_array([self.array_from(a)]))})
        B["ArrayBuffer"] = nat("ArrayBuffer", lambda t, a, n: JSBytes(int(to_num(a0(a)))), lambda a, n: JSBytes(min(int(to_num(a0(a))), MAX_LOOP)))
        B["DataView"] = nat("DataView", lambda t, a, n: a0(a), lambda a, n: a0(a))
        B["TextDecoder"] = nat("TextDecoder", lambda t, a, n: Host("TextDecoder", enc=to_str(a0(a)) if a else "utf-8"),
                               lambda a, n: Host("TextDecoder", enc=to_str(a0(a)) if a else "utf-8"))
        B["TextEncoder"] = nat("TextEncoder", lambda t, a, n: Host("TextEncoder"), lambda a, n: Host("TextEncoder"))
        B["Blob"] = nat("Blob", lambda t, a, n: self.blob(a), lambda a, n: self.blob(a))
        B["XMLHttpRequest"] = nat("XMLHttpRequest", lambda t, a, n: Host("HTTP", progid="XMLHttpRequest"),
                                  lambda a, n: Host("HTTP", progid="XMLHttpRequest"))
        B["ActiveXObject"] = nat("ActiveXObject", lambda t, a, n: self.com(a0(a), n), lambda a, n: self.com(a0(a), n))
        B["GetObject"] = nat("GetObject", lambda t, a, n: self.com(a0(a), n))
        B["WScript"] = Host("WScript")
        B["WSH"] = B["WScript"]
        B["document"] = Host("document")
        B["location"] = Host("location")
        B["navigator"] = Host("navigator")
        B["console"] = Host("console")
        B["localStorage"] = Host("storage", d={})
        B["sessionStorage"] = Host("storage", d={})
        B["fetch"] = nat("fetch", lambda t, a, n: self.fetch(a, n))
        B["setTimeout"] = nat("setTimeout", lambda t, a, n: self.timer(a, n, "setTimeout"))
        B["setInterval"] = nat("setInterval", lambda t, a, n: self.timer(a, n, "setInterval"))
        B["setImmediate"] = nat("setImmediate", lambda t, a, n: self.timer(a, n, "setImmediate"))
        B["clearTimeout"] = B["clearInterval"] = nat("clearTimeout", lambda t, a, n: UNDEF)
        B["alert"] = B["confirm"] = B["prompt"] = nat("alert", lambda t, a, n: UNDEF)
        B["require"] = nat("require", lambda t, a, n: self.require(to_str(a0(a))))
        B["process"] = Host("process")
        B["Buffer"] = Host("Buffer")
        B["CryptoJS"] = Host("CryptoJS")
        B["pako"] = Host("pako")
        B["module"] = JSObj(exports=JSObj())
        B["exports"] = B["module"]["exports"]
        B["Enumerator"] = nat("Enumerator", lambda t, a, n: Host("Enumerator", items=list(self.iterate(a0(a))), i=0),
                              lambda a, n: Host("Enumerator", items=list(self.iterate(a0(a))), i=0))
        self.statics = {"String": B["String"].props}
        return B

    def _assign(self, a: list) -> Any:
        t = a[0] if a else JSObj()
        for s in a[1:]:
            if isinstance(s, dict) and isinstance(t, dict):
                t.update(s)
        return t

    def _define(self, a: list) -> Any:
        if len(a) >= 3 and isinstance(a[0], dict) and isinstance(a[2], dict):
            d = a[2]
            if "value" in d:
                a[0][to_str(a[1])] = d["value"]
            elif isinstance(d.get("get"), JSFunc):
                a[0][to_str(a[1])] = self.call_func(d["get"], a[0], [])
        return a[0] if a else UNDEF

    def _create(self, a: list) -> Any:
        o = JSObj()
        if a and isinstance(a[0], JSObj):
            o.proto = a[0]
        return o

    def _promise(self, a: list) -> Any:
        p = Host("Promise", value=UNDEF)
        f = a[0] if a else UNDEF
        if isinstance(f, (JSFunc, Native)):
            def res(this: Any, args: list, n: Any) -> Any:
                p.st["value"] = args[0] if args else UNDEF
                return UNDEF
            self.invoke(f, UNDEF, [Native("resolve", res), Native("reject", lambda t, a, n: UNDEF)])
        return p

    def _math(self) -> Host:
        h = Host("Math")
        h.props.update({"PI": math.pi, "E": math.e})
        return h

    def array_from(self, a: list) -> Any:
        src = a[0] if a else UNDEF
        f = a[1] if len(a) > 1 else None
        if isinstance(src, dict) and "length" in src:
            items = [src.get(str(i), UNDEF) for i in range(int(to_num(src["length"])))]
        else:
            items = list(self.iterate(src))
        if isinstance(f, (JSFunc, Native)):
            items = [self.invoke(f, UNDEF, [x, i]) for i, x in enumerate(items)]
        return tag(JSArr(items), rec(src)) if rec(src) else JSArr(items)

    def typed_array(self, a: list) -> Any:
        src = a[0] if a else 0
        if is_num(src):
            return JSBytes(min(int(src), MAX_STR))
        if isinstance(src, Unk):
            return src
        b = bin_of(src) if not isinstance(src, str) else None
        if b is None:
            b = bytes(to_int32(x) & 0xFF for x in self.iterate(src))
        return tag(JSBytes(b), rec(src))

    def blob(self, a: list) -> Any:
        parts = list(self.iterate(a[0])) if a else []
        data = bytearray()
        r: tuple = ()
        for p in parts:
            if isinstance(p, Unk):
                return Host("Blob", data=p)
            b = bin_of(p) if not isinstance(p, str) else p.encode("utf-8")
            data += b or b""
            r = r or rec(p)
        opts = a[1] if len(a) > 1 and isinstance(a[1], dict) else {}
        return Host("Blob", data=tag(JSBytes(data), r), mime=to_str(opts.get("type", "")))

    def new_regexp(self, a: list) -> Any:
        p = a[0] if a else ""
        if isinstance(p, Host) and p.kind == "RegExp":
            return self.regexp(p.st["source"], to_str(a[1]) if len(a) > 1 else p.st["flags"])
        return self.regexp(to_str(p), to_str(a[1]) if len(a) > 1 and a[1] is not UNDEF else "")

    def new_function(self, a: list, node: Any) -> Any:
        if any(isinstance(x, Unk) for x in a):
            u = next(x for x in a if isinstance(x, Unk))
            self.sinks.exec_(Value.unknown(u.why), self.called_as("Function", node), self.line(node))
            return Unk(f"a function built from {u.why}")
        params = [to_str(x) for x in a[:-1]]
        body = a[-1] if a else ""
        code = to_str(body)
        r = rec(body)
        self.sinks.exec_(Value("str", code, r), self.called_as("Function", node), self.line(node))
        src = f"(function anonymous({','.join(params)}\n) {{\n{code}\n}})"
        try:
            prog = self.parse(src)
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"line {self.line(node)}: Function of code that does not parse: {exc}"[:300])
            return Native("anonymous", lambda t, a2, n2: UNDEF)
        f = JSFunc(prog.body[0].expression, self.gscope, src, "anonymous")
        outer = self

        def run(this: Any, args: list, n: Any) -> Any:
            outer.depth += 1
            outer.sinks.depth = outer.depth
            try:
                if outer.depth > MAX_DEPTH:
                    return UNDEF
                return outer.call_func(f, this, args)
            finally:
                outer.depth -= 1
                outer.sinks.depth = outer.depth
        return Native("anonymous", run)

    def do_eval(self, code: Any, sink: str, line: int | None, want: bool = False, scope: Scope | None = None) -> Any:
        if isinstance(code, Unk):
            self.sinks.exec_(Value.unknown(code.why), sink, line)
            return Unk(f"the result of code computed from {code.why}")
        if not isinstance(code, str):
            return code
        text = str(code)
        self.sinks.exec_(Value("str", text, rec(code)), sink, line)
        h = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if self.depth >= MAX_DEPTH or (h in self.ran and not want):
            return UNDEF
        self.ran.add(h)
        try:
            prog = self.parse(text)
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"line {line}: {sink} of code that does not parse: {exc}"[:300])
            return UNDEF
        self.depth += 1
        self.sinks.depth = self.depth
        saved, saved_last = self.source, self.last
        self.source = text
        self.last = UNDEF
        try:
            self.body(prog.body, scope or self.gscope, top=True)
            return self.last
        finally:
            self.source, self.last = saved, saved_last
            self.depth -= 1
            self.sinks.depth = self.depth

    def timer(self, a: list, node: Any, name: str) -> Any:
        f = a[0] if a else UNDEF
        if isinstance(f, (str, Unk)):
            self.do_eval(f, self.called_as(name, node), self.line(node))
        elif isinstance(f, (JSFunc, Native)):
            try:
                self.invoke(f, UNDEF, list(a[2:]), node)
            except _Throw:
                pass
        return 1

    def fetch(self, a: list, node: Any) -> Any:
        url = a[0] if a else UNDEF
        self.download(url, "fetch", "returns it to the script", self.line(node))
        why = f"the content downloaded from {to_str(url) if not isinstance(url, Unk) else url.why}"
        resp = Host("Response", why=why)
        return Host("Promise", value=resp)

    def download(self, url: Any, method: str, use: str, line: int | None, dest: str = "") -> None:
        if isinstance(url, Unk):
            self.sinks.download(Value.unknown(url.why), method, use, line, dest)
        else:
            self.sinks.download(Value("str", to_str(url), rec(url)), method, use, line, dest)

    def launch(self, cmd: Any, via: str, node: Any) -> Any:
        line = self.line(node)
        if isinstance(cmd, Unk):
            if cmd.why.startswith("the content downloaded from "):
                self.sinks.exec_(Value.unknown(cmd.why), via, line)
            else:
                self.sinks.unresolved_(self.text(node), cmd.why, "the command it runs is computed at run time", line)
            return 0
        text = to_str(cmd)
        if not commands.launch(self.sinks, text, rec(cmd), line, via):
            for d in self.sinks.downloads:
                dest = d.get("saved_to") or ""
                if dest and dest.lower().rsplit("\\", 1)[-1] in text.lower():
                    d["use"] = d["use"] + f", then runs it ({via})" if "runs it" not in d["use"] else d["use"]
            if len(text) > 120:
                n = len(self.sinks.stages)
                self.sinks.exec_(Value("str", text, rec(cmd)), via, line)
                if len(self.sinks.stages) > n:
                    self.sinks.stages[-1].ext = ".bat"
        return 0

    # -- Node ----------------------------------------------------------------------------------------
    def require(self, name: str) -> Any:
        name = name.removeprefix("node:")
        if name == "child_process":
            return Host("child_process")
        if name in ("fs", "fs/promises"):
            return Host("fs")
        if name in ("http", "https", "axios", "node-fetch", "request"):
            return Host("http", mod=name)
        if name == "zlib":
            return Host("zlib")
        if name == "crypto":
            return Host("nodecrypto")
        if name in ("crypto-js",):
            return self.builtins["CryptoJS"]
        if name == "pako":
            return self.builtins["pako"]
        if name in ("os", "path", "util", "process"):
            return Host(name)
        return Unk(f"the module '{name}' ({_LIB_UNKNOWN})", quiet=True)

    # -- COM objects -----------------------------------------------------------------------------------
    def com(self, progid: Any, node: Any) -> Any:
        if isinstance(progid, Unk):
            self.sinks.unresolved_(self.text(node), progid.why, "the COM object it creates is named at run time", self.line(node))
            return Unk(f"a COM object named from {progid.why}")
        p = to_str(progid).lower().strip()
        self.sinks.step(self.line(node), "creates COM object", Value("str", to_str(progid), rec(progid)))
        if p == "wscript.shell":
            return Host("Shell")
        if p == "scripting.filesystemobject":
            return Host("FSO")
        if p.startswith("adodb.stream"):
            return Host("Stream", type=2, data=None, text="", charset="unicode", pos=0)
        if "xmldom" in p or "domdocument" in p:
            return Host("XMLDOM")
        if "xmlhttp" in p or "winhttprequest" in p or "serverxmlhttp" in p:
            return Host("HTTP", progid=to_str(progid))
        if p == "shell.application":
            return Host("ShellApp")
        if p in ("scripting.dictionary",):
            return Host("Dictionary", d={})
        if p == "vbscript.regexp":
            return Host("VBRegExp")
        if p.startswith("winmgmts") or p.startswith("wbemscripting"):
            return Host("WMI")
        return Host("COM", progid=to_str(progid))

    # -- host objects: properties ----------------------------------------------------------------------
    def host_get(self, h: Host, k: str, node: Any) -> Any:  # noqa: C901, PLR0911, PLR0912
        if k in h.props:
            return h.props[k]
        kl = k.lower()
        kind = h.kind
        if kind == "global":
            s = self.gscope.find(k)
            if s is not None:
                return s.vars[k]
            if k in self.builtins:
                return self.builtins[k]
            if k in ("window", "self", "globalThis", "top", "parent"):
                return self.glob
            return Unk(f"'{k}' ({_LIB_UNKNOWN})", quiet=True)
        if kind == "Math":
            return self.math_fn(k)
        if kind == "JSON":
            return self.json_fn(k)

        def mth(fn: Callable[..., Any]) -> Native:
            return Native(f"{kind}.{k}", lambda this, args, n: fn(args, n))
        if kind == "WScript":
            if kl in ("createobject",):
                return mth(lambda a, n: self.com(a[0] if a else "", n))
            if kl == "getobject":
                return mth(lambda a, n: self.com(a[0] if a else "", n))
            if kl in ("echo", "sleep", "stdout", "disconnectobject", "connectobject"):
                return mth(lambda a, n: UNDEF) if kl != "stdout" else Host("console")
            if kl == "quit":
                def q(a: list, n: Any) -> Any:
                    raise _Quit()
                return mth(q)
            if kl in ("scriptfullname", "fullname"):
                return self.script_path if kl == "scriptfullname" else "C:\\Windows\\System32\\wscript.exe"
            if kl == "scriptname":
                return "script.js"
            if kl == "arguments":
                return Host("WArgs")
            return Unk(f"WScript.{k}", quiet=True)
        if kind == "WArgs":
            if kl in ("length", "count"):
                return 0
            return mth(lambda a, n: Unk("the script's command-line arguments"))
        if kind == "Shell":
            return self.shell_get(h, k, kl, mth)
        if kind == "FSO":
            return self.fso_get(h, k, kl, mth)
        if kind == "TextStream":
            if kl in ("write", "writeline"):
                def w(a: list, n: Any) -> Any:
                    v = a[0] if a else ""
                    if isinstance(v, Unk):
                        h.st["unk"] = v
                    else:
                        h.st["text"] = h.st.get("text", "") + to_str(v) + ("\r\n" if kl == "writeline" else "")
                        h.st["rec"] = h.st.get("rec") or rec(v)
                    return UNDEF
                return mth(w)
            if kl == "close":
                def c(a: list, n: Any) -> Any:
                    self._flush_text(h, n)
                    return UNDEF
                return mth(c)
            if kl in ("readall", "readline", "read"):
                if h.st.get("me"):
                    # the script reads its own file: that is the source analysed here
                    return mth(lambda a, n: tag(self.top_source, ("the script's own file",)))
                return mth(lambda a, n: Unk(f"the content of {h.st.get('path')} (a file on the victim's machine)"))
            if kl == "atendofstream":
                return True
            return UNDEF
        if kind == "Stream":
            return self.stream_get(h, k, kl, mth)
        if kind == "XMLDOM":
            if kl == "createelement":
                return mth(lambda a, n: Host("XMLElem", dtype="", text=""))
            if kl in ("loadxml", "load"):
                return mth(lambda a, n: True)
            return mth(lambda a, n: UNDEF)
        if kind == "XMLElem":
            if kl == "nodetypedvalue":
                return self.xml_typed(h)
            if kl in ("text", "nodevalue"):
                return h.st.get("text", "")
            if kl == "datatype":
                return h.st.get("dtype", "")
            return UNDEF
        if kind == "HTTP":
            return self.http_get(h, k, kl, mth)
        if kind == "Response":
            why = h.st["why"]
            if k in ("text", "json", "arrayBuffer", "blob"):
                return mth(lambda a, n: Host("Promise", value=Unk(why)))
            return Unk(why)
        if kind == "Promise":
            if k == "then":
                def then(a: list, n: Any) -> Any:
                    f = a[0] if a else UNDEF
                    if isinstance(f, (JSFunc, Native)):
                        r = self.invoke(f, UNDEF, [h.st.get("value", UNDEF)], n)
                        return r if isinstance(r, Host) and r.kind == "Promise" else Host("Promise", value=r)
                    return h
                return mth(then)
            if k in ("catch", "finally"):
                return mth(lambda a, n: h)
            return UNDEF
        if kind == "ShellApp":
            if kl == "shellexecute":
                def se(a: list, n: Any) -> Any:
                    parts = [x for x in a[:2] if x is not UNDEF]
                    if any(isinstance(x, Unk) for x in parts):
                        return self.launch(next(x for x in parts if isinstance(x, Unk)), "Shell.Application.ShellExecute", n)
                    return self.launch(" ".join(to_str(x) for x in parts), "Shell.Application.ShellExecute", n)
                return mth(se)
            if kl == "namespace":
                return mth(lambda a, n: Host("COM", progid="Folder"))
            return mth(lambda a, n: UNDEF)
        if kind == "VBRegExp":                       # VBScript.RegExp: Pattern / Global / IgnoreCase, Replace / Test
            def prop(name: str, default: Any) -> Any:
                return next((v for pk, v in h.props.items() if pk.lower() == name), default)

            def compiled() -> Any:
                pat = prop("pattern", "")
                if isinstance(pat, Unk):
                    return pat
                flags = re.I if truthy(prop("ignorecase", False)) else 0
                try:
                    return re.compile(to_str(pat), flags | (re.M if truthy(prop("multiline", False)) else 0))
                except re.error:
                    return Unk("a VBScript regular expression this engine does not read")
            if kl == "replace":
                def rep(a: list, n: Any) -> Any:
                    rx = compiled()
                    text, by = (a + [UNDEF, UNDEF])[:2]
                    if isinstance(rx, Unk) or isinstance(text, Unk) or isinstance(by, Unk):
                        return next(x for x in (rx, text, by) if isinstance(x, Unk))
                    repl = re.sub(r"\$(\d)", r"\\\1", to_str(by)).replace("$&", "\\g<0>")
                    return rx.sub(repl, to_str(text), count=0 if truthy(prop("global", False)) else 1)
                return mth(rep)
            if kl == "test":
                def test(a: list, n: Any) -> Any:
                    rx = compiled()
                    if isinstance(rx, Unk) or (a and isinstance(a[0], Unk)):
                        return rx if isinstance(rx, Unk) else a[0]
                    return bool(rx.search(to_str(a[0]) if a else ""))
                return mth(test)
            return mth(lambda a, n: UNDEF)
        if kind == "Dictionary":
            if kl in ("add", "item"):
                def add(a: list, n: Any) -> Any:
                    if kl == "add" and len(a) >= 2:
                        h.st["d"][to_str(a[0])] = a[1]
                        return UNDEF
                    return h.st["d"].get(to_str(a[0]) if a else "", UNDEF)
                return mth(add)
            if kl == "exists":
                return mth(lambda a, n: (to_str(a[0]) if a else "") in h.st["d"])
            if kl == "items":
                return mth(lambda a, n: JSArr(h.st["d"].values()))
            if kl == "keys":
                return mth(lambda a, n: JSArr(h.st["d"].keys()))
            if kl == "count":
                return len(h.st["d"])
            return UNDEF
        if kind == "Enumerator":
            if kl == "atend":
                return mth(lambda a, n: h.st["i"] >= len(h.st["items"]))
            if kl == "item":
                return mth(lambda a, n: h.st["items"][h.st["i"]] if h.st["i"] < len(h.st["items"]) else UNDEF)
            if kl == "movenext":
                return mth(lambda a, n: h.st.__setitem__("i", h.st["i"] + 1))
            return UNDEF
        if kind == "document":
            return self.doc_get(h, k, mth)
        if kind == "location":
            if k in ("replace", "assign"):
                return mth(lambda a, n: self.download(a[0] if a else "", f"location.{k}", "navigates the browser to it", self.line(n)))
            if k == "href":
                return h.st.get("href", "about:blank")
            if k in ("hostname", "host"):
                return Unk("the page's own address")
            return ""
        if kind == "navigator":
            if k == "userAgent":
                return Unk("the victim's browser")
            return Unk(f"navigator.{k}", quiet=True)
        if kind == "console":
            return mth(lambda a, n: UNDEF)
        if kind == "storage":
            if k == "getItem":
                return mth(lambda a, n: h.st["d"].get(to_str(a[0]) if a else "", None))
            if k == "setItem":
                return mth(lambda a, n: h.st["d"].__setitem__(to_str(a[0]), a[1] if len(a) > 1 else UNDEF))
            return UNDEF
        if kind == "TextDecoder":
            if k == "decode":
                def dec(a: list, n: Any) -> Any:
                    b = bin_of(a[0]) if a else b""
                    if a and isinstance(a[0], Unk):
                        return Unk(a[0].why, a[0].recipe)
                    enc = h.st.get("enc", "utf-8")
                    return step(a[0], "", T.as_text(b or b"", enc))
                return mth(dec)
            return UNDEF
        if kind == "TextEncoder":
            if k == "encode":
                return mth(lambda a, n: step(a[0] if a else "", "", JSBytes(to_str(a[0] if a else "").encode("utf-8"))))
            return UNDEF
        if kind == "Blob":
            return UNDEF
        if kind in ("Map", "Set"):
            return self.coll_get(h, k, mth)
        if kind == "RegExp":
            if k == "test":
                return mth(lambda a, n: bool(h.st["re"].search(to_str(a[0]) if a else "undefined")))
            if k == "exec":
                def ex(a: list, n: Any) -> Any:
                    s = to_str(a[0]) if a else ""
                    pos = h.st["lastIndex"] if "g" in h.st["flags"] else 0
                    m = h.st["re"].search(s, pos)
                    if not m:
                        h.st["lastIndex"] = 0
                        return None
                    if "g" in h.st["flags"]:
                        h.st["lastIndex"] = m.end() if m.end() > m.start() else m.end() + 1
                    r = JSArr([m.group(0), *[g if g is not None else UNDEF for g in m.groups()]])
                    return r
                return mth(ex)
            if k in ("source", "flags", "lastIndex"):
                return h.st[k]
            if k == "global":
                return "g" in h.st["flags"]
            return UNDEF
        if kind == "Error":
            if k == "message":
                return h.st.get("message", "")
            if k == "stack":
                return ""
            return UNDEF
        if kind == "Date":
            return mth(lambda a, n: Unk("the current date"))
        if kind == "process":
            if k == "env":
                return Host("env")
            if k == "platform":
                return "win32"
            if k == "argv":
                return JSArr(["node", "script.js"])
            if k == "exit":
                def ex2(a: list, n: Any) -> Any:
                    raise _Quit()
                return mth(ex2)
            return UNDEF
        if kind == "env":
            return self.env(k)
        if kind == "os":
            if k in ("tmpdir",):
                return mth(lambda a, n: "%TEMP%")
            if k == "homedir":
                return mth(lambda a, n: "%USERPROFILE%")
            return mth(lambda a, n: Unk(f"os.{k}() on the victim's machine"))
        if kind == "path":
            if k == "join" or k == "resolve":
                return mth(lambda a, n: "\\".join(to_str(x) for x in a))
            if k == "basename":
                return mth(lambda a, n: re.split(r"[\\/]", to_str(a[0]))[-1] if a else "")
            return mth(lambda a, n: to_str(a[0]) if a else "")
        if kind == "child_process":
            if k in ("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"):
                def run(a: list, n: Any) -> Any:
                    cmd = a[0] if a else ""
                    if len(a) > 1 and isinstance(a[1], list) and k.startswith(("spawn", "execFile")):
                        if isinstance(cmd, Unk):
                            return self.launch(cmd, f"child_process.{k}", n)
                        cmd = " ".join([to_str(cmd)] + [to_str(x) for x in a[1]])
                    self.launch(cmd, f"child_process.{k}", n)
                    return Unk("the output of a command")
                return mth(run)
            return UNDEF
        if kind == "fs":
            if k in ("writeFileSync", "writeFile", "appendFileSync", "createWriteStream"):
                def wf(a: list, n: Any) -> Any:
                    path = to_str(a[0]) if a else ""
                    data = a[1] if len(a) > 1 else ""
                    self.write(data, path, f"fs.{k}", n)
                    return UNDEF
                return mth(wf)
            if k in ("readFileSync", "readFile"):
                return mth(lambda a, n: Unk(f"the content of {to_str(a[0]) if a else 'a file'} (a file on the victim's machine)"))
            if k in ("existsSync",):
                return mth(lambda a, n: Unk("whether a file exists on the victim's machine"))
            return mth(lambda a, n: UNDEF)
        if kind == "http":
            if k in ("get", "request", "post"):
                def g(a: list, n: Any) -> Any:
                    url = a[0] if a else ""
                    if isinstance(url, dict):
                        url = to_str(url.get("href") or url.get("url") or f"https://{to_str(url.get('hostname', url.get('host', '')))}{to_str(url.get('path', ''))}")
                    self.download(url, f"{h.st['mod']}.{k}", "returns it to the script", self.line(n))
                    why = f"the content downloaded from {to_str(url) if not isinstance(url, Unk) else url.why}"
                    return Host("Promise", value=JSObj(data=Unk(why)))
                return mth(g)
            return UNDEF
        if kind == "Buffer":
            if k == "from":
                return mth(lambda a, n: self.buffer_from(a))
            if k in ("alloc", "allocUnsafe"):
                return mth(lambda a, n: JSBytes(min(int(to_num(a[0])) if a else 0, MAX_STR)))
            if k == "concat":
                def cc(a: list, n: Any) -> Any:
                    out = JSBytes()
                    r: tuple = ()
                    for x in self.iterate(a[0] if a else []):
                        out += bin_of(x) or b""
                        r = r or rec(x)
                    return tag(out, r)
                return mth(cc)
            if k == "isBuffer":
                return mth(lambda a, n: isinstance(a[0] if a else None, bytearray))
            return UNDEF
        if kind == "zlib":
            ops = {"inflateSync": ("inflate (zlib)", T.zlib_decompress), "inflateRawSync": ("inflate", T.inflate),
                   "gunzipSync": ("gzip", T.gunzip), "unzipSync": ("decompress", T.decompress_any),
                   "brotliDecompressSync": ("brotli", T.brotli_decompress)}
            if k in ops:
                name, fn = ops[k]
                return mth(lambda a, n: self.bytes_op(a[0] if a else b"", name, fn, out=JSBytes))
            return UNDEF
        if kind == "nodecrypto":
            if k in ("createDecipheriv", "createDecipher"):
                return mth(lambda a, n: Host("Decipher", alg=to_str(a[0]) if a else "", key=a[1] if len(a) > 1 else b"",
                                             iv=a[2] if len(a) > 2 else None, buf=bytearray(), rec=()))
            if k == "createHash":
                return mth(lambda a, n: Host("Hash", alg=to_str(a[0]) if a else "sha256", buf=bytearray()))
            return UNDEF
        if kind == "Decipher":
            if k == "update":
                def up(a: list, n: Any) -> Any:
                    d = a[0] if a else b""
                    if isinstance(d, Unk):
                        h.st["unk"] = d
                        return JSBytes()
                    if isinstance(d, str):
                        enc = to_str(a[1]) if len(a) > 1 and a[1] is not UNDEF else "utf8"
                        d2 = T.b64decode(d) if enc == "base64" else bytes.fromhex(d) if enc == "hex" else bin_of(d)
                    else:
                        d2 = bin_of(d)
                    h.st["buf"] += d2 or b""
                    h.st["rec"] = h.st["rec"] or rec(d)
                    h.st["out"] = to_str(a[2]) if len(a) > 2 else ""
                    return JSBytes() if not h.st["out"] else ""
                return mth(up)
            if k == "final":
                return mth(lambda a, n: self.node_decipher(h, to_str(a[0]) if a and a[0] is not UNDEF else h.st.get("out", "")))
            if k == "setAutoPadding":
                return mth(lambda a, n: h)
            return UNDEF
        if kind == "Hash":
            if k == "update":
                def hu(a: list, n: Any) -> Any:
                    h.st["buf"] += bin_of(a[0]) if a and not isinstance(a[0], str) else to_str(a[0] if a else "").encode()
                    return h
                return mth(hu)
            if k == "digest":
                def hd(a: list, n: Any) -> Any:
                    d = T.digest(h.st["alg"], bytes(h.st["buf"]))
                    enc = to_str(a[0]) if a else ""
                    return d.hex() if enc == "hex" else base64.b64encode(d).decode() if enc == "base64" else JSBytes(d)
                return mth(hd)
            return UNDEF
        if kind == "CryptoJS":
            return self.cryptojs_get(h, k, mth)
        if kind == "WordArray":
            if k == "toString":
                return mth(lambda a, n: self.wa_str(h, a[0] if a else None))
            if k == "sigBytes":
                return len(h.st["data"])
            if k == "words":
                d = h.st["data"] + b"\x00" * (-len(h.st["data"]) % 4)
                return JSArr(to_int32(int.from_bytes(d[i:i + 4], "big")) for i in range(0, len(d), 4))
            if k == "concat":
                def wc(a: list, n: Any) -> Any:
                    h.st["data"] += bin_of(a[0]) or b"" if a else b""
                    return h
                return mth(wc)
            if k == "clone":
                return mth(lambda a, n: Host("WordArray", data=h.st["data"], recipe=h.recipe))
            return UNDEF
        if kind == "CJSEnc":
            if k == "parse":
                return mth(lambda a, n: self.cjs_parse(h.st["enc"], a[0] if a else ""))
            if k == "stringify":
                return mth(lambda a, n: self.wa_str(a[0] if a else Host("WordArray", data=b""), h))
            return UNDEF
        if kind == "CJSCipher":
            if k == "decrypt":
                return mth(lambda a, n: self.cjs_decrypt(h.st["alg"], a, n))
            if k == "encrypt":
                return mth(lambda a, n: Host("CipherParams", ct=b""))
            return UNDEF
        if kind == "CipherParams":
            if k == "ciphertext":
                return Host("WordArray", data=h.st["ct"], recipe=h.recipe)
            if k == "toString":
                return mth(lambda a, n: base64.b64encode(h.st["ct"]).decode())
            return UNDEF
        if kind == "pako":
            ops = {"inflate": ("inflate (zlib)", T.decompress_any), "inflateRaw": ("inflate", T.inflate),
                   "ungzip": ("gzip", T.gunzip), "gunzip": ("gzip", T.gunzip)}
            if k in ops:
                name, fn = ops[k]

                def pk(a: list, n: Any) -> Any:
                    opts = a[1] if len(a) > 1 and isinstance(a[1], dict) else {}
                    as_text = to_str(opts.get("to", "")) == "string"
                    return self.bytes_op(a[0] if a else b"", name, fn, out=(str if as_text else JSBytes))
                return mth(pk)
            return UNDEF
        if kind == "WMI":
            if kl == "get" :
                return mth(lambda a, n: Host("WMIClass", name=to_str(a[0]) if a else ""))
            return mth(lambda a, n: Unk("a WMI query on the victim's machine"))
        if kind == "WMIClass":
            if kl == "create" and "win32_process" in h.st.get("name", "").lower():
                return mth(lambda a, n: self.launch(a[0] if a else "", "WMI Win32_Process.Create", n))
            return mth(lambda a, n: Unk("a WMI call on the victim's machine"))
        if kind == "COM":
            return mth(lambda a, n: Unk(f"{h.st.get('progid')}.{k}() on the victim's machine", quiet=True))
        if kind == "Symbol":
            return UNDEF
        return UNDEF

    def host_set(self, h: Host, k: str, v: Any, line: int | None) -> None:
        kl = k.lower()
        if h.kind == "global":
            self.assign_name(k, v, self.gscope, line)
            return
        if h.kind == "XMLElem":
            if kl == "datatype":
                h.st["dtype"] = to_str(v).lower()
            elif kl in ("text", "nodetypedvalue"):
                if kl == "nodetypedvalue":
                    h.st["bytes"] = v
                else:
                    h.st["text"] = v
            return
        if h.kind == "Stream":
            if kl == "type":
                h.st["type"] = int(to_num(v))
            elif kl == "charset":
                h.st["charset"] = to_str(v)
            elif kl == "position":
                h.st["pos"] = int(to_num(v))
            return
        if h.kind == "location" or (h.kind == "document" and kl == "location"):
            if kl in ("href", "location"):
                h.st["href"] = v
                self.download(v, f"location.{k}", "navigates the browser to it", line)
            return
        if h.kind == "document" and kl == "cookie":
            return
        h.props[k] = v

    def doc_get(self, h: Host, k: str, mth: Callable[..., Any]) -> Any:
        if k in ("write", "writeln"):
            def w(a: list, n: Any) -> Any:
                html = "".join(to_str(x) for x in a if not isinstance(x, Unk))
                u = next((x for x in a if isinstance(x, Unk)), None)
                if u is not None and not html:
                    self.sinks.exec_(Value.unknown(u.why), f"document.{k}", self.line(n))
                    return UNDEF
                r = next((rec(x) for x in a if rec(x)), ())
                before = len(self.sinks.stages)
                self.sinks.exec_(Value("str", html, r), self.called_as(f"document.{k}", n), self.line(n))
                if len(self.sinks.stages) > before:
                    self.sinks.stages[-1].ext = ".html"
                return UNDEF
            return mth(w)
        if k == "location":
            return self.builtins["location"]
        if k in ("createElement", "getElementById", "querySelector", "getElementsByTagName", "body", "head",
                 "documentElement"):
            return mth(lambda a, n: Host("Elem", tag=to_str(a[0]) if a else "")) if k not in ("body", "head", "documentElement") \
                else Host("Elem", tag=k)
        if k in ("cookie", "referrer", "domain", "URL"):
            return Unk(f"document.{k} (the page)")
        return Unk(f"document.{k}", quiet=True)

    def shell_get(self, h: Host, k: str, kl: str, mth: Callable[..., Any]) -> Any:
        if kl in ("run", "exec"):
            def run(a: list, n: Any) -> Any:
                self.launch(a[0] if a else "", self.called_as(f"WScript.Shell.{k}", n), n)
                return 0 if kl == "run" else Host("ExecObj")
            return mth(run)
        if kl == "expandenvironmentstrings":
            def exp(a: list, n: Any) -> Any:
                s = a[0] if a else ""
                if isinstance(s, Unk):
                    return s
                m = re.fullmatch(r"\s*%([A-Za-z_][\w()]*)%\s*", to_str(s))
                if m and m.group(1).upper() not in ENV and m.group(1).upper() not in ENV_MACHINE:
                    return Unk(f"the environment variable {m.group(1)}")
                return step(s, "", _expand_env(to_str(s)))
            return mth(exp)
        if kl == "environment":
            return mth(lambda a, n: Host("callable", fn=lambda this, args, n2: self.env(to_str(args[0]) if args else "")))
        if kl == "regread":
            return mth(lambda a, n: Unk(f"the registry value {to_str(a[0]) if a else ''}"))
        if kl in ("regwrite", "regdelete", "popup", "sendkeys", "appactivate", "logevent"):
            def rw(a: list, n: Any) -> Any:
                if kl == "regwrite" and len(a) >= 2 and isinstance(a[1], str) and len(a[1]) > 60:
                    self.sinks.value_(Value("str", a[1], rec(a[1])), f"WScript.Shell.RegWrite {to_str(a[0])}", self.line(n))
                return UNDEF
            return mth(rw)
        if kl == "specialfolders":
            return mth(lambda a, n: f"%{to_str(a[0]).upper()}%" if a else "")
        if kl == "currentdirectory":
            return Unk("the current folder on the victim's machine")
        if kl == "createshortcut":
            return mth(lambda a, n: Host("COM", progid="WshShortcut"))
        return UNDEF

    def env(self, name: str) -> Any:
        u = name.upper()
        if u in ENV:
            return ENV[u]
        if u in ENV_MACHINE:
            return f"%{u}%"
        return Unk(f"the environment variable {name}")

    def fso_get(self, h: Host, k: str, kl: str, mth: Callable[..., Any]) -> Any:
        if kl in ("createtextfile", "opentextfile"):
            def ct(a: list, n: Any) -> Any:
                path = a[0] if a else ""
                mode = int(to_num(a[1])) if len(a) > 1 and kl == "opentextfile" and a[1] is not UNDEF else (2 if kl == "createtextfile" else 1)
                ps = to_str(path) if not isinstance(path, Unk) else f"<{path.why}>"
                if mode == 1:
                    return Host("TextStream", path=ps, mode=1, text="", me=ps.lower() == self.script_path.lower())
                ts = Host("TextStream", path=ps, mode=mode, text="")
                self.streams.append(ts)
                return ts
            return mth(ct)
        if kl == "getspecialfolder":
            return mth(lambda a, n: {0: "C:\\WINDOWS", 1: "C:\\WINDOWS\\system32", 2: "%TEMP%"}.get(int(to_num(a[0])) if a else 2, "%TEMP%"))
        if kl == "gettempname":
            return mth(lambda a, n: "rad0A1B2.tmp")
        if kl == "buildpath":
            return mth(lambda a, n: to_str(a[0]).rstrip("\\") + "\\" + to_str(a[1]) if len(a) > 1 else "")
        if kl in ("fileexists", "folderexists"):
            return mth(lambda a, n: Unk("whether a file exists on the victim's machine"))
        if kl in ("copyfile", "movefile", "deletefile", "createfolder", "copyfolder"):
            return mth(lambda a, n: UNDEF)
        if kl in ("getfile", "getfolder", "drives"):
            return mth(lambda a, n: Host("COM", progid="FSO item"))
        return UNDEF

    def _flush_text(self, h: Host, node: Any) -> None:
        if h.st.get("flushed") or h.st.get("mode") == 1:
            return
        h.st["flushed"] = True
        if h.st.get("unk") is not None and not h.st.get("text"):
            u = h.st["unk"]
            self.sinks._downloaded(Value.unknown(u.why), f"saves it to {h.st.get('path')}")
            return
        t = h.st.get("text", "")
        if t:
            self.write(tag(t, h.st.get("rec") or ()), h.st.get("path", ""), "FileSystemObject.CreateTextFile", node)

    def write(self, data: Any, path: str, sink: str, node: Any) -> None:
        line = self.line(node)
        if isinstance(data, Unk):
            if not self.sinks._downloaded(Value.unknown(data.why), f"saves it to {path}"):
                self.sinks.unresolved_(self.text(node), data.why, f"what it writes to {path} is not in the script", line)
            for d in self.sinks.downloads:
                if data.why.endswith(d["url"]):
                    d["saved_to"] = path
            return
        if isinstance(data, Host) and data.kind == "Blob":
            data = data.st["data"]
        if isinstance(data, str):
            v = Value("str", str(data), rec(data))
        else:
            b = bin_of(data)
            if b is None:
                return
            v = Value("bytes", b, rec(data))
        self.sinks.write(v, path, sink, line)

    def stream_get(self, h: Host, k: str, kl: str, mth: Callable[..., Any]) -> Any:
        if kl in ("open", "close", "flush", "seteos", "skipline"):
            def op(a: list, n: Any) -> Any:
                if kl == "open":
                    h.st.update(data=None, text="", pos=0)
                return UNDEF
            return mth(op)
        if kl == "write":
            def w(a: list, n: Any) -> Any:
                v = a[0] if a else b""
                if isinstance(v, Unk):
                    h.st["data"] = v
                    return UNDEF
                b = bin_of(v)
                cur = h.st.get("data")
                if isinstance(cur, (bytes, bytearray)):
                    b = bytes(cur) + (b or b"")
                h.st["data"] = tag(JSBytes(b or b""), rec(v) or rec(cur))
                return UNDEF
            return mth(w)
        if kl == "writetext":
            def wt(a: list, n: Any) -> Any:
                v = a[0] if a else ""
                if isinstance(v, Unk):
                    h.st["data"] = v
                    return UNDEF
                cs = h.st.get("charset", "unicode").lower()
                enc = {"unicode": "utf-16-le", "utf-16": "utf-16-le", "us-ascii": "latin-1", "ascii": "latin-1",
                       "iso-8859-1": "latin-1", "windows-1252": "cp1252", "437": "cp437"}.get(cs, cs)
                try:
                    b = to_str(v).encode(enc, "replace")
                except LookupError:
                    b = to_str(v).encode("utf-8", "replace")
                cur = h.st.get("data")
                if isinstance(cur, (bytes, bytearray)):
                    b = bytes(cur) + b
                h.st["data"] = tag(JSBytes(b), rec(v))
                return UNDEF
            return mth(wt)
        if kl in ("savetofile",):
            def sv(a: list, n: Any) -> Any:
                path = to_str(a[0]) if a and not isinstance(a[0], Unk) else f"<{a[0].why if a else ''}>"
                d = h.st.get("data")
                if d is None:
                    return UNDEF
                self.write(d, path, "ADODB.Stream.SaveToFile", n)
                return UNDEF
            return mth(sv)
        if kl in ("read", "readtext"):
            def rd(a: list, n: Any) -> Any:
                d = h.st.get("data")
                if isinstance(d, Unk) or d is None:
                    return d if d is not None else ""
                b = bytes(d)[h.st.get("pos", 0):]
                if kl == "readtext":
                    cs = h.st.get("charset", "unicode").lower()
                    enc = {"unicode": "utf-16-le", "us-ascii": "latin-1", "ascii": "latin-1", "iso-8859-1": "latin-1",
                           "windows-1252": "cp1252", "437": "cp437"}.get(cs, cs)
                    return step(d, "", T.as_text(b, enc))
                return step(d, "", JSBytes(b))
            return mth(rd)
        if kl == "loadfromfile":
            def lf(a: list, n: Any) -> Any:
                h.st["data"] = Unk(f"the content of {to_str(a[0]) if a else 'a file'} (a file on the victim's machine)")
                return UNDEF
            return mth(lf)
        if kl == "size":
            d = h.st.get("data")
            return len(d) if isinstance(d, (bytes, bytearray)) else 0
        if kl == "type":
            return h.st.get("type", 2)
        if kl == "position":
            return h.st.get("pos", 0)
        if kl == "charset":
            return h.st.get("charset", "")
        return UNDEF

    def xml_typed(self, h: Host) -> Any:
        dt = h.st.get("dtype", "")
        txt = h.st.get("text", "")
        if "bytes" in h.st:
            b = h.st["bytes"]
            if dt == "bin.base64":
                return step(b, "", base64.b64encode(bin_of(b) or b"").decode())
            return b
        if isinstance(txt, Unk):
            return Unk(txt.why, txt.recipe)
        try:
            if dt == "bin.base64":
                return step(txt, "base64 (MSXML bin.base64)", JSBytes(T.b64decode(to_str(txt))))
            if dt == "bin.hex":
                return step(txt, "hex (MSXML bin.hex)", JSBytes(T.hexdecode(to_str(txt))))
        except T.TransformError as exc:
            raise _Throw(Host("Error", message=str(exc))) from exc
        return txt

    def http_get(self, h: Host, k: str, kl: str, mth: Callable[..., Any]) -> Any:
        if kl == "open":
            def op(a: list, n: Any) -> Any:
                h.st["url"] = a[1] if len(a) > 1 else ""
                h.st["method"] = to_str(a[0]) if a else "GET"
                return UNDEF
            return mth(op)
        if kl == "send":
            def snd(a: list, n: Any) -> Any:
                url = h.st.get("url", "")
                self.download(url, f"{h.st.get('progid', 'XMLHTTP')} {h.st.get('method', 'GET')}", "returns it to the script", self.line(n))
                return UNDEF
            return mth(snd)
        if kl in ("responsetext", "responsebody", "response", "responsestream", "responsexml"):
            url = h.st.get("url", "")
            return Unk(f"the content downloaded from {to_str(url) if not isinstance(url, Unk) else url.why}")
        if kl == "status":
            return 200
        if kl == "readystate":
            return 4
        if kl in ("setrequestheader", "setoption", "settimeouts", "waitforresponse", "setproxy", "abort",
                  "getresponseheader", "getallresponseheaders", "overridemimetype"):
            return mth(lambda a, n: UNDEF if kl != "waitforresponse" else True)
        return UNDEF

    def coll_get(self, h: Host, k: str, mth: Callable[..., Any]) -> Any:
        if h.kind == "Map":
            d = h.st["d"]
            if k == "set":
                def s(a: list, n: Any) -> Any:
                    key = to_str(a[0]) if a else ""
                    if key not in d:
                        h.st["items"].append(JSArr([a[0] if a else UNDEF, a[1] if len(a) > 1 else UNDEF]))
                    d[key] = a[1] if len(a) > 1 else UNDEF
                    return h
                return mth(s)
            if k == "get":
                return mth(lambda a, n: d.get(to_str(a[0]) if a else "", UNDEF))
            if k == "has":
                return mth(lambda a, n: (to_str(a[0]) if a else "") in d)
            if k == "size":
                return len(d)
            return UNDEF
        if k == "add":
            return mth(lambda a, n: (h.st["items"].append(a[0]) if a and a[0] not in h.st["items"] else None) or h)
        if k == "has":
            return mth(lambda a, n: bool(a) and a[0] in h.st["items"])
        if k == "size":
            return len(h.st["items"])
        return UNDEF

    # -- Math / JSON ------------------------------------------------------------------------------------
    def math_fn(self, k: str) -> Any:
        def f1(fn: Callable[[float], Any]) -> Native:
            return Native(f"Math.{k}", lambda t, a, n: (Unk(a[0].why) if a and isinstance(a[0], Unk)
                                                        else norm(fn(to_num(a[0]) if a else math.nan))))

        def safe(fn: Callable[[float], Any]) -> Callable[[float], Any]:
            def g(x: float) -> Any:
                try:
                    return fn(x)
                except (ValueError, OverflowError):
                    return math.nan
            return g
        table = {
            "floor": f1(safe(lambda x: math.floor(x) if math.isfinite(x) else x)),
            "ceil": f1(safe(lambda x: math.ceil(x) if math.isfinite(x) else x)),
            "round": f1(safe(lambda x: math.floor(x + 0.5) if math.isfinite(x) else x)),
            "trunc": f1(safe(lambda x: math.trunc(x) if math.isfinite(x) else x)),
            "abs": f1(abs), "sqrt": f1(safe(math.sqrt)), "log": f1(safe(math.log)),
            "sin": f1(safe(math.sin)), "cos": f1(safe(math.cos)), "exp": f1(safe(math.exp)),
            "sign": f1(lambda x: (x > 0) - (x < 0)),
        }
        if k in table:
            return table[k]
        if k in ("max", "min"):
            def mm(t: Any, a: list, n: Any) -> Any:
                xs = [to_num(x) for x in a]
                if not xs:
                    return -math.inf if k == "max" else math.inf
                if any(x != x for x in xs):
                    return math.nan
                return max(xs) if k == "max" else min(xs)
            return Native(f"Math.{k}", mm)
        if k == "pow":
            return Native("Math.pow", lambda t, a, n: self.binop("**", a[0] if a else UNDEF, a[1] if len(a) > 1 else UNDEF))
        if k == "random":
            return Native("Math.random", lambda t, a, n: Unk("a random number"))
        if k == "imul":
            return Native("Math.imul", lambda t, a, n: to_int32(to_int32(a[0]) * to_int32(a[1])))
        if k in ("PI", "E"):
            return getattr(math, k.lower() if k == "PI" else "e") if k != "PI" else math.pi
        return UNDEF

    def json_fn(self, k: str) -> Any:
        def to_js(x: Any) -> Any:
            if isinstance(x, dict):
                return JSObj({kk: to_js(v) for kk, v in x.items()})
            if isinstance(x, list):
                return JSArr(to_js(v) for v in x)
            if isinstance(x, float):
                return norm(x)
            return x

        def to_py(x: Any, depth: int = 0) -> Any:
            if depth > 50:
                return None
            if isinstance(x, dict):
                return {kk: to_py(v, depth + 1) for kk, v in x.items() if not isinstance(v, (JSFunc, Native)) and v is not UNDEF}
            if isinstance(x, list):
                return [to_py(v, depth + 1) for v in x]
            if x is UNDEF or isinstance(x, (Unk, Host)):
                return None
            if isinstance(x, str):
                return str(x)
            return x
        if k == "parse":
            def p(t: Any, a: list, n: Any) -> Any:
                s = a[0] if a else ""
                if isinstance(s, Unk):
                    return Unk(s.why)
                try:
                    return to_js(json.loads(to_str(s)))
                except (ValueError, RecursionError) as exc:
                    raise _Throw(Host("Error", message=f"SyntaxError: {exc}")) from exc
            return Native("JSON.parse", p)
        if k == "stringify":
            return Native("JSON.stringify", lambda t, a, n: json.dumps(to_py(a[0] if a else None), separators=(",", ":")))
        return UNDEF

    # -- bytes, CryptoJS, Node crypto -------------------------------------------------------------------
    def bytes_op(self, v: Any, name: str, fn: Callable[[bytes], bytes], out: Any = JSBytes) -> Any:
        if isinstance(v, Unk):
            return Unk(v.why, v.recipe + (name,))
        b = bin_of(v)
        if b is None:
            raise _Throw(Host("Error", message=f"{name}: not bytes"))
        try:
            r = fn(b)
        except T.TransformError as exc:
            raise _Throw(Host("Error", message=f"{name}: {exc}")) from exc
        if out is str:
            return step(v, name, T.as_text(r))
        return step(v, name, JSBytes(r))

    def buffer_from(self, a: list) -> Any:
        v = a[0] if a else ""
        enc = to_str(a[1]).lower() if len(a) > 1 and a[1] is not UNDEF else "utf8"
        if isinstance(v, Unk):
            return Unk(v.why, v.recipe)
        if isinstance(v, str):
            try:
                if enc == "base64" or enc == "base64url":
                    return step(v, "base64", JSBytes(T.b64decode(v)))
                if enc == "hex":
                    return step(v, "hex", JSBytes(T.hexdecode(v)))
            except T.TransformError as exc:
                raise _Throw(Host("Error", message=str(exc))) from exc
            if enc in ("latin1", "binary", "ascii"):
                return step(v, "", JSBytes(v.encode("latin-1", "replace")))
            if enc in ("utf16le", "ucs2", "utf-16le"):
                return step(v, "", JSBytes(v.encode("utf-16-le")))
            return step(v, "", JSBytes(v.encode("utf-8", "replace")))
        b = bin_of(v)
        return step(v, "", JSBytes(b or b""))

    def bytes_to_string(self, b: Any, a: list) -> Any:
        enc = to_str(a[0]).lower() if a and a[0] is not UNDEF else "utf8"
        raw = bytes(b)
        if enc == "base64":
            return base64.b64encode(raw).decode()
        if enc == "hex":
            return raw.hex()
        if enc in ("latin1", "binary", "ascii"):
            return step(b, "", raw.decode("latin-1"))
        if enc in ("utf16le", "ucs2"):
            return step(b, "", raw.decode("utf-16-le", "replace"))
        return step(b, "", raw.decode("utf-8", "replace"))

    def node_decipher(self, h: Host, outenc: str) -> Any:
        if h.st.get("unk") is not None:
            return Unk(h.st["unk"].why, h.st["unk"].recipe)
        alg = h.st["alg"].lower()
        m = re.match(r"(aes|des-ede3|des|chacha20|rc4)(?:-(\d+))?(?:-(cbc|ecb|ctr|cfb|ofb|gcm))?", alg)
        key = bin_of(h.st["key"]) or b""
        iv = bin_of(h.st["iv"]) if h.st.get("iv") not in (None, UNDEF) else None
        data = bytes(h.st["buf"])
        try:
            if m and m.group(1) == "rc4":
                out = T.rc4(data, key)
            else:
                base = {"des-ede3": "3des"}.get(m.group(1), m.group(1)) if m else "aes"
                out = T.decrypt(base, data, key, iv, (m.group(3) if m and m.group(3) else "cbc"))
        except T.TransformError as exc:
            raise _Throw(Host("Error", message=f"decipher: {exc}")) from exc
        r = h.st["rec"] + (f"{alg}(key {len(key)} bytes)",)
        if outenc in ("utf8", "utf-8", "latin1", "binary", "ascii"):
            return tag(out.decode("utf-8" if outenc.startswith("utf") else "latin-1", "replace"), r)
        if outenc == "base64":
            return base64.b64encode(out).decode()
        return tag(JSBytes(out), r)

    def cryptojs_get(self, h: Host, k: str, mth: Callable[..., Any]) -> Any:
        if k in ("AES", "DES", "TripleDES", "RC4", "Rabbit", "RC4Drop"):
            return Host("CJSCipher", alg=k)
        if k == "enc":
            e = Host("CJSEncNS")
            for name in ("Base64", "Hex", "Utf8", "Latin1", "Utf16", "Utf16LE", "Base64url"):
                e.props[name] = Host("CJSEnc", enc=name)
            return e
        if k == "mode":
            m = Host("CJSModeNS")
            for name in ("CBC", "ECB", "CFB", "OFB", "CTR"):
                m.props[name] = name.lower()
            return m
        if k == "pad":
            p = Host("CJSPadNS")
            for name in ("Pkcs7", "NoPadding", "ZeroPadding", "Iso10126", "AnsiX923"):
                p.props[name] = name.lower()
            return p
        if k in ("MD5", "SHA1", "SHA256", "SHA512", "SHA224", "SHA384"):
            def hs(a: list, n: Any) -> Any:
                v = a[0] if a else ""
                b = v.st["data"] if isinstance(v, Host) and v.kind == "WordArray" else to_str(v).encode("utf-8")
                return Host("WordArray", data=T.digest(k.lower(), b))
            return mth(hs)
        if k == "lib":
            lib = Host("CJSLib")
            lib.props["WordArray"] = Host("CJSWA")
            lib.props["CipherParams"] = Host("CJSCP")
            return lib
        if k in ("PBKDF2", "EvpKDF"):
            def kdf(a: list, n: Any) -> Any:
                pw = bin_of(a[0]) if a and not isinstance(a[0], str) else to_str(a[0] if a else "").encode()
                salt = bin_of(a[1]) if len(a) > 1 and not isinstance(a[1], str) else to_str(a[1] if len(a) > 1 else "").encode()
                cfg = a[2] if len(a) > 2 and isinstance(a[2], dict) else {}
                ks = int(to_num(cfg.get("keySize", 4))) * 4
                it = int(to_num(cfg.get("iterations", 1)))
                if k == "PBKDF2":
                    return Host("WordArray", data=T.pbkdf2(pw, salt, it, ks, "sha1"))
                return Host("WordArray", data=self.evp_kdf(pw, salt, ks, 0)[0])
            return mth(kdf)
        return UNDEF

    def cjs_parse(self, enc: str, v: Any) -> Any:
        if isinstance(v, Unk):
            return Unk(v.why, v.recipe)
        s = to_str(v)
        try:
            if enc in ("Base64", "Base64url"):
                return Host("WordArray", data=T.b64decode(s), recipe=rec(v) + ("base64",))
            if enc == "Hex":
                return Host("WordArray", data=T.hexdecode(s), recipe=rec(v) + ("hex",))
        except T.TransformError as exc:
            raise _Throw(Host("Error", message=str(exc))) from exc
        if enc == "Latin1":
            return Host("WordArray", data=s.encode("latin-1", "replace"), recipe=rec(v))
        if enc in ("Utf16", "Utf16LE"):
            return Host("WordArray", data=s.encode("utf-16-le" if enc == "Utf16LE" else "utf-16-be"), recipe=rec(v))
        return Host("WordArray", data=s.encode("utf-8", "replace"), recipe=rec(v))

    def wa_str(self, wa: Any, enc: Any) -> Any:
        if isinstance(wa, Unk):
            return Unk(wa.why, wa.recipe)
        if not (isinstance(wa, Host) and wa.kind == "WordArray"):
            return to_str(wa)
        d = wa.st["data"]
        e = enc.st["enc"] if isinstance(enc, Host) and enc.kind == "CJSEnc" else "Hex"
        if e == "Utf8":
            try:
                out = d.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _Throw(Host("Error", message="Malformed UTF-8 data")) from exc
            return tag(out, wa.recipe) if wa.recipe else out
        if e == "Latin1":
            return tag(d.decode("latin-1"), wa.recipe) if wa.recipe else d.decode("latin-1")
        if e in ("Base64", "Base64url"):
            return base64.b64encode(d).decode()
        if e in ("Utf16", "Utf16LE"):
            return d.decode("utf-16-le" if e == "Utf16LE" else "utf-16-be", "replace")
        return d.hex()

    @staticmethod
    def evp_kdf(pw: bytes, salt: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
        """OpenSSL's EVP_BytesToKey (MD5, 1 round): what CryptoJS does with a passphrase."""
        out = b""
        prev = b""
        while len(out) < key_len + iv_len:
            prev = hashlib.md5(prev + pw + salt).digest()  # noqa: S324  (the format's own KDF)
            out += prev
        return out[:key_len], out[key_len:key_len + iv_len]

    def cjs_decrypt(self, alg: str, a: list, node: Any) -> Any:
        ct = a[0] if a else ""
        key = a[1] if len(a) > 1 else ""
        cfg = a[2] if len(a) > 2 and isinstance(a[2], dict) else {}
        for x in (ct, key):
            if isinstance(x, Unk):
                return Unk(x.why, x.recipe)
        if isinstance(ct, Host) and ct.kind == "CipherParams":
            data, r = ct.st["ct"], ct.recipe
        elif isinstance(ct, dict) and isinstance(ct.get("ciphertext"), Host):
            data, r = ct["ciphertext"].st["data"], ct["ciphertext"].recipe
        elif isinstance(ct, Host) and ct.kind == "WordArray":
            data, r = ct.st["data"], ct.recipe
        else:
            try:
                data, r = T.b64decode(to_str(ct)), rec(ct) + ("base64",)
            except T.TransformError as exc:
                raise _Throw(Host("Error", message=str(exc))) from exc
        mode = to_str(cfg.get("mode", "cbc")) if cfg.get("mode") not in (None, UNDEF) else "cbc"
        pad = to_str(cfg.get("padding", "pkcs7")) if cfg.get("padding") not in (None, UNDEF) else "pkcs7"
        padding = "none" if pad == "nopadding" else "zeros" if pad == "zeropadding" else "pkcs7"
        base = {"AES": "aes", "DES": "des", "TripleDES": "3des"}.get(alg, alg.lower())
        block = 16 if base == "aes" else 8
        try:
            if isinstance(key, str):
                # a passphrase: OpenSSL "Salted__" + salt, key and IV from EVP_BytesToKey(MD5)
                salt = b""
                if data[:8] == b"Salted__":
                    salt, data = data[8:16], data[16:]
                klen = {"aes": 32, "des": 8, "3des": 24}.get(base, 32)
                if base in ("rc4",):
                    k2, iv = self.evp_kdf(key.encode("utf-8"), salt, 32, 0)
                else:
                    k2, iv = self.evp_kdf(key.encode("utf-8"), salt, klen, block)
                desc = f"{base}(passphrase {key[:12]!r})"
            else:
                k2 = bin_of(key) or b""
                ivv = cfg.get("iv")
                iv = bin_of(ivv) if ivv not in (None, UNDEF) else None
                desc = f"{base}-{len(k2) * 8}-{mode}(key {len(k2)} bytes)" if base == "aes" else f"{base}(key {len(k2)} bytes)"
            if base == "rc4":
                out = T.rc4(data, k2)
            else:
                out = T.decrypt(base, data, k2, iv, mode, padding)
        except T.TransformError as exc:
            raise _Throw(Host("Error", message=f"CryptoJS {alg}: {exc}")) from exc
        return Host("WordArray", data=out, recipe=r + (desc,))

    # -- the values a script computed ----------------------------------------------------------------
    def to_value(self, v: Any) -> Value:
        r = rec(v)
        if isinstance(v, Unk):
            return Value.unknown(v.why, r)
        if isinstance(v, (bytes, bytearray)):
            return Value("bytes", bytes(v), r)
        if isinstance(v, Host) and v.kind == "WordArray":
            return Value("bytes", v.st["data"], v.recipe)
        if isinstance(v, str):
            return Value("str", str(v), r)
        if isinstance(v, list) and v and all(is_num(x) for x in v[:64]):
            try:
                return Value("bytes", bytes(int(x) & 0xFF for x in v), r)
            except (TypeError, ValueError, OverflowError):
                pass
        if isinstance(v, list):
            return Value("list", [], r)
        return Value("obj", None, r)

    def computed_values(self) -> None:
        """Values computed and left in a variable: a PE, an archive, code — a stage as well."""
        from . import langdetect
        seen: set[int] = set()
        items = list(self.gscope.vars.items()) + list(self.tracked.items())
        for name, v in items:
            if isinstance(v, Host) and v.kind == "WordArray":
                v = tag(JSBytes(v.st["data"]), v.recipe)
            if id(v) in seen or not isinstance(v, (str, bytearray, list)) or len(v) < 40:
                continue
            seen.add(id(v))
            r = rec(v)
            ops = [x for x in r if not x.startswith(("literal", "number array"))]
            if not ops:
                continue
            if isinstance(v, list):
                b = bin_of(v)
                if b is None:
                    continue
                raw = b
            elif isinstance(v, str):
                raw = bin_of(v) or b""
            else:
                raw = bytes(v)
            if any(st.recipe[:len(r)] == r and len(st.recipe) > len(r) for st in self.sinks.stages):
                continue
            kind = T.magic(raw)
            if not kind and isinstance(v, str) and T.is_text(raw):
                txt = str(v)
                if txt in self.source:
                    continue
                if len(ops) >= 1 and langdetect.languages(txt):
                    self.sinks.exec_(Value("str", txt, r), f"value of {name} (computed, not run here)")
                    continue
                if re.search(r"(?i)\bhttps?://|\b\d{1,3}(?:\.\d{1,3}){3}\b", txt):
                    self.sinks.value_(Value("str", txt, r), f"value of {name} (decoded text with IOCs)")
                continue
            if kind:
                self.sinks.load(Value("bytes", raw, r), f"value of {name} (computed, not run here)")


# --- the methods of values the property table does not cover --------------------------------------
_orig_method = Interp.method


def _method(self: Interp, o: Any, name: str) -> Any:
    if isinstance(o, JSBytes) and name == "toString":
        return Native("Buffer.toString", lambda this, a, n: self.bytes_to_string(this, a))
    if isinstance(o, JSBytes) and name in ("readUInt8", "readUInt32LE", "readInt32LE"):
        def rd(this: Any, a: list, n: Any) -> Any:
            off = int(to_num(a[0])) if a else 0
            b = bytes(this)
            if name == "readUInt8":
                return b[off]
            return int.from_bytes(b[off:off + 4], "little", signed=name == "readInt32LE")
        return Native(name, rd)
    return _orig_method(self, o, name)


Interp.method = _method  # type: ignore[method-assign]


def resolve(code: str, location: str = "javascript") -> Sinks:
    """Evaluate a JavaScript / JScript script statically; its stages, downloads, unresolved calls and trace."""
    s = Sinks("javascript")
    code = code.lstrip("\ufeff")
    try:
        import esprima  # noqa: F401
    except ImportError:
        s.errors = ["esprima is not installed: JavaScript is not evaluated statically"]  # type: ignore[attr-defined]
        s.stats = {}  # type: ignore[attr-defined]
        return s
    it = Interp(s, code)
    try:
        it.run(code)
    except RecursionError:
        it.errors.append("recursion")
    s.errors = it.errors  # type: ignore[attr-defined]
    s.stats = {"steps": it.steps, "seconds": round(time.monotonic() - it.t0, 2)}  # type: ignore[attr-defined]
    return s
