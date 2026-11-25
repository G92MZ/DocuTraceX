"""Python, evaluated statically: what a loader computes, without running it.

The script is parsed with Python's own parser (:mod:`ast`) and walked by a small interpreter —
never ``exec``'d. It follows assignments, the script's functions and lambdas, comprehensions,
slicing, f-strings, loops and conditions, and the library calls loaders use, mapped to the shared
operations (:mod:`.transforms`): ``base64``, ``binascii``, ``zlib`` / ``gzip`` / ``lzma`` / ``bz2``,
``codecs``, ``marshal``, ``bytes.fromhex``, ``int.from_bytes``, XOR comprehensions, PyCryptodome
(``AES`` / ``DES3`` / ``ARC4`` / ``ChaCha20``) and ``cryptography`` (``Fernet``, ``Cipher``).

What reaches ``exec`` / ``eval`` / ``compile`` runs next (it is evaluated here too, a later stage);
bytes handed to ``ctypes`` (``VirtualAlloc`` + ``RtlMoveMemory``, ``create_string_buffer``) are
loaded; ``open(…, 'wb').write`` writes; ``subprocess`` / ``os.system`` launch a command (a
PowerShell ``-enc`` in it is decoded). ``urlopen`` / ``requests`` downloads are reported, never
fetched. Names computed at run time (``getattr(__builtins__, 'ex'+'ec')``, ``__import__('ba'+'se64')``)
are resolved; one that depends on the victim's machine is a dynamic call not resolved.

Bounded: steps, time, loop iterations and inline nesting.
"""

from __future__ import annotations

import ast
import hashlib
import re
import time
from typing import Any, Callable

from . import transforms as T
from .sinks import Sinks
from .value import Value

MAX_STEPS = 4_000_000
MAX_SECONDS = 60.0
MAX_LOOP = 2_000_000
MAX_DEPTH = 12
MAX_CALL_DEPTH = 64


# --- values with a recipe ------------------------------------------------------------------
class RStr(str):
    recipe: tuple[str, ...] = ()


class RBytes(bytes):
    recipe: tuple[str, ...] = ()


class RByteArray(bytearray):
    recipe: tuple[str, ...] = ()
    inplace: str = ""


class RList(list):
    recipe: tuple[str, ...] = ()


class Unk:
    def __init__(self, why: str, recipe: tuple[str, ...] = ()) -> None:
        self.why = why
        self.recipe = recipe

    def __repr__(self) -> str:
        return f"<unknown: {self.why}>"


def rec(v: Any) -> tuple[str, ...]:
    return getattr(v, "recipe", ()) or ()


def tag(v: Any, recipe: tuple[str, ...]) -> Any:
    if type(v) is str:
        v = RStr(v)
    elif type(v) is bytes:
        v = RBytes(v)
    elif type(v) is bytearray:
        v = RByteArray(v)
    elif type(v) is list:
        v = RList(v)
    try:
        v.recipe = tuple(recipe)[-40:]
    except AttributeError:
        pass
    return v


def step(src: Any, name: str, out: Any) -> Any:
    return tag(out, rec(src) + ((name,) if name else ()))


def label(v: Any, fallback: str = "") -> str:
    for r in rec(v):
        m = re.search(r"\b([A-Za-z_]\w*)$", r)
        if m and r.startswith(("literal", "variable")):
            return m.group(1)
    return fallback


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value: Any) -> None:
        self.value = value


class _Raise(Exception):
    pass


class Limit(Exception):
    pass


class Func:
    def __init__(self, name: str, args: ast.arguments, body: Any, closure: dict, lam: bool = False) -> None:
        self.name, self.args, self.body, self.closure, self.lam = name, args, body, closure, lam


class Builtin:
    def __init__(self, name: str, fn: Callable[..., Any]) -> None:
        self.name, self.fn = name, fn

    def __repr__(self) -> str:
        return f"<built-in {self.name}>"


class Module:
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"<module {self.name}>"


class Obj:
    def __init__(self, kind: str, **kw: Any) -> None:
        self.kind = kind
        self.__dict__.update(kw)


class CodeObj:
    def __init__(self, source: str | None, raw: bytes | None, recipe: tuple[str, ...]) -> None:
        self.source, self.raw, self.recipe = source, raw, recipe


ENV = {"COMSPEC": "C:\\WINDOWS\\system32\\cmd.exe", "WINDIR": "C:\\WINDOWS", "SYSTEMROOT": "C:\\WINDOWS",
       "PROGRAMDATA": "C:\\ProgramData", "PUBLIC": "C:\\Users\\Public", "OS": "Windows_NT"}
ENV_MACHINE = {"USERNAME": "the victim's user name", "COMPUTERNAME": "the victim's computer name",
               "APPDATA": "the victim's AppData folder", "LOCALAPPDATA": "the victim's AppData folder",
               "TEMP": "the victim's TEMP folder", "TMP": "the victim's TEMP folder",
               "USERPROFILE": "the victim's profile folder", "HOME": "the victim's home folder",
               "USERDOMAIN": "the victim's domain", "USER": "the victim's user name"}


class Interp:
    def __init__(self, sinks: Sinks, source: str) -> None:
        self.sinks = sinks
        self.source = source
        self.g: dict[str, Any] = {}
        self.scopes: list[dict[str, Any]] = [self.g]
        self.steps = 0
        self.t0 = time.monotonic()
        self.depth = 0
        self.call_depth = 0
        self.errors: list[str] = []
        self.ran: set[str] = set()
        self.tracked: dict[str, Any] = {}
        self.builtins = self._builtins()

    # -- running --------------------------------------------------------------------------
    def run(self, code: str) -> None:
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError, RecursionError) as exc:
            self.errors.append(f"not parsed: {exc}"[:300])
            return
        try:
            self.block(tree.body, top=True)
        except (Limit, _Return, _Break, _Continue):
            pass
        except _Raise as e:
            self.errors.append(f"script stops: {e}"[:300])
        except SystemExit:
            pass
        self.computed_values()

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise Limit("steps")
        if not self.steps & 0x3FFF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise Limit("time")

    def block(self, body: list, top: bool = False) -> None:
        for st in body:
            try:
                self.stmt(st)
            except (_Return, _Break, _Continue, Limit, SystemExit):
                raise
            except RecursionError:
                raise _Raise("recursion") from None
            except _Raise:
                if top:
                    self.errors.append(f"line {getattr(st, 'lineno', '?')}: raises")
                    continue
                raise
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"line {getattr(st, 'lineno', '?')}: {type(exc).__name__}: {exc}"[:300])
                if top:
                    continue
                raise _Raise(str(exc)) from exc

    # -- names ------------------------------------------------------------------------------
    def get(self, name: str) -> Any:
        for sc in reversed(self.scopes):
            if name in sc:
                return sc[name]
        if name in self.g:
            return self.g[name]
        if name in self.builtins:
            return self.builtins[name]
        if name in ("__builtins__", "builtins"):
            return Module("builtins")
        if name == "__name__":
            return "__main__"
        if name == "__file__":
            return "script.py"
        raise NameError(name)

    def set(self, name: str, v: Any, line: int | None = None) -> None:
        if isinstance(v, (str, bytes, bytearray)) and not rec(v) and len(v) >= 16:
            v = tag(v, (f"literal {name}",))
        elif isinstance(v, (str, bytes, bytearray, list)) and rec(v) and len(v) >= 16 and isinstance(v, (str, bytes, bytearray)):
            self.sinks.step(line, f"{name} =", self.to_value(v))
        if isinstance(v, (str, bytes, bytearray, list)) and len(v) >= 40:
            self.tracked[name] = v
        self.scopes[-1][name] = v

    # -- statements ---------------------------------------------------------------------------
    def stmt(self, st: ast.stmt) -> None:  # noqa: C901
        self.tick()
        line = getattr(st, "lineno", None)
        if isinstance(st, ast.Expr):
            self.eval(st.value)
        elif isinstance(st, ast.Assign):
            v = self.eval(st.value)
            for t in st.targets:
                self.assign(t, v, line)
        elif isinstance(st, ast.AnnAssign):
            if st.value is not None:
                self.assign(st.target, self.eval(st.value), line)
        elif isinstance(st, ast.AugAssign):
            cur = self.eval(st.target) if not isinstance(st.target, ast.Name) else self.get(st.target.id)
            v = self.binop(st.op, cur, self.eval(st.value))
            self.assign(st.target, v, line, aug=st)
        elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.scopes[-1][st.name] = Func(st.name, st.args, st.body, dict(self.scopes[-1]) if len(self.scopes) > 1 else {})
        elif isinstance(st, ast.ClassDef):
            self.scopes[-1][st.name] = Obj("class", name=st.name)
        elif isinstance(st, ast.Return):
            raise _Return(self.eval(st.value) if st.value is not None else None)
        elif isinstance(st, ast.If):
            c = self.truth(self.eval(st.test))
            if c is None:
                for b in (st.body, st.orelse):
                    try:
                        self.block(b)
                    except _Raise:
                        pass
            elif c:
                self.block(st.body)
            else:
                self.block(st.orelse)
        elif isinstance(st, ast.For):
            seq = self.eval(st.iter)
            n = 0
            for item in self.iterate(seq):
                n += 1
                if n > MAX_LOOP:
                    break
                self.assign(st.target, item, line)
                try:
                    self.block(st.body)
                except _Break:
                    break
                except _Continue:
                    continue
            else:
                self.block(st.orelse)
        elif isinstance(st, ast.While):
            n = 0
            forever = isinstance(st.test, ast.Constant) and bool(st.test.value)
            cap = 3 if forever else MAX_LOOP
            while True:
                c = self.truth(self.eval(st.test))
                if c is None:
                    c = n == 0
                if not c or n >= cap:
                    break
                n += 1
                try:
                    self.block(st.body)
                except _Break:
                    break
                except _Continue:
                    continue
        elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
            try:
                self.block(st.body)
            except _Raise:
                if st.handlers:
                    h = st.handlers[0]
                    if h.name:
                        self.scopes[-1][h.name] = Obj("exception")
                    self.block(h.body)
            else:
                self.block(st.orelse)
            finally:
                self.block(st.finalbody)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                v = self.eval(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, v, line)
            self.block(st.body)
        elif isinstance(st, ast.Import):
            for a in st.names:
                mod = Module(a.name)
                if a.asname:
                    self.scopes[-1][a.asname] = mod
                else:
                    self.scopes[-1][a.name.split(".")[0]] = Module(a.name.split(".")[0])
        elif isinstance(st, ast.ImportFrom):
            for a in st.names:
                self.scopes[-1][a.asname or a.name] = Module(f"{st.module}.{a.name}") if st.module else Module(a.name)
        elif isinstance(st, ast.Break):
            raise _Break()
        elif isinstance(st, ast.Continue):
            raise _Continue()
        elif isinstance(st, ast.Raise):
            raise _Raise("raise")
        elif isinstance(st, (ast.Pass, ast.Global, ast.Nonlocal, ast.Assert, ast.Delete)):
            pass
        elif isinstance(st, ast.Match):
            pass

    def assign(self, t: ast.expr, v: Any, line: int | None, aug: Any = None) -> None:
        if isinstance(t, ast.Name):
            self.set(t.id, v, line)
        elif isinstance(t, (ast.Tuple, ast.List)):
            items = list(self.iterate(v))
            for sub, item in zip(t.elts, items):
                self.assign(sub, item, line)
        elif isinstance(t, ast.Subscript):
            target = self.eval(t.value)
            idx = self.eval(t.slice)
            if isinstance(target, (bytearray, list, dict)):
                if isinstance(target, bytearray):
                    target[idx] = v & 0xFF if isinstance(v, int) else v
                    if isinstance(target, RByteArray) and not target.inplace:
                        target.inplace = self._inplace(t, aug) or ""
                else:
                    target[idx] = v
        elif isinstance(t, ast.Attribute):
            o = self.eval(t.value)
            if isinstance(o, Obj):
                setattr(o, t.attr, v)
        elif isinstance(t, ast.Starred):
            self.assign(t.value, v, line)

    def _inplace(self, t: ast.Subscript, aug: Any) -> str | None:
        if aug is not None and isinstance(aug.op, ast.BitXor):
            try:
                k = self.eval(aug.value)
                return f"xor(0x{k:x})" if isinstance(k, int) else "xor"
            except Exception:  # noqa: BLE001
                return "xor"
        return None

    # -- expressions -------------------------------------------------------------------------------
    def eval(self, n: ast.expr | None) -> Any:  # noqa: C901
        self.tick()
        if n is None:
            return None
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Name):
            return self.get(n.id)
        if isinstance(n, ast.JoinedStr):
            parts = []
            for v in n.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                else:
                    x = self.eval(v.value)
                    if isinstance(x, Unk):
                        return x
                    parts.append(format(x, self.eval(v.format_spec) if v.format_spec else "") if not isinstance(x, (str, bytes)) else str(x))
            return "".join(parts)
        if isinstance(n, ast.FormattedValue):
            return str(self.eval(n.value))
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            items = []
            for e in n.elts:
                if isinstance(e, ast.Starred):
                    items.extend(self.iterate(self.eval(e.value)))
                else:
                    items.append(self.eval(e))
            return items if isinstance(n, ast.List) else (tuple(items) if isinstance(n, ast.Tuple) else set(items))
        if isinstance(n, ast.Dict):
            return {self.eval(k): self.eval(v) for k, v in zip(n.keys, n.values) if k is not None}
        if isinstance(n, ast.BinOp):
            return self.binop(n.op, self.eval(n.left), self.eval(n.right))
        if isinstance(n, ast.UnaryOp):
            v = self.eval(n.operand)
            if isinstance(v, Unk):
                return v
            if isinstance(n.op, ast.Not):
                t = self.truth(v)
                return None if t is None else not t
            return {ast.USub: lambda x: -x, ast.UAdd: lambda x: +x, ast.Invert: lambda x: ~x}[type(n.op)](v)
        if isinstance(n, ast.BoolOp):
            last = None
            for e in n.values:
                last = self.eval(e)
                t = self.truth(last)
                if t is None:
                    return Unk("a condition not known")
                if isinstance(n.op, ast.And) and not t:
                    return last
                if isinstance(n.op, ast.Or) and t:
                    return last
            return last
        if isinstance(n, ast.Compare):
            left = self.eval(n.left)
            for op, comp in zip(n.ops, n.comparators):
                right = self.eval(comp)
                if isinstance(left, Unk) or isinstance(right, Unk):
                    return Unk("a comparison with a value not known")
                ok = self.compare(op, left, right)
                if not ok:
                    return False
                left = right
            return True
        if isinstance(n, ast.IfExp):
            t = self.truth(self.eval(n.test))
            if t is None:
                return Unk("a condition not known")
            return self.eval(n.body if t else n.orelse)
        if isinstance(n, ast.Subscript):
            o = self.eval(n.value)
            idx = self.eval(n.slice)
            if isinstance(o, Unk):
                return o
            if isinstance(idx, Unk):
                return idx
            if isinstance(o, Obj) and o.kind == "environ":
                return self.env(str(idx))
            if isinstance(o, (Obj, Module, Func, Builtin, CodeObj)):
                return Unk(f"an item of a {type(o).__name__}")
            out = o[idx]
            if isinstance(idx, slice) and isinstance(out, (str, bytes, bytearray)):
                r = rec(o)
                step_name = "reverse" if idx.step == -1 and idx.start is None and idx.stop is None else ""
                return tag(out, r + ((step_name,) if step_name else ())) if r or step_name else out
            return out
        if isinstance(n, ast.Slice):
            return slice(self.eval(n.lower), self.eval(n.upper), self.eval(n.step))
        if isinstance(n, ast.Attribute):
            return self.attr(self.eval(n.value), n.attr)
        if isinstance(n, ast.Call):
            return self.call(n)
        if isinstance(n, ast.Lambda):
            return Func("<lambda>", n.args, n.body, dict(self.scopes[-1]) if len(self.scopes) > 1 else {}, lam=True)
        if isinstance(n, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            out = self.comp(n.generators, lambda: self.eval(n.elt))
            if isinstance(n, ast.SetComp):
                return set(out)
            # [b ^ 0x41 for b in data] / [b ^ k[i % len(k)] for i, b in enumerate(data)]: a named step
            src = self._comp_source(n)
            if src is not None and rec(src):
                return tag(out, rec(src) + ((self._comp_op(n.elt),) if self._comp_op(n.elt) else ()))
            return out
        if isinstance(n, ast.DictComp):
            pairs = self.comp(n.generators, lambda: (self.eval(n.key), self.eval(n.value)))
            return dict(pairs)
        if isinstance(n, ast.Starred):
            return self.eval(n.value)
        if isinstance(n, ast.NamedExpr):
            v = self.eval(n.value)
            self.assign(n.target, v, getattr(n, "lineno", None))
            return v
        if isinstance(n, ast.Await):
            return self.eval(n.value)
        raise ValueError(f"cannot evaluate {type(n).__name__}")

    def _comp_source(self, n: Any) -> Any:
        try:
            it = n.generators[0].iter
            if isinstance(it, ast.Call) and getattr(it.func, "id", "") in ("enumerate", "zip") and it.args:
                it = it.args[0]
            return self.eval(it)
        except Exception:  # noqa: BLE001
            return None

    def _comp_op(self, elt: Any) -> str:
        if isinstance(elt, ast.BinOp):
            op = {ast.BitXor: "xor", ast.Add: "add", ast.Sub: "sub"}.get(type(elt.op))
            if not op:
                return ""
            other = elt.right if isinstance(elt.left, ast.Name) else elt.left
            if isinstance(other, ast.Constant) and isinstance(other.value, int):
                return f"{op}(0x{other.value:x})"
            if isinstance(other, ast.Subscript) and isinstance(other.value, ast.Name):
                return f"{op}(key {other.value.id})"
            if isinstance(other, ast.Name):
                return f"{op}({other.id})"
            return op
        if isinstance(elt, ast.Call) and getattr(elt.func, "id", "") in ("chr", "ord") and elt.args:
            return self._comp_op(elt.args[0])
        return ""

    def comp(self, gens: list, elt: Callable[[], Any]) -> list:
        out: list = []
        self.scopes.append({})
        try:
            def rec_gen(i: int) -> None:
                if i == len(gens):
                    out.append(elt())
                    return
                g = gens[i]
                for item in self.iterate(self.eval(g.iter)):
                    self.tick()
                    self.assign(g.target, item, None)
                    if all(self.truth(self.eval(c)) for c in g.ifs):
                        rec_gen(i + 1)
            rec_gen(0)
        finally:
            self.scopes.pop()
        return out

    def truth(self, v: Any) -> bool | None:
        if isinstance(v, Unk):
            return None
        try:
            return bool(v)
        except Exception:  # noqa: BLE001
            return True

    def iterate(self, v: Any) -> Any:
        if isinstance(v, Unk):
            return []
        if isinstance(v, (Obj, Module, Func, Builtin)):
            return []
        if isinstance(v, dict):
            return list(v)
        try:
            return list(v) if not isinstance(v, (range,)) or len(v) <= MAX_LOOP else []
        except TypeError:
            return []

    def compare(self, op: ast.cmpop, a: Any, b: Any) -> bool:
        return {ast.Eq: lambda: a == b, ast.NotEq: lambda: a != b, ast.Lt: lambda: a < b, ast.LtE: lambda: a <= b,
                ast.Gt: lambda: a > b, ast.GtE: lambda: a >= b, ast.Is: lambda: a is b, ast.IsNot: lambda: a is not b,
                ast.In: lambda: a in b, ast.NotIn: lambda: a not in b}[type(op)]()

    def binop(self, op: ast.operator, a: Any, b: Any) -> Any:
        if isinstance(a, Unk) or isinstance(b, Unk):
            u = a if isinstance(a, Unk) else b
            return Unk(u.why)
        f = {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b, ast.Div: lambda: a / b,
             ast.FloorDiv: lambda: a // b, ast.Mod: lambda: a % b, ast.Pow: lambda: pow(a, b),
             ast.LShift: lambda: a << b, ast.RShift: lambda: a >> b, ast.BitOr: lambda: a | b,
             ast.BitXor: lambda: a ^ b, ast.BitAnd: lambda: a & b}[type(op)]
        if isinstance(op, ast.Mult) and isinstance(a, (str, bytes, list)) and isinstance(b, int) and len(a) * b > T.MAX_OUT:
            raise Limit("repeat")
        if isinstance(op, ast.Pow) and isinstance(b, int) and b > 4096:
            raise Limit("pow")
        out = f()
        if isinstance(out, (str, bytes)) and (rec(a) or rec(b)):
            return tag(out, rec(a) or rec(b))
        return out

    # -- attributes / calls -----------------------------------------------------------------------
    def attr(self, o: Any, name: str) -> Any:
        if isinstance(o, Unk):
            return o
        if isinstance(o, Module):
            full = f"{o.name}.{name}"
            if name.startswith("MODE_"):            # PyCryptodome's mode constants
                return {"MODE_ECB": 1, "MODE_CBC": 2, "MODE_CFB": 3, "MODE_OFB": 5, "MODE_CTR": 6,
                        "MODE_OPENPGP": 7, "MODE_EAX": 9, "MODE_CCM": 8, "MODE_SIV": 10, "MODE_GCM": 11}.get(name, 2)
            if o.name in ("builtins", "__builtins__") and name in self.builtins:
                return self.builtins[name]
            if o.name in ("os", "os.environ") and name == "environ":
                return Obj("environ")
            return Module(full)
        if isinstance(o, Builtin):
            f = getattr(o, name, None)
            return Builtin(f"{o.name}.{name}", f) if callable(f) else Unk(f"{o.name}.{name}")
        if isinstance(o, Obj):
            if hasattr(o, name):
                return getattr(o, name)
            return Obj("method", owner=o, name=name)
        if isinstance(o, (str, bytes, bytearray, list, dict, int, tuple, set)):
            return Obj("pymethod", owner=o, name=name)
        if isinstance(o, CodeObj):
            return Obj("method", owner=o, name=name)
        return Unk(f"{type(o).__name__}.{name}")

    def call(self, n: ast.Call) -> Any:
        line = getattr(n, "lineno", None)
        fn = self.eval(n.func)
        args: list = []
        for a in n.args:
            if isinstance(a, ast.Starred):
                args.extend(self.iterate(self.eval(a.value)))
            else:
                args.append(self.eval(a))
        kw = {k.arg: self.eval(k.value) for k in n.keywords if k.arg}
        return self.invoke(fn, args, kw, line, n)

    def invoke(self, fn: Any, args: list, kw: dict, line: int | None, node: Any = None) -> Any:  # noqa: C901
        if isinstance(fn, Unk):
            self.sinks.unresolved_(self._span(line) or "call", fn.why,
                                   "the function called is computed from something not in the script", line)
            return Unk(f"the result of a call whose target depends on {fn.why}")
        if isinstance(fn, Func):
            return self.call_func(fn, args, kw)
        if isinstance(fn, Builtin):
            return fn.fn(*args, **kw) if fn.name not in ("exec", "eval", "compile") else fn.fn(*args, _line=line, **kw)
        if isinstance(fn, Module):
            return self.module_call(fn.name, args, kw, line)
        if isinstance(fn, Obj) and fn.kind == "pymethod":
            return self.py_method(fn.owner, fn.name, args, kw, line)
        if isinstance(fn, Obj) and fn.kind == "method":
            return self.obj_method(fn.owner, fn.name, args, kw, line)
        if isinstance(fn, Obj) and fn.kind == "class":
            return Obj("instance", cls=fn.name)
        return Unk(f"a call of {type(fn).__name__}")

    def call_func(self, f: Func, args: list, kw: dict) -> Any:
        self.call_depth += 1
        if self.call_depth > MAX_CALL_DEPTH:
            self.call_depth -= 1
            raise _Raise("recursion")
        scope: dict[str, Any] = dict(f.closure)
        a = f.args
        names = [x.arg for x in a.posonlyargs + a.args]
        defaults = [self.eval(d) for d in a.defaults]
        for i, nm in enumerate(names):
            if i < len(args):
                scope[nm] = args[i]
            elif nm in kw:
                scope[nm] = kw.pop(nm)
            else:
                di = i - (len(names) - len(defaults))
                scope[nm] = defaults[di] if 0 <= di < len(defaults) else None
        if a.vararg:
            scope[a.vararg.arg] = tuple(args[len(names):])
        for x, d in zip(a.kwonlyargs, a.kw_defaults):
            scope[x.arg] = kw.pop(x.arg, self.eval(d) if d is not None else None)
        if a.kwarg:
            scope[a.kwarg.arg] = dict(kw)
        inputs = [(nm, scope[nm]) for nm in names if isinstance(scope.get(nm), (str, bytes, bytearray)) and len(scope[nm]) >= 8]
        self.scopes.append(scope)
        try:
            if f.lam:
                result = self.eval(f.body)
            else:
                try:
                    self.block(f.body)
                    result = None
                except _Return as r:
                    result = r.value
        finally:
            self.scopes.pop()
            self.call_depth -= 1
        if isinstance(result, (str, bytes, bytearray)) and inputs and f.name != "<lambda>":
            main = max(inputs, key=lambda x: len(x[1]))
            r = rec(result)
            stepname = getattr(result, "inplace", "") or f"{f.name}()"
            base = r if r[:len(rec(main[1]))] == rec(main[1]) and rec(main[1]) else (rec(main[1]) + r[-3:])
            result = tag(result, base + (stepname,))
        return result

    # -- the library a loader uses ---------------------------------------------------------------
    def module_call(self, name: str, args: list, kw: dict, line: int | None) -> Any:  # noqa: C901
        n = name.lower()
        last = n.rsplit(".", 1)[-1]
        a0 = args[0] if args else kw.get("s", kw.get("data", kw.get("string")))
        if any(isinstance(x, Unk) for x in args):
            u = next(x for x in args if isinstance(x, Unk))
            if n in ("builtins.exec", "exec"):
                return self._exec(u, "exec", line)
            return Unk(u.why)
        if n.startswith("base64."):
            if last in ("b64decode", "standard_b64decode", "decodebytes", "decodestring", "urlsafe_b64decode"):
                return step(a0, "base64", RBytes(T.b64decode(a0, urlsafe=True if "urlsafe" in last else None)))
            if last in ("b32decode",):
                return step(a0, "base32", RBytes(T.b32decode(a0)))
            if last in ("b16decode",):
                return step(a0, "hex", RBytes(T.hexdecode(a0)))
            if last in ("b85decode", "a85decode"):
                return step(a0, "base85", RBytes(T.b85decode(a0)))
            if last in ("b64encode", "standard_b64encode", "urlsafe_b64encode", "encodebytes"):
                return RBytes(T.b64encode(a0).encode())
        if n.startswith("binascii."):
            if last in ("unhexlify", "a2b_hex"):
                return step(a0, "hex", RBytes(T.hexdecode(a0)))
            if last == "a2b_base64":
                return step(a0, "base64", RBytes(T.b64decode(a0)))
            if last in ("hexlify", "b2a_hex"):
                return RBytes(T.as_bytes(a0).hex().encode())
        if n in ("zlib.decompress", "zlib.decompressobj"):
            wbits = args[1] if len(args) > 1 else kw.get("wbits", 15)
            data = T.as_bytes(a0)
            out = T.inflate(data) if wbits < 0 else (T.gunzip(data) if wbits > 25 else T.zlib_decompress(data))
            return step(a0, {True: "deflate", False: "zlib"}[wbits < 0] if wbits <= 25 else "gzip", RBytes(out))
        if n == "gzip.decompress":
            return step(a0, "gzip", RBytes(T.gunzip(a0)))
        if n == "lzma.decompress":
            return step(a0, "lzma", RBytes(T.unlzma(a0)))
        if n == "bz2.decompress":
            return step(a0, "bzip2", RBytes(T.bunzip2(a0)))
        if n in ("codecs.decode", "codecs.encode"):
            enc = str(args[1] if len(args) > 1 else kw.get("encoding", "utf-8")).lower().replace("_", "")
            if enc in ("rot13", "rot-13"):
                return step(a0, "rot13", T.rot(str(a0)))
            if enc in ("hex", "hexcodec") and n.endswith("decode"):
                return step(a0, "hex", RBytes(T.hexdecode(a0)))
            if enc in ("base64", "base64codec") and n.endswith("decode"):
                return step(a0, "base64", RBytes(T.b64decode(a0)))
            if enc in ("zlib", "zlibcodec") and n.endswith("decode"):
                return step(a0, "zlib", RBytes(T.zlib_decompress(a0)))
            if enc in ("bz2", "bz2codec") and n.endswith("decode"):
                return step(a0, "bzip2", RBytes(T.bunzip2(a0)))
            if isinstance(a0, (bytes, bytearray)):
                return T.as_text(bytes(a0), enc)
            return a0
        if n in ("marshal.loads", "pickle.loads"):
            raw = T.as_bytes(a0)
            return CodeObj(None, raw, rec(a0) + (n,))
        if n.startswith(("crypto.cipher.", "cryptodome.cipher.")) and last == "new":
            alg = n.split(".")[2].lower()
            key = args[0] if args else kw.get("key")
            mode = args[1] if len(args) > 1 else kw.get("mode", 1)
            iv = args[2] if len(args) > 2 else kw.get("iv", kw.get("nonce"))
            return Obj("pycipher", alg=alg, key=key, mode=mode, iv=iv)
        if n.endswith(("crypto.util.padding.unpad", "cryptodome.util.padding.unpad")) or n == "unpad":
            data = T.as_bytes(a0)
            pad = data[-1] if data else 0
            return tag(RBytes(data[:-pad] if 0 < pad <= 32 else data), rec(a0))
        if n.endswith("fernet.fernet") or last == "fernet":
            return Obj("fernet", key=a0)
        if n.endswith(("ciphers.cipher",)) or last == "cipher":
            return Obj("hazmat_cipher", alg=args[0] if args else None, mode=args[1] if len(args) > 1 else None)
        if n.endswith(("algorithms.aes", "algorithms.tripledes", "algorithms.chacha20", "algorithms.arc4")):
            return Obj("hazmat_alg", alg=last, key=a0, nonce=args[1] if len(args) > 1 else None)
        if n.endswith(("modes.cbc", "modes.ecb", "modes.ctr", "modes.cfb", "modes.ofb", "modes.gcm")):
            return Obj("hazmat_mode", mode=last, iv=a0)
        if n in ("hashlib.sha256", "hashlib.md5", "hashlib.sha1"):
            return Obj("hasher", alg=last, data=T.as_bytes(a0) if a0 is not None else b"")
        if n.startswith("ctypes") or n.startswith("windll") or ".windll." in n or "kernel32" in n:
            for x in args:
                if isinstance(x, (bytes, bytearray)) and len(x) >= 32:
                    self.sinks.load(self.to_value(x), f"ctypes {name.split('ctypes.', 1)[-1]} (bytes to native memory)", line=line)
            if last in ("create_string_buffer", "c_char_p", "c_buffer"):
                return Obj("cbuffer", data=a0)
            return Obj("cvalue")
        if n in ("os.system", "os.popen", "subprocess.run", "subprocess.popen", "subprocess.call", "subprocess.check_output",
                 "subprocess.check_call", "os.startfile", "os.execv", "os.spawnv"):
            cmd = a0 if not isinstance(a0, (list, tuple)) else " ".join(str(x) for x in a0)
            self.sinks.step(line, f"{name} {str(cmd)[:200]}", Value.of(str(cmd)))
            self.external(str(cmd), line, rec(a0))
            return Obj("process") if n != "subprocess.check_output" else Unk(f"the output of {str(cmd)[:60]}")
        if n in ("urllib.request.urlopen", "urllib2.urlopen", "urllib.urlopen", "requests.get", "requests.post",
                 "urllib.request.urlretrieve", "requests.request", "httpx.get", "urllib.request.request"):
            url = a0 if not (n.endswith("request") and len(args) > 1) else args[1]
            dest = str(args[1]) if n.endswith("urlretrieve") and len(args) > 1 else ""
            self._download(url, name, f"saves it to {dest}" if dest else "returns it to the script", line, dest)
            got = Unk(f"the content downloaded from {url if not isinstance(url, Unk) else 'a URL'}")
            return Obj("response", url=str(url), content=got, text=got, status_code=200) if not dest else None
        if n in ("os.getenv", "os.environ.get"):
            return self.env(str(a0))
        if n in ("os.path.join",):
            return "\\".join(str(x) for x in args)
        if n in ("os.path.exists", "os.path.isfile", "os.path.isdir"):
            return Unk(f"whether {a0} exists on the victim's machine")
        if n in ("os.getcwd", "tempfile.gettempdir", "os.path.expanduser", "platform.node", "socket.gethostname", "getpass.getuser"):
            return Unk(f"{name}() on the victim's machine")
        if n in ("time.sleep", "random.seed", "sys.exit", "os._exit", "atexit.register", "print"):
            if n in ("sys.exit", "os._exit"):
                raise SystemExit()
            return None
        if n in ("importlib.import_module",):
            return Module(str(a0))
        if n == "socket.socket":
            return Obj("socket")
        if n in ("struct.unpack", "struct.pack"):
            import struct
            return getattr(struct, last)(*args)
        if n == "random.randint":
            return args[0] if args else 0
        return Unk(f"the result of {name}()")

    def py_method(self, o: Any, name: str, args: list, kw: dict, line: int | None) -> Any:  # noqa: C901
        if any(isinstance(x, Unk) for x in args):
            return next(x for x in args if isinstance(x, Unk))
        r = rec(o)
        if isinstance(o, (bytes, bytearray)):
            if name == "decode":
                enc = str(args[0] if args else kw.get("encoding", "utf-8"))
                out = T.as_text(bytes(o), enc)
                return tag(out, r) if r else out
            if name == "hex":
                return bytes(o).hex()
            if name == "translate":
                return tag(RBytes(bytes(o).translate(*args)), r)
        if isinstance(o, str):
            if name == "encode":
                enc = str(args[0] if args else kw.get("encoding", "utf-8"))
                try:
                    out = o.encode(enc if enc.lower() not in ("unicode_escape",) else "latin-1", "replace")
                except LookupError:
                    out = o.encode("utf-8", "replace")
                return tag(RBytes(out), r)
        if isinstance(o, dict) and name == "get":
            return o.get(*args)
        fn = getattr(o, name, None)
        if fn is None or name.startswith("_"):
            return Unk(f"{type(o).__name__}.{name}")
        out = fn(*args, **kw)
        if isinstance(out, (str, bytes, bytearray)) and r:
            return tag(out, r)
        return out

    def obj_method(self, o: Any, name: str, args: list, kw: dict, line: int | None) -> Any:  # noqa: C901
        if isinstance(o, CodeObj):
            return None
        k = getattr(o, "kind", "")
        if k == "pycipher" and name in ("decrypt", "decrypt_and_verify"):
            data = args[0] if args else b""
            if isinstance(data, Unk) or isinstance(o.key, Unk):
                return Unk("data or key not known")
            alg = {"aes": "aes", "des3": "3des", "des": "des", "arc4": "rc4", "chacha20": "chacha20"}.get(o.alg, o.alg)
            key = T.as_bytes(o.key)
            if alg == "rc4":
                return step(data, f"rc4(key {label(o.key, key[:6].hex())})", RBytes(T.rc4(data, key)))
            if alg == "chacha20":
                return step(data, "chacha20", RBytes(T.decrypt("chacha20", data, key, T.as_bytes(o.iv) if o.iv else None)))
            mode = {1: "ecb", 2: "cbc", 3: "cfb", 5: "ofb", 6: "ctr", 11: "gcm"}.get(o.mode if isinstance(o.mode, int) else 1, "cbc")
            out = T.decrypt(alg, data, key, T.as_bytes(o.iv) if o.iv is not None else None, mode, "none")
            return step(data, f"{alg}-{len(key) * 8}-{mode}(key {label(o.key, key[:6].hex())})" if alg == "aes" else f"{alg}-{mode}", RBytes(out))
        if k == "fernet" and name == "decrypt":
            return self.fernet(o.key, args[0] if args else b"")
        if k == "hazmat_cipher" and name == "decryptor":
            return Obj("hazmat_dec", cipher=o, buf=bytearray(), recipe=())
        if k == "hazmat_dec":
            if name == "update":
                o.buf += T.as_bytes(args[0])
                o.recipe = rec(args[0]) or o.recipe
                return RBytes(b"")
            if name == "finalize":
                alg, mode = o.cipher.alg, o.cipher.mode
                key = T.as_bytes(alg.key)
                a = {"aes": "aes", "tripledes": "3des", "chacha20": "chacha20", "arc4": "rc4"}[alg.alg]
                if a == "rc4":
                    return tag(RBytes(T.rc4(bytes(o.buf), key)), o.recipe + ("rc4",))
                if a == "chacha20":
                    return tag(RBytes(T.decrypt("chacha20", bytes(o.buf), key, T.as_bytes(alg.nonce))), o.recipe + ("chacha20",))
                out = T.decrypt(a, bytes(o.buf), key, T.as_bytes(mode.iv) if mode and mode.iv is not None else None,
                                mode.mode if mode else "ecb", "none")
                return tag(RBytes(out), o.recipe + (f"{a}-{len(key) * 8}-{mode.mode if mode else 'ecb'}",))
        if k == "hasher":
            if name == "update":
                o.data += T.as_bytes(args[0])
                return None
            if name in ("digest", "hexdigest"):
                d = T.digest(o.alg, o.data)
                return d if name == "digest" else d.hex()
        if k == "response":
            if name in ("read", "json", "iter_content"):
                return Unk(f"the content downloaded from {o.url}")
        if k == "cbuffer":
            return None
        if k == "environ" and name == "get":
            return self.env(str(args[0]))
        if k == "file":
            if name == "write" and args:
                if isinstance(args[0], Unk):
                    self.sinks._downloaded(Value.unknown(args[0].why), f"saves it to {o.path}")
                    return 0
                self.sinks.write(self.to_value(args[0]), o.path, "open().write", line)
                return len(args[0]) if not isinstance(args[0], Unk) else 0
            if name in ("read", "readlines"):
                return Unk(f"the content of the file {o.path} on the victim's machine")
            return None
        if k == "socket" and name == "connect" and args:
            host = args[0]
            self.sinks.download(Value.of(f"tcp://{host[0]}:{host[1]}" if isinstance(host, tuple) else str(host)), "socket.connect",
                                "opens a raw TCP connection (reverse shell / C2)", line)
            return None
        return Unk(f"{name}() of a {k}")

    def fernet(self, key: Any, token: Any) -> Any:
        if isinstance(key, Unk) or isinstance(token, Unk):
            return Unk("a Fernet key or token not known")
        k = T.b64decode(key, urlsafe=True)
        t = T.b64decode(token, urlsafe=True)
        if len(k) != 32 or len(t) < 57 or t[0] != 0x80:
            raise ValueError("not a Fernet token")
        out = T.decrypt("aes", t[25:-32], k[16:], t[9:25], "cbc")
        return step(token, f"fernet(key {label(key, 'key')})", RBytes(out))

    def env(self, name: str) -> Any:
        u = name.upper()
        if u in ENV:
            return ENV[u]
        return Unk(ENV_MACHINE.get(u, f"the environment variable {name} of the victim's machine"))

    def attr_env(self) -> Any:
        return Obj("environ")

    # -- builtins -------------------------------------------------------------------------------
    def _builtins(self) -> dict[str, Any]:
        def b(name: str, fn: Callable[..., Any]) -> Builtin:
            return Builtin(name, fn)

        def _bytes(x: Any = b"", enc: str | None = None, errors: str = "strict") -> Any:
            if isinstance(x, Unk):
                return x
            if isinstance(x, str):
                return tag(RBytes(x.encode(enc or "utf-8", "replace")), rec(x))
            if isinstance(x, int):
                if x > T.MAX_OUT:
                    raise Limit("bytes")
                return RBytes(x)
            return tag(RBytes(bytes(x)), rec(x))

        def _bytearray(x: Any = b"", enc: str | None = None) -> Any:
            if isinstance(x, Unk):
                return x
            if isinstance(x, str):
                return tag(RByteArray(x.encode(enc or "utf-8", "replace")), rec(x))
            if isinstance(x, int):
                if x > T.MAX_OUT:
                    raise Limit("bytearray")
                return RByteArray(x)
            return tag(RByteArray(bytes(x)), rec(x))

        def _getattr(o: Any, name: Any, *default: Any) -> Any:
            if isinstance(name, Unk):
                return Unk(name.why)
            return self.attr(o, str(name))

        def _import(name: Any, *a: Any, **k: Any) -> Any:
            if isinstance(name, Unk):
                self.sinks.unresolved_("__import__(…)", name.why, "the module name is computed from something not in the script", None)
                return Unk(f"a module whose name depends on {name.why}")
            return Module(str(name))

        def _open(path: Any, mode: str = "r", *a: Any, **k: Any) -> Any:
            return Obj("file", path=str(path) if not isinstance(path, Unk) else f"<{path.why}>", mode=mode)

        def _print(*a: Any, **k: Any) -> None:
            self.sinks.step(None, "print " + " ".join(str(x) for x in a)[:200], Value.of(""))

        def _bytes_fromhex(s: str) -> Any:
            return step(s, "hex", RBytes(T.hexdecode(s)))

        def _join_ints(it: Any) -> Any:
            return it

        def _int(x: Any = 0, base: int = 10) -> Any:
            if isinstance(x, Unk):
                return x
            return int(x, base) if isinstance(x, (str, bytes)) else int(x)

        def _chr(x: Any) -> Any:
            return x if isinstance(x, Unk) else chr(x)

        def _ord(x: Any) -> Any:
            return x if isinstance(x, Unk) else ord(x)

        def _range(*a: Any) -> Any:
            r = range(*a)
            if len(r) > MAX_LOOP:
                raise Limit("range")
            return r

        def _sstr(x: Any = "", *a: Any) -> Any:
            if isinstance(x, Unk):
                return x
            if isinstance(x, (bytes, bytearray)) and a:
                return tag(T.as_text(bytes(x), str(a[0])), rec(x))
            return tag(str(x), rec(x)) if rec(x) else str(x)

        bfn = {
            "len": len, "range": _range, "chr": _chr, "ord": _ord, "int": _int, "str": _sstr, "bytes": _bytes,
            "bytearray": _bytearray, "list": list, "tuple": tuple, "dict": dict, "set": set, "sorted": sorted,
            "reversed": lambda x: tag(list(reversed(x)), rec(x)), "enumerate": enumerate, "zip": zip, "sum": sum,
            "min": min, "max": max, "abs": abs, "hex": hex, "bin": bin, "oct": oct, "any": any, "all": all,
            "bool": bool, "float": float, "round": round, "divmod": divmod, "pow": pow, "isinstance": lambda a, b: False,
            "getattr": _getattr, "__import__": _import, "open": _open, "print": _print, "repr": repr, "type": lambda x: type(x),
            "map": lambda f, *its: [self.invoke(f, list(x), {}, None) for x in zip(*its)],
            "filter": lambda f, it: [x for x in it if self.truth(self.invoke(f, [x], {}, None) if f is not None else x)],
            "iter": iter, "next": next, "hasattr": lambda o, n: True, "setattr": lambda *a: None, "id": id, "hash": hash,
            "format": format, "slice": slice, "frozenset": frozenset, "object": object, "callable": lambda x: True,
            "globals": lambda: self.g, "locals": lambda: self.scopes[-1], "vars": lambda *a: self.scopes[-1],
            "input": lambda *a: Unk("what the user types"),
        }
        out: dict[str, Any] = {k: b(k, v) for k, v in bfn.items()}
        out["exec"] = b("exec", lambda code, *a, _line=None, **k: self._exec(code, "exec", _line))
        out["eval"] = b("eval", lambda code, *a, _line=None, **k: self._exec(code, "eval", _line, want=True))
        out["compile"] = b("compile", lambda code, *a, _line=None, **k: CodeObj(code if isinstance(code, str) else (T.as_text(bytes(code)) if isinstance(code, (bytes, bytearray)) else None), None, rec(code) + ("compile",)))
        out["bytes"].fromhex = _bytes_fromhex  # type: ignore[attr-defined]
        out["int"].from_bytes = lambda b, order="big", signed=False: int.from_bytes(bytes(b), order, signed=signed)  # type: ignore[attr-defined]
        return out

    # -- exec / eval -------------------------------------------------------------------------------
    def _exec(self, code: Any, sink: str, line: int | None, want: bool = False) -> Any:
        if isinstance(code, Unk):
            self.sinks.exec_(Value.unknown(code.why), sink, line)
            return Unk(f"the output of code computed from {code.why}")
        if isinstance(code, CodeObj):
            if code.source is not None:
                code = tag(code.source, code.recipe)
            elif code.raw is not None:
                self.sinks.load(Value("bytes", code.raw, code.recipe), f"{sink} of a code object (marshal)", line=line)
                return None
        if isinstance(code, (bytes, bytearray)):
            code = tag(T.as_text(bytes(code)), rec(code))
        text = str(code)
        self.sinks.exec_(Value("str", text, rec(code)), sink, line)
        h = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if self.depth >= MAX_DEPTH or h in self.ran:
            return None
        self.ran.add(h)
        self.depth += 1
        self.sinks.depth = self.depth
        saved = self.source
        self.source = text
        try:
            if want:
                try:
                    return self.eval(ast.parse(text.strip(), mode="eval").body)
                except SyntaxError:
                    pass
            tree = ast.parse(text)
            self.block(tree.body, top=True)
        except (SyntaxError, ValueError) as exc:
            self.errors.append(f"line {line}: {sink} of code that does not parse: {exc}"[:300])
        finally:
            self.source = saved
            self.depth -= 1
            self.sinks.depth = self.depth
        return None

    # -- helpers ------------------------------------------------------------------------------
    def _download(self, url: Any, method: str, use: str, line: int | None, dest: str = "") -> None:
        if isinstance(url, Unk):
            self.sinks.download(Value.unknown(url.why), method, use, line, dest)
        else:
            self.sinks.download(Value("str", str(url), rec(url)), method, use, line, dest)

    def external(self, cmd: str, line: int | None, recipe: tuple[str, ...]) -> None:
        from .ps_eval import resolve as ps_resolve
        m = re.search(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*?\s-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", cmd)
        if m:
            try:
                code = T.as_text(T.b64decode(m.group(1)), "utf-16-le")
            except T.TransformError:
                return
            self.sinks.exec_(Value("str", code, recipe + ("base64 (-EncodedCommand)", "utf-16")), "powershell -EncodedCommand", line)
            st = self.sinks.stages[-1] if self.sinks.stages else None
            if st is not None and st.data == code:
                st.ext = ".ps1"
            del ps_resolve

    def _span(self, line: int | None) -> str:
        lines = self.source.splitlines()
        return lines[line - 1].strip()[:200] if line and 0 < line <= len(lines) else ""

    def to_value(self, v: Any) -> Value:
        r = rec(v)
        if isinstance(v, Unk):
            return Value.unknown(v.why, r)
        if isinstance(v, (bytes, bytearray)):
            return Value("bytes", bytes(v), r)
        if isinstance(v, str):
            return Value("str", str(v), r)
        if isinstance(v, list) and v and all(isinstance(x, int) for x in v[:64]):
            try:
                return Value("bytes", bytes(x & 0xFF for x in v), r)
            except (TypeError, ValueError):
                pass
        return Value.of(v)

    def computed_values(self) -> None:
        """Values computed and left in a variable: a PE, an archive, code — a stage as well."""
        from . import langdetect
        seen: set[int] = set()
        for name, v in list(self.g.items()) + list(self.tracked.items()):
            if id(v) in seen or not isinstance(v, (str, bytes, bytearray)) or len(v) < 40:
                continue
            seen.add(id(v))
            ops = [r for r in rec(v) if not r.startswith(("literal", "variable"))]
            if len(ops) < 2 and not getattr(v, "inplace", ""):
                continue
            raw = bytes(v) if isinstance(v, (bytes, bytearray)) else str(v).encode("utf-8", "replace")
            if any(st.recipe[:len(rec(v))] == rec(v) and len(st.recipe) > len(rec(v)) for st in self.sinks.stages):
                continue
            kind = T.magic(raw)
            if not kind and T.is_text(raw):
                txt = T.as_text(raw) if not isinstance(v, str) else str(v)
                if txt in self.source:
                    continue
                if langdetect.languages(txt):
                    self.sinks.exec_(Value("str", txt, rec(v)), f"value of {name} (computed, not run here)")
                    continue
                if re.search(r"(?i)\bhttps?://|\b\d{1,3}(?:\.\d{1,3}){3}\b", txt):
                    self.sinks.value_(Value("str", txt, rec(v)), f"value of {name} (decoded text with IOCs)")
                continue
            if kind or getattr(v, "inplace", ""):
                r = rec(v) + ((v.inplace,) if getattr(v, "inplace", "") else ())
                self.sinks.load(Value("bytes", raw, r), f"value of {name} (computed, not run here)")


def resolve(code: str, location: str = "python") -> Sinks:
    """Evaluate a Python script statically; its stages, downloads, unresolved calls and trace."""
    s = Sinks("python")
    it = Interp(s, code.lstrip("\ufeff"))
    try:
        it.run(code.lstrip("\ufeff"))
    except RecursionError:
        it.errors.append("recursion")
    s.errors = it.errors  # type: ignore[attr-defined]
    s.stats = {"steps": it.steps, "seconds": round(time.monotonic() - it.t0, 2)}  # type: ignore[attr-defined]
    return s
