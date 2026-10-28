"""Static unwrapping of Python "exec chains" — nothing is executed.

Python droppers and the public obfuscators (pyobfuscate, Kramer, BlankOBF,
"Development-Tool"…) hide the real code behind layers of

    exec(zlib.decompress(base64.b64decode(b'...')))
    exec(marshal.loads(lzma.decompress(base64.b85decode('...')[::-1])))
    _ = lambda __: __import__('zlib').decompress(__import__('base64').b64decode(__[::-1])); exec((_)(b'...'))

often 10–100 deep. This module walks the AST, evaluates **only** a whitelist of
pure decoding functions (base64/32/16/85, hex, zlib/gzip/bz2/lzma, rot13,
``.decode()``/``.encode()``, ``[::-1]``, ``bytes([...])``, ``str()``/``bytes()``
conversions) over constants and single-assignment variables, and repeats on the
result until no ``exec``/``eval``/``compile`` wrapper is left. ``marshal.loads``
results are not run: the code object is described (names, strings) when the
analysing interpreter can load it, else its strings are carved.

PyArmor and similar runtime-encryption protectors cannot be undone statically;
they are detected so the analyst knows why the code stays opaque.
"""

from __future__ import annotations

import ast
import base64
import binascii
import bz2
import codecs
import gzip
import lzma
import re
import zlib
from typing import Any, Callable

MAX_LAYERS = 120
MAX_SIZE = 8 * 1024 * 1024


class _Marshal(bytes):
    """Bytes that were passed to marshal.loads (a code object, not text)."""


def _rot13(x: Any) -> str:
    return codecs.decode(x if isinstance(x, str) else x.decode("latin-1"), "rot13")


def _codecs_decode(x: Any, enc: str = "utf-8", *_a: Any) -> Any:
    e = str(enc).lower().replace("-", "_")
    if e in ("rot13", "rot_13"):
        return _rot13(x)
    if e in ("hex", "hex_codec"):
        return bytes.fromhex(x.decode() if isinstance(x, bytes) else x)
    if e in ("base64", "base64_codec", "base_64"):
        return base64.b64decode(x)
    if e in ("zlib", "zlib_codec", "zip"):
        return zlib.decompress(x)
    if e in ("bz2", "bz2_codec"):
        return bz2.decompress(x)
    return x.decode(enc) if isinstance(x, bytes) else x


def _limit(fn: Callable[..., Any]) -> Callable[..., Any]:
    def f(*a: Any, **k: Any) -> Any:
        out = fn(*a, **k)
        if isinstance(out, (bytes, str)) and len(out) > MAX_SIZE:
            raise ValueError("too large")
        return out
    return f


def _zdec(data: bytes, wbits: int = 15, *_a: Any) -> bytes:
    d = zlib.decompressobj(wbits)
    out = d.decompress(data, MAX_SIZE + 1)
    if len(out) > MAX_SIZE:
        raise ValueError("too large")
    return out


# dotted name -> (callable, step label)
_FUNCS: dict[str, tuple[Callable[..., Any], str]] = {
    "base64.b64decode": (base64.b64decode, "base64"),
    "base64.standard_b64decode": (base64.standard_b64decode, "base64"),
    "base64.urlsafe_b64decode": (base64.urlsafe_b64decode, "base64url"),
    "base64.b32decode": (base64.b32decode, "base32"),
    "base64.b16decode": (base64.b16decode, "base16"),
    "base64.b85decode": (base64.b85decode, "base85"),
    "base64.a85decode": (base64.a85decode, "ascii85"),
    "base64.decodebytes": (base64.decodebytes, "base64"),
    "binascii.unhexlify": (binascii.unhexlify, "hex"),
    "binascii.a2b_hex": (binascii.a2b_hex, "hex"),
    "binascii.a2b_base64": (binascii.a2b_base64, "base64"),
    "bytes.fromhex": (bytes.fromhex, "hex"),
    "zlib.decompress": (_zdec, "zlib"),
    "gzip.decompress": (_limit(gzip.decompress), "gzip"),
    "bz2.decompress": (_limit(bz2.decompress), "bz2"),
    "lzma.decompress": (_limit(lzma.decompress), "lzma"),
    "codecs.decode": (_codecs_decode, "codecs"),
    "marshal.loads": (lambda b, *_a: _Marshal(b), "marshal"),
}
_METHODS = {"decode", "encode", "strip", "replace", "lower", "upper"}
_EXEC = {"exec", "eval", "compile", "builtins.exec", "builtins.eval"}

PYARMOR = re.compile(r"(?:from\s+pytransform\s+import\s+pyarmor|__pyarmor__\s*\(|pyarmor_runtime(?:_\d+)?|"
                     r"__pyarmor_(?:enter|exit|assert)_|#\s*Pyarmor\s+\d)", re.I)


class _Fail(Exception):
    pass


class _Eval:
    def __init__(self, tree: ast.AST) -> None:
        self.alias: dict[str, str] = {}      # local name -> dotted module/function
        self.consts: dict[str, ast.AST] = {}
        self.lambdas: dict[str, ast.Lambda] = {}
        self.steps: list[str] = []
        counts: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    self.alias[a.asname or a.name] = f"{node.module}.{a.name}"
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                counts[name] = counts.get(name, 0) + 1
                if isinstance(node.value, ast.Lambda):
                    self.lambdas[name] = node.value
                else:
                    self.consts[name] = node.value
        for name, c in counts.items():
            if c > 1:
                self.consts.pop(name, None)
                self.lambdas.pop(name, None)

    def dotted(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__"
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            return node.args[0].value
        return None

    def ev(self, node: ast.AST, env: dict[str, Any] | None = None, depth: int = 0) -> Any:
        if depth > 200:
            raise _Fail
        env = env or {}
        d = depth + 1
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int)):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id in self.consts:
                return self.ev(self.consts[node.id], None, d)
            raise _Fail
        if isinstance(node, ast.JoinedStr):
            raise _Fail
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            a, b = self.ev(node.left, env, d), self.ev(node.right, env, d)
            if type(a) is not type(b) and not (isinstance(a, bytes) and isinstance(b, bytes)):
                raise _Fail
            return a + b
        if isinstance(node, ast.Subscript):
            val = self.ev(node.value, env, d)
            sl = node.slice
            if isinstance(sl, ast.Slice):
                parts = [None if p is None else self.ev(p, env, d) for p in (sl.lower, sl.upper, sl.step)]
                if not all(p is None or isinstance(p, int) for p in parts):
                    raise _Fail
                if parts == [None, None, -1]:
                    self.steps.append("reverse")
                return val[slice(*parts)]
            raise _Fail
        if isinstance(node, (ast.List, ast.Tuple)):
            return [self.ev(e, env, d) for e in node.elts]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            v = self.ev(node.operand, env, d)
            if isinstance(v, int):
                return -v
            raise _Fail
        if isinstance(node, ast.Call):
            return self.call(node, env, d)
        raise _Fail

    def call(self, node: ast.Call, env: dict[str, Any], d: int) -> Any:
        args = [self.ev(a, env, d) for a in node.args]
        f = node.func
        # (lambda x: ...)(arg) / name bound to a lambda
        lam = f if isinstance(f, ast.Lambda) else (self.lambdas.get(f.id) if isinstance(f, ast.Name) else None)
        if lam is not None:
            names = [a.arg for a in lam.args.args]
            if len(names) != len(args):
                raise _Fail
            return self.ev(lam.body, {**env, **dict(zip(names, args))}, d)
        if isinstance(f, ast.Attribute) and f.attr in _METHODS:
            obj = self.dotted(f.value)
            if obj not in ("str", "bytes"):
                target = self.ev(f.value, env, d)
                if not isinstance(target, (str, bytes)):
                    raise _Fail
                enc = next((a for a in args if isinstance(a, str)), "utf-8")
                if f.attr == "decode" and isinstance(target, bytes):
                    return target.decode(enc, "replace")
                if f.attr == "encode" and isinstance(target, str):
                    return target.encode(enc)
                return getattr(target, f.attr)(*args)
        name = self.dotted(f)
        if name in ("bytes", "bytearray") and args and isinstance(args[0], list):
            return bytes(args[0])
        if name in ("bytes", "str") and args and isinstance(args[0], (str, bytes)):
            if name == "str":
                return args[0].decode(*(args[1:2] or ["utf-8"])) if isinstance(args[0], bytes) else args[0]
            return args[0].encode(*(args[1:2] or ["utf-8"])) if isinstance(args[0], str) else args[0]
        if name and name.endswith(".decode") and name.split(".")[0] in ("bytes", "str") and args:
            return args[0].decode(*args[1:2]) if isinstance(args[0], bytes) else args[0]
        if name in _FUNCS:
            fn, label = _FUNCS[name]
            try:
                out = fn(*args)
            except Exception as exc:  # noqa: BLE001
                raise _Fail from exc
            self.steps.append(label if label != "codecs" else f"codecs({args[1] if len(args) > 1 else ''})")
            return out
        raise _Fail


def _exec_args(tree: ast.AST, ev: _Eval) -> list[ast.AST]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            name = ev.dotted(node.func)
            if name in _EXEC:
                arg = node.args[0]
                # exec(compile(X, '<string>', 'exec'))
                if isinstance(arg, ast.Call) and ev.dotted(arg.func) == "compile" and arg.args:
                    arg = arg.args[0]
                out.append(arg)
    return out


def describe_code(blob: bytes) -> str:
    """Names and strings of a marshalled code object (no execution)."""
    try:
        import marshal
        from .python import _reconstruct
        co = marshal.loads(blob)
        if hasattr(co, "co_code"):
            return "\n".join(_reconstruct(co))
    except Exception:  # noqa: BLE001
        pass
    from .python import _carve_strings
    return "\n".join(_carve_strings(blob))


def unwrap(src: str) -> dict[str, Any]:
    """Peel exec layers. Returns ``{"layers": n, "steps": [...], "code": final,
    "kind": "source"|"marshal"|None, "pyarmor": bool}``."""
    res: dict[str, Any] = {"layers": 0, "steps": [], "code": None, "kind": None,
                           "pyarmor": bool(PYARMOR.search(src or ""))}
    cur = src
    for _ in range(MAX_LAYERS):
        try:
            tree = ast.parse(cur)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            break
        ev = _Eval(tree)
        got = None
        for arg in _exec_args(tree, ev):
            ev.steps = []
            try:
                val = ev.ev(arg)
            except (_Fail, RecursionError, ValueError, TypeError, UnicodeError, MemoryError):
                continue
            if isinstance(val, (str, bytes)) and len(val) >= 4:
                got = (val, list(ev.steps))
                break
        if got is None:
            break
        val, steps = got
        res["layers"] += 1
        res["steps"].extend(steps)
        if isinstance(val, _Marshal):
            res["code"], res["kind"] = describe_code(bytes(val)), "marshal"
            break
        text = val.decode("utf-8", "replace") if isinstance(val, bytes) else val
        res["code"], res["kind"] = text, "source"
        if PYARMOR.search(text):
            res["pyarmor"] = True
        cur = text
    return res
