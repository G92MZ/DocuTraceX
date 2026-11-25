"""A small CIL emulator for ConfuserEx's constants (and the assembly it embeds), as de4dot does.

ConfuserEx builds that mutate the constants protection — control flow flattened into a
``switch`` on a state number, the key derivation inlined into ``<Module>.cctor``, the ids
passed through ``br.s`` — defeat the pattern reader in ``confuser.py``. This module does
not read patterns: it **interprets the CIL** of the module initializer and of the getters
(``Get<T>(uint id)``) on a model of the runtime, so whatever arithmetic the protection uses,
the strings come out as the program would see them.

What is modelled: the evaluation stack, locals and arguments, integer / long arithmetic and
conversions, branches and ``switch``, arrays (``newarr`` / ``ldelem`` / ``stelem`` /
``ldelema`` / ``ldind`` / ``stind``), static fields, ``RuntimeHelpers.InitializeArray``
from the FieldRVA data, ``Buffer.BlockCopy``, ``Array.Copy`` / ``Reverse``,
``BitConverter``, ``Encoding.GetString``, ``String.Intern``, ``MemoryStream`` and calls into
the assembly's own methods. A method that decompresses LZMA (ConfuserEx's own decoder) is
answered with Python's ``lzma`` when its argument is an LZMA stream. ``Assembly.Load`` of a
byte array records the assembly (ConfuserEx's embedded resources / compressor payload).

Everything else of the platform — reflection, ``AppDomain``, ``Environment``, P/Invoke —
answers *unknown* (null / 0 for a branch): nothing touches the machine. ``Environment.FailFast``
stops. Budgets on steps, time, call depth and array sizes bound every run.
"""

from __future__ import annotations

import lzma
import re
import struct
import time
from typing import Any

MAX_STEPS = 30_000_000
MAX_SECONDS = 45.0
MAX_DEPTH = 48
MAX_ARRAY = 32 * 1024 * 1024
MAX_GETTER_STEPS = 300_000
MAX_SITES = 3000


class EmuError(Exception):
    pass


class _Stop(Exception):
    pass


class _Opaque:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<unknown>"


OPQ = _Opaque()


class I8(int):
    """A 64-bit value on the stack (int32 values are plain ints)."""


class Arr:
    __slots__ = ("data", "kind")

    def __init__(self, kind: str, n: int) -> None:
        if n < 0 or n > MAX_ARRAY:
            raise EmuError(f"array of {n}")
        self.kind = kind
        self.data: Any = bytearray(n) if kind in ("u1", "i1") else [None if kind == "ref" else 0] * n


class Ref:
    __slots__ = ("box", "key")

    def __init__(self, box: Any, key: Any) -> None:
        self.box, self.key = box, key

    def get(self) -> Any:
        if isinstance(self.box, Arr):
            return _elem_get(self.box, self.key, self.box.kind)
        return self.box.get(self.key) if isinstance(self.box, dict) else self.box[self.key]

    def set(self, v: Any) -> None:
        if isinstance(self.box, Arr):
            _elem_set(self.box, self.key, v)
        else:
            self.box[self.key] = v


class Obj:
    __slots__ = ("st", "type")

    def __init__(self, type_: str, **st: Any) -> None:
        self.type, self.st = type_, st


_SIZE = {"u1": 1, "i1": 1, "u2": 2, "i2": 2, "u4": 4, "i4": 4, "u8": 8, "i8": 8, "r4": 4, "r8": 8}
_ELEM = {"System.Byte": "u1", "System.SByte": "i1", "System.UInt16": "u2", "System.Int16": "i2", "System.Char": "u2",
         "System.UInt32": "u4", "System.Int32": "i4", "System.UInt64": "u8", "System.Int64": "i8",
         "System.Boolean": "u1", "System.IntPtr": "i4", "System.UIntPtr": "u4"}
_LD = {"ldelem.u1": "u1", "ldelem.i1": "i1", "ldelem.u2": "u2", "ldelem.i2": "i2", "ldelem.u4": "u4",
       "ldelem.i4": "i4", "ldelem.i8": "i8", "ldelem.i": "i4", "ldelem.ref": "ref", "ldelem.r4": "r4",
       "ldelem.r8": "r8"}
_ST = {"stelem.i1": "i1", "stelem.i2": "i2", "stelem.i4": "i4", "stelem.i8": "i8", "stelem.i": "i4",
       "stelem.ref": "ref", "stelem.r4": "r4", "stelem.r8": "r8"}
_IND = {"ldind.u1": "u1", "ldind.i1": "i1", "ldind.u2": "u2", "ldind.i2": "i2", "ldind.u4": "u4", "ldind.i4": "i4",
        "ldind.i8": "i8", "ldind.i": "i4", "ldind.ref": "ref", "ldind.r4": "r4", "ldind.r8": "r8"}


def _i4(x: int) -> int:
    return ((int(x) + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def _i8(x: int) -> I8:
    return I8(((int(x) + (1 << 63)) & 0xFFFFFFFFFFFFFFFF) - (1 << 63))


def _num(v: Any) -> Any:
    if v is None:
        return 0
    if isinstance(v, bool):
        return int(v)
    return v


def _load_as(v: Any, kind: str) -> Any:
    """A stored element / indirect value as it lands on the stack."""
    if kind == "ref" or v is None or v is OPQ or not isinstance(v, (int, float)):
        return v
    if kind == "u1":
        return v & 0xFF
    if kind == "i1":
        return ((v & 0xFF) ^ 0x80) - 0x80
    if kind == "u2":
        return v & 0xFFFF
    if kind == "i2":
        return ((v & 0xFFFF) ^ 0x8000) - 0x8000
    if kind in ("u4", "i4"):
        return _i4(v)
    if kind in ("u8", "i8"):
        return _i8(v)
    return float(v)


def _elem_get(a: Arr, i: Any, kind: str) -> Any:
    i = _num(i)
    if not isinstance(i, int):
        raise EmuError("index")
    v = a.data[i]
    return _load_as(v, kind if kind != "ref" else a.kind if a.kind != "ref" else "ref")


def _elem_set(a: Arr, i: Any, v: Any) -> None:
    i = _num(i)
    if not isinstance(i, int):
        raise EmuError("index")
    if a.kind in ("u1", "i1"):
        a.data[i] = (_num(v) if isinstance(_num(v), int) else 0) & 0xFF
    elif a.kind == "ref":
        a.data[i] = v
    elif a.kind in ("r4", "r8"):
        a.data[i] = float(_num(v)) if v is not OPQ else 0.0
    else:
        bits = _SIZE.get(a.kind, 4) * 8
        a.data[i] = (_num(v) & ((1 << bits) - 1)) if isinstance(_num(v), int) else 0


def arr_bytes(a: Arr) -> bytes:
    if a.kind in ("u1", "i1"):
        return bytes(a.data)
    if a.kind == "ref":
        raise EmuError("bytes of a reference array")
    n = _SIZE.get(a.kind, 4)
    if a.kind in ("r4", "r8"):
        return b"".join(struct.pack("<f" if n == 4 else "<d", x) for x in a.data)
    return b"".join(int(x).to_bytes(n, "little") for x in a.data)


def arr_set_bytes(a: Arr, off: int, b: bytes) -> None:
    if a.kind in ("u1", "i1"):
        a.data[off:off + len(b)] = b
        return
    whole = bytearray(arr_bytes(a))
    whole[off:off + len(b)] = b
    n = _SIZE.get(a.kind, 4)
    for i in range(len(a.data)):
        a.data[i] = int.from_bytes(whole[i * n:i * n + n], "little")


def _truthy(v: Any) -> bool:
    if v is OPQ or v is None:
        return False
    if isinstance(v, (int, float)):
        return v != 0
    return True


def _cmp(op: str, a: Any, b: Any) -> bool:
    a, b = _num(a), _num(b)
    if a is OPQ or b is OPQ:
        return False
    if op in ("eq",):
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a == b
        if isinstance(a, str) and isinstance(b, str):
            return a == b
        return a is b
    if op == "ne":
        return not _cmp("eq", a, b)
    if not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
        # reference compared with null: cgt.un obj, null → obj != null
        if op == "gt_un":
            return a is not None and b is None
        return False
    if op.endswith("_un") and isinstance(a, int) and isinstance(b, int):
        mask = 0xFFFFFFFFFFFFFFFF if isinstance(a, I8) or isinstance(b, I8) else 0xFFFFFFFF
        a, b = a & mask, b & mask
    o = op.replace("_un", "")
    return {"gt": a > b, "lt": a < b, "ge": a >= b, "le": a <= b}[o]


def _arith(op: str, a: Any, b: Any) -> Any:
    a, b = _num(a), _num(b)
    if a is OPQ or b is OPQ or not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return OPQ
    if isinstance(a, float) or isinstance(b, float):
        if op == "add":
            return a + b
        if op == "sub":
            return a - b
        if op == "mul":
            return a * b
        if op in ("div", "div.un"):
            return a / b if b else OPQ
        if op in ("rem", "rem.un"):
            return a % b if b else OPQ
        return OPQ
    wide = isinstance(a, I8) or isinstance(b, I8)
    bits = 64 if wide else 32
    mask = (1 << bits) - 1
    wrap = _i8 if wide else _i4
    if op == "add":
        return wrap(a + b)
    if op == "sub":
        return wrap(a - b)
    if op == "mul":
        return wrap(a * b)
    if op == "and":
        return wrap(a & b)
    if op == "or":
        return wrap(a | b)
    if op == "xor":
        return wrap(a ^ b)
    if op == "shl":
        return wrap(a << (b & (bits - 1)))
    if op == "shr":
        return wrap(a >> (b & (bits - 1)))
    if op == "shr.un":
        return wrap((a & mask) >> (b & (bits - 1)))
    if op in ("div", "rem"):
        if b == 0:
            raise EmuError("division by zero")
        q = abs(a) // abs(b) * (1 if (a >= 0) == (b >= 0) else -1)
        return wrap(q if op == "div" else a - q * b)
    if op in ("div.un", "rem.un"):
        ua, ub = a & mask, b & mask
        if ub == 0:
            raise EmuError("division by zero")
        return wrap(ua // ub if op == "div.un" else ua % ub)
    return OPQ


def _conv(op: str, v: Any) -> Any:
    v = _num(v)
    if v is OPQ or not isinstance(v, (int, float)):
        return v if op in ("conv.i", "conv.u") else OPQ
    k = op.replace("conv.ovf.", "conv.").replace(".un", "")
    if isinstance(v, float) and k not in ("conv.r4", "conv.r8", "conv.r"):
        v = int(v)
    if k == "conv.i1":
        return ((v & 0xFF) ^ 0x80) - 0x80
    if k == "conv.u1":
        return v & 0xFF
    if k == "conv.i2":
        return ((v & 0xFFFF) ^ 0x8000) - 0x8000
    if k == "conv.u2":
        return v & 0xFFFF
    if k in ("conv.i4", "conv.u4", "conv.i", "conv.u"):
        return _i4(v)
    if k == "conv.i8":
        return _i8(v)
    if k == "conv.u8":
        return _i8(v if isinstance(v, I8) else v & 0xFFFFFFFF) if v >= 0 or isinstance(v, I8) else _i8(v & 0xFFFFFFFF)
    if k in ("conv.r4", "conv.r8", "conv.r"):
        return float(v if not op.endswith(".un") else (v & 0xFFFFFFFFFFFFFFFF if isinstance(v, I8) else v & 0xFFFFFFFF))
    return OPQ


def _cint(b: bytes, i: int) -> tuple[int, int]:
    """ECMA-335 compressed unsigned integer."""
    x = b[i]
    if not x & 0x80:
        return x, i + 1
    if not x & 0x40:
        return ((x & 0x3F) << 8) | b[i + 1], i + 2
    return ((x & 0x1F) << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3], i + 4


def sig_shape(sig: bytes) -> tuple[bool, int, bool]:
    """(has this, number of parameters, returns void) of a method signature blob."""
    if not sig:
        return False, 0, True
    flags = sig[0]
    i = 1
    if flags & 0x10:
        _, i = _cint(sig, i)
    n, i = _cint(sig, i)
    ret = sig[i] if i < len(sig) else 0x01
    return bool(flags & 0x20) and not flags & 0x40, n, ret == 0x01


class Emu:
    def __init__(self, pe: Any) -> None:
        from .cil import _name, _owners, _reader_class, static_fields
        self.pe = pe
        self.t = pe.net.mdtables
        self.us = pe.net.user_strings
        self.owners = _owners(self.t)
        self.fields = static_fields(pe)
        self._reader = _reader_class(pe)
        self._name = _name
        self.statics: dict[Any, Any] = {}
        self.bodies: dict[int, Any] = {}
        self.def_rid = {id(m): i for i, m in enumerate(self.t.MethodDef or [], 1)}
        self.mref_rid = {id(m): i for i, m in enumerate(getattr(self.t, "MemberRef", None) or [], 1)}
        self.steps = 0
        self.t0 = time.monotonic()
        self.limit = MAX_STEPS
        self.assemblies: list[bytes] = []
        self.lzma_calls = 0
        self.unknown_calls: dict[str, int] = {}
        self.last_off = 0
        self.this_assembly = Obj("Assembly", name="(this module)")
        self.capture: list[tuple[int, int, Any, str]] | None = None
        self.frames: list[int] = []

    # -- metadata ---------------------------------------------------------------------------
    def body(self, rid: int) -> Any:
        if rid in self.bodies:
            return self.bodies[rid]
        from dncil.cil.body import CilMethodBody
        m = self.t.MethodDef[rid - 1]
        _this, n, void = sig_shape(bytes(m.Signature.value or b""))
        static = bool(m.Flags.mdStatic)
        nargs = n + (0 if static else 1)
        if not m.Rva:                         # runtime-implemented (a delegate's .ctor / Invoke) or extern
            self.bodies[rid] = (None, None, nargs, void)
            return self.bodies[rid]
        b = CilMethodBody(self._reader(m.Rva))
        insns = list(b.instructions)
        idx = {ins.offset: n for n, ins in enumerate(insns)}
        self.bodies[rid] = (insns, idx, nargs, void)
        return self.bodies[rid]

    def method_name(self, rid: int) -> str:
        return self.owners.get(rid, f"#{rid}").split("::")[-1]

    def method_target(self, tok: Any) -> tuple[str, Any]:
        """('def', rid) for the assembly's own code, ('ref', (name, has_this, nparams, void))."""
        table, rid = getattr(tok, "table", None), getattr(tok, "rid", 0)
        if table == 0x06:
            return "def", rid
        if table == 0x2B:
            row = self.t.MethodSpec[rid - 1]
            r = self.def_rid.get(id(row.Method.row))
            if r:
                return "def", r
            mr = self.mref_rid.get(id(row.Method.row))
            if mr:
                return self.method_target(type("T", (), {"table": 0x0A, "rid": mr})())
            return "ref", ("?", False, 0, True)
        if table == 0x0A:
            row = self.t.MemberRef[rid - 1]
            has_this, n, void = sig_shape(bytes(row.Signature.value or b""))
            return "ref", (self._name(0x0A, row), has_this, n, void)
        return "ref", ("?", False, 0, True)

    def type_name(self, tok: Any) -> str:
        table, rid = getattr(tok, "table", None), getattr(tok, "rid", 0)
        try:
            if table in (0x01, 0x02):
                row = (self.t.TypeRef if table == 0x01 else self.t.TypeDef)[rid - 1]
                return f"{row.TypeNamespace}.{row.TypeName}".strip(".")
        except (IndexError, AttributeError):
            pass
        return "?"

    def ustring(self, tok: Any) -> str:
        try:
            v = self.us.get(tok.rid)
            return str(v.value) if v is not None and v.value is not None else ""
        except Exception:  # noqa: BLE001
            return ""

    # -- execution ----------------------------------------------------------------------------
    def tick(self) -> None:
        self.steps += 1
        if self.steps > self.limit:
            raise EmuError("step budget")
        if not self.steps & 0xFFFF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise EmuError("time budget")

    def call_def(self, rid: int, args: list[Any], depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise EmuError("call depth")
        b = self.body(rid)
        if b is None:
            return OPQ
        insns, idx, nargs, void = b
        if insns is None:
            return self.runtime_method(rid, args, depth)
        # ConfuserEx's own LZMA decoder: answered natively when the argument is an LZMA stream
        if nargs == 1 and isinstance(args[0], Arr) and args[0].kind == "u1" and not void:
            out = _lzma(bytes(args[0].data))
            if out is not None:
                self.lzma_calls += 1
                a = Arr("u1", 0)
                a.data = bytearray(out)
                return a
        try:
            r = self.run(insns, idx, args, void, depth)
            # a decoder: integer arguments in, text out (a constants getter, reached directly, through a
            # proxy method or a delegate) — kept with the method that asked for it
            if self.capture is not None and isinstance(r, str) and r and args and all(
                    isinstance(x, int) and not isinstance(x, bool) for x in args):
                self.capture.append((self.frames[0] if self.frames else rid, rid, args[0], r))
            return r
        except EmuError as exc:
            if " @ " not in str(exc):
                raise EmuError(f"{exc} @ method #{rid} IL_{self.last_off - insns[0].offset:04x}") from None
            raise

    def runtime_method(self, rid: int, args: list[Any], depth: int) -> Any:
        """A delegate's runtime methods: ``.ctor(object, native int)`` keeps the target ``ldftn`` gave,
        ``Invoke`` calls it (ConfuserEx's reference proxies through delegates)."""
        name = self.method_name(rid)
        if name == ".ctor" and len(args) == 3 and isinstance(args[0], Obj):
            fn = args[2]
            args[0].st["target"] = fn.st.get("target") if isinstance(fn, Obj) else None
            args[0].st["bound"] = args[1]
            return None
        if name == "Invoke" and args and isinstance(args[0], Obj):
            return self.invoke(args[0].st.get("target"), args[0].st.get("bound"), list(args[1:]), depth)
        return OPQ

    def invoke(self, target: Any, bound: Any, args: list[Any], depth: int) -> Any:
        if not target:
            return OPQ
        kind, t = target
        if kind == "def":
            b = self.body(t)
            if b and b[2] == len(args) + 1 and bound is not None:
                args = [bound] + args
            return self.call_def(t, args, depth + 1)
        name, has_this, _n, _void = t
        return self.extern(name, ([bound] if has_this and bound is not None else []) + args, False)

    def run(self, insns: list[Any], idx: dict[int, int], args: list[Any], void: bool, depth: int) -> Any:  # noqa: C901, PLR0912, PLR0915
        st: list[Any] = []
        loc: dict[int, Any] = {}
        args = list(args)
        pc = 0
        n = len(insns)
        push, pop = st.append, st.pop
        while pc < n:
            self.tick()
            ins = insns[pc]
            self.last_off = ins.offset
            op = ins.opcode.name
            arg = ins.operand
            pc += 1
            if op == "nop" or op.startswith(("volatile.", "unaligned.", "readonly.", "constrained.", "tail.")):
                continue
            if op.startswith("ldc."):
                if op in ("ldc.i8",):
                    push(_i8(arg))
                elif op in ("ldc.r4", "ldc.r8"):
                    push(float(arg))
                else:
                    push(_i4(ins.get_ldc()))
                continue
            if op.startswith("ldloc"):
                i = arg.index if hasattr(arg, "index") else int(op.rsplit(".", 1)[1])
                push(loc.get(i, 0))
                continue
            if op.startswith("stloc"):
                i = arg.index if hasattr(arg, "index") else int(op.rsplit(".", 1)[1])
                loc[i] = pop()
                continue
            if op.startswith("ldarga"):
                push(Ref(args, arg.index))
                continue
            if op.startswith("ldarg"):
                i = arg.index if hasattr(arg, "index") else int(op.rsplit(".", 1)[1])
                push(args[i] if i < len(args) else 0)
                continue
            if op.startswith("starg"):
                args[arg.index] = pop()
                continue
            if op.startswith("ldloca"):
                push(Ref(loc, arg.index))
                continue
            if op in ("br", "br.s", "leave", "leave.s"):
                pc = idx[arg]
                continue
            if op in ("brtrue", "brtrue.s", "brfalse", "brfalse.s"):
                v = _truthy(pop())
                if v == op.startswith("brtrue"):
                    pc = idx[arg]
                continue
            if op.startswith(("beq", "bne", "bge", "bgt", "ble", "blt")):
                b, a = pop(), pop()
                kind = op.split(".")[0][1:]
                kind = {"eq": "eq", "ne": "ne"}.get(kind, kind)
                if ".un" in op and kind not in ("eq", "ne"):
                    kind += "_un"
                if _cmp(kind, a, b):
                    pc = idx[arg]
                continue
            if op == "switch":
                v = _num(pop())
                if isinstance(v, int) and 0 <= (v & 0xFFFFFFFF) < len(arg):
                    pc = idx[arg[v & 0xFFFFFFFF]]
                continue
            if op in ("add", "sub", "mul", "div", "div.un", "rem", "rem.un", "and", "or", "xor", "shl", "shr",
                      "shr.un", "add.ovf", "add.ovf.un", "sub.ovf", "sub.ovf.un", "mul.ovf", "mul.ovf.un"):
                b, a = pop(), pop()
                push(_arith(op.replace(".ovf.un", "").replace(".ovf", ""), a, b))
                continue
            if op == "neg":
                v = _num(pop())
                push(OPQ if not isinstance(v, (int, float)) else (-v if isinstance(v, float) else
                                                                   (_i8(-v) if isinstance(v, I8) else _i4(-v))))
                continue
            if op == "not":
                v = _num(pop())
                push(OPQ if not isinstance(v, int) else (_i8(~v) if isinstance(v, I8) else _i4(~v)))
                continue
            if op.startswith("conv."):
                push(_conv(op, pop()))
                continue
            if op in ("ceq", "cgt", "cgt.un", "clt", "clt.un"):
                b, a = pop(), pop()
                push(1 if _cmp({"ceq": "eq", "cgt": "gt", "cgt.un": "gt_un", "clt": "lt", "clt.un": "lt_un"}[op],
                               a, b) else 0)
                continue
            if op == "dup":
                push(st[-1])
                continue
            if op == "pop":
                pop()
                continue
            if op == "ldnull":
                push(None)
                continue
            if op == "ldstr":
                push(self.ustring(arg))
                continue
            if op == "ret":
                return None if void else (pop() if st else OPQ)
            if op == "newarr":
                cnt = _num(pop())
                if not isinstance(cnt, int):
                    raise EmuError("array size")
                push(Arr(_ELEM.get(self.type_name(arg), "ref"), cnt))
                continue
            if op == "ldlen":
                a = pop()
                if not isinstance(a, Arr):
                    raise EmuError("ldlen")
                push(len(a.data))
                continue
            if op in _LD or op == "ldelem":
                i, a = pop(), pop()
                if not isinstance(a, Arr):
                    raise EmuError("ldelem")
                kind = _LD.get(op) or _ELEM.get(self.type_name(arg), "ref")
                push(_elem_get(a, i, kind))
                continue
            if op in _ST or op == "stelem":
                v, i, a = pop(), pop(), pop()
                if not isinstance(a, Arr):
                    raise EmuError("stelem")
                _elem_set(a, i, v)
                continue
            if op == "ldelema":
                i, a = pop(), pop()
                if not isinstance(a, Arr):
                    raise EmuError("ldelema")
                push(Ref(a, _num(i)))
                continue
            if op in _IND:
                r = pop()
                if not isinstance(r, Ref):
                    raise EmuError("ldind")
                push(_load_as(r.get(), _IND[op]))
                continue
            if op.startswith("stind."):
                v, r = pop(), pop()
                if not isinstance(r, Ref):
                    raise EmuError("stind")
                r.set(v)
                continue
            if op == "ldsfld":
                push(self.load_static(arg))
                continue
            if op == "stsfld":
                self.statics[self.field_key(arg)] = pop()
                continue
            if op == "ldsflda":
                push(Ref(self.statics, self.field_key(arg)))
                continue
            if op == "ldfld":
                o = pop()
                push(o.st.get(("f", self.field_key(arg)), 0) if isinstance(o, Obj) else OPQ)
                continue
            if op == "stfld":
                v, o = pop(), pop()
                if isinstance(o, Obj):
                    o.st[("f", self.field_key(arg))] = v
                continue
            if op == "ldflda":
                o = pop()
                push(Ref(o.st, ("f", self.field_key(arg))) if isinstance(o, Obj) else OPQ)
                continue
            if op == "ldtoken":
                tb = getattr(arg, "table", None)
                push(("field", arg.rid) if tb == 0x04 else ("type", self.type_name(arg)) if tb in (0x01, 0x02)
                     else OPQ)
                continue
            if op in ("ldftn", "ldvirtftn"):
                if op == "ldvirtftn":
                    pop()
                push(Obj("fn", target=self.method_target(arg)))
                continue
            if op in ("box", "unbox.any", "unbox", "castclass", "isinst"):
                continue                      # values are untyped here
            if op in ("call", "callvirt", "newobj"):
                kind, tgt = self.method_target(arg)
                if kind == "def":
                    b = self.body(tgt)
                    nargs = b[2] if b else 0
                    void = b[3] if b else True
                    if op == "newobj":
                        o = Obj(self.owners.get(tgt, "?"))
                        cargs = [pop() for _ in range(max(0, nargs - 1))][::-1]
                        self.call_def(tgt, [o] + cargs, depth + 1)
                        push(o)
                        continue
                    cargs = [pop() for _ in range(nargs)][::-1]
                    r = self.call_def(tgt, cargs, depth + 1)
                    if not void:
                        push(r)
                    continue
                name, has_this, nparams, void = tgt
                cnt = nparams + (1 if has_this and op != "newobj" else 0)
                cargs = [pop() for _ in range(cnt)][::-1]
                r = self.extern(name, cargs, op == "newobj")
                if op == "newobj" or not void:
                    push(r)
                continue
            if op in ("throw", "rethrow"):
                raise EmuError("throw")
            if op in ("endfinally", "endfault", "endfilter"):
                continue
            if op in ("initobj",):
                pop()
                continue
            if op in ("sizeof",):
                push(4)
                continue
            if op in ("localloc", "cpblk", "initblk", "jmp", "calli", "mkrefany", "refanyval", "refanytype",
                      "arglist", "ckfinite", "break", "ldobj", "stobj", "cpobj", "ldelem.any"):
                raise EmuError(f"unsupported {op}")
            raise EmuError(f"unsupported {op}")
        return None if void else OPQ

    def field_key(self, tok: Any) -> Any:
        tb = getattr(tok, "table", None)
        if tb == 0x04:
            return tok.rid
        if tb == 0x0A:
            try:
                return "ref:" + self._name(0x0A, self.t.MemberRef[tok.rid - 1])
            except (IndexError, AttributeError):
                return "ref:?"
        return f"?{tb}:{getattr(tok, 'rid', 0)}"

    def load_static(self, tok: Any) -> Any:
        k = self.field_key(tok)
        if k in self.statics:
            return self.statics[k]
        if isinstance(k, str) and k.endswith("BitConverter::IsLittleEndian"):
            return 1
        if isinstance(k, str):
            return OPQ
        return 0 if isinstance(k, int) else OPQ

    # -- the platform ---------------------------------------------------------------------------
    def extern(self, name: str, a: list[Any], new: bool) -> Any:  # noqa: C901, PLR0911, PLR0912
        short = name.split("::")[-1]
        typ = name.split("::")[0]
        if new and short == ".ctor" and len(a) == 2 and isinstance(a[1], Obj) and a[1].type == "fn":
            return Obj("delegate", target=a[1].st.get("target"), bound=a[0])     # Func<…> / Action<…>
        if name.endswith("RuntimeHelpers::InitializeArray"):
            arr, fld = a
            if isinstance(arr, Arr) and isinstance(fld, tuple) and fld[0] == "field" and fld[1] in self.fields:
                raw = self.fields[fld[1]]
                if arr.kind in ("u1", "i1"):
                    arr.data[:len(raw)] = raw[:len(arr.data)]
                elif arr.kind != "ref":
                    arr_set_bytes(arr, 0, raw[:len(arr.data) * _SIZE.get(arr.kind, 4)])
            return None
        if name == "System.Type::GetTypeFromHandle":
            return Obj("Type", name=a[0][1] if isinstance(a[0], tuple) else "?")
        if typ == "System.Text.Encoding" and short in ("get_UTF8", "get_ASCII", "get_Unicode", "get_Default",
                                                       "get_BigEndianUnicode", "get_UTF32"):
            return Obj("Encoding", codec={"get_UTF8": "utf-8", "get_ASCII": "ascii", "get_Unicode": "utf-16-le",
                                          "get_BigEndianUnicode": "utf-16-be", "get_UTF32": "utf-32-le",
                                          "get_Default": "cp1252"}[short])
        if typ.startswith("System.Text.") and short == "GetString":
            enc = a[0].st.get("codec", "utf-8") if isinstance(a[0], Obj) else "utf-8"
            data = a[1]
            if not isinstance(data, Arr) or data.kind not in ("u1", "i1"):
                return OPQ
            raw = bytes(data.data)
            if len(a) >= 4:
                raw = raw[_num(a[2]):_num(a[2]) + _num(a[3])]
            return raw.decode(enc, "replace")
        if typ.startswith("System.Text.") and short == "GetBytes" and isinstance(a[-1], str):
            enc = a[0].st.get("codec", "utf-8") if isinstance(a[0], Obj) else "utf-8"
            out = Arr("u1", 0)
            out.data = bytearray(a[-1].encode(enc, "replace"))
            return out
        if typ == "System.String":
            return self.string_call(short, a)
        if name == "System.Buffer::BlockCopy":
            src, so, dst, do, cnt = a
            if isinstance(src, Arr) and isinstance(dst, Arr):
                b = arr_bytes(src)[_num(so):_num(so) + _num(cnt)]
                arr_set_bytes(dst, _num(do), b)
            return None
        if name == "System.Array::Reverse" and isinstance(a[0], Arr):
            if len(a) == 1:
                a[0].data.reverse()
            else:
                i, c = _num(a[1]), _num(a[2])
                a[0].data[i:i + c] = a[0].data[i:i + c][::-1]
            return None
        if name == "System.Array::Copy":
            if len(a) == 3:
                src, dst, cnt = a
                so = do = 0
            else:
                src, so, dst, do, cnt = a
            if isinstance(src, Arr) and isinstance(dst, Arr):
                dst.data[_num(do):_num(do) + _num(cnt)] = src.data[_num(so):_num(so) + _num(cnt)]
            return None
        if name in ("System.Array::get_Length",) and isinstance(a[0], Arr):
            return len(a[0].data)
        if typ == "System.BitConverter" and short.startswith("To") and isinstance(a[0], Arr):
            fmt = {"ToInt32": "<i", "ToUInt32": "<I", "ToInt16": "<h", "ToUInt16": "<H", "ToInt64": "<q",
                   "ToUInt64": "<Q"}.get(short)
            if fmt:
                v = struct.unpack_from(fmt, arr_bytes(a[0]), _num(a[1]))[0]
                return _i8(v) if fmt[-1] in "qQ" else _i4(v)
            return OPQ
        if typ == "System.Math" and short in ("Min", "Max", "Abs"):
            vs = [_num(x) for x in a]
            if any(not isinstance(v, (int, float)) for v in vs):
                return OPQ
            return {"Min": min, "Max": max}.get(short, lambda v: abs(v))(*vs)
        if typ in ("System.IO.MemoryStream", "System.IO.Stream", "System.IO.BinaryReader"):
            return self.stream_call(short, a, new)
        if name == "System.Reflection.Assembly::Load" and a and isinstance(a[0], Arr) and a[0].kind == "u1":
            if bytes(a[0].data) not in self.assemblies:
                self.assemblies.append(bytes(a[0].data))
            return Obj("Assembly")
        if name in ("System.Reflection.Assembly::GetCallingAssembly", "System.Reflection.Assembly::GetExecutingAssembly",
                    "System.Reflection.Assembly::GetEntryAssembly"):
            return self.this_assembly                  # ConfuserEx's getters check the caller is the module itself
        if short in ("Equals", "op_Equality", "op_Inequality", "ReferenceEquals") and len(a) == 2 and typ in (
                "System.Object", "System.Reflection.Assembly", "System.Type", "System.Reflection.Module"):
            same = a[0] is a[1] or (isinstance(a[0], (int, str)) and a[0] == a[1])
            return int(same) if short != "op_Inequality" else int(not same)
        if short in ("ResolveMethod", "ResolveField", "ResolveMember") and typ == "System.Reflection.Module":
            tok = _num(a[1]) if len(a) > 1 else 0
            if isinstance(tok, int):
                tb, r = (tok >> 24) & 0xFF, tok & 0xFFFFFF
                if tb == 0x06:
                    return Obj("MethodInfo", target=("def", r))
                if tb == 0x0A:
                    return Obj("MethodInfo", target=self.method_target(type("T", (), {"table": 0x0A, "rid": r})()))
                if tb == 0x04:
                    return Obj("FieldInfo", rid=r)
            return OPQ
        if name == "System.Reflection.FieldInfo::GetFieldFromHandle" and isinstance(a[0], tuple):
            return Obj("FieldInfo", rid=a[0][1])
        if short == "get_Name" and a and isinstance(a[0], Obj) and a[0].type == "FieldInfo":
            try:
                return str(self.t.Field[a[0].st["rid"] - 1].Name)
            except (IndexError, AttributeError):
                return OPQ
        if short == "SetValue" and a and isinstance(a[0], Obj) and a[0].type == "FieldInfo" and len(a) >= 3:
            self.statics[a[0].st["rid"]] = a[2]
            return None
        if short == "GetValue" and a and isinstance(a[0], Obj) and a[0].type == "FieldInfo":
            return self.statics.get(a[0].st["rid"], OPQ)
        if name == "System.Delegate::CreateDelegate":
            mi = next((x for x in a if isinstance(x, Obj) and x.type == "MethodInfo"), None)
            return Obj("delegate", target=mi.st["target"], bound=None) if mi else OPQ
        if short in ("Invoke", "DynamicInvoke") and a and isinstance(a[0], Obj) and a[0].type in ("MethodInfo", "delegate"):
            rest = a[1:]
            if a[0].type == "MethodInfo" and len(rest) == 2:          # MethodBase.Invoke(obj, object[])
                bound, arr = rest
                params = list(arr.data) if isinstance(arr, Arr) else []
                return self.invoke(a[0].st["target"], bound, params, 1)
            params = list(rest[0].data) if len(rest) == 1 and isinstance(rest[0], Arr) else list(rest)
            return self.invoke(a[0].st["target"], a[0].st.get("bound"), params, 1)
        if name == "System.Convert::FromBase64String" and a and isinstance(a[0], str):
            import base64 as _b64
            try:
                raw = _b64.b64decode(a[0] + "=" * (-len(a[0]) % 4))
            except ValueError:
                return OPQ
            out = Arr("u1", 0)
            out.data = bytearray(raw)
            return out
        if name == "System.Environment::FailFast":
            raise _Stop("FailFast")
        if name == "System.Object::.ctor":
            return None
        self.unknown_calls[name] = self.unknown_calls.get(name, 0) + 1
        return Obj(typ) if new else OPQ

    def string_call(self, short: str, a: list[Any]) -> Any:
        s = a[0] if a else None
        if short == "Intern" or short == "IsInterned":
            return s
        if short == "get_Length" and isinstance(s, str):
            return len(s)
        if short == "get_Chars" and isinstance(s, str):
            return ord(s[_num(a[1])])
        if short == "Concat":
            parts = a[0].data if len(a) == 1 and isinstance(a[0], Arr) else a
            if all(isinstance(p, str) or p is None for p in parts):
                return "".join(p or "" for p in parts)
            return OPQ
        if short in ("op_Equality", "Equals") and len(a) == 2:
            return 1 if isinstance(a[0], str) and a[0] == a[1] else 0
        if short == "op_Inequality" and len(a) == 2:
            return 0 if isinstance(a[0], str) and a[0] == a[1] else 1
        if short == "Substring" and isinstance(s, str):
            i = _num(a[1])
            return s[i:i + _num(a[2])] if len(a) > 2 else s[i:]
        if short == "ToCharArray" and isinstance(s, str):
            out = Arr("u2", len(s))
            out.data = [ord(c) for c in s]
            return out
        if short == ".ctor" and a and isinstance(a[0], Arr) and a[0].kind == "u2":
            return "".join(chr(c) for c in a[0].data)
        return OPQ

    def stream_call(self, short: str, a: list[Any], new: bool) -> Any:
        if new:
            data = bytearray(bytes(a[0].data)) if a and isinstance(a[0], Arr) else bytearray()
            return Obj("Stream", data=data, pos=0)
        s = a[0] if a else None
        if not isinstance(s, Obj) or s.type != "Stream":
            return OPQ
        d, pos = s.st["data"], s.st["pos"]
        if short == "Read":
            buf, off, cnt = a[1], _num(a[2]), _num(a[3])
            chunk = bytes(d[pos:pos + cnt])
            if isinstance(buf, Arr):
                arr_set_bytes(buf, off, chunk)
            s.st["pos"] = pos + len(chunk)
            return len(chunk)
        if short == "ReadByte":
            if pos >= len(d):
                return -1
            s.st["pos"] = pos + 1
            return d[pos]
        if short == "Write":
            buf, off, cnt = a[1], _num(a[2]), _num(a[3])
            if isinstance(buf, Arr):
                chunk = arr_bytes(buf)[off:off + cnt]
                d[pos:pos + len(chunk)] = chunk
                s.st["pos"] = pos + len(chunk)
            return None
        if short == "WriteByte":
            d[pos:pos + 1] = bytes([_num(a[1]) & 0xFF])
            s.st["pos"] = pos + 1
            return None
        if short == "get_Length":
            return _i8(len(d))
        if short == "get_Position":
            return _i8(pos)
        if short == "set_Position":
            s.st["pos"] = int(_num(a[1]))
            return None
        if short == "Seek":
            off, origin = int(_num(a[1])), _num(a[2])
            s.st["pos"] = off if origin == 0 else pos + off if origin == 1 else len(d) + off
            return _i8(s.st["pos"])
        if short == "ToArray":
            out = Arr("u1", 0)
            out.data = bytearray(d)
            return out
        return None


def _lzma(b: bytes) -> bytes | None:
    """An LZMA stream: the standard header (5 bytes of properties + a 64-bit size) or ConfuserEx's
    (properties + a 32-bit size)."""
    if len(b) < 9 or b[0] > 225:
        return None
    for head in (b[:13], b[:5] + b[5:9] + b"\x00" * 4):
        body = b[len(head) if head == b[:13] else 9:]
        size = int.from_bytes(head[5:13], "little")
        if size > MAX_ARRAY and size != 0xFFFFFFFFFFFFFFFF:
            continue
        try:
            out = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(head + body, max_length=MAX_ARRAY)
        except lzma.LZMAError:
            continue
        if out and (size == 0xFFFFFFFFFFFFFFFF or len(out) == size):
            return out
    return None


def _sites(emu: Emu) -> dict[int, list[tuple[int, int]]]:
    """getter rid → [(caller rid, id)]: ``ldc.i4 id`` (``br.s`` / ``nop`` between) ``call <one-arg static>``."""
    out: dict[int, list[tuple[int, int]]] = {}
    for rid in range(1, len(emu.t.MethodDef or []) + 1):
        try:
            b = emu.body(rid)
        except Exception:  # noqa: BLE001
            continue
        if not b or b[0] is None:
            continue
        insns, idx = b[0], b[1]
        for n, ins in enumerate(insns):
            if not ins.opcode.name.startswith("ldc.i4"):
                continue
            j = n + 1
            while j < len(insns) and (insns[j].opcode.name == "nop" or (
                    insns[j].opcode.name in ("br", "br.s") and idx.get(insns[j].operand) == j + 1)):
                j += 1
            if j >= len(insns) or insns[j].opcode.name != "call":
                continue
            try:
                kind, tgt = emu.method_target(insns[j].operand)
            except Exception:  # noqa: BLE001
                continue
            if kind != "def" or tgt == rid:
                continue
            tb = emu.body(tgt)
            if tb and tb[2] == 1 and not tb[3]:
                out.setdefault(tgt, []).append((rid, _i4(ins.get_ldc())))
    return out


MAX_DYN_STEPS = 200_000
MAX_DYN_SECONDS = 20.0


def _file_trials(blob: bytes, material: list[bytes]) -> tuple[bytes, list[str]] | None:
    """3DES / AES, CBC with each IV of the constants (or ECB), every key of the constants: the one whose
    plaintext starts with a file signature."""
    from .. import decrypted as dec
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            TripleDES = algorithms.TripleDES  # noqa: N806
    except Exception:  # noqa: BLE001
        return None
    keys = [k for k in material if len(k) in (16, 24, 32)][:8]
    ivs = [k for k in material if len(k) in (8, 16)][:8]
    for k in keys:
        algos = ([("3des", TripleDES, 8)] if len(k) in (16, 24) else []) + [("aes", algorithms.AES, 16)]
        for nm, algo, block in algos:
            if nm == "aes" and len(k) not in (16, 24, 32):
                continue
            for iv in [x for x in ivs if len(x) == block] + [None]:
                if len(blob) % block:
                    continue
                try:
                    c = Cipher(algo(k), modes.CBC(iv) if iv else modes.ECB())
                    head = c.decryptor().update(blob[:64])
                except Exception:  # noqa: BLE001
                    continue
                if head[:2] == b"MZ" or dec._strong_magic(head):
                    plain = Cipher(algo(k), modes.CBC(iv) if iv else modes.ECB()).decryptor().update(blob)
                    plain = dec._unpad(plain) or plain
                    bits = f"-{len(k) * 8}" if nm == "aes" else ""
                    mode = f"cbc, iv {iv.hex()}" if iv else "ecb"
                    return plain, [f"{nm}{bits}-{mode.split(',')[0]}(key {k[:8].hex()}…{', ' + mode.split(', ')[1] if iv else ''})"]
    return None


def _payloads(strings: list[str]) -> list[tuple[bytes, list[str]]]:
    """Files hidden in the recovered constants: a large base64 string that is itself a file, or one
    the other constants decrypt — base64 keys / IVs (8 / 16 / 24 / 32 bytes) and plain strings, tried
    with 3DES / AES / RC4 by the blind trials (the DarkCloud chain keeps its payload as base64 3DES
    with the key and IV next to it)."""
    import base64 as _b64

    from .. import decrypted as dec

    def b64(v: str) -> bytes | None:
        v = v.strip()
        if len(v) < 8 or len(v) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v):
            return None
        try:
            return _b64.b64decode(v)
        except ValueError:
            return None
    decoded = [(v, b64(v)) for v in strings]
    keys = {"arrays": [b for _v, b in decoded if b and len(b) in (8, 16, 24, 32)],
            "strings": [v.encode() for v, b in decoded if not b and 4 <= len(v) <= 64][:30]}
    out: list[tuple[bytes, list[str]]] = []
    for _v, b in decoded:
        if not b or len(b) < 256:
            continue
        if b[:2] == b"MZ" or dec._strong_magic(b[:64]):
            out.append((b, ["base64"]))
            continue
        got = _file_trials(b, keys["arrays"]) or dec._blind_ciphers(b, keys)
        if got:
            plain, steps = got
            out.append((plain, ["base64", *steps]))
    return out


def confuser_strings(data: bytes) -> dict[str, Any] | None:
    """Run ``<Module>.cctor``, every constants getter on its call sites, and then each method of the
    assembly, keeping what decoders return on the way (getters reached through proxy methods or
    delegates).

    ``{strings: [{caller, getter, id, output}], assemblies: [bytes], payloads: [(bytes, recipe)], how,
    error}`` or None when there is no module initializer."""
    import dnfile

    try:
        pe = dnfile.dnPE(data=data)
    except Exception:  # noqa: BLE001
        return None
    try:
        if not getattr(pe, "net", None) or not getattr(pe.net, "mdtables", None):
            return None
        emu = Emu(pe)
        cctor = next((rid for rid, nm in emu.owners.items() if nm == "<Module>::.cctor"), None)
        if cctor is None:
            return None
        sites = _sites(emu)
        getters = {g: s for g, s in sites.items() if len(s) >= 2}
        err = ""
        try:
            emu.call_def(cctor, [], 0)
        except _Stop as exc:
            err = f"module initializer stopped at {exc}"
        except (EmuError, Exception) as exc:  # noqa: BLE001
            err = f"module initializer: {exc}"[:200]
        found: list[dict[str, Any]] = []
        seen: set[tuple[int, int]] = set()

        def keep(caller: int, g: int, ident: int, v: str) -> None:
            if (g, ident) in seen:
                return
            seen.add((g, ident))
            found.append({"caller": emu.owners.get(caller, f"#{caller}"), "getter": emu.owners.get(g, f"#{g}"),
                          "id": f"0x{ident & 0xFFFFFFFF:08x}", "output": v})
        for g, ss in getters.items():
            for caller, ident in ss[:MAX_SITES]:
                if (g, ident) in seen:
                    continue
                emu.steps, emu.limit = 0, MAX_GETTER_STEPS
                try:
                    v = emu.call_def(g, [ident], 0)
                except (EmuError, _Stop, Exception):  # noqa: BLE001
                    continue
                if isinstance(v, str) and v:
                    keep(caller, g, ident, v)
        # every method once, its arguments zero: decoders called on the way are caught as they return
        n_static = len(found)
        t0 = time.monotonic()
        emu.capture = []
        for rid in range(1, len(emu.t.MethodDef or []) + 1):
            if rid == cctor or rid in getters or time.monotonic() - t0 > MAX_DYN_SECONDS:
                continue
            try:
                b = emu.body(rid)
            except Exception:  # noqa: BLE001
                continue
            if not b or b[0] is None:
                continue
            emu.frames = [rid]
            emu.steps, emu.limit = 0, MAX_DYN_STEPS
            m = emu.t.MethodDef[rid - 1]
            args = [0] * b[2]
            if not m.Flags.mdStatic and args:
                args[0] = Obj(emu.owners.get(rid, "?").split("::")[0])
            try:
                emu.call_def(rid, args, 0)
            except (EmuError, _Stop, Exception):  # noqa: BLE001
                pass
            for caller, g, ident, v in emu.capture:
                if caller != g:
                    keep(caller, g, ident, v)
            emu.capture = []
        emu.capture = None
        n_dyn = len(found) - n_static
        payloads = _payloads([x["output"] for x in found])
        if not found and not emu.assemblies:
            return {"strings": [], "assemblies": [], "payloads": [], "how": "",
                    "error": err or "no getter returned a string"}
        how = ("CIL emulation of <Module>.cctor and the constants getters (control flow followed as the "
               "program runs it" + (", LZMA answered natively" if emu.lzma_calls else "")
               + (f", {n_dyn} reached through proxies / delegates" if n_dyn else "") + ")")
        return {"strings": found, "assemblies": emu.assemblies, "payloads": payloads, "how": how, "error": err,
                "unknown_calls": sorted(emu.unknown_calls)[:40]}
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass
