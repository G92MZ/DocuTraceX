"""Inert .NET assemblies for the samples: a well-formed CLR metadata root with
the tables the .NET analysis reads (Module, TypeRef, TypeDef, MethodDef,
MemberRef, CustomAttribute, ModuleRef, ImplMap, Assembly, AssemblyRef,
ManifestResource) and the #Strings / #US / #GUID / #Blob heaps. Method bodies
are tiny IL (``ret`` unless given); nothing in them does anything.

Used through ``binkit.pe(dotnet_md=...)``: ``build(va, spec)`` returns
(bytes, clr header size, metadata rva, resources rva, resources size, entry token).
"""

from __future__ import annotations

import struct
from typing import Any


def _al(n: int, a: int) -> int:
    return (n + a - 1) // a * a


class _Heap:
    def __init__(self, first: bytes = b"\x00"):
        self.b = bytearray(first)
        self.idx: dict[Any, int] = {}

    def str(self, s: str) -> int:
        if not s:
            return 0
        if s not in self.idx:
            self.idx[s] = len(self.b)
            self.b += s.encode() + b"\x00"
        return self.idx[s]

    def blob(self, data: bytes) -> int:
        if not data:
            return 0
        key = ("b", data)
        if key not in self.idx:
            self.idx[key] = len(self.b)
            n = len(data)
            self.b += (bytes([n]) if n < 0x80 else struct.pack(">H", 0x8000 | n)) + data
        return self.idx[key]

    def us(self, s: str) -> int:
        key = ("u", s)
        if key not in self.idx:
            self.idx[key] = len(self.b)
            raw = s.encode("utf-16-le")
            raw += b"\x01" if any(ord(c) > 0x7E or ord(c) < 0x20 for c in s) else b"\x00"
            n = len(raw)
            self.b += (bytes([n]) if n < 0x80 else struct.pack(">H", 0x8000 | n)) + raw
        return self.idx[key]


_OP = {"ldstr": 0x72, "call": 0x28, "callvirt": 0x6F, "newobj": 0x73, "pop": 0x26, "ret": 0x2A, "calldef": 0x28,
       "xor": 0x61, "ldarg.0": 0x02, "initarray": 0x00, "ldc": 0x20, "shl": 0x62, "shr.un": 0x64, "mul": 0x5A,
       "brfalse.s": 0x2C, "br.s": 0x2B, "stsfld": 0x80}


def _ops(ops: list[tuple], us: _Heap, rids: dict[str, int] | None = None) -> bytes:
    """Tiny IL from (op, arg): ldstr "text" / call|callvirt|newobj memberref index /
    calldef "Type::Method" (own method) / ldc int / xor / shl / shr.un / mul / ldarg.0 / pop / ret /
    brfalse.s|br.s <signed byte offset from the next instruction>."""
    out = bytearray()
    for op, *arg in ops:
        out.append(_OP[op])
        if op == "ldstr":
            out += struct.pack("<I", 0x70000000 | us.us(arg[0]))
        elif op == "ldc":                           # ldc.i4 <int32>
            out += struct.pack("<I", arg[0] & 0xFFFFFFFF)
        elif op == "initarray":                     # ldc.i4 n; newarr byte; dup; ldtoken f; call InitializeArray
            name, size, mr = arg
            out[-1:] = b"\x20" + struct.pack("<i", size) + b"\x8d" + struct.pack("<I", 0x01000001) + b"\x25"
            out += b"\xd0" + struct.pack("<I", 0x04000000 | (rids or {})["field:" + name])
            out += b"\x28" + struct.pack("<I", 0x0A000000 | (mr + 1))
        elif op in ("brfalse.s", "br.s"):
            out += struct.pack("<b", arg[0])
        elif op == "calldef":
            out += struct.pack("<I", 0x06000000 | (rids or {})[arg[0]])
        elif op == "stsfld":                        # stsfld <own static field "Type::Field">
            out += struct.pack("<I", 0x04000000 | (rids or {})["field:" + arg[0]])
        elif op in ("call", "callvirt", "newobj"):
            out += struct.pack("<I", 0x0A000000 | (arg[0] + 1))
    return bytes(out)


def _7bit(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append(n & 0x7F | 0x80)
        n >>= 7
    return bytes(out + bytes([n]))


def resources(entries: list[tuple[str, Any]]) -> bytes:
    """A .resources file (ResourceReader v2): str → string, bytes → byte[],
    ("stream", bytes) → Stream, ("object", "Type, Assembly", bytes) → a
    serialized user type (BinaryFormatter-like blob, e.g. a Bitmap with its PNG)."""
    def s(x: str) -> bytes:
        b = x.encode()
        return _7bit(len(b)) + b
    reader = s("System.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
    reader += s("System.Resources.RuntimeResourceSet")
    out = bytearray(struct.pack("<iii", -1091581234, 1, len(reader)) + reader)
    utypes = list(dict.fromkeys(v[1] for _, v in entries if isinstance(v, tuple) and v[0] == "object"))
    out += struct.pack("<iii", 2, len(entries), len(utypes)) + b"".join(s(t) for t in utypes)
    while len(out) % 8:
        out += b"PAD"[len(out) % 3:len(out) % 3 + 1]
    data, names = bytearray(), bytearray()
    positions = []
    for name, v in entries:
        positions.append(len(names))
        nb = name.encode("utf-16-le")
        names += _7bit(len(nb)) + nb + struct.pack("<i", len(data))
        if isinstance(v, str):
            data += _7bit(1) + s(v)
        elif isinstance(v, tuple) and v[0] == "object":
            data += _7bit(0x40 + utypes.index(v[1])) + b"\x00\x01\x00\x00\x00\xff\xff\xff\xff" + v[2]
        elif isinstance(v, tuple):
            data += _7bit(0x21) + struct.pack("<i", len(v[1])) + v[1]
        else:
            data += _7bit(0x20) + struct.pack("<i", len(v)) + v
    out += b"".join(struct.pack("<i", i) for i in range(len(entries)))      # name hashes (unused)
    out += b"".join(struct.pack("<i", p) for p in positions)
    out += struct.pack("<i", len(out) + 4 + len(names))
    return bytes(out + names + data)


def build(va: int, spec: dict[str, Any]) -> tuple[bytes, int, int, int, int, int]:
    """spec: {assembly, version, refs: [(name, version)], typerefs: [(scope_ref_index|None, ns, name)],
    types: [{ns, name, fields?: [static string field names], methods: [{name, il?, ops?, pinvoke?: (dll, entry)}]}],
    memberrefs: [(typeref_idx, name)],
    attributes: [(parent: "module"|"assembly", memberref_idx)], resources: [(name, bytes)], user_strings: [...]}"""
    st, us, bl = _Heap(), _Heap(), _Heap()
    guid = bytes(range(0x30, 0x40))
    sig_void = bl.blob(b"\x00\x00\x01")                               # default, 0 params, void
    sig_ctor = bl.blob(b"\x20\x00\x01")                               # instance void .ctor()
    for s in spec.get("user_strings") or []:
        us.us(s)
    rows: dict[int, list[bytes]] = {t: [] for t in (0x00, 0x01, 0x02, 0x04, 0x06, 0x0A, 0x0C, 0x0F, 0x1A, 0x1C, 0x1D,
                                                    0x20, 0x23, 0x28)}
    rows[0x00].append(struct.pack("<HHHHH", 0, st.str(spec["assembly"] + ".exe"), 1, 0, 0))
    refs = spec.get("refs") or [("mscorlib", (4, 0, 0, 0))]
    for name, ver in refs:
        rows[0x23].append(struct.pack("<HHHHIHHHH", *ver, 0, 0, st.str(name), 0, 0))
    for scope, ns, name in spec.get("typerefs") or []:
        rs = ((scope + 1) << 2 | 2) if scope is not None else 0       # ResolutionScope → AssemblyRef
        rows[0x01].append(struct.pack("<HHH", rs, st.str(name), st.str(ns)))
    for tr, name in spec.get("memberrefs") or []:
        rows[0x0A].append(struct.pack("<HHH", (tr + 1) << 3 | 1, st.str(name), sig_ctor))   # MemberRefParent → TypeRef
    # TypeDefs: <Module> first, then the program's types; methods numbered in order
    il_blobs: list[bytes] = []
    meth_rows: list[tuple[int, int, int, int, int]] = []              # (il index or -1, implflags, flags, name, sig)
    types = [{"ns": "", "name": "<Module>", "methods": []}] + list(spec.get("types") or [])
    # static byte[] initialisers: fields of <PrivateImplementationDetails> typed
    # __StaticArrayInitTypeSize=N (ClassLayout gives N), data at a FieldRVA
    arrays = list(spec.get("static_arrays") or [])           # [(field name, bytes)]
    field_rids = {name: i for i, (name, _) in enumerate(arrays, 1)}
    pid_index = size_index = {}
    if arrays:
        pid_index = len(types) + 1
        types.append({"ns": "", "name": "<PrivateImplementationDetails>", "methods": [], "_fields": True})
        size_index = {}
        for _, data in arrays:
            if len(data) not in size_index:
                size_index[len(data)] = len(types) + 1
                types.append({"ns": "", "name": f"__StaticArrayInitTypeSize={len(data)}", "methods": [],
                              "_size": len(data)})
    entry = 0
    rids = {f"{t['name']}::{m['name']}": i for i, (t, m) in
            enumerate(((t, m) for t in types for m in t.get("methods") or []), 1)}
    # Field table: the types' own static string fields first (in type order), then the array fields
    own_fields = [(k, f) for k, t in enumerate(types) for f in t.get("fields") or []]
    field_first = {}
    for i, (k, f) in enumerate(own_fields, 1):
        field_first.setdefault(k, i)
        rids[f"field:{types[k]['name']}::{f}"] = i
    field_rids = {name: len(own_fields) + i for name, i in field_rids.items()}
    rids.update({"field:" + n: r for n, r in field_rids.items()})
    for t in types:
        first = len(meth_rows) + 1
        for m in t.get("methods") or []:
            if m.get("pinvoke"):
                meth_rows.append((-1, 0x0080, 0x2096, st.str(m["name"]), sig_void))   # static pinvokeimpl public
                dll, ep = m["pinvoke"]
                if dll not in [r[0] for r in spec.setdefault("_modrefs", [])]:
                    spec["_modrefs"].append((dll,))
                mi = [r[0] for r in spec["_modrefs"]].index(dll)
                rows[0x1C].append(struct.pack("<HHHH", 0x0100, len(meth_rows) << 1 | 1, st.str(ep), mi + 1))
            else:
                il_blobs.append(_ops(m["ops"], us, rids) if m.get("ops") else (m.get("il") or b"\x2a"))
                meth_rows.append((len(il_blobs) - 1, 0, 0x0096, st.str(m["name"]), sig_void))
                if m.get("entry"):
                    entry = 0x06000000 | len(meth_rows)
        flags = 0x00100001 if t["name"] != "<Module>" else 0
        rows[0x02].append((flags, st.str(t["name"]), st.str(t["ns"]), first))      # finished below
    for (dll,) in spec.get("_modrefs") or []:
        rows[0x1A].append(struct.pack("<H", st.str(dll)))
    for parent, mr in spec.get("attributes") or []:
        hca = (1 << 5 | 7) if parent == "module" else (1 << 5 | 14)   # HasCustomAttribute → Module / Assembly
        rows[0x0C].append(struct.pack("<HHH", hca, (mr + 1) << 3 | 3, bl.blob(b"\x01\x00\x00\x00")))
    major, minor, build_, rev = spec.get("version", (1, 0, 0, 0))
    rows[0x20].append(struct.pack("<IHHHHIHHH", 0x8004, major, minor, build_, rev, 0, 0, st.str(spec["assembly"]), 0))
    res_blob = bytearray()
    for name, data in spec.get("resources") or []:
        rows[0x28].append(struct.pack("<IIHH", len(res_blob), 1, st.str(name), 0))   # public, embedded
        res_blob += struct.pack("<I", len(data)) + data
        while len(res_blob) % 8:
            res_blob.append(0)
    # IL bodies (tiny headers) after the COR20 header
    out = bytearray(b"\x00" * 72)
    while len(out) % 4:
        out.append(0)
    il_rva = []
    for il in il_blobs:
        if len(il) < 64:                                          # tiny header
            il_rva.append(va + len(out))
            out += bytes([0x02 | (len(il) << 2)]) + il
        else:                                                     # fat header (12 bytes, 4-aligned)
            while len(out) % 4:
                out.append(0)
            il_rva.append(va + len(out))
            out += struct.pack("<HHII", 0x3003, 8, len(il), 0) + il
        while len(out) % 4:
            out.append(0)
    field_rva = []
    for _, data in arrays:
        while len(out) % 8:
            out.append(0)
        field_rva.append(va + len(out))
        out += data
    rows[0x06] = [struct.pack("<IHHHHH", il_rva[i] if i >= 0 else 0, impl, fl, nm, sg, 1)
                  for i, impl, fl, nm, sg in meth_rows]
    n_methods = len(meth_rows)
    tdefs = []
    for k, (flags, nm, ns, first) in enumerate(rows[0x02]):
        nxt = rows[0x02][k + 1][3] if k + 1 < len(rows[0x02]) else n_methods + 1
        first = min(first, nxt)
        if k in field_first:
            flist = field_first[k]
        elif k + 1 >= (pid_index or 10 ** 6):
            flist = len(own_fields) + 1 if k + 1 == pid_index else len(own_fields) + len(arrays) + 1
        else:                                       # no fields: the next type's first field
            flist = next((field_first[j] for j in sorted(field_first) if j > k), len(own_fields) + 1)
        if types[k].get("_size"):
            flags = 0x00000113                                     # sealed explicit value type
        tdefs.append(struct.pack("<IHHHHH", flags, nm, ns, 0, flist, first))
    for n, ti in size_index.items():
        rows[0x0F].append(struct.pack("<HIH", 1, n, ti))
    for k, f in own_fields:
        rows[0x04].append(struct.pack("<HHH", 0x0016, st.str(f), bl.blob(b"\x06\x0e")))   # public static string
    for k, (name, data) in enumerate(arrays, 1):
        sig = bl.blob(bytes([0x06, 0x11, (size_index[len(data)] << 2) & 0x7F if size_index[len(data)] < 32 else 0]))
        rows[0x04].append(struct.pack("<HHH", 0x0133, st.str(name), sig))   # static assembly initonly HasFieldRVA
        rows[0x1D].append(struct.pack("<IH", field_rva[k - 1], k))
    rows[0x02] = tdefs
    valid = sum(1 << t for t, r in rows.items() if r)
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0x16003301FA00)
    tables += b"".join(struct.pack("<I", len(rows[t])) for t in sorted(rows) if rows[t])
    for t in sorted(rows):
        tables += b"".join(rows[t])
    while len(tables) % 4:
        tables += b"\x00"
    for h in (st, us, bl):
        while len(h.b) % 4:
            h.b.append(0)
    version = b"v4.0.30319\x00\x00"
    streams = [(b"#~", tables), (b"#Strings", bytes(st.b)), (b"#US", bytes(us.b)), (b"#GUID", guid), (b"#Blob", bytes(bl.b))]
    hdr_len = 16 + len(version) + 4 + sum(8 + _al(len(n) + 1, 4) for n, _ in streams)
    root = bytearray(b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, len(streams)))
    off = hdr_len
    for name, data in streams:
        root += struct.pack("<II", off, len(data)) + name + b"\x00" * (_al(len(name) + 1, 4) - len(name))
        off += len(data)
    for _, data in streams:
        root += data
    md_rva = va + len(out)
    out += root
    res_rva = res_size = 0
    if res_blob:
        while len(out) % 8:
            out.append(0)
        res_rva, res_size = va + len(out), len(res_blob)
        out += res_blob
    struct.pack_into("<IHH" + "I" * 16, out, 0, 72, 2, 5, md_rva, len(root), 1, entry,     # COR20 = 72 bytes
                     res_rva, res_size, *([0] * 10))
    return bytes(out), 72, md_rva, res_rva, res_size, entry
