"""CIL disassembly per method (dncil, Apache-2.0): which framework members each
method calls and which literal strings it loads. Static only: method bodies
are decoded, never run. Feeds the .NET view (methods of interest), the IOC
extractor (``ldstr`` strings with their method) and the findings."""

from __future__ import annotations

from typing import Any

MAX_METHODS = 20000
MAX_INTERESTING = 200
MAX_CALLS = 60
CALL_OPS = {"call", "callvirt", "newobj", "ldftn", "ldvirtftn", "jmp"}

# member → (category, weight): what makes a method worth reading first
_INTEREST = (
    ("System.Reflection.Assembly::Load", "loader", 5), ("System.Reflection.Assembly::LoadFile", "loader", 4),
    ("System.Reflection.Assembly::LoadFrom", "loader", 4), ("System.Reflection.MethodBase::Invoke", "loader", 4),
    ("System.Reflection.MethodInfo::Invoke", "loader", 4), ("System.AppDomain::Load", "loader", 4),
    ("System.Activator::CreateInstance", "loader", 2),
    ("System.Diagnostics.Process::Start", "execution", 4), ("System.Diagnostics.ProcessStartInfo", "execution", 2),
    ("System.Net.WebClient", "network", 4), ("System.Net.Http.HttpClient", "network", 4),
    ("System.Net.WebRequest", "network", 4), ("System.Net.HttpWebRequest", "network", 4),
    ("System.Net.Sockets", "network", 4), ("System.Net.Mail.SmtpClient", "exfiltration", 5),
    ("System.Net.FtpWebRequest", "exfiltration", 4), ("System.Net.Dns", "network", 2),
    ("System.Security.Cryptography", "crypto", 3), ("System.Convert::FromBase64String", "encoding", 2),
    ("System.IO.Compression", "encoding", 2),
    ("Microsoft.Win32.Registry", "persistence", 3), ("System.IO.File::WriteAllBytes", "filesystem", 2),
    ("System.IO.File::Copy", "filesystem", 1), ("System.Environment::GetFolderPath", "filesystem", 1),
    ("System.Windows.Forms.Clipboard", "collection", 3), ("System.Drawing.Graphics::CopyFromScreen", "collection", 4),
    ("System.Runtime.InteropServices.Marshal::Copy", "injection", 3),
    ("System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer", "injection", 4),
    ("System.Resources.ResourceManager::GetObject", "loader", 2),
    ("System.Reflection.Assembly::GetManifestResourceStream", "loader", 3),
    ("System.Drawing.Bitmap::GetPixel", "stego", 4), ("System.Drawing.Bitmap::LockBits", "stego", 3),
    ("System.Drawing.Color::get_R", "stego", 1), ("System.Drawing.Color::get_G", "stego", 1),
    ("System.Drawing.Color::get_B", "stego", 1), ("System.Drawing.Color::ToArgb", "stego", 1),
    ("System.Threading.Thread::Sleep", "evasion", 1), ("System.Diagnostics.Debugger::IsAttached", "evasion", 2),
)


def _name(table: Any, row: Any) -> str:
    try:
        if table == 0x0A:                                   # MemberRef → parent type
            cls = row.Class.row
            parent = f"{cls.TypeNamespace}.{cls.TypeName}".strip(".") if hasattr(cls, "TypeName") else str(getattr(cls, "Name", "?"))
            return f"{parent}::{row.Name}"
        if table == 0x06:                                   # MethodDef (own code)
            return f"::{row.Name}"
        if table == 0x2B:                                   # MethodSpec → generic method
            return _name(row.Method.table, row.Method.row) if hasattr(row.Method, "row") else "?"
    except AttributeError:
        pass
    return "?"


def _owners(t: Any) -> dict[int, str]:
    """MethodDef rid → Type::Method."""
    by_id: dict[int, str] = {}
    for td in t.TypeDef or []:
        tn = f"{td.TypeNamespace}.{td.TypeName}".strip(".")
        for mref in td.MethodList or []:
            by_id[id(mref.row)] = f"{tn}::{mref.row.Name}"
    return {rid: by_id[id(m)] for rid, m in enumerate(t.MethodDef or [], 1) if id(m) in by_id}


def _ldc(op: str, operand: Any) -> int | None:
    """Value of an ldc.i4 / ldc.i4.s / ldc.i4.N / ldc.i4.m1, as an unsigned 32-bit int."""
    if op == "ldc.i4.m1":
        v = -1
    elif op in ("ldc.i4", "ldc.i4.s"):
        try:
            v = int(operand)
        except (TypeError, ValueError):
            return None
    else:
        try:
            v = int(op.rsplit(".", 1)[1])
        except ValueError:
            return None
    return v & 0xFFFFFFFF


def _spec_target(t: Any, rid: int, def_rid: dict[int, int]) -> int:
    """MethodSpec (a generic instantiation, e.g. Get<string>) → the MethodDef rid it instantiates."""
    try:
        row = t.MethodSpec[rid - 1]
        return def_rid.get(id(row.Method.row), 0)
    except (AttributeError, IndexError, TypeError):
        return 0


def static_fields(pe: Any) -> dict[int, bytes]:
    """Field rid → initial bytes of the static arrays (FieldRVA + the size of
    their ``__StaticArrayInitTypeSize=N`` value type, from ClassLayout)."""
    t = pe.net.mdtables
    sizes: dict[int, int] = {}
    for cl in getattr(t, "ClassLayout", None) or []:
        sizes[int(cl.struct.Parent_Index)] = int(cl.ClassSize or 0)
    names = {i: str(td.TypeName) for i, td in enumerate(t.TypeDef or [], 1)}
    out: dict[int, bytes] = {}
    for fr in getattr(t, "FieldRva", None) or []:
        try:
            frid = int(fr.struct.Field_Index)
            sg = t.Field[frid - 1].Signature
            sig = bytes(sg.value if isinstance(getattr(sg, "value", None), (bytes, bytearray)) else b"")
            size = 0
            if len(sig) >= 3 and sig[0] == 0x06 and sig[1] == 0x11:
                b, i = sig[2], 3                          # compressed TypeDefOrRef coded index
                if b & 0x80:
                    b = ((b & 0x3F) << 8 | sig[3]) if not b & 0x40 else ((b & 0x1F) << 24 | sig[3] << 16 | sig[4] << 8 | sig[5])
                tag, trid = b & 3, b >> 2
                if tag == 0:
                    size = sizes.get(trid) or 0
                    if not size and names.get(trid, "").startswith("__StaticArrayInitTypeSize="):
                        size = int(names[trid].split("=", 1)[1].split("_")[0] or 0)
            elif len(sig) >= 2 and sig[0] == 0x06:
                size = {0x02: 1, 0x04: 1, 0x05: 1, 0x06: 2, 0x07: 2, 0x08: 4, 0x09: 4, 0x0A: 8, 0x0B: 8}.get(sig[1], 0)
            if 0 < size <= 16 * 1024 * 1024:
                out[frid] = bytes(pe.get_data(int(fr.Rva), size))
        except Exception:  # noqa: BLE001
            continue
    return out


MAX_IL_METHODS = 60
MAX_IL_LINES = 400


def _reader_class(pe: Any) -> Any:
    from dncil.cil.body.reader import CilMethodBodyReaderBase

    class _Reader(CilMethodBodyReaderBase):
        def __init__(self, rva: int):
            self.off = pe.get_offset_from_rva(rva)

        def read(self, n: int) -> bytes:
            data = pe.__data__[self.off:self.off + n]
            self.off += n
            return bytes(data)

        def tell(self) -> int:
            return self.off

        def seek(self, off: int) -> int:
            self.off = off
            return off

    return _Reader


def _token_name(t: Any, tok: Any, owners: dict[int, str]) -> str:
    """A metadata token as a readable name (methods, fields, types)."""
    table, rid = getattr(tok, "table", None), getattr(tok, "rid", 0)
    try:
        if table == 0x06:
            return owners.get(rid, f"::#{rid}")
        if table in (0x0A, 0x2B):
            tbl = t.MemberRef if table == 0x0A else t.MethodSpec
            return _name(table, tbl[rid - 1])
        if table == 0x04:
            return f"field {t.Field[rid - 1].Name}"
        if table in (0x01, 0x02):
            row = (t.TypeRef if table == 0x01 else t.TypeDef)[rid - 1]
            return f"{row.TypeNamespace}.{row.TypeName}".strip(".")
    except (AttributeError, IndexError, TypeError):
        pass
    return f"token 0x{(table or 0):02x}{rid:06x}"


def _quote(s: str, n: int = 200) -> str:
    s = s if len(s) <= n else s[:n] + "…"
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n") + '"'


def il_listing(pe: Any, rid: int, owners: dict[int, str] | None = None) -> list[str]:
    """Readable IL of one method (``IL_0000: call System.Convert::FromBase64String``):
    calls, fields and types by name, ``ldstr`` quoted, branches as labels. Decoded
    from the method body with dncil, never run. At most MAX_IL_LINES lines."""
    from dncil.cil.body import CilMethodBody

    t = pe.net.mdtables
    owners = owners if owners is not None else _owners(t)
    us = pe.net.user_strings
    try:
        m = t.MethodDef[rid - 1]
        if not m.Rva:
            return []
        body = CilMethodBody(_reader_class(pe)(m.Rva))
    except Exception:  # noqa: BLE001
        return []
    out: list[str] = []
    insns = list(body.instructions)
    base = insns[0].offset if insns else 0            # dncil offsets are file offsets: make them IL offsets
    for insn in insns:
        if len(out) >= MAX_IL_LINES:
            out.append(f"// … truncated at {MAX_IL_LINES} instructions")
            break
        op, operand = insn.opcode.name, insn.operand
        arg = ""
        if op == "ldstr" and us is not None:
            try:
                v = us.get(operand.rid)
                arg = _quote(str(v.value)) if v is not None and v.value is not None else ""
            except Exception:  # noqa: BLE001
                arg = ""
        elif hasattr(operand, "table"):
            arg = _token_name(t, operand, owners)
        elif op.startswith(("br", "b", "leave")) and isinstance(operand, int) and op not in ("box",):
            arg = f"IL_{operand - base:04x}"
        elif op == "switch" and isinstance(operand, list):
            arg = "(" + ", ".join(f"IL_{x - base:04x}" for x in operand[:64] if isinstance(x, int)) + ")"
        elif operand is not None:
            arg = str(operand)
        out.append(f"IL_{insn.offset - base:04x}: {op}" + (f" {arg}" if arg else ""))
    return out


def disassemble(pe: Any) -> dict[str, Any]:
    from dncil.cil.body import CilMethodBody
    from dncil.cil.error import MethodBodyFormatError

    _Reader = _reader_class(pe)

    t = pe.net.mdtables
    us = pe.net.user_strings
    owners = _owners(t)
    fields = static_fields(pe)
    def_rid = {id(m): i for i, m in enumerate(t.MethodDef or [], 1)}
    methods: list[dict[str, Any]] = []
    done = errors = 0
    for rid, m in enumerate(t.MethodDef or [], 1):
        if done >= MAX_METHODS:
            break
        if not m.Rva:
            continue
        try:
            body = CilMethodBody(_Reader(m.Rva))
        except (MethodBodyFormatError, ValueError, IndexError, Exception):  # noqa: BLE001
            errors += 1
            continue
        done += 1
        calls: list[str] = []
        strings: list[str] = []
        pending: list[Any] = []                        # ldstr / static byte[] args right before a call
        sites: list[tuple[int, list[Any]]] = []        # (own method rid, args)
        arrays: list[bytes] = []                       # static byte[] initialised here (keys, blobs)
        ops: set[str] = set()
        ints: list[int] = []                            # ldc.i4 constants (keys, seeds, sizes)
        int_sites: list[tuple[int, int]] = []           # (own method rid, the int passed right before)
        prev_int: int | None = None
        token_field = 0
        for insn in body.instructions:
            op = insn.opcode.name
            ops.add(op)
            if op.startswith("ldc.i4"):
                v = _ldc(op, insn.operand)
                if v is not None:
                    if len(ints) < 4000:
                        ints.append(v)
                    prev_int = v
                    continue
            if op in CALL_OPS and prev_int is not None and getattr(insn.operand, "table", None) in (0x06, 0x2B):
                target = insn.operand.rid if insn.operand.table == 0x06 else _spec_target(t, insn.operand.rid, def_rid)
                if target:
                    int_sites.append((target, prev_int))
            prev_int = None
            if op == "ldstr" and us is not None:
                try:
                    s = us.get(insn.operand.rid)
                    v = s.value if s is not None else None
                    if v:
                        strings.append(str(v)[:2000])
                        pending.append(str(v)[:20000])
                except Exception:  # noqa: BLE001
                    pass
                continue
            if op == "ldtoken" and getattr(insn.operand, "table", None) == 0x04:
                token_field = insn.operand.rid
                continue
            if op in CALL_OPS and getattr(insn.operand, "table", None) == 0x06 and pending:
                sites.append((insn.operand.rid, pending[-3:]))
            if not op.startswith(("ldc", "nop", "newarr", "dup")):
                pending = []
            if op in CALL_OPS and hasattr(insn.operand, "table"):
                tok = insn.operand
                try:
                    tbl = {0x0A: getattr(t, "MemberRef", None), 0x06: getattr(t, "MethodDef", None),
                           0x2B: getattr(t, "MethodSpec", None)}.get(tok.table)
                    row = tbl[tok.rid - 1] if tbl is not None and tok.rid else None
                except (IndexError, TypeError):
                    row = None
                if row is None:
                    continue
                name = owners.get(tok.rid, "?") if tok.table == 0x06 else _name(tok.table, row)
                if name.endswith("RuntimeHelpers::InitializeArray") and token_field in fields:
                    arr = fields[token_field]
                    arrays.append(arr)
                    pending = [arr]
                    token_field = 0
                if name not in calls:
                    calls.append(name)
        cats: dict[str, int] = {}
        score = 0
        for c in calls:
            for pre, cat, w in _INTEREST:
                if c.startswith(pre):
                    cats[cat] = cats.get(cat, 0) + 1
                    score += w
                    break
        score += min(len(strings), 5) // 2
        methods.append({"method": owners.get(rid, f"#{rid}"), "rid": rid, "size": int(body.code_size or 0),
                        "calls": calls[:MAX_CALLS], "strings": strings[:40], "categories": sorted(cats), "score": score,
                        "_ops": ops, "_sites": sites, "_all_strings": strings, "_arrays": arrays,
                        "_ints": ints, "_int_sites": int_sites,
                        "arrays": [f"byte[{len(a)}] {a[:16].hex()}" for a in arrays[:10]]})
    # own methods a loader calls (the decoder behind Assembly.Load) are worth reading too
    own = set(owners.values())
    by_name = {m["method"]: m for m in methods}
    for m in list(methods):
        if "loader" in m["categories"]:
            for c in m["calls"]:
                callee = by_name.get(c) if c in own else None
                if callee is not None and callee is not m:
                    callee["score"] += 3
                    if "called by a loader" not in callee["categories"]:
                        callee["categories"] = sorted(callee["categories"] + ["called by a loader"])
    internal = [{k: m.pop(k) for k in ("_ops", "_sites", "_all_strings", "_arrays", "_ints", "_int_sites")}
                | {"method": m["method"], "rid": m["rid"],
                 "calls": m["calls"]} for m in methods]
    interesting = sorted((m for m in methods if m["score"] > 0), key=lambda m: -m["score"])[:MAX_INTERESTING]
    for m in interesting[:MAX_IL_METHODS]:             # readable IL of the methods worth reading first
        m["il"] = il_listing(pe, m["rid"], owners)
    return {"methods": done, "errors": errors, "interesting": interesting,
            "_strings": [(m["method"], s) for m in methods for s in m["strings"]], "_methods": internal}
