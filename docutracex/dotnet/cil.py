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


def disassemble(pe: Any) -> dict[str, Any]:
    from dncil.cil.body import CilMethodBody
    from dncil.cil.body.reader import CilMethodBodyReaderBase
    from dncil.cil.error import MethodBodyFormatError

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

    t = pe.net.mdtables
    us = pe.net.user_strings
    owners = _owners(t)
    fields = static_fields(pe)
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
        token_field = 0
        for insn in body.instructions:
            op = insn.opcode.name
            ops.add(op)
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
                        "arrays": [f"byte[{len(a)}] {a[:16].hex()}" for a in arrays[:10]]})
    internal = [{k: m.pop(k) for k in ("_ops", "_sites", "_all_strings", "_arrays")} | {"method": m["method"], "rid": m["rid"],
                 "calls": m["calls"]} for m in methods]
    interesting = sorted((m for m in methods if m["score"] > 0), key=lambda m: -m["score"])[:MAX_INTERESTING]
    return {"methods": done, "errors": errors, "interesting": interesting,
            "_strings": [(m["method"], s) for m in methods for s in m["strings"]], "_methods": internal}
