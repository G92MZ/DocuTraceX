"""Code analysis engine (Rizin + rz-ghidra): functions, calls, strings,
disassembly and pseudocode of native binaries — statically.

Shared by the Go Malware Intelligence (function names from GoReSym / the
pclntab) and by any native PE / ELF (Rizin's own analysis). Flow:

1. **Inventory**: define the functions (Go: from the name table; native:
   Rizin ``aa``), read their size, blocks, complexity, loops, calls and data
   references, and their instructions (``afij`` / ``pdfj``).
2. **Context**: callers / callees, called APIs or Go packages, strings used
   (Go strings rebuilt from pointer + length), XOR loops.
3. **Priority**: score + reasons (``priority.py``).
4. **Decompilation** of the top functions with rz-ghidra (``pdgj``), in
   batches against the time budget.

Limits (env-tunable): 30 min per binary, extended up to 40 while it is still
decompiling; 3 GB of RAM per Rizin process; one code analysis at a time across
the whole app. Pseudocode is a reconstruction — the instructions, addresses
and references it comes from are kept next to it.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from ..logging_config import get_logger
from . import priority, rz

log = get_logger(__name__)

ENGINE_VERSION = "2"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


BUDGET_S = _env_int("DOCUTRACEX_CODE_BUDGET_MIN", 30) * 60
MAX_S = _env_int("DOCUTRACEX_CODE_MAX_MIN", 40) * 60
MEM_MB = _env_int("DOCUTRACEX_CODE_MEM_MB", 3072)
DECOMPILE_N = _env_int("DOCUTRACEX_CODE_DECOMPILE", 100)
INVENTORY_MAX = _env_int("DOCUTRACEX_CODE_FUNCTIONS", 4000)
DISASM_KEEP = 300                 # functions whose instructions are stored
OPS_KEEP = 1500                   # instructions kept per function
MAX_BLOCKS = 400                  # CFG view
BLOCK_OPS = 40
DECOMPILE_MAX_SIZE = _env_int("DOCUTRACEX_CODE_DECOMPILE_MAX_BYTES", 24000)   # bigger: on demand only
DECOMPILE_MAX_SIZE = _env_int("DOCUTRACEX_CODE_DECOMPILE_MAX_BYTES", 24000)   # bigger: on demand only
BATCH = 250
DEC_BATCH = 10
_FLAG_BAD = re.compile(r"[^A-Za-z0-9_.]")
_CALL_TYPES = ("call", "ucall", "icall", "ircall", "rcall", "jmp", "ujmp", "ijmp", "irjmp")
_REG = re.compile(r"^(?:[re]?[abcd]x|[re]?[sd]il?|[re]?[sb]p|r\d{1,2}[dwb]?|[xw]\d{1,2}|lr|pc|ip|eip|rip|e?ax)$")
_CALLEE = re.compile(r"^(?:call|jmp|bl|blx|b)\s+(?:qword |dword )?(?:\[)?([A-Za-z_][\w.@$?]*)")


def available() -> bool:
    exe = rz.executable()
    return exe is not None and rz.sleigh_home(exe) is not None


def _flag(name: str, prefix: str) -> str:
    return prefix + _FLAG_BAD.sub("_", name)[:200]


_CLOSURE = re.compile(r"\.func\d+(\.\d+)*$|\.gowrap\d+$")


def _traits(f: dict[str, Any], mode: str) -> list[str]:
    """Go / program-structure markers of a function (call graph decorations)."""
    names = f.get("callee_names") or []
    name = f.get("name") or ""
    out = []
    if name in ("main.main", "main", "entry0", "WinMain", "wWinMain", "DllMain", "_start") or name.startswith("entry"):
        out.append("entry")
    if name.endswith((".init", ".init.0")) or re.search(r"\.init\.\d+$", name):
        out.append("init")
    if mode == "go":
        if _CLOSURE.search(name):
            out.append("closure")
        if any("runtime.newproc" in n for n in names):
            out.append("goroutine")
        if any(n.startswith(("runtime.deferproc", "runtime.deferreturn")) for n in names):
            out.append("defer")
        if any(n in ("runtime.gopanic", "runtime.gorecover") for n in names):
            out.append("panic/recover")
        if any(n.startswith("reflect.") for n in names):
            out.append("reflection")
        if any(n.startswith("runtime.") and ("itab" in n or "assertE2I" in n or "typeAssert" in n) for n in names):
            out.append("interface")
    if f.get("indirect_calls"):
        out.append("indirect calls")
    return out


def _readable(flag: str) -> str:
    """'sym.imp.KERNEL32.dll_VirtualAlloc' → 'KERNEL32.dll_VirtualAlloc', 'sym.main.foo' → 'main.foo'."""
    for p in ("sym.imp.", "sym.", "go."):
        if flag.startswith(p):
            return flag[len(p):] if p != "sym.imp." else "imp." + flag[len(p):]
    return flag


def _pretty(code: str, annotations: list[dict[str, Any]], names_by_addr: dict[int, str]) -> str:
    """Put the real (Go) names back where rz-ghidra printed flag names."""
    spans = sorted((a for a in annotations if a.get("type") == "function_name" and a.get("offset") in names_by_addr),
                   key=lambda a: -a["start"])
    for a in spans:
        code = code[:a["start"]] + names_by_addr[a["offset"]] + code[a["end"]:]
    return code


class _Reader:
    """Bytes at virtual addresses (for strings referenced by the code)."""

    def __init__(self, data: bytes):
        from ..golang import binfmt
        self.data = data
        self.bin = binfmt.parse(data)

    def at(self, va: int, n: int) -> bytes:
        off = self.bin.va_to_off(va)
        return self.data[off:off + n] if off is not None and n > 0 else b""

    def cstring(self, va: int) -> str:
        raw = self.at(va, 512)
        if not raw:
            return ""
        if len(raw) > 3 and raw[1] == 0 and raw[3] == 0:                  # UTF-16LE
            s = raw.decode("utf-16-le", "replace").split("\x00", 1)[0]
        else:
            s = raw.split(b"\x00", 1)[0].decode("latin-1", "replace")
        return s if len(s) >= 4 and all(c.isprintable() or c in "\t\r\n" for c in s) else ""


_IMM = re.compile(r"mov\s+\w+,\s*(0x[0-9a-f]+|\d+)$")
_XOR_IMM = re.compile(r"xor\s+(?:byte |word |dword |qword )?[^,]+,\s*(0x[0-9a-f]+|\d+)$")


def _data_refs(ops: list[dict[str, Any]]) -> tuple[list[list[int | None]], list[int]]:
    """Data the function points at ([address, length or None] — the length when a
    ``mov reg, imm`` follows the ``lea``, as Go slices / strings and many C calls
    do) and the immediates it XORs with (decoding keys)."""
    blobs: dict[int, int | None] = {}
    keys: list[int] = []
    for i, op in enumerate(ops):
        dis = (op.get("disasm") or "").lower()
        m = _XOR_IMM.match(dis)
        if m:
            k = int(m.group(1), 0)
            if 0 < k < 1 << 32 and k not in keys:
                keys.append(k)
        ptr = op.get("ptr") if op.get("refptr") is not False else None
        if not isinstance(ptr, int) or ptr <= 0 or op.get("type") in ("call", "jmp", "cjmp"):
            continue
        n = None
        for nxt in ops[i + 1:i + 4]:
            mm = _IMM.match((nxt.get("disasm") or "").lower())
            if mm:
                v = int(mm.group(1), 0)
                n = v if 1 <= v <= 1 << 20 else None
                break
        if blobs.get(ptr) is None:
            blobs[ptr] = n
    return [[a, n] for a, n in list(blobs.items())[:64]], keys[:16]


def _strings_and_xor(ops: list[dict[str, Any]], reader: _Reader, mode: str) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    xor = 0
    for i, op in enumerate(ops):
        dis = (op.get("disasm") or "").lower()
        if op.get("type") == "xor" and "," in dis:
            a, b = (x.strip() for x in dis.split(" ", 1)[1].split(",", 1))
            if a != b:
                xor += 1
        ptr = op.get("ptr") if op.get("refptr") is not False else None
        if not isinstance(ptr, int) or ptr <= 0:
            continue
        s = ""
        if mode == "go":                                  # Go string: lea reg,[ptr] ... mov reg2, LEN
            for nxt in ops[i + 1:i + 4]:
                m = re.match(r"mov\s+\w+,\s*(0x[0-9a-f]+|\d+)$", (nxt.get("disasm") or "").lower())
                if m:
                    n = int(m.group(1), 0)
                    if 1 <= n <= 4096:
                        raw = reader.at(ptr, n)
                        try:
                            t = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            t = ""
                        if len(t) == n and all(c.isprintable() or c in "\t\r\n" for c in t):
                            s = t
                    break
        if not s and mode != "go":                      # Go strings carry no NUL: never read past the length
            s = reader.cstring(ptr)
        if s:
            out.append({"value": s[:500], "addr": ptr, "at": op.get("offset")})
    return out, xor


def _trim_ops(ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keep = ("offset", "bytes", "disasm", "type", "jump", "fail", "ptr")
    return [{k: o[k] for k in keep if k in o} for o in ops[:OPS_KEEP]]


def analyze(path: Path, *, mode: str, names: list[dict[str, Any]] | None, out_file: Path,
            lock_path: Path, progress=None) -> dict[str, Any]:
    """Analyse one binary; the full result goes to ``out_file`` (JSON) and a
    summary is returned. ``mode`` is "go" (names required) or "native"."""
    t0 = time.monotonic()
    summary: dict[str, Any] = {"engine": "rizin + rz-ghidra", "engine_version": ENGINE_VERSION, "mode": mode,
                               "status": "ok", "warnings": [], "file": out_file.name}
    if not available():
        summary.update(status="unavailable", detail="Rizin + rz-ghidra not provisioned (tools/rizin/)")
        return summary
    exe = rz.executable()
    summary["rizin"] = rz.version(exe)
    data = path.read_bytes()
    reader = _Reader(data)
    deadline, hard = t0 + BUDGET_S, t0 + MAX_S

    def left() -> float:
        return max(30.0, hard - time.monotonic())

    with rz.exclusive(lock_path):
        prelude: list[str] = ["f- reloc.*"] if mode == "go" else ["aa"]
        names_by_addr: dict[int, str] = {}
        fn_list: list[dict[str, Any]] = []
        if mode == "go":
            for n in names or []:
                flag = _flag(n["name"], "go.")
                names_by_addr[n["start"]] = n["name"]
                prelude.append(f"f {flag} {max(1, n['end'] - n['start'])} @ {n['start']:#x}")
            user = [n for n in names or [] if n.get("user")]
            fn_list = sorted(user, key=lambda n: n["start"])[:INVENTORY_MAX]
            if len([n for n in names or [] if n.get("user")]) > INVENTORY_MAX:
                summary["warnings"].append(f"only the first {INVENTORY_MAX} program functions are analysed")
        else:
            r = rz.run(path, [("afl", "aflj")], timeout=min(left(), BUDGET_S), mem_mb=MEM_MB, prelude=prelude)
            if r.get("killed"):
                summary["warnings"].append(f"Rizin analysis stopped: {r['killed']}")
            afl = rz.as_json(r["outputs"].get("afl")) or []
            for f in afl:
                nm = f.get("name") or ""
                if nm.startswith(("sym.imp.", "loc.imp.", "reloc.")):
                    continue
                names_by_addr[f["offset"]] = nm
                fn_list.append({"name": nm, "start": f["offset"], "end": f["offset"] + (f.get("size") or 0),
                                "user": not nm.startswith(("flirt.", "sym.std")), "named": not nm.startswith("fcn.")})
            fn_list = sorted(fn_list, key=lambda n: (not n["user"], n["start"]))[:INVENTORY_MAX]
        summary["functions_total"] = len(names or []) if mode == "go" else len(fn_list)

        # 1. inventory
        functions: dict[int, dict[str, Any]] = {}
        disasm: dict[int, list[dict[str, Any]]] = {}
        for i in range(0, len(fn_list), BATCH):
            if time.monotonic() > deadline:
                summary["warnings"].append("time budget reached during the inventory")
                break
            chunk = fn_list[i:i + BATCH]
            groups = []
            for n in chunk:
                a = n["start"]
                cmds = [(f"af:{a}", f"af @ {a:#x}")] if mode == "go" else []
                cmds += [(f"i:{a}", f"afij @ {a:#x}"), (f"d:{a}", f"pdfj @ {a:#x}")]
                groups.append((str(a), cmds))
            if progress:
                progress(f"inventory {i + len(chunk)}/{len(fn_list)}")
            r = rz.run_groups(path, groups, timeout=left(), mem_mb=MEM_MB, prelude=prelude, deadline=hard)
            if r.get("killed"):
                summary["warnings"].append(f"Rizin stopped during the inventory: {r['killed']}")
            for n in chunk:
                a = n["start"]
                info = rz.as_json(r["outputs"].get(f"i:{a}"))
                info = info[0] if isinstance(info, list) and info else None
                if not info:
                    continue
                pdf = rz.as_json(r["outputs"].get(f"d:{a}")) or {}
                ops = pdf.get("ops") or []
                callees = []
                indirect = 0
                spawns: list[int] = []
                last_fn_ptr = None
                for op in ops:
                    t = op.get("type")
                    m = _CALLEE.match(op.get("disasm") or "")
                    if t == "lea" and op.get("ptr") in names_by_addr:
                        last_fn_ptr = op["ptr"]                   # a function value (closure / goroutine body)
                    if m and t in _CALL_TYPES and not _REG.match(m.group(1)):
                        callees.append(m.group(1))
                        if "newproc" in m.group(1) and last_fn_ptr is not None:
                            spawns.append(last_fn_ptr)            # go f(): the body handed to runtime.newproc
                    elif t in _CALL_TYPES and t != "jmp" and not op.get("jump"):
                        indirect += 1                             # target in a register / memory: unresolved
                strs, xor = _strings_and_xor(ops, reader, mode)
                refs, xkeys = _data_refs(ops)
                back = sum(1 for op in ops if op.get("type") == "cjmp" and isinstance(op.get("jump"), int)
                           and a <= op["jump"] < (op.get("offset") or 0))       # backward branches = loops
                functions[a] = {
                    "addr": a, "name": n["name"], "named": n.get("named", True), "user": n.get("user", True),
                    "file": n.get("file") or "", "line": n.get("line"),
                    "size": info.get("size") or info.get("realsz"), "blocks": info.get("nbbs"),
                    "complexity": info.get("cc"), "loops": max(info.get("loops") or 0, back), "stack": info.get("stackframe"),
                    "calls": sorted({c["to"] for c in info.get("callrefs") or [] if c.get("type") == "CALL"}),
                    "callee_names": [c for c in dict.fromkeys(callees) if c != _flag(n["name"], "go.")][:200],
                    "strings": strs[:100], "xor_ops": xor, "instructions": len(ops),
                    "indirect_calls": indirect, "spawns": sorted(set(spawns)),
                    "data_refs": refs, "xor_keys": xkeys,
                }
                disasm[a] = ops
            if r.get("killed") and "memory" in (r.get("killed") or ""):
                break

        # 2. context: callers, readable callee names
        flag_to_name: dict[str, str] = {}
        for v in names_by_addr.values():
            flag_to_name[_flag(v, "go.")] = v
            flag_to_name[_flag(v, "sym.")] = v              # symbol-table names of non-stripped builds
        for f in functions.values():
            f["callee_names"] = [flag_to_name.get(c) or _readable(c) for c in f["callee_names"]]
            for c in f["calls"]:
                if c in functions:
                    functions[c].setdefault("callers", []).append(f["addr"])
        for f in functions.values():
            f["traits"] = _traits(f, mode)
        # 3. priority
        for f in functions.values():
            f["score"], f["reasons"], f["categories"] = priority.score(
                f, f["callee_names"], [s["value"] for s in f["strings"]], mode)
        ranked = sorted(functions.values(), key=lambda f: (-f["score"], -(f.get("size") or 0)))
        for k, f in enumerate(ranked):
            f["rank"] = k + 1

        # 4. decompilation of the top functions, against the budget
        decompiled: dict[str, Any] = {}
        for f in ranked:
            if f["user"] and (f.get("size") or 0) > DECOMPILE_MAX_SIZE:
                f["decompile_note"] = "too large for the automatic pass: decompile it on demand"
        todo = [f for f in ranked if f["user"] and (f.get("size") or 0) <= DECOMPILE_MAX_SIZE][:DECOMPILE_N]
        kills = 0
        for i in range(0, len(todo), DEC_BATCH):
            now = time.monotonic()
            if now > hard or (now > deadline and not decompiled):
                summary["warnings"].append(f"time limit reached: {len(decompiled)} of {len(todo)} functions decompiled")
                break
            if now > deadline:
                summary["extended"] = True                  # still producing: allowed until the hard limit
            chunk = todo[i:i + DEC_BATCH]
            groups = []
            for f in chunk:
                cmds = [(f"af:{f['addr']}", f"af @ {f['addr']:#x}")] if mode == "go" else []
                groups.append((str(f["addr"]), cmds + [(f"g:{f['addr']}", f"pdgj @ {f['addr']:#x}")]))
            if progress:
                progress(f"decompiling {i + len(chunk)}/{len(todo)}")
            r = rz.run_groups(path, groups, timeout=left(), mem_mb=MEM_MB, prelude=prelude, deadline=hard)
            outs = dict(r["outputs"])
            if r.get("killed"):
                # one function blew the limits: retry the rest of the batch one by one
                kills += 1
                for f, grp in zip(chunk, groups):
                    if rz.as_json(outs.get(f"g:{f['addr']}")) or time.monotonic() > hard:
                        continue
                    r1 = rz.run_groups(path, [grp], timeout=min(left(), 300), mem_mb=MEM_MB, prelude=prelude,
                                       deadline=hard)
                    outs.update(r1["outputs"])
                    if r1.get("killed"):
                        f["decompile_note"] = f"automatic pass stopped: {r1['killed']}; decompile it on demand"
            for f in chunk:
                g = rz.as_json(outs.get(f"g:{f['addr']}"))
                if isinstance(g, dict) and g.get("code"):
                    decompiled[str(f["addr"])] = {"code": _pretty(g["code"], g.get("annotations") or [], names_by_addr),
                                                  "status": "ok"}
                    f["decompiled"] = True
                else:
                    decompiled[str(f["addr"])] = {"status": "failed",
                                                  "detail": r.get("killed") or "rz-ghidra could not decompile it"}
            if r.get("killed"):
                summary["warnings"].append(f"Rizin stopped while decompiling ({r['killed']}); retried one by one")
                if kills >= 5:
                    break

        # 5. imported APIs (PE / ELF / Mach-O import tables) and who calls them
        apis = _imports(path, ranked)

    keep = {f["addr"] for f in ranked[:DISASM_KEEP]}
    strings = [dict(s, function=f["name"]) for f in ranked for s in f["strings"]]
    full = {"summary": None, "functions": ranked, "decompiled": decompiled,
            "disasm": {str(a): _trim_ops(ops) for a, ops in disasm.items() if a in keep},
            "strings": strings[:5000], "apis": apis}
    summary.update({
        "elapsed_s": round(time.monotonic() - t0, 1), "functions_analyzed": len(functions),
        "decompiled": sum(1 for d in decompiled.values() if d.get("status") == "ok"),
        "strings": len(strings), "apis": len(apis), "limits": {"budget_min": BUDGET_S // 60, "max_min": MAX_S // 60, "mem_mb": MEM_MB,
                                            "decompile": DECOMPILE_N},
        "top": [{"addr": f["addr"], "name": f["name"], "score": f["score"], "categories": f["categories"]}
                for f in ranked[:15]],
    })
    if summary["warnings"] and summary["status"] == "ok":
        summary["status"] = "partial"
    full["summary"] = summary
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(full), encoding="utf-8")
    return summary


def _imports(path: Path, ranked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    r = rz.run(path, [("imp", "iij")], timeout=120, mem_mb=MEM_MB)
    imps = rz.as_json(r.get("outputs", {}).get("imp")) or []
    users: dict[str, list[str]] = {}
    for f in ranked:
        for c in f.get("callee_names") or []:
            if c.startswith("imp."):
                key = c[4:].rsplit("_", 1)[-1] if ".dll_" in c.lower() else c[4:]
                users.setdefault(key.lower(), []).append(f["name"])
    out = []
    for i in imps if isinstance(imps, list) else []:
        name = i.get("name") or ""
        if not name:
            continue
        low = name.lower()
        cats = [k for k, c in priority.CATEGORIES.items() if any(x in low for x in c.get("api", ()))]
        out.append({"name": name, "lib": i.get("libname") or "", "ordinal": i.get("ordinal"),
                    "plt": i.get("plt"), "categories": cats,
                    "used_by": list(dict.fromkeys(users.get(low, [])))[:50]})
    out.sort(key=lambda x: (not x["categories"], not x["used_by"], (x["lib"] or "").lower(), x["name"].lower()))
    return out[:5000]


def _hex(s: str) -> int:
    try:
        return int(s, 16)
    except ValueError:
        return -1


def decompile_one(path: Path, addr: int, *, mode: str, names: list[dict[str, Any]] | None,
                  lock_path: Path) -> dict[str, Any]:
    """Decompile a single function on demand (Code view)."""
    if not available():
        return {"status": "unavailable"}
    prelude = ["f- reloc.*"] if mode == "go" else ["aa"]
    names_by_addr = {}
    for n in names or []:
        names_by_addr[n["start"]] = n["name"]
        prelude.append(f"f {_flag(n['name'], 'go.')} {max(1, n['end'] - n['start'])} @ {n['start']:#x}")
    cmds = ([("af", f"af @ {addr:#x}")] if mode == "go" else []) + [("d", f"pdfj @ {addr:#x}"),
                                                                    ("g", f"pdgj @ {addr:#x}")]
    with rz.exclusive(lock_path, wait_s=600):
        r = rz.run(path, cmds, timeout=600, mem_mb=MEM_MB, prelude=prelude)
    pdf = rz.as_json(r["outputs"].get("d")) or {}
    ops = _trim_ops(pdf.get("ops") or []) if isinstance(pdf, dict) else []
    g = rz.as_json(r["outputs"].get("g"))
    if isinstance(g, dict) and g.get("code"):
        return {"status": "ok", "code": _pretty(g["code"], g.get("annotations") or [], names_by_addr), "ops": ops}
    return {"status": "failed", "ops": ops,
            "detail": (r.get("killed") or r.get("stderr") or r.get("error") or "rz-ghidra could not decompile it")[-300:]}


def decompile_many(path: Path, addrs: list[int], *, mode: str, names: list[dict[str, Any]] | None,
                   lock_path: Path) -> dict[int, dict[str, Any]]:
    """Decompile several functions in ONE Rizin session (one analysis pass for
    all of them): {addr: decompile_one-like result}."""
    if not available():
        return {a: {"status": "unavailable"} for a in addrs}
    prelude = ["f- reloc.*"] if mode == "go" else ["aa"]
    names_by_addr = {}
    for n in names or []:
        names_by_addr[n["start"]] = n["name"]
        prelude.append(f"f {_flag(n['name'], 'go.')} {max(1, n['end'] - n['start'])} @ {n['start']:#x}")
    cmds: list[tuple[str, str]] = []
    for i, addr in enumerate(addrs):
        if mode == "go":
            cmds.append((f"af{i}", f"af @ {addr:#x}"))
        cmds += [(f"d{i}", f"pdfj @ {addr:#x}"), (f"g{i}", f"pdgj @ {addr:#x}")]
    with rz.exclusive(lock_path, wait_s=1800):
        r = rz.run(path, cmds, timeout=300 + 240 * len(addrs), mem_mb=MEM_MB, prelude=prelude)
    out: dict[int, dict[str, Any]] = {}
    for i, addr in enumerate(addrs):
        pdf = rz.as_json(r["outputs"].get(f"d{i}")) or {}
        ops = _trim_ops(pdf.get("ops") or []) if isinstance(pdf, dict) else []
        g = rz.as_json(r["outputs"].get(f"g{i}"))
        if isinstance(g, dict) and g.get("code"):
            out[addr] = {"status": "ok", "code": _pretty(g["code"], g.get("annotations") or [], names_by_addr), "ops": ops}
        else:
            out[addr] = {"status": "failed", "ops": ops,
                         "detail": (r.get("killed") or r.get("stderr") or r.get("error")
                                    or "rz-ghidra could not decompile it")[-300:]}
    return out


def cfg_one(path: Path, addr: int, *, mode: str, names: list[dict[str, Any]] | None,
            lock_path: Path) -> dict[str, Any]:
    """Control-flow graph of one function: basic blocks (with their
    instructions) and the jump / fall-through edges between them."""
    if not available():
        return {"status": "unavailable"}
    prelude = ["f- reloc.*"] if mode == "go" else ["aa"]
    for n in names or []:
        prelude.append(f"f {_flag(n['name'], 'go.')} {max(1, n['end'] - n['start'])} @ {n['start']:#x}")
    cmds = ([("af", f"af @ {addr:#x}")] if mode == "go" else []) + [("b", f"afbj @ {addr:#x}"),
                                                                    ("d", f"pdfj @ {addr:#x}")]
    with rz.exclusive(lock_path, wait_s=600):
        r = rz.run(path, cmds, timeout=300, mem_mb=MEM_MB, prelude=prelude)
    bbs = rz.as_json(r["outputs"].get("b")) or []
    pdf = rz.as_json(r["outputs"].get("d")) or {}
    ops = (pdf.get("ops") or []) if isinstance(pdf, dict) else []
    if not isinstance(bbs, list) or not bbs:
        return {"status": "failed", "detail": (r.get("killed") or r.get("stderr") or "no basic blocks")[-300:]}
    blocks = []
    for b in bbs[:MAX_BLOCKS]:
        start, size = b.get("addr"), b.get("size") or 0
        bops = [o for o in ops if start <= (o.get("offset") or -1) < start + size]
        blocks.append({"addr": start, "size": size, "jump": b.get("jump"), "fail": b.get("fail"),
                       "switch": [c.get("jump") for c in (b.get("switch_op") or {}).get("cases") or []][:64],
                       "ninstr": b.get("ninstr") or len(bops), "ops": _trim_ops(bops)[:BLOCK_OPS]})
    edges = []
    have = {b["addr"] for b in blocks}
    for b in blocks:
        if b["jump"] in have:
            edges.append({"from": b["addr"], "to": b["jump"], "kind": "jump" if b["fail"] is not None else "always"})
        if b["fail"] in have:
            edges.append({"from": b["addr"], "to": b["fail"], "kind": "fail"})
        for c in b["switch"]:
            if c in have:
                edges.append({"from": b["addr"], "to": c, "kind": "switch"})
    return {"status": "ok", "blocks": blocks, "edges": edges, "truncated": len(bbs) > MAX_BLOCKS,
            "loops": sum(1 for e in edges if e["to"] <= e["from"])}
