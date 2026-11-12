"""Go binary identification (Go Malware Intelligence, phase 1) — own parser.

Evidence read directly from the file, each with its offset:

* **BuildInfo** (``\\xff Go buildinf:``): Go version, main module, dependencies
  and build settings (inline strings since Go 1.18; pointers before).
* **pclntab** (magic ``0xfffffffb`` 1.2–1.15, ``…fa`` 1.16–1.17, ``…f0``
  1.18–1.19, ``…f1`` 1.20+): header validated (quantum, pointer size, offsets),
  function count and a sample of function names.
* **moduledata**: the runtime table that points back at pclntab (validated by
  the pointers it must hold).
* **Go build ID** (``\\xff Go build ID: "…"``), kept apart from the GNU build ID.
* runtime functions / strings, symbol table and DWARF presence (``-s -w``),
  packer signs and Garble-style renamed packages.

A score (provisional weights, to calibrate) gives the state: Confirmed,
Likely, Suspected, Not detected or Inconclusive. Nothing is executed.
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from typing import Any

from . import binfmt

BUILDINFO_MAGIC = b"\xff Go buildinf:"
BUILDID_MAGIC = b'\xff Go build ID: "'
MODINFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
MODINFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
PCLN_MAGICS = {0xFFFFFFFB: "1.2-1.15", 0xFFFFFFFA: "1.16-1.17", 0xFFFFFFF0: "1.18-1.19", 0xFFFFFFF1: "1.20+"}
PCLN_SECTIONS = (".gopclntab", "__gopclntab")
RUNTIME_STRINGS = (b"runtime.gopanic", b"runtime.goexit", b"runtime.morestack", b"runtime.mallocgc",
                   b"runtime.newproc", b"runtime.main")
# The Go runtime's own messages: string literals of the runtime that garble (-literals only touches the
# program's own) and a stripped / tampered pclntab leave in place — Go, even when its metadata is hidden.
RUNTIME_MESSAGES = (b"runtime.main not on m0", b"goroutine running on other thread",
                    b"invalid memory address or nil pointer dereference", b"sweep increased allocation count",
                    b"GODEBUG", b"bad g status", b"newproc: function arguments too large",
                    b"unexpected signal during runtime execution", b"all goroutines are asleep",
                    b"malloc deadlock", b"concurrent map writes", b"runtime: out of memory", b"unknown pc ")
MIN_RUNTIME_MESSAGES = 5
OTHER_SIGNS = (b"go.itab.", b"type:.eq.", b"type..eq.", b"go:buildid", b"runtime/internal/", b"go.shape.")
PACKER_SECTIONS = ("UPX0", "UPX1", "UPX2", ".petite", ".MPRESS1", ".MPRESS2", ".aspack", ".themida", ".vmp0", ".vmp1")
STD_PREFIXES = ("runtime", "internal", "sync", "syscall", "os", "fmt", "io", "net", "crypto", "time", "strings",
                "strconv", "bytes", "errors", "unicode", "math", "sort", "reflect", "encoding", "bufio", "path",
                "context", "compress", "hash", "regexp", "text", "html", "mime", "log", "flag", "vendor",
                "type:", "type.", "go:", "go.", "slices", "maps", "iter", "unique", "weak", "cmp", "embed",
                "container", "archive", "image", "debug", "golang.org", "github.com", "gopkg.in", "main")
# Std library / runtime / toolchain names (not "user" code) for the function sample.
NOT_USER = tuple(p for p in STD_PREFIXES if p not in ("main", "github.com", "golang.org", "gopkg.in")) + (
    "_cgo_", "__x86", "x_cgo", "_rt0", "callRet", "gcWriteBarrier", "setg_gcc", "crosscall", "aeshash",
    "memeqbody", "indexbytebody", "cmpbody", "countbody", "debugCall", "gogo", "gosave")
WEIGHTS = {"buildinfo": 40, "pclntab": 40, "go_build_id": 15, "runtime": 15, "moduledata": 10, "other": 5,
           "runtime_messages": 35}
MAX_NAMES = 4000


def _ev(kind: str, detail: str, offset: int | None = None, points: int = 0, **extra: Any) -> dict[str, Any]:
    e = {"kind": kind, "detail": detail, "points": points, "source": "docutracex.golang"}
    if offset is not None:
        e["offset"] = offset
        e["offset_hex"] = f"0x{offset:x}"
    e.update(extra)
    return e


# --- BuildInfo -------------------------------------------------------------------------
def _uvarint(b: bytes, i: int) -> tuple[int, int]:
    x = s = 0
    while i < len(b):
        c = b[i]
        x |= (c & 0x7F) << s
        i += 1
        if c < 0x80:
            return x, i
        s += 7
        if s > 63:
            break
    raise ValueError("bad varint")


def _read_gostring_ptr(data: bytes, binf: binfmt.Binary, va: int, ptrsize: int, en: str) -> str | None:
    off = binf.va_to_off(va)
    if off is None:
        return None
    fmt = en + ("Q" if ptrsize == 8 else "I")
    sptr = struct.unpack_from(fmt, data, off)[0]
    slen = struct.unpack_from(fmt, data, off + ptrsize)[0]
    soff = binf.va_to_off(sptr)
    if soff is None or slen > 1 << 22:
        return None
    return data[soff:soff + slen].decode("utf-8", "replace")


def parse_modinfo(mod: str) -> dict[str, Any]:
    if len(mod) >= 33 and mod[-17:-16] == "\n":
        mod = mod[16:-16]
    out: dict[str, Any] = {"path": "", "main": None, "deps": [], "settings": {}}
    for line in mod.splitlines():
        parts = line.split("\t")
        if parts[0] == "path" and len(parts) > 1:
            out["path"] = parts[1]
        elif parts[0] == "mod" and len(parts) > 1:
            out["main"] = {"path": parts[1], "version": parts[2] if len(parts) > 2 else "",
                           "sum": parts[3] if len(parts) > 3 else ""}
        elif parts[0] == "dep" and len(parts) > 1:
            out["deps"].append({"path": parts[1], "version": parts[2] if len(parts) > 2 else "",
                                "sum": parts[3] if len(parts) > 3 else ""})
        elif parts[0] == "=>" and out["deps"]:
            out["deps"][-1]["replace"] = " ".join(parts[1:])
        elif parts[0] == "build" and len(parts) > 1 and "=" in parts[1]:
            k, v = parts[1].split("=", 1)
            out["settings"][k] = v
    return out


def buildinfo(data: bytes, binf: binfmt.Binary) -> dict[str, Any] | None:
    first = i = data.find(BUILDINFO_MAGIC)
    while i >= 0 and i % 16:                            # the linker aligns it to 16
        i = data.find(BUILDINFO_MAGIC, i + 1)
    if i < 0:
        i = first                                       # unaligned (rebuilt / carved file): still read it
    if i < 0 or i + 32 > len(data):
        return None
    ptrsize, flags = data[i + 14], data[i + 15]
    en = ">" if flags & 1 else "<"
    version = modinfo = None
    try:
        if flags & 2:                                   # Go 1.18+: inline varint strings
            n, j = _uvarint(data, i + 32)
            version = data[j:j + n].decode("utf-8", "replace")
            n2, k = _uvarint(data, j + n)
            modinfo = data[k:k + n2].decode("utf-8", "replace")
        elif ptrsize in (4, 8):                         # older: pointers to string headers
            fmt = en + ("Q" if ptrsize == 8 else "I")
            vptr = struct.unpack_from(fmt, data, i + 16)[0]
            mptr = struct.unpack_from(fmt, data, i + 16 + ptrsize)[0]
            version = _read_gostring_ptr(data, binf, vptr, ptrsize, en)
            modinfo = _read_gostring_ptr(data, binf, mptr, ptrsize, en)
    except (ValueError, struct.error):
        pass
    valid = bool(version and re.match(r"^(go|devel)\d*", version))
    info = {"offset": i, "ptr_size": ptrsize, "flags": flags, "inline": bool(flags & 2),
            "version": version or "", "valid": valid}
    if modinfo:
        info.update(parse_modinfo(modinfo))
    return info


# --- pclntab -------------------------------------------------------------------------
def _pcln_header(data: bytes, off: int) -> dict[str, Any] | None:
    if off + 8 > len(data):
        return None
    for en in ("<", ">"):
        magic = struct.unpack_from(en + "I", data, off)[0]
        if magic not in PCLN_MAGICS:
            continue
        pad1, pad2, quantum, ptrsize = data[off + 4:off + 8]
        if pad1 or pad2 or quantum not in (1, 2, 4) or ptrsize not in (4, 8):
            continue
        word = en + ("Q" if ptrsize == 8 else "I")
        h: dict[str, Any] = {"offset": off, "magic": f"0x{magic:08x}", "version_range": PCLN_MAGICS[magic],
                             "quantum": quantum, "ptr_size": ptrsize, "endianness": "big" if en == ">" else "little"}
        try:
            vals = [struct.unpack_from(word, data, off + 8 + k * ptrsize)[0] for k in range(8)]
        except struct.error:
            return None
        size_left = len(data) - off
        if magic in (0xFFFFFFF0, 0xFFFFFFF1):
            nfunc, nfiles, text, fname, cu, ftab, pctab, pcln = vals
            h["text_start"] = text
            offs = [fname, cu, ftab, pctab, pcln]
        elif magic == 0xFFFFFFFA:
            nfunc, nfiles, fname, cu, ftab, pctab, pcln = vals[:7]
            offs = [fname, cu, ftab, pctab, pcln]
        else:                                           # 1.2–1.15: nfunctab then functab
            nfunc, nfiles, offs = vals[0], None, []
        if not 0 < nfunc < 10_000_000:
            continue
        if offs and (offs != sorted(offs) or offs[0] < 8 + 8 * ptrsize or offs[-1] >= size_left):
            continue
        h["nfunc"] = nfunc
        if nfiles is not None:
            h["nfiles"] = nfiles
        if offs:
            h["funcname_offset"], h["cu_offset"], h["filetab_offset"], h["pctab_offset"], h["pcln_offset"] = offs
        h["_en"] = en
        return h
    return None


def _func_names(data: bytes, h: dict[str, Any]) -> list[str]:
    off = h["offset"]
    if "funcname_offset" in h:                          # 1.16+: one table of NUL-terminated names
        a = off + h["funcname_offset"]
        b = off + h["cu_offset"]
        blob = data[a:min(b, a + 8 * 1024 * 1024)]
        return [n.decode("utf-8", "replace") for n in blob.split(b"\x00") if n]
    # 1.2–1.15: functab (pc, funcoff) pairs → _func.nameoff
    ps, en = h["ptr_size"], h["_en"]
    word = en + ("Q" if ps == 8 else "I")
    names = []
    base = off + 8 + ps
    for k in range(min(h["nfunc"], MAX_NAMES)):
        try:
            funcoff = struct.unpack_from(word, data, base + (2 * k + 1) * ps)[0]
            nameoff = struct.unpack_from(en + "i", data, off + funcoff + ps)[0]
        except struct.error:
            break
        if not 0 < nameoff < len(data) - off:
            continue
        end = data.find(b"\x00", off + nameoff, off + nameoff + 512)
        if end > 0:
            names.append(data[off + nameoff:end].decode("utf-8", "replace"))
    return names


def pclntab(data: bytes, binf: binfmt.Binary) -> dict[str, Any] | None:
    cands: list[int] = []
    sec = binf.section(*PCLN_SECTIONS)
    if sec and sec.offset:
        cands.append(sec.offset)
    for m in PCLN_MAGICS:
        for en in ("<", ">"):
            pat = struct.pack(en + "I", m) + b"\x00\x00"
            i = data.find(pat)
            n = 0
            while i >= 0 and n < 64:
                cands.append(i)
                i = data.find(pat, i + 1)
                n += 1
    for off in dict.fromkeys(cands):
        h = _pcln_header(data, off)
        if not h:
            continue
        names = _func_names(data, h)
        runtime = sum(1 for n in names if n.startswith("runtime."))
        if runtime < 3:                                 # a header shape alone is not enough
            continue
        h["section"] = sec.name if sec and sec.offset == off else ""
        h["va"] = binf.off_to_va(off)
        h["names"] = names
        h["runtime_functions"] = runtime
        h["has_main_main"] = "main.main" in names
        return h
    return None


def function_table(data: bytes, h: dict[str, Any], binf: binfmt.Binary | None = None) -> list[dict[str, Any]]:
    """[{name, start, end}] from pclntab's functab (Go 1.16+): the own fallback
    when GoReSym is missing or refuses the file. Addresses are virtual."""
    if "pcln_offset" not in h:
        return []
    off, ps, en = h["offset"], h["ptr_size"], h.get("_en", "<")
    ftab = off + h["pcln_offset"]
    names_at = off + h["funcname_offset"]
    n = h["nfunc"]
    out = []
    try:
        if "text_start" in h:                            # 1.18+: uint32 entryoff / funcoff, text-relative
            text = h["text_start"]
            if not text and binf is not None:            # newer linkers leave it 0: runtime.text = .text
                sec = binf.section(".text", "__text")
                text = sec.va if sec else 0
            ents = [struct.unpack_from(en + "II", data, ftab + 8 * k) for k in range(n + 1)]
            for k in range(n):
                eoff, foff = ents[k]
                fstart = ftab + foff
                nameoff = struct.unpack_from(en + "i", data, fstart + 4)[0]
                out.append((text + eoff, text + ents[k + 1][0], nameoff, fstart, 4))
        else:                                            # 1.16–1.17: uintptr entry / funcoff
            word = en + ("Q" if ps == 8 else "I")
            ents = [(struct.unpack_from(word, data, ftab + 2 * ps * k)[0],
                     struct.unpack_from(word, data, ftab + 2 * ps * k + ps)[0]) for k in range(n + 1)]
            for k in range(n):
                entry, foff = ents[k]
                nameoff = struct.unpack_from(en + "i", data, ftab + foff + ps)[0]
                out.append((entry, ents[k + 1][0], nameoff, ftab + foff, ps))
    except struct.error:
        return []
    res = []
    for start, end, nameoff, fstart, entsz in out:
        a = names_at + nameoff
        e = data.find(b"\x00", a, a + 1024)
        if nameoff < 0 or e < 0:
            continue
        rec = {"name": data[a:e].decode("utf-8", "replace"), "start": start, "end": max(end, start)}
        src = _source(data, h, fstart, entsz)
        if src:
            rec.update(src)
        res.append(rec)
    return res


def _pcvalues(data: bytes, at: int, quantum: int, limit: int = 4096) -> list[int]:
    """Values of a pc-value table (zig-zag value delta, pc delta) — Go's runtime.pcvalue."""
    vals, val, first = [], -1, True
    i = at
    for _ in range(limit):
        if i >= len(data):
            break
        uv, i = _uvarint(data, i)
        if uv == 0 and not first:
            break
        first = False
        val += -((uv >> 1) + 1) if uv & 1 else uv >> 1
        _pcd, i = _uvarint(data, i)
        vals.append(val)
    return vals


def _source(data: bytes, h: dict[str, Any], fstart: int, entsz: int) -> dict[str, Any] | None:
    """{file, line} of one function, from its _func pcfile / pcln tables
    (the same tables the runtime prints in a panic trace). Go 1.16+."""
    if "pctab_offset" not in h:
        return None
    en, off = h.get("_en", "<"), h["offset"]
    try:
        base = fstart + entsz + 4 + 4 + 4                  # after entry, nameoff, args, deferreturn
        pcfile, pcln, _npcdata, cuoff = struct.unpack_from(en + "4I", data, base + 4)
        start_line = (struct.unpack_from(en + "i", data, base + 20)[0]
                      if h.get("magic") == "0xfffffff1" else 0)
        if not pcfile or not pcln:
            return None
        pct = off + h["pctab_offset"]
        files = _pcvalues(data, pct + pcfile, h["quantum"])
        lines = [x for x in _pcvalues(data, pct + pcln, h["quantum"]) if 0 < x < 10_000_000]
        if not files or files[0] < 0:
            return None
        foff = struct.unpack_from(en + "I", data, off + h["cu_offset"] + 4 * (cuoff + files[0]))[0]
        if foff == 0xFFFFFFFF:
            return None
        a = off + h["filetab_offset"] + foff
        e = data.find(b"\x00", a, a + 1024)
        if e <= a:
            return None
        name = data[a:e].decode("utf-8", "replace")
    except (struct.error, IndexError):
        return None
    out: dict[str, Any] = {"file": name}
    # the declaration line (Go 1.20+), else the line at the entry; inlined code
    # brings other files' lines into pcln, so no end line is derived from it
    if start_line > 0 or lines:
        out["line"] = start_line if start_line > 0 else lines[0]
    return out


# --- moduledata ------------------------------------------------------------------------
def moduledata(data: bytes, binf: binfmt.Binary, h: dict[str, Any]) -> dict[str, Any] | None:
    va = h.get("va")
    if not va:
        return None
    ps, en = h["ptr_size"], h["_en"]
    word = en + ("Q" if ps == 8 else "I")
    needle = struct.pack(word, va)
    i = data.find(needle)
    n = 0
    while i >= 0 and n < 256:
        try:
            nxt = struct.unpack_from(word, data, i + ps)[0]
            nlen = struct.unpack_from(word, data, i + 2 * ps)[0]
        except struct.error:
            break
        if "funcname_offset" in h:                      # 1.16+: pcHeader, funcnametab{ptr,len,cap}
            if nxt == va + h["funcname_offset"] and 0 < nlen < 1 << 28:
                return {"offset": i, "va": binf.off_to_va(i), "layout": "1.16+"}
        elif 0 < nxt < 1 << 30 and nlen == nxt:          # ≤1.15: pclntable{ptr,len,cap}
            return {"offset": i, "va": binf.off_to_va(i), "layout": "1.2-1.15"}
        i = data.find(needle, i + 1)
        n += 1
    return None


# --- helpers ---------------------------------------------------------------------------
def go_build_id(data: bytes, binf: binfmt.Binary | None = None) -> tuple[str, int] | None:
    i = data.find(BUILDID_MAGIC)
    if i < 0:
        sec = binf.section(".note.go.buildid") if binf else None     # ELF: a "Go" note, type 4
        if sec and sec.offset and sec.size >= 16:
            en = ">" if binf.big_endian else "<"
            namesz, descsz, typ = struct.unpack_from(en + "III", data, sec.offset)
            name = data[sec.offset + 12:sec.offset + 12 + namesz].rstrip(b"\x00")
            d = sec.offset + 12 + ((namesz + 3) & ~3)
            if name == b"Go" and typ == 4 and 0 < descsz < 512:
                return data[d:d + descsz].rstrip(b"\x00").decode("latin-1", "replace"), d
        return None
    j = data.find(b'"', i + len(BUILDID_MAGIC), i + len(BUILDID_MAGIC) + 512)
    if j < 0:
        return None
    bid = data[i + len(BUILDID_MAGIC):j].decode("latin-1", "replace")
    return (bid, i) if "/" in bid or len(bid) >= 20 else None


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def garble_signs(names: list[str]) -> dict[str, Any] | None:
    """Garble renames non-std packages to short random identifiers."""
    user = [n for n in names if "." in n and not n.startswith(NOT_USER)]
    if len(user) < 10:
        return None
    pkgs = Counter(n.split(".", 1)[0] for n in user if "." in n)
    rnd = [p for p in pkgs if re.fullmatch(r"[A-Za-z0-9_]{6,16}", p) and re.search(r"[A-Z]", p)
           and re.search(r"[a-z]", p) and "/" not in p]
    share = sum(pkgs[p] for p in rnd) / max(1, sum(pkgs.values()))
    if share < 0.5:
        return None
    return {"random_package_share": round(share, 2), "examples": rnd[:8]}


def identify(data: bytes) -> dict[str, Any]:
    binf = binfmt.parse(data)
    res: dict[str, Any] = {"binary": binf.as_dict(), "evidence": [], "warnings": []}
    if binf.fmt == "unknown":
        res.update(state="Not detected", score=0, reason="not a PE / ELF / Mach-O file")
        return res
    ev = res["evidence"]
    score = 0

    bi = buildinfo(data, binf)
    if bi:
        res["buildinfo"] = bi
        if bi["valid"]:
            score += WEIGHTS["buildinfo"]
            ev.append(_ev("buildinfo", f"BuildInfo: {bi['version']}"
                          + (f", module {bi.get('path')}" if bi.get("path") else ""), bi["offset"], WEIGHTS["buildinfo"]))
        else:
            ev.append(_ev("buildinfo", "BuildInfo magic present but its version string is not valid", bi["offset"]))
            res["warnings"].append("BuildInfo present but unreadable or altered")

    h = pclntab(data, binf)
    names: list[str] = []
    if h:
        names = h.pop("names")
        h.pop("_en_", None)
        score += WEIGHTS["pclntab"]
        ev.append(_ev("pclntab", f"pclntab {h['magic']} (Go {h['version_range']}), {h['nfunc']} functions, "
                      f"pointer size {h['ptr_size']}" + (f", section {h['section']}" if h["section"] else ""),
                      h["offset"], WEIGHTS["pclntab"]))
        md = moduledata(data, binf, h)
        if md:
            score += WEIGHTS["moduledata"]
            res["moduledata"] = md
            ev.append(_ev("moduledata", f"moduledata ({md['layout']}) points back at pclntab", md["offset"],
                          WEIGHTS["moduledata"]))
        res["_pcln"] = dict(h)                          # internal: functab fallback (not serialised)
        h.pop("_en", None)
        res["pclntab"] = {k: v for k, v in h.items()}
        user = [n for n in names if "." in n and not n.startswith(NOT_USER)]
        res["function_sample"] = ([n for n in user if n.startswith("main.")] + [n for n in user if not n.startswith("main.")])[:40]
        res["user_functions"] = len(user)
        res["function_names_read"] = len(names)
    bid = go_build_id(data, binf)
    if bid:
        score += WEIGHTS["go_build_id"]
        res["go_build_id"] = bid[0]
        ev.append(_ev("go_build_id", f"Go build ID {bid[0][:60]}", bid[1], WEIGHTS["go_build_id"]))
    if binf.gnu_build_id:
        ev.append(_ev("gnu_build_id", f"GNU build ID {binf.gnu_build_id} (linker note, not the Go build ID)"))

    rt_names = h["runtime_functions"] if h else 0
    rt_strings = [s.decode() for s in RUNTIME_STRINGS if s in data]
    rt_msgs = [s.decode() for s in RUNTIME_MESSAGES if s in data]
    if len(rt_msgs) >= MIN_RUNTIME_MESSAGES and not h:
        # no readable pclntab: the runtime's messages are what says Go
        score += WEIGHTS["runtime_messages"]
        ev.append(_ev("runtime_messages", f"{len(rt_msgs)} Go runtime messages ({', '.join(rt_msgs[:3])}…) "
                      "without a readable pclntab", points=WEIGHTS["runtime_messages"]))
    if rt_names >= 5 or len(rt_strings) >= 3 or len(rt_msgs) >= MIN_RUNTIME_MESSAGES:
        score += WEIGHTS["runtime"]
        ev.append(_ev("runtime", f"Go runtime: {rt_names} runtime.* functions in pclntab" if rt_names
                      else f"Go runtime strings: {', '.join(rt_strings[:4])}", points=WEIGHTS["runtime"]))
    other = [s.decode() for s in OTHER_SIGNS if s in data]
    if other:
        score += WEIGHTS["other"]
        ev.append(_ev("other", "other Go signatures: " + ", ".join(other[:4]), points=WEIGHTS["other"]))

    # stripped / packed / obfuscated / altered
    traits: dict[str, Any] = {}
    if score >= 40:
        # -w drops DWARF, -s the symbol table (Mach-O keeps a symbol table either way)
        traits["stripped"] = bool(binf.has_dwarf is False and (binf.has_symbols is False or binf.fmt == "macho"))
    packer = [s.name for s in binf.sections if s.name in PACKER_SECTIONS]
    if b"UPX!" in data[:4096] or packer:
        traits["packed"] = packer or ["UPX!"]
    big = max(binf.sections, key=lambda s: s.size, default=None)
    if big and big.offset and big.size > 65536:
        ent = _entropy(data[big.offset:big.offset + min(big.size, 1 << 22)])
        if ent > 7.4:
            traits["high_entropy_section"] = {"name": big.name, "entropy": round(ent, 2)}
    g = garble_signs(names)
    if g:
        traits["garble"] = g
    if bi and not bi["valid"]:
        traits["metadata_altered"] = "BuildInfo unreadable"
    if h and not bi:
        traits["metadata_altered"] = traits.get("metadata_altered") or "pclntab present but no BuildInfo (removed?)"
    if (rt_strings or other or rt_msgs) and not h:
        traits["pclntab_missing"] = True
        if len(rt_msgs) >= MIN_RUNTIME_MESSAGES and not traits.get("garble"):
            traits["garble"] = {"reason": "Go runtime present but pclntab hidden and BuildInfo "
                                          + ("altered" if bi else "removed")
                                          + ": garble or a modified toolchain — function names and config are "
                                          "not readable statically"}
    res["traits"] = traits
    res["score"] = score
    if score >= 80:
        state = "Confirmed"
    elif score >= 50:
        state = "Likely"
    elif score >= 20:
        state = "Suspected"
    else:
        state = "Not detected"
    if state in ("Suspected", "Not detected") and (traits.get("packed") or traits.get("high_entropy_section")) \
            and (rt_strings or other or bi):
        state = "Inconclusive"
    res["state"] = state
    v = (bi or {}).get("version") if bi and bi.get("valid") else ""
    res["go_version"] = v or (f"Go {h['version_range']} (from pclntab)" if h else "")
    return res
