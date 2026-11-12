"""Windows minidumps (``MDMP``: procdump, Task Manager "Create dump file",
WinDbg ``.dump``, comsvcs MiniDump…) read statically.

A process dump is where a crypter's work is already undone: the stage it
decrypted in memory sits there in clear. DocuTraceX does NOT run anything to get
it — the analyst dumps the process in his own lab VM; this reader only takes the
file apart:

- **process**: architecture, PID, the loaded modules (path, base, size) and the
  memory regions (with protection and type when the dump has MemoryInfoList);
- **PE images in memory**, carved and rebuilt as files:
  - *mapped* images (page-aligned, sections at their virtual addresses) are put
    back in file layout (each section copied from ``VirtualAddress`` to
    ``PointerToRawData``);
  - *flat* images (the ``byte[]`` handed to ``Assembly.Load`` / a buffer before
    it is mapped) are kept as they are, cut to the end of their last section;
  - modules loaded from the Windows folder are listed, not carved (they are the
    system's own); everything else is carved — above all PEs **no module on disk
    backs** (injected, reflectively loaded, ``Assembly.Load``);
- **private executable memory without a PE header** (shellcode, a beacon whose
  header was wiped) is saved as ``.bin`` so the C2 extractors can read it.

Every carved file becomes a nested child (and an object for the C2 tab).
Bounded: at most MAX_CARVED files, MAX_IMAGE bytes each, MAX_SCAN bytes scanned.
"""

from __future__ import annotations

import hashlib
import mmap
import re
import struct
from bisect import bisect_right
from pathlib import Path
from typing import Any

MAGIC = b"MDMP"
MAX_CARVED = 120
MAX_IMAGE = 64 * 1024 * 1024
MAX_EXEC_REGION = 16 * 1024 * 1024
MAX_SCAN = 8 * 1024 * 1024 * 1024
MAX_MODULES_LISTED = 400

_ARCH = {0: "x86", 5: "ARM", 6: "IA64", 9: "x64", 12: "ARM64"}
_MEM_COMMIT, _MEM_PRIVATE, _MEM_IMAGE, _MEM_MAPPED = 0x1000, 0x20000, 0x1000000, 0x40000
_EXEC = {0x10: "X", 0x20: "RX", 0x40: "RWX", 0x80: "WCX"}
_MZ = re.compile(rb"MZ")


def is_minidump(data: bytes) -> bool:
    return data[:4] == MAGIC


class _Dump:
    def __init__(self, buf: Any):
        self.b = buf
        self.size = len(buf)
        sig, _ver, n, rva = struct.unpack_from("<4sIII", buf, 0)
        if sig != MAGIC:
            raise ValueError("not a minidump")
        self.streams: dict[int, tuple[int, int]] = {}
        for i in range(min(n, 4096)):
            t, size, off = struct.unpack_from("<III", buf, rva + 12 * i)
            self.streams.setdefault(t, (off, size))
        self.ranges: list[tuple[int, int, int]] = []       # (va, size, file offset), sorted by va
        self._memory()
        self.starts = [r[0] for r in self.ranges]

    def _memory(self) -> None:
        if 9 in self.streams:                              # Memory64ListStream (full dumps)
            off, _ = self.streams[9]
            n, base = struct.unpack_from("<QQ", self.b, off)
            pos = base
            for i in range(min(n, 2_000_000)):
                va, size = struct.unpack_from("<QQ", self.b, off + 16 + 16 * i)
                if pos + size > self.size:
                    break
                self.ranges.append((va, size, pos))
                pos += size
        if 5 in self.streams:                              # MemoryListStream (small dumps)
            off, _ = self.streams[5]
            n = struct.unpack_from("<I", self.b, off)[0]
            for i in range(min(n, 2_000_000)):
                va, size, rva = struct.unpack_from("<QII", self.b, off + 4 + 16 * i)
                if rva + size <= self.size:
                    self.ranges.append((va, size, rva))
        self.ranges.sort()

    def read(self, va: int, n: int) -> bytes:
        """``n`` bytes at ``va``; pages missing from the dump read as zeros."""
        out = bytearray(n)
        pos = 0
        while pos < n:
            i = bisect_right(self.starts, va + pos) - 1
            if i < 0:
                nxt = self.starts[0] if self.starts else va + n
                pos = min(n, nxt - va)
                continue
            rva, size, off = self.ranges[i]
            if va + pos >= rva + size:                     # in a hole: jump to the next range
                nxt = self.starts[i + 1] if i + 1 < len(self.starts) else va + n
                pos = min(n, max(pos + 1, nxt - va))
                continue
            k = min(n - pos, rva + size - (va + pos))
            start = off + (va + pos - rva)
            out[pos:pos + k] = self.b[start:start + k]
            pos += k
        return bytes(out)

    def _string(self, rva: int) -> str:
        try:
            n = struct.unpack_from("<I", self.b, rva)[0]
            return bytes(self.b[rva + 4:rva + 4 + min(n, 2048)]).decode("utf-16-le", "replace")
        except struct.error:
            return ""

    def modules(self) -> list[dict[str, Any]]:
        if 4 not in self.streams:
            return []
        off, _ = self.streams[4]
        n = struct.unpack_from("<I", self.b, off)[0]
        out = []
        for i in range(min(n, 10_000)):
            base, size, _ck, ts, name_rva = struct.unpack_from("<QIIII", self.b, off + 4 + 108 * i)
            out.append({"path": self._string(name_rva), "base": base, "size": size, "timestamp": ts})
        return out

    def memory_info(self) -> list[dict[str, int]]:
        if 16 not in self.streams:
            return []
        off, _ = self.streams[16]
        hdr, ent, n = struct.unpack_from("<IIQ", self.b, off)
        out = []
        for i in range(min(n, 2_000_000)):
            e = off + hdr + ent * i
            base, alloc, aprot, _a, size, state, prot, typ = struct.unpack_from("<QQIIQIII", self.b, e)
            out.append({"base": base, "alloc": alloc, "size": size, "state": state, "protect": prot, "type": typ})
        return out

    def system(self) -> dict[str, Any]:
        info: dict[str, Any] = {}
        if 7 in self.streams:
            off, _ = self.streams[7]
            arch, _lvl, _rev, _np, _pt, major, minor, build = struct.unpack_from("<HHHBBIII", self.b, off)
            info.update(arch=_ARCH.get(arch, str(arch)), windows=f"{major}.{minor}.{build}")
        if 15 in self.streams:
            off, size = self.streams[15]
            if size >= 12:
                _sz, flags, pid = struct.unpack_from("<III", self.b, off)
                if flags & 1:
                    info["pid"] = pid
        return info


def _pe_header(d: _Dump, va: int) -> dict[str, Any] | None:
    head = d.read(va, 0x400)
    if head[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if not 0x40 <= lfanew <= 0x300 or head[lfanew:lfanew + 4] != b"PE\x00\x00":
        return None
    machine, nsec, _ts, _p, _n, optsize, chars = struct.unpack_from("<HHIIIHH", head, lfanew + 4)
    if not 0 < nsec <= 96 or optsize not in (0xE0, 0xF0):
        return None
    opt = lfanew + 24
    magic = struct.unpack_from("<H", head, opt)[0]
    if magic not in (0x10B, 0x20B):
        return None
    size_image, size_headers = struct.unpack_from("<II", head, opt + 56)
    clr_dir = opt + (208 if magic == 0x10B else 224)       # data directory 14 (CLR)
    clr = struct.unpack_from("<I", head, clr_dir)[0] if clr_dir + 8 <= len(head) else 0
    secs = []
    for i in range(nsec):
        sh = opt + optsize + 40 * i
        if sh + 40 > len(head):
            break
        name = head[sh:sh + 8].rstrip(b"\x00").decode("latin-1")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", head, sh + 8)
        secs.append({"name": name, "vsize": vsize, "va": vaddr, "rsize": rsize, "raw": rptr})
    if not secs:
        return None
    return {"machine": machine, "dll": bool(chars & 0x2000), "size_image": size_image,
            "size_headers": min(size_headers, 0x1000), "sections": secs, "dotnet": bool(clr)}


def _file_size(h: dict[str, Any]) -> int:
    return max([h["size_headers"]] + [s["raw"] + s["rsize"] for s in h["sections"]])


def _is_mapped(d: _Dump, va: int, h: dict[str, Any]) -> bool:
    """Mapped (loader layout) or flat (file layout)? Flat buffers from the managed
    heap are not page-aligned; for aligned ones, a mapped image has zero padding
    where the first section's file bytes would be, and that section's data at its
    virtual address."""
    if va & 0xFFF:
        return False
    s = next((s for s in h["sections"] if s["rsize"] and s["raw"] and s["raw"] != s["va"]), None)
    if s is None:
        return True                                        # same offsets either way
    at_raw, at_va = d.read(va + s["raw"], 64), d.read(va + s["va"], 64)
    return not any(at_raw) and any(at_va)


def _rebuild(d: _Dump, va: int, h: dict[str, Any], mapped: bool) -> bytes:
    size = _file_size(h)
    if size <= 0 or size > MAX_IMAGE:
        return b""
    if not mapped:
        return d.read(va, size)
    out = bytearray(size)
    out[:h["size_headers"]] = d.read(va, h["size_headers"])
    for s in h["sections"]:
        if s["rsize"] and s["raw"] + s["rsize"] <= size:
            out[s["raw"]:s["raw"] + s["rsize"]] = d.read(va + s["va"], s["rsize"])
    return bytes(out)


def _windows_module(path: str) -> bool:
    p = path.replace("/", "\\").lower()
    return bool(re.match(r"^(?:[a-z]:)?\\windows\\", p) or p.startswith("\\systemroot\\"))


def analyze(path: Path, out_dir: Path | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "memdump", "file": path.name, "findings": [], "carved": [], "warnings": []}
    with path.open("rb") as fh:
        try:
            buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            res.update(status="error", detail="empty file")
            return res
        try:
            return _analyze(_Dump(buf), path, out_dir, res)
        except (ValueError, struct.error) as exc:
            res.update(status="error", detail=f"not a readable minidump: {exc}"[:200])
            return res
        finally:
            buf.close()


def _analyze(d: _Dump, path: Path, out_dir: Path | None, res: dict[str, Any]) -> dict[str, Any]:
    mods = d.modules()
    info = d.memory_info()
    by_base = {m["base"]: m for m in mods}
    region_of = {r["base"]: r for r in info}
    alloc_type = {}
    for r in info:
        alloc_type.setdefault(r["alloc"], r["type"])
    res.update(status="ok", process=d.system(), size=d.size,
               counts={"modules": len(mods), "ranges": len(d.ranges),
                       "memory_bytes": sum(r[1] for r in d.ranges)},
               streams=sorted(d.streams),
               modules=[{"path": m["path"], "base": f"{m['base']:#x}", "size": m["size"],
                         "system": _windows_module(m["path"])} for m in mods[:MAX_MODULES_LISTED]])
    main = next((m for m in mods if not m["path"].lower().endswith(".dll")), mods[0] if mods else None)
    if main:
        res["process"]["image"] = main["path"]
    if not d.ranges:
        res["warnings"].append("the dump has no memory (only thread / module lists): nothing to carve")
        res["counts"]["findings"] = 0
        return res

    seen: set[str] = set()
    carved_starts: list[tuple[int, int]] = []
    scanned = 0
    skipped_system = 0

    def keep(name: str, data: bytes, rec: dict[str, Any]) -> None:
        sha = hashlib.sha256(data).hexdigest()
        if sha in seen or len(res["carved"]) >= MAX_CARVED:
            return
        seen.add(sha)
        rec.update(name=name, size=len(data), sha256=sha)
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            p = out_dir / name
            p.write_bytes(data)
            rec["_path"] = str(p)
        res["carved"].append(rec)

    for va, size, off in d.ranges:
        if scanned >= MAX_SCAN:
            res["warnings"].append(f"stopped scanning after {MAX_SCAN // 2**30} GiB of memory")
            break
        scanned += size
        chunk = d.b[off:off + size]
        for m in _MZ.finditer(chunk):
            at = va + m.start()
            h = _pe_header(d, at)
            if h is None:
                continue
            mod = by_base.get(at)
            if mod and _windows_module(mod["path"]):
                skipped_system += 1
                continue
            mapped = _is_mapped(d, at, h)
            data = _rebuild(d, at, h, mapped)
            if len(data) < 0x200:
                continue
            backed = bool(mod) or alloc_type.get(at) == _MEM_IMAGE
            label = Path(mod["path"].replace("\\", "/")).name if mod else "unbacked"
            ext = "dll" if h["dll"] else "exe"
            keep(f"{label}_{at:x}.{ext}", data,
                 {"va": f"{at:#x}", "layout": "mapped → rebuilt" if mapped else "flat (file layout)",
                  "backed": backed, "module": mod["path"] if mod else "", "dotnet": h["dotnet"], "kind": "pe"})
            carved_starts.append((at, h["size_image"] or len(data)))
            if len(res["carved"]) >= MAX_CARVED:
                break

    # private executable memory without a PE: shellcode, a beacon with a wiped header
    for r in info:
        if r["state"] != _MEM_COMMIT or r["type"] != _MEM_PRIVATE or r["protect"] & 0xFF not in _EXEC:
            continue
        if r["size"] > MAX_EXEC_REGION or any(s <= r["base"] < s + n for s, n in carved_starts):
            continue
        blob = d.read(r["base"], r["size"])
        if not blob.strip(b"\x00"):
            continue
        keep(f"exec_private_{r['base']:x}.bin", blob.rstrip(b"\x00") or blob,
             {"va": f"{r['base']:#x}", "layout": "raw region", "backed": False, "module": "",
              "protect": _EXEC[r["protect"] & 0xFF], "kind": "region"})

    res["counts"].update(carved=len(res["carved"]), system_modules_skipped=skipped_system)
    _findings(res, region_of)
    return res


def _findings(res: dict[str, Any], region_of: dict[int, dict[str, int]]) -> None:  # noqa: ARG001
    loc = f"file:{res['file']}"
    p = res.get("process") or {}
    res["findings"].append({
        "tool": "memdump", "rule": "memdump_process", "severity": "info", "location": loc,
        "detail": f"Process memory dump of {Path((p.get('image') or '?').replace(chr(92), '/')).name}"
                  + (f" (PID {p['pid']})" if p.get("pid") else "") + (f", {p['arch']}" if p.get("arch") else "")
                  + f": {res['counts']['modules']} module(s), {res['counts']['memory_bytes'] // 1024} KiB of memory",
        "evidence": ""})
    unbacked = [c for c in res["carved"] if c["kind"] == "pe" and not c["backed"]]
    if unbacked:
        res["findings"].append({
            "tool": "memdump", "rule": "memdump_unbacked_pe", "severity": "high", "location": loc,
            "detail": f"{len(unbacked)} PE image(s) in memory that no module on disk backs (injected, reflectively "
                      "loaded or Assembly.Load): carved as nested objects · T1055 / T1620",
            "evidence": ", ".join(f"{c['va']}{' .NET' if c.get('dotnet') else ''}" for c in unbacked[:10]),
            "attack": "T1620"})
    execs = [c for c in res["carved"] if c["kind"] == "region"]
    if execs:
        rwx = [c for c in execs if c.get("protect") == "RWX"]
        res["findings"].append({
            "tool": "memdump", "rule": "memdump_exec_private", "severity": "medium" if rwx else "low",
            "location": loc,
            "detail": f"{len(execs)} private executable region(s) without a PE header"
                      + (f", {len(rwx)} of them RWX" if rwx else "")
                      + " (shellcode / a beacon with a wiped header?): saved for the C2 extractors · T1055",
            "evidence": ", ".join(f"{c['va']} {c.get('protect')}" for c in execs[:10]), "attack": "T1055"})
    res["counts"]["findings"] = len(res["findings"])


def public(res: dict[str, Any], root: Path) -> dict[str, Any]:
    """The result without local paths, with each carved file's case-relative path."""
    out = dict(res)
    out["carved"] = []
    for c in res.get("carved") or []:
        c = dict(c)
        p = c.pop("_path", None)
        if p:
            try:
                c["stored_path"] = Path(p).resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                c["stored_path"] = ""
        out["carved"].append(c)
    return out
