"""Minimal, dependency-light view of PE / ELF / Mach-O containers for the Go
identification: format, architecture, sections (name, virtual address, file
offset, size), virtual-address → file-offset mapping, and whether the symbol
table / DWARF debug info is present (a ``-s -w`` build has neither).

Only headers are parsed — nothing in the file is executed. Malformed headers
make the helpers return less, never raise.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

PE_MACHINES = {0x14C: "386", 0x8664: "amd64", 0x1C0: "arm", 0x1C4: "arm", 0xAA64: "arm64"}
ELF_MACHINES = {3: "386", 62: "amd64", 40: "arm", 183: "arm64", 8: "mips", 20: "ppc", 21: "ppc64",
                22: "s390x", 243: "riscv64", 258: "loong64"}
MACHO_CPUS = {7: "386", 0x01000007: "amd64", 12: "arm", 0x0100000C: "arm64", 18: "ppc", 0x01000012: "ppc64"}


@dataclass
class Section:
    name: str
    va: int
    offset: int
    size: int


@dataclass
class Binary:
    fmt: str = "unknown"            # pe | elf | macho | unknown
    arch: str = ""
    bits: int = 0
    big_endian: bool = False
    os: str = ""
    sections: list[Section] = field(default_factory=list)
    has_symbols: bool | None = None
    has_dwarf: bool | None = None
    gnu_build_id: str = ""
    notes: list[str] = field(default_factory=list)

    def section(self, *names: str) -> Section | None:
        for s in self.sections:
            if s.name in names:
                return s
        return None

    def va_to_off(self, va: int) -> int | None:
        for s in self.sections:
            if s.size and s.va <= va < s.va + s.size and s.offset:
                return s.offset + (va - s.va)
        return None

    def off_to_va(self, off: int) -> int | None:
        for s in self.sections:
            if s.size and s.offset <= off < s.offset + s.size and s.va:
                return s.va + (off - s.offset)
        return None

    def as_dict(self) -> dict[str, Any]:
        return {"format": self.fmt, "arch": self.arch, "bits": self.bits, "os": self.os,
                "endianness": "big" if self.big_endian else "little",
                "sections": len(self.sections), "has_symbols": self.has_symbols,
                "has_dwarf": self.has_dwarf, "gnu_build_id": self.gnu_build_id or None}


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("latin-1", "replace")


def parse(data: bytes) -> Binary:
    try:
        if data[:2] == b"MZ":
            return _pe(data)
        if data[:4] == b"\x7fELF":
            return _elf(data)
        if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
            return _macho(data, 0)
        if data[:4] == b"\xca\xfe\xba\xbe" and len(data) > 32:
            nfat = struct.unpack_from(">I", data, 4)[0]
            if 0 < nfat < 32:                              # universal binary: first slice
                _cpu, _sub, off, _size, _al = struct.unpack_from(">IIIII", data, 8)
                b = _macho(data, off)
                b.notes.append(f"universal Mach-O ({nfat} slices), first slice analysed")
                return b
    except (struct.error, ValueError, IndexError):
        pass
    return Binary()


# --- PE -------------------------------------------------------------------------------
def _pe(data: bytes) -> Binary:
    b = Binary(fmt="pe", os="windows")
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\x00\x00":
        b.fmt = "unknown"
        return b
    mach, nsec, _ts, psym, nsym, optsz = struct.unpack_from("<HHIIIH", data, e + 4)
    b.arch = PE_MACHINES.get(mach, f"0x{mach:x}")
    opt = e + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    b.bits = 64 if magic == 0x20B else 32
    base = struct.unpack_from("<Q", data, opt + 24)[0] if b.bits == 64 else struct.unpack_from("<I", data, opt + 28)[0]
    strtab = psym + nsym * 18 if psym and nsym else 0
    sh = opt + optsz
    for i in range(min(nsec, 96)):
        o = sh + i * 40
        name = _cstr(data[o:o + 8])
        vsize, va, rawsz, rawoff = struct.unpack_from("<IIII", data, o + 8)
        if name.startswith("/") and strtab and name[1:].isdigit():      # long name (Go uses them)
            p = strtab + int(name[1:])
            name = _cstr(data[p:p + 64])
        b.sections.append(Section(name, base + va, rawoff, min(max(vsize, rawsz), rawsz or vsize)))
    b.has_symbols = bool(psym and nsym)
    b.has_dwarf = any(s.name.startswith((".debug_", ".zdebug_")) for s in b.sections)
    return b


# --- ELF ------------------------------------------------------------------------------
def _elf(data: bytes) -> Binary:
    b = Binary(fmt="elf", os="linux")
    cls, enc = data[4], data[5]
    b.bits = 64 if cls == 2 else 32
    b.big_endian = enc == 2
    en = ">" if b.big_endian else "<"
    osabi = data[7]
    b.os = {9: "freebsd", 12: "openbsd", 6: "solaris"}.get(osabi, "linux")
    mach = struct.unpack_from(en + "H", data, 18)[0]
    b.arch = ELF_MACHINES.get(mach, f"0x{mach:x}")
    if b.bits == 64:
        shoff = struct.unpack_from(en + "Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(en + "HHH", data, 58)
    else:
        shoff = struct.unpack_from(en + "I", data, 32)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(en + "HHH", data, 46)
    raw = []
    for i in range(min(shnum, 512)):
        o = shoff + i * shentsize
        if b.bits == 64:
            nm, typ, _fl, addr, off, size = struct.unpack_from(en + "IIQQQQ", data, o)
        else:
            nm, typ, _fl, addr, off, size = struct.unpack_from(en + "IIIIII", data, o)
        raw.append((nm, typ, addr, off, size))
    if raw and shstrndx < len(raw):
        stoff = raw[shstrndx][3]
        for nm, typ, addr, off, size in raw:
            name = _cstr(data[stoff + nm:stoff + nm + 64])
            b.sections.append(Section(name, addr, off if typ != 8 else 0, size))   # 8 = NOBITS
            if name == ".note.gnu.build-id":
                b.gnu_build_id = _elf_note_desc(data[off:off + size], en)
    b.has_symbols = b.section(".symtab") is not None
    b.has_dwarf = any(s.name.startswith((".debug_", ".zdebug_")) for s in b.sections)
    return b


def _elf_note_desc(note: bytes, en: str) -> str:
    if len(note) < 12:
        return ""
    namesz, descsz, _typ = struct.unpack_from(en + "III", note, 0)
    d = 12 + ((namesz + 3) & ~3)
    return note[d:d + descsz].hex()


# --- Mach-O ---------------------------------------------------------------------------
def _macho(data: bytes, base: int) -> Binary:
    b = Binary(fmt="macho", os="darwin")
    magic = data[base:base + 4]
    b.big_endian = magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
    en = ">" if b.big_endian else "<"
    b.bits = 64 if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
    cpu, _sub, _ft, ncmds, _sz, _fl = struct.unpack_from(en + "iiIIII", data, base + 4)
    b.arch = MACHO_CPUS.get(cpu & 0xFFFFFFFF, f"0x{cpu & 0xFFFFFFFF:x}")
    p = base + (32 if b.bits == 64 else 28)
    b.has_symbols = False
    for _ in range(min(ncmds, 512)):
        cmd, cmdsize = struct.unpack_from(en + "II", data, p)
        if cmd in (0x19, 0x1):                               # LC_SEGMENT_64 / LC_SEGMENT
            if cmd == 0x19:
                seg = _cstr(data[p + 8:p + 24])
                nsects = struct.unpack_from(en + "I", data, p + 64)[0]
                q, step = p + 72, 80
            else:
                seg = _cstr(data[p + 8:p + 24])
                nsects = struct.unpack_from(en + "I", data, p + 48)[0]
                q, step = p + 56, 68
            for _j in range(min(nsects, 256)):
                sname = _cstr(data[q:q + 16])
                if cmd == 0x19:
                    addr, size = struct.unpack_from(en + "QQ", data, q + 32)
                    off = struct.unpack_from(en + "I", data, q + 48)[0]
                else:
                    addr, size, off = struct.unpack_from(en + "III", data, q + 32)
                b.sections.append(Section(sname, addr, base + off if off else 0, size))
                q += step
            if seg == "__DWARF":
                b.has_dwarf = True
        elif cmd == 0x2:                                     # LC_SYMTAB
            nsyms = struct.unpack_from(en + "I", data, p + 12)[0]
            b.has_symbols = nsyms > 0
        p += cmdsize
        if cmdsize == 0:
            break
    if b.has_dwarf is None:
        b.has_dwarf = any(s.name.startswith(("__debug_", "__zdebug_")) for s in b.sections)
    return b
