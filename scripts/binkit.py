"""Tiny builders for inert binaries used by the samples (Machine Learning tab).

Every file is *structurally* valid — pefile / LIEF / the EMBER feature
extractor parse it like a real binary — but carries no behaviour: the only code
is a single ``ret``. Imports, strings, sections, .NET metadata and ELF sections
are there so the static classifiers have something to read. Indicators are
inert (*.example domains, RFC 5737 IPs).
"""

from __future__ import annotations

import io
import random
import struct
import zipfile

FA, SA = 0x200, 0x1000


def _al(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def _strz(*items: str) -> bytes:
    return b"".join(s.encode("latin-1", "replace") + b"\x00" for s in items)


def _wstrz(*items: str) -> bytes:
    return b"".join(s.encode("utf-16-le") + b"\x00\x00" for s in items)


# --- PE ----------------------------------------------------------------------------

def _imports(va: int, imports: dict[str, list[str]], ptr: int) -> tuple[bytes, int, int]:
    """An import section at ``va``: (bytes, import dir size, IAT rva)."""
    dlls = list(imports)
    desc_size = (len(dlls) + 1) * 20
    blob = bytearray(desc_size)
    thunks: list[tuple[int, int]] = []          # (ilt offset, iat offset) per dll
    for dll in dlls:
        n = len(imports[dll]) + 1
        ilt = len(blob)
        blob += b"\x00" * (n * ptr)
        iat = len(blob)
        blob += b"\x00" * (n * ptr)
        thunks.append((ilt, iat))
    iat_start = thunks[0][1] if thunks else 0
    fmt = "<Q" if ptr == 8 else "<I"
    for i, dll in enumerate(dlls):
        ilt, iat = thunks[i]
        for j, fn in enumerate(imports[dll]):
            if len(blob) % 2:
                blob.append(0)
            hn = va + len(blob)
            blob += struct.pack("<H", 0) + fn.encode() + b"\x00"
            struct.pack_into(fmt, blob, ilt + j * ptr, hn)
            struct.pack_into(fmt, blob, iat + j * ptr, hn)
        name = va + len(blob)
        blob += dll.encode() + b"\x00"
        struct.pack_into("<IIIII", blob, i * 20, va + ilt, 0, 0, name, va + iat)
    return bytes(blob), desc_size, va + iat_start


def _dotnet(va: int, assembly: str, strings: list[str], user_strings: list[str],
            resource: bytes = b"") -> tuple[bytes, int, int, int, int]:
    """COR20 header + a small but well-formed metadata root (Module + TypeDef +
    MethodDef rows, #Strings / #US / #GUID / #Blob heaps) at ``va``.
    Returns (bytes, clr header size, metadata rva, resources rva, resources size)."""
    st = bytearray(b"\x00")

    def sidx(s: str) -> int:
        i = len(st)
        st.extend(s.encode() + b"\x00")
        return i

    module_type = sidx("<Module>")
    mod_name = sidx(assembly)
    ns = sidx(assembly.rsplit(".", 1)[0])
    type_name = sidx("Program")
    meth = sidx("Main")
    for s in strings:
        sidx(s)
    while len(st) % 4:
        st.append(0)
    us = bytearray(b"\x00")
    for s in user_strings:
        b = s.encode("utf-16-le") + b"\x00"
        us += bytes([len(b)]) + b if len(b) < 0x80 else struct.pack(">H", 0x8000 | len(b)) + b
    while len(us) % 4:
        us.append(0)
    guid = bytes(range(0x30, 0x40))
    blob = b"\x00\x03\x00\x00\x01"                       # empty + static method sig "void()"
    # #~ : Module(0x00), TypeDef(0x02), MethodDef(0x06), small heaps (2-byte indexes)
    valid = (1 << 0x00) | (1 << 0x02) | (1 << 0x06)
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0) + struct.pack("<III", 1, 2, 1)
    tables += struct.pack("<HHHHH", 0, mod_name, 1, 0, 0)                     # Module
    tables += struct.pack("<IHHHHH", 0, module_type, 0, 0, 1, 1)              # TypeDef <Module>
    tables += struct.pack("<IHHHHH", 0x00100001, type_name, ns, 0, 1, 1)      # TypeDef Program
    tables += struct.pack("<IHHHHH", va + 0x50, 0, 0x0096, meth, 1, 1)     # MethodDef (RVA → IL)
    while len(tables) % 4:
        tables += b"\x00"
    version = b"v4.0.30319\x00\x00"
    streams = [(b"#~", tables), (b"#Strings", bytes(st)), (b"#US", bytes(us)),
               (b"#GUID", guid), (b"#Blob", blob.ljust(_al(len(blob), 4), b"\x00"))]
    hdr_len = 16 + len(version) + 4 + sum(8 + _al(len(n) + 1, 4) for n, _ in streams)
    root = bytearray(b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, len(streams)))
    off = hdr_len
    for name, data in streams:
        root += struct.pack("<II", off, len(data)) + name + b"\x00" * (_al(len(name) + 1, 4) - len(name))
        off += len(data)
    for _, data in streams:
        root += data
    il = b"\x2a"                                           # IL: ret
    out = bytearray(b"\x00" * 72)                          # COR20 header
    out += b"\x00" * (0x50 - len(out)) + bytes([0x06 | (len(il) << 2)]) + il   # tiny IL method at +0x50
    while len(out) % 4:
        out.append(0)
    md_rva = va + len(out)
    out += root
    res_rva = res_size = 0
    if resource:
        while len(out) % 8:
            out.append(0)
        res_rva, res_size = va + len(out), 4 + len(resource)
        out += struct.pack("<I", len(resource)) + resource
    struct.pack_into("<IHHIIIIIIIIIIIIIIIIII", out, 0, 72, 2, 5, md_rva, len(root), 1, 0x06000001,
                     res_rva, res_size, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return bytes(out), 72, md_rva, res_rva, res_size



def _rol(v: int, n: int) -> int:
    n %= 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def rich_header(dos: bytes, entries: list[tuple[int, int, int]]) -> bytes:
    """A Rich header (MSVC toolchain stamp) for a DOS header+stub ``dos``:
    ``entries`` are (product id, build, count)."""
    start = len(dos)
    csum = start
    for i, b in enumerate(dos):
        if 0x3C <= i < 0x40:
            continue
        csum = (csum + _rol(b, i)) & 0xFFFFFFFF
    for pid, build, cnt in entries:
        csum = (csum + _rol((pid << 16) | build, cnt)) & 0xFFFFFFFF
    out = struct.pack("<IIII", 0x536E6144 ^ csum, csum, csum, csum)
    for pid, build, cnt in entries:
        out += struct.pack("<II", ((pid << 16) | build) ^ csum, cnt ^ csum)
    return out + b"Rich" + struct.pack("<I", csum)


MSVC_RICH = [(0x0104, 30148, 12), (0x0105, 30148, 22), (0x0103, 30148, 9), (0x0093, 30795, 7),
             (0x0001, 0, 143), (0x0102, 30148, 1), (0x0101, 30148, 1)]


def pe_checksum(data: bytes, off: int) -> int:
    """The PE header checksum (as IMAGEHLP computes it); ``off`` = checksum field."""
    d = bytearray(data)
    d[off:off + 4] = b"\x00\x00\x00\x00"
    if len(d) % 4:
        d += b"\x00" * (4 - len(d) % 4)
    c = 0
    for (w,) in struct.iter_unpack("<I", bytes(d)):
        c += w
        c = (c & 0xFFFFFFFF) + (c >> 32)
    c = (c & 0xFFFF) + (c >> 16)
    c = c + (c >> 16)
    return (c & 0xFFFF) + len(data)


def _version_info(fields: dict[str, str], ver: tuple[int, int, int, int]) -> bytes:
    """VS_VERSIONINFO with a StringFileInfo (es-ES, Unicode) and VarFileInfo."""
    def node(key: str, value: bytes, children: list[bytes], text: bool) -> bytes:
        k = key.encode("utf-16-le") + b"\x00\x00"
        hdr_len = 6 + len(k)
        pad = b"\x00" * (_al(hdr_len, 4) - hdr_len)
        body = value + b"\x00" * (_al(len(value), 4) - len(value))
        for c in children:
            body += c + b"\x00" * (_al(len(c), 4) - len(c))
        vlen = len(value) // 2 if text else len(value)
        total = hdr_len + len(pad) + body.__len__()
        return struct.pack("<HHH", total, vlen, 1 if text else 0) + k + pad + body
    strs = [node(k, v.encode("utf-16-le") + b"\x00\x00", [], True) for k, v in fields.items()]
    table = node("0C0A04B0", b"", strs, True)
    sfi = node("StringFileInfo", b"", [table], True)
    var = node("Translation", struct.pack("<HH", 0x0C0A, 1200), [], False)
    vfi = node("VarFileInfo", b"", [var], True)
    a, b, c, d = ver
    ffi = struct.pack("<13I", 0xFEEF04BD, 0x10000, (a << 16) | b, (c << 16) | d, (a << 16) | b, (c << 16) | d,
                      0x3F, 0, 0x40004, 1, 0, 0, 0)
    return node("VS_VERSION_INFO", ffi, [sfi, vfi], False)


MANIFEST = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
            b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
            b'<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>'
            b'<requestedExecutionLevel level="asInvoker" uiAccess="false"/>'
            b'</requestedPrivileges></security></trustInfo></assembly>\r\n')


def _rsrc(va: int, items: list[tuple[int, bytes]]) -> bytes:
    """Resource tree type → id 1 → lang 0x0C0A, one entry per (type, data)."""
    n = len(items)
    dir_hdr = lambda cnt: struct.pack("<IIHHHH", 0, 0, 0, 0, 0, cnt)  # noqa: E731
    root = dir_hdr(n)
    off = 16 + 8 * n
    name_dirs, lang_dirs, entries = b"", b"", b""
    name_base = off
    lang_base = name_base + n * 24
    entry_base = lang_base + n * 24
    data_base = entry_base + n * 16
    data_blob = b""
    for i, (typ, data) in enumerate(items):
        root += struct.pack("<II", typ, 0x80000000 | (name_base + 24 * i))
        name_dirs += dir_hdr(1) + struct.pack("<II", 1, 0x80000000 | (lang_base + 24 * i))
        lang_dirs += dir_hdr(1) + struct.pack("<II", 0x0C0A, entry_base + 16 * i)
        while len(data_blob) % 8:
            data_blob += b"\x00"
        entries += struct.pack("<IIII", va + data_base + len(data_blob), len(data), 0, 0)
        data_blob += data
    return root + name_dirs + lang_dirs + entries + data_blob


def pe(*, bits: int = 32, dll: bool = False, gui: bool = True,
       imports: dict[str, list[str]] | None = None, exports: list[str] | None = None,
       sections: list[tuple[str, bytes, int]] | None = None, strings: list[str] | None = None,
       wstrings: list[str] | None = None, dotnet: dict | None = None, overlay: bytes = b"",
       timestamp: int = 0x6713A2C0, code: bytes = b"\xc3", text_name: str = ".text",
       text_flags: int = 0x60000020, pdb: str | None = None, version: dict[str, str] | None = None,
       manifest: bool = False, rich: bool = False, reloc: bool = False, checksum: bool = False) -> bytes:
    """An inert PE32 / PE32+. ``sections`` are extra (name, data, characteristics).
    ``pdb`` / ``version`` / ``manifest`` / ``rich`` / ``reloc`` / ``checksum`` add
    what a normal MSVC build carries (debug directory, version resource, Rich
    header, relocations, correct header checksum)."""
    ptr = 8 if bits == 64 else 4
    imports = dict(imports or {})
    if dotnet:
        imports = {"mscoree.dll": ["_CorDllMain" if dll else "_CorExeMain"]}
    secs: list[list] = []                                   # [name, va, data, flags]
    va = SA
    text = bytearray(code)
    clr = None
    if dotnet:
        text = bytearray(b"\xff\x25\x00\x20\x40\x00")       # jmp [_CorExeMain] stub, never run here
        while len(text) % 16:
            text.append(0)
        blob, clr_size, _md, _r, _rs = _dotnet(va + len(text), **dotnet)
        clr = (va + len(text), clr_size)
        text += blob
    secs.append([text_name, va, bytes(text), text_flags])
    va = _al(va + max(len(text), 1), SA)
    rdata = _strz(*(strings or [])) + _wstrz(*(wstrings or []))
    dbg_dir = (0, 0)
    dbg_fix = None
    if pdb:
        rdata += b"\x00" * (-len(rdata) % 4)
        dbg_off = len(rdata)
        rdata += b"\x00" * 28
        rsds = b"RSDS" + bytes(range(0x41, 0x51)) + struct.pack("<I", 1) + pdb.encode() + b"\x00"
        rsds_off = len(rdata)
        rdata += rsds
        dbg_dir = (va + dbg_off, 28)
        dbg_fix = (dbg_off, rsds_off, len(rsds))
    exp_dir = (0, 0)
    if exports:
        exp = bytearray(40)
        name_rva = va + len(rdata) + len(exp)
        dllname = b"module.dll\x00"
        exp += dllname
        fn_rvas = []
        for e in exports:
            fn_rvas.append(va + len(rdata) + len(exp))
            exp += e.encode() + b"\x00"
        while len(exp) % 4:
            exp.append(0)
        funcs = va + len(rdata) + len(exp)
        exp += struct.pack(f"<{len(exports)}I", *([SA] * len(exports)))
        names = va + len(rdata) + len(exp)
        exp += struct.pack(f"<{len(exports)}I", *fn_rvas)
        ords = va + len(rdata) + len(exp)
        exp += struct.pack(f"<{len(exports)}H", *range(len(exports)))
        struct.pack_into("<IIHHIIIIIII", exp, 0, 0, timestamp, 0, 0, name_rva, 1, len(exports),
                         len(exports), funcs, names, ords)
        exp_dir = (va + len(rdata), len(exp))
        rdata += bytes(exp)
    rdata_idx = None
    if rdata:
        rdata_idx = len(secs)
        secs.append([".rdata", va, rdata, 0x40000040])
        va = _al(va + len(rdata), SA)
    imp_dir = iat = (0, 0)
    if imports:
        blob, dsize, iat_rva = _imports(va, imports, ptr)
        secs.append([".idata", va, blob, 0xC0000040])
        imp_dir = (va, dsize)
        n_thunks = sum(len(v) + 1 for v in imports.values())
        iat = (iat_rva, n_thunks * ptr)
        va = _al(va + len(blob), SA)
    for name, data, flags in sections or []:
        secs.append([name, va, data, flags])
        va = _al(va + max(len(data), 1), SA)
    rsrc_dir = (0, 0)
    res_items = []
    if version:
        res_items.append((16, _version_info(version, (1, 4, 2, 0))))
    if manifest:
        res_items.append((24, MANIFEST))
    if res_items:
        blob = _rsrc(va, res_items)
        secs.append([".rsrc", va, blob, 0x40000040])
        rsrc_dir = (va, len(blob))
        va = _al(va + len(blob), SA)
    reloc_dir = (0, 0)
    if reloc:
        blob = struct.pack("<II", SA, 12) + struct.pack("<HH", (0xA if bits == 64 else 3) << 12 | 0x10, 0)
        secs.append([".reloc", va, blob, 0x42000040])
        reloc_dir = (va, len(blob))
        va = _al(va + len(blob), SA)
    size_image = va
    e_lfanew = 0x80
    opt_size = 240 if bits == 64 else 224
    size_headers = _al(e_lfanew + 4 + 20 + opt_size + len(secs) * 40, FA)
    raw = size_headers
    for s in secs:
        s.append(raw)
        raw += _al(len(s[2]), FA)
    machine = 0x8664 if bits == 64 else 0x14C
    chars = 0x0002 | (0x0020 if bits == 64 else 0x0100) | (0x2000 if dll else 0)
    dos = (b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8" + b"\x00" * 7 + b"\x40"
           + b"\x00" * 35 + struct.pack("<I", e_lfanew))
    dos += (b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
            b"This program cannot be run in DOS mode.\r\r\n$").ljust(0x80 - len(dos), b"\x00")
    if rich:
        dos += rich_header(dos, MSVC_RICH)
        e_lfanew = _al(len(dos) + 8, 8)
        dos = dos[:0x3C] + struct.pack("<I", e_lfanew) + dos[0x40:]
        size_headers = _al(e_lfanew + 4 + 20 + opt_size + len(secs) * 40, FA)
        if size_headers != secs[0][4]:
            raise ValueError("Rich header pushed the headers past the first section")
    dos = dos.ljust(e_lfanew, b"\x00")
    coff = struct.pack("<HHIIIHH", machine, len(secs), timestamp, 0, 0, opt_size, chars)
    code_size = sum(_al(len(s[2]), FA) for s in secs if s[3] & 0x20)
    init_size = sum(_al(len(s[2]), FA) for s in secs if not s[3] & 0x20)
    ep = secs[0][1]
    if bits == 64:
        opt = struct.pack("<HBBIIIII", 0x20B, 14, 36, code_size, init_size, 0, ep, secs[0][1])
        opt += struct.pack("<Q", 0x180000000 if dll else 0x140000000)
    else:
        opt = struct.pack("<HBBIIIIII", 0x10B, 14, 36, code_size, init_size, 0, ep, secs[0][1],
                          secs[1][1] if len(secs) > 1 else 0)
        opt += struct.pack("<I", 0x10000000 if dll else 0x400000)
    opt += struct.pack("<IIHHHHHHIIIIHH", SA, FA, 6, 0, 0, 0, 6, 0, 0, size_image, size_headers, 0,
                       2 if gui else 3, 0x8160 if bits == 64 else 0x8140)
    stack = (0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<QQQQ" if bits == 64 else "<IIII", *stack)
    dirs = [(0, 0)] * 16
    dirs[0], dirs[1], dirs[12] = exp_dir, imp_dir, iat
    dirs[2], dirs[5], dirs[6] = rsrc_dir, reloc_dir, dbg_dir
    if clr:
        dirs[14] = clr
    opt += struct.pack("<II", 0, 16) + b"".join(struct.pack("<II", *d) for d in dirs)
    assert len(opt) == opt_size, (len(opt), opt_size)
    sectbl = b""
    for name, sva, data, flags, rawp in secs:
        sectbl += name.encode()[:8].ljust(8, b"\x00") + struct.pack("<IIII", len(data), sva, _al(len(data), FA), rawp)
        sectbl += struct.pack("<IIHHI", 0, 0, 0, 0, flags)
    body = (dos + b"PE\x00\x00" + coff + opt + sectbl).ljust(size_headers, b"\x00")
    if dbg_fix and rdata_idx is not None:
        dbg_off, rsds_off, rsds_len = dbg_fix
        sec = secs[rdata_idx]
        d = bytearray(sec[2])
        d[dbg_off:dbg_off + 28] = struct.pack("<IIHHIIII", 0, timestamp, 0, 0, 2, rsds_len,
                                              sec[1] + rsds_off, sec[4] + rsds_off)
        sec[2] = bytes(d)
    for name, sva, data, flags, rawp in secs:
        body = body.ljust(rawp, b"\x00") + data.ljust(_al(len(data), FA), b"\x00")
    body += overlay
    if checksum:
        off = e_lfanew + 4 + 20 + 64
        body = body[:off] + struct.pack("<I", pe_checksum(body, off)) + body[off + 4:]
    return body


def noise(n: int, seed: int) -> bytes:
    """High-entropy bytes (stand-in for an encrypted / compressed payload)."""
    rnd = random.Random(seed)
    return bytes(rnd.randrange(256) for _ in range(n))


# --- ELF ---------------------------------------------------------------------------

def elf(*, strings: list[str], code: bytes = b"\xc3", interp: str | None = None,
        needed: list[str] | None = None, comment: str = "GCC: (Debian 12.2.0-14) 12.2.0",
        extra: list[tuple[str, bytes]] | None = None, shared: bool = False, soname: str | None = None,
        machine: int = 0x3E) -> bytes:
    """An inert ELF64 executable (or ``shared`` object): one PT_LOAD, entry =
    ``ret``; sections .interp / .text / .rodata / .dynstr / .dynamic /
    .comment / extra / .shstrtab. ``needed`` libraries become real DT_NEEDED
    entries (PT_DYNAMIC), so LIEF / readelf list them like a real binary."""
    base = 0 if shared else 0x400000
    secs: list[list] = []                                   # name, data, type, flags, link, entsize
    if interp:
        secs.append([".interp", interp.encode() + b"\x00", 1, 2, 0, 0])
    secs.append([".text", code, 1, 6, 0, 0])
    secs.append([".rodata", _strz(*strings), 1, 2, 0, 0])
    dyn_names = list(needed or []) + ([soname] if soname else [])
    if dyn_names:
        dynstr = b"\x00"
        offs = {}
        for n in dyn_names:
            offs[n] = len(dynstr)
            dynstr += n.encode() + b"\x00"
        secs.append([".dynstr", dynstr, 3, 2, 0, 0])
        n_dyn = len(needed or []) + (1 if soname else 0) + 3
        secs.append([".dynamic", b"\x00" * (16 * n_dyn), 6, 3, len(secs), 16])   # link → .dynstr index
    secs.append([".comment", comment.encode() + b"\x00", 1, 0x30, 0, 0])
    for name, data in extra or []:
        secs.append([name, data, 1, 2, 0, 0])
    shstr = b"\x00"
    name_off = []
    for sec in secs + [[".shstrtab"]]:
        name_off.append(len(shstr))
        shstr += sec[0].encode() + b"\x00"
    names = [x[0] for x in secs]
    phnum = 2 if dyn_names else 1
    phoff = 64
    off = phoff + 56 * phnum
    layout = []
    for sec in secs:
        off = _al(off, 16)
        layout.append(off)
        off += len(sec[1])
    if dyn_names:
        ds, dy = names.index(".dynstr"), names.index(".dynamic")
        ents = [(1, offs[n]) for n in needed or []]
        if soname:
            ents.append((14, offs[soname]))
        ents += [(5, base + layout[ds]), (10, len(secs[ds][1])), (0, 0)]
        secs[dy][1] = b"".join(struct.pack("<qQ", t, v) for t, v in ents)
    shstr_off = off
    off += len(shstr)
    shoff = _al(off, 8)
    text_off = layout[names.index(".text")]
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack("<HHIQQQIHHHHHH", 3 if shared else 2, machine, 1, base + text_off, phoff, shoff, 0, 64, 56,
                        phnum, 64, len(secs) + 2, len(secs) + 1)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, shoff, shoff, 0x1000)
    if dyn_names:
        dy = names.index(".dynamic")
        phdr += struct.pack("<IIQQQQQQ", 2, 6, layout[dy], base + layout[dy], base + layout[dy],
                            len(secs[dy][1]), len(secs[dy][1]), 8)
    body = bytearray(ehdr + phdr)
    for sec, o in zip(secs, layout):
        body = body.ljust(o, b"\x00") + sec[1]
    body += shstr
    body = body.ljust(shoff, b"\x00")
    body += b"\x00" * 64                                   # SHN_UNDEF
    for i, (sec, o) in enumerate(zip(secs, layout)):
        name, data, typ, flags, link, entsize = sec
        body += struct.pack("<IIQQQQIIQQ", name_off[i], typ, flags, base + o if flags & 2 else 0, o,
                            len(data), link, 0, 16 if name == ".text" else 8 if typ == 6 else 1, entsize)
    body += struct.pack("<IIQQQQIIQQ", name_off[-1], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(body)


# --- APK ---------------------------------------------------------------------------

def apk(*, package: str, permissions: list[str], dex_strings: list[str], app_name: str,
        extra: dict[str, bytes | str] | None = None, store: bool = False) -> bytes:
    """An inert Android package: stub binary-XML manifest (package + permissions
    as UTF-16 strings), stub classes.dex (header magic + strings), resources.
    ``store`` keeps every entry uncompressed (as packers / droppers often do,
    so the payload can be mapped directly). Not installable."""
    manifest = (b"\x03\x00\x08\x00" + b"\x00" * 28
                + " ".join([package] + permissions).encode("utf-16-le"))
    dex = b"dex\n035\x00" + b"\x00" * 104 + _strz(*dex_strings)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED if store else zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)
        z.writestr("res/values/strings.xml", f'<resources><string name="app_name">{app_name}</string></resources>')
        for name, data in (extra or {}).items():
            z.writestr(name, data)
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n")
    return buf.getvalue()
