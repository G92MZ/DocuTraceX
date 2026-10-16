"""VBA project builder (MS-OVBA), for realistic samples and test fixtures.

Produces the storages/streams of a VBA project from plain module source:
``PROJECT``, ``PROJECTwm``, ``VBA/_VBA_PROJECT``, ``VBA/dir`` and one compressed
stream per module — what Office writes, minus the compiled p-code (the
_VBA_PROJECT version is 0xFFFF, which tells Office to recompile from source).
olevba, mraptor, oledump and ViperMonkey read it like any real project.

    vba_project_bin(modules)          -> vbaProject.bin bytes (OOXML .docm/.xlsm/...)
    vba_storage(modules)              -> dict tree to place under Macros/ (.doc)
                                         or _VBA_PROJECT_CUR/ (.xls)

``hidden=True`` on a module omits it from the PROJECT stream, which hides it
from the VBA editor while it still runs — the EvilClippy trick. ``locked=True``
adds a DPB (password-protected project) line.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cfb import build_cfb


@dataclass
class Module:
    name: str
    code: str
    document: bool = False   # document/class module (ThisDocument, ThisWorkbook...)
    hidden: bool = False     # EvilClippy: not listed in PROJECT (hidden from the VBE)


# --- MS-OVBA compression (2.4.1) ---------------------------------------------------

def _copy_token_params(difference: int) -> tuple[int, int]:
    bit_count = max((difference - 1).bit_length(), 4)
    length_mask = 0xFFFF >> bit_count
    return bit_count, length_mask


def _compress_chunk(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n:
        flag_index = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if pos >= n:
                break
            difference = pos
            # gmzpt
            best_len, best_off = 0, 0
            if difference > 0:
                bit_count, length_mask = _copy_token_params(difference)
                max_len = min(length_mask + 3, n - pos)
                start = max(0, pos - (1 << bit_count))
                for cand in range(pos - 1, start - 1, -1):
                    length = 0
                    while length < max_len and data[cand + length] == data[pos + length]:
                        length += 1
                    if length > best_len:
                        best_len, best_off = length, pos - cand
                        if length == max_len:
                            break
            if best_len >= 3:
                bit_count, _ = _copy_token_params(difference)
                token = ((best_off - 1) << (16 - bit_count)) | (best_len - 3)
                out += struct.pack("<H", token)
                flags |= 1 << bit
                pos += best_len
            else:
                out.append(data[pos])
                pos += 1
        out[flag_index] = flags
    return bytes(out)


def compress(data: bytes) -> bytes:
    """Compress with the MS-OVBA algorithm (signature 0x01 + 4096-byte chunks)."""
    out = bytearray(b"\x01")
    if not data:
        return bytes(out)
    for i in range(0, len(data), 4096):
        chunk = data[i:i + 4096]
        comp = _compress_chunk(chunk)
        if len(comp) <= 4096:
            header = 0xB000 | (len(comp) + 2 - 3)        # flag=1, signature 0b011
            out += struct.pack("<H", header) + comp
        else:                                             # raw chunk: exactly 4096 bytes
            header = 0x3000 | (4096 + 2 - 3)
            out += struct.pack("<H", header) + chunk.ljust(4096, b"\x00")
    return bytes(out)


# --- dir stream (2.3.4.2) -----------------------------------------------------------

def _rec(rid: int, payload: bytes) -> bytes:
    return struct.pack("<HI", rid, len(payload)) + payload


def _dir_stream(project: str, modules: list[Module], codepage: int = 1252) -> bytes:
    enc = f"cp{codepage}"
    d = bytearray()
    d += _rec(0x0001, struct.pack("<I", 0x03))            # PROJECTSYSKIND: 64-bit Windows
    d += _rec(0x0002, struct.pack("<I", 0x0409))          # PROJECTLCID
    d += _rec(0x0014, struct.pack("<I", 0x0409))          # PROJECTLCIDINVOKE
    d += _rec(0x0003, struct.pack("<H", codepage))        # PROJECTCODEPAGE
    d += _rec(0x0004, project.encode(enc))                # PROJECTNAME
    d += _rec(0x0005, b"") + _rec(0x0040, b"")            # PROJECTDOCSTRING (+unicode)
    d += _rec(0x0006, b"") + _rec(0x003D, b"")            # PROJECTHELPFILEPATH (x2)
    d += _rec(0x0007, struct.pack("<I", 0))               # PROJECTHELPCONTEXT
    d += _rec(0x0008, struct.pack("<I", 0))               # PROJECTLIBFLAGS
    d += struct.pack("<HIIH", 0x0009, 4, 1, 0)            # PROJECTVERSION (major 1, minor 0)
    d += _rec(0x000C, b"") + _rec(0x003C, b"")            # PROJECTCONSTANTS (+unicode)
    # REFERENCES: stdole (OLE Automation), as Office always writes.
    libid = b"*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation"
    d += _rec(0x0016, b"stdole") + _rec(0x003E, "stdole".encode("utf-16-le"))
    d += struct.pack("<HII", 0x000D, 4 + len(libid) + 6, len(libid)) + libid + struct.pack("<IH", 0, 0)
    d += _rec(0x000F, struct.pack("<H", len(modules)))   # PROJECTMODULES
    d += _rec(0x0013, struct.pack("<H", 0xFFFF))         # PROJECTCOOKIE
    for m in modules:
        d += _rec(0x0019, m.name.encode(enc))             # MODULENAME
        d += _rec(0x0047, m.name.encode("utf-16-le"))     # MODULENAMEUNICODE
        d += _rec(0x001A, m.name.encode(enc))             # MODULESTREAMNAME
        d += _rec(0x0032, m.name.encode("utf-16-le"))
        d += _rec(0x001C, b"") + _rec(0x0048, b"")        # MODULEDOCSTRING (+unicode)
        d += _rec(0x0031, struct.pack("<I", 0))           # MODULEOFFSET: no p-code
        d += _rec(0x001E, struct.pack("<I", 0))           # MODULEHELPCONTEXT
        d += _rec(0x002C, struct.pack("<H", 0xFFFF))      # MODULECOOKIE
        d += _rec(0x0022 if m.document else 0x0021, b"")  # MODULETYPE
        d += _rec(0x002B, b"")                            # module terminator
    # k: gmzpt
    d += _rec(0x0010, b"")                                # dir terminator
    return compress(bytes(d))


def _module_source(m: Module) -> bytes:
    if m.document:
        attrs = [f'Attribute VB_Name = "{m.name}"', 'Attribute VB_Base = "1Normal.ThisDocument"',
                 "Attribute VB_GlobalNameSpace = False", "Attribute VB_Creatable = False",
                 "Attribute VB_PredeclaredId = True", "Attribute VB_Exposed = True",
                 "Attribute VB_TemplateDerived = True", "Attribute VB_Customizable = True"]
    else:
        attrs = [f'Attribute VB_Name = "{m.name}"']
    text = "\r\n".join(attrs) + "\r\n" + m.code.replace("\r\n", "\n").replace("\n", "\r\n")
    return text.encode("cp1252", "replace")


def _project_stream(project: str, modules: list[Module], locked: bool,
                    host: str = "ThisDocument") -> bytes:
    lines = ['ID="{5B3F6A1D-8C2E-4D7A-9B41-2E6F0C9A7D13}"']
    for m in modules:
        if m.hidden:
            continue
        lines.append(f"Document={m.name}/&H00000000" if m.document else f"Module={m.name}")
    lines += [f'Name="{project}"', 'HelpContextID="0"', 'VersionCompatible32="393222000"',
              'CMG="C2C04BAFD0B4D4B4D4B4D4B4D4"']
    # A password-protected project stores a long encrypted DPB; an open one a short one.
    lines.append('DPB="0E0CD1ECDFE3E0E3E01F20E2C8C7A2B8E7B97C9F8D2B8C7D4E1B0C2D3E4F5A6B7C8D9E"'
                 if locked else 'DPB="1517E7AAEBAAEBAA"')
    lines += ['GC="3E3CDE9FDF9FDF60"', "", "[Host Extender Info]",
              "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000", "",
              "[Workspace]"]
    lines += [f"{m.name}=26, 26, 1062, 609, " for m in modules if not m.hidden]
    return ("\r\n".join(lines) + "\r\n").encode("cp1252")


def _projectwm(modules: list[Module]) -> bytes:
    out = bytearray()
    for m in modules:
        out += m.name.encode("cp1252") + b"\x00" + m.name.encode("utf-16-le") + b"\x00\x00"
    return bytes(out) + b"\x00\x00"


def vba_storage(modules: list[Module], project: str = "Project", locked: bool = False) -> dict:
    """The VBA project as a CFB tree: {PROJECT, PROJECTwm, VBA: {...}}."""
    vba: dict = {
        "_VBA_PROJECT": struct.pack("<HHBH", 0x61CC, 0xFFFF, 0x00, 0x0000),
        "dir": _dir_stream(project, modules),
    }
    for m in modules:
        vba[m.name] = compress(_module_source(m))
    return {"PROJECT": _project_stream(project, modules, locked),
            "PROJECTwm": _projectwm(modules), "VBA": vba}


def vba_project_bin(modules: list[Module], project: str = "Project", locked: bool = False) -> bytes:
    """A complete vbaProject.bin (as stored inside OOXML macro-enabled files)."""
    return build_cfb(vba_storage(modules, project, locked))
