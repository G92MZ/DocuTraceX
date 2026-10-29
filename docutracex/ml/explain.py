"""Plain-language explanation of the EMBER2024 features that drove a score.

For each top feature (``{block, feature, value, contribution, matches}``) this
adds:
  plain     what the feature means for THIS file, in words
            ("not a DLL", "no debug directory", "compiled 2019-07-22 02:46 UTC")
  evidence  the concrete data behind it (the strings that matched, the section,
            the import…), at most a few items
  at        {offset, length, label} — where it is in the file, for the Hex tab

Runs inside the ML child process, where the file's bytes and the raw EMBER
features are at hand. Best effort: a feature it cannot place keeps its plain
text only.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any

# --- vocabulary -----------------------------------------------------------------------

_CHARACTERISTICS = {
    "RELOCS_STRIPPED": "relocations stripped (fixed load address)",
    "EXECUTABLE_IMAGE": "marked as an executable image",
    "LINE_NUMS_STRIPPED": "line numbers stripped",
    "LOCAL_SYMS_STRIPPED": "local symbols stripped",
    "AGGRESIVE_WS_TRIM": "aggressive working-set trim (obsolete flag)",
    "LARGE_ADDRESS_AWARE": "large-address aware (> 2 GB)",
    "BYTES_REVERSED_LO": "bytes-reversed flag (obsolete)",
    "32BIT_MACHINE": "32-bit machine flag",
    "DEBUG_STRIPPED": "debug information stripped",
    "REMOVABLE_RUN_FROM_SWAP": "copy to swap when run from removable media",
    "NET_RUN_FROM_SWAP": "copy to swap when run from the network",
    "SYSTEM": "a system file (driver)",
    "DLL": "a DLL",
    "UP_SYSTEM_ONLY": "uniprocessor-only flag",
    "BYTES_REVERSED_HI": "bytes-reversed flag (obsolete)",
    "16BIT_MACHINE": "16-bit machine flag",
}
_DLL_CHARACTERISTICS = {
    "HIGH_ENTROPY_VA": "high-entropy ASLR (64-bit)", "DYNAMIC_BASE": "ASLR (dynamic base)",
    "FORCE_INTEGRITY": "forced signature check", "NX_COMPAT": "DEP (NX compatible)",
    "NO_ISOLATION": "no isolation (no manifest)", "NO_SEH": "no structured exception handling",
    "NO_BIND": "do not bind", "APPCONTAINER": "AppContainer", "WDM_DRIVER": "WDM driver",
    "GUARD_CF": "Control Flow Guard", "TERMINAL_SERVER_AWARE": "terminal-server aware",
}
_DIRECTORY = {
    "EXPORT": "export directory", "IMPORT": "import directory", "RESOURCE": "resources",
    "EXCEPTION": "exception table", "SECURITY": "Authenticode signature", "BASERELOC": "relocations",
    "DEBUG": "debug directory (PDB / build info)", "COPYRIGHT": "architecture (copyright) directory",
    "GLOBALPTR": "global pointer", "TLS": "TLS (thread-local storage, callbacks run before main)",
    "LOAD_CONFIG": "load configuration (CFG, SafeSEH…)", "BOUND_IMPORT": "bound imports",
    "IAT": "import address table", "DELAY_IMPORT": "delay-load imports", "COM_DESCRIPTOR": ".NET (CLR) header",
    "RESERVED": "reserved directory",
}
_STRING_PATTERNS = {
    "dos_msg": "the DOS-stub message ('This program cannot be run in DOS mode')",
    "url": "URLs", "http://": "'http://' strings", "https://": "'https://' strings", "http": "'http' strings",
    "ipv4_addr": "IPv4 addresses", "ipv6_addr": "IPv6 addresses", "mac_addr": "MAC addresses",
    "email_addr": "e-mail addresses", "file_path": "file paths", "registry_key": "registry keys",
    "btc_wallet": "Bitcoin wallet addresses", "useragent": "browser user-agent strings", "base64": "base64 text",
    "base64string": "long base64 strings", "powershell": "'powershell'", "Invoke-Expression": "'Invoke-Expression'",
    "Invoke-Command": "'Invoke-Command'", "Start-process": "'Start-Process'", "<script": "'<script' tags",
    "/EmbeddedFile": "PDF embedded files", "/FlateDecode": "PDF compressed streams", "/URI": "PDF links (/URI)",
    "javascript": "'javascript'", ".click(": "'.click(' calls", "onlick": "'onclick' handlers",
}
_DOS_MEMBERS = {"e_magic": 0, "e_cblp": 2, "e_cp": 4, "e_crlc": 6, "e_cparhdr": 8, "e_minalloc": 10,
                "e_maxalloc": 12, "e_ss": 14, "e_sp": 16, "e_csum": 18, "e_ip": 20, "e_cs": 22, "e_lfarlc": 24,
                "e_ovno": 26, "e_oemid": 36, "e_oeminfo": 38, "e_lfanew": 60}
# offset inside the COFF header / optional header, size (PE32, PE32+ where they differ)
_COFF = {"machine": (0, 2), "number of sections": (2, 2), "COFF timestamp": (4, 4), "pointer to symbol table": (8, 4),
         "number of symbols": (12, 4), "size of optional header": (16, 2)}
_OPT = {"linker version (major)": (2, 1, 2, 1), "linker version (minor)": (3, 1, 3, 1),
        "size of code": (4, 4, 4, 4), "size of initialized data": (8, 4, 8, 4),
        "size of uninitialized data": (12, 4, 12, 4), "entry point address": (16, 4, 16, 4),
        "base of code": (20, 4, 20, 4), "image base": (28, 4, 24, 8), "section alignment": (32, 4, 32, 4),
        "OS version (major)": (40, 2, 40, 2), "OS version (minor)": (42, 2, 42, 2),
        "image version (major)": (44, 2, 44, 2), "image version (minor)": (46, 2, 46, 2),
        "subsystem version (major)": (48, 2, 48, 2), "subsystem version (minor)": (50, 2, 50, 2),
        "size of image": (56, 4, 56, 4), "size of headers": (60, 4, 60, 4), "header checksum": (64, 4, 64, 4),
        "subsystem": (68, 2, 68, 2), "stack reserve": (72, 4, 72, 8), "stack commit": (76, 4, 80, 8),
        "heap reserve": (80, 4, 88, 8), "heap commit": (84, 4, 96, 8), "number of RVAs and sizes": (92, 4, 108, 4)}
_SUBSYSTEM = {1: "native (driver)", 2: "Windows GUI", 3: "Windows console", 9: "Windows CE", 10: "EFI application",
              14: "Xbox", 16: "boot application"}
_MACHINE = {0x14C: "x86 (32-bit)", 0x8664: "x64", 0xAA64: "ARM64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2"}


def _num(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else f"{v:.4g}"


def _yes(v: float) -> bool:
    return float(v) >= 0.5


class _Ctx:
    """Lazy PE layout of the file: header offsets, sections, overlay."""

    def __init__(self, data: bytes, raw: dict[str, Any]) -> None:
        self.data, self.raw = data, raw
        self._pe: Any = None
        self._done = False
        self._strings: list[tuple[int, str]] | None = None

    @property
    def pe(self) -> Any:
        if not self._done:
            self._done = True
            if self.data[:2] == b"MZ":
                try:
                    import pefile
                    self._pe = pefile.PE(data=self.data, fast_load=True)
                except Exception:  # noqa: BLE001
                    self._pe = None
        return self._pe

    def lfanew(self) -> int | None:
        if len(self.data) < 64 or self.data[:2] != b"MZ":
            return None
        v = int.from_bytes(self.data[60:64], "little")
        return v if 0 < v < len(self.data) - 24 else None

    def pe32plus(self) -> bool:
        pe = self.pe
        return bool(pe and pe.OPTIONAL_HEADER.Magic == 0x20B)

    def strings(self) -> list[tuple[int, str]]:
        """(offset, text) of printable strings (EMBER: >= 5 chars)."""
        if self._strings is None:
            self._strings = [(m.start(), m.group().decode("ascii", "replace"))
                             for m in re.finditer(rb"[\x20-\x7f]{5,}", self.data[:16 * 1024 * 1024])]
        return self._strings

    def section(self, name: str) -> dict[str, Any] | None:
        pe = self.pe
        if not pe:
            return None
        for s in pe.sections:
            if s.Name.rstrip(b"\x00").decode("latin-1", "replace").lower() == name.lower():   # EMBER lower-cases
                return {"offset": int(s.PointerToRawData), "length": int(s.SizeOfRawData),
                        "vsize": int(s.Misc_VirtualSize), "chars": int(s.Characteristics)}
        return None

    def find(self, needle: bytes) -> int | None:
        i = self.data.find(needle)
        return i if i >= 0 else None


def _at(offset: int | None, length: int, label: str) -> dict[str, Any] | None:
    if offset is None or offset < 0:
        return None
    return {"offset": int(offset), "length": max(1, int(length)), "label": label}


def _strings_pattern(ctx: _Ctx, pat: str, value: float) -> tuple[str, list[str], dict | None]:
    what = _STRING_PATTERNS.get(pat, f"'{pat}'")
    n = int(value)
    plain = (f"{n} string(s) contain {what}" if n else f"no string contains {what}")
    ev, at = [], None
    if n:
        try:
            rx = _regex(pat)                              # the same regexes the model counted with
        except Exception:  # noqa: BLE001
            rx = None
        if rx is not None:
            for off, s in ctx.strings():
                if rx.search(s):
                    ev.append(s[:120])
                    if at is None:
                        at = _at(off, len(s), f"string matching '{pat}'")
                    if len(ev) >= 3:
                        break
    return plain, ev, at


_RX_CACHE: dict[str, Any] = {}


def _regex(pat: str) -> Any:
    if not _RX_CACHE:
        from .ember_features import PEFeatureExtractor
        for fe in PEFeatureExtractor().features:
            if fe.name == "strings":
                _RX_CACHE.update(fe._regexes)
    return _RX_CACHE.get(pat)


def explain_feature(t: dict[str, Any], ctx: _Ctx) -> dict[str, Any]:
    """{plain, evidence, at} for one top feature."""
    blk, name, v = t.get("block", ""), t.get("feature", ""), float(t.get("value") or 0)
    matches = list(t.get("matches") or [])
    if re.search(r"#\d+$", name):
        v = abs(v)            # hashed features carry the hash's sign, not the data's
    plain, ev, at = name, matches[:3], None
    lf = ctx.lfanew()

    if blk == "general":
        plain = {"file size": f"file size {_num(v)} bytes", "file entropy": f"whole-file entropy {v:.2f} of 8",
                 "is PE": "a PE file" if _yes(v) else "not a PE file"}.get(name, f"{name} = 0x{int(v):02x}")
    elif blk == "byte histogram":
        m = re.search(r"0x([0-9a-f]{2})", name)
        plain = f"byte 0x{m.group(1)} makes up {v * 100:.2f}% of the file" if m else name
    elif blk == "byte entropy":
        plain = ("how much of the file is in this mix of local entropy and byte values "
                 f"(sliding windows; {v * 100:.2f}% here)")
    elif blk == "strings":
        if name.startswith("strings matching '"):
            pat = name[len("strings matching '"):-1]
            plain, ev, at = _strings_pattern(ctx, pat, v)
        elif name == "number of strings":
            plain = f"{_num(v)} printable strings (5+ characters)"
        elif name == "average string length":
            plain = f"average string length {v:.1f} characters"
        elif name == "printable chars":
            plain = f"{_num(v)} printable characters in strings"
        elif name == "string entropy":
            plain = f"character variety of the strings: entropy {v:.2f}"
        elif name.startswith("printable char"):
            ch = name.split("'")[1] if "'" in name else "?"
            plain = f"character {ch!r} is {v * 100:.2f}% of the string text"
    elif blk == "header":
        if name.startswith("characteristic "):
            key = name.split(" ", 1)[1]
            desc = _CHARACTERISTICS.get(key, key)
            plain = (f"is {desc}" if key in ("DLL", "SYSTEM") else desc) if _yes(v) else \
                    (f"not {desc}" if key in ("DLL", "SYSTEM") else f"not set: {desc}")
            if lf is not None:
                at = _at(lf + 4 + 18, 2, "COFF characteristics")
        elif name.startswith("DLL characteristic "):
            key = name.split(" ", 2)[2]
            desc = _DLL_CHARACTERISTICS.get(key, key)
            plain = f"{desc}: {'enabled' if _yes(v) else 'not enabled'}"
            if lf is not None:
                at = _at(lf + 24 + 70, 2, "DllCharacteristics")
        elif name.startswith("DOS header "):
            mem = name.split(" ", 2)[2]
            plain = f"DOS header field {mem} = {_num(v)}"
            if mem in _DOS_MEMBERS:
                at = _at(_DOS_MEMBERS[mem], 4 if mem == "e_lfanew" else 2, f"DOS header {mem}")
        elif name in _COFF:
            off, size = _COFF[name]
            if name == "COFF timestamp":
                try:
                    plain = ("compiled (COFF timestamp) " + _dt.datetime.fromtimestamp(v, _dt.timezone.utc)
                             .strftime("%Y-%m-%d %H:%M UTC")) if v else "COFF timestamp is zero (wiped)"
                except (OverflowError, OSError, ValueError):
                    plain = f"COFF timestamp {_num(v)} (not a valid date)"
            elif name == "machine":
                plain = f"machine: {_MACHINE.get(int(v), hex(int(v)))}"
            else:
                plain = f"{name}: {_num(v)}"
            if lf is not None:
                at = _at(lf + 4 + off, size, name if name.startswith("COFF") else f"COFF {name}")
        elif name in _OPT:
            o32, s32, o64, s64 = _OPT[name]
            off, size = (o64, s64) if ctx.pe32plus() else (o32, s32)
            if name == "subsystem":
                plain = f"subsystem: {_SUBSYSTEM.get(int(v), _num(v))}"
            elif name == "header checksum":
                plain = "header checksum is zero (not set)" if not v else f"header checksum 0x{int(v):08x}"
            elif name in ("entry point address", "base of code", "image base"):
                plain = f"{name}: 0x{int(v):x}"
            else:
                plain = f"{name}: {_num(v)}"
            if lf is not None:
                at = _at(lf + 24 + off, size, f"optional header {name}")
    elif blk == "data directories":
        m = re.match(r"(\w+) (size|address)$", name)
        if m:
            key, what = m.groups()
            desc = _DIRECTORY.get(key, key)
            plain = (f"no {desc}" if not v else
                     (f"{desc}: {_num(v)} bytes" if what == "size" else f"{desc} at RVA 0x{int(v):x}"))
            idx = list(_DIRECTORY).index(key) if key in _DIRECTORY else None
            if lf is not None and idx is not None:
                base = lf + 24 + (112 if ctx.pe32plus() else 96)
                at = _at(base + 8 * idx, 8, f"data directory {key}")
        elif name == "has relocations":
            plain = "has relocations" if _yes(v) else "no relocations"
        elif name == "has dynamic relocations":
            plain = "has dynamic relocations" if _yes(v) else "no dynamic relocations"
    elif blk == "sections":
        m = re.match(r"(section size|section virtual size|section entropy|section characteristic|entry-point section) #\d+",
                     name)
        if m and not matches:
            plain = f"{m.group(1)}: no section of this file falls in this hashed group ({_num(v)})"
        elif m and matches:
            what = m.group(1)
            sec_name = matches[0].split(":", 1)[0]
            sec = ctx.section(sec_name)
            plain = {"section size": f"size of section {sec_name!r}: {_num(v)}",
                     "section virtual size": f"in-memory size of section {sec_name!r}: {_num(v)}",
                     "section entropy": f"entropy of section {sec_name!r}: {v:.2f} of 8",
                     "section characteristic": f"section flags {', '.join(matches)}",
                     "entry-point section": f"the entry point is in section {sec_name!r}"}[what]
            if sec:
                at = _at(sec["offset"], sec["length"], f"section {sec_name}")
        elif name in ("overlay size", "overlay size ratio", "overlay entropy"):
            plain = {"overlay size": f"data appended after the image (overlay): {_num(v)} bytes",
                     "overlay size ratio": f"overlay is {v * 100:.1f}% of the file",
                     "overlay entropy": f"overlay entropy {v:.2f} of 8"}[name] if v else "no overlay"
            pe = ctx.pe
            if pe and v:
                try:
                    start = pe.get_overlay_data_start_offset()
                    if start:
                        at = _at(start, len(ctx.data) - start, "overlay")
                except Exception:  # noqa: BLE001
                    pass
        else:
            plain = f"{name}: {_num(v)}"
    elif blk == "imports":
        if name.startswith(("imported function #", "imported DLL #")):
            plain = ("imports " + ", ".join(matches[:3]) if matches and _yes(v)
                     else "does not import anything in this group" if not _yes(v) else name)
            if matches and _yes(v):
                fn = matches[0].split(":", 1)[-1].encode("latin-1", "replace")
                off = ctx.find(fn + b"\x00")
                at = _at(off, len(fn), f"import {matches[0]}")
        else:
            plain = f"{name}: {_num(v)}"
    elif blk == "exports":
        if name.startswith("export #"):
            plain = ("exports " + ", ".join(matches[:3])) if matches and _yes(v) else "no export in this group"
            if matches and _yes(v):
                fn = matches[0].encode("latin-1", "replace")
                at = _at(ctx.find(fn + b"\x00"), len(fn), f"export {matches[0]}")
        else:
            plain = f"export table size {_num(v)}" if v else "no export table"
    elif blk == "rich header":
        off = ctx.find(b"Rich")
        if name == "number of entries":
            plain = f"Rich header (compiler toolchain stamp) with {_num(v)} entries" if v else "no Rich header"
        else:
            plain = f"Rich header tool {', '.join(matches) or '(this group)'}: {_num(v)}"
        if off is not None and off < 0x400:
            dans = 0x80
            at = _at(dans, off + 8 - dans, "Rich header")
    elif blk == "authenticode":
        plain = {"number of signatures": f"{_num(v)} Authenticode signature(s)" if v else "not signed",
                 "self-signed cert": "self-signed certificate" if _yes(v) else "certificate not self-signed",
                 "no countersigner": "no timestamp countersignature" if _yes(v) else "has a timestamp countersignature",
                 "parse error": "signature could not be parsed" if _yes(v) else "signature parsed",
                 "chain depth": f"certificate chain depth {_num(v)}",
                 "latest signing time": "no signing time" if not v else "signing time present",
                 "empty program name": "signature has no program name" if _yes(v) else "signature names the program",
                 "signing time − compile time": f"signed {_num(v)} s after compilation"}.get(name, name)
        pe = ctx.pe
        if pe:
            try:
                d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
                if d.VirtualAddress and d.Size:
                    at = _at(int(d.VirtualAddress), int(d.Size), "Authenticode signature")
            except Exception:  # noqa: BLE001
                pass
    elif blk == "parse warnings":
        if name == "number of pefile warnings":
            plain = f"{_num(v)} structural oddities found while parsing the PE"
        else:
            plain = ("the PE parser flags: " if _yes(v) else "the PE parser does not flag: ") + \
                    name.replace("pefile warning: ", "")
    return {"plain": plain, "evidence": [e for e in ev if e][:3], "at": at}


def explain_top(top: list[dict[str, Any]], data: bytes, raw: dict[str, Any]) -> None:
    """Add ``plain`` / ``evidence`` / ``at`` to every top feature (in place)."""
    ctx = _Ctx(data, raw)
    for t in top:
        try:
            t.update({k: v for k, v in explain_feature(t, ctx).items() if v not in (None, [], "")})
        except Exception:  # noqa: BLE001 - explanation is best effort
            continue
