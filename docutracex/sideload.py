"""DLL side-loading shipped in an archive, disk image or folder.

The pattern of Bumblebee, PlugX, QakBot, Latrodectus and many loaders: a
legitimate, signed program travels next to a DLL with the name of a Windows
system library (``version.dll``, ``winhttp.dll``, ``dbghelp.dll``…). Windows
looks in the program's own folder before System32, so the program loads the
attacker's DLL — often a *proxy* that forwards every export to the real library
and runs its payload on load.

Signals, per DLL next to an EXE in the same folder:

* a system library name the EXE imports (or delay-loads) — loaded from there,
  not from System32;
* the EXE carries a signature and the DLL none, or another signer;
* the DLL forwards its exports to the real system library (a proxy DLL);
* the program is one HijackLibs lists as loading that DLL from its own folder
  (``hijacklibs``: the catalogue is downloaded and kept current, ~600 DLLs; it also
  adds vendor DLLs — ``libcurl.dll`` next to the updater that loads it — and says
  where each DLL is expected). Without it, the built-in system names below.

The signer is read from the certificate table as names only (the subject CNs):
the signature is *not* verified here. Pure byte reading: nothing is run.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path, PurePosixPath
from typing import Any

# Windows system libraries that are not KnownDLLs, so an application folder can
# shadow them — the names side-loading uses again and again (HijackLibs and
# public reports). KnownDLLs (kernel32, user32, ntdll, ole32…) always come from
# System32 and are not here.
SYSTEM_DLLS = {
    "version.dll", "winhttp.dll", "wininet.dll", "dbghelp.dll", "dbgcore.dll", "wtsapi32.dll", "uxtheme.dll",
    "cryptbase.dll", "cryptsp.dll", "cryptnet.dll", "dwmapi.dll", "userenv.dll", "profapi.dll", "winmm.dll",
    "msimg32.dll", "iphlpapi.dll", "secur32.dll", "sspicli.dll", "propsys.dll", "edputil.dll", "netapi32.dll",
    "netutils.dll", "srvcli.dll", "wkscli.dll", "mpclient.dll", "dpapi.dll", "oleacc.dll", "mscms.dll",
    "dxgi.dll", "d3d9.dll", "d3d11.dll", "d3d12.dll", "dwrite.dll", "wsock32.dll", "mswsock.dll", "winsta.dll",
    "xmllite.dll", "wldp.dll", "amsi.dll", "rasapi32.dll", "rasman.dll", "rtutils.dll", "samcli.dll", "mpr.dll",
    "ntmarta.dll", "textshaping.dll", "windowscodecs.dll", "wer.dll", "faultrep.dll", "dsrole.dll",
    "logoncli.dll", "cscapi.dll", "apphelp.dll", "dnsapi.dll", "fwpuclnt.dll", "wintrust.dll", "bcrypt.dll",
    "ncrypt.dll", "credui.dll", "dbgeng.dll", "devobj.dll", "hid.dll", "winscard.dll", "wtsapi.dll",
    "activeds.dll", "cabinet.dll", "msacm32.dll", "msvfw32.dll", "avrt.dll", "dinput8.dll", "xinput1_3.dll",
    "xinput1_4.dll", "winsqlite3.dll", "urlmon.dll", "iertutil.dll", "slc.dll", "sppc.dll",
    "dui70.dll", "duser.dll", "mfplat.dll", "msftedit.dll", "vaultcli.dll", "wbemcomn.dll",
    "atl.dll", "feclient.dll", "msi.dll", "wdscore.dll", "ntdsapi.dll", "authz.dll", "tapi32.dll",
    "linkinfo.dll", "ntshrui.dll", "cscui.dll", "fltlib.dll", "powrprof.dll", "umpdc.dll", "winnsi.dll",
}
# Runtimes applications deploy next to themselves by design (Microsoft's app-local
# deployment): only suspicious when the pair does not hold together (signature, proxy).
_APP_LOCAL = re.compile(r"^(?:vcruntime\d+(?:_\d)?|msvcp\d+(?:_\w+)?|msvcr\d+|ucrtbase|api-ms-win-[\w-]+|"
                        r"concrt\d+|vccorlib\d+|mfc\d+\w*|vcomp\d+|d3dcompiler_\d+|xinput1_\d|"
                        r"libcrypto[\w-]*|libssl[\w-]*)\.dll$")
_MAX_PE = 256 * 1024 * 1024
_CN = re.compile(rb"\x06\x03\x55\x04\x03[\x0c\x13\x14\x16\x1e]([\x01-\x7f])")
_CA_LIKE = re.compile(r"\b(?:CA|Root|Authority|Certification|Time ?Stamp\w*|TSA|Timestamping)\b|CA\d*$", re.IGNORECASE)


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


class _PE:
    """The few PE facts side-loading needs, from the headers (no pefile / LIEF)."""

    def __init__(self, data: bytes) -> None:
        self.d = data
        e = _u32(data, 0x3C)
        if data[:2] != b"MZ" or data[e:e + 4] != b"PE\0\0":
            raise ValueError("not a PE")
        nsec, optsz, self.chars = _u16(data, e + 6), _u16(data, e + 20), _u16(data, e + 22)
        opt = e + 24
        magic = _u16(data, opt)
        ddir = opt + (112 if magic == 0x20B else 96)
        ndirs = min(_u32(data, ddir - 4), 16)
        self.dirs = [struct.unpack_from("<II", data, ddir + 8 * i) for i in range(ndirs)]
        self.dirs += [(0, 0)] * (16 - len(self.dirs))
        self.secs = []
        for i in range(min(nsec, 96)):
            s = opt + optsz + 40 * i
            vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
            self.secs.append((va, max(vsize, rsize), raw, rsize))

    @property
    def is_dll(self) -> bool:
        return bool(self.chars & 0x2000)

    def off(self, rva: int) -> int | None:
        for va, size, raw, rsize in self.secs:
            if va <= rva < va + size and rva - va < rsize:
                return raw + rva - va
        return None

    def cstr(self, rva: int, limit: int = 260) -> str:
        o = self.off(rva)
        if o is None:
            return ""
        end = self.d.find(b"\0", o, o + limit)
        return self.d[o:end if end > 0 else o + limit].decode("latin-1")

    def imports(self) -> set[str]:
        """Imported and delay-loaded library names (lower case)."""
        out: set[str] = set()
        rva, _size = self.dirs[1]
        o = self.off(rva) if rva else None
        while o is not None and o + 20 <= len(self.d) and len(out) < 512:
            name = _u32(self.d, o + 12)
            if not name and not _u32(self.d, o):
                break
            if name:
                out.add(self.cstr(name).lower())
            o += 20
        rva, _size = self.dirs[13]
        o = self.off(rva) if rva else None
        while o is not None and o + 32 <= len(self.d) and len(out) < 1024:
            attrs, name = _u32(self.d, o), _u32(self.d, o + 4)
            if not name:
                break
            out.add(self.cstr(name if attrs & 1 else name - self._base()).lower())
            o += 32
        return {n for n in out if n}

    def _base(self) -> int:
        e = _u32(self.d, 0x3C)
        opt = e + 24
        return struct.unpack_from("<Q", self.d, opt + 24)[0] if _u16(self.d, opt) == 0x20B else _u32(self.d, opt + 28)

    def exports(self) -> tuple[list[str], dict[str, str]]:
        """Exported names and the forwarded ones (name → "library.Function")."""
        rva, size = self.dirs[0]
        o = self.off(rva) if rva else None
        if o is None:
            return [], {}
        nfun, nnames, funcs, names, ords = struct.unpack_from("<IIIII", self.d, o + 20)
        fo, no, oo = self.off(funcs), self.off(names), self.off(ords)
        if fo is None or no is None or oo is None:
            return [], {}
        out, fwd = [], {}
        for i in range(min(nnames, 8192)):
            name = self.cstr(_u32(self.d, no + 4 * i), 512)
            idx = _u16(self.d, oo + 2 * i)
            if idx >= nfun:
                continue
            frva = _u32(self.d, fo + 4 * idx)
            out.append(name)
            if rva <= frva < rva + size:
                fwd[name] = self.cstr(frva, 512)
        return out, fwd

    def signers(self) -> list[str] | None:
        """Subject names in the certificate table (None: not signed). Not verified."""
        off, size = self.dirs[4]
        if not off or not size or off + size > len(self.d):
            return None
        blob = self.d[off:off + size]
        names: list[str] = []
        for m in _CN.finditer(blob):
            n = m.group(1)[0]
            raw = blob[m.end():m.end() + n]
            txt = raw.decode("utf-16-be", "replace") if blob[m.start() + 5] == 0x1E else raw.decode("latin-1")
            if txt and txt not in names:
                names.append(txt)
        return names


def _signer(names: list[str] | None) -> set[str]:
    """The publisher names: CNs that are not certificate authorities or timestamping."""
    if not names:
        return set()
    own = {n for n in names if not _CA_LIKE.search(n)}
    return own or set(names)


def _read(path: str | None) -> _PE | None:
    if not path:
        return None
    try:
        p = Path(path)
        if not p.is_file() or p.stat().st_size > _MAX_PE:
            return None
        with p.open("rb") as fh:
            if fh.read(2) != b"MZ":
                return None
        return _PE(p.read_bytes())
    except (OSError, ValueError, struct.error, IndexError):
        return None


def catalogue() -> dict[str, dict[str, Any]]:
    """DLL name → what is known about it: the downloaded HijackLibs catalogue when there
    is one, plus the built-in system names (``source`` says which)."""
    out: dict[str, dict[str, Any]] = {n: {"name": n, "vendor": "Microsoft", "locations": ["%SYSTEM32%"],
                                          "system": True, "hosts": {}, "url": "", "source": "builtin"}
                                      for n in SYSTEM_DLLS}
    try:
        from . import hijacklibs
        for n, rec in (hijacklibs.dlls() or {}).items():
            out[n] = {**rec, "system": rec["system"] or n in SYSTEM_DLLS, "source": "hijacklibs"}
    except Exception:  # noqa: BLE001, S110  (catalogue unreadable: the built-in names)
        pass
    return out


def _host(info: dict[str, Any], exe_names: set[str]) -> dict[str, Any] | None:
    """A program next to the DLL that the catalogue lists as loading it from its own folder."""
    for e in exe_names:
        if e in info["hosts"]:
            return {"exe": e, **info["hosts"][e]}
    return None


def pairs(entries: list[tuple[str, str | None]]) -> list[dict[str, Any]]:
    """Side-loading candidates among ``entries`` (name inside the container, local file):
    one record per DLL next to an EXE when the DLL has a system library's name, or is a
    third-party DLL the catalogue lists with that very program as its known host."""
    cat = catalogue()
    by_dir: dict[str, list[tuple[str, str, str]]] = {}
    for name, f in entries:
        if not name or not f:
            continue
        pp = PurePosixPath(name.replace("\\", "/"))
        by_dir.setdefault(str(pp.parent).lower(), []).append((name, pp.name.lower(), f))
    out = []
    for files in by_dir.values():
        dlls = [(n, b, f) for n, b, f in files if b in cat]
        if not dlls:
            continue
        exes = []
        for n, b, f in files:
            if b.endswith((".exe", ".scr", ".com")) or "." not in b:
                pe = _read(f)
                if pe and not pe.is_dll:
                    from .interpreters import original_filename
                    exes.append((n, pe, {b, original_filename(f) or b}))
        if not exes:
            continue
        for n, b, f in dlls:
            info = cat[b]
            host = None
            for en, _pe, names in exes:
                host = _host(info, names)
                if host:
                    host["entry"] = en
                    break
            if not info["system"] and not host:
                continue                        # a vendor DLL next to some program: normal, unless a known pair
            dll = _read(f)
            if not dll or not dll.is_dll:
                continue
            importers = [(en, pe) for en, pe, _n in exes if b in pe.imports()]
            hosts = [(en, pe) for en, pe, _n in exes if host and en == host["entry"]]
            exe_name, exe = (hosts or importers or [(en, pe) for en, pe, _n in exes])[0]
            exports, fwd = dll.exports()
            to_system = {k: v for k, v in fwd.items()
                         if re.search(r"(?i)(?:system32|syswow64)[\\/]|^" + re.escape(b[:-4]) + r"(?:_?orig\w*|\d+)?\.", v)}
            e_sig, d_sig = exe.signers(), dll.signers()
            e_pub, d_pub = _signer(e_sig), _signer(d_sig)
            out.append({
                "dll": n, "exe": exe_name, "imported": bool(importers) and exe_name in {x for x, _p in importers},
                "system": info["system"], "vendor": info["vendor"], "locations": info["locations"][:4],
                "known_host": host, "catalogue": info["source"], "url": info.get("url") or "",
                "exe_signed": e_sig is not None, "dll_signed": d_sig is not None,
                "exe_signer": sorted(e_pub), "dll_signer": sorted(d_pub),
                "other_signer": bool(e_pub and d_pub and not e_pub & d_pub),
                "exports": len(exports), "forwarded": len(fwd), "forwarded_to_system": len(to_system),
                "forward_sample": list(to_system.items())[:3] or list(fwd.items())[:3],
                "own_exports": [x for x in exports if x not in fwd][:8],
            })
    return out


def findings(entries: list[tuple[str, str | None]], where: str, container: str = "archive") -> list[dict[str, Any]]:
    out = []
    for r in pairs(entries):
        dll, exe = PurePosixPath(r["dll"].replace("\\", "/")).name, PurePosixPath(r["exe"].replace("\\", "/")).name
        where_ok = ", ".join(r["locations"][:2]) or "its vendor's folder"
        if r["system"]:
            head = (f"{dll} (a Windows system library's name) ships next to {exe}"
                    + (" which imports it" if r["imported"] else "")
                    + f": Windows loads it from that folder instead of System32 (expected in {where_ok})")
        else:
            head = (f"{dll} ({r['vendor'] or 'third-party'} library, expected in {where_ok}) ships next to {exe}, "
                    "a program known to load it from its own folder")
        parts = [head]
        if r["known_host"]:
            kh = r["known_host"]
            parts.append(f"HijackLibs lists {kh['exe']} as a {kh['type'].lower() or 'side-loading'} host for {dll}"
                         + (f" ({kh['condition']})" if kh["condition"] else ""))
        strong = False
        genuine = r["dll_signed"] and any("microsoft" in n.lower() for n in r["dll_signer"]) \
            and not r["forwarded_to_system"] and r["system"]
        if genuine:
            parts.append(f"{dll} is signed by {', '.join(r['dll_signer'][:2])}: likely a redistributable copy "
                         "(dbghelp, d3d…), unless the signature does not verify")
            strong = False
        elif r["exe_signed"] and not r["dll_signed"]:
            parts.append(f"{exe} carries a signature"
                         + (f" ({', '.join(r['exe_signer'][:2])})" if r["exe_signer"] else "")
                         + f", {dll} none")
            strong = True
        elif r["other_signer"]:
            parts.append(f"signed by someone else: {exe} by {', '.join(r['exe_signer'][:2])}, "
                         f"{dll} by {', '.join(r['dll_signer'][:2])}")
            strong = True
        if r["forwarded_to_system"]:
            parts.append(f"a proxy DLL: {r['forwarded_to_system']} of its {r['exports']} exports are forwarded to the "
                         "real library" + (f"; its own: {', '.join(r['own_exports'][:4])}" if r["own_exports"] else ""))
            strong = True
        # a vendor's own DLL, or a runtime apps ship next to themselves, that holds together: normal
        if not strong and (not r["system"] or _APP_LOCAL.match(dll.lower())) and not genuine:
            continue
        parts.append("signatures read, not verified")
        kh = r["known_host"]
        ev = "\n".join([f"exe: {r['exe']}  signed={r['exe_signed']}  signer={', '.join(r['exe_signer']) or '-'}",
                        f"dll: {r['dll']}  signed={r['dll_signed']}  signer={', '.join(r['dll_signer']) or '-'}",
                        f"imported by the exe: {r['imported']}",
                        f"expected location: {', '.join(r['locations']) or '-'}  (list: {r['catalogue']})",
                        f"exports: {r['exports']}  forwarded: {r['forwarded']}"]
                       + [f"  {k} → {v}" for k, v in r["forward_sample"]]
                       + ([f"known host: {kh['path']}"] if kh else [])
                       + ([f"HijackLibs: {r['url']}"] if r["url"] else []))
        hit = r["imported"] or r["forwarded_to_system"] or bool(kh)
        out.append({"tool": container, "rule": "dll_sideloading",
                    "severity": "low" if genuine else "high" if strong and hit else "medium",
                    "detail": " — ".join(parts), "location": where, "evidence": ev, "attack": "T1574.002"})
    return out
