"""LIEF: deep binary parsing for PE, ELF and Mach-O.

pefile already gives the PE triage (header, sections, imports, resources). LIEF
(Quarkslab's Library to Instrument Executable Formats) adds what an analyst
pivots on next, and covers ELF and Mach-O too:

- **PE**: imphash, Rich header (toolchain fingerprint), the **PDB path** /
  GUID of the CodeView debug entry (attribution, build-host user names),
  Authenticode parsed **and verified** (signer, issuer, serial, validity,
  authentihash), the embedded manifest (``requireAdministrator``), version
  info, TLS callbacks, load configuration (CFG), security mitigations
  (ASLR / DEP / CFG / high-entropy VA), header checksum vs the real one,
  delay imports, exports with forwarders, overlay;
- **ELF**: type, machine, interpreter, needed libraries, RPATH/RUNPATH,
  sections with entropy, imported/exported symbols, stripped/static/PIE flags;
- **Mach-O**: CPU, file type, linked dylibs, code signature presence, sections.

LIEF is a C++ library: a hostile file could crash it. It is therefore run in
its own child process (``python -m docutracex.parsers.lief_info FILE``) with a
time limit, so a crash only costs this sub-analysis, never the case.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..config import tmo
from ..logging_config import get_logger

log = get_logger(__name__)

TIMEOUT = tmo(120)
_MAX_LIST = 300


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in counts if c), 3)


def _s(x: Any) -> str:
    """Enum / bytes / anything → short display string."""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x).hex()
    name = getattr(x, "name", None)          # LIEF enums
    if isinstance(name, str) and name and not isinstance(x, (str, int)):
        return name
    s = str(x)
    head, _, tail = s.rpartition(".")
    return tail if head and head.replace(".", "").replace("_", "").isalnum() and tail.isupper() else s


def _try(fn: Any, default: Any = None) -> Any:
    try:
        return fn()
    except Exception:  # noqa: BLE001 - LIEF raises on missing structures
        return default


# --- PE ----------------------------------------------------------------------

def _pe(b: Any, lief: Any) -> dict[str, Any]:
    PE = lief.PE
    out: dict[str, Any] = {"format": "PE"}
    oh = b.optional_header
    out["imphash"] = _try(lambda: PE.get_imphash(b, PE.IMPHASH_MODE.PEFILE), "")
    out["imagebase"] = hex(b.imagebase)
    out["entrypoint"] = hex(_try(lambda: b.entrypoint, 0) or 0)
    out["linker"] = f"{oh.major_linker_version}.{oh.minor_linker_version}"
    out["os_version"] = f"{oh.major_operating_system_version}.{oh.minor_operating_system_version}"
    bits = int(_try(lambda: oh.dll_characteristics, 0) or 0)
    names = {0x20: "HIGH_ENTROPY_VA", 0x40: "DYNAMIC_BASE", 0x80: "FORCE_INTEGRITY", 0x100: "NX_COMPAT",
             0x200: "NO_ISOLATION", 0x400: "NO_SEH", 0x800: "NO_BIND", 0x1000: "APPCONTAINER",
             0x2000: "WDM_DRIVER", 0x4000: "GUARD_CF", 0x8000: "TERMINAL_SERVER_AWARE"}
    chars = [n for b, n in names.items() if bits & b]
    out["mitigations"] = {
        "aslr": bool(bits & 0x40), "dep": bool(bits & 0x100), "cfg": bool(bits & 0x4000),
        "high_entropy_va": bool(bits & 0x20), "no_seh": bool(bits & 0x400), "force_integrity": bool(bits & 0x80),
    }
    out["dll_characteristics"] = chars
    declared, real = oh.checksum, _try(b.compute_checksum, None)
    out["checksum"] = {"declared": hex(declared), "computed": hex(real) if real is not None else "",
                       "valid": declared == 0 or real is None or declared == real}

    if b.has_rich_header:
        rh = b.rich_header
        out["rich_header"] = {"key": hex(rh.key), "entries": [
            {"id": e.id, "build_id": e.build_id, "count": e.count} for e in list(rh.entries)[:60]]}

    pdbs = []
    for d in _try(lambda: list(b.debug), []) or []:
        if isinstance(d, PE.CodeViewPDB):
            guid = _try(lambda d=d: str(d.guid), "")
            pdbs.append({"path": d.filename, "guid": guid, "age": d.age})
    out["pdb"] = pdbs

    sigs = []
    if b.has_signatures:
        verified = _try(lambda: b.verify_signature(), None)
        out["signature_check"] = _s(verified) if verified is not None else "error"
        for sig in list(b.signatures)[:4]:
            certs = []
            for c in list(sig.certificates)[:8]:
                certs.append({"subject": c.subject, "issuer": c.issuer,
                              "serial": _s(c.serial_number),
                              "valid_from": "-".join(f"{x:02d}" for x in c.valid_from[:3]),
                              "valid_to": "-".join(f"{x:02d}" for x in c.valid_to[:3])})
            signers = [{"issuer": s.issuer, "serial": _s(s.serial_number)} for s in list(sig.signers)[:4]]
            sigs.append({"digest": _s(sig.digest_algorithm), "signers": signers, "certificates": certs})
        out["authentihash_sha256"] = _try(lambda: _s(b.authentihash_sha256), "")
    out["signatures"] = sigs

    rm = _try(lambda: b.resources_manager if b.has_resources else None)
    if rm is not None:
        out["manifest"] = (_try(lambda: rm.manifest, "") or "")[:4000] if _try(lambda: rm.has_manifest) else ""
        vers = []
        for v in _try(lambda: rm.version, []) or []:
            sfi = _try(lambda v=v: v.string_file_info)
            for tbl in (_try(lambda s=sfi: s.children, []) or []) if sfi else []:
                for e in _try(lambda t=tbl: t.entries, []) or []:
                    vers.append({"key": e.key, "value": e.value})
        out["version_info"] = vers[:40]
        out["resource_types"] = [_s(t) for t in _try(lambda: rm.types, []) or []][:40]
        out["icons"] = len(_try(lambda: rm.icons, []) or [])

    if b.has_tls:
        out["tls_callbacks"] = [hex(x) for x in _try(lambda: list(b.tls.callbacks), []) or []][:20]
    lc = _try(lambda: b.load_configuration if b.has_configuration else None)
    if lc is not None:
        out["load_config"] = {"guard_flags": _s(_try(lambda: lc.guard_flags, "")),
                              "security_cookie": hex(_try(lambda: lc.security_cookie, 0) or 0)}

    imports = []
    for lib in list(b.imports)[:_MAX_LIST]:
        ents = [e.name if not e.is_ordinal else f"#{e.ordinal}" for e in list(lib.entries)[:400]]
        imports.append({"library": lib.name, "count": len(ents), "functions": ents})
    out["imports"] = imports
    out["delay_imports"] = [{"library": d.name, "functions": [e.name for e in list(d.entries)[:200]]}
                            for d in _try(lambda: list(b.delay_imports), []) or []][:60]
    exp = _try(lambda: b.get_export() if b.has_exports else None)
    if exp is not None:
        out["export_name"] = exp.name
        out["exports"] = [{"name": e.name, "ordinal": e.ordinal,
                           "forward": (f"{e.forward_information.library}.{e.forward_information.function}"
                                       if e.is_forwarded else "")}
                          for e in list(exp.entries)[:_MAX_LIST]]
    out["sections"] = [{"name": s.name, "vsize": s.virtual_size, "size": s.size, "offset": s.offset,
                        "entropy": round(s.entropy, 3),
                        "flags": [_s(c).replace("MEM_", "") for c in s.characteristics_lists
                                  if _s(c).startswith("MEM_")]}
                       for s in list(b.sections)[:60]]
    ov = _try(lambda: bytes(b.overlay), b"") or b""
    if ov:
        out["overlay"] = {"offset": b.overlay_offset, "size": len(ov), "entropy": _entropy(ov[:4 << 20]),
                          "head": ov[:16].hex()}
    return out


def _pe_findings(info: dict[str, Any], loc: str) -> list[dict[str, Any]]:
    f: list[dict[str, Any]] = []
    for p in info.get("pdb") or []:
        if p.get("path"):
            f.append(_finding("lief_pdb_path", "info",
                              f"PDB debug path: {p['path']} — build host/project names (attribution)",
                              loc, f"{p['path']} guid={p.get('guid', '')} age={p.get('age', '')}"))
    chk = info.get("signature_check")
    if info.get("signatures"):
        subj = ((info["signatures"][0].get("certificates") or [{}])[0]).get("subject", "")
        if chk and chk != "OK":
            f.append(_finding("lief_signature_invalid", "high",
                              f"Authenticode signature does NOT verify ({chk}) — tampered, or a copied/"
                              f"forged signature", loc, subj, "T1553.002"))
        else:
            f.append(_finding("lief_signature_valid", "info",
                              f"Authenticode signature verifies (integrity) — signer: {subj[:160]}", loc, subj))
    man = (info.get("manifest") or "").lower()
    if "requireadministrator" in man:
        f.append(_finding("lief_manifest_admin", "low",
                          "manifest requests administrator rights (requireAdministrator)", loc,
                          "requestedExecutionLevel=requireAdministrator", "T1548"))
    if "autoelevate" in man and "true" in man:
        f.append(_finding("lief_manifest_autoelevate", "medium",
                          "manifest sets autoElevate=true (UAC auto-elevation / bypass pattern)", loc,
                          "autoElevate", "T1548.002"))
    chk = info.get("checksum") or {}
    if chk and not chk.get("valid"):
        f.append(_finding("lief_checksum_mismatch", "low",
                          f"PE header checksum {chk.get('declared')} does not match the file "
                          f"({chk.get('computed')}) — modified after linking (patched/packed)", loc))
    if info.get("tls_callbacks"):
        f.append(_finding("lief_tls_callbacks", "medium",
                          f"{len(info['tls_callbacks'])} TLS callback(s) run before the entry point: "
                          + ", ".join(info["tls_callbacks"][:5]), loc, "", "T1574"))
    fwd = [e for e in info.get("exports") or [] if e.get("forward")]
    if fwd:
        f.append(_finding("lief_forwarded_exports", "medium",
                          f"{len(fwd)} forwarded export(s) (proxy DLL pattern for DLL hijacking): "
                          + ", ".join(e["forward"] for e in fwd[:4]), loc, "", "T1574.001"))
    ov = info.get("overlay") or {}
    if ov.get("size", 0) > 4096 and ov.get("entropy", 0) >= 7.5:
        f.append(_finding("lief_overlay_encrypted", "medium",
                          f"high-entropy overlay ({ov['size']} bytes, entropy {ov['entropy']}) — "
                          "appended encrypted/compressed payload", loc, ov.get("head", ""), "T1027"))
    return f


# --- ELF / Mach-O ------------------------------------------------------------

def _elf(b: Any, lief: Any) -> dict[str, Any]:
    h = b.header
    out: dict[str, Any] = {"format": "ELF", "type": _s(h.file_type), "machine": _s(h.machine_type),
                           "class": _s(h.identity_class), "entrypoint": hex(b.entrypoint)}
    out["interpreter"] = _try(lambda: b.interpreter if b.has_interpreter else "", "")
    out["libraries"] = list(_try(lambda: b.libraries, []) or [])[:_MAX_LIST]
    rpath = []
    for e in _try(lambda: list(b.dynamic_entries), []) or []:
        tag = _s(e.tag)
        if tag in ("RPATH", "RUNPATH"):
            rpath.append(f"{tag}={_try(lambda e=e: e.paths, '') or _try(lambda e=e: e.name, '')}")
    out["rpath"] = rpath
    out["pie"] = bool(_try(lambda: b.is_pie, False))
    out["nx"] = bool(_try(lambda: b.has_nx, False))
    out["static"] = not out["interpreter"] and not out["libraries"]
    syms = _try(lambda: list(b.symtab_symbols), []) or []
    out["stripped"] = not syms
    out["imported"] = sorted({s.name for s in _try(lambda: list(b.imported_symbols), []) or [] if s.name})[:_MAX_LIST]
    out["exported"] = sorted({s.name for s in _try(lambda: list(b.exported_symbols), []) or [] if s.name})[:_MAX_LIST]
    out["sections"] = [{"name": s.name, "size": s.size, "offset": s.offset, "entropy": round(s.entropy, 3),
                        "flags": [_s(x) for x in _try(lambda s=s: s.flags_list, []) or []]}
                       for s in list(b.sections)[:80]]
    return out


def _elf_findings(info: dict[str, Any], loc: str) -> list[dict[str, Any]]:
    f = [_finding("lief_elf", "info",
                  f"ELF {info.get('type')} ({info.get('machine')}, {info.get('class')})"
                  + (", statically linked" if info.get("static") else "")
                  + (", stripped" if info.get("stripped") else ""), loc)]
    imp = {s.lower() for s in info.get("imported") or []}
    groups = [
        ("lief_elf_exec", "medium", "T1059.004", "process execution", ("execve", "execl", "execvp", "system", "popen")),
        ("lief_elf_net", "medium", "T1071", "networking", ("socket", "connect", "bind", "listen", "accept",
                                                            "getaddrinfo", "gethostbyname")),
        ("lief_elf_ptrace", "medium", "T1055.008", "ptrace (injection / anti-debug)", ("ptrace",)),
        ("lief_elf_privesc", "medium", "T1548.001", "set uid/gid", ("setuid", "setgid", "setreuid", "setresuid")),
        ("lief_elf_hide", "medium", "T1014", "LD_PRELOAD / dynamic loading", ("dlopen", "dlsym")),
    ]
    for rule, sev, attack, label, apis in groups:
        hit = sorted(a for a in apis if a in imp)
        if hit:
            f.append(_finding(rule, sev, f"ELF imports {label}: {', '.join(hit)}", loc, ", ".join(hit), attack))
    if any("$origin" in r.lower() or "/tmp" in r for r in info.get("rpath") or []):
        f.append(_finding("lief_elf_rpath", "medium", "RPATH/RUNPATH points to a writable or relative "
                          "location (library hijacking)", loc, "; ".join(info["rpath"]), "T1574.006"))
    packed = [s for s in info.get("sections") or [] if s.get("entropy", 0) >= 7.2 and s.get("size", 0) > 4096]
    if packed or (not info.get("sections")):
        f.append(_finding("lief_elf_packed", "medium",
                          "ELF looks packed (no section table, or high-entropy sections)", loc,
                          ", ".join(s["name"] for s in packed[:5]), "T1027.002"))
    return f


def _macho(b: Any, lief: Any) -> dict[str, Any]:
    h = b.header
    out: dict[str, Any] = {"format": "MachO", "cpu": _s(h.cpu_type), "type": _s(h.file_type),
                           "entrypoint": hex(_try(lambda: b.entrypoint, 0) or 0)}
    out["libraries"] = [lib.name for lib in list(_try(lambda: b.libraries, []) or [])][:_MAX_LIST]
    out["signed"] = bool(_try(lambda: b.has_code_signature, False))
    out["pie"] = bool(_try(lambda: b.is_pie, False))
    out["imported"] = sorted({s.name for s in _try(lambda: list(b.imported_symbols), []) or [] if s.name})[:_MAX_LIST]
    out["sections"] = [{"name": f"{s.segment_name},{s.name}", "size": s.size, "offset": s.offset,
                        "entropy": round(s.entropy, 3)} for s in list(b.sections)[:80]]
    return out


def _macho_findings(info: dict[str, Any], loc: str) -> list[dict[str, Any]]:
    f = [_finding("lief_macho", "info", f"Mach-O {info.get('type')} ({info.get('cpu')})", loc)]
    if not info.get("signed"):
        f.append(_finding("lief_macho_unsigned", "low", "Mach-O has no code signature", loc))
    return f


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "",
             attack: str = "") -> dict[str, Any]:
    return {"tool": "lief", "rule": rule, "severity": severity,
            "detail": detail + (f" · {attack}" if attack else ""),
            "location": location, "evidence": evidence[:1500]}


def parse(path: Path) -> dict[str, Any]:
    """In-process parse (used by the child process)."""
    import lief
    lief.logging.disable()
    b = lief.parse(str(path))
    if b is None:
        return {"status": "error", "detail": "LIEF could not parse the file (not PE/ELF/Mach-O, or malformed)"}
    if isinstance(b, lief.MachO.FatBinary):
        b = b.at(0)
    if isinstance(b, lief.PE.Binary):
        info = _pe(b, lief)
    elif isinstance(b, lief.ELF.Binary):
        info = _elf(b, lief)
    elif isinstance(b, lief.MachO.Binary):
        info = _macho(b, lief)
    else:
        return {"status": "error", "detail": f"unsupported format {type(b).__name__}"}
    info["status"] = "ok"
    info["version"] = str(lief.__version__).split("-")[0]
    return info


def analyze(path: Path, rel: str) -> dict[str, Any]:
    """Run LIEF on ``path`` in a child process. Returns the info record with a
    ``findings`` list and a ``status`` (ok / not_installed / timeout / error)."""
    loc = f"file:{rel}"
    try:
        import importlib.util
        if importlib.util.find_spec("lief") is None:
            return {"status": "not_installed", "detail": "LIEF not installed (pip install lief)", "findings": []}
    except Exception:  # noqa: BLE001
        pass
    try:
        r = subprocess.run([sys.executable, "-m", "docutracex.parsers.lief_info", str(path)],
                           capture_output=True, text=True, timeout=TIMEOUT,
                           cwd=str(Path(__file__).resolve().parents[2]))
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "detail": f"LIEF timed out after {TIMEOUT}s", "findings": []}
    if r.returncode != 0 or not r.stdout.strip():
        err = (r.stderr or "").strip().splitlines()[-1:] or [f"exit {r.returncode}"]
        log.warning("LIEF failed on %s: %s", rel, err[0])
        return {"status": "error", "detail": f"LIEF failed: {err[0][:300]}", "findings": []}
    try:
        info = json.loads(r.stdout)
    except ValueError:
        return {"status": "error", "detail": "LIEF output is not JSON", "findings": []}
    if info.get("status") != "ok":
        info["findings"] = []
        return info
    fmt = info.get("format")
    info["findings"] = (_pe_findings(info, loc) if fmt == "PE" else
                        _elf_findings(info, loc) if fmt == "ELF" else _macho_findings(info, loc))
    return info


if __name__ == "__main__":
    try:
        res = parse(Path(sys.argv[1]))
    except Exception as exc:  # noqa: BLE001
        res = {"status": "error", "detail": f"{type(exc).__name__}: {exc}"[:400]}
    sys.stdout.write(json.dumps(res, default=str))
