"""PE binaries (``.exe``/``.dll``/``.sys``/…): static triage with pefile.

Not a disassembler or an unpacker — a *static triage* that surfaces what the PE
header and tables already tell you, so a compiled binary is more than an opaque
"use another tool" note:

- header: machine, subsystem, DLL flag, compile timestamp (and anomalies);
- sections: size, Shannon entropy (packing), write+exec flags, packer names;
- imports: suspicious Win32 APIs grouped by behaviour (injection, download,
  dynamic resolution, process/exec, crypto, anti-debug);
- resources / overlay: an embedded PE (a dropper carrying a second stage),
  appended overlay data;
- TLS callbacks (early / anti-debug execution), Authenticode presence, and a
  version-info masquerade check (OriginalFilename vs the real name).

With **FLOSS** provisioned (optional, portable) the obfuscated/stack strings it
decodes are mined for IOCs too. Deep RE stays with the analyst's dedicated tools;
nothing is executed.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

_MAX_BYTES = 64 * 1024 * 1024

_PACKER_SECTIONS = ("upx", "aspack", "petite", "nspack", "mpress", "themida",
                    "vmp", ".enigma", "pebundle", "mew", "fsg", "molebox")

# Suspicious imports grouped by behaviour → (rule, severity, attack, label).
_IMPORT_GROUPS: list[tuple[str, str, str, str, tuple[str, ...]]] = [
    ("pe_inject_imports", "high", "T1055", "process injection APIs",
     ("virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
      "ntwritevirtualmemory", "queueuserapc", "setthreadcontext", "virtualprotect",
      "rtlcreateuserthread", "mapviewofsection", "ntmapviewofsection")),
    ("pe_net_imports", "high", "T1105", "network / download APIs",
     ("urldownloadtofile", "internetopen", "internetreadfile", "internetconnect",
      "winhttpopen", "winhttpsendrequest", "httpsendrequest", "wsastartup", "connect",
      "send", "recv", "getaddrinfo")),
    ("pe_exec_imports", "high", "T1106", "process / command execution APIs",
     ("winexec", "createprocess", "shellexecute", "shellexecuteex", "ntcreateprocess",
      "system", "_wsystem")),
    ("pe_dynamic_resolve", "medium", "T1027", "dynamic API resolution",
     ("loadlibrary", "loadlibraryex", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress")),
    ("pe_crypto_imports", "medium", "T1027", "crypto APIs",
     ("cryptencrypt", "cryptdecrypt", "cryptacquirecontext", "bcryptencrypt", "cryptgenkey")),
    ("pe_antidebug_imports", "medium", "T1622", "anti-debug / anti-analysis APIs",
     ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
      "ntsetinformationthread", "outputdebugstringa", "debugactiveprocess")),
    ("pe_persist_imports", "medium", "T1547.001", "persistence / registry APIs",
     ("regsetvalue", "regsetvalueex", "regcreatekey", "regcreatekeyex")),
    ("pe_cred_imports", "high", "T1555", "credential-access APIs",
     ("cryptunprotectdata", "lsaretrieveprivatedata", "credenumerate", "credread")),
]


def _finding(rule: str, severity: str, detail: str, location: str,
             evidence: str = "", attack: str = "") -> dict[str, Any]:
    return {"tool": "pe", "rule": rule, "severity": severity,
            "detail": detail + (f" · {attack}" if attack else ""),
            "location": location, "evidence": evidence[:2000]}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 2)


def analyze(path: Path, rel: str, run_tools: bool = True) -> dict[str, Any]:
    item: dict[str, Any] = {"kind": "pe", "file": rel, "findings": []}
    loc = f"file:{rel}"
    try:
        blob = path.read_bytes()[:_MAX_BYTES]
    except OSError as exc:
        item["error"] = str(exc)
        return item
    size = len(blob)
    item["size"] = size
    if blob[:2] != b"MZ":
        item["is_pe"] = False
        item["findings"].append(_finding("pe_not_pe", "medium",
            f"'{Path(rel).suffix}' is not a PE image (no MZ header) — possible masquerade",
            loc, "", "T1036"))
        return item
    item["is_pe"] = True

    try:
        import pefile
    except Exception as exc:  # noqa: BLE001
        item["findings"].append(_finding("pe_image", "info",
            f"PE binary ({size} bytes) — pefile unavailable ({exc}); categorised only", loc))
        return item

    try:
        pe = pefile.PE(data=blob, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
    except Exception as exc:  # noqa: BLE001
        item["findings"].append(_finding("pe_malformed", "medium",
            f"PE header present but malformed ({exc}) — possible anti-analysis", loc, "", "T1027"))
        return item

    f = item["findings"]
    strings_for_ioc: list[str] = []

    machine = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64", 0x1c4: "ARMv7"}.get(
        pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    subsystem = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "unknown")
    ts = pe.FILE_HEADER.TimeDateStamp
    item.update(machine=machine, is_dll=is_dll, subsystem=subsystem,
                compiled=_fmt_ts(ts), entrypoint=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    f.append(_finding("pe_image", "info",
        f"PE {'DLL' if is_dll else 'EXE'} ({machine}, {subsystem}, {size} bytes, compiled {_fmt_ts(ts)})",
        loc, "", "T1204.002"))
    if ts == 0 or ts > 4_102_444_800 or (0 < ts < 946_684_800):   # zero / >2100 / <2000
        f.append(_finding("pe_timestamp_anomaly", "low",
            f"suspicious compile timestamp ({ts})", loc, str(ts)))

    # --- sections: entropy, W+X, packer names ---
    sections = []
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = None
    high_entropy = 0
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        data = s.get_data()
        ent = _entropy(data)
        wx = bool(s.Characteristics & 0x80000000) and bool(s.Characteristics & 0x20000000)
        sections.append({"name": name, "vsize": s.Misc_VirtualSize, "rawsize": s.SizeOfRawData,
                         "entropy": ent, "wx": wx})
        if ent >= 7.2 and s.SizeOfRawData > 512:
            high_entropy += 1
        if wx:
            f.append(_finding("pe_section_wx", "medium",
                f"section '{name}' is writable AND executable (self-modifying / unpacking)",
                loc, name, "T1027"))
        if any(p in name.lower() for p in _PACKER_SECTIONS):
            f.append(_finding("pe_packer_section", "high",
                f"packer section name '{name}'", loc, name, "T1027.002"))
        if s.contains_rva(ep):
            ep_section = name
    item["sections"] = sections[:40]
    if high_entropy and high_entropy >= max(1, len(sections) // 2):
        f.append(_finding("pe_packed", "high",
            f"{high_entropy}/{len(sections)} sections have high entropy (≥7.2) — likely packed/encrypted",
            loc, "", "T1027.002"))
    if ep_section and ep_section.lower() not in (".text", "code") and ep_section.lower().lstrip("."):
        f.append(_finding("pe_entrypoint_section", "medium",
            f"entry point is in section '{ep_section}', not .text (packer/anomaly)", loc, ep_section, "T1027"))

    # --- imports ---
    imported: set[str] = set()
    dlls: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = (entry.dll or b"").decode("latin-1", "replace")
        dlls.append(dll)
        for imp in entry.imports:
            if imp.name:
                imported.add(imp.name.decode("latin-1", "replace").lower())
    item["imports_dll"] = dlls[:60]
    item["imports_count"] = len(imported)
    for rule, sev, attack, label, apis in _IMPORT_GROUPS:
        hit = sorted({a for a in apis if a in imported})
        if hit:
            f.append(_finding(rule, sev, f"{label}: {', '.join(hit[:8])}", loc, ", ".join(hit[:20]), attack))
    if not imported and not is_dll:
        f.append(_finding("pe_no_imports", "medium",
            "no readable imports (packed, or imports resolved dynamically / shellcode stub)",
            loc, "", "T1027.002"))

    # --- exports (DLL) ---
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        names = [e.name.decode("latin-1", "replace") for e in exp.symbols if e.name][:60]
        item["exports"] = names
        if any(n.lower() in ("dllregisterserver", "install", "start", "run", "main") for n in names):
            f.append(_finding("pe_dll_export", "info",
                f"DLL exports a likely entry: {', '.join(names[:6])}", loc, ", ".join(names[:10])))

    # --- TLS callbacks ---
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None and getattr(tls.struct, "AddressOfCallBacks", 0):
        f.append(_finding("pe_tls_callback", "medium",
            "TLS callback(s) present — code runs before the entry point (anti-debug/early exec)",
            loc, "", "T1574"))

    # --- Authenticode ---
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    item["signed"] = bool(sec.VirtualAddress and sec.Size)
    if item["signed"]:
        f.append(_finding("pe_signed", "info", "carries an Authenticode signature (not verified here)", loc))

    # --- embedded PE in resources, overlay ---
    if _has_embedded_pe(pe, blob):
        f.append(_finding("pe_embedded_pe", "high",
            "an embedded PE (MZ) was found in a resource — likely a dropper carrying a payload",
            loc, "", "T1027.009"))
    overlay = pe.get_overlay_data_start_offset()
    if overlay is not None and size - overlay > 1024:
        f.append(_finding("pe_overlay", "low",
            f"overlay data appended after the last section ({size - overlay} bytes)", loc, str(size - overlay)))

    # --- version-info masquerade ---
    orig = _version_string(pe, "OriginalFilename")
    if orig and Path(rel).suffix and orig.lower() != Path(rel).name.lower():
        f.append(_finding("pe_masquerade", "medium",
            f"OriginalFilename '{orig}' differs from the file name '{Path(rel).name}'",
            loc, orig, "T1036"))
    for key in ("CompanyName", "ProductName", "OriginalFilename"):
        v = _version_string(pe, key)
        if v:
            strings_for_ioc.append(v)

    # --- optional FLOSS strings (deobfuscated) ---
    if run_tools:
        floss_strings = _run_floss(path)
        if floss_strings:
            item["floss_strings"] = floss_strings[:200]
            strings_for_ioc.extend(floss_strings)
            f.append(_finding("pe_floss_strings", "info",
                f"FLOSS decoded {len(floss_strings)} obfuscated/stack string(s)", loc))

    item["_strings_sample"] = strings_for_ioc[:200]
    try:
        pe.close()
    except Exception:  # noqa: BLE001
        pass
    return item


def _fmt_ts(ts: int) -> str:
    import datetime
    if not ts:
        return "0"
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return str(ts)


def _has_embedded_pe(pe: Any, blob: bytes) -> bool:
    try:
        rsrc = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if rsrc is None:
            return False
        for t in rsrc.entries:
            for nm in getattr(t.directory, "entries", []) or []:
                for lang in getattr(nm.directory, "entries", []) or []:
                    d = lang.data.struct
                    off = pe.get_offset_from_rva(d.OffsetToData)
                    if blob[off:off + 2] == b"MZ" and blob[off:off + 64].find(b"PE\x00\x00") == -1:
                        # MZ at the start of a resource; a nested stub often has PE later too
                        return True
                    if blob[off:off + 2] == b"MZ":
                        return True
    except Exception:  # noqa: BLE001
        return False
    return False


def _version_string(pe: Any, key: str) -> str:
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                if getattr(entry, "Key", b"") == b"StringFileInfo":
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            if k.decode("latin-1", "replace") == key:
                                return v.decode("latin-1", "replace")
    except Exception:  # noqa: BLE001
        pass
    return ""


def _run_floss(path: Path) -> list[str]:
    """Run FLOSS on the portable interpreter (optional, bounded). Returns the
    decoded/stack/tight strings, or [] when FLOSS is not provisioned."""
    import json
    import subprocess

    from ..config import settings

    portable = settings.portable_python()
    if portable is None:
        return []
    try:
        from . import native
        proc = subprocess.run(
            [str(portable), "-m", "floss", "--json", "--no", "static", "--quiet", str(path)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120, env=native.subprocess_env())
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        data = json.loads(proc.stdout)
        out: list[str] = []
        strings = (data.get("strings") or {})
        for key in ("decoded_strings", "stack_strings", "tight_strings"):
            for s in strings.get(key, []) or []:
                val = s.get("string") if isinstance(s, dict) else s
                if isinstance(val, str) and val.strip():
                    out.append(val)
        return out
    except Exception:  # noqa: BLE001
        return []
