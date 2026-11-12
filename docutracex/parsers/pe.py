"""PE binaries (``.exe``/``.dll``/``.sys``/…): static triage with pefile.

Not a disassembler — a *static triage* that surfaces what the PE header and
tables already tell you, so a compiled binary is more than an opaque "use
another tool" note. First step: packer / installer detection and STATIC
unpacking (UPX, AutoIt, Inno, NSIS/SFX, Nuitka, Enigma VB — see
:mod:`unpack`); the unpacked files are analysed as children (Nested tab).
Then:

- header: machine, subsystem, DLL flag, compile timestamp (and anomalies);
- sections: size, Shannon entropy (packing), write+exec flags, packer names;
- imports: suspicious Win32 APIs grouped by behaviour (injection, download,
  dynamic resolution, process/exec, crypto, anti-debug);
- resources / overlay: an embedded PE (a dropper carrying a second stage),
  appended overlay data;
- TLS callbacks (early / anti-debug execution), Authenticode presence, and a
  version-info masquerade check (OriginalFilename vs the real name);
- **LIEF** (:mod:`lief_info`, own process): imphash, Rich header, PDB path,
  Authenticode verified, manifest, mitigations, checksum, forwarded exports,
  overlay entropy.

With **FLOSS** and **capa** provisioned (optional; Mandiant's standalone
binaries under ``tools/floss/`` and ``tools/capa/``) the static, obfuscated,
stack and tight strings FLOSS extracts are mined for IOCs, and capa's matched
capabilities become findings with their ATT&CK technique. Both are skipped for
PyInstaller bundles and packed/protected PEs (they would only see the stub;
when unpacked, they run on the unpacked file instead). Each run leaves a status
record (ok / skipped / not provisioned / timeout / error) so a missing result
is never silent. The sample never runs natively: capa is static; FLOSS
emulates decoding routines (vivisect) to recover strings.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

_MAX_BYTES = 64 * 1024 * 1024

# External static tools (FLOSS / capa): per-run time limits and output caps.
import os as _os
from ..config import tmo

FLOSS_TIMEOUT = int(_os.environ.get("DOCUTRACEX_FLOSS_TIMEOUT", str(tmo(1200))))   # 20 min x factor
# FLOSS arguments (besides --json / --quiet, which the parser needs):
# --large-file lifts FLOSS's 16 MB limit; -n 7 = minimum string length.
FLOSS_EXTRA_ARGS = ["--large-file", "-n", "7"]
# FLOSS's language-specific (Go / Rust) string extraction crashes on some PEs
# (FLOSS 3.2.0: "ValueError: bytes length not a multiple of item size" in
# get_struct_string_candidates_with_pointer_size, e.g. a .rdata whose size is
# not a multiple of the pointer size) and takes the whole run down with it.
# Then FLOSS is run once more without that phase (``--language none``, FLOSS
# 3.x) so the static / decoded / stack / tight strings are not lost.
FLOSS_NO_LANGUAGE_ARGS = ["--language", "none"]
_FLOSS_LANGUAGE_CRASH = ("get_struct_string_candidates", "bytes length not a multiple of item size",
                         "language_strings", "floss/language/")
CAPA_TIMEOUT = int(_os.environ.get("DOCUTRACEX_CAPA_TIMEOUT", str(tmo(1800))))   # 30 min x factor
_FLOSS_MAX_STRINGS = 7000
_CAPA_MAX_RULES = 300
# PyInstaller CArchive cookie (same as parsers.pyinstaller.MAGIC), searched in
# the file tail like analyze.py does.
_PYI_MAGIC = b"MEI\014\013\012\013\016"
_PYI_TAIL = 4 * 1024 * 1024

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


def analyze(path: Path, rel: str, run_tools: bool = True, unpack_dir: Path | None = None,
            tools_budget_ok: bool = True) -> dict[str, Any]:
    """Static PE triage. ``run_tools`` enables the external tools (DIE, the
    unpackers, FLOSS, capa); ``unpack_dir`` is where a packed/installer PE is
    unpacked, and a padded PE debloated, next to it: the resulting files come
    back in ``item["_children"]`` (``{path, filename, origin, recipe,
    source}``) — the caller pops them and scans them as nested children. ``tools_budget_ok=False`` skips
    FLOSS/capa (used for the Nth nested PE so a big installer can't eat the
    whole case time limit)."""
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
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
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
    repro = _reproducible(pe)
    compiled = "not a date (reproducible build: the timestamp is a hash)" if repro else _fmt_ts(ts)
    item.update(machine=machine, is_dll=is_dll, subsystem=subsystem, compiled=compiled, reproducible=repro,
                entrypoint=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    f.append(_finding("pe_image", "info",
        f"PE {'DLL' if is_dll else 'EXE'} ({machine}, {subsystem}, {size} bytes, compiled {compiled})",
        loc, "", "T1204.002"))
    # a reproducible (deterministic) build stores a hash there, any value is normal
    if not repro and (ts == 0 or ts > 4_102_444_800 or (0 < ts < 946_684_800)):   # zero / >2100 / <2000
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
        if hit and rule in _ROUTINE and set(hit) <= _ROUTINE[rule]:
            sev = "low"          # what every C / C++ runtime imports: context, not a lead
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
    # (severity set after the Authenticode check below: a signed installer or
    # bootstrapper carrying its own binaries is normal)
    embedded_pe = _has_embedded_pe(pe, blob)
    overlay = pe.get_overlay_data_start_offset()
    if overlay is not None and size - overlay > 1024:
        f.append(_finding("pe_overlay", "low",
            f"overlay data appended after the last section ({size - overlay} bytes)", loc, str(size - overlay)))

    # --- version-info masquerade ---
    orig = _version_string(pe, "OriginalFilename")
    if orig and Path(rel).suffix and not _same_name(orig, Path(rel).name) and not _tool_named(rel):
        f.append(_finding("pe_masquerade", "medium",
            f"OriginalFilename '{orig}' differs from the file name '{Path(rel).name}'",
            loc, orig, "T1036"))
    for key in ("CompanyName", "ProductName", "OriginalFilename"):
        v = _version_string(pe, key)
        if v:
            strings_for_ioc.append(v)

    # --- LIEF: imphash, Rich header, PDB path, Authenticode verification,
    # manifest, mitigations, checksum, forwarded exports, overlay (own process).
    from . import lief_info
    lf = lief_info.analyze(path, rel)
    have = {x["rule"] for x in f}
    for x in lf.pop("findings", []):
        if x["rule"] == "lief_tls_callbacks" and "pe_tls_callback" in have:
            continue
        f.append(x)
    item["lief"] = lf
    if embedded_pe:
        sig_ok = str(lf.get("signature_check") or "").upper().endswith("OK")
        if item["signed"] and sig_ok:
            f.append(_finding("pe_embedded_pe", "low",
                "embedded PE in a resource of a binary with a valid Authenticode signature — normal for "
                "installers and bootstrappers; what it carries is analysed as a child", loc, "", "T1027.009"))
        else:
            f.append(_finding("pe_embedded_pe", "medium" if item["signed"] else "high",
                "an embedded PE (MZ) was found in a resource — likely a dropper carrying a payload"
                + (" (signed, but the signature could not be verified)" if item["signed"] else ""),
                loc, "", "T1027.009"))
    for p in lf.get("pdb") or []:
        if p.get("path"):
            strings_for_ioc.append(p["path"])

    # --- binary padding (T1027.001): strip the junk first; the real binary is
    # a nested child where the whole pipeline (unpack, FLOSS, capa…) runs.
    children: list[dict[str, Any]] = []
    deb: dict[str, Any] = {}
    if unpack_dir is not None and run_tools:
        from . import debloat_pe
        sha12 = hashlib.sha256(blob).hexdigest()[:12]
        out = unpack_dir.parent / "debloated" / sha12 / Path(rel).name
        try:
            deb = debloat_pe.run(path, out)
        except Exception as exc:  # noqa: BLE001  (never break the PE triage)
            deb = {"status": "error", "detail": str(exc)}
        item["debloat"] = deb
        if deb.get("status") == "debloated":
            f.append(debloat_pe.finding(deb, loc))
            children.append({"path": str(out), "filename": Path(rel).name, "source": "debloat",
                             "origin": f"debloated {Path(rel).name} ({deb.get('method')})",
                             "recipe": ["debloat", str(deb.get("method") or "")]})
    bloated = deb.get("status") == "debloated"

    # --- packer / installer: detect, then unpack STATICALLY (first, so the real
    # code is what FLOSS/capa/YARA/IOCs see). PyInstaller has its own pipeline.
    is_pyi = _is_pyinstaller(path)
    up: dict[str, Any] = {}
    if bloated:
        item["unpack"] = {"status": "skipped", "detail": "bloated: unpacking runs on the debloated child (Nested)",
                          "detected": [], "files": []}
    elif not is_pyi:
        from . import unpack
        try:
            dest = (unpack_dir / hashlib.sha256(blob).hexdigest()[:12]) if (unpack_dir and run_tools) else None
            up = unpack.process(path, blob, pe, dest,
                                use_die=run_tools)
        except Exception as exc:  # noqa: BLE001  (never break the PE triage)
            log.warning("packer detection/unpacking failed on %s: %s", rel, exc)
            up = {"status": "error", "detail": str(exc), "detected": [], "findings": []}
        files = up.pop("_files", [])
        for fp, fn in files:
            children.append({"path": fp, "filename": Path(fn).name, "source": "unpack",
                             "origin": f"unpacked from {Path(rel).name} ({up.get('tool') or up.get('family')})",
                             "recipe": ["unpack", str(up.get("family") or up.get("tool") or "")]})
        for x in up.get("findings", []):
            x["location"] = loc
            f.append(x)
        item["unpack"] = {k: v for k, v in up.items() if k != "findings"}

    # --- optional external static tools: FLOSS (strings) + capa (capabilities) ---
    if run_tools:
        skip_why = ""
        if bloated:
            skip_why = ("bloated (binary padding): FLOSS/capa run on the debloated binary instead — "
                        "see the Nested tab")
        elif is_pyi:
            skip_why = ("PyInstaller bundle: FLOSS/capa would only see the bootloader — "
                        "the payload logic is in the Python tab")
        elif up.get("status") == "unpacked":
            skip_why = (f"packed ({up.get('detail', '')}): FLOSS/capa run on the unpacked "
                        f"file(s) instead — see the Nested tab")
        elif up.get("status") in ("detected", "failed", "not_provisioned", "no_static"):
            skip_why = (f"packed/protected and not unpacked ({up.get('detail', '')}): "
                        f"FLOSS/capa would only see the stub")
        elif not tools_budget_ok:
            skip_why = "skipped: FLOSS/capa budget for this case already used (nested PE)"
        if skip_why:
            item["floss"] = {"status": "skipped", "detail": skip_why}
            item["capa"] = {"status": "skipped", "detail": skip_why}
        else:
            floss, capa = tools_for(path)
            floss_strings = floss.pop("strings", [])
            item["floss"] = floss
            if floss_strings:
                item["floss_strings"] = floss_strings[:_FLOSS_MAX_STRINGS]
                strings_for_ioc.extend(floss_strings)
                counts = floss.get("counts", {})
                # FIX: include static in the finding summary
                f.append(_finding("pe_floss_strings", "info",
                    f"FLOSS extracted {len(floss_strings)} string(s): "
                    f"{counts.get('static', 0)} static, "
                    f"{counts.get('decoded', 0)} decoded, "
                    f"{counts.get('stack', 0)} stack, "
                    f"{counts.get('tight', 0)} tight",
                    loc))

            item["capa"] = capa
            # Only capabilities that matter for triage become findings (low+);
            # the full list (incl. "info" ones) is shown in the Binary tab.
            for cap in capa.get("capabilities", []):
                sev = _capa_severity(cap)
                if sev == "info":
                    continue
                attack = ", ".join(a["id"] for a in cap.get("attack", []) if a.get("id"))
                f.append(_finding("pe_capa_capability", sev,
                    f"capa: {cap['name']}"
                    + (f" [{cap['namespace']}]" if cap.get("namespace") else ""),
                    loc, f"{cap.get('matches', 0)} match(es)", attack))

    if children:
        item["_children"] = children
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


# Imports every C / C++ runtime brings in: alone they are no lead.
_ROUTINE: dict[str, set[str]] = {
    "pe_dynamic_resolve": {"loadlibrary", "loadlibraryex", "getprocaddress"},
    "pe_antidebug_imports": {"isdebuggerpresent", "outputdebugstringa"},
}


def _reproducible(pe: Any) -> bool:
    """A reproducible / deterministic build (debug entry IMAGE_DEBUG_TYPE_REPRO):
    the linker writes a hash where the compile timestamp would be."""
    try:
        return any(getattr(d.struct, "Type", None) == 16 for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or [])
    except Exception:  # noqa: BLE001
        return False


def _same_name(orig: str, name: str) -> bool:
    """OriginalFilename vs the file's name, tolerant of what extraction does to names:
    a prefix (resource namespace, ``<sha>_``), a cut from either end, another extension."""
    o, n = orig.lower().strip(), name.lower().strip()
    if o == n or n.endswith(o) or o.endswith(n):
        return True
    so, sn = Path(o).stem, Path(n).stem
    return len(so) >= 4 and (so in n or (len(sn) >= 6 and sn in so))


# Folders where the app names the files itself (resources, hidden payloads, carved
# data): their names are labels, not names an attacker chose.
_TOOL_DIRS = ("hidden", "dotnet_resources", "carved", "images", "stego")


def _tool_named(rel: str) -> bool:
    parts = Path(rel).parts[:-1]
    return any(p in _TOOL_DIRS for p in parts)


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


def _is_pyinstaller(path: Path) -> bool:
    """True if the PyInstaller CArchive cookie is in the file tail (same check
    as analyze.py). FLOSS/capa are skipped then: they only see the bootloader."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            fh.seek(max(0, size - _PYI_TAIL))
            return _PYI_MAGIC in fh.read()
    except OSError:
        return False


def _run_tool(name: str, exe: Path | None, args: list[str], path: Path,
              timeout: int) -> tuple[dict[str, Any], str]:
    """Run a standalone tool binary on ``path``. Returns (status record, stdout).

    The record always has ``status`` (ok / not_provisioned / timeout / error)
    and a human ``detail``, so the Binary tab can say why a result is missing.
    Failures are logged; never raises.
    """
    from ..proctools import run_bounded

    if exe is None:
        return ({"status": "not_provisioned",
                 "detail": f"{name} not provisioned (tools/{name}/) — run "
                           f"scripts/setup_portable_python.py"}, "")
    # Hard limit + whole-tree kill: floss.exe / capa.exe are PyInstaller onefile
    # (bootloader + child); a plain subprocess.run could hang on the orphan.
    r = run_bounded([str(exe), *args, str(path)], timeout)
    if r.get("timed_out"):
        log.warning("%s timed out after %ss on %s", name, timeout, path.name)
        return ({"status": "timeout", "detail": f"{name} timed out after {timeout}s",
                 "duration_s": r.get("duration_s", timeout)}, "")
    if r.get("error"):
        log.warning("%s could not run on %s: %s", name, path.name, r["error"])
        return {"status": "error", "detail": f"{name} could not run: {r['error']}"}, ""
    rec: dict[str, Any] = {"status": "ok", "returncode": r["rc"], "duration_s": r["duration_s"]}
    if r["rc"] != 0 or not (r.get("out") or "").strip():
        err = (r.get("err") or "").strip()[-400:]
        log.warning("%s failed on %s (exit %s): %s", name, path.name, r["rc"], err)
        rec.update(status="error",
                   detail=f"{name} exited {r['rc']}" + (f": {err}" if err else ""))
        return rec, ""
    return rec, r["out"]


# --- FLOSS + capa scheduling -----------------------------------------------------
# Both tools analyse the whole binary on their own (vivisect), so on one PE they
# run at the same time, and the PEs of a nested batch are started ahead
# (``prefetch``) on a small pool while the rest of the scan goes on: when the
# PE triage reaches its tools the results are usually ready. The pool size is
# bounded (each binary = 2 tool processes; vivisect is memory-hungry):
# DOCUTRACEX_TOOLS_PARALLEL binaries at once (default 2, never above CPUs - 1).
import threading as _threading  # noqa: E402
from concurrent.futures import Future, ThreadPoolExecutor  # noqa: E402

_pool: ThreadPoolExecutor | None = None
_pending: dict[str, Future] = {}
_lock = _threading.Lock()
PREFETCH_MAX = 64


def _tools_workers() -> int:
    from ..objects import workers
    try:
        cap = int(_os.environ.get("DOCUTRACEX_TOOLS_PARALLEL", "2"))
    except ValueError:
        cap = 2
    return workers(cap, cap)


# Large binaries: FLOSS's "tight strings" (emulating every tight loop) is what
# takes minutes; above this size it is skipped (decoded + stack strings stay).
FLOSS_LARGE_BYTES = int(_os.environ.get("DOCUTRACEX_FLOSS_LARGE_MB", "15")) * 1024 * 1024
FLOSS_LARGE_ARGS = ["--no", "tight"]
# Valid Authenticode from these publishers = library / runtime code (python3x.dll,
# vcruntime, Qt…): FLOSS / capa would spend minutes on code nobody suspects.
# DOCUTRACEX_TOOLS_SKIP_TRUSTED=0 analyses them anyway.
TRUSTED_PUBLISHERS = (
    "Microsoft Corporation", "Microsoft Windows", "Python Software Foundation", "Oracle America", "Google LLC",
    "Mozilla Corporation", "Adobe Inc.", "Intel Corporation", "NVIDIA Corporation", "VMware, Inc.", "Broadcom Inc.",
    "The Qt Company", "Apple Inc.", "Dell Inc.", "Cisco Systems", "Amazon.com Services LLC", "JetBrains s.r.o.",
    "OpenJS Foundation", "Node.js Foundation", "Advanced Micro Devices", "Citrix Systems", "Zoom Video Communications",
)


def _trusted_signer(path: Path) -> str | None:
    """Publisher name when ``path`` has a VALID Authenticode signature from a
    trusted publisher (verified by Windows; elsewhere nothing is skipped)."""
    if _os.environ.get("DOCUTRACEX_TOOLS_SKIP_TRUSTED", "1") == "0":
        return None
    try:
        from . import authenticode
        res = authenticode.verify(path)
    except Exception:  # noqa: BLE001
        return None
    if res.get("status") != "valid":
        return None
    subj = str((res.get("signer") or {}).get("subject") or "")
    org = next((v.strip() for k, v in (x.split("=", 1) for x in subj.split(",") if "=" in x)
                if k.strip().upper() in ("O", "CN") and any(t.lower() == v.strip().lower() for t in TRUSTED_PUBLISHERS)), None)
    return org


def _tool_id(exe: Path | None) -> str:
    try:
        st = exe.stat() if exe else None
        return f"{exe.name}:{st.st_size}:{int(st.st_mtime)}" if st else "none"
    except OSError:
        return "none"


def _cache_file(sha: str, tool: str) -> Path:
    from ..config import settings
    return Path(settings.cases_dir) / ".tools_cache" / sha[:2] / f"{sha}.{tool}.json"


def _cache_get(path: Path, tool: str, exe: Path | None, extra: list[str]) -> dict[str, Any] | None:
    import json
    sha = _sha(path)
    if not sha:
        return None
    try:
        got = json.loads(_cache_file(sha, tool).read_text(encoding="utf-8"))
        if got.get("_key") == f"{_tool_id(exe)}|{' '.join(extra)}":
            rec = got["record"]
            rec["cached"] = True
            return rec
    except (OSError, ValueError, KeyError):
        pass
    return None


def _cached(path: Path, tool: str, exe: Path | None, extra: list[str], run) -> dict[str, Any]:  # noqa: ANN001
    """A FLOSS / capa result by SHA-256 across cases (same tool build, same
    options): a re-analysis, or the same DLL in another case, is instant."""
    import json
    sha = _sha(path)
    key = f"{_tool_id(exe)}|{' '.join(extra)}"
    f = _cache_file(sha, tool) if sha else None
    got = _cache_get(path, tool, exe, extra)
    if got is not None:
        return got
    rec = run()
    if f is not None and rec.get("status") == "ok":
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            tmp = f.with_suffix(".tmp")
            tmp.write_text(json.dumps({"_key": key, "record": rec}, default=str), encoding="utf-8")
            tmp.replace(f)
        except OSError:
            pass
    return dict(rec)


def _both(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """FLOSS and capa on one binary: from the cache when this exact file was
    analysed before, skipped for libraries signed by a trusted publisher, else
    both at the same time (two processes), FLOSS without tight strings on large files."""
    from ..config import settings
    pub = _trusted_signer(path)
    if pub:
        why = (f"signed by {pub} (valid Authenticode): library / runtime code — FLOSS/capa skipped to save time "
               f"(DOCUTRACEX_TOOLS_SKIP_TRUSTED=0 analyses it)")
        return {"status": "skipped", "detail": why, "trusted_signer": pub}, \
               {"status": "skipped", "detail": why, "trusted_signer": pub}
    try:
        large = path.stat().st_size > FLOSS_LARGE_BYTES
    except OSError:
        large = False
    fextra = FLOSS_LARGE_ARGS if large else []
    if large and _cache_get(path, "floss_full", settings.floss_executable(), []) is not None:
        fextra = []                     # the analyst already ran the full FLOSS on it: reuse that
    with ThreadPoolExecutor(max_workers=2) as ex:
        ff = ex.submit(_cached, path, "floss_full" if large and not fextra else "floss", settings.floss_executable(),
                       fextra, lambda: _run_floss(path, fextra) if fextra else _run_floss(path))
        cf = ex.submit(_cached, path, "capa", settings.capa_executable(), [], lambda: _run_capa(path))
        floss = ff.result()
        if large and fextra and floss.get("status") == "ok":
            floss["note"] = (f"large file (> {FLOSS_LARGE_BYTES // 1048576} MB): tight strings skipped on the "
                             "whole file (decoded and stack strings extracted); the code analysis runs them on "
                             "its priority functions")
            floss["tight_skipped"] = True
        return floss, cf.result()


PRIORITY_TIGHT_MAX = int(_os.environ.get("DOCUTRACEX_FLOSS_PRIORITY_FUNCS", "128") or 128)


def tight_on_functions(path: Path, addrs: list[int]) -> dict[str, Any]:
    """FLOSS tight strings of only these functions (``--only tight --functions``):
    what a large file skipped on the whole binary, recovered where it matters.
    Cached by SHA-256 + function list like the full run."""
    from ..config import settings
    addrs = sorted(set(int(a) for a in addrs))[:PRIORITY_TIGHT_MAX]
    if not addrs:
        return {"status": "skipped", "detail": "no priority function"}
    hexes = [hex(a) for a in addrs]

    def run() -> dict[str, Any]:
        # FLOSS releases call the filter --functions; newer builds --analyze-functions
        r = _run_floss(path, ["--only", "tight", "--functions", *hexes])
        if r.get("status") == "error" and "unrecognized arguments" in str(r.get("detail") or ""):
            r = _run_floss(path, ["--only", "tight", "--analyze-functions", *hexes])
        return r
    extra = ["--only", "tight", "--functions", *hexes]
    rec = _cached(path, "floss_tight", settings.floss_executable(), extra, run)
    rec.pop("strings", None)
    rec["functions"] = len(addrs)
    return rec


def full_floss(path: Path) -> dict[str, Any]:
    """FLOSS with every string type on a file that was too large for the
    automatic run (tight strings included). Cached: the next analysis of the
    file reuses it instead of the lighter run."""
    from ..config import settings
    return _cached(path, "floss_full", settings.floss_executable(), [], lambda: _run_floss(path))


def _sha(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _worth_prefetch(path: Path) -> bool:
    """A PE whose tools will most likely run: not PyInstaller, not obviously
    packed (an executable section near entropy 8), not huge. A wrong guess only
    costs a background run; the triage still decides."""
    try:
        if path.stat().st_size > 64 * 1024 * 1024 or _is_pyinstaller(path):
            return False
        import pefile
        pe = pefile.PE(str(path), fast_load=True)
        try:
            if getattr(pe, "OPTIONAL_HEADER", None) is None:
                return False
            for sec in pe.sections:
                if sec.Characteristics & 0x20000000 and sec.SizeOfRawData > 4096 and sec.get_entropy() > 7.3:
                    return False
            return True
        finally:
            pe.close()
    except Exception:  # noqa: BLE001
        return False


def _tools_available() -> bool:
    from ..config import settings
    return settings.floss_executable() is not None or settings.capa_executable() is not None


def prefetch(paths: list[Path]) -> int:
    """Start FLOSS + capa in the background for the PEs of a batch that is about
    to be scanned. Returns how many were queued."""
    if not _tools_available():
        return 0
    global _pool
    n = 0
    for p in paths:
        try:
            with Path(p).open("rb") as fh:
                if fh.read(2) != b"MZ":
                    continue
        except OSError:
            continue
        if not _worth_prefetch(Path(p)):
            continue
        sha = _sha(Path(p))
        with _lock:
            if not sha or sha in _pending or len(_pending) >= PREFETCH_MAX:
                continue
            if _pool is None:
                _pool = ThreadPoolExecutor(max_workers=_tools_workers(), thread_name_prefix="floss-capa")
            _pending[sha] = _pool.submit(_both, Path(p))
            n += 1
    return n


def tools_for(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """FLOSS + capa records of one PE: the prefetched run if there is one
    (waiting for it), else both now, concurrently."""
    sha = _sha(path)
    with _lock:
        fut = _pending.pop(sha, None) if sha else None
    if fut is not None:
        try:
            floss, capa = fut.result()
            floss = dict(floss)
            if "strings" in floss:
                floss["strings"] = list(floss["strings"])
            floss["prefetched"] = capa["prefetched"] = True
            return floss, dict(capa)
        except Exception as exc:  # noqa: BLE001
            log.warning("prefetched FLOSS/capa failed on %s: %s", path.name, exc)
    return _both(path)


def _run_floss(path: Path, extra: list[str] | None = None) -> dict[str, Any]:
    """FLOSS (standalone binary): static / decoded / stack / tight strings.
    Returns a status record plus ``strings`` (list[str]) when it ran."""
    import json

    from ..config import settings

    exe = settings.floss_executable()
    args = ["--json", "--quiet", *FLOSS_EXTRA_ARGS, *(extra or [])]
    # "--" before the sample: --no / --only / --analyze-functions take several
    # values (nargs="+") and would swallow the path otherwise
    rec, out = _run_tool("floss", exe, [*args, "--"], path, FLOSS_TIMEOUT)
    retry_note = ""
    if rec["status"] == "error" and _floss_language_crash(rec.get("detail") or ""):
        # Only this known crash is retried (never a timeout, a missing tool or
        # any other error), and only once.
        first = rec.get("detail") or ""
        log.info("floss: language-specific string extraction crashed on %s; "
                 "retrying with --language none", path.name)
        rec, out = _run_tool("floss", exe, [*args, *FLOSS_NO_LANGUAGE_ARGS, "--"], path, FLOSS_TIMEOUT)
        if rec["status"] != "ok":
            rec["detail"] = (f"{rec.get('detail') or 'floss failed'} (retried with --language none "
                             f"after a Go/Rust string extraction crash; first run: {first[-160:]})")
            return rec
        retry_note = ("Go/Rust (language-specific) string extraction crashed in FLOSS, "
                      "so it ran again without it (--language none)")
    if rec["status"] != "ok":
        return rec
    try:
        data = json.loads(out)
    except ValueError as exc:
        log.warning("floss returned non-JSON output on %s: %s", path.name, exc)
        rec.update(status="error", detail=f"floss output is not JSON ({exc})")
        return rec
    strings: list[str] = []
    counts: dict[str, int] = {}
    block = data.get("strings") or {}
    # FIX: include static_strings — previously omitted, causing the bulk of
    # FLOSS output to be silently discarded. decoded/stack/tight are kept too.
    for key in ("static_strings", "decoded_strings", "stack_strings", "tight_strings"):
        vals = [s.get("string") if isinstance(s, dict) else s for s in (block.get(key) or [])]
        vals = [v for v in vals if isinstance(v, str) and v.strip()]
        counts[key.split("_")[0]] = len(vals)
        strings.extend(vals)
    rec["counts"] = counts
    # decoded / stack / tight strings with the function that builds or decodes
    # them, so the code analysis can show them next to that function
    located = []
    for key in ("decoded_strings", "stack_strings", "tight_strings"):
        for s in block.get(key) or []:
            if isinstance(s, dict) and isinstance(s.get("string"), str) and s["string"].strip():
                fn = s.get("function") if isinstance(s.get("function"), int) else s.get("decoding_routine")
                located.append({"kind": key.split("_")[0], "string": s["string"][:500],
                                "function": fn if isinstance(fn, int) else None,
                                "routine": s.get("decoding_routine") if isinstance(s.get("decoding_routine"), int) else None})
    if located:
        rec["located"] = located[:5000]
    rec["version"] = str((data.get("metadata") or {}).get("version") or "")
    # FIX: detail now reflects all four categories including static
    rec["detail"] = (f"{len(strings)} string(s): {counts.get('static', 0)} static, "
                     f"{counts.get('decoded', 0)} decoded, "
                     f"{counts.get('stack', 0)} stack, "
                     f"{counts.get('tight', 0)} tight")
    if retry_note:
        rec["detail"] += f" · {retry_note}"
        rec["language_strings"] = "disabled (crashed)"
    rec["strings"] = strings
    return rec


def _floss_language_crash(detail: str) -> bool:
    """True when FLOSS died in its language-specific (Go / Rust) string
    extraction — the one failure worth a retry with ``--language none``."""
    d = detail.lower()
    return any(m.lower() in d for m in _FLOSS_LANGUAGE_CRASH)


def _run_capa(path: Path) -> dict[str, Any]:
    """capa (standalone binary, embedded rules): matched capabilities with their
    namespace, ATT&CK and MBC ids. Returns a status record plus
    ``capabilities`` (list of dicts) when it ran."""
    import json

    from ..config import settings

    rec, out = _run_tool("capa", settings.capa_executable(), ["-j", "-q"], path, CAPA_TIMEOUT)
    if rec["status"] != "ok":
        return rec
    try:
        data = json.loads(out)
    except ValueError as exc:
        log.warning("capa returned non-JSON output on %s: %s", path.name, exc)
        rec.update(status="error", detail=f"capa output is not JSON ({exc})")
        return rec
    caps: list[dict[str, Any]] = []
    for name, rm in (data.get("rules") or {}).items():
        meta = (rm or {}).get("meta") or {}
        # capa's JSON uses field names (lib, is_subscope_rule, attack); accept
        # the rule-file aliases too in case a future version dumps by alias.
        if (meta.get("lib") or meta.get("is_subscope_rule")
                or meta.get("capa/subscope-rule")):
            continue  # helper rules, not capabilities
        attack = [{"id": a.get("id", ""), "tactic": a.get("tactic", ""),
                   "technique": a.get("technique", ""), "subtechnique": a.get("subtechnique", "")}
                  for a in (meta.get("attack") or meta.get("att&ck") or []) if isinstance(a, dict)]
        mbc = [m.get("id", "") for m in (meta.get("mbc") or []) if isinstance(m, dict)]
        caps.append({"name": meta.get("name") or name,
                     "namespace": meta.get("namespace") or "",
                     "attack": attack, "mbc": [m for m in mbc if m],
                     "matches": len((rm or {}).get("matches") or [])})
    caps.sort(key=lambda c: (c["namespace"], c["name"]))
    meta = data.get("meta") or {}
    rec["version"] = str(meta.get("version") or "")
    rec["total"] = len(caps)
    rec["attack_ids"] = sorted({a["id"] for c in caps for a in c["attack"] if a["id"]})
    rec["capabilities"] = caps[:_CAPA_MAX_RULES]
    rec["detail"] = (f"{len(caps)} capabilit{'y' if len(caps) == 1 else 'ies'}, "
                     f"{len(rec['attack_ids'])} ATT&CK technique(s)")
    return rec


# Namespaces whose capabilities are worth more than "info" in triage.
_CAPA_HIGH_NS = ("anti-analysis", "host-interaction/process/inject", "persistence",
                 "collection/keylog", "impact", "load-code/shellcode")
_CAPA_MEDIUM_NS = ("communication", "host-interaction/process/create", "data-manipulation/encryption",
                   "load-code", "linking/runtime-linking", "executable/installer",
                   "host-interaction/registry", "host-interaction/service")


def _capa_severity(cap: dict[str, Any]) -> str:
    ns = (cap.get("namespace") or "").lower()
    if any(ns.startswith(p) for p in _CAPA_HIGH_NS):
        return "medium"
    if any(ns.startswith(p) for p in _CAPA_MEDIUM_NS) or cap.get("attack"):
        return "low"
    return "info"
