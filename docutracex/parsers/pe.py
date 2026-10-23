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
  version-info masquerade check (OriginalFilename vs the real name).

With **FLOSS** and **capa** provisioned (optional; Mandiant's standalone
binaries under ``tools/floss/`` and ``tools/capa/``) the obfuscated/stack/tight
strings FLOSS decodes are mined for IOCs, and capa's matched capabilities become
findings with their ATT&CK technique. Both are skipped for PyInstaller bundles
and packed/protected PEs (they would only see the stub; when unpacked, they run
on the unpacked file instead). Each run leaves a status record (ok / skipped /
not provisioned / timeout / error) so a missing result is never silent. The
sample never runs natively: capa is static; FLOSS emulates decoding routines
(vivisect) to recover strings.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

_MAX_BYTES = 64 * 1024 * 1024

# External static tools (FLOSS / capa): per-run time limits and output caps.
import os as _os

FLOSS_TIMEOUT = int(_os.environ.get("DOCUTRACEX_FLOSS_TIMEOUT", "1200"))   # 20 min
# FLOSS arguments (besides --json / --no static / --quiet, which the parser needs):
# --large-file lifts FLOSS's 16 MB limit; -n 8 = minimum string length.
FLOSS_EXTRA_ARGS = ["--large-file", "-n", "7"]
CAPA_TIMEOUT = int(_os.environ.get("DOCUTRACEX_CAPA_TIMEOUT", "1800"))   # 30 min
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
    unpacked (its files come back in ``item["_unpacked_files"]`` — the caller
    pops them and scans them as children). ``tools_budget_ok=False`` skips
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

    # --- packer / installer: detect, then unpack STATICALLY (first, so the real
    # code is what FLOSS/capa/YARA/IOCs see). PyInstaller has its own pipeline.
    is_pyi = _is_pyinstaller(path)
    up: dict[str, Any] = {}
    if not is_pyi:
        from . import unpack
        try:
            up = unpack.process(path, blob, pe, unpack_dir if run_tools else None,
                                use_die=run_tools)
        except Exception as exc:  # noqa: BLE001  (never break the PE triage)
            log.warning("packer detection/unpacking failed on %s: %s", rel, exc)
            up = {"status": "error", "detail": str(exc), "detected": [], "findings": []}
        files = up.pop("_files", [])
        if files:
            item["_unpacked_files"] = files
        for x in up.get("findings", []):
            x["location"] = loc
            f.append(x)
        item["unpack"] = {k: v for k, v in up.items() if k != "findings"}

    # --- optional external static tools: FLOSS (strings) + capa (capabilities) ---
    if run_tools:
        skip_why = ""
        if is_pyi:
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
            floss = _run_floss(path)
            floss_strings = floss.pop("strings", [])
            item["floss"] = floss
            if floss_strings:
                item["floss_strings"] = floss_strings[:_FLOSS_MAX_STRINGS]
                strings_for_ioc.extend(floss_strings)
                f.append(_finding("pe_floss_strings", "info",
                    f"FLOSS decoded {len(floss_strings)} obfuscated/stack/tight string(s)", loc))

            capa = _run_capa(path)
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


def _run_floss(path: Path) -> dict[str, Any]:
    """FLOSS (standalone binary): decoded / stack / tight strings, no static
    strings (pe.py already has those). Returns a status record plus
    ``strings`` (list[str]) when it ran."""
    import json

    from ..config import settings

    rec, out = _run_tool("floss", settings.floss_executable(),
                         ["--json", "--quiet", *FLOSS_EXTRA_ARGS],
                         path, FLOSS_TIMEOUT)
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
    for key in ("decoded_strings", "stack_strings", "tight_strings"):
        vals = [s.get("string") if isinstance(s, dict) else s for s in (block.get(key) or [])]
        vals = [v for v in vals if isinstance(v, str) and v.strip()]
        counts[key.split("_")[0]] = len(vals)
        strings.extend(vals)
    rec["counts"] = counts
    rec["version"] = str((data.get("metadata") or {}).get("version") or "")
    rec["detail"] = (f"{len(strings)} string(s): {counts.get('decoded', 0)} decoded, "
                     f"{counts.get('stack', 0)} stack, {counts.get('tight', 0)} tight")
    rec["strings"] = strings
    return rec


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
