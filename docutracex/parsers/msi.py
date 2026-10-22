"""Windows Installer (``.msi``) and PE binaries (``.exe``/``.dll``/…).

An MSI is an **OLE/CFB compound file** holding a relational database. The parts
that execute code at install time live in a handful of tables:

- ``CustomAction`` — the actions themselves; types 0x06/0x25 run JScript/VBScript,
  0x22/0x26 run an EXE, 0x32/0x33 run a DLL entry point, 0x34 runs a command.
- ``InstallExecuteSequence`` / ``InstallUISequence`` / ``AdminExecuteSequence`` —
  *when* each custom action fires (so an attacker schedules theirs during install).
- ``Binary`` — embedded EXEs/DLLs/scripts a custom action invokes.
- ``Property`` — values such as ``CustomActionData`` carrying the real command.

MSI mangles every stream name with a base64-ish scheme (Wine's ``mapping``); we
decode it to recover the table names, flag the dangerous tables, mine the
``_StringData`` pool and ``Binary`` streams for commands/URLs/LOLBins, feed any
command line through the shared scripting engine, and note embedded CABs. All
static — nothing is installed or executed.

PE images (``.exe``/``.dll``/``.scr``/…) are **categorised and triaged**, not
statically unpacked: we record type, size and whether the bytes look like a PE,
and leave deep RE to the analyst's dedicated tools. This keeps the family honest
about what static triage can and cannot say about a compiled binary.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import script_rules

_MSI_EXT = {".msi", ".msp", ".msm"}
_PE_EXT = {".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".com"}

# Wine dlls/msi/table.c mapping: 6-bit value -> character.
_MAP = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"

_LOLBIN = re.compile(
    r"(?i)\b(?:powershell|pwsh|cmd|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|"
    r"msiexec|installutil|regasm|regsvcs|forfiles|wmic|curl|wget|conhost|cscript|jscript|vbscript)\b")
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]{4,300}")
_SUSP = re.compile(
    r"(?i)(?:DownloadString|DownloadFile|Invoke-Expression|\bIEX\b|FromBase64String|-enc(?:odedcommand)?\b|"
    r"WScript\.Shell|Shell\.Application|cmd\s*/c|powershell\s|New-Object\s+Net|bypass|hidden|GetObject)")

# CustomAction type bits (low byte) → what runs. See MSI SDK.
_CA_SOURCE = {0x00: "directory/property", 0x01: "Binary table", 0x02: "file key", 0x03: "installed file"}
_CA_KIND = {0x01: "DLL entry point", 0x02: "EXE", 0x03: "JScript", 0x04: "VBScript",
            0x05: "command (install dir)", 0x06: "command (property)", 0x07: "nested install"}


def _finding(rule: str, severity: str, detail: str, location: str = "",
             evidence: str = "", attack: str = "") -> dict[str, Any]:
    return {"tool": "msi", "rule": rule, "severity": severity,
            "detail": detail + (f" · {attack}" if attack else ""),
            "location": location, "evidence": evidence[:2000]}


def decode_streamname(name: str) -> tuple[str, bool]:
    """Decode an MSI mangled stream name. Returns (decoded, is_table)."""
    out: list[str] = []
    is_table = False
    for ch in name:
        c = ord(ch)
        if 0x3800 <= c <= 0x4840:
            if c >= 0x4800:
                idx = c - 0x4800
                if idx == 0x40:          # 0x4840: table-name sentinel
                    is_table = True
                    continue
                out.append(_MAP[idx]) if idx < 64 else out.append("?")
            else:
                c -= 0x3800
                out.append(_MAP[c & 0x3f])
                hi = (c >> 6) & 0x3f
                out.append(_MAP[hi])
        else:
            out.append(ch)
    return "".join(out), is_table


def encode_streamname(name: str, is_table: bool = False) -> str:
    """Inverse of :func:`decode_streamname` (for samples and round-trip tests)."""
    out: list[str] = []
    if is_table:
        out.append(chr(0x4840))
    i = 0
    while i < len(name):
        lo = _MAP.index(name[i])
        if i + 1 < len(name):
            hi = _MAP.index(name[i + 1])
            out.append(chr(0x3800 + lo + (hi << 6)))
            i += 2
        else:
            out.append(chr(0x4800 + lo))
            i += 1
    return "".join(out)


def _strings(blob: bytes, minlen: int = 5) -> list[str]:
    """Printable ASCII and UTF-16LE runs from a stream."""
    found: list[str] = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, blob):
        found.append(m.group().decode("latin-1"))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, blob):
        found.append(m.group().decode("utf-16-le", "replace"))
    return found


def _scan_strings(strings: list[str], loc: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    joined = "\n".join(strings)
    seen_cmd = False
    for s in strings:
        if _LOLBIN.search(s) and not seen_cmd:
            out.append(_finding("msi_lolbin_string", "high",
                                "string references a LOLBin / shell", loc, s[:400], "T1218.007"))
            # Treat the richest LOLBin string as a command for the scripting engine.
            lang = script_rules.PS if re.search(r"(?i)powershell|pwsh", s) else script_rules.BAT
            try:
                if lang == script_rules.PS:
                    from . import ps_deobf
                    r = ps_deobf.deobfuscate(s)
                    s2 = r["code"] if r.get("changed") else s
                else:
                    from . import bat_deobf
                    r = bat_deobf.deobfuscate(s)
                    s2 = r["code"] if r.get("changed") else s
            except Exception:  # noqa: BLE001
                s2 = s
            for h in script_rules.scan(s2, lang):
                out.append(_finding(h["rule"], h["severity"],
                                    h["label"].rsplit(" · ", 1)[0], loc,
                                    h.get("line", "")[:300], h.get("attack", "")))
            seen_cmd = True
    if _SUSP.search(joined):
        ev = next((s for s in strings if _SUSP.search(s)), "")
        out.append(_finding("msi_suspicious_api", "medium",
                            "download/exec indicators in the installer strings", loc, ev[:300], "T1059"))
    return out


def analyze_msi(path: Path, rel: str) -> dict[str, Any]:
    item: dict[str, Any] = {"kind": "msi", "file": rel, "tables": [], "binary_streams": [],
                            "metadata": {}, "findings": []}
    loc = f"file:{rel}"
    try:
        import olefile
    except Exception as exc:  # noqa: BLE001
        item["error"] = f"olefile unavailable: {exc}"
        return item
    if not olefile.isOleFile(str(path)):
        item["findings"].append(_finding("msi_not_ole", "high",
                                "file is not a valid MSI/OLE compound file", loc))
        return item

    ole = olefile.OleFileIO(str(path))
    try:
        tables: set[str] = set()
        bin_streams: list[str] = []
        pool_strings: list[str] = []
        cabs: list[str] = []
        for entry in ole.listdir(streams=True, storages=False):
            raw = entry[-1] if isinstance(entry, list) else entry
            decoded, is_table = decode_streamname(raw)
            if is_table:
                tables.add(decoded)
                continue
            if decoded.startswith("\x05"):          # SummaryInformation etc.
                continue
            # Named data streams (Binary.*, _StringData, CABs) have no table sentinel.
            try:
                blob = ole.openstream(entry).read()
            except Exception:  # noqa: BLE001
                continue
            head = blob[:4]
            if decoded in ("_StringData", "_StringPool"):
                pool_strings.extend(_strings(blob))
            elif head == b"MSCF":
                cabs.append(decoded)
            elif head[:2] == b"MZ":
                bin_streams.append(f"{decoded} (PE)")
            elif decoded and not decoded.startswith("_"):
                bin_streams.append(decoded)
                pool_strings.extend(_strings(blob)[:200])

        item["tables"] = sorted(tables)
        item["binary_streams"] = bin_streams[:200]

        try:
            md = ole.get_metadata()
            meta: dict[str, Any] = {}
            for attr in ("author", "title", "subject", "comments", "keywords",
                         "creating_application", "last_saved_by", "revision_number"):
                v = getattr(md, attr, None)
                if v:
                    meta[attr] = v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v)
            item["metadata"] = meta
        except Exception:  # noqa: BLE001
            pass
    finally:
        ole.close()

    f = item["findings"]
    low = {t.lower() for t in item["tables"]}
    if "customaction" in low:
        f.append(_finding("msi_custom_action", "high",
                          "CustomAction table present — runs code during install", loc,
                          "", "T1218.007"))
    if {"installexecutesequence", "installuisequence", "adminexecutesequence"} & low:
        f.append(_finding("msi_install_sequence", "medium",
                          "install sequence tables schedule custom actions", loc))
    if "binary" in low or bin_streams:
        f.append(_finding("msi_embedded_binary", "high",
                          f"embedded Binary/stream payload(s): {', '.join(bin_streams[:5]) or 'Binary table'}",
                          loc, "", "T1027.009"))
    if cabs:
        f.append(_finding("msi_embedded_cab", "medium",
                          f"embedded CAB archive(s): {', '.join(cabs[:5])}", loc, "", "T1027"))
    f.extend(_scan_strings(pool_strings, loc))
    # Aggregate the mined strings for the IOC sweep and the UI command view.
    cmd = next((s for s in pool_strings if _LOLBIN.search(s)), "")
    if cmd:
        item["_full_code"] = cmd
    item["_strings_sample"] = [s for s in pool_strings if _LOLBIN.search(s) or _URL.search(s)][:50]
    return item


def analyze_pe(path: Path, rel: str) -> dict[str, Any]:
    """PE image static triage (pefile) — delegated to :mod:`pe`."""
    from . import pe as pe_mod
    return pe_mod.analyze(path, rel)


def analyze(original: Path, extracted_dir: Path | None = None,
            modules: dict[str, Any] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "msi", "status": "ok", "items": [], "findings": []}
    ext = original.suffix.lower()
    if ext in _MSI_EXT:
        item = analyze_msi(original, original.name)
    elif ext in _PE_EXT:
        item = analyze_pe(original, original.name)
    else:
        return res
    res["items"].append(item)
    res["findings"].extend(item.get("findings", []))
    res["counts"] = {"findings": len(res["findings"]), "items": len(res["items"])}
    if any(x["severity"] in ("high", "medium") for x in res["findings"]):
        res["status"] = "ok_with_findings"
    return res
