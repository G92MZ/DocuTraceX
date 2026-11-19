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

import hashlib
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


def _verify_msi_authenticode(path: Path) -> dict[str, Any]:
    """Verify the MSI package with the shared Windows Authenticode layer."""
    from . import authenticode
    return authenticode.verify(path)


def _msi_signature_findings(signature: dict[str, Any], loc: str) -> list[dict[str, Any]]:
    from . import authenticode
    return authenticode.findings(signature, loc, tool="msi")


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


# Interpreters and script hosts: an installer that runs one of them on a file it ships is running a
# script in disguise (a "Setup notice" HTML that is a Python program, an .a3x, a .jar…).
INTERPRETERS = {
    "python.exe": "Python", "pythonw.exe": "Python", "py.exe": "Python", "pyw.exe": "Python",
    "node.exe": "Node.js", "bun.exe": "Bun", "deno.exe": "Deno",
    "java.exe": "Java", "javaw.exe": "Java", "dotnet.exe": ".NET",
    "autoit3.exe": "AutoIt", "autoit3_x64.exe": "AutoIt", "autohotkey.exe": "AutoHotkey",
    "autohotkey64.exe": "AutoHotkey", "autohotkeyu64.exe": "AutoHotkey", "autohotkeyu32.exe": "AutoHotkey",
    "lua.exe": "Lua", "luajit.exe": "Lua", "wlua.exe": "Lua", "ruby.exe": "Ruby", "rubyw.exe": "Ruby",
    "perl.exe": "Perl", "wperl.exe": "Perl", "php.exe": "PHP", "php-win.exe": "PHP", "tclsh.exe": "Tcl",
    "wish.exe": "Tcl", "rscript.exe": "R", "julia.exe": "Julia",
    "powershell.exe": "PowerShell", "pwsh.exe": "PowerShell", "wscript.exe": "Windows Script Host",
    "cscript.exe": "Windows Script Host", "mshta.exe": "HTML Application host", "cmd.exe": "cmd",
    "rundll32.exe": "rundll32", "regsvr32.exe": "regsvr32", "msbuild.exe": "MSBuild",
    "installutil.exe": "InstallUtil", "regasm.exe": "RegAsm", "msxsl.exe": "msxsl",
}
_CA_BASE = {1: "DLL in the Binary table", 2: "EXE in the Binary table", 5: "JScript in the Binary table",
            6: "VBScript in the Binary table", 7: "nested installation", 17: "DLL installed with the product",
            18: "EXE installed with the product", 19: "error message", 21: "JScript file installed with the product",
            22: "VBScript file installed with the product", 23: "nested installation", 34: "command line",
            35: "sets a directory", 37: "inline JScript", 38: "inline VBScript", 39: "nested installation",
            50: "EXE named by a property", 51: "sets a property", 53: "JScript in a property", 54: "VBScript in a property"}
# Binary-table DLLs the usual installer builders ship (Visual Studio setup projects, WiX, InstallShield, Advanced
# Installer): their entry points check prerequisites and set folders
_STD_CA_DLL = re.compile(r"(?i)^(?:MSVBDPCADLL|VSDNETCFG|WixCA|WixUIWixca|Wix4.*|InstallShield|ISSetupAllLanguages|"
                         r"aicustact|AICustAct|viewer\.exe|ExternalUICleaner|SoftwareDetector|PowerShellScriptLauncher|"
                         r"ISChainerLauncher|ISBEW64|NetFxCA|UtilCA|IISCA|SqlCA|FirewallCA|DependencyCA|BalExtension)$")
_PROP = re.compile(r"\[([A-Za-z_][\w.]*)\]")


def _resolve(text: str, props: dict[str, str], files: dict[str, str], depth: int = 0) -> str:
    """[PROPERTY] / [#FileKey] / [!FileKey] references expanded where the tables say."""
    if not text or depth > 4:
        return text or ""

    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        return _resolve(props[name], props, files, depth + 1) if name in props else m.group(0)
    text = re.sub(r"\[[#!]([\w.]+)\]", lambda m: f"[{files.get(m.group(1), m.group(1))}]", text)
    return _PROP.sub(sub, text)


def _sideloading(t: dict[str, Any], files: dict[str, str], actions: list[dict[str, Any]],
                 loc: str) -> list[dict[str, Any]]:
    """A Windows system library's name installed in the same folder as a program the
    package installs (``version.dll`` next to ``App.exe``): DLL side-loading. Names only
    here; the bytes (signature, proxy exports) are judged when the files are extracted."""
    from ..sideload import SYSTEM_DLLS
    comp_dir = {str(r.get("Component") or ""): str(r.get("Directory_") or "") for r in t.get("Component") or []}
    by_dir: dict[str, list[str]] = {}
    for r in t.get("File") or []:
        name = str(r.get("FileName") or "").split("|")[-1]
        by_dir.setdefault(comp_dir.get(str(r.get("Component_") or ""), "?"), []).append(name)
    out = []
    for d, names in by_dir.items():
        low = [n.lower() for n in names]
        dlls = [n for n in names if n.lower() in SYSTEM_DLLS]
        exes = [n for n, lo in zip(names, low) if lo.endswith(".exe")]
        if not dlls or not exes:
            continue
        run = [a for a in actions if any(e.lower() in (a["runs"] or "").lower() for e in exes)]
        sev = "high" if run else "medium"
        out.append(_finding("msi_dll_sideloading", sev,
                            f"installs {', '.join(dlls[:3])} (Windows system library name) in the same folder as "
                            f"{', '.join(exes[:3])}: the program loads it from there instead of System32"
                            + (f"; the installer then runs it ({run[0]['action']})" if run else ""),
                            loc, f"directory {d}: " + ", ".join(names[:30]), "T1574.002"))
    return out


def _custom_actions(path: Path, item: dict[str, Any], loc: str) -> list[dict[str, Any]] | None:
    """Findings from the CustomAction table read as rows (None when the tables cannot be read)."""
    from . import msidb
    t = msidb.read_tables(path, ("CustomAction", "Property", "File", "Binary", "Shortcut", "Registry",
                                 "InstallExecuteSequence", "Component"))
    if not t or not (t.get("CustomAction") or t.get("File") or t.get("Property")):
        return None
    props = {str(r.get("Property") or ""): str(r.get("Value") or "") for r in t.get("Property") or []}
    for r in t.get("CustomAction") or []:            # type 51 / 35: a property / directory set by an action
        if (int(r.get("Type") or 0) & 0x3F) in (51, 35) and r.get("Source") and r.get("Source") not in props:
            props[str(r["Source"])] = str(r.get("Target") or "")
    files = {str(r.get("File") or ""): str(r.get("FileName") or "").split("|")[-1] for r in t.get("File") or []}
    item["installed_files"] = [{"key": k, "name": v} for k, v in files.items()][:500]
    out: list[dict[str, Any]] = []
    actions = []
    for r in t.get("CustomAction") or []:
        typ = int(r.get("Type") or 0)
        base = typ & 0x3F
        src, tgt = str(r.get("Source") or ""), str(r.get("Target") or "")
        what = _CA_BASE.get(base, f"type {typ}")
        if base in (19, 35, 51):
            actions.append({"action": r.get("Action"), "type": typ, "what": what, "runs": "", "severity": "info"})
            continue
        if base == 50:
            runs = f"{_resolve('[' + src + ']', props, files)} {_resolve(tgt, props, files)}".strip()
        elif base == 34:
            runs = _resolve(tgt, props, files)
        elif base == 18:
            runs = f"{files.get(src, src)} {_resolve(tgt, props, files)}".strip()
        elif base in (1, 2, 5, 6, 17, 21, 22):
            runs = f"{files.get(src, src)} :: {tgt}"
        elif base in (37, 38, 53, 54):
            runs = _resolve(tgt if base in (37, 38) else props.get(src, tgt), props, files)
        else:
            runs = f"{src} {tgt}".strip()
        sev = "low"
        if base in (1, 2) and _STD_CA_DLL.match(src):
            sev = "info"
        elif base in (37, 38, 53, 54) or _SUSP.search(runs) or (_LOLBIN.search(runs) and not re.search(
                r"(?i)\bmsiexec(?:\.exe)?\W+/[ix]\s+\"?\[?[\w\\.:\[\] -]+\.msi", runs)):
            sev = "high"
        elif base in (2, 18, 34, 50):
            sev = "medium"
        actions.append({"action": r.get("Action"), "type": typ, "what": what, "runs": runs[:400], "severity": sev})
    item["custom_actions"] = actions[:200]
    # an interpreter the package installs, run on a file it also installs: a script in disguise
    shipped = {v.lower(): k for k, v in files.items()}
    for a in actions:
        m = re.search(r"(?i)([\w.-]+\.exe)\"?\s+\"?(?:\[[\w.]+\]|[a-z]:\\[^\"]*\\|)?([\w .-]+\.\w{1,8})\"?", a["runs"] or "")
        if not m:
            continue
        exe, arg = m.group(1).lower(), m.group(2).strip().lower()
        if exe in INTERPRETERS and exe in shipped:
            lang = INTERPRETERS[exe]
            stream = shipped.get(arg, "")
            a["severity"] = "high"
            out.append(_finding("msi_embedded_interpreter", "high",
                                f"embedded {lang} interpreter ({m.group(1)}) shipped and run by the installer on "
                                f"'{m.group(2).strip()}'" + (f" (stream {stream})" if stream else "")
                                + " — a script in disguise, whatever its extension", loc,
                                f"custom action {a['action']} (type {a['type']}): {a['runs']}", "T1059"))
            item.setdefault("embedded_interpreters", []).append(
                {"interpreter": lang, "exe": m.group(1), "file": m.group(2).strip(), "stream": stream, "action": a["action"]})
    out.extend(_sideloading(t, files, actions, loc))
    nested_msi = [a for a in actions if re.search(r"(?i)msiexec(?:\.exe)?\W+/i", a["runs"] or "")]
    if nested_msi and item.get("embedded_interpreters"):
        out.append(_finding("msi_decoy_installer", "high",
                            "installs another MSI as a decoy while it runs its own payload: "
                            + "; ".join(a["runs"][:120] for a in nested_msi[:3]), loc, "", "T1036"))
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    worst = max((a["severity"] for a in actions), key=lambda x: rank[x], default="info")
    if actions:
        shown = sorted(actions, key=lambda a: -rank[a["severity"]])[:12]
        out.append(_finding("msi_custom_action", worst,
                            f"{len(actions)} custom action(s); " + (
                                "the riskiest: " + ", ".join(f"{a['action']} ({a['what']})" for a in shown[:3])
                                if worst != "info" else "only the installer builder's own (folders, prerequisites, properties)"),
                            loc, "\n".join(f"{a['action']} [{a['what']}, type {a['type']}]: {a['runs']}" for a in shown),
                            "T1218.007" if worst != "info" else ""))
        # the commands go through the scripting engine (LOLBins, downloads, encoded PowerShell…)
        cmds = [a["runs"] for a in actions if a["severity"] in ("medium", "high") and a["runs"]
                and not re.search(r"(?i)msiexec(?:\.exe)?\W+/[ix]\s", a["runs"])]
        if cmds:
            out.extend(_scan_strings(cmds, loc))
    for r in t.get("Registry") or []:              # Run keys written by the package
        key, val = str(r.get("Key") or ""), _resolve(str(r.get("Value") or ""), props, files)
        if re.search(r"(?i)\\CurrentVersion\\Run(?:Once)?$", key):
            out.append(_finding("msi_run_key", "high" if _LOLBIN.search(val) or _SUSP.search(val) else "medium",
                                f"writes a Run key: {key} :: {r.get('Name') or '(default)'}", loc, val[:300], "T1547.001"))
    for r in t.get("Shortcut") or []:
        args = _resolve(str(r.get("Arguments") or ""), props, files)
        if args and (_LOLBIN.search(args) or _SUSP.search(args)):
            out.append(_finding("msi_shortcut_command", "high", f"shortcut {str(r.get('Name') or '').split('|')[-1]} "
                                "runs a command", loc, args[:300], "T1547.009"))
    return out


def analyze_msi(path: Path, rel: str) -> dict[str, Any]:
    item: dict[str, Any] = {"kind": "msi", "file": rel, "tables": [], "binary_streams": [],
                            "metadata": {}, "findings": []}
    loc = f"file:{rel}"
    # Verify the package's own Authenticode signature before inspecting its
    # OLE streams. This does not invoke msiexec or execute installer actions.
    signature = _verify_msi_authenticode(path)
    item["signature"] = signature
    item["signed"] = signature.get("signed")
    item["findings"].extend(_msi_signature_findings(signature, loc))
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
            # The string pool is where every table's text lives (CustomAction
            # targets, commands, URLs). In a real MSI it carries the table prefix
            # (0x4840, "!_StringData" in 7-Zip): mine it whatever the prefix.
            pool = decoded in ("_StringData", "_StringPool")
            if is_table:
                tables.add(decoded)
                if not pool:
                    continue
            if decoded.startswith("\x05"):          # SummaryInformation etc.
                continue
            # Named data streams (Binary.*, Icon.*, CABs) have no table prefix.
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
    # The tables themselves: what each custom action runs, with which file and arguments. When they
    # can be read, they replace the coarse "the table exists" / "a string in the pool" signals that
    # fire on every installer.
    structured = _custom_actions(path, item, loc)
    if structured is not None:
        f.extend(structured)
        if cabs:
            f.append(_finding("msi_embedded_cab", "info",
                              f"embedded CAB archive(s): {', '.join(cabs[:5])}", loc, "", "T1027"))
        item["_strings_sample"] = [s for s in pool_strings if _LOLBIN.search(s) or _URL.search(s)][:50]
        return item
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


def analyze_pe(path: Path, rel: str, unpack_dir: Path | None = None) -> dict[str, Any]:
    """PE image static triage (pefile) — delegated to :mod:`pe`. With
    ``unpack_dir`` a packed/installer PE is unpacked there; its files come back
    (and the debloated binary) in ``item["_children"]`` for the caller to scan as
    nested children."""
    from . import pe as pe_mod
    return pe_mod.analyze(path, rel, unpack_dir=unpack_dir)


UNPACK_DIRNAME = "unpacked"     # extracted/unpacked/<family>/…: scanned as nested children

NATIVE_MAGIC = (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def native_kind(path: Path) -> str | None:
    """'pe' / 'native' (ELF, Mach-O) by magic, else None."""
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in NATIVE_MAGIC:
        # 0xCAFEBABE is also a Java class: a Mach-O fat header has a small arch count
        if head[:4] == b"\xca\xfe\xba\xbe" and int.from_bytes(head[4:8], "big") > 30:
            return None
        return "native"
    return None


def analyze_native(path: Path, rel: str) -> dict[str, Any]:
    """ELF / Mach-O: parsed with LIEF (format, libraries, symbols, sections)."""
    from . import lief_info
    lf = lief_info.analyze(path, rel)
    item: dict[str, Any] = {"kind": "native", "file": rel, "findings": lf.pop("findings", []),
                            "format": lf.get("format", ""), "lief": lf}
    try:
        item["size"] = path.stat().st_size
    except OSError:
        pass
    if lf.get("status") != "ok":
        item["error"] = lf.get("detail", "")
    return item


def is_msi_file(path: Path) -> bool:
    """Recognise an MSI by its compound-file streams, even without an extension."""
    try:
        import olefile
        if not olefile.isOleFile(str(path)):
            return False
        ole = olefile.OleFileIO(str(path))
        try:
            # Windows Installer stores ALL its system streams (_StringData,
            # _StringPool, _Tables, _Columns, _Validation...) with the 0x4840 table
            # prefix — 7-Zip lists them as "!_StringData". Whether a name carries
            # the prefix is irrelevant here: match on the decoded names.
            names: set[str] = set()
            for entry in ole.listdir(streams=True, storages=False):
                raw = entry[-1] if isinstance(entry, list) else entry
                decoded, _is_table = decode_streamname(raw)
                names.add(decoded.lower())
            return {"_stringdata", "_stringpool", "_tables", "_columns"}.issubset(names)
        finally:
            ole.close()
    except Exception:  # noqa: BLE001
        return False


def analyze_binary(path: Path, rel: str, unpack_dir: Path | None = None) -> dict[str, Any]:
    """MSI, PE or ELF/Mach-O — by extension, then by validated content."""
    ext = path.suffix.lower()
    if ext in _MSI_EXT or is_msi_file(path):
        item = analyze_msi(path, rel)
        if unpack_dir is not None:
            from .. import unlock
            extracted = unlock.extract_msi(path, unpack_dir, location=f"file:{rel}", name=rel)
            item["extraction"] = {k: v for k, v in extracted.items() if k != "entries"}
            item["extraction"]["entries"] = [
                {k: v for k, v in e.items() if k != "file"} for e in extracted.get("entries", [])
            ]
            item["findings"].extend(extracted.get("findings", []))
            item["_children"] = [
                {"path": e["file"], "filename": Path(e["name"]).name,
                 "member": e["name"], "origin": "MSI (7-Zip extraction)"}
                for e in extracted.get("entries", []) if e.get("file")
            ]
        return item
    kind = native_kind(path)
    if kind == "native":
        item = analyze_native(path, rel)
        if unpack_dir is not None:
            _unpack_native_upx(path, rel, unpack_dir, item)
        return item
    return analyze_pe(path, rel, unpack_dir)


def _unpack_native_upx(path: Path, rel: str, unpack_dir: Path, item: dict[str, Any]) -> None:
    """ELF / Mach-O packed with UPX (Go implants, Linux bots): ``upx -d`` statically, the real
    binary analysed as a child (the PE path does the same in ``unpack.process``)."""
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return
    if b"UPX!" not in head:
        return
    from . import unpack
    rec = unpack._unpack_upx(path, unpack_dir)
    item["unpack"] = {k: v for k, v in rec.items()}
    if rec.get("status") != "ok":
        item["findings"].append({"tool": "unpack", "rule": "native_upx_not_unpacked", "severity": "low",
                                 "detail": f"UPX-packed {item.get('format') or 'binary'}: {rec.get('detail', '')}",
                                 "location": f"file:{rel}", "evidence": ""})
        return
    out = next((p for p in sorted(unpack_dir.glob(path.stem + ".unpacked*")) if p.is_file()), None)
    if out is None:
        return
    item["findings"].append({"tool": "unpack", "rule": "native_upx_unpacked", "severity": "medium",
                             "detail": f"UPX-packed {item.get('format') or 'binary'} unpacked with upx -d "
                                       f"({out.stat().st_size} bytes) · T1027.002",
                             "location": f"file:{rel}", "evidence": ""})
    item["_children"] = [{"path": str(out), "filename": out.name, "source": "unpack",
                          "origin": f"unpacked from {Path(rel).name} (upx -d)", "recipe": ["unpack", "UPX"]}]


def analyze(original: Path, extracted_dir: Path | None = None,
            modules: dict[str, Any] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "msi", "status": "ok", "items": [], "findings": []}
    ext = original.suffix.lower()
    if ext in _MSI_EXT or ext in _PE_EXT or native_kind(original) or is_msi_file(original):
        digest = hashlib.sha256(original.read_bytes()).hexdigest()[:12] if extracted_dir is not None else ""
        item = analyze_binary(original, original.name,
                              (extracted_dir / UNPACK_DIRNAME / digest)
                              if extracted_dir is not None else None)
    else:
        return res
    res["items"].append(item)
    res["findings"].extend(item.get("findings", []))
    res["counts"] = {"findings": len(res["findings"]), "items": len(res["items"])}
    if any(x["severity"] in ("high", "medium") for x in res["findings"]):
        res["status"] = "ok_with_findings"
    return res
