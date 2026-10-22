"""Packer / installer detection and STATIC unpacking of PE files.

Runs first in the PE triage (``pe.analyze``), before FLOSS/capa: a UPX-packed
binary tells almost nothing until it is unpacked. The unpacked file(s) are then
analysed like any child (Nested tab: pefile, FLOSS, capa, YARA, IOCs), and
recovered scripts (AutoIt) are kept in the result so the IOC sweep mines them.

Detection: cheap byte/section heuristics (always) + Detect It Easy (``diec``,
optional). Unpacking, all static (nothing is executed), each in a separate
process with a time limit:

==================  ==========================================  ==============
family              tool                                        license
==================  ==========================================  ==============
UPX                 ``upx -d`` (+ section-name repair retry)    GPL-2.0+
AutoIt (compiled)   AutoIt-Ripper (portable Python)             MIT
Inno Setup          innoextract                                 zlib
NSIS, 7z/RAR/ZIP    7-Zip (``7z x``)                            LGPL-2.1
SFX
Nuitka onefile      nuitka-extractor                            MIT
Enigma Virtual Box  evbunpack (portable Python)                 Apache-2.0
==================  ==========================================  ==============

Every tool is downloaded at provisioning time into ``tools/`` (never committed).
Protectors with no static unpacker (Themida, VMProtect, ...) are only reported.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

UNPACK_TIMEOUT = int(os.environ.get("DOCUTRACEX_UNPACK_TIMEOUT", "300"))
DIE_TIMEOUT = 90
_MAX_LISTED = 200          # unpacked files listed in the result
_MAX_SCRIPT = 200_000      # chars of a recovered script kept in the result

# family id -> label, in unpacking priority order (outer layer first).
FAMILIES: dict[str, str] = {
    "upx": "UPX",
    "nuitka": "Nuitka onefile",
    "evb": "Enigma Virtual Box",
    "autoit": "AutoIt (compiled script)",
    "inno": "Inno Setup",
    "nsis": "NSIS installer",
    "sfx7z": "7-Zip SFX",
    "sfxrar": "RAR SFX",
    "sfxzip": "ZIP SFX",
}
INSTALLERS = {"inno", "nsis", "sfx7z", "sfxrar", "sfxzip"}

# DIE name (lowercase substring) -> family id.
_DIE_MAP = (
    ("upx", "upx"), ("nuitka", "nuitka"), ("enigma virtual box", "evb"),
    ("autoit", "autoit"), ("inno setup", "inno"), ("nullsoft", "nsis"), ("nsis", "nsis"),
    ("7-zip", "sfx7z"), ("winrar", "sfxrar"), ("rar", "sfxrar"), ("zip", "sfxzip"),
)
# DIE types that mean "this is a wrapper around the real code".
_DIE_WRAPPER_TYPES = ("packer", "protector", "cryptor", "installer", "sfx", "joiner")

_PRIORITY_EXT = {".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".com", ".msi",
                 ".au3", ".a3x", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js",
                 ".jse", ".wsf", ".hta", ".py", ".pyc", ".lnk", ".iss", ".nsi"}
_SCRIPT_EXT = {".au3", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta",
               ".py", ".iss", ".nsi"}

# Protectors / packers with no static unpacker: detected and reported only.
# (section-name substring -> label); DIE adds many more by name.
_NO_STATIC = (
    (".themida", "Themida/WinLicense"), (".winlice", "Themida/WinLicense"),
    (".vmp", "VMProtect"), ("vmp0", "VMProtect"), ("vmp1", "VMProtect"),
    (".enigma", "Enigma Protector"), ("aspack", "ASPack"), (".adata", "ASPack"),
    (".aspr", "ASProtect"), ("pec1", "PECompact"), ("pec2", "PECompact"),
    ("pecompact", "PECompact"), (".nsp0", "NsPack"), (".nsp1", "NsPack"),
    ("mpress1", "MPRESS"), (".mpress", "MPRESS"), ("petite", "PEtite"),
    (".mew", "MEW"), (".fsg", "FSG"), (".obsidium", "Obsidium"),
    (".pelock", "PELock"), (".yp", "Y0da Protector"), (".perplex", "Perplex"),
)


# --------------------------------------------------------------------------- tools

def _tools_dir() -> Path:
    from ..config import settings
    return settings.tools_dir


def _first_file(env: str, *cands: Path) -> Path | None:
    v = os.environ.get(env)
    if v and Path(v).is_file():
        return Path(v)
    for c in cands:
        if c.is_file():
            return c
    return None


def die_exe() -> Path | None:
    t = _tools_dir() / "die"
    return _first_file("DOCUTRACEX_DIEC", t / "diec.exe", t / "die" / "diec.exe", t / "diec")


def upx_exe() -> Path | None:
    t = _tools_dir() / "upx"
    return _first_file("DOCUTRACEX_UPX", t / "upx.exe", t / "upx")


def innoextract_exe() -> Path | None:
    t = _tools_dir() / "innoextract"
    return _first_file("DOCUTRACEX_INNOEXTRACT", t / "innoextract.exe", t / "innoextract")


def sevenzip_exe() -> Path | None:
    t = _tools_dir() / "7zip"
    return _first_file("DOCUTRACEX_7Z", t / "7z.exe", t / "7z", t / "7zz")


def nuitka_exe() -> Path | None:
    t = _tools_dir() / "nuitka-extractor"
    return _first_file("DOCUTRACEX_NUITKA_EXTRACTOR", t / "nuitka-extractor.exe",
                       t / "nuitka-extractor")


def _portable() -> Path | None:
    from ..config import settings
    return settings.portable_python() or Path(sys.executable)


def _has_module(name: str) -> bool:
    """Is ``name`` importable by the portable interpreter (where the tools live)?"""
    py = _portable()
    try:
        r = subprocess.run([str(py), "-I", "-c", f"import {name}"], capture_output=True,
                           timeout=30, stdin=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def tool_status() -> dict[str, str]:
    """Which unpacking tools are available (for the Dependencies panel / UI)."""
    def p(x: Path | None) -> str:
        return str(x) if x else ""
    return {"die": p(die_exe()), "upx": p(upx_exe()), "innoextract": p(innoextract_exe()),
            "7zip": p(sevenzip_exe()), "nuitka-extractor": p(nuitka_exe()),
            "autoit-ripper": "portable" if _has_module("autoit_ripper") else "",
            "evbunpack": "portable" if _has_module("evbunpack") else ""}


def _run(cmd: list[str], timeout: int, cwd: Path | None = None) -> dict[str, Any]:
    """Run a tool; never raises. Returns {rc, out, err, timed_out, duration_s, error}.
    Hard time limit with whole-process-tree kill (see :mod:`docutracex.proctools`)."""
    from ..proctools import run_bounded
    return run_bounded(cmd, timeout, cwd=cwd)


# ----------------------------------------------------------------------- detection

def _overlay_offset(pe: Any) -> int | None:
    try:
        return pe.get_overlay_data_start_offset()
    except Exception:  # noqa: BLE001
        return None


def _sfx7z_offset(blob: bytes, start: int) -> int | None:
    """Offset of a real 7z archive (signature header CRC verified) at/after ``start``."""
    sig = b"7z\xbc\xaf\x27\x1c"
    i = blob.find(sig, start)
    while i >= 0:
        h = blob[i:i + 32]
        if len(h) == 32 and zlib.crc32(h[12:32]) & 0xFFFFFFFF == struct.unpack("<I", h[8:12])[0]:
            return i
        i = blob.find(sig, i + 1)
    return None


def heuristics(blob: bytes, pe: Any | None) -> list[dict[str, str]]:
    """Cheap, dependency-free family detection. Returns [{family, label, by, evidence}]."""
    hits: list[dict[str, str]] = []

    def add(fam: str, by: str, ev: str = "") -> None:
        if not any(h["family"] == fam for h in hits):
            hits.append({"family": fam, "label": FAMILIES.get(fam, fam), "by": by, "evidence": ev})

    names: list[str] = []
    if pe is not None:
        names = [s.Name.rstrip(b"\x00").decode("latin-1", "replace") for s in pe.sections]
    lnames = [n.lower() for n in names]
    head = blob[:0x2000]
    ovl = _overlay_offset(pe) if pe is not None else None
    tail_from = ovl if ovl is not None else max(0, len(blob) - 8 * 1024 * 1024)

    # UPX: section names, or the "UPX!" marker near the headers (renamed sections).
    if any(n.startswith("upx") for n in lnames):
        add("upx", "sections", ", ".join(names[:4]))
    elif b"UPX!" in head:
        add("upx", "marker", "UPX! marker in headers (section names altered?)")
    # AutoIt: script resource / overlay markers.
    if b"AU3!EA06" in blob or b"AU3!EA05" in blob:
        add("autoit", "marker", "AU3!EA0x script marker")
    # Inno Setup
    if b"Inno Setup Setup Data" in blob or b"Inno Setup Messages" in blob or b"zlb\x1a" in blob[tail_from:tail_from + 64]:
        add("inno", "marker", "Inno Setup data marker")
    # NSIS
    if b"NullsoftInst" in blob[tail_from:] or b"Nullsoft Install System" in blob:
        add("nsis", "marker", "NullsoftInst signature")
    # Nuitka onefile (payload in an RCDATA resource; "KA" magic)
    if b"nuitka" in blob[:4_000_000].lower() or b"NUITKA_ONEFILE_PARENT" in blob:
        add("nuitka", "marker", "Nuitka strings")
    # Enigma Virtual Box
    if any(n.startswith(".enigma") for n in lnames) and b"EVB\x00" in blob:
        add("evb", "marker", "EVB\\0 header + .enigma sections")
    # Archive SFX (overlay)
    if ovl is not None:
        o = blob[ovl:ovl + 0x200]
        if _sfx7z_offset(blob, ovl) is not None:
            add("sfx7z", "overlay", "7z archive in overlay")
        elif o[:4] == b"Rar!":
            add("sfxrar", "overlay", "RAR archive in overlay")
        elif o[:4] == b"PK\x03\x04":
            add("sfxzip", "overlay", "ZIP archive in overlay")
    return hits


def no_static_hits(pe: Any | None) -> list[str]:
    """Protector/packer labels with no static unpacker (by section names)."""
    if pe is None:
        return []
    out: list[str] = []
    for s in pe.sections:
        n = s.Name.rstrip(b"\x00").decode("latin-1", "replace").lower()
        for key, label in _NO_STATIC:
            if key in n and label not in out:
                out.append(label)
    return out


def run_die(path: Path) -> dict[str, Any]:
    """Detect It Easy (diec --json). Returns {status, detects:[{type,name,version,string}]}."""
    exe = die_exe()
    if exe is None:
        return {"status": "not_provisioned", "detail": "Detect It Easy not provisioned (tools/die/)"}
    # Run from DIE's folder so it finds its db/ and Qt DLLs.
    r = _run([str(exe), "--json", str(path)], DIE_TIMEOUT, cwd=exe.parent)
    if r.get("timed_out"):
        return {"status": "timeout", "detail": f"diec timed out after {DIE_TIMEOUT}s"}
    if r.get("error") or r.get("rc") not in (0, None) and not r.get("out"):
        log.warning("diec failed on %s: %s %s", path.name, r.get("error"), r.get("err"))
        return {"status": "error", "detail": r.get("error") or f"diec exited {r.get('rc')}"}
    out = r.get("out", "")
    try:
        data = json.loads(out[out.find("{"):]) if "{" in out else {}
    except ValueError as exc:
        return {"status": "error", "detail": f"diec output is not JSON ({exc})"}
    detects: list[dict[str, str]] = []

    def walk(o: Any) -> None:  # DIE nests results per file type / sub-scan
        if isinstance(o, dict):
            if "name" in o and "type" in o:
                detects.append({k: str(o.get(k, "")) for k in ("type", "name", "version", "info", "string")})
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(data)
    return {"status": "ok", "detects": detects[:40], "duration_s": r["duration_s"]}


def die_families(die: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    """(unpackable family hits, other wrapper labels with no static unpacker) from DIE."""
    fams: list[dict[str, str]] = []
    other: list[str] = []
    for d in die.get("detects") or []:
        typ = d.get("type", "").lower()
        name = d.get("name", "")
        lname = name.lower()
        label = f"{name} {d.get('version', '')}".strip()
        fam = next((f for key, f in _DIE_MAP if key in lname), None)
        # Archive SFX names ("zip", "rar") are too generic: only trust them when
        # DIE files them as an SFX / overlay / archive / installer.
        if fam in ("sfxrar", "sfxzip", "sfx7z") and not any(
                t in typ for t in ("sfx", "overlay", "archive", "installer")):
            fam = None
        if fam:
            if not any(x["family"] == fam for x in fams):
                fams.append({"family": fam, "label": label, "by": "die", "evidence": d.get("string", "")})
        elif any(t in typ for t in _DIE_WRAPPER_TYPES) and label not in other:
            other.append(label)
    return fams, other


# ----------------------------------------------------------------------- unpackers

def _list_files(root: Path) -> list[Path]:
    """Extracted files, scripts/PEs first then by size (largest first), capped."""
    if not root.is_dir():
        return []
    files = [p for p in root.rglob("*") if p.is_file() and not p.is_symlink()]

    def key(p: Path) -> tuple[int, int]:
        return (0 if p.suffix.lower() in _PRIORITY_EXT else 1, -p.stat().st_size)
    return sorted(files, key=key)


def _safe_copy(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return dst


def _strip_signature(src: Path, dst: Path) -> bool:
    """Copy ``src`` to ``dst`` without its Authenticode blob (nuitka-extractor
    does not support signed PEs). Returns True if a signature was removed."""
    try:
        import pefile
        pe = pefile.PE(str(src), fast_load=True)
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if not (sec.VirtualAddress and sec.Size):
            pe.close()
            _safe_copy(src, dst)
            return False
        off = sec.VirtualAddress
        sec.VirtualAddress = 0
        sec.Size = 0
        data = pe.write()
        pe.close()
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(bytes(data[:off]) if off < len(data) else bytes(data))
        return True
    except Exception:  # noqa: BLE001
        _safe_copy(src, dst)
        return False


def _upx_repair(src: Path, dst: Path) -> bool:
    """Undo the usual anti-unpack tweak: renamed UPX sections. Writes a fixed copy
    (UPX0/UPX1 names on the first two sections). Never touches ``src``."""
    try:
        import pefile
        pe = pefile.PE(str(src), fast_load=True)
        if len(pe.sections) < 2:
            pe.close()
            return False
        for s, name in zip(pe.sections[:2], (b"UPX0", b"UPX1")):
            s.Name = name.ljust(8, b"\x00")
        data = pe.write()
        pe.close()
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(bytes(data))
        return True
    except Exception:  # noqa: BLE001
        return False


def _unpack_upx(path: Path, out: Path) -> dict[str, Any]:
    exe = upx_exe()
    if exe is None:
        return {"status": "not_provisioned", "tool": "upx", "detail": "UPX not provisioned (tools/upx/)"}
    out.mkdir(parents=True, exist_ok=True)
    target = out / (path.stem + ".unpacked" + (path.suffix or ".exe"))
    r = _run([str(exe), "-d", "-q", "-o", str(target), str(path)], UNPACK_TIMEOUT)
    rec = {"tool": "upx -d", "duration_s": r["duration_s"]}
    if r.get("rc") == 0 and target.is_file():
        return {**rec, "status": "ok", "detail": "unpacked with upx -d"}
    first_err = (r.get("err") or r.get("out") or r.get("error") or "").strip()[-300:]
    # Retry on a copy with the section names restored (modified UPX stub).
    fixed = out / "_upx_repaired.bin"
    if _upx_repair(path, fixed):
        target.unlink(missing_ok=True)
        r2 = _run([str(exe), "-d", "-q", "-o", str(target), str(fixed)], UNPACK_TIMEOUT)
        fixed.unlink(missing_ok=True)
        if r2.get("rc") == 0 and target.is_file():
            return {**rec, "status": "ok", "tool": "upx -d (section names repaired)",
                    "detail": "UPX header was altered (renamed sections); repaired copy unpacked"}
    if r.get("timed_out"):
        return {**rec, "status": "timeout", "detail": f"upx timed out after {UNPACK_TIMEOUT}s"}
    return {**rec, "status": "error",
            "detail": f"upx could not unpack (modified/hacked UPX?): {first_err}"}


def _unpack_autoit(path: Path, out: Path) -> dict[str, Any]:
    if not _has_module("autoit_ripper"):
        return {"status": "not_provisioned", "tool": "autoit-ripper",
                "detail": "AutoIt-Ripper not installed in the portable Python"}
    out.mkdir(parents=True, exist_ok=True)
    r = _run([str(_portable()), "-m", "autoit_ripper.cli", str(path), str(out)], UNPACK_TIMEOUT)
    rec = {"tool": "autoit-ripper", "duration_s": r["duration_s"]}
    if any(out.iterdir()):
        return {**rec, "status": "ok", "detail": "AutoIt script recovered"}
    if r.get("timed_out"):
        return {**rec, "status": "timeout", "detail": f"autoit-ripper timed out after {UNPACK_TIMEOUT}s"}
    return {**rec, "status": "error", "detail": "no AutoIt script found (unsupported version or not AutoIt)"}


def _unpack_inno(path: Path, out: Path) -> dict[str, Any]:
    exe = innoextract_exe()
    if exe is None:
        return {"status": "not_provisioned", "tool": "innoextract",
                "detail": "innoextract not provisioned (tools/innoextract/)"}
    out.mkdir(parents=True, exist_ok=True)
    r = _run([str(exe), "--extract", "--quiet", "--output-dir", str(out), str(path)], UNPACK_TIMEOUT)
    rec = {"tool": "innoextract", "duration_s": r["duration_s"]}
    if any(out.rglob("*")):
        return {**rec, "status": "ok", "detail": "Inno Setup payload extracted"}
    if r.get("timed_out"):
        return {**rec, "status": "timeout", "detail": f"innoextract timed out after {UNPACK_TIMEOUT}s"}
    err = (r.get("err") or r.get("out") or r.get("error") or "").strip()[-300:]
    return {**rec, "status": "error", "detail": f"innoextract failed: {err}"}


def _unpack_7z(path: Path, out: Path, label: str) -> dict[str, Any]:
    exe = sevenzip_exe()
    if exe is None:
        return {"status": "not_provisioned", "tool": "7-Zip", "detail": "7-Zip not provisioned (tools/7zip/)"}
    out.mkdir(parents=True, exist_ok=True)
    # -p- : never prompt for a password (non-interactive); -y: assume yes.
    r = _run([str(exe), "x", "-y", "-p-", f"-o{out}", str(path)], UNPACK_TIMEOUT)
    rec = {"tool": "7z x", "duration_s": r["duration_s"]}
    if any(out.rglob("*")):
        return {**rec, "status": "ok", "detail": f"{label} extracted"}
    if r.get("timed_out"):
        return {**rec, "status": "timeout", "detail": f"7z timed out after {UNPACK_TIMEOUT}s"}
    err = (r.get("err") or r.get("error") or "").strip()[-300:]
    return {**rec, "status": "error", "detail": f"7z could not extract: {err}"}


def _unpack_nuitka(path: Path, out: Path) -> dict[str, Any]:
    exe = nuitka_exe()
    if exe is None:
        return {"status": "not_provisioned", "tool": "nuitka-extractor",
                "detail": "nuitka-extractor not provisioned (tools/nuitka-extractor/)"}
    # It writes next to its input ("<file>_extracted"): work on a copy (and
    # without the Authenticode blob, which it does not support).
    out.mkdir(parents=True, exist_ok=True)
    copy = out / ("input" + (path.suffix or ".exe"))
    _strip_signature(path, copy)
    r = _run([str(exe), str(copy)], UNPACK_TIMEOUT, cwd=out)
    copy.unlink(missing_ok=True)
    rec = {"tool": "nuitka-extractor", "duration_s": r["duration_s"]}
    produced = out / (copy.name + "_extracted")
    if produced.is_dir() and any(produced.rglob("*")):
        return {**rec, "status": "ok",
                "detail": "Nuitka payload extracted (compiled modules: no Python source)"}
    if r.get("timed_out"):
        return {**rec, "status": "timeout", "detail": f"nuitka-extractor timed out after {UNPACK_TIMEOUT}s"}
    msg = " ".join(l for l in (r.get("out") or "").splitlines() if l.startswith("[!]"))[:300]
    return {**rec, "status": "error", "detail": f"nuitka-extractor failed: {msg or r.get('error', '')}"}


def _unpack_evb(path: Path, out: Path) -> dict[str, Any]:
    if not _has_module("evbunpack"):
        return {"status": "not_provisioned", "tool": "evbunpack",
                "detail": "evbunpack not installed in the portable Python"}
    out.mkdir(parents=True, exist_ok=True)
    r = _run([str(_portable()), "-m", "evbunpack", str(path), str(out)], UNPACK_TIMEOUT)
    rec = {"tool": "evbunpack", "duration_s": r["duration_s"]}
    if any(out.rglob("*")):
        return {**rec, "status": "ok", "detail": "Enigma Virtual Box files / executable restored"}
    if r.get("timed_out"):
        return {**rec, "status": "timeout", "detail": f"evbunpack timed out after {UNPACK_TIMEOUT}s"}
    err = (r.get("err") or "").strip()[-300:]
    return {**rec, "status": "error", "detail": f"evbunpack failed: {err}"}


_UNPACKERS = {
    "upx": _unpack_upx,
    "nuitka": _unpack_nuitka,
    "evb": _unpack_evb,
    "autoit": _unpack_autoit,
    "inno": _unpack_inno,
    "nsis": lambda p, o: _unpack_7z(p, o, "NSIS installer"),
    "sfx7z": lambda p, o: _unpack_7z(p, o, "7-Zip SFX"),
    "sfxrar": lambda p, o: _unpack_7z(p, o, "RAR SFX"),
    "sfxzip": lambda p, o: _unpack_7z(p, o, "ZIP SFX"),
}

# AutoIt functions worth flagging in a recovered script.
_AU3_RISKY = ("Run", "RunWait", "ShellExecute", "ShellExecuteWait", "InetGet", "InetRead",
              "DllCall", "DllStructCreate", "RegWrite", "FileInstall", "BinaryToString",
              "_WinAPI_", "ProcessClose", "TCPConnect", "HttpSetProxy", "Execute")


# ------------------------------------------------------------------------- driver

def process(path: Path, blob: bytes, pe: Any | None, out_dir: Path | None,
            use_die: bool = True) -> dict[str, Any]:
    """Detect the packer/installer of a PE and, with ``out_dir``, unpack it.

    Returns a JSON-able record:
      detected      [{family, label, by, evidence}]   (unpackable families)
      die           DIE status + raw detections (when run)
      no_static     labels of protectors with no static unpacker
      status        none | unpacked | failed | not_provisioned | no_static | detected
      tool, detail, duration_s, files [{name, size}], scripts [{file, text}]
      _files        [(abs_path, display_name)]  — popped by the caller
      findings      [...] (pe-style dicts, tool "unpack")
    """
    rec: dict[str, Any] = {"detected": heuristics(blob, pe), "no_static": no_static_hits(pe),
                           "status": "none", "files": [], "scripts": [], "findings": []}
    if use_die:
        die = run_die(path)
        rec["die"] = die
        if die.get("status") == "ok":
            fams, other = die_families(die)
            for h in fams:
                if not any(x["family"] == h["family"] for x in rec["detected"]):
                    rec["detected"].append(h)
                else:   # keep DIE's richer label (with version)
                    for x in rec["detected"]:
                        if x["family"] == h["family"]:
                            x["label"] = h["label"] or x["label"]
                            x["by"] = x["by"] + "+die"
            for o in other:
                if not any(o.lower().startswith(f.lower().split()[0]) for f in
                           [x["label"] for x in rec["detected"]]) and o not in rec["no_static"]:
                    rec["no_static"].append(o)
    # Order by unpacking priority (outer layer first).
    order = list(FAMILIES)
    rec["detected"].sort(key=lambda h: order.index(h["family"]) if h["family"] in order else 99)
    labels = ", ".join(h["label"] for h in rec["detected"])

    if not rec["detected"]:
        if rec["no_static"]:
            rec["status"] = "no_static"
            rec["detail"] = (f"packed/protected with {', '.join(rec['no_static'])} — "
                             f"static unpacking not possible")
            rec["findings"].append({
                "tool": "unpack", "rule": "pe_protector", "severity": "medium",
                "detail": rec["detail"] + " (FLOSS/capa skipped: they would only see the stub)"
                          " · T1027.002",
                "location": "unpack", "evidence": ", ".join(rec["no_static"])})
        return rec
    rec["status"] = "detected"
    rec["detail"] = f"detected: {labels}"
    if out_dir is None:
        return rec

    attempts: list[dict[str, Any]] = []
    for h in rec["detected"]:
        fn = _UNPACKERS.get(h["family"])
        if fn is None:
            continue
        sub = out_dir / h["family"]
        try:
            res = fn(path, sub)
        except Exception as exc:  # noqa: BLE001
            log.warning("unpack %s failed on %s: %s", h["family"], path.name, exc)
            res = {"status": "error", "tool": h["family"], "detail": str(exc)}
        res["family"] = h["family"]
        attempts.append(res)
        if res.get("status") == "ok":
            files = _list_files(sub)
            rec.update(status="unpacked", family=h["family"], tool=res.get("tool"),
                       detail=f"{h['label']}: {res.get('detail', '')}",
                       duration_s=res.get("duration_s"))
            rec["files"] = [{"name": p.relative_to(sub).as_posix(), "size": p.stat().st_size}
                            for p in files[:_MAX_LISTED]]
            rec["files_total"] = len(files)
            rec["_files"] = [(str(p), p.name) for p in files]
            for p in files:
                if p.suffix.lower() in _SCRIPT_EXT and len(rec["scripts"]) < 10:
                    try:
                        txt = p.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    rec["scripts"].append({"file": p.relative_to(sub).as_posix(),
                                           "lines": txt.count("\n") + 1,
                                           "text": txt[:_MAX_SCRIPT],
                                           "truncated": len(txt) > _MAX_SCRIPT})
            break
        log.warning("unpack %s on %s: %s — %s", h["family"], path.name,
                    res.get("status"), res.get("detail"))
    rec["attempts"] = [{k: v for k, v in a.items()} for a in attempts]
    if rec["status"] != "unpacked" and attempts:
        st = {a.get("status") for a in attempts}
        rec["status"] = "not_provisioned" if st == {"not_provisioned"} else "failed"
        rec["detail"] = f"{labels}: " + " | ".join(a.get("detail", "") for a in attempts)
    _add_findings(rec)
    return rec


def _add_findings(rec: dict[str, Any]) -> None:
    f = rec["findings"]
    labels = ", ".join(h["label"] for h in rec["detected"])

    def add(rule: str, sev: str, detail: str, ev: str = "", attack: str = "") -> None:
        f.append({"tool": "unpack", "rule": rule, "severity": sev,
                  "detail": detail + (f" · {attack}" if attack else ""),
                  "location": "unpack", "evidence": ev[:2000]})

    installer_only = all(h["family"] in INSTALLERS for h in rec["detected"])
    if rec["status"] == "unpacked":
        n = rec.get("files_total", len(rec["files"]))
        add("pe_unpacked", "info" if installer_only else "medium",
            f"{labels}: unpacked statically with {rec.get('tool')} → {n} file(s) "
            f"(analysed in the Nested tab)", ", ".join(x["name"] for x in rec["files"][:20]),
            "" if installer_only else "T1027.002")
        for s in rec["scripts"]:
            if s["file"].lower().endswith(".au3"):
                hits = sorted({fn for fn in _AU3_RISKY if fn.lower() in s["text"].lower()})
                add("autoit_script", "medium" if hits else "low",
                    f"AutoIt script recovered ({s['lines']} lines)"
                    + (f"; uses {', '.join(hits[:10])}" if hits else ""),
                    s["text"][:1500], "T1059.010")
    elif rec["status"] in ("failed", "not_provisioned"):
        add("pe_unpack_failed", "low" if installer_only else "medium",
            f"{labels}: could not unpack statically — {rec.get('detail', '')}", "",
            "" if installer_only else "T1027.002")
