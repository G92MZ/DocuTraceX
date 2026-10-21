"""Microsoft OneNote (``.one`` / ``.onepkg``): carve embedded files.

OneNote became a major initial-access vector once Office blocked macros: a page
shows a fake "Double-click to view" button over an embedded script or executable
(``.hta``/``.vbs``/``.js``/``.exe``/``.bat``) that runs when clicked. In the
MS-ONESTORE format every embedded file is a ``FileDataStoreObject`` delimited by
a fixed header GUID, so the payloads are carved directly from the bytes
(``guidHeader`` + ``cbLength`` + 36-byte prologue → ``FileData``) and handed to
the nested scanner, which routes each one to the right engine. Nothing runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# FileDataStoreObject GUID {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}, little-endian
# in the first three fields as stored on disk.
_HEADER_GUID = bytes((0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
                      0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC))
# guidFileType at the start of a .one section.
_ONE_MAGIC = bytes((0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
                    0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3))
_PROLOGUE = 36          # guidHeader(16) + cbLength(8) + unused(4) + reserved(8)
_MAX_FILES = 100
_MAX_FILE = 100 * 1024 * 1024
_MAX_TOTAL = 250 * 1024 * 1024


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "onenote", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


def is_onenote(blob: bytes) -> bool:
    return blob[:16] == _ONE_MAGIC or _HEADER_GUID in blob[:4_000_000]


def _guess_ext(data: bytes) -> str:
    head = data[:16]
    low = data[:4096].lower()
    if head[:2] == b"MZ":
        return ".exe"
    if head[:4] == b"PK\x03\x04":
        return ".zip"
    if head[:4] == b"%PDF":
        return ".pdf"
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return ".ole"
    if head[:4] == b"MSCF":
        return ".cab"
    if head[:2] in (b"\x1f\x8b",) or head[:5] == b"\xfd7zXZ":
        return ".gz"
    # Order matters: a script that *launches* powershell is still a .bat/.vbs/.hta,
    # so match the script's own language markers before the "powershell" payload.
    if b"hta:application" in low or (b"<html" in low and b"<script" in low):
        return ".hta"
    if b"@echo" in low or b"cmd /c" in low or b"%comspec%" in low or b"setlocal" in low:
        return ".bat"
    if b"createobject" in low or b"wscript" in low or b"vbscript" in low or b"execute(" in low:
        return ".vbs"
    if b"activexobject" in low or b"<script" in low or b"eval(" in low:
        return ".js"
    if b"invoke-expression" in low or b"\niex" in low or b"-encodedcommand" in low or b"$(" in low \
            or b"powershell" in low:
        return ".ps1"
    if head.isascii() and head.strip():
        return ".txt"
    return ".bin"


def carve(blob: bytes) -> list[tuple[str, bytes]]:
    """Return (suggested_name, data) for each embedded FileDataStoreObject."""
    out: list[tuple[str, bytes]] = []
    total = 0
    i = 0
    while len(out) < _MAX_FILES and total < _MAX_TOTAL:
        j = blob.find(_HEADER_GUID, i)
        if j < 0:
            break
        i = j + 16
        if j + _PROLOGUE > len(blob):
            break
        cb = int.from_bytes(blob[j + 16:j + 24], "little")
        if cb == 0 or cb > _MAX_FILE:
            continue
        data = blob[j + _PROLOGUE:j + _PROLOGUE + cb]
        if len(data) < cb:
            continue
        total += len(data)
        out.append((f"embedded_{len(out) + 1:02d}{_guess_ext(data)}", data))
    return out


def extract(path: Path, out_dir: Path) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "onenote", "status": "ok", "is_onenote": False,
                           "embedded": [], "findings": [], "_files": []}
    loc = f"file:{path.name}"
    try:
        blob = path.read_bytes()
    except OSError as exc:
        res["status"] = "error"
        res["findings"].append(_finding("onenote_error", "low", str(exc), loc))
        return res
    res["is_onenote"] = is_onenote(blob)
    carved = carve(blob)
    if not carved:
        if res["is_onenote"]:
            res["findings"].append(_finding("onenote_no_embedded", "info",
                                            "OneNote document with no embedded files carved", loc))
        return res

    out_dir.mkdir(parents=True, exist_ok=True)
    _RISKY = {".exe", ".hta", ".vbs", ".js", ".bat", ".ps1", ".cmd", ".scr", ".cab", ".zip"}
    for name, data in carved:
        target = out_dir / name
        try:
            target.write_bytes(data)
        except OSError:
            continue
        ext = Path(name).suffix.lower()
        res["embedded"].append({"name": name, "size": len(data), "ext": ext})
        res["_files"].append((str(target), name))
        sev = "high" if ext in _RISKY else "medium"
        res["findings"].append(_finding("onenote_embedded_file", sev,
                                        f"embedded {ext or 'file'} ({len(data)} bytes) — OneNote lure payload",
                                        loc, name))
    res["counts"] = {"findings": len(res["findings"]), "embedded": len(res["embedded"])}
    res["status"] = "ok_with_findings"
    return res
