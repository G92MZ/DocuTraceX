"""Content before extension: a "script" that is not text is not treated as code.

Loaders ship binaries under script names — a compiled AutoIt script called
``.au3`` (with junk in front), a PE called ``.py``, a ZIP called ``.pl`` — so the
script engines would paint bytes as code and find nothing. Here a file with a
script extension is checked first:

* **text** (UTF-8 / ANSI, UTF-16 with or without BOM, encoded ``.vbe`` / ``.jse``) →
  the script engines, as before;
* **binary** → a finding (the extension says one thing, the content another), no
  script engine, and the binary path: identified by its content, and the pieces
  embedded anywhere in it (a compiled AutoIt blob, PEs, ZIP / 7z / CAB / OLE / PDF)
  carved out as nested children.

Pure byte inspection: nothing is run.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

# extensions that promise source code (and the language they promise)
SCRIPT_EXT = {
    ".au3": "AutoIt", ".ahk": "AutoHotkey", ".py": "Python", ".pyw": "Python", ".pl": "Perl", ".pm": "Perl",
    ".rb": "Ruby", ".rbw": "Ruby", ".lua": "Lua", ".tcl": "Tcl", ".sh": "shell", ".bash": "shell", ".php": "PHP",
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".psd1": "PowerShell", ".vbs": "VBScript", ".vbe": "VBScript",
    ".js": "JavaScript", ".jse": "JScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".wsf": "Windows Script",
    ".wsc": "Windows Script", ".sct": "scriptlet", ".hta": "HTA", ".bat": "batch", ".cmd": "batch",
    ".r": "R", ".jl": "Julia", ".txt": "text",
}
HEAD = 64 * 1024
MAX_SCAN = 96 * 1024 * 1024
MAX_PIECES = 16
_A3X = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d")


def is_text(data: bytes) -> bool:
    """Readable text: a BOM'd or NUL-patterned UTF-16, or bytes without NULs and with
    hardly any control characters (UTF-8, ANSI code pages, encoded .vbe/.jse)."""
    head = data[:HEAD]
    if not head:
        return True
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            head[2:len(head) // 2 * 2].decode("utf-16-le" if head[:2] == b"\xff\xfe" else "utf-16-be")
            return True
        except UnicodeDecodeError:
            return False
    if len(head) >= 16 and head[1::2].count(0) > len(head) // 2 * 0.9 and head[0::2].count(0) < len(head) // 20:
        return True                                   # UTF-16LE without BOM (ASCII text: every 2nd byte 0)
    if b"\x00" in head:
        return False
    ctrl = sum(1 for b in head if b < 32 and b not in (9, 10, 12, 13, 26, 27))
    return ctrl <= max(2, len(head) // 200)


def magic_kind(data: bytes) -> str | None:
    """What a binary is by its first bytes (the formats the analysis has a path for)."""
    h = data[:8]
    if h[:2] == b"MZ":
        return "PE"
    if h[:4] == b"\x7fELF":
        return "ELF"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "ZIP"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if h[:4] == b"Rar!":
        return "RAR"
    if h[:4] == b"MSCF":
        return "CAB"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE"
    if h[:5] == b"%PDF-":
        return "PDF"
    if h[:2] in (b"\x1f\x8b",):
        return "gzip"
    if data[:16] == _A3X:
        return "compiled AutoIt"
    return None


def check(name: str, data: bytes) -> dict[str, Any] | None:
    """A file whose extension promises a script but whose content is binary, or None."""
    ext = Path(name).suffix.lower()
    if ext not in SCRIPT_EXT or ext == ".txt" and magic_kind(data) is None:
        return None
    if is_text(data):
        return None
    pieces = embedded(data)
    return {"ext": ext, "language": SCRIPT_EXT[ext], "kind": magic_kind(data), "pieces": pieces}


def finding(rec: dict[str, Any], name: str, where: str) -> dict[str, Any]:
    what = rec["kind"] or (rec["pieces"][0]["kind"] + " inside" if rec["pieces"] else "binary data")
    detail = (f"'{name}' is named like {rec['language']} source ({rec['ext']}) but is binary ({what}) — "
              "not analysed as code; read as a binary")
    if rec["pieces"]:
        detail += ": " + ", ".join(f"{p['kind']} at 0x{p['offset']:x}" for p in rec["pieces"][:6]) + " carved out"
    return {"tool": "content", "rule": "disguised_binary", "severity": "medium", "detail": detail,
            "location": where, "evidence": "", "attack": "T1036.008"}


# --- pieces embedded anywhere in the bytes ----------------------------------------------------

def _zip_end(data: bytes, at: int) -> int:
    e = data.find(b"PK\x05\x06", at)
    if e < 0 or e + 22 > len(data):
        return len(data)
    clen = struct.unpack_from("<H", data, e + 20)[0]
    return min(len(data), e + 22 + clen)


def _7z_end(data: bytes, at: int) -> int:
    try:
        off, size = struct.unpack_from("<QQ", data, at + 12)
        end = at + 32 + off + size
        return end if at < end <= len(data) else len(data)
    except struct.error:
        return len(data)


def _cab_end(data: bytes, at: int) -> int:
    try:
        size = struct.unpack_from("<I", data, at + 8)[0]
        return at + size if 0 < size <= len(data) - at else len(data)
    except struct.error:
        return len(data)


def _pdf_end(data: bytes, at: int) -> int:
    e = data.rfind(b"%%EOF")
    return e + 5 if e > at else len(data)


def embedded(data: bytes) -> list[dict[str, Any]]:
    """Pieces inside the bytes, with their offset and size: a compiled AutoIt blob (with
    junk in front), PEs (cut to their headers' size), ZIP / 7z / CAB / OLE / PDF."""
    from .decrypted import _valid_mz, pe_extent
    data = data[:MAX_SCAN]
    out: list[dict[str, Any]] = []
    taken: list[tuple[int, int]] = []

    def inside(i: int) -> bool:
        return any(a <= i < b for a, b in taken)

    def add(kind: str, at: int, end: int) -> None:
        if len(out) < MAX_PIECES and end - at >= 64:
            out.append({"kind": kind, "offset": at, "size": end - at})
            taken.append((at, end))

    i = data.find(_A3X)
    if i >= 0 and data[i + 16:i + 20] in (b"AU3!", b"JB01"):
        add("compiled AutoIt script", i, len(data))   # its own format runs to the end (marker repeated there)
    for sig, kind, end_of in ((b"MZ", "PE", None), (b"PK\x03\x04", "ZIP", _zip_end),
                              (b"7z\xbc\xaf\x27\x1c", "7z", _7z_end), (b"MSCF\x00\x00\x00\x00", "CAB", _cab_end),
                              (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE", None), (b"%PDF-", "PDF", _pdf_end)):
        pos = 0
        while len(out) < MAX_PIECES:
            j = data.find(sig, pos)
            if j < 0:
                break
            pos = j + len(sig)
            if inside(j):
                continue
            if kind == "PE":
                if not _valid_mz(data, j):
                    continue
                size = pe_extent(data, j)
                if not size:
                    continue
                add("PE", j, j + size)
            elif end_of:
                add(kind, j, end_of(data, j))
            else:
                add(kind, j, len(data))
    return sorted(out, key=lambda p: p["offset"])


_EXT = {"compiled AutoIt script": ".a3x", "PE": ".exe", "ZIP": ".zip", "7z": ".7z", "CAB": ".cab", "OLE": ".ole",
        "PDF": ".pdf"}


def carve(data: bytes, pieces: list[dict[str, Any]], name: str, out_dir: Path) -> list[dict[str, Any]]:
    """Write the pieces as files the nested analysis takes as children."""
    out = []
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return out
    stem = Path(name).stem or "piece"
    for k, p in enumerate(pieces, 1):
        raw = data[p["offset"]:p["offset"] + p["size"]]
        ext = _EXT.get(p["kind"], ".bin")
        if p["kind"] == "PE":
            from .decrypted import _pe_ext
            ext = _pe_ext(raw)
        fn = f"{stem}.piece{k}_0x{p['offset']:x}{ext}"
        try:
            (out_dir / fn).write_bytes(raw)
        except OSError:
            continue
        out.append({"path": str(out_dir / fn), "filename": fn,
                    "origin": f"{p['kind']} carved from {name} at offset 0x{p['offset']:x} ({p['size']} bytes)"})
    return out
