"""PyInstaller unpacker: recover the bundled Python from a frozen ``.exe``.

A PyInstaller executable is an ordinary PE with a **CArchive** appended, marked
by the cookie ``MEI\\014\\013\\012\\013\\016``. The archive holds the entry
script(s) and, inside a **PYZ** (ZlibArchive), the bundled modules — all as
marshalled Python code objects. This module finds the cookie, parses the TOC
and the PYZ, and writes each module back out as a ``.pyc`` (with a synthesised
header so the Python engine and a decompiler can read it), to be analysed by
:mod:`python` directly and through the nested path. Pure ``struct`` + ``zlib`` +
``marshal``; nothing is executed.

Scope: PyInstaller only. Nuitka (compiled C), py2exe and cx_Freeze use other
layouts; a py2exe/cx_Freeze bundle still surfaces its ``.pyc`` through the normal
archive/categorisation paths.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Any

from .python import _PYC_MAGIC

MAGIC = b"MEI\014\013\012\013\016"
_MAX_ENTRIES = 2000
_MAX_TOTAL = 200 * 1024 * 1024
_VER_TO_MAGIC = {v: k for k, v in _PYC_MAGIC.items()}


def is_pyinstaller(blob: bytes) -> bool:
    return MAGIC in blob[-4 * 1024 * 1024:]


def _ver_str(pyvers: int) -> str:
    if pyvers >= 100:
        return f"{pyvers // 100}.{pyvers % 100}"
    if pyvers >= 10:
        return f"{pyvers // 10}.{pyvers % 10}"
    return "unknown"


def _pyc_header(ver: str) -> bytes:
    """A 16-byte .pyc header for the detected version (magic + null timestamp)."""
    magic_val = _VER_TO_MAGIC.get(ver) or _VER_TO_MAGIC.get(ver.rstrip("+"), 3495)
    return struct.pack("<H", magic_val) + b"\r\n" + b"\x00" * 12


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "pyinstaller", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


def _parse_pyz(data: bytes, hdr: bytes) -> list[tuple[str, bytes]]:
    """Extract (name, .pyc-bytes) from a PYZ (ZlibArchive) blob."""
    import marshal

    out: list[tuple[str, bytes]] = []
    if data[:4] != b"PYZ\x00" or len(data) < 12:
        return out
    toc_pos = struct.unpack(">I", data[8:12])[0]
    try:
        toc = marshal.loads(data[toc_pos:])
    except Exception:  # noqa: BLE001
        return out
    entries = toc.items() if isinstance(toc, dict) else toc
    for item in entries:
        try:
            name, (_ispkg, pos, length) = item
            raw = data[pos:pos + length]
            code = zlib.decompress(raw)
            out.append((str(name), hdr + code))
        except Exception:  # noqa: BLE001
            continue
        if len(out) >= _MAX_ENTRIES:
            break
    return out


def extract(path: Path, out_dir: Path) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "pyinstaller", "status": "ok", "is_pyinstaller": False,
                           "python_version": "", "pylib": "", "entries": [], "findings": [],
                           "_files": []}
    try:
        blob = path.read_bytes()
    except OSError as exc:
        res["status"] = "error"
        res["findings"].append(_finding("pyinstaller_error", "low", str(exc), f"file:{path.name}"))
        return res

    idx = blob.rfind(MAGIC)
    if idx == -1:
        return res
    res["is_pyinstaller"] = True
    loc = f"file:{path.name}"

    # Cookie: magic(8) pkgLen(4) toc(4) tocLen(4) pyvers(4) [pylibname(64)].
    cookie = blob[idx:idx + 88]
    try:
        pkg_len, toc_off, toc_len, pyvers = struct.unpack(">IIII", cookie[8:24])
    except struct.error:
        res["findings"].append(_finding("pyinstaller_truncated", "medium",
                                        "PyInstaller cookie present but truncated", loc))
        return res
    pylib = ""
    if len(cookie) >= 88:
        pylib = cookie[24:88].split(b"\x00", 1)[0].decode("latin-1", "replace")
    ver = _ver_str(pyvers)
    if ver == "unknown" and pylib:
        import re as _re
        m = _re.search(r"python(\d)(\d+)", pylib, _re.I)
        if m:
            ver = f"{m.group(1)}.{m.group(2)}"
    res.update(python_version=ver, pylib=pylib)
    hdr = _pyc_header(ver)

    overlay = len(blob) - pkg_len
    toc_start = overlay + toc_off
    toc = blob[toc_start:toc_start + toc_len]

    out_dir.mkdir(parents=True, exist_ok=True)
    pos = 0
    total = 0
    n_scripts = 0
    pyz_count = 0
    while pos + 18 <= len(toc) and len(res["entries"]) < _MAX_ENTRIES and total < _MAX_TOTAL:
        entry_len, entry_pos, csize, usize, flag = struct.unpack(">IIIIB", toc[pos:pos + 17])
        typ = toc[pos + 17:pos + 18].decode("latin-1", "replace")
        name = toc[pos + 18:pos + entry_len].split(b"\x00", 1)[0].decode("latin-1", "replace") or f"entry{pos}"
        pos += entry_len
        if entry_len < 18:
            break
        data = blob[overlay + entry_pos:overlay + entry_pos + csize]
        if flag == 1:
            try:
                data = zlib.decompress(data)
            except zlib.error:
                continue
        total += len(data)
        res["entries"].append({"name": name, "type": typ, "size": usize or len(data)})
        safe = name.replace("..", "_").replace("/", "_").replace("\\", "_").strip() or f"entry{pos}"

        if typ in ("s", "m", "M"):  # entry script / importable module (bare code object)
            p = out_dir / f"{safe}.pyc"
            try:
                p.write_bytes(hdr + data)
                res["_files"].append((str(p), f"{safe}.pyc"))
                if typ == "s":
                    n_scripts += 1
            except OSError:
                pass
        elif typ in ("z", "Z"):  # PYZ archive of modules
            for mod_name, pyc_bytes in _parse_pyz(data, hdr):
                if len(res["_files"]) >= _MAX_ENTRIES or total >= _MAX_TOTAL:
                    break
                total += len(pyc_bytes)
                pyz_count += 1
                safe_m = mod_name.replace("..", "_").replace("/", "_") or f"mod{pyz_count}"
                mp = out_dir / "PYZ" / f"{safe_m}.pyc"
                try:
                    mp.parent.mkdir(parents=True, exist_ok=True)
                    mp.write_bytes(pyc_bytes)
                    res["_files"].append((str(mp), f"PYZ/{safe_m}.pyc"))
                except OSError:
                    pass

    res["pyz_modules"] = pyz_count
    f = res["findings"]
    f.append(_finding("pyinstaller_bundle", "medium",
                      f"PyInstaller-frozen executable (Python {ver or 'unknown'}"
                      + (f", {pylib}" if pylib else "") + f"); {len(res['entries'])} archive entries, "
                      f"{pyz_count} PYZ modules — Python recovered for analysis", loc, "", ))
    if n_scripts:
        f.append(_finding("pyinstaller_entry_script", "medium",
                          f"{n_scripts} entry script(s) recovered and analysed as Python", loc))
    res["counts"] = {"findings": len(f), "entries": len(res["entries"]),
                     "extracted": len(res["_files"])}
    res["status"] = "ok_with_findings"
    return res
