"""Compiled AutoIt scripts on their own (``.a3x``), whatever their name.

``Aut2Exe`` can write the compiled script without the interpreter: an ``.a3x`` is
the same blob a compiled EXE keeps in its ``SCRIPT`` resource — a 16-byte magic,
``AU3!EA06`` (``EA05`` for AutoIt 3.2 and older) and the encrypted, compressed
script — and ``AutoIt3.exe file.a3x`` runs it. Loaders ship one next to a
portable (often renamed) ``AutoIt3.exe`` under a harmless name.

The file is recognised by its content; the script is recovered with
AutoIt-Ripper (the same tool used for compiled EXEs: it reads the blob directly)
and handed to the nested analysis, where the generic script engine reads it.
Nothing is run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MAGIC = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d")
VERSIONS = {b"AU3!EA06": "EA06 (AutoIt 3.2.6+)", b"AU3!EA05": "EA05 (AutoIt 3.0–3.2.5)"}


def version(data: bytes) -> str | None:
    """The format of a compiled AutoIt script blob, or None."""
    if data[:16] != MAGIC:
        return None
    return VERSIONS.get(data[16:24]) or ("JB01 (AutoHotkey / AutoIt 2)" if data[16:20] == b"JB01" else None)


def is_a3x(data: bytes) -> bool:
    return version(data) is not None


def analyze(path: Path, out_dir: Path, where: str = "") -> dict[str, Any]:
    """Finding + the recovered files (``_files``: [(path, name)]) for one ``.a3x``."""
    try:
        with path.open("rb") as fh:
            head = fh.read(32)
    except OSError:
        return {"module": "autoit", "status": "error", "findings": []}
    ver = version(head)
    res: dict[str, Any] = {"module": "autoit", "status": "ok", "findings": [], "format": ver, "_files": []}
    if not ver:
        res["status"] = "not_autoit"
        return res
    from .unpack import _unpack_autoit
    try:
        rec = _unpack_autoit(path, out_dir)
    except Exception as exc:  # noqa: BLE001
        rec = {"status": "error", "detail": str(exc)}
    res["decompile"] = {k: v for k, v in rec.items() if k in ("tool", "status", "detail", "duration_s")}
    files = sorted(p for p in out_dir.rglob("*") if p.is_file()) if rec.get("status") == "ok" else []
    res["_files"] = [(str(p), p.name) for p in files]
    res["recovered"] = [p.name for p in files]
    where = where or path.name
    note = (f"script recovered ({', '.join(p.name for p in files[:5])}) and analysed in Nested"
            if files else f"script not recovered: {rec.get('detail') or rec.get('status')}")
    res["findings"].append({
        "tool": "autoit", "rule": "autoit_a3x", "severity": "high" if path.suffix.lower() != ".a3x" else "medium",
        "detail": f"compiled AutoIt script ({ver}) on its own, run with AutoIt3.exe"
                  + ("" if path.suffix.lower() == ".a3x" else f", named '{path.name}' to hide what it is")
                  + f" — {note}",
        "location": where, "evidence": head[:24].hex(" "), "attack": "T1059.010",
    })
    return res
