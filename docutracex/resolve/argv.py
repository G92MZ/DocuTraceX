"""The files a stage's command-line arguments point at, when the stage is analysed on its own.

A dropper often starts its next stage with its own path as an argument (``wscript next.js
"<dropper.vbs>"``, ``powershell -File x.ps1 "%~f0"``); the stage then reads the payload from that file
(lines with a marker, a block between tags). Nested analyses each stage as a separate file, so when it
analyses a stage it sets here the sample above it (the case's original): ``WScript.Arguments(i)`` then
names it and reading that path returns its text. Only files already in the case are ever read — never
a path on this machine.
"""

from __future__ import annotations

import contextvars
from pathlib import Path

MAX_BYTES = 8 << 20
PARENTS: contextvars.ContextVar[tuple[tuple[str, str], ...]] = contextvars.ContextVar("parents", default=())


def path_of(i: int) -> str:
    return f"C:\\Users\\Public\\Downloads\\{PARENTS.get()[i][0]}"


def text_of(path: str) -> str | None:
    """The text of a parent named by the path the stage built from its arguments, or None."""
    for i, (_name, text) in enumerate(PARENTS.get()):
        if path.strip().strip('"').lower() == path_of(i).lower():
            return text
    return None


def from_dir(d: Path) -> tuple[tuple[str, str], ...]:
    out = []
    for p in sorted(d.glob("*"))[:1] if d.is_dir() else []:
        if p.is_file() and p.stat().st_size <= MAX_BYTES:
            name = "".join(c for c in p.name if c.isalnum() or c in "._-")[:80] or "sample"
            out.append((name, p.read_bytes().decode("utf-8", "replace").lstrip("\ufeff")))
    return tuple(out)
