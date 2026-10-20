"""Dump extracted code (VBA / JavaScript / XLM) to files inside the case.

The parsers keep code in the result JSON for display; this writes it out as
real files under ``extracted/code/`` so the analyst can open or download the
source and run their own tools on it (grep, CyberChef, an editor, YARA). Each
item is tagged with a case-relative ``code_file`` the UI turns into the usual
Folder / Download buttons.

Idempotent: a file is (re)written only when missing or its size changed, so
re-runs and on-demand recomputes don't churn the disk.
"""

from __future__ import annotations

import re
from typing import Any

from .storage import CasePaths

_CODE_DIR = "code"  # under extracted/
_MAX_BYTES = 8_000_000  # guard: never write an absurdly large blob


def _slug(value: str, fallback: str = "code") -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("_")
    return (s[:48] or fallback)


def _write(paths: CasePaths, sub: str, name: str, text: Any) -> str | None:
    """Write ``text`` to extracted/code/<sub>/<name>; return its case-relative
    path, or None when there is nothing worth writing."""
    if not isinstance(text, str) or not text.strip():
        return None
    data = text.encode("utf-8", "replace")[:_MAX_BYTES]
    dest_dir = paths.extracted_dir / _CODE_DIR / sub
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / name
    try:
        if not (dest.exists() and dest.stat().st_size == len(data)):
            dest.write_bytes(data)
    except OSError:
        return None
    return dest.relative_to(paths.root).as_posix()


def annotate(modules: dict[str, Any], paths: CasePaths) -> set[str]:
    """Write code files and tag each item with its ``code_file``.

    Returns the set of module names whose sub-result dict changed, so the
    caller can persist exactly those (nothing else is touched).
    """
    changed: set[str] = set()

    # VBA: olevba gives the full macro source as code_text (not truncated).
    ole = modules.get("oletools")
    if isinstance(ole, dict):
        rel = _write(paths, "vba", "vba_macros.vba", ole.get("code_text"))
        if rel and ole.get("code_file") != rel:
            ole["code_file"] = rel
            changed.add("oletools")

    # JavaScript: one file per script (code as stored; may be truncated, which
    # the UI already flags with code_truncated).
    js = modules.get("javascript")
    if isinstance(js, dict):
        touched = False
        for i, sc in enumerate(js.get("scripts") or [], 1):
            if not isinstance(sc, dict):
                continue
            label = _slug(sc.get("location") or sc.get("kind") or sc.get("origin"), f"script{i}")
            rel = _write(paths, "js", f"{i:02d}_{label}.js", sc.get("code"))
            if rel and sc.get("code_file") != rel:
                sc["code_file"] = rel
                touched = True
        if touched:
            changed.add("javascript")

    # Excel 4.0 (XLM): the deobfuscated formulas as a single listing.
    xlm = modules.get("xlmdeobf")
    if isinstance(xlm, dict):
        rel = _write(paths, "xlm", "xlm_macros.txt", xlm.get("code_text"))
        if rel and xlm.get("code_file") != rel:
            xlm["code_file"] = rel
            changed.add("xlmdeobf")

    return changed
