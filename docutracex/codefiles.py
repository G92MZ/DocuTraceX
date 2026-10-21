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


def _pop_full(d: dict[str, Any], display_key: str) -> tuple[str | None, bool]:
    """The complete source to write: the parser's internal ``_full_code`` when
    present, else the (possibly truncated) display field. Returns the text and
    whether a ``_full_code`` scratch key was removed (so the caller re-persists
    a clean dict — the full source lives in the dumped file, never the JSON)."""
    popped = "_full_code" in d
    full = d.pop("_full_code", None)
    return (full if isinstance(full, str) and full.strip() else d.get(display_key)), popped


def _dump_script_list(scripts: list, paths: CasePaths, sub: str, ext: str) -> bool:
    """Dump the original (``code_file``) and, when present, the deobfuscated
    (``code_file_deob``) source for each script in ``scripts``. Returns True if
    any tag was (re)written. Shared by the JS / PowerShell / VBScript modules."""
    touched = False
    for i, sc in enumerate(scripts, 1):
        if not isinstance(sc, dict):
            continue
        label = _slug(sc.get("location") or sc.get("kind") or sc.get("origin"), f"script{i}")
        # Original source: prefer _full_code; fall back to the display field
        # only when the script was NOT deobfuscated (otherwise `code` already
        # holds the deobfuscated artifact, dumped separately below).
        orig = sc.pop("_full_code", None)
        orig_popped = orig is not None
        if not (isinstance(orig, str) and orig.strip()):
            orig = "" if sc.get("code_is_deobfuscated") else sc.get("code")
        rel = _write(paths, sub, f"{i:02d}_{label}.{ext}", orig)
        if (rel and sc.get("code_file") != rel) or orig_popped:
            if rel:
                sc["code_file"] = rel
            touched = True
        deob = sc.pop("_full_deob", None)
        deob_popped = deob is not None
        if not (isinstance(deob, str) and deob.strip()):
            deob = None
        rel_d = _write(paths, sub, f"{i:02d}_{label}.deobfuscated.{ext}", deob)
        if (rel_d and sc.get("code_file_deob") != rel_d) or deob_popped:
            if rel_d:
                sc["code_file_deob"] = rel_d
            touched = True
    return touched


def annotate(modules: dict[str, Any], paths: CasePaths) -> set[str]:
    """Write the extracted code to files and tag each item with its ``code_file``.

    The dumped file always holds the COMPLETE source (the parsers stash it as
    ``_full_code`` before truncating for display); the UI stays bounded and
    flags ``code_truncated``. Returns the set of module names whose sub-result
    dict changed, so the caller persists exactly those.
    """
    changed: set[str] = set()

    # VBA: full macro source (olevba _full_code), falling back to code_text.
    ole = modules.get("oletools")
    if isinstance(ole, dict):
        olevba = ole.get("tools", {}).get("olevba") if isinstance(ole.get("tools"), dict) else None
        if isinstance(olevba, dict):
            text, popped = _pop_full(olevba, "")
            text = text or ole.get("code_text")
        else:
            text, popped = ole.get("code_text"), False
        rel = _write(paths, "vba", "vba_macros.vba", text)
        if (rel and ole.get("code_file") != rel) or popped:
            if rel:
                ole["code_file"] = rel
            changed.add("oletools")
        # Deobfuscated VBA (static string resolver), when present.
        if isinstance(olevba, dict):
            deob = olevba.pop("_full_deob", None)
            deob_popped = deob is not None
            if not (isinstance(deob, str) and deob.strip()):
                deob = None
            rel_d = _write(paths, "vba", "vba_macros.deobfuscated.vba", deob)
            if (rel_d and ole.get("code_file_deob") != rel_d) or deob_popped:
                if rel_d:
                    ole["code_file_deob"] = rel_d
                changed.add("oletools")

    # Code-with-scripts modules (JavaScript / PowerShell / VBScript): one
    # complete file per script, plus the deobfuscated artifact when the
    # deobfuscation cascade recovered a cleaner payload.
    for module_name, sub, ext in (("javascript", "js", "js"),
                                   ("powershell", "powershell", "ps1"),
                                   ("vbscript", "vbscript", "vbs")):
        mod = modules.get(module_name)
        if not isinstance(mod, dict):
            continue
        if _dump_script_list(mod.get("scripts") or [], paths, sub, ext):
            changed.add(module_name)

    # Excel 4.0 (XLM): all deobfuscated formulas.
    xlm = modules.get("xlmdeobf")
    if isinstance(xlm, dict):
        text, popped = _pop_full(xlm, "code_text")
        rel = _write(paths, "xlm", "xlm_macros.txt", text)
        if (rel and xlm.get("code_file") != rel) or popped:
            if rel:
                xlm["code_file"] = rel
            changed.add("xlmdeobf")

    return changed
