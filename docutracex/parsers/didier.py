"""Didier Stevens Suite tools (external scripts, run on the portable).

These are standalone scripts (public domain) provisioned under ``tools/didier/``
by scripts/setup_portable_python.py. We run the relevant ones and capture their
raw output — the way an analyst reads them — rather than parsing it fragilely.

Mapping by file family:
- Office / OLE : ``oledump.py`` (OLE streams, VBA), ``zipdump.py`` (OOXML ZIP)
- PDF          : ``pdfid.py``, ``pdf-parser.py``   (used by the PDF parser later)
- Email        : ``emldump.py``                    (used by the email parser later)

If a script is not provisioned, it is skipped gracefully.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from ..config import settings
from ..logging_config import get_logger

log = get_logger(__name__)

SCRIPTS = {
    "oledump": "oledump.py",
    "zipdump": "zipdump.py",
    "pdfid": "pdfid.py",
    "pdf-parser": "pdf-parser.py",
    "emldump": "emldump.py",
    "rtfdump": "rtfdump.py",
    "decode-vbe": "decode-vbe.py",
}

# oledump plugins (run with ``oledump.py -p plugin_x.py``).
PLUGINS = ["plugin_biff.py", "plugin_vba_summary.py", "plugin_vba_dco.py",
           "plugin_vba_routines.py", "plugin_http_heuristics.py", "plugin_stream_o.py"]

# Which scripts apply to which family (by default invocation).
FAMILY_SCRIPTS = {
    "ooxml": ["zipdump", "oledump"],
    "ole": ["oledump"],
    "pdf": ["pdfid", "pdf-parser"],
    "email": ["emldump"],
    "rtf": ["rtfdump"],
}

_OUTPUT_BOUND = 60000


def didier_dir() -> Path:
    return settings.tools_dir / "didier"


def available_scripts() -> dict[str, Path]:
    d = didier_dir()
    return {name: d / fn for name, fn in SCRIPTS.items() if (d / fn).is_file()}


def _run_one(name: str, script: Path, target: Path, args: list[str] | None) -> dict[str, Any]:
    cmd = [sys.executable, str(script), *(args or []), str(target)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120,
        )
        out = (proc.stdout or "")[:_OUTPUT_BOUND]
        return {"available": True, "returncode": proc.returncode, "output": out,
                "stderr": (proc.stderr or "")[:2000] or None}
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "error": str(exc)}


def analyze(original_path: Path, family: str) -> dict[str, Any]:
    """Run the Didier scripts applicable to ``family`` and capture raw output."""
    result: dict[str, Any] = {"module": "didier", "available": False, "tools": {}, "findings": []}
    present = available_scripts()
    if not present:
        result["error"] = "Didier Stevens scripts not provisioned (tools/didier/)"
        return result
    result["available"] = True
    for name in FAMILY_SCRIPTS.get(family, []):
        script = present.get(name)
        if script is None:
            result["tools"][name] = {"available": False, "error": "not provisioned"}
            continue
        result["tools"][name] = _run_one(name, script, original_path, None)
    return result
