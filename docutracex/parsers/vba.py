"""VBA macro analysis via oletools (external tool, runs on the portable).

This is the first real third-party analysis tool. ``olevba`` (oletools, BSD)
statically extracts and analyzes VBA macros from Office files (OOXML and legacy
OLE): it lists modules, decompresses the VBA source, and flags auto-exec
triggers, suspicious keywords and IOCs — without executing anything.

The parser code runs on the portable Python (where oletools is installed), so it
imports oletools directly. If oletools is missing (e.g. in a dev environment
without the portable), it degrades gracefully instead of failing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

_CODE_BOUND = 100000  # bounded VBA source kept for the IOC phase / display

# olevba analysis result type -> severity
_SEVERITY = {
    "AutoExec": "high",
    "Suspicious": "medium",
    "IOC": "low",
    "Hex String": "low",
    "Base64 String": "low",
    "Dridex string": "medium",
    "VBA string": "info",
}


def analyze(original_path: Path) -> dict[str, Any]:
    """Analyze VBA macros with olevba. Never raises on tool failure."""
    result: dict[str, Any] = {
        "module": "vba",
        "tool": "oletools",
        "tool_version": None,
        "available": False,
        "macros": False,
        "vba_modules": [],
        "findings": [],
        "code_text": "",
        "error": None,
        "status": "ok",
    }
    try:
        from oletools.olevba import VBA_Parser, __version__ as olevba_version
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"oletools unavailable: {exc}"
        return result

    result["available"] = True
    result["tool_version"] = olevba_version

    vp = None
    try:
        vp = VBA_Parser(str(original_path))
        if vp.detect_vba_macros():
            result["macros"] = True
            code_parts: list[str] = []
            for (_f, stream, vba_name, code) in vp.extract_macros():
                result["vba_modules"].append({
                    "stream": stream,
                    "vba_filename": vba_name,
                    "code_length": len(code or ""),
                })
                if code:
                    code_parts.append(code)
            result["code_text"] = ("\n".join(code_parts))[:_CODE_BOUND]
            for (kind, keyword, description) in vp.analyze_macros():
                sev = _SEVERITY.get(kind, "info")
                rule = "vba_" + str(kind).lower().replace(" ", "_")
                result["findings"].append({
                    "rule": rule,
                    "severity": sev,
                    "detail": f"{keyword}: {description}",
                    "location": "vba",
                })
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"olevba failed: {exc}"
    finally:
        try:
            if vp is not None:
                vp.close()
        except Exception:  # noqa: BLE001
            pass

    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
