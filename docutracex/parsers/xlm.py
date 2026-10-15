"""Excel 4.0 (XLM) macro deobfuscation via XLMMacroDeobfuscator.

XLM macros live in hidden/very-hidden macro sheets and are a common evasion
(distinct from VBA). This runs XLMMacroDeobfuscator statically to detect and
deobfuscate them; the deobfuscated formulas feed the IOC phase. It never opens
Excel or executes anything (uses the library's own emulator).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

_MAX_FORMULAS = 5000
_TIMEOUT = 60


def analyze(original_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "xlmdeobf",
        "available": False,
        "tool_version": None,
        "xlm_macros": False,
        "formulas": [],
        "code_text": "",
        "findings": [],
        "error": None,
        "status": "ok",
    }
    try:
        from .. import quiet
        quiet.silence()  # hide the harmless "pywin32 is not installed" banner
        from XLMMacroDeobfuscator import deobfuscator
        import importlib.metadata as md
        result["tool_version"] = md.version("XLMMacroDeobfuscator")
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"XLMMacroDeobfuscator unavailable: {exc}"
        return result

    result["available"] = True
    try:
        records = deobfuscator.process_file(
            file=str(original_path),
            noninteractive=True,
            return_deobfuscated=True,
            silent=True,
            noindent=True,
            timeout=_TIMEOUT,
            output_formula_format="[[CELL-ADDR]], [[INT-FORMULA]]",
        )
        records = [str(r) for r in (records or [])]
        if records:
            result["xlm_macros"] = True
            result["formulas"] = records[:_MAX_FORMULAS]
            result["code_text"] = "\n".join(result["formulas"])
            result["findings"].append({
                "tool": "xlmdeobf", "rule": "xlm_macros", "severity": "high",
                "detail": f"{len(records)} deobfuscated Excel 4.0 (XLM) formula(s)",
                "location": "xlm",
            })
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"XLMMacroDeobfuscator failed: {exc}"

    result["command"] = f"xlmdeobfuscator --file {original_path.name} --no-indent (python API)"
    result["output"] = result["error"] or ("\n".join(result["formulas"]) if result["formulas"]
                                           else "No Excel 4.0 (XLM) macros found.")
    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
