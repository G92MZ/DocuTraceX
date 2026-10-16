"""Excel binary workbooks (.xlsb) via pyxlsb2 (Apache-2.0).

.xlsb keeps sheets and formulas in BIFF12 binary parts, so the XML-based Excel
parser cannot read them. This produces the same "excel" sub-result shape
(sheets, hidden sheets, formulas) plus what matters for maldocs: Excel 4.0
macro sheets, Auto_Open-style defined names and dangerous XLM functions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .office_rules import XLM_DANGEROUS

_MAX_FORMULAS = 2000


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"rule": rule, "severity": severity, "detail": detail, "location": location,
            "evidence": evidence[:2000]}


# gmzpt
def analyze(original_path: Path) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "excel", "format": "excel", "variant": "xlsb", "status": "ok",
                           "sheets": [], "formulas": [], "macro_formulas": [], "defined_names": [],
                           "findings": [], "metadata": {}}
    try:
        from pyxlsb2 import open_workbook
        from pyxlsb2.formula import Formula
    except Exception as exc:  # noqa: BLE001
        res["status"] = "error"
        res["error"] = f"pyxlsb2 unavailable: {exc}"
        return res
    try:
        with open_workbook(str(original_path)) as wb:
            for s in wb.sheets:
                state = str(getattr(s.state, "name", s.state)).lower()
                state = {"veryhidden": "veryHidden", "very_hidden": "veryHidden"}.get(state, state)
                kind = str(s.type).lower()
                res["sheets"].append({"name": s.name, "state": state, "type": kind})
                try:
                    with wb.get_sheet_by_name(s.name) as sh:
                        for row in sh.rows():
                            for c in row:
                                if not c.formula or len(res["formulas"]) >= _MAX_FORMULAS:
                                    continue
                                try:
                                    text = Formula.parse(c.formula).stringify(wb)
                                except Exception:  # noqa: BLE001
                                    continue
                                res["formulas"].append(text)
                                if "macro" in kind:
                                    res["macro_formulas"].append(f"{s.name}!R{c.row_num + 1}C{c.col + 1}: ={text}")
                except Exception:  # noqa: BLE001
                    continue
            try:
                for name, dn in (wb.defined_names or {}).items():
                    res["defined_names"].append({"name": str(name), "refers_to": str(getattr(dn, "formula", ""))})
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        res["status"] = "error"
        res["error"] = f"pyxlsb2 failed: {exc}"
        return res

    for s in res["sheets"]:
        if s["state"] in ("hidden", "veryHidden"):
            sev = "high" if "macro" in s["type"] else ("medium" if s["state"] == "veryHidden" else "low")
            res["findings"].append(_finding("hidden_sheet", sev, f"Sheet '{s['name']}' is {s['state']}"
                                            + (" (Excel 4.0 macro sheet)" if "macro" in s["type"] else ""),
                                            "xl/workbook.bin"))
    macro = [s["name"] for s in res["sheets"] if "macro" in s["type"]]
    if macro:
        res["findings"].append(_finding("xlm_macrosheet", "high",
                                        f"{len(macro)} Excel 4.0 (XLM) macro sheet(s): {', '.join(macro)}",
                                        "xl/workbook.bin", "\n".join(res["macro_formulas"][:15])))
    for dn in res["defined_names"]:
        nm = dn["name"].lower().replace("_xlnm.", "")
        if nm.startswith(("auto_open", "auto_close", "auto_activate", "auto_deactivate")):
            res["findings"].append(_finding("xlm_auto_open", "high",
                                            f"Auto-run name '{dn['name']}' (runs an XLM macro on open/close)",
                                            "xl/workbook.bin", f"{dn['name']} -> {dn['refers_to']}"))
    danger = [f for f in res["macro_formulas"]
              if any(re.search(rf"\b{re.escape(k)}\s*\(", f.upper()) for k in XLM_DANGEROUS)]
    if danger:
        res["findings"].append(_finding("xlm_dangerous_function", "high",
                                        f"{len(danger)} XLM formula(s) with dangerous functions",
                                        "xl/macrosheets", "\n".join(danger[:10])))
    for f in res["formulas"]:
        up = f.upper()
        for kw, rule, sev in (("WEBSERVICE", "webservice", "high"), ("FILTERXML", "filterxml", "high")):
            if kw in up:
                res["findings"].append(_finding(rule, sev, f"Formula uses {kw}", "xl/worksheets", "=" + f))

    res["sheet_count"] = len(res["sheets"])
    res["hidden_sheets"] = [s["name"] for s in res["sheets"] if s["state"] in ("hidden", "veryHidden")]
    res["formula_count"] = len(res["formulas"])
    res["counts"] = {"findings": len(res["findings"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
