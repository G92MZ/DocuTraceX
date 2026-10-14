"""oletools suite (external tools, run on the portable).

Runs the relevant oletools analyzers over an Office document and aggregates
their findings. None of them execute content:

- olevba  — extracts and analyzes VBA macros (auto-exec, suspicious keywords,
  obfuscation, IOCs).
- oleid   — flags suspicious document characteristics (macros, encryption,
  external relationships, Flash, ...).
- mraptor — rates macros as likely-malicious (AutoExec + Write + Execute).
- msodde  — detects dangerous DDE links.
- oleobj  — detects and extracts embedded OLE objects.

Each tool is wrapped independently so one failure does not stop the others.
oletools is BSD-licensed and runs on the portable Python.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

_CODE_BOUND = 400000       # total VBA source kept for the IOC phase
_MODULE_BOUND = 200000     # per-module source kept for display

# olevba analyze_macros result type -> severity
_OLEVBA_SEV = {
    "AutoExec": "high", "Suspicious": "medium", "IOC": "low",
    "Hex String": "low", "Base64 String": "low", "Dridex string": "medium",
    "VBA string": "info",
}


def _finding(tool: str, rule: str, severity: str, detail: str, location: str = "vba") -> dict:
    return {"tool": tool, "rule": rule, "severity": severity, "detail": detail, "location": location}


def _run_olevba(path: Path, result: dict[str, Any]) -> str:
    """Returns the extracted VBA source (for mraptor / IOC)."""
    code = ""
    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser(str(path))
        try:
            info: dict[str, Any] = {"macros": False, "modules": []}
            if vp.detect_vba_macros():
                info["macros"] = True
                parts = []
                for (_f, stream, vba_name, c) in vp.extract_macros():
                    c = c or ""
                    info["modules"].append({
                        "stream": stream,
                        "vba_filename": vba_name,
                        "code_length": len(c),
                        "code": c[:_MODULE_BOUND],
                        "code_truncated": len(c) > _MODULE_BOUND,
                    })
                    if c:
                        parts.append(c)
                code = "\n".join(parts)
                for (kind, keyword, desc) in vp.analyze_macros():
                    sev = _OLEVBA_SEV.get(kind, "info")
                    rule = "olevba_" + str(kind).lower().replace(" ", "_")
                    result["findings"].append(_finding("olevba", rule, sev, f"{keyword}: {desc}"))
            result["tools"]["olevba"] = info
        finally:
            vp.close()
    except Exception as exc:  # noqa: BLE001
        result["tools"]["olevba"] = {"error": str(exc)}
    return code[:_CODE_BOUND]


def _run_oleid(path: Path, result: dict[str, Any]) -> None:
    try:
        from oletools.oleid import OleID
        indicators = OleID(str(path)).check()
        recs = []
        for ind in indicators:
            risk = str(getattr(ind, "risk", "") or "").lower()
            name = getattr(ind, "name", getattr(ind, "id", ""))
            value = getattr(ind, "value", "")
            recs.append({"name": name, "value": str(value), "risk": risk})
            if risk in ("low", "medium", "high"):
                result["findings"].append(
                    _finding("oleid", "oleid_" + str(getattr(ind, "id", "indicator")),
                             risk, f"{name}: {value}", "document"))
        result["tools"]["oleid"] = {"indicators": recs}
    except Exception as exc:  # noqa: BLE001
        result["tools"]["oleid"] = {"error": str(exc)}


def _run_mraptor(code: str, result: dict[str, Any]) -> None:
    if not code:
        return
    try:
        from oletools import mraptor
        mr = mraptor.MacroRaptor(code)
        mr.scan()
        flags = mr.get_flags()
        result["tools"]["mraptor"] = {
            "suspicious": bool(mr.suspicious),
            "flags": flags,
            "matches": list(getattr(mr, "matches", []) or []),
        }
        if mr.suspicious:
            result["findings"].append(
                _finding("mraptor", "mraptor_suspicious", "high",
                         f"Likely malicious macro (flags {flags}): "
                         f"{', '.join(getattr(mr, 'matches', []) or [])}"))
    except Exception as exc:  # noqa: BLE001
        result["tools"]["mraptor"] = {"error": str(exc)}


def _run_msodde(path: Path, result: dict[str, Any]) -> None:
    try:
        from oletools import msodde
        out = msodde.process_file(str(path), field_filter_mode=getattr(msodde, "FIELD_FILTER_DDE", None))
        links = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
        result["tools"]["msodde"] = {"dde_links": links}
        for link in links:
            result["findings"].append(
                _finding("msodde", "dde_link", "high", link, "dde"))
    except Exception as exc:  # noqa: BLE001
        result["tools"]["msodde"] = {"error": str(exc)}


def _run_oleobj(path: Path, extracted_dir: Path | None, result: dict[str, Any]) -> None:
    try:
        from oletools import oleobj
        data = path.read_bytes()
        out_dir = (extracted_dir / "oleobj") if extracted_dir else None
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
        before = set(out_dir.iterdir()) if out_dir and out_dir.exists() else set()
        oleobj.process_file(str(path), data, output_dir=str(out_dir) if out_dir else None)
        objects = []
        if out_dir and out_dir.exists():
            for f in sorted(set(out_dir.iterdir()) - before):
                if f.is_file():
                    raw = f.read_bytes()
                    objects.append({
                        "stored_path": str(f.relative_to(extracted_dir.parent).as_posix()),
                        "size_bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    })
        result["tools"]["oleobj"] = {"objects": objects}
        if objects:
            result["findings"].append(
                _finding("oleobj", "embedded_ole_object", "medium",
                         f"{len(objects)} embedded OLE object(s) extracted", "oleobj"))
    except Exception as exc:  # noqa: BLE001
        result["tools"]["oleobj"] = {"error": str(exc)}


def analyze(original_path: Path, extracted_dir: Path | None = None) -> dict[str, Any]:
    """Run the oletools suite. Never raises on tool failure."""
    result: dict[str, Any] = {
        "module": "oletools",
        "available": False,
        "tool_versions": {},
        "tools": {},
        "findings": [],
        "code_text": "",
        "dde_links": [],
        "error": None,
        "status": "ok",
    }
    try:
        import oletools
        from oletools.olevba import __version__ as olevba_version
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"oletools unavailable: {exc}"
        return result

    result["available"] = True
    result["tool_versions"] = {"oletools": getattr(oletools, "__version__", olevba_version)}

    code = _run_olevba(original_path, result)
    result["code_text"] = code
    _run_oleid(original_path, result)
    _run_mraptor(code, result)
    _run_msodde(original_path, result)
    _run_oleobj(original_path, extracted_dir, result)

    result["dde_links"] = result["tools"].get("msodde", {}).get("dde_links", [])
    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
