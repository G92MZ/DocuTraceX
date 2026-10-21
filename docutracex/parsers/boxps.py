"""box-ps: PowerShell behavioural sandbox (runs on the portable PowerShell Core).

Our PowerShell analysis so far was static (layered deobfuscation + rules). box-ps
(GPL-3.0, provisioned under ``tools/boxps/`` and invoked through the portable
``pwsh`` under ``tools/pwsh/``) overrides the dangerous cmdlets and *emulates* the
script, recording what it would do — network fetches, dropped files, commands,
decoded layers — without executing anything real. It is to PowerShell what the
STPyV8 sandbox is to JavaScript and ViperMonkey is to VBA.

``analyze(code)`` runs box-ps on one PowerShell command/script and returns its
actions, indicators, dropped artifacts, the deobfuscated layers and findings.
Degrades gracefully: when pwsh/box-ps are not provisioned it returns
``available=False`` and nothing else runs.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .. import toolrun
from ..config import settings
from ..logging_config import get_logger

log = get_logger(__name__)

PROCESS_TIMEOUT = 90
_MAX_ACTIONS = 300
_MAX_LAYER = 200_000

# behaviour keyword -> (rule, severity, label); first match wins.
_BEHAVIOUR_RULES: list[tuple[tuple[str, ...], str, str, str]] = [
    (("network", "download", "http", "webclient", "webrequest", "uri"),
     "boxps_network", "high", "would access the network"),
    (("file_system", "file write", "savetofile", "writeallbytes", "dropped", "outfile"),
     "boxps_file", "high", "would write a file"),
    (("code_execution", "start_process", "command", "shell", "invoke", "iex"),
     "boxps_exec", "high", "would execute a command / process"),
    (("code_import", "reflection", "assembly", "add-type", "dllimport"),
     "boxps_inject", "high", "loads code in memory"),
    (("registry",), "boxps_registry", "high", "would modify the registry"),
    (("scheduled", "persistence"), "boxps_persist", "high", "would set up persistence"),
]


def boxps_status() -> dict[str, Any]:
    """Is pwsh present and box-ps provisioned?"""
    pwsh = settings.pwsh_executable()
    box = settings.boxps_script()
    if pwsh is None:
        return {"available": False, "detail": "PowerShell Core not provisioned under tools/pwsh/"}
    if box is None:
        return {"available": False, "detail": "box-ps not provisioned under tools/boxps/"}
    return {"available": True, "detail": f"box-ps ready on {pwsh}"}


def _classify(text: str) -> tuple[str, str, str] | None:
    low = text.lower()
    for keys, rule, sev, label in _BEHAVIOUR_RULES:
        if any(k in low for k in keys):
            return rule, sev, label
    return None


def _load_report(out: Path) -> dict[str, Any]:
    """Read box-ps output defensively: a report.json (or any json) holding the
    actions, plus layers.ps1 with the deobfuscated script."""
    report: dict[str, Any] = {"actions": [], "layers": "", "raw": None}
    # Deobfuscated layers.
    for name in ("layers.ps1", "Layers.ps1"):
        f = out / name
        if f.is_file():
            try:
                report["layers"] = f.read_text(encoding="utf-8", errors="replace")[:_MAX_LAYER]
            except OSError:
                pass
            break
    # Actions / report JSON.
    candidates = [out / "report.json", out / "actions.json"] + sorted(out.glob("*.json"))
    for f in candidates:
        if not f.is_file():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        actions = data.get("Actions") if isinstance(data, dict) else (data if isinstance(data, list) else None)
        if isinstance(actions, list):
            report["actions"] = actions[:_MAX_ACTIONS]
            report["raw"] = data if isinstance(data, dict) else {"Actions": actions}
            break
    return report


def analyze(code: str, location: str = "powershell") -> dict[str, Any]:
    result: dict[str, Any] = {"available": False, "actions": [], "iocs": [],
                              "artifacts": [], "layers": "", "findings": [], "error": None}
    pwsh = settings.pwsh_executable()
    box = settings.boxps_script()
    if pwsh is None or box is None:
        result["error"] = "pwsh / box-ps not provisioned"
        return result
    if not code or not code.strip():
        return result
    result["available"] = True

    work = Path(tempfile.mkdtemp(prefix="dtx_boxps_"))
    try:
        infile = work / "in.ps1"
        outdir = work / "out"
        infile.write_text(code, encoding="utf-8")
        rec = toolrun.run(
            [str(pwsh), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(box),
             "-InFile", str(infile), "-OutDir", str(outdir)],
            f"box-ps {location}", timeout=PROCESS_TIMEOUT, cwd=box.parent)
        result["tool"] = rec
        report = _load_report(outdir) if outdir.is_dir() else {"actions": [], "layers": ""}
        result["layers"] = report.get("layers") or ""
        for a in report.get("actions") or []:
            if not isinstance(a, dict):
                continue
            behaviours = a.get("Behaviors") or a.get("Behaviours") or a.get("behaviors") or []
            text = " ".join(str(b) for b in behaviours) + " " + json.dumps(a, default=str)[:400]
            line = str(a.get("Line") or a.get("line") or "")[:300]
            result["actions"].append({"behaviours": [str(b) for b in behaviours], "line": line})
            cls = _classify(text)
            if cls:
                rule, sev, label = cls
                result["findings"].append({
                    "tool": "boxps", "rule": rule, "severity": sev,
                    "detail": f"PowerShell sandbox (box-ps): {label}",
                    "location": location, "evidence": line or text[:400]})
        # Network indicators the report surfaces directly.
        raw = report.get("raw") or {}
        for key in ("PotentialIndicators", "Indicators", "Network", "network"):
            for ind in (raw.get(key) or []) if isinstance(raw, dict) else []:
                result["iocs"].append(str(ind)[:400])
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # Dedupe findings.
    seen: set[tuple[str, str]] = set()
    uniq = []
    for f in result["findings"]:
        k = (f["rule"], f["evidence"][:120])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    result["findings"] = uniq
    return result
