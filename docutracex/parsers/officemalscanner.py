"""OfficeMalScanner (external Windows binary, optional).

OfficeMalScanner (Frank Boldewin) scans Office documents for malicious traces:
shellcode patterns, embedded OLE/PE signatures and brute-forced XOR/ADD/ROL
encodings, plus VBA/OLE structure info. It is a Windows PE binary, provisioned
under ``tools/officemalscanner/`` by scripts/setup_portable_python.py. If the
executable is absent the module degrades gracefully (checked by presence, like
the Didier scripts).

Family-aware orchestration, mirroring the analyst workflow:
- OLE (legacy .doc/.xls/.ppt): ``scan brute`` + ``info`` directly on the file.
- OOXML (.docm/.xlsm/...): capture ``inflate`` output for fidelity, then run
  ``info``/``scan brute`` on each ``vbaProject.bin`` we extract from the package
  (deterministic, instead of parsing the tool's temp path from stdout).

Output is captured raw (as an analyst reads it); the obvious verdict
(``Malicious Index`` and shellcode hits) is promoted to a finding.
"""

from __future__ import annotations

import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from ..config import settings
from ..logging_config import get_logger

log = get_logger(__name__)

EXE_NAME = "OfficeMalScanner.exe"
_OUTPUT_BOUND = 60000
_TIMEOUT = 180

# OfficeMalScanner prints a "Malicious Index = N" summary line.
_MALICIOUS_INDEX = re.compile(r"Malicious Index\s*=\s*(\d+)", re.IGNORECASE)
_SHELLCODE_HINT = re.compile(r"shellcode|FS:\[30h\]|API-Name string|PE-Header", re.IGNORECASE)


def oms_dir() -> Path:
    return settings.tools_dir / "officemalscanner"


def exe_path() -> Path | None:
    p = oms_dir() / EXE_NAME
    return p if p.is_file() else None


def available() -> bool:
    return exe_path() is not None


def _run(exe: Path, target: Path, args: list[str], cwd: Path | None) -> dict[str, Any]:
    cmd = [str(exe), str(target), *args]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=_TIMEOUT, cwd=str(cwd) if cwd else None,
        )
        return {
            "command": " ".join([EXE_NAME, target.name, *args]),
            "returncode": proc.returncode,
            "output": (proc.stdout or "")[:_OUTPUT_BOUND],
            "stderr": (proc.stderr or "")[:2000] or None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"command": " ".join([EXE_NAME, target.name, *args]), "error": str(exc)}


def _extract_vba_bins(original_path: Path, workdir: Path) -> list[Path]:
    """Extract every ``vbaProject.bin`` from an OOXML package into *workdir*.

    Returns the written paths (empty if the file is not a ZIP or has no VBA).
    """
    if not zipfile.is_zipfile(original_path):
        return []
    out: list[Path] = []
    dest_dir = workdir / "bins"
    try:
        with zipfile.ZipFile(original_path) as zf:
            targets = [n for n in zf.namelist() if n.lower().endswith("vbaproject.bin")]
            if targets:
                dest_dir.mkdir(parents=True, exist_ok=True)
            for i, name in enumerate(targets):
                safe = f"{i:02d}_{Path(name).name}"
                dest = dest_dir / safe
                dest.write_bytes(zf.read(name))
                out.append(dest)
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not extract vbaProject.bin for OfficeMalScanner: %s", exc)
    return out


def _promote_findings(result: dict[str, Any]) -> None:
    """Promote OfficeMalScanner's verdict to findings from the captured output."""
    for key, tool in result.get("tools", {}).items():
        out = tool.get("output") or ""
        if not out:
            continue
        m = _MALICIOUS_INDEX.search(out)
        if m:
            idx = int(m.group(1))
            if idx > 0:
                sev = "high" if idx >= 10 else "medium"
                result["findings"].append({
                    "tool": "officemalscanner", "rule": "malicious_index", "severity": sev,
                    "detail": f"Malicious Index = {idx} ({key})", "location": "officemalscanner",
                })
        if _SHELLCODE_HINT.search(out):
            result["findings"].append({
                "tool": "officemalscanner", "rule": "shellcode_signature", "severity": "high",
                "detail": f"Shellcode/encoded-payload signature reported ({key})",
                "location": "officemalscanner",
            })


def analyze(original_path: Path, family: str,
            extracted_dir: Path | None = None) -> dict[str, Any]:
    """Run OfficeMalScanner for *family* and capture raw output. Never raises."""
    result: dict[str, Any] = {
        "module": "officemalscanner", "available": False,
        "tools": {}, "findings": [], "error": None,
    }
    exe = exe_path()
    if exe is None:
        result["error"] = "OfficeMalScanner.exe not provisioned (tools/officemalscanner/)"
        return result
    result["available"] = True

    workdir = (extracted_dir / "officemalscanner") if extracted_dir else None
    if workdir:
        workdir.mkdir(parents=True, exist_ok=True)

    if family == "ole":
        result["tools"]["scan"] = _run(exe, original_path, ["scan", "brute"], workdir)
        result["tools"]["info"] = _run(exe, original_path, ["info"], workdir)
    elif family == "ooxml":
        # Keep the inflate report for fidelity with the analyst's own workflow...
        result["tools"]["inflate"] = _run(exe, original_path, ["inflate"], workdir)
        # ...then analyze the VBA container(s) we extract ourselves (deterministic).
        if workdir:
            for b in _extract_vba_bins(original_path, workdir):
                result["tools"][f"info:{b.name}"] = _run(exe, b, ["info"], workdir)
                result["tools"][f"scan:{b.name}"] = _run(exe, b, ["scan", "brute"], workdir)

    _promote_findings(result)
    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
