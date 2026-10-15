"""ViperMonkey: VBA emulation (runs on the PyPy 2.7 portable).

olevba/mraptor read the macro source and spot keywords; ViperMonkey *emulates*
it — no Office, nothing touches the host — and records what the macro would do:
commands it would run, URLs it would fetch, files it would write, COM objects it
would create. That resolves the usual obfuscation (Chr() arithmetic,
StrReverse, Replace chains, payloads read from document variables / form fields
/ cells) into concrete actions and IOCs.

ViperMonkey is Python 2 only, so it runs on a separate PyPy 2.7 interpreter
under ``tools/pypy/``. It works on a copy of the file inside a temporary folder
(it writes "artifacts" next to its input); artifacts are then moved under the
case's extracted/ folder.
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

EMULATION_MINUTES = 3          # ViperMonkey's own time limit
PROCESS_TIMEOUT = 8 * 60       # hard limit for the whole run
_MAX_ACTIONS = 500

# action keyword -> (rule, severity, label); first match wins.
_ACTION_RULES: list[tuple[tuple[str, ...], str, str, str]] = [
    (("execute command", "shell", "run", "wscript.shell", "exec"),
     "vm_execute", "high", "would execute a command"),
    (("download", "url", "http", "xmlhttp", "open url", "winhttp"),
     "vm_network", "high", "would access the network"),
    (("write file", "dropped file", "savetofile", "save file", "file write"),
     "vm_write_file", "high", "would write a file"),
    (("powershell", "cmd.exe", "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin"),
     "vm_lolbin", "high", "uses a LOLBin"),
    (("createobject", "getobject", "object.method"),
     "vm_com_object", "medium", "creates/uses a COM object"),
    (("registry", "regwrite"), "vm_registry", "high", "would modify the registry"),
]
_IGNORED_ACTIONS = ("found entry point", "found heuristic entry point", "display message")


def vipermonkey_status() -> dict[str, Any]:
    """Is the PyPy 2.7 interpreter present and does ViperMonkey import in it?"""
    exe = settings.pypy_python()
    if exe is None:
        return {"available": False, "detail": "PyPy 2.7 not provisioned under tools/pypy/"}
    rec = toolrun.run([str(exe), "-c", "import vipermonkey.vmonkey"], "import vipermonkey",
                      timeout=120)
    if rec.get("returncode") == 0:
        return {"available": True, "detail": f"ViperMonkey importable on {exe}"}
    err = (rec.get("stderr") or rec.get("error") or "").strip().splitlines()
    return {"available": False,
            "detail": f"PyPy present but ViperMonkey not importable: {err[-1] if err else '?'}"}


def _classify(action: str, params: str) -> tuple[str, str, str] | None:
    text = f"{action} {params}".lower()
    if action.lower() in _IGNORED_ACTIONS:
        return None
    for keys, rule, sev, label in _ACTION_RULES:
        if any(k in text for k in keys):
            return rule, sev, label
    return "vm_action", "low", "emulated action"


def analyze(original_path: Path, extracted_dir: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "vipermonkey", "available": False, "status": "ok",
        "actions": [], "potential_iocs": [], "vba_builtins": [], "shellcode": [],
        "artifacts": [], "findings": [],
    }
    exe = settings.pypy_python()
    if exe is None:
        result["error"] = "PyPy 2.7 / ViperMonkey not provisioned"
        return result
    result["available"] = True

    work = Path(tempfile.mkdtemp(prefix="dtx_vm_"))
    try:
        target = work / original_path.name
        shutil.copyfile(original_path, target)
        out_json = work / "vmonkey.json"
        rec = toolrun.run(
            [str(exe), "-m", "vipermonkey.vmonkey", "-s", "-c", "-t", str(EMULATION_MINUTES),
             "-l", "warning", "-o", str(out_json), str(target)],
            f"vmonkey -s -c -t {EMULATION_MINUTES} {original_path.name}",
            timeout=PROCESS_TIMEOUT, cwd=work)
        result["tool"] = rec
        data: dict[str, Any] = {}
        if out_json.is_file():
            try:
                data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
            except ValueError:
                data = {}
        if not data:
            result["status"] = "error" if rec.get("error") or rec.get("returncode") else "ok"
            if rec.get("error"):
                result["error"] = rec["error"]
        result["actions"] = [
            {"action": str(a.get("action", "")), "parameters": str(a.get("parameters", "")),
             "description": str(a.get("description", ""))}
            for a in (data.get("actions") or [])[:_MAX_ACTIONS]]
        result["potential_iocs"] = [str(x) for x in data.get("potential_iocs") or []][:200]
        result["vba_builtins"] = [str(x) for x in data.get("vba_builtins") or []][:200]
        result["shellcode"] = [str(x)[:500] for x in data.get("shellcode") or []][:20]

        # Artifacts (files the emulated macro "dropped") -> extracted/vipermonkey/.
        art_dir = work / f"{target.name}_artifacts"
        if art_dir.is_dir() and extracted_dir is not None:
            dest_root = extracted_dir / "vipermonkey"
            for f in sorted(art_dir.rglob("*")):
                if f.is_file():
                    dest = dest_root / f.relative_to(art_dir)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(f, dest)
                    result["artifacts"].append(dest.relative_to(extracted_dir.parent).as_posix())
    finally:
        shutil.rmtree(work, ignore_errors=True)

    _findings(result)
    result["counts"] = {"findings": len(result["findings"]), "actions": len(result["actions"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result


def _findings(result: dict[str, Any]) -> None:
    seen: set[tuple[str, str]] = set()
    for a in result["actions"]:
        cls = _classify(a["action"], a["parameters"])
        if cls is None:
            continue
        rule, sev, label = cls
        key = (rule, a["parameters"])
        if key in seen:
            continue
        seen.add(key)
        result["findings"].append({
            "tool": "vipermonkey", "rule": rule, "severity": sev,
            "detail": f"Emulated macro {label}: {a['action']} — {a['parameters'][:300]}",
            "location": "vba-emulation",
            "evidence": f"{a['action']} | {a['parameters']} | {a['description']}"[:1000],
        })
    if result["shellcode"]:
        result["findings"].append({
            "tool": "vipermonkey", "rule": "vm_shellcode", "severity": "high",
            "detail": f"Emulation produced {len(result['shellcode'])} shellcode-like byte array(s)",
            "location": "vba-emulation", "evidence": result["shellcode"][0][:400]})
    if result["artifacts"]:
        result["findings"].append({
            "tool": "vipermonkey", "rule": "vm_artifacts", "severity": "high",
            "detail": f"Emulation dropped {len(result['artifacts'])} file(s)",
            "location": "vba-emulation", "evidence": "\n".join(result["artifacts"][:10])})
    iocs = [i for i in result["potential_iocs"] if "schemas.openxmlformats.org" not in i
            and "schemas.microsoft.com" not in i]
    if iocs:
        result["findings"].append({
            "tool": "vipermonkey", "rule": "vm_potential_iocs", "severity": "medium",
            "detail": f"{len(iocs)} potential IOC(s) assembled in VBA variables during emulation",
            "location": "vba-emulation", "evidence": "\n".join(iocs[:15])})
