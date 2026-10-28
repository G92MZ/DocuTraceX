"""VBA / OLE structure tools for Office documents.

Runs alongside oletools (olevba, oleid, ...) and ViperMonkey:

- pcodedmp: disassembles the compiled VBA p-code. pcode2code: rebuilds VBA
  source from that p-code. Together with olevba (which reports "VBA Stomping"
  when pcodedmp is installed) they expose code that only exists compiled.
- Didier Stevens' oledump plugins: VBA summary, Declare/CreateObject lines
  (plugin_vba_dco), routines, HTTP-looking strings in obfuscated code
  (plugin_http_heuristics), generic stream objects and BIFF/XLM records.
- oletools oletimes / olemeta / oledir: per-stream timestamps (timeline),
  SummaryInformation metadata and the directory tree.
- Own checks: EvilClippy tricks (modules hidden from the VBA editor, locked
  projects), VBA source removed while p-code remains, and data hidden after
  the last OLE sector.

All tools run as separate processes with time limits; their raw output is kept.
For OOXML files the OLE tools work on the extracted vbaProject.bin.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .. import quiet, toolrun
from ..logging_config import get_logger
from .didier import didier_dir
from ..config import tmo

log = get_logger(__name__)

_VBA_SPECIAL = {"dir", "_vba_project", "projectwm", "project"}
_RISKY_DECLARE = ("urldownloadtofile", "shellexecute", "winexec", "createprocess", "virtualalloc",
                  "rtlmovememory", "createthread", "writeprocessmemory", "loadlibrary", "getprocaddress",
                  "internetopen", "callwindowproc", "enumsystemcodepages")


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "vbatools", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


def _py(target: str, args: list[str], shown: str, script: bool = False, timeout: int = tmo(180),
        cwd: Path | None = None) -> dict[str, Any]:
    return toolrun.run(quiet.python_tool_cmd(target, args, script), shown, timeout=timeout,
                       cwd=cwd, extra_env=toolrun.with_package_path())


def _vba_ole_path(original: Path, work: Path) -> tuple[Path | None, str]:
    """The OLE file holding the VBA project: the document itself (legacy OLE) or
    the vbaProject.bin extracted from an OOXML package."""
    if zipfile.is_zipfile(original):
        with zipfile.ZipFile(original) as zf:
            names = [n for n in zf.namelist() if n.lower().endswith("vbaproject.bin")]
            if not names:
                return None, ""
            dest = work / "vbaProject.bin"
            dest.write_bytes(zf.read(names[0]))
            return dest, names[0]
    return original, "document"


def _project_checks(ole_path: Path, location: str, res: dict[str, Any]) -> None:
    """EvilClippy-style hiding and protection, from the PROJECT stream."""
    try:
        import olefile
        ole = olefile.OleFileIO(str(ole_path))
    except Exception:  # noqa: BLE001
        return
    try:
        entries = ["/".join(e) for e in ole.listdir()]
        for proj in [e for e in entries if e.split("/")[-1].upper() == "PROJECT"]:
            prefix = proj[: -len("PROJECT")]
            text = ole.openstream(proj).read().decode("latin-1", "replace")
            listed = {m.group(2) for m in re.finditer(
                r"^(Module|Document|Class|BaseClass)=([^/\r\n]+)", text, re.MULTILINE)}
            streams = {e[len(prefix) + 4:] for e in entries
                       if e.startswith(prefix + "VBA/") and "/" not in e[len(prefix) + 4:]}
            modules = {s for s in streams if s.lower() not in _VBA_SPECIAL
                       and not s.lower().startswith("__srp_")}
            hidden = sorted(modules - listed)
            res["project"] = {"listed_modules": sorted(listed), "module_streams": sorted(modules),
                              "hidden_modules": hidden}
            if hidden:
                res["findings"].append(_finding(
                    "vba_hidden_module", "high",
                    f"VBA module(s) hidden from the VBA editor (EvilClippy): {', '.join(hidden)}",
                    location, "Present in the VBA storage but not listed in the PROJECT stream"))
            m = re.search(r'^DPB="([0-9A-Fa-f]*)"', text, re.MULTILINE)
            if m and len(m.group(1)) >= 40:
                res["project"]["locked"] = True
                res["findings"].append(_finding(
                    "vba_project_locked", "medium",
                    "VBA project is password-protected / locked for viewing",
                    location, f'DPB="{m.group(1)[:60]}..."'))
            if not re.search(r"^ID=", text, re.MULTILINE) or "[Host Extender Info]" not in text:
                res["findings"].append(_finding(
                    "vba_project_stream_tampered", "medium",
                    "PROJECT stream lacks standard sections (tampered / generated by a tool)",
                    location, text[:300]))
    finally:
        ole.close()


def _trailing_data(ole_path: Path, location: str, res: dict[str, Any]) -> None:
    """Data hidden after the last sector used by the compound file."""
    try:
        import olefile
        ole = olefile.OleFileIO(str(ole_path))
    except Exception:  # noqa: BLE001
        return
    try:
        used = [i for i, v in enumerate(ole.fat) if v != 0xFFFFFFFF]
        if used:
            end = (max(used) + 2) * ole.sectorsize
            size = ole_path.stat().st_size
            if size - end > ole.sectorsize:
                res["findings"].append(_finding(
                    "ole_trailing_data", "medium",
                    f"{size - end} bytes after the last allocated OLE sector (hidden data)",
                    location, f"file size {size}, last allocated byte {end}"))
    except Exception:  # noqa: BLE001
        pass
    finally:
        ole.close()


def _pcode_checks(res: dict[str, Any], olevba_modules: list[dict[str, Any]]) -> None:
    """VBA source removed (or replaced by blanks) while the p-code still exists."""
    dis = (res["tools"].get("pcodedmp") or {}).get("output", "")
    pcode_lines = len(re.findall(r"^Line #\d+:\s*\n\s+\S", dis, re.MULTILINE))
    src = "\n".join(m.get("code") or "" for m in olevba_modules)
    real_src = [ln for ln in src.splitlines()
                if ln.strip() and not ln.strip().lower().startswith("attribute ")]
    if pcode_lines >= 3 and not real_src:
        res["findings"].append(_finding(
            "vba_source_removed", "high",
            "VBA p-code present but the source code is empty (stomped / stripped source)",
            "vba", f"{pcode_lines} p-code line(s), 0 source lines"))


def _plugin_findings(res: dict[str, Any]) -> None:
    dco = (res["tools"].get("oledump plugin_vba_dco") or {}).get("output", "")
    risky = [ln.strip() for ln in dco.splitlines()
             if "declare" in ln.lower() and any(k in ln.lower() for k in _RISKY_DECLARE)]
    if risky:
        res["findings"].append(_finding("vba_risky_api_declare", "high",
                                        f"{len(risky)} Windows API declaration(s) often used by droppers",
                                        "vba", "\n".join(risky[:10])))
    http = (res["tools"].get("oledump plugin_http_heuristics") or {}).get("output", "")
    urls = sorted({u for u in re.findall(r"https?://[^\s'\"<>]+", http)})
    if urls:
        res["findings"].append(_finding("vba_hidden_url", "high",
                                        f"{len(urls)} URL(s) recovered from obfuscated strings "
                                        "(oledump plugin_http_heuristics)", "vba", "\n".join(urls[:10])))
    biff = (res["tools"].get("oledump plugin_biff -x") or {}).get("output", "")
    vh = [ln.strip() for ln in biff.splitlines() if "very hidden" in ln.lower()]
    if any("macro" in ln.lower() for ln in vh):
        res["findings"].append(_finding("xlm_very_hidden_macrosheet", "high",
                                        "Excel 4.0 macro sheet set to 'very hidden' (BIFF)",
                                        "Workbook", "\n".join(vh[:5])))


def analyze(original_path: Path, family: str, vba_present: bool,
            olevba_modules: list[dict[str, Any]] | None = None,
            is_excel_binary: bool = False) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "vbatools", "status": "ok", "tools": {}, "findings": []}
    work = Path(tempfile.mkdtemp(prefix="dtx_vba_"))
    try:
        ole_path, location = _vba_ole_path(original_path, work)
        name = original_path.name
        d = didier_dir()
        oledump = d / "oledump.py"

        if vba_present and ole_path is not None:
            res["tools"]["pcodedmp"] = _py("pcodedmp.pcodedmp", ["-n", str(original_path)],
                                           f"pcodedmp -n {name}")
            res["tools"]["pcode2code"] = _py("pcode2code.pcode2code", [str(original_path)],
                                             f"pcode2code {name}")
            # rev: gmzpt
            _project_checks(ole_path, location, res)
            _pcode_checks(res, olevba_modules or [])
            if oledump.is_file():
                for plugin in ("plugin_vba_summary.py", "plugin_vba_dco.py",
                               "plugin_vba_routines.py", "plugin_http_heuristics.py"):
                    if (d / plugin).is_file():
                        res["tools"][f"oledump {plugin[:-3]}"] = _py(
                            str(oledump), ["-p", str(d / plugin), str(original_path)],
                            f"oledump.py -p {plugin} {name}", script=True)
        if is_excel_binary and oledump.is_file() and (d / "plugin_biff.py").is_file():
            res["tools"]["oledump plugin_biff -x"] = _py(
                str(oledump), ["-p", str(d / "plugin_biff.py"), "--pluginoptions", "-x",
                               str(original_path)], f"oledump.py -p plugin_biff.py -x {name}",
                script=True)
        if ole_path is not None:
            target = str(ole_path)
            shown_target = name if ole_path == original_path else f"{name}:{location}"
            for tool in ("oletimes", "olemeta", "oledir"):
                if tool == "olemeta" and ole_path != original_path:
                    continue  # vbaProject.bin carries no SummaryInformation
                res["tools"][tool] = _py(f"oletools.{tool}", [target], f"{tool} {shown_target}")
            _trailing_data(ole_path, location, res)
        # ref: gmzpt
        _plugin_findings(res)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    res["counts"] = {"findings": len(res["findings"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
