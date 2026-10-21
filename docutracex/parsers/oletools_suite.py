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
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

_CODE_BOUND = 400000       # total VBA source kept for the IOC phase
_MODULE_BOUND = 200000     # per-module source kept for display
_OUTPUT_BOUND = 60000      # raw CLI output kept per tool
_EVIDENCE_LINES = 8        # evidence lines kept per finding

# olevba analyze_macros result type -> severity
_OLEVBA_SEV = {
    "AutoExec": "high", "Suspicious": "medium", "IOC": "low",
    "Hex String": "low", "Base64 String": "low", "Dridex string": "medium",
    "VBA string": "info",
}


def _finding(tool: str, rule: str, severity: str, detail: str, location: str = "vba",
             evidence: str = "") -> dict:
    return {"tool": tool, "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence}


def _cli(module: str, args: list[str], path: Path) -> dict[str, Any]:
    """Run an oletools command-line tool and keep its raw output, so the analyst
    sees exactly what the tool reported (stored alongside the parsed result)."""
    # rev: MH22fELbKP
    from .. import native

    from .. import quiet

    cmd = [sys.executable, "-c", quiet.CLI_WRAPPER, f"oletools.{module}", *args, str(path)]
    shown = " ".join([module, *args, path.name])
    env = native.subprocess_env()
    env["PYTHONWARNINGS"] = quiet.WARNINGS_FILTER
    # The wrapper imports docutracex.quiet: make the package importable.
    root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=180, env=env)
        out = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr.strip() else "")
        return {"command": shown, "returncode": proc.returncode,
                "output": out[:_OUTPUT_BOUND], "output_truncated": len(out) > _OUTPUT_BOUND}
    except Exception as exc:  # noqa: BLE001
        return {"command": shown, "error": str(exc)}


def _short(text: str, n: int = 200) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n] + "…"


def _code_lines(modules: list[dict[str, Any]], keyword: str) -> list[str]:
    """Lines of VBA source containing ``keyword``, with module and line number."""
    kw = keyword.lower()
    out: list[str] = []
    for mod in modules:
        for no, line in enumerate((mod.get("code") or "").splitlines(), 1):
            if kw in line.lower():
                out.append(f"{mod.get('vba_filename') or mod.get('stream')} line {no}: {_short(line)}")
                if len(out) >= _EVIDENCE_LINES:
                    return out
    return out


def _olevba_evidence(kind: str, keyword: str, desc: str, modules: list[dict[str, Any]],
                     decoded: dict[str, list[tuple[str, str]]]) -> str:
    """Where olevba saw it: the decoded strings for 'Hex/Base64/Dridex Strings',
    otherwise the VBA lines that contain the keyword."""
    for label, key in (("Hex Strings", "hex"), ("Base64 Strings", "base64"),
                       ("Dridex Strings", "dridex")):
        if keyword == label:
            pairs = decoded.get(key, [])
            lines = [f"{_short(enc, 80)} → {_short(dec, 160)}" for enc, dec in pairs[:_EVIDENCE_LINES]]
            if len(pairs) > _EVIDENCE_LINES:
                lines.append(f"… {len(pairs) - _EVIDENCE_LINES} more (see olevba output)")
            return "\n".join(lines)
    if kind in ("Hex String", "Base64 String", "Dridex string", "VBA string"):
        return f"{_short(desc, 120)} → {_short(keyword, 200)}"
    lines = _code_lines(modules, keyword)
    if "obfuscation:" in desc:
        hits = [f"decoded: {_short(dec, 200)}" for pairs in decoded.values()
                for _enc, dec in pairs if keyword.lower() in dec.lower()]
        lines = hits[:_EVIDENCE_LINES] + lines
    return "\n".join(lines[:_EVIDENCE_LINES])


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
                info["_full_code"] = code  # complete VBA source, dumped to disk whole
                # Deobfuscate-first fallback: resolve VBA string tricks statically
                # (works even when ViperMonkey is absent/fails) so the detector and
                # IOC scan see the real strings.
                if code:
                    try:
                        from . import vba_deobf
                        dv = vba_deobf.deobfuscate(code)
                    except Exception:  # noqa: BLE001
                        dv = {"changed": False}
                    if dv.get("changed"):
                        info["deobfuscated"] = dv["code"][:_MODULE_BOUND]
                        info["deob_truncated"] = len(dv["code"]) > _MODULE_BOUND
                        info["deob_methods"] = dv["methods"]
                        info["_full_deob"] = dv["code"]
                        result["findings"].append(_finding(
                            "vba_deobf", "vba_deobfuscated", "medium",
                            f"VBA deobfuscated statically ({', '.join(dv['methods']) or 'string resolver'})",
                            evidence=dv["code"][:600].strip()))
                        for h in vba_deobf.static_hits(dv["code"]):
                            result["findings"].append(_finding(
                                "vba_deobf", h["rule"], h["severity"], h["label"], evidence=h["line"]))
                decoded: dict[str, list[tuple[str, str]]] = {}
                try:
                    from oletools.olevba import VBA_Scanner
                    sc = VBA_Scanner(code)
                    sc.scan()
                    decoded = {"hex": list(sc.hex_strings or []),
                               "base64": list(sc.base64_strings or []),
                               "dridex": list(sc.dridex_strings or [])}
                except Exception:  # noqa: BLE001
                    pass
                info["decoded_strings"] = {k: [[e[:500], d[:500]] for e, d in v[:200]]
                                           for k, v in decoded.items()}
                info["analysis"] = []
                for (kind, keyword, desc) in vp.analyze_macros():
                    info["analysis"].append({"type": kind, "keyword": keyword, "description": desc})
                    sev = _OLEVBA_SEV.get(kind, "info")
                    rule = "olevba_" + str(kind).lower().replace(" ", "_")
                    result["findings"].append(_finding(
                        "olevba", rule, sev, f"{keyword}: {desc}",
                        evidence=_olevba_evidence(kind, str(keyword), str(desc),
                                                  info["modules"], decoded)))
            info.update(_cli("olevba", ["--decode"], path))
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
            desc = str(getattr(ind, "description", "") or "")
            recs.append({"id": str(getattr(ind, "id", "")), "name": name, "value": str(value),
                         "risk": risk, "description": desc})
            if risk in ("low", "medium", "high"):
                ev = desc
                if getattr(ind, "id", "") == "vba":
                    mods = (result["tools"].get("olevba") or {}).get("modules", [])
                    if mods:
                        ev += ("\n" if ev else "") + "VBA modules found by olevba: " + ", ".join(
                            f"{m.get('vba_filename')} ({m.get('stream')}, {m.get('code_length')} chars)"
                            for m in mods[:_EVIDENCE_LINES])
                result["findings"].append(
                    _finding("oleid", "oleid_" + str(getattr(ind, "id", "indicator")),
                             risk, f"{name}: {value}", "document", ev))
        result["tools"]["oleid"] = {"indicators": recs, **_cli("oleid", [], path)}
    except Exception as exc:  # noqa: BLE001
        result["tools"]["oleid"] = {"error": str(exc)}


def _run_mraptor(code: str, path: Path, result: dict[str, Any]) -> None:
    if not code:
        return
    try:
        from oletools import mraptor
        mr = mraptor.MacroRaptor(code)
        mr.scan()
        flags = mr.get_flags()
        matches = [str(m) for m in (getattr(mr, "matches", []) or [])]
        result["tools"]["mraptor"] = {
            "suspicious": bool(mr.suspicious),
            "flags": flags,
            "matches": matches,
            "legend": "A=AutoExec, W=Write, X=Execute; suspicious = A and (W or X)",
            **_cli("mraptor", ["-m"], path),
        }
        if mr.suspicious:
            mods = (result["tools"].get("olevba") or {}).get("modules", [])
            ev = [line for kw in matches for line in _code_lines(mods, kw)[:2]]
            result["findings"].append(
                _finding("mraptor", "mraptor_suspicious", "high",
                         f"Likely malicious macro (flags {flags}): "
                         f"{', '.join(matches)}",
                         evidence="\n".join(ev[:_EVIDENCE_LINES])))
    except Exception as exc:  # noqa: BLE001
        result["tools"]["mraptor"] = {"error": str(exc)}


def _run_msodde(path: Path, result: dict[str, Any]) -> None:
    try:
        # tag: gmzpt
        from oletools import msodde
        out = msodde.process_file(str(path), field_filter_mode=getattr(msodde, "FIELD_FILTER_DDE", None))
        links = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
        result["tools"]["msodde"] = {"dde_links": links, **_cli("msodde", [], path)}
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
        result["tools"]["oleobj"] = {
            "objects": objects,
            "command": f"oleobj (python API) {path.name}",
            "output": "\n".join(f"{o['stored_path']}  {o['size_bytes']} bytes  sha256 {o['sha256']}"
                                for o in objects) or "No embedded OLE objects found.",
        }
        if objects:
            # gmzpt
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
    from .. import quiet
    quiet.silence()  # before oletools.olevba pulls in XLMMacroDeobfuscator
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
    _run_mraptor(code, original_path, result)
    _run_msodde(original_path, result)
    _run_oleobj(original_path, extracted_dir, result)

    result["dde_links"] = result["tools"].get("msodde", {}).get("dde_links", [])
    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
