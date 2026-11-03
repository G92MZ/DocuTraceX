"""GoReSym (Mandiant, MIT) as the contrast for the own Go parser.

Run headless on the file (it only parses it), JSON on stdout. Phase 1 keeps
what identification needs — version, build ID, pclntab / moduledata metadata,
BuildInfo, function counts — and the raw output is written next to the case
results. Absent tool → a warning, the own parser carries on alone.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import tmo
from ..toolrun import run

TIMEOUT = 180
MAX_OUT = 64 * 1024 * 1024


def executable() -> Path | None:
    from ..config import settings
    return settings.goresym_executable()


def analyze(path: Path, raw_dir: Path | None = None, sha256: str = "") -> dict[str, Any]:
    exe = executable()
    if exe is None:
        return {"available": False, "detail": "GoReSym not provisioned (tools/goresym/)"}
    rec = run([str(exe), str(path)], f"GoReSym {path.name}", timeout=tmo(TIMEOUT), bound=MAX_OUT)
    out: dict[str, Any] = {"available": True, "command": rec.get("command"), "returncode": rec.get("returncode"),
                           "duration_s": rec.get("duration_s"), "stderr": rec.get("stderr")}
    if rec.get("error"):
        out["error"] = rec["error"]
        return out
    text = rec.get("output") or ""
    if raw_dir is not None and text:
        try:
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw = raw_dir / f"{sha256 or path.name}.goresym.json"
            raw.write_text(text, encoding="utf-8")
            out["raw_file"] = raw.name
        except OSError:
            pass
    try:
        d = json.loads(text) if text.strip() else {}
    except ValueError:
        out["error"] = "output is not JSON"
        out["output_head"] = text[:2000]
        return out
    if isinstance(d, dict) and d.get("error") and not d.get("TabMeta"):
        out["error"] = str(d["error"])[:500]             # e.g. "no valid pclntab found"
        return out
    tab = d.get("TabMeta") or {}
    bi = d.get("BuildInfo") or {}
    out.update({
        "version": d.get("Version") or "",
        "build_id": d.get("BuildId") or "",
        "arch": d.get("Arch") or "", "os": d.get("OS") or "",
        "pclntab": {k: tab.get(k) for k in ("VA", "Version", "Endianess", "CpuQuantumStr", "PointerSize")} if tab else None,
        "moduledata": bool(d.get("ModuleMeta")),
        "buildinfo": {"go_version": bi.get("GoVersion"), "path": bi.get("Path"),
                      "main": (bi.get("Main") or {}).get("Path"),
                      "deps": len(bi.get("Deps") or [])} if bi else None,
        "user_functions": len(d.get("UserFunctions") or []),
        "std_functions": len(d.get("StdFunctions") or []),
    })
    return out


def compare(own: dict[str, Any], gr: dict[str, Any]) -> dict[str, Any]:
    """Agreement between the own parser and GoReSym on the shared facts."""
    rows = []

    def row(field: str, a: Any, b: Any, same: bool | None) -> None:
        rows.append({"field": field, "docutracex": a, "goresym": b,
                     "agree": same if (a not in (None, "") and b not in (None, "")) else None})
    own_v = (own.get("buildinfo") or {}).get("version") or ""
    gr_v = gr.get("version") or ""
    row("Go version", own_v, gr_v, own_v.removeprefix("go") == gr_v.removeprefix("go") if own_v and gr_v else None)
    row("Go build ID", own.get("go_build_id", ""), gr.get("build_id", ""),
        own.get("go_build_id", "") == gr.get("build_id", ""))
    own_t = (own.get("pclntab") or {}).get("version_range")
    gr_t = (gr.get("pclntab") or {}).get("Version")
    row("pclntab", own_t, gr_t, bool(own_t) == bool(gr_t))
    row("moduledata", bool(own.get("moduledata")), gr.get("moduledata"), bool(own.get("moduledata")) == gr.get("moduledata"))
    row("main module", (own.get("buildinfo") or {}).get("path", ""), (gr.get("buildinfo") or {}).get("path", ""),
        (own.get("buildinfo") or {}).get("path", "") == (gr.get("buildinfo") or {}).get("path", ""))
    disagree = [r["field"] for r in rows if r["agree"] is False]
    return {"rows": rows, "disagreements": disagree}
