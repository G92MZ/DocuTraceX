"""webcrack: static JavaScript deobfuscation on the portable Node.

webcrack (MIT, provisioned under ``tools/webcrack/`` with a portable Node under
``tools/node/``) unminifies and, crucially, **unpacks obfuscator.io** — the
string-array + rotator + accessor scheme and control-flow flattening that our
pure-Python cascade cannot flatten statically — re-emitting readable code. It
evaluates only the obfuscation *decoder* in an isolated-vm sandbox; it never
runs the analysed payload's effects.

Runs before the pure-Python cascade so the whole pipeline (rules, IOC scan,
STPyV8 sandbox) sees the flattened code. Degrades gracefully: when Node/webcrack
are not provisioned, ``deobfuscate`` returns the input unchanged.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from .. import toolrun
from ..config import settings

_RUNNER = Path(__file__).resolve().parent.parent / "assets" / "webcrack_run.js"
_TIMEOUT = 60
_MAX_INPUT = 4_000_000
_MAX_OUTPUT = 8_000_000


def _node() -> Path | None:
    exe = settings.node_executable()
    if exe:
        return exe
    p = shutil.which("node")          # last resort: a system Node
    return Path(p) if p else None


def available() -> bool:
    return _node() is not None and settings.webcrack_dir() is not None and _RUNNER.is_file()


def status() -> dict[str, Any]:
    node = _node()
    wc = settings.webcrack_dir()
    if node is None:
        return {"available": False, "detail": "portable Node not provisioned under tools/node/"}
    if wc is None:
        return {"available": False, "detail": "webcrack not installed under tools/webcrack/"}
    return {"available": True, "detail": f"webcrack ready on {node}"}


def deobfuscate(code: str) -> dict[str, Any]:
    """Return ``{available, changed, code, error}``. ``code`` is webcrack's
    output when it recovered something, otherwise the input unchanged."""
    out: dict[str, Any] = {"available": available(), "changed": False, "code": code or "", "error": None}
    if not code or not code.strip() or not out["available"]:
        if not out["available"]:
            out["error"] = "node/webcrack not provisioned"
        return out

    node, wc = _node(), settings.webcrack_dir()
    with tempfile.TemporaryDirectory(prefix="dtx_wc_") as td:
        src = Path(td) / "in.js"
        try:
            src.write_text(code[:_MAX_INPUT], encoding="utf-8")
        except OSError as exc:
            out["error"] = str(exc)
            return out
        rec = toolrun.run(
            [str(node), str(_RUNNER), str(src)],
            "webcrack (JS deobfuscation)", timeout=_TIMEOUT, bound=_MAX_OUTPUT,
            extra_env={"NODE_PATH": str(wc / "node_modules")},
        )
    if rec.get("returncode") == 0 and (rec.get("output") or "").strip():
        new = rec["output"]
        if new.strip() != (code or "").strip():
            out["changed"] = True
            out["code"] = new
    else:
        out["error"] = (rec.get("stderr") or rec.get("error") or "webcrack failed")[:300]
    return out
