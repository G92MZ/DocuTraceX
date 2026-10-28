"""webcrack: static JavaScript deobfuscation on the portable Node.

webcrack (MIT, provisioned under ``tools/webcrack/`` with a portable Node under
``tools/node/``) unminifies and, crucially, **unpacks obfuscator.io** — the
string-array + rotator + accessor scheme and control-flow flattening that our
pure-Python cascade cannot flatten statically — re-emitting readable code. It
evaluates only the obfuscation *decoder* in an isolated-vm sandbox; it never
runs the analysed payload's effects.

Runs before the pure-Python cascade so the whole pipeline (rules, IOC scan,
STPyV8 sandbox) sees the flattened code — but **only when the script looks like
obfuscator.io output or a webpack/browserify bundle** (``needs_webcrack``):
that is all webcrack adds, and starting Node per script is not free. Degrades gracefully: when Node/webcrack
are not provisioned, ``deobfuscate`` returns the input unchanged.
"""

from __future__ import annotations

import re

import shutil
import tempfile
from pathlib import Path
from typing import Any

from .. import toolrun
from ..config import settings
from ..config import tmo

_RUNNER = Path(__file__).resolve().parent.parent / "assets" / "webcrack_run.js"
_TIMEOUT = tmo(60)
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


_HEX_ID = re.compile(r"\b_0x[0-9a-fA-F]{4,}\b")
_OBF_MARKERS = (
    re.compile(r"while\s*\(\s*!!\s*\[\s*\]\s*\)"),                       # rotator loop
    re.compile(r"parseInt\s*\(\s*_0x[0-9a-fA-F]+\s*\(\s*0x[0-9a-fA-F]+"),   # rotator checksum
    re.compile(r"['\"](?:\d+\|){2,}\d+['\"]\s*\[?\s*['\"]?split"),           # control-flow flattening
    re.compile(r"function\s+_0x[0-9a-fA-F]+\s*\(\s*\)\s*\{\s*(?:var|const|let)\s+_0x[0-9a-fA-F]+\s*=\s*\["),  # string array
)
_BUNDLE = re.compile(r"__webpack_require__|webpackJsonp|webpackChunk|\btypeof\s+require\s*==\s*['\"]function['\"]\s*&&\s*require")


def needs_webcrack(code: str) -> bool:
    """obfuscator.io (string array + rotator, ``_0x`` identifiers, flattened
    control flow) or a JS bundle: the cases webcrack actually unpacks."""
    sample = (code or "")[:400_000]
    ids = len(set(_HEX_ID.findall(sample)))
    if ids >= 10 and any(rx.search(sample) for rx in _OBF_MARKERS):
        return True
    return ids >= 40 or bool(_BUNDLE.search(sample))


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
