"""Binary padding (T1027.001): strip the junk, keep the real binary.

Loaders are often inflated to hundreds of MB — zeros or a repeated pattern in
the overlay, a bloated resource / section / .NET resource, junk after the
Authenticode signature — so sandboxes, AV engines and upload portals skip them
for being too big. This runs **debloat** (Squiblydoo, BSD) on a PE and, when it
finds bloat, writes the real binary next to the case. The caller analyses that
file as a nested child (recipe ``debloat → <method>``), where the full PE
pipeline runs on it: pefile, LIEF, unpacking, FLOSS, capa, YARA.

debloat loads the whole file with pefile and rebuilds it, so it runs in its own
child process with a time limit (``python -m docutracex.parsers.debloat_pe IN
OUT``): a huge or hostile file costs only this step. Nothing is executed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..config import tmo
from ..logging_config import get_logger

log = get_logger(__name__)

TIMEOUT = tmo(300)
MIN_SIZE = 1 * 1024 * 1024          # smaller files are not worth checking
MAX_SIZE = 2 * 1024 * 1024 * 1024   # beyond this, do not even try
MIN_SAVING = 0.10                   # at least 10% of the file must be junk


def available() -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec("debloat") is not None
    except Exception:  # noqa: BLE001
        return False


def run(path: Path, out: Path) -> dict[str, Any]:
    """Debloat ``path`` into ``out``. Returns a status record:
    ``{status: debloated|clean|skipped|not_installed|timeout|error, method,
    size_before, size_after, removed, detail}``; ``out`` exists only when
    status is ``debloated``."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return {"status": "error", "detail": str(exc)}
    rec: dict[str, Any] = {"size_before": size}
    if size < MIN_SIZE:
        return {**rec, "status": "skipped", "detail": f"{size} bytes — too small to be padded"}
    if size > MAX_SIZE:
        return {**rec, "status": "skipped", "detail": f"{size} bytes — above the {MAX_SIZE >> 30} GB limit"}
    if not available():
        return {**rec, "status": "not_installed", "detail": "debloat not installed (pip install debloat)"}
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run([sys.executable, "-m", "docutracex.parsers.debloat_pe", str(path), str(out)],
                           capture_output=True, text=True, timeout=TIMEOUT,
                           cwd=str(Path(__file__).resolve().parents[2]))
    except subprocess.TimeoutExpired:
        out.unlink(missing_ok=True)
        return {**rec, "status": "timeout", "detail": f"debloat timed out after {TIMEOUT}s"}
    try:
        res = json.loads(r.stdout or "{}")
    except ValueError:
        res = {}
    if r.returncode != 0 or not res:
        out.unlink(missing_ok=True)
        err = (r.stderr or "").strip().splitlines()[-1:] or [f"exit {r.returncode}"]
        return {**rec, "status": "error", "detail": f"debloat failed: {err[0][:300]}"}
    rec.update(method=res.get("method", ""), code=res.get("code", 0))
    after = out.stat().st_size if out.is_file() else 0
    if not res.get("code") or not after or after > size * (1 - MIN_SAVING):
        out.unlink(missing_ok=True)
        return {**rec, "status": "clean", "detail": "no padding found"}
    rec.update(status="debloated", size_after=after, removed=size - after,
               detail=f"{res.get('method')}: {_mb(size)} → {_mb(after)} ({100 * (size - after) / size:.1f}% junk)")
    return rec


def finding(rec: dict[str, Any], loc: str) -> dict[str, Any]:
    return {"tool": "debloat", "rule": "pe_bloated", "severity": "medium",
            "detail": f"binary padding: {rec['method']} — {_mb(rec['removed'])} of junk removed "
                      f"({_mb(rec['size_before'])} → {_mb(rec['size_after'])}); the real binary is "
                      f"analysed as a nested child · T1027.001",
            "location": loc, "evidence": rec.get("detail", "")}


def _mb(n: int) -> str:
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{n / 1024:.1f} KB"


def _main(src: str, dst: str) -> dict[str, Any]:
    import os

    import pefile
    from debloat import processor

    pe = pefile.PE(src, fast_load=True)
    code = processor.process_pe(pe, dst, False, False, lambda _m: None, os.path.getsize(src), extract=False)
    return {"code": code, "method": processor.RESULT_CODES.get(code, str(code)).rstrip(".")}


if __name__ == "__main__":
    try:
        res = _main(sys.argv[1], sys.argv[2])
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
        sys.exit(1)
    sys.stdout.write(json.dumps(res))
