"""Registry database reads from any interpreter.

The web app runs on the user's own Python, which carries only the web dependencies;
DuckDB lives with the analysis tools on the portable Python under ``tools/``. So the
reads (``store.query`` / ``user_query`` / ``children`` / ``value`` / ``search``) run
in-process when DuckDB is importable and otherwise in a short-lived portable child:

    python -m docutracex.registry.remote   < {"fn": "search", "kw": {...}}   > {"ok": ...}
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

FUNCS = ("query", "user_query", "children", "value", "search")


def _portable() -> Path | None:
    from ..config import settings
    py = settings.portable_python()
    if py and py.resolve() != Path(sys.executable).resolve():
        return py
    return None


def available() -> bool:
    from . import store
    return store.available() or _portable() is not None


def call(fn: str, **kw: Any) -> Any:
    """``store.<fn>(**kw)`` here or on the portable. A bad query raises ValueError."""
    if fn not in FUNCS:
        raise ValueError(f"unknown registry call: {fn}")
    from . import store
    if store.available():
        return getattr(store, fn)(**kw)
    py = _portable()
    if py is None:
        raise RuntimeError("DuckDB is not installed (run scripts/setup_portable_python.py).")
    from .. import native
    from ..config import APP_ROOT
    env = dict(native.subprocess_env() or os.environ)
    env["PYTHONPATH"] = str(APP_ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    payload = json.dumps({"fn": fn, "kw": {k: str(v) if isinstance(v, Path) else v for k, v in kw.items()}})
    proc = subprocess.run([str(py), "-m", "docutracex.registry.remote"], input=payload, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", env=env, timeout=store.QUERY_TIMEOUT + 30)
    try:
        out = json.loads(proc.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        raise RuntimeError(f"registry query failed: {(proc.stderr or proc.stdout)[-400:]}") from None
    if "ok" in out:
        return out["ok"]
    raise ValueError(out.get("error") or "registry query failed")


def main() -> None:
    from . import store
    req = json.loads(sys.stdin.read())
    kw = dict(req.get("kw") or {})
    if "path" in kw:
        kw["path"] = Path(kw["path"])
    try:
        if req.get("fn") not in FUNCS:
            raise ValueError("unknown registry call")
        res: dict[str, Any] = {"ok": getattr(store, req["fn"])(**kw)}
    except Exception as exc:  # noqa: BLE001  (sent back to the web app as a 400)
        res = {"error": f"{type(exc).__name__}: {exc}"[:500] if not isinstance(exc, ValueError) else str(exc)[:500]}
    sys.stdout.write(json.dumps(res, default=str) + "\n")


if __name__ == "__main__":
    main()
