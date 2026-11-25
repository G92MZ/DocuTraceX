"""Run an external analysis tool and keep what it printed.

Every external tool (oletools CLIs, Didier scripts, peepdf, pcodedmp,
ViperMonkey...) goes through :func:`run`: a separate process, a hard time limit,
bounded output and an environment that silences harmless library noise. The
returned record is stored as-is in the module result, so the analyst can always
see the exact command and its raw output next to the findings derived from it.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import subprocess
import threading
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any
from .config import tmo

OUTPUT_BOUND = 60000          # characters of a tool's output kept in the module result (the UI)
STDERR_BOUND = 4000
FULL_DIR = "tool_output"      # under results/: every output over its bound, complete

# The case being analysed, so a tool's complete output can be kept next to its results.
# A ContextVar for the analysis thread; worker threads of a step (no context) fall back to
# the one case analysed in this process, when there is only one.
_CASE: ContextVar[Path | None] = ContextVar("dtx_toolrun_case", default=None)
_ACTIVE: list[Path] = []
_ACTIVE_LOCK = threading.Lock()


@contextlib.contextmanager
def case_scope(case_root: Path):  # noqa: ANN201
    """Tool outputs over their bound, while this block runs, are kept whole in the case."""
    root = Path(case_root)
    tok = _CASE.set(root)
    with _ACTIVE_LOCK:
        _ACTIVE.append(root)
    try:
        yield
    finally:
        _CASE.reset(tok)
        with _ACTIVE_LOCK:
            try:
                _ACTIVE.remove(root)
            except ValueError:
                pass


def _case_root() -> Path | None:
    root = _CASE.get()
    if root is None:
        with _ACTIVE_LOCK:
            root = _ACTIVE[0] if len(set(_ACTIVE)) == 1 else None
    return root


def keep_full(text: str | None, label: str, case_root: Path | None = None) -> str | None:
    """Write ``text`` whole to ``results/tool_output/`` of the case; its path relative to the
    case root (None: no text or no case known). Content-addressed: the same output once."""
    if not text:
        return None
    root = Path(case_root) if case_root else _case_root()
    if root is None:
        return None
    data = text.encode("utf-8", "replace")
    slug = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(label))[:60].strip("_") or "tool"
    rel = Path("results") / FULL_DIR / f"{slug}.{hashlib.sha1(data).hexdigest()[:12]}.txt"
    try:
        out = root / rel
        if not out.is_file():
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
    except OSError:
        return None
    return rel.as_posix()


def keep_field(rec: dict[str, Any], key: str, text: str | None, bound: int, label: str) -> dict[str, Any]:
    """``rec[key]`` = the first ``bound`` characters of ``text`` (what the tab shows); the whole text
    kept in the case as ``rec[key + "_full"]`` when longer — the Markdown report's Complete content."""
    t = text or ""
    rec[key] = t[:bound]
    if len(t) > bound:
        full = keep_full(t, label)
        if full:
            rec[f"{key}_full"] = full
    return rec


def bounded(rec: dict[str, Any], out: str | None, label: str, bound: int = OUTPUT_BOUND,
            err: str | None = None, err_bound: int = STDERR_BOUND, err_tail: bool = True) -> dict[str, Any]:
    """Store a tool's stdout / stderr in ``rec``: bounded for the UI, and whole in the case
    (``output_full`` / ``stderr_full``) when over the bound."""
    out = out or ""
    rec["output"] = out[:bound]
    rec["output_truncated"] = len(out) > bound
    if len(out) > bound:
        full = keep_full(out, label)
        if full:
            rec["output_full"] = full
    if err is not None:
        e = err or ""
        rec["stderr"] = (e[-err_bound:] if err_tail else e[:err_bound]) or None
        if len(e) > err_bound:
            full = keep_full(e, f"{label}.stderr")
            if full:
                rec["stderr_full"] = full
    return rec


def env() -> dict[str, str]:
    """Environment for tool subprocesses (bundled libmagic, quiet warnings)."""
    from . import native, quiet

    # gmzpt
    e = native.subprocess_env()
    e["PYTHONWARNINGS"] = quiet.WARNINGS_FILTER
    e["PYTHONIOENCODING"] = "utf-8"
    return e


def run(cmd: list[str], shown: str, timeout: int = tmo(180), cwd: Path | None = None,
        bound: int = OUTPUT_BOUND, extra_env: dict[str, str] | None = None,
        input_text: str | None = None) -> dict[str, Any]:
    """Run ``cmd``; return {command, returncode, output, stderr, duration_s, ...}.

    ``shown`` is the human-readable command stored for the UI (tool name and the
    file name, not full local paths). Never raises.
    """
    e = env()
    if extra_env:
        e.update(extra_env)
    t0 = time.perf_counter()
    rec: dict[str, Any] = {"command": shown}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, env=e,
                              cwd=str(cwd) if cwd else None, input=input_text,
                              stdin=None if input_text is not None else subprocess.DEVNULL)
        rec["returncode"] = proc.returncode
        bounded(rec, proc.stdout, shown, bound, proc.stderr)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        rec.update(error=f"timed out after {timeout}s", timed_out=True)
        bounded(rec, out, shown, bound)
    except Exception as exc:  # noqa: BLE001
        rec["error"] = str(exc)
    rec["duration_s"] = round(time.perf_counter() - t0, 2)
    return rec


def package_root() -> str:
    """Directory containing the ``docutracex`` package (for PYTHONPATH)."""
    return str(Path(__file__).resolve().parent.parent)


def with_package_path(e: dict[str, str] | None = None) -> dict[str, str]:
    e = dict(e or {})
    root = package_root()
    cur = e.get("PYTHONPATH") or os.environ.get("PYTHONPATH")
    e["PYTHONPATH"] = root + (os.pathsep + cur if cur else "")
    return e
