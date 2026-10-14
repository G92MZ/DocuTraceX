"""Dependency self-check.

Declares the Python packages (and, later, native libraries and bundled tools)
the application relies on, and checks at startup whether each is importable and
what version is present. Optional dependencies (e.g. the libmagic binding) are
reported but do not stop the app — identification simply degrades.

As new tools are added to the project, register them here so the startup check
and the ``/api/diagnostics`` endpoint report their status in one place.
"""

from __future__ import annotations

import importlib
import importlib.metadata as md
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import settings
from .logging_config import get_logger

log = get_logger(__name__)

# Probe executed INSIDE a target interpreter (e.g. the portable Python in
# tools/) so the check reflects that environment, not the app's launcher.
# Run isolated (-I); takes a JSON list of [import_name, pip_name] as argv[1].
_PROBE = r"""
import importlib, json, sys
try:
    import importlib.metadata as md
except Exception:
    md = None
deps = json.loads(sys.argv[1])
out = {"python_version": sys.version.split()[0], "executable": sys.executable, "deps": {}}
for imp, pip in deps:
    rec = {"installed": True, "version": None, "error": None}
    try:
        importlib.import_module(imp)
    except Exception as e:
        rec["installed"] = False
        rec["error"] = str(e)
    if rec["installed"] and md is not None:
        try:
            rec["version"] = md.version(pip)
        except Exception:
            rec["version"] = None
    out["deps"][imp] = rec
print(json.dumps(out))
"""


@dataclass(frozen=True)
class Dependency:
    import_name: str          # module name used in `import ...`
    pip_name: str             # name on PyPI (for the install hint)
    purpose: str
    required: bool = True
    install_hint: str = ""    # extra guidance (e.g. native library on Windows)


# Python dependencies. Extend this list as tools are integrated.
PYTHON_DEPS: list[Dependency] = [
    Dependency("fastapi", "fastapi", "Web framework"),
    Dependency("uvicorn", "uvicorn", "ASGI server"),
    Dependency("jinja2", "jinja2", "HTML templates"),
    Dependency("multipart", "python-multipart", "File uploads"),
    Dependency(
        "magic", "python-magic", "Type identification (libmagic)",
        required=False,
        install_hint=(
            "needs the native libmagic library; on Windows bundle the DLL under "
            "tools/ (or, for development, `pip install python-magic-bin`)"
        ),
    ),
]


@dataclass
class DepStatus:
    import_name: str
    pip_name: str
    purpose: str
    required: bool
    installed: bool
    version: str | None = None
    error: str | None = None
    install_hint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.pip_name,
            "import_name": self.import_name,
            "purpose": self.purpose,
            "required": self.required,
            "installed": self.installed,
            "version": self.version,
            "error": self.error,
            "install_hint": self.install_hint,
        }


def _version(pip_name: str) -> str | None:
    try:
        return md.version(pip_name)
    except Exception:  # noqa: BLE001
        return None


def check_dependencies(deps: list[Dependency] | None = None) -> list[DepStatus]:
    """Check each dependency: importable? which version?"""
    results: list[DepStatus] = []
    for dep in deps or PYTHON_DEPS:
        installed = True
        error = None
        try:
            importlib.import_module(dep.import_name)
        except Exception as exc:  # noqa: BLE001  (ImportError and native-load errors)
            installed = False
            error = str(exc)
        results.append(
            DepStatus(
                import_name=dep.import_name,
                pip_name=dep.pip_name,
                purpose=dep.purpose,
                required=dep.required,
                installed=installed,
                version=_version(dep.pip_name) if installed else None,
                error=error,
                install_hint=dep.install_hint,
            )
        )
    return results


def _under_tools(executable: str | Path) -> bool:
    # Use the path as given (do NOT resolve symlinks): a venv/portable launcher
    # under tools/ may symlink to a system binary, but it is still "the tools/
    # interpreter" for our purposes.
    try:
        exe = Path(executable).absolute()
        tools = settings.tools_dir.resolve()
        return tools == exe or tools in exe.parents
    except OSError:
        return False


def check_in_interpreter(
    executable: str | Path, deps: list[Dependency] | None = None
) -> tuple[dict[str, Any], list[DepStatus]] | None:
    """Run the dependency check INSIDE ``executable`` via a subprocess probe.

    Returns (interpreter_info, results), or None if the interpreter could not
    be probed (so the caller can fall back to the current one).
    """
    from . import native

    deps = deps or PYTHON_DEPS
    payload = json.dumps([[d.import_name, d.pip_name] for d in deps])
    try:
        proc = subprocess.run(
            [str(executable), "-I", "-c", _PROBE, payload],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",  # child output may not be valid UTF-8 (e.g. cp1252)
            timeout=30,
            env=native.subprocess_env(),
        )
    except Exception as exc:  # noqa: BLE001  (never let a probe failure break startup)
        log.warning("Could not run probe in %s: %s", executable, exc)
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        log.warning("Probe failed in %s: %s", executable, proc.stderr.strip()[:200])
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        log.warning("Probe returned invalid output from %s", executable)
        return None

    by_name = {d.import_name: d for d in deps}
    results: list[DepStatus] = []
    for imp, rec in data.get("deps", {}).items():
        dep = by_name.get(imp)
        if dep is None:
            continue
        results.append(
            DepStatus(
                import_name=imp,
                pip_name=dep.pip_name,
                purpose=dep.purpose,
                required=dep.required,
                installed=bool(rec.get("installed")),
                version=rec.get("version"),
                error=rec.get("error"),
                install_hint=dep.install_hint,
            )
        )
    info = {
        "executable": data.get("executable", str(executable)),
        "python_version": data.get("python_version"),
        "is_portable": _under_tools(executable),
        "source": "portable" if _under_tools(executable) else "configured",
    }
    return info, results


def current_interpreter_info() -> dict[str, Any]:
    return {
        "executable": sys.executable,
        "python_version": sys.version.split()[0],
        "is_portable": _under_tools(sys.executable),
        "source": "current",
    }


def check_runtime(deps: list[Dependency] | None = None) -> tuple[dict[str, Any], list[DepStatus]]:
    """Check dependencies in the interpreter that will actually run the tools.

    Prefers the portable Python under ``tools/`` (checked via subprocess); falls
    back to the current interpreter when none is bundled or the probe fails.
    """
    portable = settings.portable_python()
    if portable:
        # Always probe the bundled interpreter in its own environment: even a
        # venv that shares the base binary has its own site-packages.
        probed = check_in_interpreter(portable, deps)
        if probed is not None:
            return probed
        log.warning("Falling back to the current interpreter for the dependency check")
    return current_interpreter_info(), check_dependencies(deps)


def summarize(results: list[DepStatus]) -> dict[str, Any]:
    present = sum(1 for r in results if r.installed)
    missing_required = [r for r in results if r.required and not r.installed]
    missing_optional = [r for r in results if not r.required and not r.installed]
    return {
        "total": len(results),
        "present": present,
        "ok": not missing_required,
        "missing_required": [r.pip_name for r in missing_required],
        "missing_optional": [r.pip_name for r in missing_optional],
        "dependencies": [r.as_dict() for r in results],
    }


@dataclass
class Check:
    """A single diagnostic check for the Diagnostics tab."""

    category: str
    name: str
    status: str          # "ok" | "warn" | "fail"
    detail: str = ""     # what was found / why it failed
    remedy: str = ""     # how to fix it
    purpose: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "remedy": self.remedy,
            "purpose": self.purpose,
        }


def run_checks(deps: list[Dependency] | None = None) -> dict[str, Any]:
    """Run all diagnostics and return a structured report for the UI/endpoint."""
    interp, dep_results = check_runtime(deps)
    checks: list[Check] = []

    # --- Runtime checks ---
    portable = settings.portable_python()
    checks.append(
        Check(
            category="Runtime",
            name="Portable Python (tools/)",
            status="ok" if portable else "warn",
            detail=str(portable) if portable
            else "No bundled interpreter found under tools/; using the system Python.",
            remedy="" if portable
            else "Bundle a portable Python under tools/python/ (runtime phase) "
                 "or set DOCUTRACEX_PYTHON.",
            purpose="Interpreter that runs the bundled tools",
        )
    )
    checks.append(
        Check(
            category="Runtime",
            name="Interpreter in use",
            status="ok",
            detail=f"{'portable' if interp.get('is_portable') else interp.get('source')} · "
                   f"Python {interp.get('python_version') or '?'} · {interp.get('executable')}",
            purpose="Where dependencies are checked",
        )
    )

    # --- Python dependency checks (in the interpreter above) ---
    for r in dep_results:
        if r.installed:
            status, detail, remedy = "ok", f"version {r.version or '?'}", ""
        else:
            status = "fail" if r.required else "warn"
            detail = r.error or "not importable"
            remedy = r.install_hint or "pip install -e ."
        checks.append(
            Check(
                category="Python dependency",
                name=r.pip_name,
                status=status,
                detail=detail,
                remedy=remedy,
                purpose=r.purpose,
            )
        )

    counts = {"ok": 0, "warn": 0, "fail": 0}
    for c in checks:
        counts[c.status] = counts.get(c.status, 0) + 1
    return {
        "interpreter": interp,
        "ok": counts["fail"] == 0,
        "counts": counts,
        "checks": [c.as_dict() for c in checks],
    }


def log_startup_report() -> dict[str, Any]:
    """Run the runtime check and log a concise report. Returns the summary."""
    interp, results = check_runtime()
    summary = summarize(results)
    summary["interpreter"] = interp
    kind = "portable" if interp.get("is_portable") else interp.get("source", "current")
    log.info(
        "Dependency check (%s Python %s at %s): %d/%d present",
        kind,
        interp.get("python_version") or "?",
        interp.get("executable"),
        summary["present"],
        summary["total"],
    )
    for r in results:
        if r.installed:
            continue
        level = log.warning if not r.required else log.error
        hint = f" — {r.install_hint}" if r.install_hint else ""
        kind = "required" if r.required else "optional"
        level("Missing %s dependency: %s (%s)%s", kind, r.pip_name, r.purpose, hint)
    if summary["missing_required"]:
        log.error(
            "Required dependencies missing: %s. Install with: pip install -e .",
            ", ".join(summary["missing_required"]),
        )
    return summary
