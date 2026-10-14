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
from dataclasses import dataclass, field
from typing import Any

from .logging_config import get_logger

log = get_logger(__name__)


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


def log_startup_report(results: list[DepStatus] | None = None) -> dict[str, Any]:
    """Run the check and log a concise report. Returns the summary."""
    results = results or check_dependencies()
    summary = summarize(results)
    log.info("Dependency check: %d/%d present", summary["present"], summary["total"])
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
