"""DocuTraceX — static forensic analysis of Office, PDF and email files.

Web application (FastAPI) run locally on Windows. See README.md for scope,
principles and the task backlog.
"""

from pathlib import Path


def _read_version() -> str:
    """The app version is the VERSION file at the repo root — the same file
    update.py compares with GitHub — so the UI always shows what is installed."""
    try:
        return (Path(__file__).resolve().parent.parent / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        try:
            from importlib.metadata import version
            return version("docutracex")
        except Exception:  # noqa: BLE001
            return "0.0.0"


__version__ = _read_version()
