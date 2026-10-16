"""Entry point: ``python -m docutracex`` (or the ``docutracex`` script).

The web app runs on the interpreter that launches it (your Python). The bundled
analysis tools run on the portable Python under ``tools/`` — see run.py, which
ensures the portable exists before starting the app.
"""

from __future__ import annotations

import sys
from pathlib import Path

import uvicorn

from .config import settings
from .logging_config import configure_logging, get_logger

log = get_logger(__name__)


def _ensure_portable() -> None:
    """Ensure the portable Python + tools exist (provision on first run).

    Best-effort: never blocks app startup. Skip with DOCUTRACEX_SKIP_SETUP=1.
    """
    import os

    if os.environ.get("DOCUTRACEX_SKIP_SETUP") == "1":
        return
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    try:
        sys.path.insert(0, str(scripts_dir))
        from setup_portable_python import ensure  # type: ignore
        ensure()
    except Exception as exc:  # noqa: BLE001
        log.warning("Portable setup check failed: %s", exc)


def _prefetch_free_proxies() -> None:
    """Refresh the free proxy lists (ProxyScrape) in the background, so
    "Connect to free proxy" in Settings is instant. Never blocks startup."""
    import os

    if os.environ.get("DOCUTRACEX_SKIP_SETUP") == "1":
        return
    try:
        from .netcheck import freeproxy
        freeproxy.refresh_all_async()
    except Exception as exc:  # noqa: BLE001
        log.warning("Free proxy list prefetch failed: %s", exc)


def main() -> None:
    configure_logging(settings.log_level)
    _ensure_portable()
    _prefetch_free_proxies()
    log.info("Starting DocuTraceX on http://%s:%s", settings.host, settings.port)
    uvicorn.run(
        "docutracex.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
