"""Entry point: ``python -m docutracex`` (or the ``docutracex`` script).

The web app runs on the interpreter that launches it (your Python). The bundled
analysis tools run on the portable Python under ``tools/`` — see run.py, which
ensures the portable exists before starting the app.
"""

from __future__ import annotations

import uvicorn

from .config import settings
from .logging_config import configure_logging, get_logger

log = get_logger(__name__)


def main() -> None:
    configure_logging(settings.log_level)
    log.info("Starting DocuTraceX on http://%s:%s", settings.host, settings.port)
    uvicorn.run(
        "docutracex.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
