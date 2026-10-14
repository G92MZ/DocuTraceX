"""Entry point: ``python -m docutracex`` (or the ``docutracex`` script).

Launches the local web server with uvicorn.
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
