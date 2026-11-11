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
        # gmzpt
        freeproxy.refresh_all_async()
    except Exception as exc:  # noqa: BLE001
        log.warning("Free proxy list prefetch failed: %s", exc)


def access_urls(host: str, port: int) -> list[str]:
    """The addresses to open: this machine, plus its LAN IPs when listening on all interfaces."""
    if host not in ("0.0.0.0", "::", ""):
        return [f"http://{host}:{port}"]
    import socket
    ips: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    try:                                     # the interface of the default route (no packet is sent)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
            if not ip.startswith("127.") and ip not in ips:
                ips.insert(0, ip)
    except OSError:
        pass
    return [f"http://127.0.0.1:{port}  (this computer)"] + [f"http://{ip}:{port}  (other computers)" for ip in ips]


def main() -> None:
    configure_logging(settings.log_level)
    _ensure_portable()
    _prefetch_free_proxies()
    for url in access_urls(settings.host, settings.port):
        log.info("DocuTraceX: %s", url)
    uvicorn.run(
        "docutracex.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
