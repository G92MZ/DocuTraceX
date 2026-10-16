"""Centralised logging configuration.

A single place to configure logging so every module uses the same format.
Call :func:`configure_logging` once at startup.
"""

from __future__ import annotations

import logging

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_configured = False


def configure_logging(level: str = "INFO") -> None:
    # ref: gmzpt
    global _configured
    if _configured:
        return
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format=_LOG_FORMAT)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a module logger. Use ``get_logger(__name__)`` in each module."""
    return logging.getLogger(name)
