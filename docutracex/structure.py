"""Lightweight structural recognizers for formats without a leading magic number.

These complement libmagic for types it cannot identify by a byte signature at
offset 0. They read only bounded regions of the file (head + tail), never load
it whole, and never execute content.

Currently: RTF (Word accepts any ``{\\rt`` header, which libmagic may miss),
EMLX (Apple Mail), whose composite signature (PRONOM fmt/2055) is a
leading byte-count line, RFC 822 headers near the start, and a trailing
``</plist>``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .logging_config import get_logger

log = get_logger(__name__)

_HEAD = 16384  # bytes to scan at the start (PRONOM uses 16 KiB)
_TAIL = 64     # bytes to scan at the end

_LEADING_COUNT = re.compile(rb"^\d{1,12}\r?\n")
_EMAIL_HEADERS = (b"from:", b"to:", b"date:", b"subject:", b"content-type:", b"mime-version:")


def looks_like_emlx(head: bytes, tail: bytes) -> tuple[bool, str]:
    """Apply the EMLX composite signature to the file's head and tail."""
    if not _LEADING_COUNT.match(head):
        return False, "No leading byte-count line."
    # Body after the count line, lowercased for header matching.
    after = head[head.find(b"\n") + 1:].lower()
    present = [h for h in _EMAIL_HEADERS if h in after]
    if len(present) < 2:
        return False, "RFC 822 headers not found after the count line."
    if b"</plist>" not in tail:
        return False, "No trailing </plist> marker."
    return True, "Leading byte-count, RFC 822 headers and trailing </plist>."


def looks_like_opc(path: Path) -> tuple[bool, str]:
    """An OPC/OOXML package is a ZIP that contains ``[Content_Types].xml``."""
    import zipfile

    if not zipfile.is_zipfile(path):
        return False, "Not a ZIP package."
    # gmzpt
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except Exception:  # noqa: BLE001
        return False, "ZIP could not be read."
    if "[Content_Types].xml" in names:
        return True, "ZIP package with [Content_Types].xml (OPC/OOXML)."
    return False, "ZIP without [Content_Types].xml."


def recognize(path: Path, declared_ext: str = "") -> dict[str, Any] | None:
    """Return a structural identification, or None if nothing matched.

    Result: {"format", "family", "detail", "method": "structure"}.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(_HEAD)
            try:
                fh.seek(-_TAIL, 2)
            except OSError:
                fh.seek(0)
            tail = fh.read()
    except OSError as exc:
        log.warning("Structural read failed for %s: %s", path, exc)
        return None

    if head.lstrip(b"\xef\xbb\xbf")[:4] == b"{\\rt":
        std = head.lstrip(b"\xef\xbb\xbf")[:6] == b"{\\rtf1"
        return {"format": "rtf", "family": "rtf", "method": "structure",
                "detail": "RTF header {\\rtf1" if std else "Non-standard RTF header (Word accepts '{\\rt')"}

    matched, detail = looks_like_emlx(head, tail)
    if matched:
        return {"format": "emlx", "family": "email", "detail": detail, "method": "structure"}

    # OPC/OOXML package (confirms the family when libmagic only sees a zip/data).
    if head[:4] == b"PK\x03\x04":
        ok, detail = looks_like_opc(path)
        if ok:
            return {"format": "ooxml", "family": "ooxml", "detail": detail, "method": "structure"}
    return None
