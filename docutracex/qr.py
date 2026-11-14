"""QR codes and barcodes in the images of a case.

PDF pages and the image attachments of an email are read by their own engines
(``pdf_tools`` / ``mail_rules``). This module reads every other image: the file
itself when it is an image, and each image child of the nested tree (archive
members, Office / OneNote / RTF media, images in the resources of a PE, images
written as ``data:`` URIs in HTML / SVG). The decoding (zxing-cpp over Pillow)
runs in its own process, as in ``parsers.pdf_qr``: decoding a hostile image is
parser work on untrusted input.

A code that holds a URL is a finding (QR phishing: "scan to see the invoice");
its text is mined for IOCs like any other result.
"""

from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path
from typing import Any

from . import toolrun
from .config import tmo

MIN_SIDE = 40                    # icons and spacers: no QR fits (21 modules + quiet zone)
MAX_BYTES = 25 * 1024 * 1024
_URL = re.compile(r"(?i)^\s*(?:https?://|www\.)")


def dimensions(data: bytes) -> tuple[int, int] | None:
    """(width, height) from the image header, when the format is known."""
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
            return struct.unpack(">II", data[16:24])
        if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
            return struct.unpack("<HH", data[6:10])
        if data[:2] == b"BM" and len(data) >= 26:
            w, h = struct.unpack("<ii", data[18:26])
            return w, abs(h)
        if data[:3] == b"\xff\xd8\xff":
            i = 2
            while i + 9 < len(data) and data[i] == 0xFF:
                marker, seg = data[i + 1], struct.unpack(">H", data[i + 2:i + 4])[0]
                if marker in (0xC0, 0xC1, 0xC2):
                    h, w = struct.unpack(">HH", data[i + 5:i + 9])
                    return w, h
                i += 2 + seg
    except struct.error:
        return None
    return None


def worth_reading(data: bytes) -> bool:
    """An image big enough to hold a code (unknown sizes are read)."""
    if not data or len(data) > MAX_BYTES:
        return False
    dims = dimensions(data)
    return dims is None or min(dims) >= MIN_SIDE


def read(files: list[Path], timeout: int | None = None) -> dict[str, list[dict[str, Any]]]:
    """{str(path): [{"format", "text"}]} for the images that hold a code — one process for all."""
    if not files:
        return {}
    rec = toolrun.run([sys.executable, "-m", "docutracex.parsers.pdf_qr", "--many", *map(str, files)],
                      f"qr ({len(files)} image(s))", timeout=timeout or tmo(30 + 5 * len(files)),
                      bound=5_000_000, extra_env=toolrun.with_package_path())
    try:
        data = json.loads(rec.get("output") or "{}")
    except ValueError:
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for f, res in (data.get("files") or {}).items():
        codes = [{"format": c.get("format", ""), "text": c.get("text", "")}
                 for c in (res or {}).get("codes") or [] if c.get("text")]
        if codes:
            out[f] = codes
    return out


def findings(codes: list[dict[str, Any]], where: str, tool: str = "qr") -> list[dict[str, Any]]:
    """One finding per code: high when it opens a URL (QR phishing), low otherwise."""
    out = []
    for c in codes:
        url = bool(_URL.match(c.get("text") or ""))
        out.append({"tool": tool, "rule": "qr_code_url" if url else "qr_code",
                    "severity": "high" if url else "low", "location": where,
                    "detail": f"{c.get('format') or 'QR'} code in {where}"
                              + (" opens a URL (QR phishing)" if url else ""),
                    "evidence": c.get("text") or "", "attack": "T1566" if url else ""})
    return out


def result(codes: list[dict[str, Any]], where: str) -> dict[str, Any]:
    """The ``qr`` sub-result of a case whose file is an image."""
    f = findings(codes, where)
    return {"module": "qr", "status": "ok_with_findings" if f else "ok", "codes": codes,
            "findings": f, "counts": {"findings": len(f), "codes": len(codes)}}
