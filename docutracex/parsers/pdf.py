"""PDF static analysis.

Forensically-minded and robust against malformed/hostile PDFs: the core is a
bounded RAW byte scan for dangerous tokens (the way pdfid works), so a broken
object tree never blinds us. On top of that, pypdf is used best-effort for
metadata, embedded-file extraction and the names tree, and pdfminer for a
bounded text sample (fed to the IOC phase). Nothing is executed and no
JavaScript is run.

Detections: automatic actions (/OpenAction, /AA), code (/JavaScript, /JS),
process launch (/Launch), external/remote targets (/URI, /SubmitForm, /GoToR),
embedded payloads (/EmbeddedFile), forms (/AcroForm, /XFA), multimedia
(/RichMedia), object streams hiding content (/ObjStm), encryption (/Encrypt),
risky codecs (/JBIG2Decode), and name-obfuscation via hex escapes (e.g.
``/J#61vaScript``). Incremental updates are counted from the EOF markers.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

_SCAN_BOUND = 30 * 1024 * 1024   # cap the raw scan at 30 MiB
_TEXT_BOUND = 20000
_MAX_URIS = 500
_MAX_EMBEDDED = 100

# token -> (rule, severity, note)
_KEYWORDS: dict[str, tuple[str, str, str]] = {
    "/OpenAction": ("open_action", "medium", "Action runs automatically on open"),
    "/AA": ("additional_actions", "medium", "Additional (event) actions"),
    "/JavaScript": ("javascript", "high", "Embedded JavaScript"),
    "/JS": ("js", "high", "Embedded JavaScript (/JS)"),
    "/Launch": ("launch", "high", "Launches an external program"),
    "/EmbeddedFile": ("embedded_file", "high", "Carries an embedded file"),
    "/XFA": ("xfa", "high", "XFA form (scriptable)"),
    "/AcroForm": ("acroform", "low", "Interactive form"),
    "/URI": ("uri", "low", "External URI action"),
    "/SubmitForm": ("submit_form", "medium", "Submits form data to a URL"),
    "/GoToR": ("goto_remote", "medium", "Jumps to a remote document"),
    "/RichMedia": ("rich_media", "medium", "Embedded multimedia (Flash/video)"),
    "/ObjStm": ("object_stream", "low", "Object streams (can hide content)"),
    "/JBIG2Decode": ("jbig2", "medium", "JBIG2 codec (exploit-prone)"),
    "/Encrypt": ("encrypted", "low", "Encrypted document"),
}
_HEX_NAME = re.compile(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}")
_URI_IN_PDF = re.compile(rb"/URI\s*\(([^)]{1,2000})\)")
_HTTP_IN_PDF = re.compile(rb"https?://[^\s()<>\"'\]]{3,2000}")
_PDF_HEADER = re.compile(rb"%PDF-(\d\.\d)")
_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.DOTALL)
_JS_STR = re.compile(rb"/JS\s*\((.*?)(?<!\\)\)", re.DOTALL)
_JS_HEX = re.compile(rb"/JS\s*<([0-9A-Fa-f\s]+)>")
_OBJ_SNIPPET = 1500
_MAX_OBJECTS = 200
_MAX_JS = 50


def _finding(rule: str, severity: str, detail: str, location: str = "pdf") -> dict[str, Any]:
    return {"tool": "pdf", "rule": rule, "severity": severity, "detail": detail, "location": location}


def _count(data: bytes, token: bytes) -> int:
    return data.count(token)


def _extract_metadata(path: Path, result: dict[str, Any]) -> None:
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path), strict=False)
        result["encrypted"] = bool(getattr(reader, "is_encrypted", False))
        try:
            result["page_count"] = len(reader.pages)
        except Exception:  # noqa: BLE001
            pass
        meta = reader.metadata or {}
        md = {}
        for k in ("/Title", "/Author", "/Subject", "/Creator", "/Producer",
                  "/CreationDate", "/ModDate", "/Keywords"):
            v = meta.get(k)
            if v:
                md[k.lstrip("/").lower()] = str(v)
        result["metadata"] = md
    except Exception as exc:  # noqa: BLE001
        result["metadata_error"] = str(exc)


def _extract_embedded(path: Path, extracted_dir: Path | None, result: dict[str, Any]) -> None:
    """Extract /EmbeddedFiles via pypdf (best-effort) for recursion + hashing."""
    if extracted_dir is None:
        return
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path), strict=False)
        names = reader.attachments or {}
    except Exception as exc:  # noqa: BLE001
        result["embedded_error"] = str(exc)
        return
    out_dir = extracted_dir / "pdf_embedded"
    for fname, blobs in list(names.items())[:_MAX_EMBEDDED]:
        try:
            data = blobs[0] if isinstance(blobs, list) and blobs else (blobs or b"")
            if not isinstance(data, (bytes, bytearray)):
                continue
            out_dir.mkdir(parents=True, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(fname))[:120] or "embedded"
            dest = out_dir / f"{len(result['embedded']):02d}_{safe}"
            dest.write_bytes(bytes(data))
            result["embedded"].append({
                "filename": str(fname), "size_bytes": len(data),
                "sha256": hashlib.sha256(bytes(data)).hexdigest(),
                "stored_path": dest.relative_to(extracted_dir.parent).as_posix(),
            })
        except Exception:  # noqa: BLE001
            continue


def _unescape_pdf_string(raw: bytes) -> str:
    s = raw.decode("latin-1", "replace")
    for a, b in (("\\n", "\n"), ("\\r", "\r"), ("\\t", "\t"),
                 ("\\(", "("), ("\\)", ")"), ("\\\\", "\\")):
        s = s.replace(a, b)
    return s


def _extract_javascript(data: bytes, result: dict[str, Any]) -> None:
    """Pull the actual JavaScript out of /JS literal and hex strings."""
    js: list[dict[str, str]] = []
    for m in _JS_STR.finditer(data):
        if len(js) >= _MAX_JS:
            break
        code = _unescape_pdf_string(m.group(1))
        if code.strip():
            js.append({"encoding": "literal", "code": code[:8000]})
    for m in _JS_HEX.finditer(data):
        if len(js) >= _MAX_JS:
            break
        try:
            code = bytes.fromhex(m.group(1).decode().replace(" ", "").replace("\n", "")) \
                .decode("utf-16-le", "replace") if len(m.group(1)) % 4 == 0 else ""
        except ValueError:
            code = ""
        if code.strip():
            js.append({"encoding": "hex", "code": code[:8000]})
    result["javascript"] = js
    if js:
        result["findings"].append(_finding("javascript_extracted", "high",
            f"{len(js)} JavaScript block(s) extracted", "javascript"))


def _extract_objects(data: bytes, result: dict[str, Any]) -> None:
    """Keep the suspicious objects (those carrying a dangerous token) with a
    bounded text snippet of their dictionary, for the collapsible view."""
    objs: list[dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        if len(objs) >= _MAX_OBJECTS:
            break
        body = m.group(3)
        dangerous = [k for k in _KEYWORDS if k.encode() in body]
        if not dangerous:
            continue
        has_stream = b"stream" in body
        dict_part = body.split(b"stream", 1)[0]
        snippet = dict_part.decode("latin-1", "replace").strip()
        objs.append({
            "id": f"{m.group(1).decode()} {m.group(2).decode()} obj",
            "dangerous": dangerous,
            "has_stream": has_stream,
            "snippet": snippet[:_OBJ_SNIPPET],
            "snippet_truncated": len(snippet) > _OBJ_SNIPPET,
        })
    result["objects"] = objs


def _extract_text(path: Path, result: dict[str, Any]) -> None:
    try:
        from pdfminer.high_level import extract_text
        text = extract_text(str(path), maxpages=20) or ""
        result["text_sample"] = text[:_TEXT_BOUND]
        result["text_length"] = len(text)
    except Exception as exc:  # noqa: BLE001
        result["text_error"] = str(exc)


def analyze(original_path: Path, extracted_dir: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "pdf", "format": "pdf", "status": "ok",
        "version": None, "keyword_counts": {}, "incremental_updates": 0,
        "uris": [], "embedded": [], "metadata": {}, "javascript": [], "objects": [],
        "text_sample": "", "findings": [],
    }
    try:
        with original_path.open("rb") as fh:
            data = fh.read(_SCAN_BOUND)
    except OSError as exc:
        result["status"] = "error"
        result["findings"].append(_finding("read_error", "medium", str(exc)))
        return result

    m = _PDF_HEADER.search(data[:1024])
    result["version"] = m.group(1).decode() if m else None
    if not m and not data.lstrip().startswith(b"%PDF"):
        result["findings"].append(_finding("no_pdf_header", "medium",
                                            "No %PDF header near the start"))

    # Dangerous keyword counts + findings.
    counts: dict[str, int] = {}
    for token, (rule, sev, note) in _KEYWORDS.items():
        n = _count(data, token.encode())
        if n:
            counts[token] = n
            result["findings"].append(_finding(rule, sev, f"{note} (×{n})"))
    result["keyword_counts"] = counts

    # High-confidence combo: auto-run code.
    if counts.get("/OpenAction") and (counts.get("/JavaScript") or counts.get("/JS")):
        result["findings"].append(_finding("auto_javascript", "high",
            "/OpenAction together with JavaScript — code runs on open"))

    # Name obfuscation via hex escapes (classic evasion of keyword scanners).
    hexn = _HEX_NAME.findall(data)
    if hexn:
        sample = ", ".join(sorted({h.decode("latin-1") for h in hexn})[:6])
        result["findings"].append(_finding("hex_obfuscated_name", "high",
            f"{len(hexn)} hex-escaped name token(s) (evasion): {sample}"))

    # Incremental updates (each save appends an EOF marker).
    eofs = _count(data, b"%%EOF")
    result["incremental_updates"] = max(0, eofs - 1)
    if eofs - 1 >= 1:
        result["findings"].append(_finding("incremental_update", "low",
            f"{eofs - 1} incremental update(s) appended"))

    # URIs (from /URI actions and raw http(s) in the body).
    uris: list[str] = []
    for mm in _URI_IN_PDF.finditer(data):
        uris.append(mm.group(1).decode("latin-1", "replace").strip())
    for mm in _HTTP_IN_PDF.finditer(data):
        uris.append(mm.group(0).decode("latin-1", "replace").strip())
    seen = set()
    result["uris"] = [u for u in uris if not (u in seen or seen.add(u))][:_MAX_URIS]

    _extract_javascript(data, result)
    _extract_objects(data, result)
    _extract_metadata(original_path, result)
    _extract_embedded(original_path, extracted_dir, result)
    _extract_text(original_path, result)

    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
