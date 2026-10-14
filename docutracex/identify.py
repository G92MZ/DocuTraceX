"""File type identification via libmagic (primary general identifier).

Wraps ``python-magic`` (libmagic). Identification never executes content. The
module degrades gracefully: if libmagic is unavailable (e.g. the native library
is not bundled on Windows yet), ``identify`` returns a result marked
``available=False`` instead of raising, so case creation still works.

It also compares the declared extension against the detected type at a *family*
level (ooxml, ole, pdf, email, zip, text...) so that, for example, a .docx seen
by libmagic as a generic ZIP is reported as an inconclusive container match
rather than a false mismatch — the exact problem that made DIE unusable here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import structure
from .logging_config import get_logger

log = get_logger(__name__)

# --- extension -> family -----------------------------------------------------
# Families group extensions by the container/structure they share.
_EXT_FAMILY: dict[str, str] = {
    # OOXML (ZIP/OPC packages)
    **{e: "ooxml" for e in (
        ".docx", ".docm", ".dotx", ".dotm",
        ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam",
        ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".ppam",
        ".sldx", ".sldm",
    )},
    ".xlsb": "ooxml",  # OPC/ZIP package with binary parts
    # Legacy Office (OLE/CFB compound files)
    **{e: "ole" for e in (".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot")},
    ".msg": "ole",  # Outlook message is an OLE/CFB container
    # Standalone
    ".pdf": "pdf",
    ".eml": "email",
    ".emlx": "email",
}

# --- detected mime/description -> family -------------------------------------
_MIME_FAMILY: dict[str, str] = {
    # proper OOXML mimes (newer libmagic databases)
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "ooxml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "ooxml",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "ooxml",
    "application/vnd.ms-office": "ooxml",
    # OLE/CFB
    "application/x-ole-storage": "ole",
    "application/vnd.ms-outlook": "ole",
    "application/msword": "ole",
    "application/vnd.ms-excel": "ole",
    "application/vnd.ms-powerpoint": "ole",
    "application/CDFV2": "ole",
    # standalone
    "application/pdf": "pdf",
    "message/rfc822": "email",
    "text/x-mail": "email",
}

# Generic container mimes: structurally correct but not type-specific. For an
# ooxml extension, application/zip is "inconclusive", not a mismatch.
_GENERIC = {"application/zip", "application/octet-stream", "application/CDFV2",
            "application/x-ole-storage"}

_MATCH = "match"
_MISMATCH = "mismatch"
_INCONCLUSIVE = "inconclusive"
_UNKNOWN = "unknown"


def _libmagic_version() -> str | None:
    try:
        import magic  # type: ignore

        ver = getattr(magic, "version", None)
        if callable(ver):
            v = ver()
            return f"libmagic {v // 10000}.{(v // 100) % 100}.{v % 100}" if v else "libmagic"
        return "libmagic"
    except Exception:  # noqa: BLE001
        return None


def detected_family(mime: str, description: str) -> str | None:
    if mime in _MIME_FAMILY:
        return _MIME_FAMILY[mime]
    desc = (description or "").lower()
    if "composite document" in desc or "cdf" in desc:
        return "ole"
    if "pdf document" in desc:
        return "pdf"
    if "zip archive" in desc:
        return "zip"
    if "mail" in desc or "rfc 822" in desc or "smtp" in desc:
        return "email"
    if mime.startswith("text/"):
        return "text"
    return None


def classify_discrepancy(
    declared_ext: str,
    mime: str,
    description: str,
    structural_family: str | None = None,
) -> dict[str, Any]:
    """Compare declared extension vs detected type at the family level.

    ``structural_family`` is strong evidence from a structural recognizer (e.g.
    EMLX) and, when it matches the declared extension's family, confirms the
    type even if libmagic only saw generic text.
    """
    ext = (declared_ext or "").lower()
    exp = _EXT_FAMILY.get(ext)
    det = detected_family(mime, description)

    if exp is not None and structural_family is not None and structural_family == exp:
        return {
            "status": _MATCH,
            "detail": "Confirmed by structural signature.",
            "declared_family": exp,
            "detected_family": structural_family,
        }

    if exp is None:
        status, detail = _UNKNOWN, "Extension not in the analysis scope."
    elif det is None:
        status, detail = _INCONCLUSIVE, "Detected type could not be mapped to a family."
    elif det == exp:
        status, detail = _MATCH, "Declared extension matches detected type."
    elif exp == "ooxml" and (det == "zip" or mime in _GENERIC):
        # e.g. .docx detected as application/zip: correct container, not specific.
        status = _INCONCLUSIVE
        detail = "Detected as a generic container consistent with the extension."
    elif exp == "email" and det == "text":
        # EML/EMLX are text-based; libmagic may not recognise EMLX specifically.
        status = _INCONCLUSIVE
        detail = "Detected as text; email formats are text-based (no specific signature)."
    elif exp == "ole" and mime in _GENERIC:
        status = _INCONCLUSIVE
        detail = "Detected as a generic compound file consistent with the extension."
    else:
        status = _MISMATCH
        detail = f"Declared '{ext}' ({exp}) but detected as {det}."

    return {
        "status": status,
        "detail": detail,
        "declared_family": exp,
        "detected_family": det,
    }


def identify(path: Path, declared_ext: str = "") -> dict[str, Any]:
    """Identify a file with libmagic. Never raises on identification failure."""
    result: dict[str, Any] = {
        "tool": "libmagic",
        "tool_version": None,
        "available": False,
        "mime": None,
        "name": None,
        "error": None,
        "discrepancy": None,
        "structural": None,
    }

    # Structural recognizer (bounded read) for formats without a leading magic
    # number, e.g. EMLX. Runs regardless of libmagic availability.
    structural = structure.recognize(path, declared_ext)
    result["structural"] = structural
    structural_family = structural["family"] if structural else None

    from . import native

    native.setup_libmagic()  # wire bundled libmagic (no-op if not bundled/needed)
    try:
        import magic  # type: ignore
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"libmagic unavailable: {exc}"
        log.warning("libmagic not available: %s", exc)
        # Still classify from structure alone if we have it.
        result["discrepancy"] = classify_discrepancy(declared_ext, "", "", structural_family)
        return result

    try:
        mime = magic.from_file(str(path), mime=True)
        name = magic.from_file(str(path))
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"identification failed: {exc}"
        log.warning("Identification failed for %s: %s", path, exc)
        return result

    result.update(
        available=True,
        tool_version=_libmagic_version(),
        mime=mime,
        name=name,
        discrepancy=classify_discrepancy(declared_ext, mime, name, structural_family),
    )
    return result
