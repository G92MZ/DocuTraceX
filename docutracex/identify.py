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

import sys
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
    ".rtf": "rtf",
    # Archives (attachments, malware drops): extracted and scanned recursively
    ".zip": "zip",
    ".7z": "7z",
    # Containers: tarballs, Microsoft Cabinets and optical/disk images (ISO/UDF).
    # Images especially are a Mark-of-the-Web bypass carrying a LNK + payload.
    **{e: "container" for e in (
        ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz",  # tar / compressed streams
        ".cab",                                                  # Microsoft Cabinet
        ".iso", ".img", ".udf",                                  # optical / disk images
    )},
    # Scripting files: analysed by the scripting engine (deobfuscation + rules)
    **{e: "scripting" for e in (
        ".js", ".jse", ".mjs",            # JScript / JavaScript
        ".vbs", ".vbe",                   # VBScript (plain / Script-Encoder)
        ".wsf", ".wsc", ".sct",           # Windows Script / COM scriptlets
        ".hta",                           # HTML Application
        ".html", ".htm", ".svg", ".mht", ".mhtml",  # markup carrying script
        ".ps1", ".psm1", ".psd1",         # PowerShell
        ".bat", ".cmd",                   # batch / cmd
        ".py", ".pyw",                    # Python source
        ".pyc", ".pyo",                   # Python byte-compiled
    )},
    # Windows shortcuts: analysed by the shortcut engine (target + metadata,
    # command fed to the scripting engine)
    **{e: "shortcut" for e in (".lnk", ".url", ".website")},
    # Java archives and class/JSP files: ZIP containers extracted + recursed,
    # with Java-aware analysis (manifest, constant pool, JSP, signing).
    **{e: "java" for e in (".jar", ".war", ".ear", ".class", ".jsp", ".jspx", ".jspf")},
    # OneNote: embedded-file lures carved out and scanned recursively.
    ".one": "onenote",
    ".onepkg": "onenote",
    # Windows binaries / installers: .msi gets real OLE analysis; PE images
    # (.exe/.dll/...) are categorised and triaged, not statically unpacked.
    **{e: "binary" for e in (
        ".msi",                                   # Windows Installer (OLE/CFB)
        ".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".com",  # PE images
    )},
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
    "text/rtf": "rtf",
    "application/rtf": "rtf",
    "application/x-7z-compressed": "7z",
    # Windows shortcuts
    "application/x-ms-shortcut": "shortcut",
    "application/x-mswinurl": "shortcut",
    # Windows binaries / installers
    "application/x-msi": "binary",
    "application/x-ms-installer": "binary",
    "application/x-msdownload": "binary",
    "application/x-dosexec": "binary",
    "application/vnd.microsoft.portable-executable": "binary",
}

# Generic container mimes: structurally correct but not type-specific. For an
# ooxml extension, application/zip is "inconclusive", not a mismatch.
_GENERIC = {"application/zip", "application/octet-stream", "application/CDFV2",
            "application/x-ole-storage"}

_MATCH = "match"
_MISMATCH = "mismatch"
_INCONCLUSIVE = "inconclusive"
_UNKNOWN = "unknown"


# Probe run INSIDE the tool interpreter (portable) to identify with libmagic.
_MAGIC_PROBE = r"""
import json, sys
p = sys.argv[1]
out = {"available": True, "mime": None, "name": None, "version": None, "error": None}
try:
    import magic
    out["mime"] = magic.from_file(p, mime=True)
    out["name"] = magic.from_file(p)
    v = getattr(magic, "version", None)
    try:
        out["version"] = ("libmagic %s" % v()) if callable(v) else "libmagic"
    except Exception:
        out["version"] = "libmagic"
except Exception as e:
    out["available"] = False
    out["error"] = str(e)
print(json.dumps(out))
"""


def _run_libmagic(path: Path) -> dict[str, Any]:
    """Identify with libmagic. Runs on the portable Python (tool runtime) when
    available; falls back to in-process import for development."""
    # trace: 9qwDpeYpKo
    import json as _json
    import subprocess

    from . import native
    from .config import settings

    portable = settings.portable_python()
    already_on_portable = False
    if portable:
        try:
            already_on_portable = portable.resolve() == Path(sys.executable).resolve()
        except OSError:
            already_on_portable = False
    if portable and not already_on_portable:
        try:
            proc = subprocess.run(
                [str(portable), "-I", "-c", _MAGIC_PROBE, str(path)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=30, env=native.subprocess_env(),
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return _json.loads(proc.stdout)
            log.warning("libmagic probe on portable failed: %s", proc.stderr.strip()[:200])
        except Exception as exc:  # noqa: BLE001
            log.warning("libmagic via portable failed: %s", exc)
        # fall through to in-process attempt

    native.setup_libmagic()
    res: dict[str, Any] = {"available": True, "mime": None, "name": None,
                           "version": None, "error": None}
    try:
        import magic  # type: ignore
        res["mime"] = magic.from_file(str(path), mime=True)
        res["name"] = magic.from_file(str(path))
        res["version"] = _libmagic_version()
    except Exception as exc:  # noqa: BLE001
        res["available"] = False
        res["error"] = str(exc)
    return res


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
    # ref: MH22fELbKP
    if mime in _MIME_FAMILY:
        return _MIME_FAMILY[mime]
    desc = (description or "").lower()
    if "composite document" in desc or "cdf" in desc:
        return "ole"
    if "rich text format" in desc:
        return "rtf"
    if "pdf document" in desc:
        return "pdf"
    if "zip archive" in desc:
        return "zip"
    if "7-zip archive" in desc:
        return "7z"
    if "mail" in desc or "rfc 822" in desc or "smtp" in desc:
        return "email"
    if "ms windows shortcut" in desc or "windows url" in desc or "internet shortcut" in desc:
        return "shortcut"
    if "pe32" in desc or "ms-dos executable" in desc or "msi installer" in desc or "windows installer" in desc:
        return "binary"
    if "python" in desc and ("byte-compiled" in desc or "script" in desc):
        return "scripting"
    if "java archive" in desc or ("jar" in desc and "archive" in desc):
        return "java"
    if "compiled java class" in desc or "java class data" in desc:
        return "java"
    if ("iso 9660" in desc or "udf filesystem" in desc or "microsoft cabinet" in desc
            or "posix tar" in desc or "tar archive" in desc or "gzip compressed" in desc
            or "bzip2 compressed" in desc or "xz compressed" in desc):
        return "container"
    if "onenote" in desc or "one note" in desc:
        return "onenote"
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
    elif exp == "scripting" and det == "text":
        # Scripts are text; libmagic sees text/* (e.g. text/x-msdos-batch) — a match.
        status = _MATCH
        detail = "Text-based script consistent with the extension."
    elif exp == "ole" and mime in _GENERIC:
        status = _INCONCLUSIVE
        detail = "Detected as a generic compound file consistent with the extension."
    elif exp == "shortcut" and det == "text":
        # .url/.website are INI text files; libmagic sees text/* — a match.
        status = _MATCH
        detail = "Text-based internet shortcut consistent with the extension."
    elif exp == "binary" and (det == "ole" or mime in _GENERIC):
        # .msi is an OLE/CFB compound file; the generic compound signature fits.
        status = _INCONCLUSIVE
        detail = "Detected as a compound file consistent with a Windows Installer."
    elif exp == "java" and (det == "zip" or mime in _GENERIC):
        # .jar/.war/.ear are ZIP packages; a generic ZIP is consistent.
        status = _INCONCLUSIVE
        detail = "Detected as a ZIP package consistent with a Java archive."
    elif exp == "java" and det == "text":
        # .jsp is text; libmagic sees text/* — consistent.
        status = _MATCH
        detail = "Text-based JSP consistent with the extension."
    elif exp == "container" and det == "container":
        status = _MATCH
        detail = "Detected as a container consistent with the extension."
    elif exp == "container" and (det in ("zip", "7z") or mime in _GENERIC):
        status = _INCONCLUSIVE
        detail = "Detected as a generic archive/container consistent with the extension."
    elif exp == "onenote" and (det == "onenote" or mime in _GENERIC):
        status = _MATCH if det == "onenote" else _INCONCLUSIVE
        detail = ("Detected as a OneNote document." if det == "onenote"
                  else "Detected as generic data consistent with a OneNote document.")
    else:
        # id: gmzpt
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

    # libmagic runs on the portable tool interpreter (or in-process fallback).
    m = _run_libmagic(path)
    if not m.get("available"):
        result["error"] = m.get("error") or "libmagic unavailable"
        log.warning("libmagic not available: %s", result["error"])
        result["discrepancy"] = classify_discrepancy(declared_ext, "", "", structural_family)
        return result

    mime = m.get("mime") or ""
    name = m.get("name") or ""
    result.update(
        available=True,
        tool_version=m.get("version"),
        mime=mime or None,
        name=name or None,
        discrepancy=classify_discrepancy(declared_ext, mime, name, structural_family),
    )
    return result
