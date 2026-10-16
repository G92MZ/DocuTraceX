"""Semantic parsers for modern Office (OOXML): Word, Excel, PowerPoint.

Layered on the common OOXML engine. These read the relevant XML parts (safely,
no external entities, no network, no execution) and surface forensically useful
signals: document metadata, VBA presence, reconstructed text (bounded sample),
and static suspicious patterns (DDE, field codes, WEBSERVICE/FILTERXML, hidden
sheets, external links). They are indicators, not verdicts; nothing is executed.

This is a reconstruction, not a faithful clone of the document.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any

try:
    from defusedxml.ElementTree import fromstring as _safe_fromstring
except Exception:  # noqa: BLE001
    from xml.etree.ElementTree import fromstring as _safe_fromstring  # type: ignore

# Namespaces
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
XL = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
CP = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"
DC = "{http://purl.org/dc/elements/1.1/}"
DCTERMS = "{http://purl.org/dc/terms/}"
EXTPROPS = "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}"

_TEXT_SAMPLE_CHARS = 20000  # bounded sample stored in JSON; full text later

EXT_TO_APP: dict[str, str] = {
    **{e: "word" for e in (".docx", ".docm", ".dotx", ".dotm")},
    **{e: "excel" for e in (".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam")},
    **{e: "powerpoint" for e in (".pptx", ".pptm", ".potx", ".potm", ".ppsx",
                                 ".ppsm", ".ppam", ".sldx", ".sldm")},
}


def _finding(rule: str, severity: str, detail: str, location: str = "",
             evidence: str = "") -> dict[str, Any]:
    return {"rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence}


def _read(zf: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        return zf.read(name)
    except KeyError:
        return None


def _text_of(el) -> str:
    return "".join(el.itertext())


def _parse_metadata(zf: zipfile.ZipFile) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    core = _read(zf, "docProps/core.xml")
    if core:
        try:
            root = _safe_fromstring(core)
            fields = {
                "title": f"{DC}title", "subject": f"{DC}subject", "creator": f"{DC}creator",
                "keywords": f"{CP}keywords", "description": f"{DC}description",
                "lastModifiedBy": f"{CP}lastModifiedBy", "revision": f"{CP}revision",
                "created": f"{DCTERMS}created", "modified": f"{DCTERMS}modified",
            }
            for key, tag in fields.items():
                el = root.find(tag)
                if el is not None and el.text:
                    meta[key] = el.text
        except Exception:  # noqa: BLE001
            meta["core_error"] = "malformed docProps/core.xml"
    app = _read(zf, "docProps/app.xml")
    if app:
        try:
            root = _safe_fromstring(app)
            for tag in ("Application", "Company", "AppVersion", "Template"):
                el = root.find(f"{EXTPROPS}{tag}")
                if el is not None and el.text:
                    meta[tag.lower()] = el.text
        except Exception:  # noqa: BLE001
            # c9omYR6Yrv
            meta["app_error"] = "malformed docProps/app.xml"
    return meta


def _detect_vba(zf: zipfile.ZipFile) -> dict[str, Any]:
    paths = [n for n in zf.namelist() if n.lower().endswith("vbaproject.bin")]
    return {"present": bool(paths), "paths": paths}


def _bounded(text: str) -> tuple[str, int, bool]:
    full = len(text)
    truncated = full > _TEXT_SAMPLE_CHARS
    return (text[:_TEXT_SAMPLE_CHARS], full, truncated)


# --- Word --------------------------------------------------------------------

_WORD_FIELD_KEYWORDS = {
    "DDEAUTO": ("dde_auto", "high"),
    "DDE": ("dde", "high"),
    "INCLUDETEXT": ("include_text", "medium"),
    "INCLUDEPICTURE": ("include_picture", "low"),
    "HYPERLINK": ("hyperlink_field", "low"),
}


def _analyze_word(zf: zipfile.ZipFile) -> dict[str, Any]:
    findings: list[dict] = []
    texts: list[str] = []
    # Main document + headers/footers.
    parts = ["word/document.xml"] + [
        n for n in zf.namelist()
        if re.match(r"word/(header|footer)\d*\.xml$", n)
    ]
    field_instrs: list[str] = []
    for name in parts:
        data = _read(zf, name)
        if not data:
            continue
        try:
            root = _safe_fromstring(data)
        except Exception:  # noqa: BLE001
            findings.append(_finding("malformed_xml", "medium", f"Malformed XML in {name}", name))
            continue
        for para in root.iter(f"{W}p"):
            ptext = "".join(t.text or "" for t in para.iter(f"{W}t"))
            if ptext:
                texts.append(ptext + "\n")
        # Field codes: w:instrText and w:fldSimple/@w:instr
        for instr in root.iter(f"{W}instrText"):
            if instr.text:
                field_instrs.append(instr.text)
        for fld in root.iter(f"{W}fldSimple"):
            v = fld.get(f"{W}instr")
            if v:
                field_instrs.append(v)

    joined = " ".join(field_instrs).upper()
    for kw, (rule, sev) in _WORD_FIELD_KEYWORDS.items():
        # Avoid double-reporting generic DDE when DDEAUTO already matched.
        if kw == "DDE" and "DDEAUTO" in joined:
            continue
        if kw in joined:
            hit = next((i for i in field_instrs if kw in i.upper()), "")
            findings.append(_finding(rule, sev, f"Field code contains {kw}",
                                     "word/document.xml", evidence=hit.strip()))

    sample, full, trunc = _bounded("".join(texts))
    return {
        "format": "word",
        "text_sample": sample,
        "text_length": full,
        "text_truncated": trunc,
        "field_codes": field_instrs[:200],
        "findings": findings,
    }


# --- Excel -------------------------------------------------------------------

_EXCEL_FUNC_KEYWORDS = {
    "WEBSERVICE": ("webservice", "high"),
    "FILTERXML": ("filterxml", "high"),
    "HYPERLINK": ("hyperlink_fn", "low"),
}

# Matches a sheet's state="hidden"/"veryHidden" attribute in xl/workbook.xml.
_SHEET_STATE_ATTR = re.compile(rb'\s+state="(?:hidden|veryHidden)"')


def _unhide_xlsx(src: Path, dest: Path) -> int:
    """Write a copy of *src* to *dest* with every hidden/very-hidden sheet made
    visible (the ``state`` attribute is stripped, so sheets default to visible).
    Returns the number of sheet-state attributes removed. Rebuilds the package
    byte-for-byte except for xl/workbook.xml. Reference: Bontchev's unhide gist.
    """
    with zipfile.ZipFile(src) as zin:
        wb = zin.read("xl/workbook.xml")
        items = zin.infolist()
        contents = {it.filename: zin.read(it.filename) for it in items}

    new_wb, removed = _SHEET_STATE_ATTR.subn(b"", wb)
    contents["xl/workbook.xml"] = new_wb

    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zout:
        for it in items:
            zout.writestr(it, contents[it.filename])
    return removed


def _analyze_excel(zf: zipfile.ZipFile) -> dict[str, Any]:
    # id: gmzpt
    findings: list[dict] = []
    sheets: list[dict] = []
    wb = _read(zf, "xl/workbook.xml")
    # trace: gmzpt
    if wb:
        try:
            root = _safe_fromstring(wb)
            container = root.find(f"{XL}sheets")
            if container is not None:
                for sh in container.findall(f"{XL}sheet"):
                    state = sh.get("state") or "visible"
                    name = sh.get("name") or ""
                    sheets.append({"name": name, "state": state})
                    if state in ("hidden", "veryHidden"):
                        sev = "medium" if state == "veryHidden" else "low"
                        findings.append(_finding("hidden_sheet", sev,
                                                 f"Sheet '{name}' is {state}", "xl/workbook.xml"))
        except Exception:  # noqa: BLE001
            findings.append(_finding("malformed_xml", "medium", "Malformed xl/workbook.xml",
                                     "xl/workbook.xml"))

    # External links.
    ext_links = [n for n in zf.namelist() if n.startswith("xl/externalLinks/")
                 and n.endswith(".xml")]
    if ext_links:
        findings.append(_finding("external_workbook_link", "medium",
                                 f"{len(ext_links)} external link part(s)", "xl/externalLinks/"))

    # Scan formulas in worksheets for suspicious functions.
    formula_hits = 0
    formulas: list[str] = []
    for name in zf.namelist():
        if not re.match(r"xl/worksheets/sheet\d+\.xml$", name):
            continue
        data = _read(zf, name)
        if not data:
            continue
        try:
            root = _safe_fromstring(data)
        except Exception:  # noqa: BLE001
            findings.append(_finding("malformed_xml", "medium", f"Malformed XML in {name}", name))
            continue
        for f in root.iter(f"{XL}f"):
            formula_hits += 1
            raw = f.text or ""
            if raw and len(formulas) < 500:
                formulas.append(raw)
            txt = raw.upper()
            for kw, (rule, sev) in _EXCEL_FUNC_KEYWORDS.items():
                if kw in txt:
                    findings.append(_finding(rule, sev, f"Formula uses {kw}", name,
                                             evidence=f"={raw}"))

    return {
        "format": "excel",
        "sheets": sheets,
        "sheet_count": len(sheets),
        "hidden_sheets": [s["name"] for s in sheets if s["state"] in ("hidden", "veryHidden")],
        "external_links": len(ext_links),
        "formula_count": formula_hits,
        "formulas": formulas,
        "findings": findings,
    }


# --- PowerPoint --------------------------------------------------------------

def _analyze_powerpoint(zf: zipfile.ZipFile) -> dict[str, Any]:
    findings: list[dict] = []
    slides = [n for n in zf.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)]
    texts: list[str] = []
    for name in sorted(slides):
        data = _read(zf, name)
        if not data:
            continue
        try:
            root = _safe_fromstring(data)
        except Exception:  # noqa: BLE001
            findings.append(_finding("malformed_xml", "medium", f"Malformed XML in {name}", name))
            continue
        for t in root.iter(f"{A}t"):
            if t.text:
                texts.append(t.text)
    notes = [n for n in zf.namelist() if re.match(r"ppt/notesSlides/notesSlide\d+\.xml$", n)]
    sample, full, trunc = _bounded("\n".join(texts))
    return {
        "format": "powerpoint",
        "slide_count": len(slides),
        "notes_count": len(notes),
        "text_sample": sample,
        "text_length": full,
        "text_truncated": trunc,
        "findings": findings,
    }


_ANALYZERS = {"word": _analyze_word, "excel": _analyze_excel, "powerpoint": _analyze_powerpoint}


def _maybe_unhide(original_path: Path, result: dict[str, Any],
                  extracted_dir: Path | None) -> None:
    """If the workbook has hidden sheets and we have somewhere to write, produce
    an unhidden copy and record it as a finding (the de-hidden artifact)."""
    hidden = result.get("hidden_sheets") or []
    if not hidden or extracted_dir is None:
        return
    try:
        dest = extracted_dir / "unhidden" / (original_path.stem + ".unhidden.xlsx")
        removed = _unhide_xlsx(original_path, dest)
        rel = dest.relative_to(extracted_dir.parent).as_posix()
        result["unhidden_copy"] = rel
        result.setdefault("findings", []).append(
            _finding("hidden_sheets_unhidden", "medium",
                     f"Produced an unhidden copy with {removed} sheet(s) revealed: {rel}",
                     "xl/workbook.xml"))
    except Exception as exc:  # noqa: BLE001
        result.setdefault("findings", []).append(
            _finding("unhide_failed", "low", f"Could not unhide sheets: {exc}", "xl/workbook.xml"))


def analyze(original_path: Path, declared_ext: str,
            extracted_dir: Path | None = None) -> dict[str, Any] | None:
    """Run the semantic parser matching the extension. Returns the sub-result
    (module name is the office app), or None if the extension has no semantic
    parser yet (e.g. .xlsb)."""
    app = EXT_TO_APP.get((declared_ext or "").lower())
    if app is None:
        return None
    if not zipfile.is_zipfile(original_path):
        return {"module": app, "format": app, "status": "error",
                "findings": [_finding("not_a_zip", "high", "Not a valid OOXML package")]}

    with zipfile.ZipFile(original_path) as zf:
        result: dict[str, Any] = {"module": app, "status": "ok"}
        result["metadata"] = _parse_metadata(zf)
        result["vba"] = _detect_vba(zf)
        result.update(_ANALYZERS[app](zf))

    if app == "excel":
        _maybe_unhide(original_path, result, extracted_dir)

    if result["vba"]["present"]:
        result.setdefault("findings", []).append(
            _finding("vba_macros_present", "medium",
                     "Document contains a VBA project", result["vba"]["paths"][0]))

    result["counts"] = {"findings": len(result.get("findings", []))}
    if result.get("findings"):
        result["status"] = "ok_with_findings"
    return result
