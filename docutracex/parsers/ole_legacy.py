"""Legacy OLE / BIFF documents: .doc / .xls / .ppt (Compound File).

A light structural parser over the CFB container (via olefile, BSD): the stream
inventory, SummaryInformation metadata, the document kind and VBA presence. The
heavy lifting is done by the tools wired alongside it in the pipeline —
oletools (olevba/oleid/mraptor/msodde/oleobj), XLMMacroDeobfuscator (Excel 4.0
macros in hidden BIFF sheets), OfficeMalScanner and Didier's oledump. Nothing is
executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

# Main content stream -> document kind.
_KIND_STREAMS = {
    "worddocument": "word", "book": "excel", "workbook": "excel",
    "powerpoint document": "powerpoint",
}
# Storage/stream names that indicate a VBA project.
_VBA_MARKERS = ("macros", "_vba_project_cur", "vba", "_vba_project")


def _finding(rule: str, severity: str, detail: str, location: str = "",
             evidence: str = "") -> dict[str, Any]:
    return {"tool": "ole", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence}


def analyze(original_path: Path, extracted_dir: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "ole", "format": "ole", "status": "ok",
        "kind": None, "streams": [], "metadata": {}, "vba": False, "findings": [],
    }
    try:
        import olefile
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        # id: gmzpt
        result["findings"].append(_finding("olefile_unavailable", "low", str(exc)))
        return result

    if not olefile.isOleFile(str(original_path)):
        result["status"] = "error"
        result["findings"].append(_finding("not_ole", "high", "Not a valid OLE/CFB container"))
        return result

    ole = olefile.OleFileIO(str(original_path))
    try:
        entries = ["/".join(e) if isinstance(e, list) else e
                   for e in ole.listdir(streams=True, storages=True)]
        result["streams"] = sorted(entries)[:500]
        low = {e.lower() for e in entries}
        flat = {part.lower() for e in entries for part in e.split("/")}

        for stream, kind in _KIND_STREAMS.items():
            if any(stream == e.split("/")[-1].lower() for e in entries):
                result["kind"] = kind
                break

        if flat & set(_VBA_MARKERS):
            result["vba"] = True
            result["findings"].append(_finding("vba_macros_present", "medium",
                "Legacy OLE document contains a VBA project", "Macros"))

        # SummaryInformation metadata (author, title, dates, last-saved-by...).
        try:
            md = ole.get_metadata()
            meta: dict[str, Any] = {}
            for attr in ("author", "title", "subject", "last_saved_by", "company",
                         "creating_application", "create_time", "last_saved_time",
                         "revision_number"):
                val = getattr(md, attr, None)
                if val:
                    meta[attr] = val.decode("latin-1", "replace") if isinstance(val, bytes) else str(val)
            result["metadata"] = meta
        except Exception:  # noqa: BLE001
            pass

        # Embedded OLE objects / packages are a common delivery vector.
        if "\x01ole10native" in flat or any("objectpool" in e.lower() for e in entries):
            result["findings"].append(_finding("embedded_ole_object", "medium",
                "Embedded OLE object(s)/ObjectPool present", "ObjectPool"))
    finally:
        ole.close()

    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
