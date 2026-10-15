"""Recursive analysis of extracted children.

A maldoc's payload usually lives one level down: a macro .docm attached to an
email, an OLE object embedded in a Word file, a PDF carrying an embedded office
document. This walks those children and runs the family-appropriate tools on
each — olevba/oleid/msodde/mraptor/oleobj for Office/OLE, the PDF scanner for
PDFs, the email parser for messages — then recurses into whatever THEY extract,
up to a bounded depth. Findings are flattened with a path chain so the origin
is always clear.

Bounds (depth, child count, per-file work) guard against zip bombs and cycles.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from .logging_config import get_logger
from .storage import CasePaths

log = get_logger(__name__)

MAX_DEPTH = 3
MAX_CHILDREN = 25

_OOXML_EXT = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
              ".xlam", ".xlsb", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
              ".ppam", ".sldx", ".sldm"}
_OLE_EXT = {".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot"}
_EMAIL_EXT = {".eml", ".emlx", ".msg"}


def _ext(name: str) -> str:
    return ("." + name.lower().rsplit(".", 1)[1]) if "." in name else ""


def _kind(path: Path, name: str) -> str:
    """Decide how to analyze a child: by extension, then by content sniff."""
    ext = _ext(name)
    if ext in _OOXML_EXT:
        return "ooxml"
    if ext in _OLE_EXT:
        return "ole"
    if ext == ".pdf":
        return "pdf"
    if ext in _EMAIL_EXT:
        return "email"
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return "other"
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "ole"
    if head[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as zf:
                if "[Content_Types].xml" in zf.namelist():
                    return "ooxml"
        except Exception:  # noqa: BLE001
            return "other"
    return "other"


def _rel(paths: CasePaths, p: Path) -> str:
    try:
        return p.relative_to(paths.root).as_posix()
    except ValueError:
        return p.name


def _scan_one(abs_path: Path, name: str, paths: CasePaths, depth: int,
              chain: str) -> dict[str, Any]:
    """Analyze one child; return a node with its findings and children."""
    node: dict[str, Any] = {
        "filename": name, "kind": _kind(abs_path, name), "depth": depth,
        "stored_path": _rel(paths, abs_path),
        "findings": [], "children": [],
    }
    try:
        data = abs_path.read_bytes()
        node["size_bytes"] = len(data)
        node["sha256"] = hashlib.sha256(data).hexdigest()
    except OSError:
        node["error"] = "unreadable"
        return node

    this_chain = f"{chain} › {name}" if chain else name
    work = paths.extracted_dir / "nested"
    kids: list[tuple[Path, str]] = []
    kind = node["kind"]

    def add_findings(findings, default_tool):  # noqa: ANN001
        for f in findings or []:
            node["findings"].append({
                "tool": f.get("tool", default_tool),
                "rule": f.get("rule", ""),
                "severity": f.get("severity", "info"),
                "detail": f"[{this_chain}] {f.get('detail', '')}",
                "location": f"nested:{this_chain}",
            })

    try:
        if kind in ("ooxml", "ole"):
            from .parsers import oletools_suite
            res = oletools_suite.analyze(abs_path, work)
            add_findings(res.get("findings"), "oletools")
            for obj in res.get("tools", {}).get("oleobj", {}).get("objects", []) or []:
                sp = obj.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, Path(sp).name))
            if kind == "ooxml":
                from .parsers import office, xlm
                if _ext(name) == ".xlsb":
                    from .parsers import xlsb
                    sem = xlsb.analyze(abs_path)
                else:
                    sem = office.analyze(abs_path, _ext(name), work)
                if sem:
                    add_findings(sem.get("findings"), kind)
                xres = xlm.analyze(abs_path)
                add_findings(xres.get("findings"), "xlmdeobf")
            # Own Office rules and, when there are macros, VBA emulation.
            from .parsers import office_rules, vipermonkey
            rules = (office_rules.analyze_ooxml(abs_path) if kind == "ooxml"
                     else office_rules.analyze_ole(abs_path))
            add_findings(rules.get("findings"), "officerules")
            if ((res.get("tools") or {}).get("olevba") or {}).get("macros"):
                vm = vipermonkey.analyze(abs_path, work)
                add_findings(vm.get("findings"), "vipermonkey")
        elif kind == "pdf":
            from .parsers import pdf
            res = pdf.analyze(abs_path, work)
            add_findings(res.get("findings"), "pdf")
            for emb in res.get("embedded", []) or []:
                sp = emb.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, emb.get("filename") or Path(sp).name))
        elif kind == "email":
            from .parsers import mail
            res = mail.analyze(abs_path, _ext(name), work)
            add_findings(res.get("findings"), "email")
            for att in res.get("attachments", []) or []:
                sp = att.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, att.get("filename") or Path(sp).name))
    except Exception as exc:  # noqa: BLE001
        node["error"] = str(exc)

    if depth < MAX_DEPTH:
        for cpath, cname in kids[:MAX_CHILDREN]:
            if cpath.is_file():
                node["children"].append(_scan_one(cpath, cname, paths, depth + 1, this_chain))
    elif kids:
        node["truncated_children"] = len(kids)
    return node


def _flatten(nodes: list[dict[str, Any]], out: list[dict[str, Any]]) -> None:
    for n in nodes:
        out.extend(n.get("findings", []))
        _flatten(n.get("children", []), out)


def scan_children(items: list[dict[str, Any]], paths: CasePaths) -> dict[str, Any]:
    """Recursively scan a list of extracted children (``{path, filename}``)."""
    result: dict[str, Any] = {"module": "nested", "tree": [], "findings": [], "status": "ok"}
    for it in items[:MAX_CHILDREN]:
        p = Path(it["path"])
        if p.is_file():
            result["tree"].append(_scan_one(p, it.get("filename") or p.name, paths, 1, ""))
    flat: list[dict[str, Any]] = []
    _flatten(result["tree"], flat)
    result["findings"] = flat
    result["counts"] = {"findings": len(flat), "nodes": _count_nodes(result["tree"])}
    if flat:
        result["status"] = "ok_with_findings"
    return result


def _count_nodes(nodes: list[dict[str, Any]]) -> int:
    return sum(1 + _count_nodes(n.get("children", [])) for n in nodes)
