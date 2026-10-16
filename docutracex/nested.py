"""Recursive analysis of extracted children.

A maldoc's payload usually lives one level down: a macro .docm attached to an
email, an OLE object embedded in a Word file, a PDF carrying an embedded office
document. This walks those children and runs the family-appropriate tools on
each — olevba/oleid/msodde/mraptor/oleobj for Office/OLE, the PDF scanner for
PDFs, the email parser for messages, extraction for ZIP/7z archives; encrypted
children are unlocked first (passwords from the analyst or the carrying email,
see ``unlock``) — then recurses into whatever THEY extract,
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
_ARCHIVE_EXT = {".zip", ".7z"}


def _ext(name: str) -> str:
    return ("." + name.lower().rsplit(".", 1)[1]) if "." in name else ""


def _kind(path: Path, name: str) -> str:
    """Decide how to analyze a child: by extension, then by content sniff."""
    ext = _ext(name)
    try:
        with path.open("rb") as fh:
            if fh.read(8).lstrip(b"\xef\xbb\xbf")[:4] == b"{\\rt":
                return "rtf"  # Word opens RTF whatever the extension (.doc that is RTF)
    except OSError:
        pass
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
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "archive"
    if head[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as zf:
                if "[Content_Types].xml" in zf.namelist():
                    return "ooxml"
        except Exception:  # noqa: BLE001
            return "other"
        return "archive"
    return "other"


def _rel(paths: CasePaths, p: Path) -> str:
    try:
        return p.relative_to(paths.root).as_posix()
    except ValueError:
        return p.name


def _scan_one(abs_path: Path, name: str, paths: CasePaths, depth: int,
              chain: str, ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Analyze one child; return a node with its findings and children.

    ``ctx`` carries the passwords to try on encrypted children: the analyst's
    (``user``) and those given by an enclosing email (``harvested``)."""
    ctx = ctx or {}
    node: dict[str, Any] = {
        "filename": name, "kind": _kind(abs_path, name), "depth": depth,
        "stored_path": _rel(paths, abs_path),
        "findings": [], "children": [],
    }
    try:
        data = abs_path.read_bytes()
        # AeWckx3pKh
        node["size_bytes"] = len(data)
        node["sha256"] = hashlib.sha256(data).hexdigest()
    except OSError:
        node["error"] = "unreadable"
        return node

    this_chain = f"{chain} › {name}" if chain else name
    work = paths.extracted_dir / "nested"
    kids: list[tuple[Path, str]] = []
    kind = node["kind"]

    # tag: gmzpt
    def add_findings(findings, default_tool):  # noqa: ANN001
        for f in findings or []:
            node["findings"].append({
                "tool": f.get("tool", default_tool),
                "rule": f.get("rule", ""),
                "severity": f.get("severity", "info"),
                "detail": f"[{this_chain}] {f.get('detail', '')}",
                "location": f"nested:{this_chain}",
            })

    from . import unlock

    try:
        # Encrypted Office/PDF child: decrypt it with the known passwords and
        # analyse the decrypted copy (the hash above stays the original's).
        if kind in ("ooxml", "ole", "pdf"):
            rec = unlock.unlock_file(abs_path, work / "decrypted" / node["sha256"][:12],
                                     unlock.candidates(ctx.get("user"), ctx.get("harvested"),
                                                       words=ctx.get("words")), name=name)
            if rec["encrypted"]:
                node["unlock"] = unlock.public(rec, paths.root)
                add_findings(rec["findings"], "unlock")
                if rec["decrypted"]:
                    abs_path = Path(rec["decrypted_file"])
                elif rec["kind"] == "office" and kind == "ooxml":
                    kind = node["kind"] = "ole"
        if kind == "archive":
            rec = unlock.extract_archive(abs_path, work / "archives" / node["sha256"][:12],
                                         unlock.candidates(ctx.get("user"), ctx.get("harvested"),
                                                           kind="archive", words=ctx.get("words")),
                                         name=name)
            node["archive"] = unlock.public(rec, paths.root)
            add_findings(rec["findings"], "archive")
            for e in rec["entries"]:
                if e.get("file"):
                    kids.append((Path(e["file"]), Path(e["name"]).name))
        elif kind in ("ooxml", "ole"):
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
        elif kind == "rtf":
            from .parsers import oletools_suite, rtf
            r = rtf.analyze(abs_path, _ext(name), work)
            add_findings(r.get("findings"), "rtf")
            res = oletools_suite.analyze(abs_path, work)
            add_findings([f for f in res.get("findings") or [] if f.get("tool") == "msodde"], "oletools")
            for obj in r.get("objects") or []:
                sp = obj.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, Path(sp).name))
        elif kind == "pdf":
            from .parsers import pdf
            res = pdf.analyze(abs_path, work)
            add_findings(res.get("findings"), "pdf")
            from .parsers import pdf_tools
            add_findings(pdf_tools.analyze(abs_path, res).get("findings"), "pdftools")
            for emb in res.get("embedded", []) or []:
                sp = emb.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, emb.get("filename") or Path(sp).name))
        elif kind == "email":
            from .parsers import mail
            res = mail.analyze(abs_path, _ext(name), work)
            add_findings(res.get("findings"), "email")
            from .parsers import mail_rules
            add_findings(mail_rules.analyze(abs_path, _ext(name), res, paths.root).get("findings"),
                         "mailrules")
            for att in res.get("attachments", []) or []:
                sp = att.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, att.get("filename") or Path(sp).name))
            # Passwords this email gives unlock its own attachments.
            # rev: gmzpt
            from . import passwords
            found = passwords.harvest((res.get("addresses") or {}).get("subject", ""),
                                      res.get("body_sample", ""), res.get("html_text_sample", ""))
            if found:
                node["password_candidates"] = found
                ctx = {**ctx, "harvested": found + list(ctx.get("harvested") or [])}
            if ctx.get("wordlist"):
                words = passwords.email_words(res)
                node["wordlist"] = {"enabled": True, "candidates": len(words)}
                ctx = {**ctx, "words": words + list(ctx.get("words") or [])}
    except Exception as exc:  # noqa: BLE001
        node["error"] = str(exc)

    if depth < MAX_DEPTH:
        for cpath, cname in kids[:MAX_CHILDREN]:
            if not cpath.is_file():
                # Tools store paths relative to the parent of their output dir
                # (here extracted/), not to the case root.
                try:
                    alt = work.parent / cpath.relative_to(paths.root)
                except ValueError:
                    alt = cpath
                cpath = alt
            if cpath.is_file():
                node["children"].append(_scan_one(cpath, cname, paths, depth + 1, this_chain, ctx))
    elif kids:
        node["truncated_children"] = len(kids)
    return node


def _flatten(nodes: list[dict[str, Any]], out: list[dict[str, Any]]) -> None:
    for n in nodes:
        out.extend(n.get("findings", []))
        _flatten(n.get("children", []), out)


def scan_children(items: list[dict[str, Any]], paths: CasePaths,
                  unlock_ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recursively scan a list of extracted children (``{path, filename}``).
    ``unlock_ctx`` = passwords for encrypted children (see ``_scan_one``)."""
    result: dict[str, Any] = {"module": "nested", "tree": [], "findings": [], "status": "ok"}
    for it in items[:MAX_CHILDREN]:
        p = Path(it["path"])
        if p.is_file():
            result["tree"].append(_scan_one(p, it.get("filename") or p.name, paths, 1, "", unlock_ctx))
    flat: list[dict[str, Any]] = []
    _flatten(result["tree"], flat)
    result["findings"] = flat
    result["counts"] = {"findings": len(flat), "nodes": _count_nodes(result["tree"])}
    if flat:
        result["status"] = "ok_with_findings"
    return result


def _count_nodes(nodes: list[dict[str, Any]]) -> int:
    return sum(1 + _count_nodes(n.get("children", [])) for n in nodes)
