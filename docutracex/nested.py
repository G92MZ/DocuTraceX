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

MAX_DEPTH = 12
MAX_CHILDREN = 25
# Total nodes per scan: 12 levels x 25 children could explode on a crafted
# archive-in-archive, so the whole tree is capped (children past it are counted
# as truncated, not analysed).
MAX_NODES = 300

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
    if ext in (".lnk", ".url", ".website"):
        return "shortcut"
    if ext in (".py", ".pyw", ".pyc", ".pyo"):
        return "python"
    if ext in (".class", ".jsp", ".jspx", ".jspf"):
        return "java"
    if ext in (".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".cab", ".iso", ".img", ".udf"):
        return "archive"
    if ext in (".one", ".onepkg"):
        return "onenote"
    if ext in (".msi", ".msp", ".msm", ".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".com"):
        return "binary"
    if ext in (".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".psm1", ".bat", ".cmd", ".html", ".htm"):
        return "script"   # analysed by the code-language phase (JS sandbox, PowerShell, VBScript, batch)
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return "other"
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:4] == b"\x4c\x00\x00\x00":   # Shell Link header (HeaderSize = 0x4C)
        return "shortcut"
    if head[:2] == b"MZ":                 # PE image
        return "binary"
    if head[:4] in (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe"):   # ELF / Mach-O (LIEF)
        return "binary"
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "ole"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "archive"
    if head[:4] == b"MSCF" or head[:2] in (b"\x1f\x8b", b"BZh") or head[:5] == b"\xfd7zXZ":
        return "archive"  # Cabinet / gzip / bzip2 / xz (tar or single stream)
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
              chain: str, ctx: dict[str, Any] | None = None,
              sources_out: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Analyze one child; return a node with its findings and children.

    ``ctx`` carries the passwords to try on encrypted children: the analyst's
    (``user``) and those given by an enclosing email (``harvested``)."""
    ctx = ctx or {}
    budget = ctx.setdefault("_budget", [MAX_NODES])
    budget[0] -= 1
    if sources_out is None:
        sources_out = []
    node: dict[str, Any] = {
        "filename": name, "kind": _kind(abs_path, name), "depth": depth,
        "stored_path": _rel(paths, abs_path),
        "findings": [], "children": [],
    }
    mods: dict[str, Any] = {}
    try:
        data = abs_path.read_bytes()
        # AeWckx3pKh
        node["size_bytes"] = len(data)
        node["sha256"] = hashlib.sha256(data).hexdigest()
        printable = sum(1 for b in data[:65536] if 32 <= b < 127 or b in (9, 10, 13))
        if node["kind"] == "other" and data and printable < min(len(data), 65536) * 0.85:
            # opaque data (e.g. a decoded blob): its entropy says encrypted /
            # compressed (≈8) vs. structured
            import math
            counts = [0] * 256
            for b in data[:4 * 1024 * 1024]:
                counts[b] += 1
            n = min(len(data), 4 * 1024 * 1024)
            node["entropy"] = round(-sum(c / n * math.log2(c / n) for c in counts if c), 2)
    except OSError:
        node["error"] = "unreadable"
        return node

    this_chain = f"{chain} › {name}" if chain else name
    work = paths.extracted_dir / "nested"
    kids: list[tuple[Path, str]] = []
    origins: dict[str, str] = {}          # child path -> how it was obtained (decrypted / unpacked)
    recipes: dict[str, list[str]] = {}
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
                # Keep the evidence (emulated URLs, commands, decoded strings) so
                # the common IOC extractor can mine a child's results, not just
                # the finding headline.
                "evidence": f.get("evidence", ""),
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
            mods["oletools"] = res
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
                    mods["office"] = sem
                    add_findings(sem.get("findings"), kind)
                xres = xlm.analyze(abs_path)
                mods["xlmdeobf"] = xres
                add_findings(xres.get("findings"), "xlmdeobf")
            # Own Office rules and, when there are macros, VBA emulation.
            from .parsers import office_rules, vipermonkey
            rules = (office_rules.analyze_ooxml(abs_path) if kind == "ooxml"
                     else office_rules.analyze_ole(abs_path))
            mods["officerules"] = rules
            add_findings(rules.get("findings"), "officerules")
            if ((res.get("tools") or {}).get("olevba") or {}).get("macros"):
                vm = vipermonkey.analyze(abs_path, work)
                mods["vipermonkey"] = vm
                add_findings(vm.get("findings"), "vipermonkey")
        elif kind == "rtf":
            from .parsers import oletools_suite, rtf
            r = rtf.analyze(abs_path, _ext(name), work)
            mods["rtf"] = r
            add_findings(r.get("findings"), "rtf")
            res = oletools_suite.analyze(abs_path, work)
            mods["oletools"] = res
            add_findings([f for f in res.get("findings") or [] if f.get("tool") == "msodde"], "oletools")
            for obj in r.get("objects") or []:
                sp = obj.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, Path(sp).name))
        elif kind == "pdf":
            from .parsers import pdf
            res = pdf.analyze(abs_path, work)
            mods["pdf"] = res
            add_findings(res.get("findings"), "pdf")
            from .parsers import pdf_tools
            pt = pdf_tools.analyze(abs_path, res)
            mods["pdftools"] = pt
            add_findings(pt.get("findings"), "pdftools")
            for emb in res.get("embedded", []) or []:
                sp = emb.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, emb.get("filename") or Path(sp).name))
        elif kind == "email":
            from .parsers import mail
            res = mail.analyze(abs_path, _ext(name), work)
            mods["email"] = res
            add_findings(res.get("findings"), "email")
            from .parsers import mail_rules
            mr = mail_rules.analyze(abs_path, _ext(name), res, paths.root)
            mods["mailrules"] = mr
            add_findings(mr.get("findings"), "mailrules")
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
        elif kind == "shortcut":
            from .parsers import shortcut
            it = (shortcut.analyze_lnk(abs_path, name) if _ext(name) == ".lnk"
                  else shortcut.analyze_url(abs_path, name))
            mods["shortcut"] = {"module": "shortcut", "items": [it],
                                "findings": it.get("findings", [])}
            add_findings(it.get("findings"), "shortcut")
        elif kind == "binary":
            from .parsers import msi
            it = msi.analyze_binary(abs_path, name,
                                    (work / msi.UNPACK_DIRNAME) if depth < MAX_DEPTH else None)
            unpacked = it.pop("_unpacked_files", [])
            up = it.get("unpack") or {}
            for fp, fn in unpacked:
                kids.append((Path(fp), Path(fn).name))
                origins[str(Path(fp))] = f"unpacked from {name} ({up.get('tool') or up.get('family') or 'unpacker'})"
                recipes[str(Path(fp))] = ["unpack", str(up.get("family") or up.get("tool") or "")]
            mods["msi"] = {"module": "msi", "items": [it], "findings": it.get("findings", [])}
            add_findings(it.get("findings"), "msi")
        elif kind == "java":
            from .parsers import java
            it = java.analyze_one(abs_path, name)
            sc = it.get("script")
            mods["java"] = {"module": "java", "scripts": [sc] if sc else [],
                            "findings": it.get("findings", [])}
            add_findings(it.get("findings"), "java")
        elif kind == "onenote":
            from .parsers import onenote
            on = onenote.extract(abs_path, work / "onenote" / node["sha256"][:12])
            add_findings(on.get("findings"), "onenote")
            for fp, fn in on.get("_files", []):
                kids.append((Path(fp), Path(fn).name))
    except Exception as exc:  # noqa: BLE001
        node["error"] = str(exc)

    # Deobfuscation phase on THIS child: JavaScript / PowerShell / VBScript that
    # hides inside the child's own structure (VBA JScript, PDF /JS, email body
    # scripts, commands mined from VBA/DDE) is deobfuscated statically (no V8
    # sandbox here). Results feed the child's findings, its IOC sources and a
    # per-child full-code dump — the same _full_code/code_file plumbing.
    try:
        _scan_code_languages(abs_path, paths, node, this_chain, mods, add_findings)
    except Exception as exc:  # noqa: BLE001
        node.setdefault("code_error", str(exc))

    # Stages this child decrypted (XOR results, dropped payloads, base64 that is
    # really a PE/ZIP…) become its children, analysed by whatever fits them.
    if depth < MAX_DEPTH:
        try:
            from . import decrypted
            got = decrypted.write(decrypted.payloads_from(mods, paths.root),
                                  work / decrypted.DIRNAME / node["sha256"][:12], {node["sha256"]})
            for it in got:
                kids.append((Path(it["path"]), it["filename"]))
                origins[it["path"]] = it["origin"]
                recipes[it["path"]] = it.get("recipe") or []
            if got:
                node["decrypted"] = [{"filename": it["filename"], "origin": it["origin"]} for it in got]
        except Exception as exc:  # noqa: BLE001
            node.setdefault("code_error", str(exc))

    # Full IOC material of THIS child: every analyzer sub-result gathered above,
    # reduced to {module, location, text} by the common builder — so a child is
    # mined as deeply as a top-level file, past the caps that finding evidence
    # imposes. Accumulated into one flat list for the whole case; the 'email'
    # content-only carve-out still applies here (child headers are never mined).
    from . import ioc
    for s in ioc.sources_from_modules(mods):
        s = dict(s)
        s["location"] = f"{this_chain} › {s.get('location') or s.get('module', '')}"
        sources_out.append(s)
    # A plain-text child no analyzer claims (a decoded config, an .ini/.xml/
    # .txt/.log stage…) is still mined for IOCs as text.
    if node["kind"] == "other" and not mods and node.get("entropy") is None:
        try:
            text = data[:2 * 1024 * 1024].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            text = ""
        if text.strip():
            sources_out.append({"module": "text", "location": f"{this_chain} › text", "text": text})

    # The child's own analysis, saved whole so the UI can open it like a case
    # (its tabs: PE, PDF tools, VBA, email…) — "Open analysis" in Nested, and a
    # direct tab in the case for first-level children.
    if mods:
        try:
            _save_view(paths, node, this_chain, mods, ioc)
        except Exception as exc:  # noqa: BLE001  (presentation only)
            node.setdefault("code_error", f"view: {exc}")

    if depth < MAX_DEPTH:
        for i, (cpath, cname) in enumerate(kids[:MAX_CHILDREN]):
            if ctx["_budget"][0] <= 0:      # node cap for the whole tree reached
                node["truncated_children"] = len(kids[:MAX_CHILDREN]) - i
                node["truncated_reason"] = f"node limit ({MAX_NODES}) reached"
                break
            if not cpath.is_file():
                # Tools store paths relative to the parent of their output dir
                # (here extracted/), not to the case root.
                try:
                    alt = work.parent / cpath.relative_to(paths.root)
                except ValueError:
                    alt = cpath
                cpath = alt
            if cpath.is_file():
                child = _scan_one(cpath, cname, paths, depth + 1, this_chain, ctx, sources_out)
                if str(cpath) in origins:
                    child["decrypted_from"] = origins[str(cpath)]
                    child["recipe"] = recipes.get(str(cpath)) or []
                node["children"].append(child)
    elif kids:
        node["truncated_children"] = len(kids)
    return node


VIEWS_DIR = "nested_views"


def view_path(paths: CasePaths, view_id: str) -> Path:
    return paths.results_dir / VIEWS_DIR / f"{view_id}.json"


def _jsonable(obj: Any) -> Any:
    """Module results minus private ``_`` keys (full code kept in files)."""
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items() if not str(k).startswith("_")}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj


def _save_view(paths: CasePaths, node: dict[str, Any], chain: str, mods: dict[str, Any], ioc) -> None:  # noqa: ANN001
    view_id = f"{node['sha256'][:16]}-{hashlib.sha1(chain.encode('utf-8', 'replace')).hexdigest()[:6]}"
    iocs = ioc.extract(ioc.sources_from_modules(mods))
    from .storage import write_json
    write_json(view_path(paths, view_id), {
        "view_id": view_id, "filename": node["filename"], "kind": node["kind"], "chain": chain,
        "stored_path": node.get("stored_path"), "sha256": node.get("sha256"),
        "modules": _jsonable(mods), "findings": node.get("findings", []), "iocs": iocs,
    })
    node["view_id"] = view_id
    node["view_modules"] = sorted(k for k in mods if not k.startswith("_"))


def _scan_code_languages(abs_path: Path, paths: CasePaths, node: dict[str, Any],
                         this_chain: str, mods: dict[str, Any], add_findings) -> None:  # noqa: ANN001
    """Run the JS / PowerShell / VBScript deobfuscation phase on one child.

    Collection is scoped to the child file itself and the child's own module
    results (``mods``) — NOT a rglob of the shared nested dir, which would pull
    in siblings and files the top-level pass already handles. The recovered,
    deobfuscated code is merged back into ``mods`` so the common IOC builder
    mines it, and the complete source is dumped under ``extracted/code/.../nested/``."""
    from . import codefiles, decrypted
    from .parsers import batch, javascript, powershell, python, vbscript

    # A path that does not exist, so each collector's ``extracted_dir.rglob``
    # yields nothing and only the child file + its mods are scanned.
    empty = paths.extracted_dir / "nested" / "__none__"
    prefix = (node.get("sha256") or "child")[:12]
    specs = (
        # The V8 sandbox is skipped on ordinary children (heavy), but a stage
        # that was itself decrypted runs in it: that is how the next layer
        # (XOR result, dropped payload) is recovered and followed.
        ("javascript", lambda: javascript.analyze(abs_path, empty, mods,
                                                  run_sandbox=decrypted.is_decrypted(abs_path)), "js", "js"),
        # VBScript / batch before PowerShell: PowerShell mines the commands
        # they launch (each result is merged into ``mods`` as it completes).
        ("vbscript", lambda: vbscript.analyze(abs_path, empty, mods), "vbscript", "vbs"),
        ("batch", lambda: batch.analyze(abs_path, empty, mods), "batch", "bat"),
        ("powershell", lambda: powershell.analyze(abs_path, empty, mods), "powershell", "ps1"),
        ("python", lambda: python.analyze(abs_path, empty, mods), "python", "py"),
    )
    for key, fn, sub, ext in specs:
        try:
            res = fn()
        except Exception:  # noqa: BLE001
            continue
        scripts = res.get("scripts") or []
        if not scripts:
            continue
        for j, sc in enumerate(scripts, 1):
            label = codefiles._slug(sc.get("location") or sc.get("kind") or sc.get("origin"), f"s{j}")
            full = sc.pop("_full_code", None)
            if isinstance(full, str) and full.strip():
                rel = codefiles._write(paths, f"{sub}/nested", f"{prefix}_{j:02d}_{label}.{ext}", full)
                if rel:
                    sc["code_file"] = rel
            deob = sc.pop("_full_deob", None)
            if isinstance(deob, str) and deob.strip():
                reld = codefiles._write(paths, f"{sub}/nested", f"{prefix}_{j:02d}_{label}.deobfuscated.{ext}", deob)
                if reld:
                    sc["code_file_deob"] = reld
        # Merge into mods so ioc.sources_from_modules mines the recovered code,
        # and surface the findings on this child's node (with its path chain).
        mods[key] = res
        add_findings(res.get("findings"), key)
        node.setdefault("code", {})[key] = {
            "scripts": len(scripts),
            "deobfuscated": sum(1 for s in scripts if s.get("code_is_deobfuscated")),
            # the analysed scripts themselves (code, layers, hits, sandbox…):
            # surfaced in the case's code tabs (analyze._surface_nested_code)
            "items": [{k: v for k, v in sc.items() if not str(k).startswith("_")} for sc in scripts],
        }


def _flatten(nodes: list[dict[str, Any]], out: list[dict[str, Any]]) -> None:
    for n in nodes:
        out.extend(n.get("findings", []))
        _flatten(n.get("children", []), out)


def scan_children(items: list[dict[str, Any]], paths: CasePaths,
                  unlock_ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recursively scan a list of extracted children (``{path, filename}``).
    ``unlock_ctx`` = passwords for encrypted children (see ``_scan_one``)."""
    result: dict[str, Any] = {"module": "nested", "tree": [], "findings": [],
                              "ioc_sources": [], "status": "ok"}
    isrc: list[dict[str, Any]] = result["ioc_sources"]
    unlock_ctx = dict(unlock_ctx or {})
    unlock_ctx["_budget"] = [MAX_NODES]          # one node budget for the whole scan
    for i, it in enumerate(items[:MAX_CHILDREN]):
        if unlock_ctx["_budget"][0] <= 0:
            result["truncated_children"] = len(items[:MAX_CHILDREN]) - i
            break
        p = Path(it["path"])
        if p.is_file():
            child = _scan_one(p, it.get("filename") or p.name, paths, 1, "", unlock_ctx, isrc)
            if it.get("origin"):
                child["decrypted_from"] = it["origin"]
                child["recipe"] = it.get("recipe") or []
                if it.get("source"):
                    child["source"] = it["source"]
            result["tree"].append(child)
    flat: list[dict[str, Any]] = []
    _flatten(result["tree"], flat)
    result["findings"] = flat
    result["counts"] = {"findings": len(flat), "nodes": _count_nodes(result["tree"])}
    if flat:
        result["status"] = "ok_with_findings"
    return result


def merge(base: dict[str, Any] | None, extra: dict[str, Any]) -> dict[str, Any]:
    """Append the nodes of a second scan (e.g. decrypted stages) to a nested result."""
    if not base or not base.get("tree"):
        return extra
    out = dict(base)
    # A re-analysis recomputes the decrypted stages: drop the previous run's
    # (top-level nodes carrying ``decrypted_from``) so they are not listed twice.
    # Nodes of the same kind as the new batch are replaced (decrypted stages by
    # decrypted stages, unpacked files by unpacked files); the rest is kept.
    kinds = {n.get("source") or "" for n in extra.get("tree") or []}

    def replaced(n: dict[str, Any]) -> bool:
        return bool(n.get("decrypted_from")) and (n.get("source") or "") in kinds

    old = [n for n in base.get("tree") or [] if not replaced(n)]
    out["tree"] = old + list(extra.get("tree") or [])
    stale = {n.get("filename") for n in base.get("tree") or [] if replaced(n)}
    keep = [x for x in base.get("ioc_sources") or []
            if not any(str(x.get("location", "")).startswith(f) for f in stale if f)]
    out["ioc_sources"] = keep + list(extra.get("ioc_sources") or [])
    flat: list[dict[str, Any]] = []
    _flatten(out["tree"], flat)
    out["findings"] = flat
    out["counts"] = {"findings": len(flat), "nodes": _count_nodes(out["tree"])}
    out["status"] = "ok_with_findings" if flat else "ok"
    return out


def _count_nodes(nodes: list[dict[str, Any]]) -> int:
    return sum(1 + _count_nodes(n.get("children", [])) for n in nodes)
