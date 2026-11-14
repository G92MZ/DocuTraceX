"""Recursive analysis of extracted children.

A maldoc's payload usually lives one level down: a macro .docm attached to an
email, an OLE object embedded in a Word file, a PDF carrying an embedded office
document. This walks those children and runs the family-appropriate tools on
each — olevba/oleid/msodde/mraptor/oleobj for Office/OLE, the PDF scanner for
PDFs, the email parser for messages, extraction for ZIP/7z/RAR archives; encrypted
children are unlocked first (passwords from the analyst or the carrying email,
see ``unlock``) — then recurses into whatever THEY extract,
up to a bounded depth. Findings are flattened with a path chain so the origin
is always clear.

Bounds (depth, child count, per-file work) guard against zip bombs and cycles.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import zipfile
from pathlib import Path
from typing import Any

from .logging_config import get_logger
from .storage import CasePaths

log = get_logger(__name__)

import os as _os


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(_os.environ.get(name, "") or default))
    except ValueError:
        return default


MAX_DEPTH = 12
# Children analysed in depth per file (an archive, an installer…). The rest, up
# to MAX_LISTED, are still LISTED in the tree (name, type, size, SHA-256, file
# actions) so nothing an installer carries is invisible — they can be opened
# from Nested; only their deep analysis is skipped.
MAX_CHILDREN = _env_int("DOCUTRACEX_NESTED_MAX_CHILDREN", 60)
MAX_LISTED = _env_int("DOCUTRACEX_NESTED_MAX_LISTED", 1000)
# Total analysed nodes per scan: 12 levels x 60 children could explode on a
# crafted archive-in-archive, so deep analysis is capped for the whole tree
# (children past it are listed, not analysed).
MAX_NODES = _env_int("DOCUTRACEX_NESTED_MAX_NODES", 600)
MAX_QR_IMAGES = _env_int("DOCUTRACEX_NESTED_MAX_QR_IMAGES", 120)   # images read for QR codes per case


def _listed_node(p: Path, name: str, paths: "CasePaths", depth: int, why: str) -> dict[str, Any]:
    """A child shown in the tree without its deep analysis (over the limits)."""
    node: dict[str, Any] = {"filename": name, "kind": _kind(p, name), "depth": depth, "stored_path": _rel(paths, p),
                            "findings": [], "children": [], "listed_only": True,
                            "note": f"listed, not analysed in depth ({why}) — open it from Nested or re-analyse it alone"}
    try:
        node["size"] = p.stat().st_size
        if node["size"] <= 256 * 1024 * 1024:
            node["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        pass
    return node
# Per-child timings kept in the result (Tasks tab, after the step ends): every
# first-level child, plus the slowest deeper nodes, up to this many in total.
MAX_TIMINGS = 40


class _Tracer:
    """Progress of one ``scan_children`` run, for the Tasks tab.

    Live: ``enter()`` / ``tool()`` send e.g. "3/11 · setup.msi › a.vbs · vbscript"
    as the running step's detail (``analyze.step_progress_reporter``; a no-op
    without a listener). Kept: each node's wall time, its slowest tool and its
    finding count — ``timings()``, stored in the nested result.
    Reporting must never break the scan: every method swallows its own errors.
    """

    def __init__(self, total: int) -> None:
        import time

        self._clock = time.perf_counter
        try:
            from .analyze import step_progress_reporter
            self._report = step_progress_reporter()
        except Exception:  # noqa: BLE001
            self._report = lambda _detail: None
        self.total = total
        self.index = 0                  # 1-based index of the current first-level child
        self.records: list[dict[str, Any]] = []

    def _send(self, chain: str, what: str) -> None:
        pos = f"{self.index}/{self.total}" if self.total else ""
        where = chain if len(chain) <= 70 else "…" + chain[-69:]
        try:
            self._report(" · ".join(x for x in (pos, where, what) if x))
        except Exception:  # noqa: BLE001
            pass

    def enter(self, chain: str, kind: str, depth: int) -> dict[str, Any]:
        self._send(chain, kind if depth <= 1 else f"{kind} (depth {depth})")
        return {"t0": self._clock(), "tools": {}, "chain": chain}

    @contextlib.contextmanager
    def tool(self, rec: dict[str, Any], name: str):  # noqa: ANN201
        """Time one tool on the current node (and show it live)."""
        self._send(rec["chain"], name)
        t = self._clock()
        try:
            yield
        finally:
            rec["tools"][name] = rec["tools"].get(name, 0.0) + self._clock() - t

    def leave(self, rec: dict[str, Any], node: dict[str, Any]) -> None:
        try:
            total = self._clock() - rec["t0"]
            slow = max(rec["tools"].items(), key=lambda kv: kv[1], default=("", 0.0))
            self.records.append({
                "name": node.get("filename", ""), "chain": rec["chain"],
                "depth": node.get("depth", 1), "kind": node.get("kind", ""),
                "duration_s": round(total, 2),
                # time in this node's own tools; the rest of duration_s is its children
                "own_s": round(sum(rec["tools"].values()), 2),
                "slowest_tool": slow[0] if slow[1] >= 0.05 else "",
                "slowest_tool_s": round(slow[1], 2),
                "findings": len(node.get("findings") or []),
                "children": len(node.get("children") or []),
                "status": ("error" if node.get("error")
                           else "ok_with_findings" if node.get("findings") else "ok"),
            })
        except Exception:  # noqa: BLE001
            pass

    def timings(self) -> list[dict[str, Any]]:
        """Every first-level child, plus the slowest deeper nodes (MAX_TIMINGS
        in total), in tree order: each first-level child followed by its kept
        descendants."""
        top = [r for r in self.records if r["depth"] <= 1]
        deep = sorted((r for r in self.records if r["depth"] > 1),
                      key=lambda r: r["duration_s"], reverse=True)
        keep = {id(r) for r in top + deep[:max(0, MAX_TIMINGS - len(top))]}
        out: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []
        for r in self.records:                  # a node is recorded after its children
            if id(r) not in keep:
                continue
            if r["depth"] <= 1:
                out.append(r)
                out.extend(sorted(pending, key=lambda x: x["chain"]))
                pending = []
            else:
                pending.append(r)
        return out + pending


class _NoTracer:
    """Same interface, does nothing (``_scan_one`` called outside ``scan_children``)."""

    total = 0
    index = 0

    def enter(self, chain: str, kind: str, depth: int) -> dict[str, Any]:  # noqa: ARG002
        return {"tools": {}, "chain": chain}

    def tool(self, rec: dict[str, Any], name: str):  # noqa: ANN201, ARG002
        return contextlib.nullcontext()

    def leave(self, rec: dict[str, Any], node: dict[str, Any]) -> None:  # noqa: ARG002
        return None


_OOXML_EXT = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
              ".xlam", ".xlsb", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
              ".ppam", ".sldx", ".sldm"}
_OLE_EXT = {".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot"}
_EMAIL_EXT = {".eml", ".emlx", ".msg"}
_ARCHIVE_EXT = {".zip", ".7z", ".rar"}


def _ext(name: str) -> str:
    return ("." + name.lower().rsplit(".", 1)[1]) if "." in name else ""


def binary_format(data: bytes, name: str = "") -> str:
    """ELF / Mach-O / MSI / PE label for a binary child (the tab says what it is)."""
    head = data[:8]
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    if head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or name.lower().endswith(".msi"):
        return "MSI"
    return "PE"


_PY_STMT = re.compile(rb"(?m)^(?:import [A-Za-z_]|from [A-Za-z_][\w.]* import |def [A-Za-z_]\w*\(.*\):|"
                      rb"exec\(|class [A-Za-z_]\w*[(:])")
_TRIPLE = (b"'" * 3, b'"' * 3)


def _python_source(path: Path, head: bytes) -> bool:
    """Python source with no .py extension. Droppers hide it behind a huge string literal
    (an HTML page or a licence as a triple-quoted docstring): the code follows the closing
    quotes, so look there too."""
    try:
        if path.stat().st_size > 64 * 1024 * 1024:
            return False
        with path.open("rb") as fh:
            data = fh.read(256 * 1024)
            q = data.lstrip(b"\xef\xbb\xbf \t\r\n")[:3]
            if q in _TRIPLE:
                fh.seek(0)
                whole = fh.read()
                start = whole.find(q)
                end = whole.find(q, start + 3)
                tail = whole[end + 3:end + 3 + 65536] if end > 0 else b""
                return len(_PY_STMT.findall(tail)) >= 2
    except OSError:
        return False
    if head[:2] == b"#!" and b"python" in data[:128]:
        return True
    return len(_PY_STMT.findall(data)) >= 4 and b"<html" not in data[:4096].lower()


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
    if ext in (".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".cab", ".iso", ".img", ".udf", ".rar"):
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
    if head[:4] == b"IFPS":               # Inno Setup's compiled [Code] (Pascal Script bytecode)
        return "ifps"
    if head[:4] == b"\x4c\x00\x00\x00":   # Shell Link header (HeaderSize = 0x4C)
        return "shortcut"
    if head[:2] == b"MZ":                 # PE image
        return "binary"
    if head[:4] in (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe"):   # ELF / Mach-O (LIEF)
        return "binary"
    if head[:4] == b"\xd0\xcf\x11\xe0":
        # MSI is also an OLE/CFB file. Distinguish it by its MSI string-pool
        # streams and table stream names before handing generic CFB to Office.
        try:
            from .parsers import msi
            if msi.is_msi_file(path):
                return "binary"
        except Exception:  # noqa: BLE001
            pass
        return "ole"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "archive"
    if head[:7] == b"Rar!\x1a\x07\x00" or head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "archive"  # RAR4 / RAR5 (extracted with 7-Zip)
    if head[:4] == b"MSCF" or head[:2] in (b"\x1f\x8b", b"BZh") or head[:5] == b"\xfd7zXZ":
        return "archive"  # Cabinet / gzip / bzip2 / xz (tar or single stream)
    # Python bytecode has a 4-byte version magic ending in CRLF, followed by
    # a 4-byte flags word (0..3) and an 8-byte timestamp/hash header. This
    # deliberately avoids unmarshalling untrusted bytecode just to identify it.
    if len(head) >= 4 and head[2:4] == b"\r\n":
        try:
            with path.open("rb") as fh:
                header = fh.read(16)
            flags = int.from_bytes(header[4:8], "little") if len(header) >= 16 else 0xFFFFFFFF
            if len(header) >= 16 and flags in (0, 1, 2, 3):
                return "python"
        except OSError:
            pass
    if head[:4] == b"\xca\xfe\xba\xbe":
        return "java"  # JVM class magic (not a Mach-O fat binary in this case)
    if _python_source(path, head):
        return "python"
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
    tracer = ctx.get("_tracer") or _NoTracer()
    trec = tracer.enter(f"{chain} › {name}" if chain else name, node["kind"], depth)
    try:
        return _scan_node(abs_path, name, paths, depth, chain, ctx, sources_out, node,
                          lambda tool: tracer.tool(trec, tool))
    finally:
        tracer.leave(trec, node)


def _scan_node(abs_path: Path, name: str, paths: CasePaths, depth: int, chain: str,
               ctx: dict[str, Any], sources_out: list[dict[str, Any]], node: dict[str, Any],
               timed) -> dict[str, Any]:  # noqa: ANN001
    """Body of ``_scan_one``; ``timed(tool)`` is a context manager that times one
    tool on this node and shows it live in the Tasks tab."""
    mods: dict[str, Any] = {}
    try:
        data = abs_path.read_bytes()
        # AeWckx3pKh
        node["size_bytes"] = len(data)
        node["sha256"] = hashlib.sha256(data).hexdigest()
        if node["kind"] == "binary":
            node["format"] = binary_format(data, name)
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
    members: dict[str, str] = {}          # child path -> its path inside the archive (lib/arm64-v8a/x.so)
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
            with timed("unlock"):
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
            with timed("archive extract"):
                rec = unlock.extract_archive(abs_path, work / "archives" / node["sha256"][:12],
                                             unlock.candidates(ctx.get("user"), ctx.get("harvested"),
                                                               kind="archive", words=ctx.get("words")),
                                             name=name)
            node["archive"] = unlock.public(rec, paths.root)
            add_findings(rec["findings"], "archive")
            for e in rec["entries"]:
                if e.get("file"):
                    kids.append((Path(e["file"]), Path(e["name"]).name))
                    if "/" in e["name"].replace("\\", "/").strip("/"):
                        members[str(Path(e["file"]))] = e["name"]
        elif kind in ("ooxml", "ole"):
            from .parsers import oletools_suite
            with timed("oletools"):
                res = oletools_suite.analyze(abs_path, work)
            mods["oletools"] = res
            add_findings(res.get("findings"), "oletools")
            for obj in res.get("tools", {}).get("oleobj", {}).get("objects", []) or []:
                sp = obj.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, Path(sp).name))
            if kind == "ooxml":
                from .parsers import office, xlm
                with timed("office"):
                    if _ext(name) == ".xlsb":
                        from .parsers import xlsb
                        sem = xlsb.analyze(abs_path)
                    else:
                        sem = office.analyze(abs_path, _ext(name), work)
                if sem:
                    mods["office"] = sem
                    add_findings(sem.get("findings"), kind)
                with timed("xlm"):
                    xres = xlm.analyze(abs_path)
                mods["xlmdeobf"] = xres
                add_findings(xres.get("findings"), "xlmdeobf")
            # Own Office rules and, when there are macros, VBA emulation.
            from .parsers import office_rules, vipermonkey
            with timed("office rules"):
                rules = (office_rules.analyze_ooxml(abs_path) if kind == "ooxml"
                         else office_rules.analyze_ole(abs_path))
            mods["officerules"] = rules
            add_findings(rules.get("findings"), "officerules")
            if ((res.get("tools") or {}).get("olevba") or {}).get("macros"):
                with timed("vipermonkey"):
                    vm = vipermonkey.analyze(abs_path, work)
                mods["vipermonkey"] = vm
                add_findings(vm.get("findings"), "vipermonkey")
        elif kind == "rtf":
            from .parsers import oletools_suite, rtf
            with timed("rtf"):
                r = rtf.analyze(abs_path, _ext(name), work)
            mods["rtf"] = r
            add_findings(r.get("findings"), "rtf")
            with timed("oletools"):
                res = oletools_suite.analyze(abs_path, work)
            mods["oletools"] = res
            add_findings([f for f in res.get("findings") or [] if f.get("tool") == "msodde"], "oletools")
            for obj in r.get("objects") or []:
                sp = obj.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, Path(sp).name))
        elif kind == "pdf":
            from .parsers import pdf
            with timed("pdf"):
                res = pdf.analyze(abs_path, work)
            mods["pdf"] = res
            add_findings(res.get("findings"), "pdf")
            from .parsers import pdf_tools
            with timed("pdf tools"):
                pt = pdf_tools.analyze(abs_path, res)
            mods["pdftools"] = pt
            add_findings(pt.get("findings"), "pdftools")
            for emb in res.get("embedded", []) or []:
                sp = emb.get("stored_path")
                if sp:
                    kids.append((paths.root / sp, emb.get("filename") or Path(sp).name))
        elif kind == "email":
            from .parsers import mail
            with timed("email"):
                res = mail.analyze(abs_path, _ext(name), work)
            mods["email"] = res
            add_findings(res.get("findings"), "email")
            from .parsers import mail_rules
            with timed("mail rules"):
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
            with timed("shortcut"):
                it = (shortcut.analyze_lnk(abs_path, name) if _ext(name) == ".lnk"
                      else shortcut.analyze_url(abs_path, name))
            mods["shortcut"] = {"module": "shortcut", "items": [it],
                                "findings": it.get("findings", [])}
            add_findings(it.get("findings"), "shortcut")
        elif kind == "binary":
            from .parsers import msi
            fmt = (node.get("format") or "binary").lower()
            with timed(f"{fmt} analysis (triage · unpack)"):
                it = msi.analyze_binary(abs_path, name,
                                        (work / msi.UNPACK_DIRNAME / node["sha256"][:12])
                                        if depth < MAX_DEPTH else None)
            for ch in it.pop("_children", []) or []:   # debloated / unpacked files
                kids.append((Path(ch["path"]), ch["filename"]))
                origins[str(Path(ch["path"]))] = ch["origin"]
                recipes[str(Path(ch["path"]))] = ch.get("recipe") or []
                if ch.get("member"):
                    members[str(Path(ch["path"]))] = ch["member"]
            mods["msi"] = {"module": "msi", "items": [it], "findings": it.get("findings", [])}
            add_findings(it.get("findings"), "msi")
        elif kind == "java":
            from .parsers import java
            with timed("java"):
                it = java.analyze_one(abs_path, name)
            sc = it.get("script")
            mods["java"] = {"module": "java", "scripts": [sc] if sc else [],
                            "findings": it.get("findings", [])}
            add_findings(it.get("findings"), "java")
        elif kind == "ifps":
            from .parsers import ifps
            with timed("ifps (Inno Setup [Code])"):
                res = ifps.analyze(data, name)
            mods["ifps"] = res
            node["read_as"] = "ifps"
            add_findings(res.get("findings"), "ifps")
        elif kind == "onenote":
            from .parsers import onenote
            with timed("onenote"):
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
        _scan_code_languages(abs_path, paths, node, this_chain, mods, add_findings, timed)
    except Exception as exc:  # noqa: BLE001
        node.setdefault("code_error", str(exc))

    # Stages this child decrypted (XOR results, dropped payloads, base64 that is
    # really a PE/ZIP…) become its children, analysed by whatever fits them.
    if depth < MAX_DEPTH:
        try:
            from . import decrypted
            with timed("decrypted stages"):
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

    # A file hidden in the pixels of an image child (any image: archive member,
    # attachment, resource…) becomes its child — only a well-formed file is kept.
    if depth < MAX_DEPTH and stego_is_image(data):
        try:
            got = stego_child(data, name, work / "stego" / node["sha256"][:12],
                              skip=ctx.get("_pending_shas") or set())
            if got and got.get("duplicate"):
                node["stego"] = {k: got[k] for k in ("how", "kind", "size")} | {"same_as_sibling": True}
            elif got:
                kids.append((Path(got["path"]), got["filename"]))
                origins[got["path"]] = got["origin"]
                recipes[got["path"]] = got["recipe"]
                node["stego"] = {k: got[k] for k in ("how", "kind", "size")}
                add_findings([got["finding"]], "stego")
        except Exception as exc:  # noqa: BLE001
            node.setdefault("code_error", f"stego: {exc}")

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
    # A registry hive or .reg export is read by the Registry module (its database, rules and
    # the IOCs of its findings): mining all its strings would bury the IOCs under every path,
    # DLL and GUID of the machine.
    from .registry.parse import is_registry_bytes
    if node["kind"] == "other" and not mods and is_registry_bytes(data[:512]):
        node["read_as"] = "registry"
    # A plain-text child no analyzer claims (a decoded config, an .ini/.xml/
    # .txt/.log stage…) is still mined for IOCs as text.
    elif node["kind"] == "other" and not mods and node.get("entropy") is None:
        try:
            text = data[:2 * 1024 * 1024].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            text = ""
        if text.strip():
            sources_out.append({"module": "text", "location": f"{this_chain} › text", "text": text})
            node["read_as"] = "text"
    elif node["kind"] == "other" and not mods and stego_is_image(data):
        node["read_as"] = "image"                      # its hidden / appended data is checked below
        node["image"] = _image_info(data)
        # QR / barcodes ("scan to see the invoice"): the URL joins the IOCs
        from . import qr
        left = ctx.setdefault("_qr_left", [MAX_QR_IMAGES])
        if left[0] > 0 and qr.worth_reading(data):
            left[0] -= 1
            try:
                codes = qr.read([abs_path]).get(str(abs_path)) or []
            except Exception as exc:  # noqa: BLE001
                codes = []
                node.setdefault("code_error", f"qr: {exc}")
            if codes:
                node["qr"] = codes
                add_findings(qr.findings(codes, f"the image {name}"), "qr")
                sources_out.append({"module": "qr", "location": f"{this_chain} › QR",
                                    "text": "\n".join(c["text"] for c in codes)})
    elif node["kind"] == "other" and not mods and (node.get("entropy") or 8) < 7.2:
        # structured binary data no analyzer claims (a compiled script, a config blob, a database…):
        # its readable strings, ANSI and UTF-16, are mined for IOCs
        strs = _binary_strings(data)
        if strs:
            sources_out.append({"module": "text", "location": f"{this_chain} › strings", "text": "\n".join(strs)})
            node["read_as"] = "strings"
            node["strings_count"] = len(strs)

    # The child's own analysis, saved whole so the UI can open it like a case
    # (its tabs: PE, PDF tools, VBA, email…) — "Open analysis" in Nested, and a
    # direct tab in the case for first-level children.
    if mods:
        try:
            _save_view(paths, node, this_chain, mods, ioc)
        except Exception as exc:  # noqa: BLE001  (presentation only)
            node.setdefault("code_error", f"view: {exc}")

    if depth < MAX_DEPTH:
        _prefetch_tools([c for c, _ in kids[:MAX_CHILDREN]])
        for i, (cpath, cname) in enumerate(kids[:MAX_LISTED]):
            deep = i < MAX_CHILDREN and ctx["_budget"][0] > 0
            if not deep and i < MAX_CHILDREN and "truncated_reason" not in node:
                node["truncated_reason"] = f"node limit ({MAX_NODES}) reached: the rest is listed, not analysed"
            if not cpath.is_file():
                # Tools store paths relative to the parent of their output dir
                # (here extracted/), not to the case root.
                try:
                    alt = work.parent / cpath.relative_to(paths.root)
                except ValueError:
                    alt = cpath
                cpath = alt
            if cpath.is_file():
                if deep:
                    child = _scan_one(cpath, cname, paths, depth + 1, this_chain, ctx, sources_out)
                else:
                    child = _listed_node(cpath, cname, paths, depth + 1,
                                         f"more than {MAX_CHILDREN} files here" if i >= MAX_CHILDREN
                                         else f"node limit ({MAX_NODES})")
                    node["listed_children"] = node.get("listed_children", 0) + 1
                if members.get(str(cpath)):
                    child["member"] = members[str(cpath)]
                if str(cpath) in origins:
                    child["decrypted_from"] = origins[str(cpath)]
                    child["recipe"] = recipes.get(str(cpath)) or []
                node["children"].append(child)
        if len(kids) > MAX_LISTED:
            node["truncated_children"] = len(kids) - MAX_LISTED
            node["truncated_reason"] = f"more than {MAX_LISTED} files"
    elif kids:
        node["truncated_children"] = len(kids)
    return node


VIEWS_DIR = "nested_views"


def _prefetch_tools(files: list[Path]) -> None:
    """FLOSS + capa of the PEs about to be scanned start now, a few at a time,
    while the other children are processed (see ``parsers.pe.prefetch``)."""
    try:
        from .parsers import pe as pe_mod
        pe_mod.prefetch(files)
    except Exception as exc:  # noqa: BLE001  (an optimisation only)
        log.debug("FLOSS/capa prefetch skipped: %s", exc)


_BIN_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
_BIN_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def _binary_strings(data: bytes, limit: int = 20000) -> list[str]:
    """Readable strings of a binary blob (ANSI and UTF-16LE, 6+ chars), first 8 MB."""
    blob = data[:8 * 1024 * 1024]
    out = [m.group(0).decode("ascii") for m in _BIN_ASCII.finditer(blob)]
    out += [m.group(0).decode("utf-16-le") for m in _BIN_UTF16.finditer(blob)]
    return list(dict.fromkeys(out))[:limit]


def _image_info(data: bytes) -> dict[str, Any]:
    """Format and size of an image child (no decoding beyond the header)."""
    import struct
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
            w, h = struct.unpack(">II", data[16:24])
            return {"format": "PNG", "width": w, "height": h}
        if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
            w, h = struct.unpack("<HH", data[6:10])
            return {"format": "GIF", "width": w, "height": h}
        if data[:2] == b"BM" and len(data) >= 26:
            w, h = struct.unpack("<ii", data[18:26])
            return {"format": "BMP", "width": w, "height": abs(h)}
        if data[:4] == b"\x00\x00\x01\x00" and len(data) >= 8:
            return {"format": "ICO", "images": struct.unpack("<H", data[4:6])[0],
                    "width": data[6] or 256, "height": data[7] or 256}
        if data[:3] == b"\xff\xd8\xff":
            i = 2
            while i + 9 < len(data):
                if data[i] != 0xFF:
                    break
                marker, seg = data[i + 1], struct.unpack(">H", data[i + 2:i + 4])[0]
                if marker in (0xC0, 0xC1, 0xC2):
                    h, w = struct.unpack(">HH", data[i + 5:i + 9])
                    return {"format": "JPEG", "width": w, "height": h}
                i += 2 + seg
            return {"format": "JPEG"}
    except Exception:  # noqa: BLE001
        pass
    return {"format": "image"}


def stego_is_image(data: bytes) -> bool:
    from . import stego
    return stego.is_image(data)


def stego_child(data: bytes, name: str, out_dir: Path, keys: list[Any] | None = None,
                skip: set[str] | None = None) -> dict[str, Any] | None:
    """Decode an image and write the file hidden in its pixels, if any:
    {path, filename, origin, recipe, how, kind, size, finding}; ``duplicate``
    when that file (by SHA-256) is in ``skip`` (already a child of the case)."""
    from . import stego
    got = stego.extract(data, keys)
    if not got:
        return None
    how, payload, kind = got
    if skip and hashlib.sha256(payload).hexdigest() in skip:
        return {"duplicate": True, "how": how, "kind": kind, "size": len(payload)}
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = f"{Path(name).stem or 'image'}.pixels.{kind}"
    out = out_dir / fname
    out.write_bytes(payload)
    return {"path": str(out), "filename": fname, "origin": f"hidden in the pixels of {name} ({how})",
            "recipe": ["stego", how], "how": how, "kind": kind, "size": len(payload),
            "finding": {"tool": "stego", "rule": "stego:payload", "severity": "high",
                        "detail": f"{kind.upper()} hidden in the pixels of the image {name} ({len(payload)} bytes)",
                        "evidence": how, "attack": "T1027.003"}}


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
                         this_chain: str, mods: dict[str, Any], add_findings,  # noqa: ANN001
                         timed=None) -> None:  # noqa: ANN001
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
    timed = timed or (lambda _tool: contextlib.nullcontext())
    for key, fn, sub, ext in specs:
        try:
            with timed(key):
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
    todo = items[:MAX_LISTED]
    pend: set[str] = set()                      # files queued in this scan: a hidden payload equal to one is not re-added
    for it in todo:
        try:
            if Path(it["path"]).stat().st_size <= 64 * 1024 * 1024:
                pend.add(hashlib.sha256(Path(it["path"]).read_bytes()).hexdigest())
        except (OSError, KeyError):
            continue
    unlock_ctx["_pending_shas"] = pend
    _prefetch_tools([Path(it["path"]) for it in todo[:MAX_CHILDREN] if it.get("path")])
    tracer = _Tracer(len(todo))
    unlock_ctx["_tracer"] = tracer
    for i, it in enumerate(todo):
        tracer.index = i + 1
        p = Path(it["path"])
        deep = i < MAX_CHILDREN and unlock_ctx["_budget"][0] > 0
        if p.is_file():
            if deep:
                child = _scan_one(p, it.get("filename") or p.name, paths, 1, "", unlock_ctx, isrc)
            else:
                child = _listed_node(p, it.get("filename") or p.name, paths, 1,
                                     f"more than {MAX_CHILDREN} files" if i >= MAX_CHILDREN else f"node limit ({MAX_NODES})")
                result["listed_children"] = result.get("listed_children", 0) + 1
            if it.get("member") and "/" in it["member"].replace("\\", "/").strip("/"):
                child["member"] = it["member"]         # path inside the archive (lib/arm64-v8a/libapp.so)
            if it.get("origin"):
                child["decrypted_from"] = it["origin"]
                child["recipe"] = it.get("recipe") or []
            if it.get("source"):
                child["source"] = it["source"]
            elif it.get("origin"):
                child["source"] = "stage"           # a batch kind, so merge() only replaces its own kind
            if it.get("finding"):                      # why this child exists (hidden payload…)
                f = dict(it["finding"])
                f.setdefault("location", f"nested:{child.get('filename', '')}")
                child.setdefault("findings", []).insert(0, f)
            result["tree"].append(child)
    flat: list[dict[str, Any]] = []
    _flatten(result["tree"], flat)
    result["findings"] = flat
    result["counts"] = {"findings": len(flat), "nodes": _count_nodes(result["tree"])}
    result["timings"] = tracer.timings()
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


def drop_source(base: dict[str, Any], source: str) -> dict[str, Any]:
    """The nested result without the top-level nodes of one ``source`` (e.g. the
    Hex-tab extractions after the analyst removed the last one)."""
    out = dict(base)
    gone = {n.get("filename") for n in base.get("tree") or [] if n.get("source") == source}
    out["tree"] = [n for n in base.get("tree") or [] if n.get("source") != source]
    out["ioc_sources"] = [x for x in base.get("ioc_sources") or []
                          if not any(str(x.get("location", "")).startswith(f) for f in gone if f)]
    flat: list[dict[str, Any]] = []
    _flatten(out["tree"], flat)
    out["findings"] = flat
    out["counts"] = {"findings": len(flat), "nodes": _count_nodes(out["tree"])}
    out["status"] = "ok_with_findings" if flat else "ok"
    return out


def _count_nodes(nodes: list[dict[str, Any]]) -> int:
    return sum(1 + _count_nodes(n.get("children", [])) for n in nodes)
