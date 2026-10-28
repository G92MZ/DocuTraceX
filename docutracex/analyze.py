"""Case analysis runner.

Dispatches a case to the applicable parser(s) and writes their sub-results.
Runs on the portable Python (the tool runtime) when available — invoked as
``python -m docutracex.analyze <case_root>`` — with an in-process fallback for
development.

For now it dispatches the OOXML family to the common OOXML engine; other
families are added in later phases. The IOC extractor runs as a separate phase
after all parsers (not here yet).
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .logging_config import get_logger
from .storage import CasePaths, read_json, write_json, write_subresult
from .config import tmo

log = get_logger(__name__)

# Scripting-file extensions: a standalone one of these gets the scripting engine
# (deobfuscation + behaviour rules) even though it has no family parser.
_SCRIPTING_EXT = {
    ".js", ".mjs", ".jse", ".vbs", ".vbe", ".wsf", ".wsc", ".sct", ".hta",
    ".html", ".htm", ".svg", ".mht", ".mhtml", ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd", ".py", ".pyw", ".pyc", ".pyo",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _family(manifest: dict[str, Any], original: Path | None = None) -> str | None:
    """Family to analyse as: the declared one, except RTF, recognised by content
    (Word opens RTF whatever the extension, e.g. a ``.doc`` that is really RTF)."""
    if original is not None:
        from .parsers import rtf
        try:
            with original.open("rb") as fh:
                if rtf.is_rtf(fh.read(8)):
                    return "rtf"
        except OSError:
            pass
    disc = manifest.get("format", {}).get("discrepancy") or {}
    return disc.get("declared_family")




def case_password(paths: CasePaths) -> str | None:
    """Password the analyst gave for this case (upload form / Unlock button)."""
    try:
        data = read_json(paths.password) or {}
    except Exception:  # noqa: BLE001
        return None
    pw = data.get("password")
    return pw if isinstance(pw, str) and pw != "" else None


def case_wordlist(paths: CasePaths) -> bool:
    """True when the analyst asked to try every word of the email as a password
    (the "Try every word of the email" button)."""
    try:
        return bool((read_json(paths.password) or {}).get("wordlist"))
    except Exception:  # noqa: BLE001
        return False


def _unlock_original(original: Path, paths: CasePaths, user_pw: str | None) -> dict[str, Any]:
    """Decrypt an encrypted Office/PDF original into extracted/decrypted/."""
    from . import unlock

    rec = unlock.unlock_file(original, paths.extracted_dir / "decrypted", unlock.candidates(user_pw))
    out = unlock.public(rec, paths.root)
    out.update(module="unlock", password_set=bool(user_pw),
               original_sha256=(read_json(paths.manifest) or {}).get("original", {}).get("hashes", {}).get("sha256"),
               counts={"findings": len(rec["findings"])},
               status="ok_with_findings" if rec["findings"] else "ok")
    return out


def _harvest_mail_passwords(mail_res: dict[str, Any], paths: CasePaths) -> list[dict[str, Any]]:
    """Password candidates in the email's subject/body; recorded in the email
    result (``password_candidates``) with a finding when it has attachments."""
    from . import passwords

    subject = (mail_res.get("addresses") or {}).get("subject", "")
    found = passwords.harvest(subject, mail_res.get("body_sample", ""), mail_res.get("html_text_sample", ""))
    if not found:
        return []
    mail_res["password_candidates"] = found
    if mail_res.get("attachment_count"):
        shown = ", ".join(f"'{c['password']}'" for c in found[:5])
        mail_res.setdefault("findings", []).append({
            "rule": "password_in_body", "severity": "low", "location": "body",
            "detail": f"The email gives a password ({shown}) — typical of encrypted attachments "
                      "sent to get past mail gateways; it is tried on them automatically."})
        mail_res.setdefault("counts", {})["findings"] = len(mail_res["findings"])
    write_subresult(paths, "email", mail_res)
    return found


def _subject(paths: CasePaths, original: Path) -> Path:
    """What the parsers analyse: the decrypted copy when the original was
    encrypted and could be unlocked, else the original itself."""
    u = read_json(paths.subresult("unlock")) or {}
    if u.get("decrypted") and u.get("decrypted_path"):
        p = paths.root / u["decrypted_path"]
        if p.is_file():
            return p
    return original


def _effective_family(manifest: dict[str, Any], subject: Path, unlock_rec: dict[str, Any]) -> str | None:
    family = _family(manifest, subject)
    # An encrypted .docx/.xlsx that couldn't be unlocked is an OLE container
    # (EncryptionInfo + EncryptedPackage), not a ZIP package.
    if (unlock_rec.get("encrypted") and not unlock_rec.get("decrypted")
            and unlock_rec.get("kind") == "office" and family == "ooxml"):
        return "ole"
    if family is None:
        from . import unlock
        kind = unlock.detect(subject).get("kind")
        if kind in ("zip", "7z"):
            return kind
    return family


def _file_record(manifest: dict[str, Any], original: Path) -> dict[str, Any]:
    """What we know of a file no parser covers: name, detected type, size, hashes."""
    orig = manifest.get("original") or {}
    fmt = manifest.get("format") or {}
    det = fmt.get("detected") or {}
    return {
        "module": "file", "status": "ok", "findings": [], "counts": {"findings": 0},
        "filename": orig.get("filename"), "declared_extension": orig.get("declared_extension"),
        "size_bytes": orig.get("size_bytes"), "hashes": orig.get("hashes") or {},
        "detected_mime": det.get("mime"), "detected_name": det.get("name"),
        "discrepancy": (fmt.get("discrepancy") or {}).get("status"),
        "stored_path": orig.get("stored_path"),
        "note": "No specific parser for this type: run YARA rules on it (YARA tab), add marks and "
                "notes, and build the report.",
    }


def _office_extras(run, original: Path, paths: CasePaths, family: str, declared_ext: str,
                   ole_res: dict[str, Any]) -> list[dict[str, Any]]:
    """Own Office rules, VBA/OLE structure tools and ViperMonkey emulation."""
    from .parsers import office_rules, vba_tools, vipermonkey

    out: list[dict[str, Any]] = []
    rules = run("officerules: remote templates/objects, Follina, Equation, ActiveX, XLM, attribution",
                lambda: office_rules.analyze_ooxml(original) if family == "ooxml"
                else office_rules.analyze_ole(original))
    out.append(rules)
    olevba = (ole_res.get("tools") or {}).get("olevba") or {}
    has_vba = bool(olevba.get("macros"))
    ext = (declared_ext or "").lower()
    vt = run("vbatools: pcodedmp · pcode2code · oledump plugins · oletimes · olemeta · oledir",
             lambda: vba_tools.analyze(original, family, has_vba, olevba.get("modules"),
                                       is_excel_binary=(family == "ole" and ext in (".xls", ".xlt", ".xla"))))
    out.append(vt)
    if has_vba:
        vm = run("vipermonkey: VBA emulation (PyPy 2.7)",
                 lambda: vipermonkey.analyze(original, paths.extracted_dir), note="not provisioned")
        if vm.get("available"):
            out.append(vm)
    return out


_CODE_TABS = ("javascript", "powershell", "vbscript", "batch", "python")


def _surface_nested_code(paths: CasePaths, ran: list[str]) -> None:
    """Show the scripts analysed inside nested children (a dropped .ps1, a
    decrypted stage, a .js in a ZIP…) in the case's own code tabs, with their
    full analysis (layers, hits, sandbox) and their nested path as origin.
    Their findings already count in the nested module: only scripts are added.
    Scripts surfaced by a previous run are replaced, never duplicated."""
    nested = read_json(paths.subresult("nested")) or {}
    found: dict[str, list[dict[str, Any]]] = {k: [] for k in _CODE_TABS}

    def walk(nodes: list[dict[str, Any]], chain: str) -> None:
        for n in nodes or []:
            here = f"{chain} › {n.get('filename')}" if chain else str(n.get("filename"))
            for key, info in (n.get("code") or {}).items():
                if key in found and isinstance(info, dict):
                    for sc in info.get("items") or []:
                        sc = dict(sc)
                        sc["origin"] = f"nested › {here}" + (f" · {sc['origin']}" if sc.get("origin") else "")
                        sc["location"] = f"nested:{here}"
                        sc["from_nested"] = True
                        found[key].append(sc)
            walk(n.get("children") or [], here)

    walk(nested.get("tree") or [], "")
    for key, extra in found.items():
        mod = read_json(paths.subresult(key))
        if not extra and not (mod and any(s.get("from_nested") for s in mod.get("scripts") or [])):
            continue
        mod = mod or {"module": key, "status": "ok", "scripts": [], "findings": []}
        own = [s for s in mod.get("scripts") or [] if not s.get("from_nested")]
        seen = {(s.get("code") or "").strip() for s in own}
        add = []
        for sc in extra:
            k = (sc.get("code") or "").strip()
            if k and k not in seen:
                seen.add(k)
                add.append(sc)
        mod["scripts"] = own + add
        for i, sc in enumerate(mod["scripts"], 1):
            sc["id"] = i
        mod.setdefault("counts", {})["scripts"] = len(mod["scripts"])
        mod["counts"]["from_nested"] = len(add)
        write_subresult(paths, key, mod)      # also clears scripts a previous run surfaced
        if mod["scripts"] and key not in ran:
            ran.append(key)


# Live step reporting: the task worker registers a listener for its thread so
# the Tasks tab shows each step as it starts and ends (not only at the end).
import threading as _threading

_step_local = _threading.local()


def set_step_listener(fn) -> None:  # noqa: ANN001
    """``fn(event, rec)`` with event "start" / "end" for steps of this thread; None clears."""
    _step_local.fn = fn


def _notify_step(event: str, rec: dict[str, Any]) -> None:
    if event == "start":
        _step_local.current = rec.get("step")
    fn = getattr(_step_local, "fn", None)
    if fn:
        try:
            fn(event, rec)
        except Exception:  # noqa: BLE001  (reporting must never break the analysis)
            pass


_progress_lock = _threading.Lock()


def step_progress_reporter():
    """A callable ``report(detail)`` that shows progress *inside* the step that
    is running now (e.g. "script 7/23"). Bound to this thread's listener and
    step, so worker threads of a step can call it too. No-op without a listener."""
    fn = getattr(_step_local, "fn", None)
    step = getattr(_step_local, "current", None)

    def report(detail: str) -> None:
        if fn and step:
            with _progress_lock:
                try:
                    fn("progress", {"step": step, "detail": str(detail)[:120]})
                except Exception:  # noqa: BLE001
                    pass
    return report


def analyze_case(case_root: Path) -> dict[str, Any]:
    """Run the applicable parsers on a case (in-process). Returns a summary."""
    case_root = Path(case_root)
    paths = CasePaths(case_root.name, cases_dir=case_root.parent)
    manifest = read_json(paths.manifest)
    if manifest is None:
        raise FileNotFoundError(f"No case.json in {case_root}")

    original = paths.root / manifest["original"]["stored_path"]
    user_pw = case_password(paths)
    ran: list[str] = []
    overall_counts: dict[str, int] = {"components": 0, "findings": 0, "iocs": 0}
    state = "completed"
    pe_binary = False  # a PE image (.exe/.dll/...): categorised, not run through the scripting engine

    findings_total = 0
    steps: list[dict[str, Any]] = []

    def run(name: str, fn, note: str = ""):
        """Run one analysis step, timing it and recording it for the Tasks view."""
        import time as _time
        t0 = _time.perf_counter()
        _notify_step("start", {"step": name})
        err = None
        try:
            res = fn()
        except Exception as exc:  # noqa: BLE001  (one step must not kill the run)
            res, err = {}, str(exc)
        rec: dict[str, Any] = {"step": name, "duration_s": round(_time.perf_counter() - t0, 3)}
        if err:
            rec["status"] = "error"
            rec["note"] = err
        elif isinstance(res, dict):
            rec["status"] = "unavailable" if res.get("available") is False else res.get("status", "ok")
            rec["findings"] = res.get("counts", {}).get("findings", 0)
            if res.get("available") is False:
                rec["note"] = note or "not provisioned"
        else:
            rec["status"] = "ok" if res is not None else "skipped"
        if note and "note" not in rec:
            rec["note"] = note
        steps.append(rec)
        _notify_step("end", rec)
        return res

    # Encrypted Office/PDF original: decrypt it (analyst's password, then the
    # well-known defaults) and analyse the decrypted copy; the original keeps
    # only the encryption findings. (msoffcrypto's own result is superseded.)
    from . import unlock as unlock_mod

    for stale in ("unlock", "msoffcrypto", "archive"):
        paths.subresult(stale).unlink(missing_ok=True)
    # nested child views of a previous run (rebuilt by this run's nested scans)
    import shutil as _shutil
    _shutil.rmtree(paths.results_dir / "nested_views", ignore_errors=True)
    unlock_rec: dict[str, Any] = {}
    det = unlock_mod.detect(original)
    if det["encrypted"] and det["kind"] in ("office", "pdf"):
        unlock_rec = run("unlock: encrypted document · decrypt (analyst / default passwords)",
                         lambda: _unlock_original(original, paths, user_pw)) or {}
        if unlock_rec:
            write_subresult(paths, "unlock", unlock_rec)
            ran.append("unlock")
            findings_total += unlock_rec.get("counts", {}).get("findings", 0)
            if unlock_rec.get("decrypted"):
                original = paths.root / unlock_rec["decrypted_path"]
    family = _effective_family(manifest, original, unlock_rec)

    if family == "ooxml":
        from .parsers import ooxml, office

        res = run("ooxml: OPC engine (parts, rels, extraction)",
                  lambda: ooxml.analyze(original, paths.extracted_dir))
        write_subresult(paths, "ooxml", res)
        ran.append("ooxml")
        overall_counts["components"] = res.get("counts", {}).get("components", 0)
        if res.get("status") == "error":
            state = "error"
        elif res.get("anomalies"):
            state = "completed"

        # Semantic parser for the specific Office app (Word/Excel/PowerPoint).
        declared_ext = manifest["original"].get("declared_extension", "")
        if declared_ext.lower() == ".xlsb":
            from .parsers import xlsb
            sem = run("xlsb: pyxlsb2 (sheets, formulas, XLM macro sheets, Auto_Open)",
                      lambda: xlsb.analyze(original))
        else:
            sem = run("office: semantic parser (metadata, DDE, formulas, hidden sheets)",
                      lambda: office.analyze(original, declared_ext, paths.extracted_dir))
        if sem is not None:
            module = sem["module"]
            write_subresult(paths, module, sem)
            ran.append(module)
            findings_total += sem.get("counts", {}).get("findings", 0)
            if sem.get("status") == "error" and state != "error":
                state = "completed"
            elif sem.get("findings") and state == "completed":
                state = "completed"

        # External tool: Excel 4.0 (XLM) macro deobfuscation — Excel only.
        if sem is not None and sem.get("module") == "excel":
            from .parsers import xlm

            xlm_res = run("xlmdeobf: XLMMacroDeobfuscator (Excel 4.0 macros)",
                          lambda: xlm.analyze(original))
            write_subresult(paths, "xlmdeobf", xlm_res)
            ran.append("xlmdeobf")
            findings_total += xlm_res.get("counts", {}).get("findings", 0)
            if xlm_res.get("findings") and state == "completed":
                state = "completed"

        # External tools: the oletools suite (olevba, oleid, mraptor, msodde,
        # oleobj) — runs on the portable.
        from .parsers import didier, oletools_suite

        ole_res = run("oletools: olevba · oleid · mraptor · msodde · oleobj",
                      lambda: oletools_suite.analyze(original, paths.extracted_dir))
        write_subresult(paths, "oletools", ole_res)
        ran.append("oletools")
        findings_total += ole_res.get("counts", {}).get("findings", 0)
        if ole_res.get("findings") and state == "completed":
            state = "completed"

        # External scripts: Didier Stevens Suite (zipdump, oledump) — raw output.
        didier_res = run("didier: zipdump · oledump",
                         lambda: didier.analyze(original, "ooxml"), note="not provisioned")
        if didier_res.get("available"):
            write_subresult(paths, "didier", didier_res)
            ran.append("didier")

        # External binary: OfficeMalScanner (optional, Windows) — inflate+scan/info.
        from .parsers import officemalscanner

        oms_res = run("officemalscanner: inflate · scan · info",
                      lambda: officemalscanner.analyze(original, "ooxml", paths.extracted_dir),
                      note="not provisioned")
        if oms_res.get("available"):
            write_subresult(paths, "officemalscanner", oms_res)
            ran.append("officemalscanner")
            findings_total += oms_res.get("counts", {}).get("findings", 0)
            if oms_res.get("findings") and state == "completed":
                state = "completed"

        for extra in _office_extras(run, original, paths, "ooxml", declared_ext, ole_res):
            write_subresult(paths, extra["module"], extra)
            ran.append(extra["module"])
            findings_total += extra.get("counts", {}).get("findings", 0)

        # Recursion: analyze embedded OLE objects (oleobj) with their own tools.
        from . import nested

        items = [{"path": str(paths.root / o["stored_path"]),
                  "filename": Path(o["stored_path"]).name}
                 for o in ole_res.get("tools", {}).get("oleobj", {}).get("objects", []) or []
                 if o.get("stored_path")]
        if items:
            nested_res = run("nested: recursive scan of embedded OLE objects",
                             lambda: nested.scan_children(items, paths, unlock_ctx={"user": user_pw}))
            if nested_res.get("tree"):
                write_subresult(paths, "nested", nested_res)
                ran.append("nested")
                findings_total += nested_res.get("counts", {}).get("findings", 0)
    elif family == "rtf":
        # RTF (also a .doc/.dot... that is really RTF): own structure/object rules,
        # rtfobj, rtfdump and RTFScan; oleid/msodde from oletools; recursion
        # into the extracted objects.
        from . import nested
        from .parsers import oletools_suite, rtf

        declared_ext = manifest["original"].get("declared_extension", "")
        # c9omYR6Yrv
        rtf_res = run("rtf: structure · objects (rtfobj) · fields · template · rtfdump · RTFScan · own rules",
                      lambda: rtf.analyze(original, declared_ext, paths.extracted_dir))
        write_subresult(paths, "rtf", rtf_res)
        ran.append("rtf")
        overall_counts["components"] = len(rtf_res.get("objects") or [])
        findings_total += rtf_res.get("counts", {}).get("findings", 0)
        if rtf_res.get("status") == "error":
            state = "error"

        ole_res = run("oletools: oleid · msodde · olevba",
                      lambda: oletools_suite.analyze(original, paths.extracted_dir))
        write_subresult(paths, "oletools", ole_res)
        ran.append("oletools")
        findings_total += ole_res.get("counts", {}).get("findings", 0)

        items = [{"path": str(paths.extracted_dir.parent / o["stored_path"]),
                  "filename": o.get("filename") or Path(o["stored_path"]).name}
                 for o in rtf_res.get("objects") or [] if o.get("stored_path")]
        if items:
            nested_res = run("nested: recursive scan of embedded RTF objects",
                             lambda: nested.scan_children(items, paths, unlock_ctx={"user": user_pw}))
            if nested_res.get("tree"):
                write_subresult(paths, "nested", nested_res)
                ran.append("nested")
                findings_total += nested_res.get("counts", {}).get("findings", 0)
    elif family == "pdf":
        # PDF family: our raw-scan parser + Didier pdfid/pdf-parser + recursion.
        from . import nested
        from .parsers import didier
        from .parsers import pdf as pdf_parser

        pdf_res = run("pdf: raw token scan · JS/objects · pypdf · pdfminer",
                      lambda: pdf_parser.analyze(original, paths.extracted_dir))
        write_subresult(paths, "pdf", pdf_res)
        ran.append("pdf")
        overall_counts["components"] = len(pdf_res.get("embedded", []))
        findings_total += pdf_res.get("counts", {}).get("findings", 0)
        if pdf_res.get("status") == "error":
            state = "error"

        from .parsers import pdf_tools
        pt_res = run("pdftools: peepdf · pdf-parser (targeted) · pdfid -e · signatures · QR · own rules",
                     lambda: pdf_tools.analyze(original, pdf_res))
        write_subresult(paths, "pdftools", pt_res)
        ran.append("pdftools")
        findings_total += pt_res.get("counts", {}).get("findings", 0)

        didier_res = run("didier: pdfid · pdf-parser",
                         lambda: didier.analyze(original, "pdf"), note="not provisioned")
        if didier_res.get("available"):
            write_subresult(paths, "didier", didier_res)
            ran.append("didier")

        items = [{"path": str(paths.root / e["stored_path"]), "filename": e.get("filename")}
                 for e in pdf_res.get("embedded", []) or [] if e.get("stored_path")]
        if items:
            nested_res = run("nested: recursive scan of embedded files",
                             lambda: nested.scan_children(items, paths, unlock_ctx={"user": user_pw}))
            if nested_res.get("tree"):
                write_subresult(paths, "nested", nested_res)
                ran.append("nested")
                findings_total += nested_res.get("counts", {}).get("findings", 0)
    elif family == "email" or manifest["original"].get("declared_extension", "").lower() == ".msg":
        # Email family: .eml/.emlx (RFC 822) and .msg (Outlook MAPI/OLE).
        from .parsers import didier, mail

        declared_ext = manifest["original"].get("declared_extension", "")
        mail_res = run("email: parser (headers, Received chain, auth, attachments)",
                       lambda: mail.analyze(original, declared_ext, paths.extracted_dir))
        if mail_res is not None:
            write_subresult(paths, "email", mail_res)
            ran.append("email")
            overall_counts["components"] = mail_res.get("attachment_count", 0)
            findings_total += mail_res.get("counts", {}).get("findings", 0)
            if mail_res.get("status") == "error":
                state = "error"
            elif mail_res.get("findings"):
                state = "completed"

        if mail_res is not None:
            from .parsers import mail_rules
            mr = run("mailrules: gateway links · HTML phishing · DKIM bh · look-alikes · Received · QR",
                     lambda: mail_rules.analyze(original, declared_ext, mail_res, paths.root))
            write_subresult(paths, "mailrules", mr)
            ran.append("mailrules")
            findings_total += mr.get("counts", {}).get("findings", 0)

        # Third-party tools (olevba/oleid/msodde/…) are NOT run on the email
        # envelope itself: an .eml is RFC 822 text, so oleid just reports noise
        # and olevba rarely reaches the attachments. The real coverage comes from
        # the recursive scan below, which runs the full suite on each extracted
        # attachment (where macros/DDE actually live), tagged with its path.
        from . import nested

        items = [{"path": str(paths.root / a["stored_path"]), "filename": a.get("filename")}
                 for a in (mail_res.get("attachments", []) if mail_res else [])
                 if a.get("stored_path")]
        # Passwords given in the mail ("the password is 1234") unlock its
        # encrypted attachments (Office, PDF, ZIP/7z).
        harvested = _harvest_mail_passwords(mail_res, paths) if mail_res else []
        ctx: dict[str, Any] = {"user": user_pw, "harvested": harvested}
        if mail_res and case_wordlist(paths):
            # On request: every word of the email is tried on its encrypted
            # attachments too (no limit — it takes what it takes).
            from . import passwords
            ctx["words"] = passwords.email_words(mail_res)
            ctx["wordlist"] = True
            mail_res["wordlist"] = {"enabled": True, "candidates": len(ctx["words"])}
            write_subresult(paths, "email", mail_res)
        nested_res = run("nested: recursive scan of attachments (unlocking encrypted ones)"
                         + (" · trying every word of the email" if ctx.get("wordlist") else ""),
                         lambda: nested.scan_children(items, paths, unlock_ctx=ctx))
        if nested_res.get("tree"):
            write_subresult(paths, "nested", nested_res)
            ran.append("nested")
            findings_total += nested_res.get("counts", {}).get("findings", 0)

        # External scripts: emldump (MIME) for .eml, oledump (OLE streams) for .msg.
        didier_family = "ole" if declared_ext.lower() == ".msg" else "email"
        didier_res = run("didier: emldump / oledump",
                         lambda: didier.analyze(original, didier_family), note="not provisioned")
        if didier_res.get("available"):
            write_subresult(paths, "didier", didier_res)
            ran.append("didier")
    elif family == "ole":
        # Legacy OLE / BIFF: .doc / .xls / .ppt (Compound File). (.msg already
        # handled by the email branch above.)
        from . import nested
        from .parsers import didier, officemalscanner, ole_legacy, oletools_suite, xlm

        declared_ext = manifest["original"].get("declared_extension", "")
        res = run("ole: CFB structure (streams, metadata, VBA)",
                  lambda: ole_legacy.analyze(original, paths.extracted_dir))
        write_subresult(paths, "ole", res)
        ran.append("ole")
        findings_total += res.get("counts", {}).get("findings", 0)
        if res.get("status") == "error":
            # MH22fELbKP
            state = "error"

        ole_res = run("oletools: olevba · oleid · mraptor · msodde · oleobj",
                      lambda: oletools_suite.analyze(original, paths.extracted_dir))
        write_subresult(paths, "oletools", ole_res)
        ran.append("oletools")
        findings_total += ole_res.get("counts", {}).get("findings", 0)

        # Excel 4.0 (XLM) macros in legacy BIFF .xls (hidden/very-hidden sheets).
        if declared_ext.lower() in (".xls", ".xlt", ".xla", ".xlm"):
            xlm_res = run("xlmdeobf: XLMMacroDeobfuscator (BIFF XLM macros)",
                          lambda: xlm.analyze(original))
            write_subresult(paths, "xlmdeobf", xlm_res)
            ran.append("xlmdeobf")
            findings_total += xlm_res.get("counts", {}).get("findings", 0)

        oms_res = run("officemalscanner: scan · info",
                      lambda: officemalscanner.analyze(original, "ole", paths.extracted_dir),
                      note="not provisioned")
        if oms_res.get("available"):
            write_subresult(paths, "officemalscanner", oms_res)
            ran.append("officemalscanner")
            findings_total += oms_res.get("counts", {}).get("findings", 0)

        didier_res = run("didier: oledump",
                         lambda: didier.analyze(original, "ole"), note="not provisioned")
        if didier_res.get("available"):
            write_subresult(paths, "didier", didier_res)
            ran.append("didier")

        for extra in _office_extras(run, original, paths, "ole", declared_ext, ole_res):
            write_subresult(paths, extra["module"], extra)
            ran.append(extra["module"])
            findings_total += extra.get("counts", {}).get("findings", 0)

        items = [{"path": str(paths.root / o["stored_path"]),
                  "filename": Path(o["stored_path"]).name}
                 for o in ole_res.get("tools", {}).get("oleobj", {}).get("objects", []) or []
                 if o.get("stored_path")]
        if items:
            nested_res = run("nested: recursive scan of embedded OLE objects",
                             lambda: nested.scan_children(items, paths, unlock_ctx={"user": user_pw}))
            if nested_res.get("tree"):
                write_subresult(paths, "nested", nested_res)
                ran.append("nested")
                findings_total += nested_res.get("counts", {}).get("findings", 0)
    elif family in ("zip", "7z", "container"):
        # Archive or container (.zip/.7z/.tar(.gz)/.cab/.iso/.img/.udf): extract
        # with bounds (and the analyst's / usual passwords for encrypted ZIP/7z)
        # and scan every entry recursively. Disk images are a common
        # Mark-of-the-Web bypass carrying a LNK + payload.
        from . import nested

        def _archive() -> dict[str, Any]:
            rec = unlock_mod.extract_archive(original, paths.extracted_dir / "archive",
                                             unlock_mod.candidates(user_pw, kind="archive"))
            out = unlock_mod.public(rec, paths.root)
            out.update(module="archive", password_set=bool(user_pw),
                       counts={"findings": len(rec["findings"]),
                               "entries": len([e for e in rec["entries"] if e.get("file")])},
                       status="ok_with_findings" if rec["findings"] else "ok")
            out["_files"] = [(e["file"], e["name"]) for e in rec["entries"] if e.get("file")]
            return out

        arc = run("archive: list · extract (bounded) · password (analyst / defaults)", _archive) or {}
        files = arc.pop("_files", [])
        if arc:
            write_subresult(paths, "archive", arc)
            ran.append("archive")
            overall_counts["components"] = arc["counts"]["entries"]
            findings_total += arc["counts"]["findings"]
        items = [{"path": f, "filename": Path(n).name} for f, n in files]
        if items:
            nested_res = run("nested: recursive scan of archive entries",
                             lambda: nested.scan_children(items, paths, unlock_ctx={"user": user_pw}))
            if nested_res.get("tree"):
                write_subresult(paths, "nested", nested_res)
                ran.append("nested")
                findings_total += nested_res.get("counts", {}).get("findings", 0)
    elif family == "java":
        # Java archive (.jar/.war/.ear: ZIP → extracted + recursed) or a loose
        # .class/.jsp. Java-aware analysis: manifest, constant pool, JSP, signing.
        from . import nested
        from .parsers import java

        jext = original.suffix.lower()
        if jext in (".jar", ".war", ".ear"):
            def _jar() -> dict[str, Any]:
                rec = unlock_mod.extract_archive(original, paths.extracted_dir / "java",
                                                 unlock_mod.candidates(user_pw, kind="archive"))
                out = unlock_mod.public(rec, paths.root)
                out.update(module="archive", password_set=bool(user_pw),
                           counts={"findings": len(rec["findings"]),
                                   "entries": len([e for e in rec["entries"] if e.get("file")])},
                           status="ok_with_findings" if rec["findings"] else "ok")
                out["_files"] = [(e["file"], e["name"]) for e in rec["entries"] if e.get("file")]
                return out

            arc = run("archive: unpack the Java archive (bounded)", _jar) or {}
            jfiles = arc.pop("_files", [])
            if arc:
                write_subresult(paths, "archive", arc)
                ran.append("archive")
                overall_counts["components"] = arc["counts"]["entries"]
                findings_total += arc["counts"]["findings"]
            items = [{"path": f, "filename": Path(n).name} for f, n in jfiles]
            if items:
                nested_res = run("nested: recursive scan of the archive entries",
                                 lambda: nested.scan_children(items, paths, unlock_ctx={"user": user_pw}))
                if nested_res.get("tree"):
                    write_subresult(paths, "nested", nested_res)
                    ran.append("nested")
                    findings_total += nested_res.get("counts", {}).get("findings", 0)

        jres = run("java: manifest · web.xml · signing · .class constant-pool / CFR · JSP rules",
                   lambda: java.analyze(original, paths.extracted_dir))
        write_subresult(paths, "java", jres)
        ran.append("java")
        findings_total += jres.get("counts", {}).get("findings", 0)
        state = "completed"

    elif family == "onenote":
        # OneNote (.one/.onepkg): carve the embedded-file lures and scan them
        # recursively (a fake "click to view" button hides an .hta/.vbs/.exe).
        from . import nested
        from .parsers import onenote

        on = run("onenote: carve embedded FileDataStoreObject payloads",
                 lambda: onenote.extract(original, paths.extracted_dir / "onenote"))
        onfiles = on.pop("_files", [])
        write_subresult(paths, "onenote", on)
        ran.append("onenote")
        findings_total += on.get("counts", {}).get("findings", 0)
        items = [{"path": f, "filename": Path(n).name} for f, n in onfiles]
        if items:
            nres = run("nested: recursive scan of the embedded OneNote payloads",
                       lambda: nested.scan_children(items, paths, unlock_ctx={"user": user_pw}))
            if nres.get("tree"):
                write_subresult(paths, "nested", nres)
                ran.append("nested")
                findings_total += nres.get("counts", {}).get("findings", 0)
        state = "completed"

    elif family == "shortcut":
        # Windows shortcut (.lnk/.url/.website): parse the target + metadata and
        # feed the launched command to the scripting engine.
        from .parsers import shortcut

        sc_res = run("shortcut: parse target/metadata · command → scripting engine",
                     lambda: shortcut.analyze(original, paths.extracted_dir))
        if sc_res.get("items"):
            write_subresult(paths, "shortcut", sc_res)
            ran.append("shortcut")
            findings_total += sc_res.get("counts", {}).get("findings", 0)
        state = "completed"

    elif family == "binary":
        # Windows Installer (.msi: real OLE analysis, strings → scripting engine)
        # or PE image (.exe/.dll/...: categorised/triaged, not statically unpacked).
        from .parsers import msi

        msi_res = run("binary: MSI tables/strings → scripting engine · PE triage",
                      lambda: msi.analyze(original, paths.extracted_dir))
        if msi_res.get("items"):
            write_subresult(paths, "msi", msi_res)
            ran.append("msi")
            findings_total += msi_res.get("counts", {}).get("findings", 0)
        if original.suffix.lower() not in (".msi", ".msp", ".msm"):
            # A PE is still a first-class case: keep the generic file record
            # (hashes, YARA on demand, marks, report) exactly as any other binary.
            pe_binary = True
            file_res = run("file: generic record (type, size, hashes) — YARA, marks and report",
                           lambda: _file_record(manifest, original))
            write_subresult(paths, "file", file_res)
            ran.append("file")

            # PyInstaller-frozen PE: unpack the bundled Python (CArchive + PYZ)
            # and analyse it with the Python engine (flat tab) and nested tree.
            from .parsers import pyinstaller
            try:
                with open(original, "rb") as fh:
                    fh.seek(max(0, original.stat().st_size - 4 * 1024 * 1024))
                    tail = fh.read()
            except OSError:
                tail = b""
            if pyinstaller.MAGIC in tail:
                from . import nested
                pi = run("pyinstaller: unpack CArchive/PYZ → Python engine",
                         lambda: pyinstaller.extract(original, paths.extracted_dir / "pyinstaller"))
                files = pi.pop("_files", [])
                if pi.get("is_pyinstaller"):
                    write_subresult(paths, "pyinstaller", pi)
                    ran.append("pyinstaller")
                    findings_total += pi.get("counts", {}).get("findings", 0)
                items = [{"path": f, "filename": Path(n).name} for f, n in files]
                if items:
                    nres = run("nested: recursive scan of the unpacked Python modules",
                               lambda: nested.scan_children(items, paths, unlock_ctx={"user": user_pw}))
                    if nres.get("tree"):
                        write_subresult(paths, "nested", nres)
                        if "nested" not in ran:
                            ran.append("nested")
                        findings_total += nres.get("counts", {}).get("findings", 0)
        state = "completed"

    else:
        # Any other file (image, data...): no family parser, but it is still a
        # case — a basic file record, YARA on demand, marks and report.
        file_res = run("file: generic record (type, size, hashes) — YARA, marks and report",
                       lambda: _file_record(manifest, original))
        write_subresult(paths, "file", file_res)
        ran.append("file")
        state = "completed"

    # Scripting engine (deobfuscation + behaviour rules). It runs whenever a
    # family parser ran (scripts hide inside those) or the case file itself is a
    # scripting file — so a standalone .js/.ps1/.vbs/.bat/.hta is analysed too.
    from .parsers import javascript
    scripting_file = original.suffix.lower() in _SCRIPTING_EXT
    # A PE's "msi" categorisation does not feed the scripting engine (it carries
    # no script); an MSI's string-mined command does.
    other_ran = [m for m in ran if m != "file" and not (pe_binary and m == "msi")]

    # JavaScript / JScript (PDF /JS, HTML body, attachments, OLE, nested, VBA).
    if other_ran or scripting_file:
        js_mods = {m: read_json(paths.subresult(m)) for m in ("pdf", "email", "oletools")}
        js_res = run("javascript: extraction · static analysis · STPyV8 sandbox",
                     lambda: javascript.analyze(original, paths.extracted_dir,
                                                {k: v for k, v in js_mods.items() if v}))
        if js_res.get("scripts"):
            write_subresult(paths, "javascript", js_res)
            ran.append("javascript")
            findings_total += js_res.get("counts", {}).get("findings", 0)

    # PowerShell / VBScript / batch: dropped files and commands mined from the
    # other modules (VBA, DDE, the JS sandbox log...), deobfuscated and given
    # their own code tabs. Run last so they can consume the results above.
    if other_ran or scripting_file:
        from .parsers import batch, powershell, vbscript
        code_mods = {m: read_json(paths.subresult(m))
                     for m in ("oletools", "vipermonkey", "javascript", "word", "excel",
                               "powerpoint", "rtf", "email", "shortcut", "msi")}
        code_mods = {k: v for k, v in code_mods.items() if v}
        vbs_res = run("vbscript: extraction · .vbe decode · string deobfuscation",
                      lambda: vbscript.analyze(original, paths.extracted_dir, code_mods))
        if vbs_res.get("scripts"):
            write_subresult(paths, "vbscript", vbs_res)
            ran.append("vbscript")
            findings_total += vbs_res.get("counts", {}).get("findings", 0)
        bat_res = run("batch: extraction · caret/set deobfuscation",
                      lambda: batch.analyze(original, paths.extracted_dir, code_mods))
        if bat_res.get("scripts"):
            write_subresult(paths, "batch", bat_res)
            ran.append("batch")
            findings_total += bat_res.get("counts", {}).get("findings", 0)
        # PowerShell last: it also mines the commands VBScript / batch launch.
        code_mods.update({k: v for k, v in (("vbscript", vbs_res), ("batch", bat_res)) if v.get("scripts")})
        ps_res = run("powershell: extraction · layered deobfuscation",
                     lambda: powershell.analyze(original, paths.extracted_dir, code_mods))
        if ps_res.get("scripts"):
            write_subresult(paths, "powershell", ps_res)
            ran.append("powershell")
            findings_total += ps_res.get("counts", {}).get("findings", 0)
        from .parsers import python as python_parser
        py_res = run("python: .py/.pyc · decompile (pycdc) / disassemble · behaviour rules",
                     lambda: python_parser.analyze(original, paths.extracted_dir, code_mods))
        if py_res.get("scripts"):
            write_subresult(paths, "python", py_res)
            ran.append("python")
            findings_total += py_res.get("counts", {}).get("findings", 0)

    # Decrypted stages: what the analyzers above resolved (JS XOR results,
    # dropped payloads, base64 blobs that are files) becomes nested children,
    # re-analysed by whatever fits them — and recursively by the nested scanner.
    if other_ran or scripting_file:
        from . import decrypted, nested
        dmods = {m: read_json(paths.subresult(m)) for m in ("javascript", "powershell", "vbscript", "batch", "python")}
        # files already in the nested tree (e.g. an attachment whose script is
        # also collected here) are not added again
        known = {((manifest.get("original") or {}).get("hashes") or {}).get("sha256", "")}

        def _shas(nodes):  # noqa: ANN001, ANN202
            for nd in nodes or []:
                known.add(nd.get("sha256") or "")
                _shas(nd.get("children"))
        prev_tree = (read_json(paths.subresult("nested")) or {}).get("tree") or []
        _shas([nd for nd in prev_tree if not nd.get("decrypted_from")])
        ditems = decrypted.write(decrypted.payloads_from({k: v for k, v in dmods.items() if v}, paths.root),
                                 paths.extracted_dir / decrypted.DIRNAME, known)
        if ditems:
            dres = run(f"decrypted: {len(ditems)} recovered stage(s) → nested analysis",
                       lambda: nested.scan_children(ditems, paths, unlock_ctx={"user": user_pw}))
            if dres.get("tree"):
                prev = read_json(paths.subresult("nested"))
                had = bool(prev and prev.get("tree"))
                merged = nested.merge(prev, dres)
                write_subresult(paths, "nested", merged)
                if "nested" not in ran:
                    ran.append("nested")
                findings_total += merged.get("counts", {}).get("findings", 0) - (
                    prev.get("counts", {}).get("findings", 0) if had else 0)

    # Scripts analysed inside nested children -> the case's code tabs.
    try:
        _surface_nested_code(paths, ran)
    except Exception as exc:  # noqa: BLE001  (presentation only; never fail the case)
        log.warning("Could not surface nested code for %s: %s", paths.root.name, exc)

    # YARA runs on every analysed object (the original, everything extracted,
    # nested children, decrypted/decoded stages) whenever rules are loaded. Its
    # hits are NOT findings until the analyst marks them (YARA tab): they are
    # left out of the counts here and filtered in marks.case_findings().
    from .parsers import yara_scan
    yres = run("yara: loaded rules over every analysed object (original, extracted, nested, stages)",
               lambda: yara_scan.analyze(original, paths.extracted_dir))
    if yres.get("rule_count"):
        yres["triage_only"] = True
        write_subresult(paths, "yara", yres)
        if "yara" not in ran:
            ran.append("yara")
    else:
        prev_yara = read_json(paths.subresult("yara"))
        if prev_yara and prev_yara.get("rule_count") and "yara" not in ran:
            ran.append("yara")
    # Network checks (on demand, Checks tab) are evidence too: kept as well.
    prev_net = read_json(paths.subresult("netcheck"))
    if prev_net and prev_net.get("checks"):
        if "netcheck" not in ran:
            ran.append("netcheck")
        findings_total += prev_net.get("counts", {}).get("findings", 0)

    overall_counts["findings"] = findings_total

    # Common IOC extraction: a single phase AFTER all parsers, over their outputs.
    if ran:
        from . import ioc

        modules: dict[str, Any] = {}
        for m in ran:
            data = read_json(paths.subresult(m))
            if data is not None:
                modules[m] = data
        ioc_result = run("ioc: common extractor (URLs, domains, IPs, hashes)",
                         lambda: ioc.extract(ioc.sources_from_modules(modules)))
        write_subresult(paths, "iocs", ioc_result)
        overall_counts["iocs"] = ioc_result.get("counts", {}).get("total", 0)
        steps[-1]["iocs"] = overall_counts["iocs"]

        # Consolidated findings with stable ids (source of truth for marks).
        # Written separately; never touches marks.json.
        from . import findings as findings_mod

        consolidated = run("findings: consolidation (stable ids for marks)",
                           lambda: findings_mod.consolidate(modules))
        write_subresult(paths, "findings", {"findings": consolidated,
                                            "counts": {"total": len(consolidated)}})
        # YARA hits count only once the analyst marks them
        from . import marks as marks_mod
        visible = len(marks_mod.case_findings(paths))
        overall_counts["findings"] = visible
        steps[-1]["findings"] = visible

        # Dump extracted code (VBA/JS/XLM) to files and persist the code_file
        # tags, so the UI can offer Folder/Download on the code panes.
        from . import codefiles
        for m in codefiles.annotate(modules, paths):
            write_subresult(paths, m, modules[m])

    # Update summary.json (fast-read view) and the manifest.
    summary = read_json(paths.summary) or {}
    summary["counts"] = overall_counts
    summary["steps"] = steps
    summary["state"] = state
    summary["modules_run"] = ran
    summary["updated_utc"] = _now()
    write_json(paths.summary, summary)

    manifest["state"] = state
    manifest["updated_utc"] = _now()
    manifest["analysis"] = {"modules_run": ran, "updated_utc": _now()}
    write_json(paths.manifest, manifest)

    log.info("Analyzed case %s (family=%s, modules=%s, state=%s)",
             case_root.name, family, ran, state)
    return {"modules_run": ran, "state": state, "counts": overall_counts}


# Modules that can be re-run in isolation over an existing case.
_RERUNNABLE = ("ooxml", "word", "excel", "powerpoint", "oletools", "msoffcrypto",
               "xlmdeobf", "officemalscanner", "didier", "email", "pdf", "yara", "ole",
               "officerules", "vbatools", "vipermonkey", "pdftools", "mailrules", "javascript", "rtf",
               "powershell", "vbscript", "batch", "shortcut", "msi", "python", "java", "onenote")
# Modules whose findings feed the consolidated view (includes derived ones).
_COLLECTABLE = _RERUNNABLE + ("nested", "netcheck", "unlock", "archive", "file", "pyinstaller")


def _collect_modules(paths: CasePaths) -> dict[str, Any]:
    """Read every module sub-result present on disk for a case."""
    modules: dict[str, Any] = {}
    for name in _COLLECTABLE:
        data = read_json(paths.subresult(name))
        if data is not None:
            modules[name] = data
    return modules


def _recompute_derived(paths: CasePaths) -> tuple[int, int]:
    """Recompute IOC + consolidated findings from whatever modules exist.

    Never touches marks.json (findings keep stable ids, so marks still match).
    Returns (ioc_total, findings_total).
    """
    from . import findings as findings_mod
    from . import ioc

    modules = _collect_modules(paths)
    ioc_result = ioc.extract(ioc.sources_from_modules(modules))
    write_subresult(paths, "iocs", ioc_result)
    consolidated = findings_mod.consolidate(modules)
    write_subresult(paths, "findings", {"findings": consolidated,
                                        "counts": {"total": len(consolidated)}})
    from . import codefiles
    for m in codefiles.annotate(modules, paths):
        write_subresult(paths, m, modules[m])
    from . import marks as marks_mod      # YARA hits count once marked
    return ioc_result.get("counts", {}).get("total", 0), len(marks_mod.case_findings(paths))


def refresh_derived(paths: CasePaths, module: str) -> dict[str, Any]:
    """After an on-demand module wrote its result (e.g. a network check):
    recompute IOCs + consolidated findings and update the case summary."""
    ioc_total, findings_total = _recompute_derived(paths)
    summary = read_json(paths.summary) or {}
    ran = summary.get("modules_run", [])
    if module not in ran:
        ran.append(module)
    summary["modules_run"] = ran
    summary.setdefault("counts", {})
    summary["counts"]["iocs"] = ioc_total
    summary["counts"]["findings"] = findings_total
    summary["updated_utc"] = _now()
    write_json(paths.summary, summary)
    manifest = read_json(paths.manifest)
    if manifest is not None:
        manifest.setdefault("analysis", {})["modules_run"] = ran
        manifest["analysis"]["updated_utc"] = _now()
        write_json(paths.manifest, manifest)
    return {"iocs": ioc_total, "findings": findings_total}


def run_module(case_root: Path, module: str) -> dict[str, Any]:
    """Re-run ONE parser/tool module over an existing case, then recompute the
    derived IOC + findings. Isolated: other modules' results are left as-is."""
    import time as _time
    _t0 = _time.perf_counter()
    _notify_step("start", {"step": f"rerun: {module}"})
    case_root = Path(case_root)
    paths = CasePaths(case_root.name, cases_dir=case_root.parent)
    manifest = read_json(paths.manifest)
    if manifest is None:
        raise FileNotFoundError(f"No case.json in {case_root}")
    if module not in _RERUNNABLE:
        raise ValueError(f"Module not re-runnable: {module!r}")

    true_original = paths.root / manifest["original"]["stored_path"]
    original = _subject(paths, true_original)
    declared_ext = manifest["original"].get("declared_extension", "")
    family = _effective_family(manifest, original, read_json(paths.subresult("unlock")) or {})
    ed = paths.extracted_dir

    if module == "ooxml":
        from .parsers import ooxml
        res = ooxml.analyze(original, ed)
    elif module in ("word", "excel", "powerpoint"):
        if declared_ext.lower() == ".xlsb":
            from .parsers import xlsb
            res = xlsb.analyze(original)
        else:
            from .parsers import office
            res = office.analyze(original, declared_ext, ed)
    elif module in ("officerules", "vbatools", "vipermonkey"):
        from .parsers import office_rules, vba_tools, vipermonkey
        fam = "ooxml" if family == "ooxml" else "ole"
        if module == "officerules":
            res = office_rules.analyze_ooxml(original) if fam == "ooxml" else office_rules.analyze_ole(original)
        else:
            olevba = ((read_json(paths.subresult("oletools")) or {}).get("tools") or {}).get("olevba") or {}
            if module == "vbatools":
                res = vba_tools.analyze(original, fam, bool(olevba.get("macros")), olevba.get("modules"),
                                        is_excel_binary=(fam == "ole" and declared_ext.lower() in (".xls", ".xlt", ".xla")))
            else:
                res = vipermonkey.analyze(original, ed)
    elif module == "rtf":
        from .parsers import rtf
        res = rtf.analyze(original, declared_ext, ed)
    elif module == "oletools":
        from .parsers import oletools_suite
        res = oletools_suite.analyze(original, ed)
    elif module == "msoffcrypto":
        from .parsers import crypto
        res = crypto.analyze(true_original, ed)
    elif module == "xlmdeobf":
        from .parsers import xlm
        res = xlm.analyze(original)
    elif module == "officemalscanner":
        from .parsers import officemalscanner
        res = officemalscanner.analyze(original, "ooxml", ed)
    elif module == "didier":
        from .parsers import didier
        fam = "ole" if declared_ext.lower() == ".msg" else (family or "ooxml")
        res = didier.analyze(original, fam)
    elif module == "email":
        from .parsers import mail
        res = mail.analyze(original, declared_ext, ed)
    elif module == "javascript":
        from .parsers import javascript
        mods = {m: read_json(paths.subresult(m)) for m in ("pdf", "email", "oletools")}
        res = javascript.analyze(original, ed, {k: v for k, v in mods.items() if v})
    elif module in ("powershell", "vbscript", "batch"):
        from .parsers import batch, powershell, vbscript
        mods = {m: read_json(paths.subresult(m))
                for m in ("oletools", "vipermonkey", "javascript", "word", "excel",
                          "powerpoint", "rtf", "email", "shortcut", "msi")}
        mods = {k: v for k, v in mods.items() if v}
        mod = {"powershell": powershell, "vbscript": vbscript, "batch": batch}[module]
        res = mod.analyze(original, ed, mods)
    elif module == "mailrules":
        # gmzpt
        from .parsers import mail_rules
        res = mail_rules.analyze(original, declared_ext, read_json(paths.subresult("email")) or {}, paths.root)
    elif module == "pdf":
        from .parsers import pdf as pdf_parser
        res = pdf_parser.analyze(original, ed)
    elif module == "pdftools":
        from .parsers import pdf_tools
        res = pdf_tools.analyze(original, read_json(paths.subresult("pdf")) or {})
    elif module == "yara":
        from .parsers import yara_scan
        res = yara_scan.analyze(original, ed)
    elif module == "ole":
        from .parsers import ole_legacy
        res = ole_legacy.analyze(original, ed)
    elif module == "shortcut":
        from .parsers import shortcut
        res = shortcut.analyze(original, ed)
    elif module == "msi":
        from .parsers import msi
        res = msi.analyze(original, ed)
    elif module == "python":
        from .parsers import python
        res = python.analyze(original, ed, {})
    elif module == "java":
        from .parsers import java
        res = java.analyze(original, ed)
    elif module == "onenote":
        from .parsers import onenote
        res = onenote.extract(original, ed / "onenote")
        res.pop("_files", None)
    else:  # pragma: no cover
        raise ValueError(module)

    if res is None:
        raise ValueError(f"Module {module!r} not applicable to this case")
    written = res.get("module", module)
    write_subresult(paths, written, res)

    ioc_total, findings_total = _recompute_derived(paths)
    summary = read_json(paths.summary) or {}
    ran = summary.get("modules_run", [])
    if written not in ran:
        ran.append(written)
    summary["modules_run"] = ran
    summary.setdefault("counts", {})
    summary["counts"]["iocs"] = ioc_total
    summary["counts"]["findings"] = findings_total
    rerun_rec = {"step": f"rerun: {written}", "status": res.get("status", "ok"),
                 "findings": res.get("counts", {}).get("findings", 0),
                 "duration_s": round(_time.perf_counter() - _t0, 3)}
    _notify_step("end", {**rerun_rec, "step": f"rerun: {module}"})
    summary["steps"] = [
        rerun_rec,
        {"step": "ioc: recompute", "status": "ok", "iocs": ioc_total},
        {"step": "findings: recompute", "status": "ok", "findings": findings_total},
    ]
    state = "completed"
    summary["state"] = state
    summary["updated_utc"] = _now()
    write_json(paths.summary, summary)

    manifest["state"] = state
    manifest["updated_utc"] = _now()
    manifest.setdefault("analysis", {})["modules_run"] = ran
    manifest["analysis"]["updated_utc"] = _now()
    write_json(paths.manifest, manifest)
    log.info("Re-ran module %r on case %s (findings=%d)", written, case_root.name, findings_total)
    return {"module": written, "state": state,
            "counts": {"iocs": ioc_total, "findings": findings_total}}


_STEP_PREFIX = "@@DTX_STEP "


def _run_portable(cmd: list[str], timeout: float | None, listener) -> "subprocess.CompletedProcess[str]":  # noqa: ANN001
    """Run the analysis on the portable interpreter, relaying its live step
    events (``@@DTX_STEP {json}`` lines on stderr) to ``listener`` as they
    happen, so the Tasks tab shows the steps of an analysis running in that
    separate process. Returns a CompletedProcess like ``subprocess.run``."""
    import json as _json
    import subprocess
    import threading

    from . import native

    env = dict(native.subprocess_env() or os.environ)
    env["DOCUTRACEX_STEP_EVENTS"] = "stderr"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", env=env)
    out_buf: list[str] = []
    err_buf: list[str] = []

    def pump_err() -> None:
        for line in proc.stderr:  # type: ignore[union-attr]
            if line.startswith(_STEP_PREFIX):
                if listener:
                    try:
                        ev = _json.loads(line[len(_STEP_PREFIX):])
                        listener(ev.get("event"), ev.get("rec") or {})
                    except Exception:  # noqa: BLE001
                        pass
            else:
                err_buf.append(line)

    def pump_out() -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            out_buf.append(line)

    readers = [threading.Thread(target=pump_err, daemon=True), threading.Thread(target=pump_out, daemon=True)]
    for t in readers:
        t.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    finally:
        for t in readers:
            t.join(timeout=5)
    return subprocess.CompletedProcess(cmd, proc.returncode, "".join(out_buf), "".join(err_buf))


def run_analysis(case_root: Path, module: str | None = None) -> None:
    """Trigger analysis for a case, preferring the portable tool interpreter.

    With ``module`` set, re-runs only that module (isolated); otherwise the
    whole case.
    """
    import subprocess

    from . import native
    from .config import settings

    case_root = Path(case_root)
    portable = settings.portable_python()
    already = False
    if portable:
        try:
            already = portable.resolve() == Path(sys.executable).resolve()
        except OSError:
            already = False
    if portable and not already:
        # gmzpt
        cmd = [str(portable), "-m", "docutracex.analyze", str(case_root)]
        if module:
            cmd += ["--module", module]
        try:
            proc = _run_portable(
                cmd,
                # Generous: every tool (incl. ViperMonkey emulation) runs per case;
                # no limit when trying every word of an email as a password.
                timeout=None if case_wordlist(CasePaths(case_root.name, cases_dir=case_root.parent)) else tmo(3600),
                listener=getattr(_step_local, "fn", None),
            )
        except Exception as exc:  # noqa: BLE001
            # The portable could not be launched at all: fall back to in-process.
            log.warning("Could not run analysis on portable: %s", exc)
        else:
            if proc.returncode == 0:
                return
            # The portable ran and died (e.g. 0xC0000005 native crash). Do NOT
            # repeat the same analysis inside the web server: the same input
            # would crash it too and close the whole app. Fail only this task.
            msg = (f"Analysis on portable failed (exit {proc.returncode} / "
                   f"0x{proc.returncode & 0xFFFFFFFF:08X}): {proc.stderr.strip()[-300:]}")
            log.warning(msg)
            raise RuntimeError(msg)
        # fall through to in-process

    try:
        if module:
            run_module(case_root, module)
        else:
            analyze_case(case_root)
    except Exception as exc:  # noqa: BLE001  (analysis failure must not break upload)
        log.warning("In-process analysis failed for %s: %s", case_root, exc)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m docutracex.analyze <case_root> [--module NAME]")
        return 2
    case_root = Path(argv[0])
    if os.environ.get("DOCUTRACEX_STEP_EVENTS") == "stderr":
        # running as the portable child of the web service: stream each step's
        # start/end to the parent (Tasks tab, live)
        import json as _json

        def _emit(event: str, rec: dict[str, Any]) -> None:
            print(_STEP_PREFIX + _json.dumps({"event": event, "rec": rec}, default=str),
                  file=sys.stderr, flush=True)
        set_step_listener(_emit)
    if "--module" in argv:
        idx = argv.index("--module")
        run_module(case_root, argv[idx + 1])
    else:
        analyze_case(case_root)
    return 0


if __name__ == "__main__":
    # Run through the canonical module, not this ``__main__`` copy: parsers
    # import ``docutracex.analyze`` (step progress, listeners), and two copies
    # of the module would each have their own per-thread state.
    from docutracex.analyze import main as _main
    raise SystemExit(_main())
