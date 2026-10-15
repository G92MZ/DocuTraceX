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

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .logging_config import get_logger
from .storage import CasePaths, read_json, write_json, write_subresult

log = get_logger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _family(manifest: dict[str, Any]) -> str | None:
    disc = manifest.get("format", {}).get("discrepancy") or {}
    return disc.get("declared_family")




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


def analyze_case(case_root: Path) -> dict[str, Any]:
    """Run the applicable parsers on a case (in-process). Returns a summary."""
    case_root = Path(case_root)
    paths = CasePaths(case_root.name, cases_dir=case_root.parent)
    manifest = read_json(paths.manifest)
    if manifest is None:
        raise FileNotFoundError(f"No case.json in {case_root}")

    family = _family(manifest)
    original = paths.root / manifest["original"]["stored_path"]
    ran: list[str] = []
    overall_counts: dict[str, int] = {"components": 0, "findings": 0, "iocs": 0}
    state = "completed"

    findings_total = 0
    steps: list[dict[str, Any]] = []

    def run(name: str, fn, note: str = ""):
        """Run one analysis step, timing it and recording it for the Tasks view."""
        import time as _time
        t0 = _time.perf_counter()
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
        return res

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
        from .parsers import crypto, didier, oletools_suite

        ole_res = run("oletools: olevba · oleid · mraptor · msodde · oleobj",
                      lambda: oletools_suite.analyze(original, paths.extracted_dir))
        write_subresult(paths, "oletools", ole_res)
        ran.append("oletools")
        findings_total += ole_res.get("counts", {}).get("findings", 0)
        if ole_res.get("findings") and state == "completed":
            state = "completed"

        # External tool: encrypted-document detection / default-password decrypt.
        crypto_res = run("msoffcrypto: encryption / default-password decrypt",
                         lambda: crypto.analyze(original, paths.extracted_dir))
        write_subresult(paths, "msoffcrypto", crypto_res)
        ran.append("msoffcrypto")
        findings_total += crypto_res.get("counts", {}).get("findings", 0)
        if crypto_res.get("findings") and state == "completed":
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
                             lambda: nested.scan_children(items, paths))
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
                             lambda: nested.scan_children(items, paths))
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
        nested_res = run("nested: recursive scan of attachments",
                         lambda: nested.scan_children(items, paths))
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
        from .parsers import (crypto, didier, ole_legacy, officemalscanner,
                              oletools_suite, xlm)

        declared_ext = manifest["original"].get("declared_extension", "")
        res = run("ole: CFB structure (streams, metadata, VBA)",
                  lambda: ole_legacy.analyze(original, paths.extracted_dir))
        write_subresult(paths, "ole", res)
        ran.append("ole")
        findings_total += res.get("counts", {}).get("findings", 0)
        if res.get("status") == "error":
            state = "error"

        ole_res = run("oletools: olevba · oleid · mraptor · msodde · oleobj",
                      lambda: oletools_suite.analyze(original, paths.extracted_dir))
        write_subresult(paths, "oletools", ole_res)
        ran.append("oletools")
        findings_total += ole_res.get("counts", {}).get("findings", 0)

        crypto_res = run("msoffcrypto: encryption / default-password decrypt",
                         lambda: crypto.analyze(original, paths.extracted_dir))
        write_subresult(paths, "msoffcrypto", crypto_res)
        ran.append("msoffcrypto")
        findings_total += crypto_res.get("counts", {}).get("findings", 0)

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
                             lambda: nested.scan_children(items, paths))
            if nested_res.get("tree"):
                write_subresult(paths, "nested", nested_res)
                ran.append("nested")
                findings_total += nested_res.get("counts", {}).get("findings", 0)
    else:
        # No parser for this family yet.
        state = "completed"

    # JavaScript: extracted from every place it can hide (PDF, HTML body,
    # attachments, OLE packages, nested children...), analysed and sandboxed.
    from .parsers import javascript
    if ran or original.suffix.lower() in javascript._SCRIPT_EXT:
        js_mods = {m: read_json(paths.subresult(m)) for m in ("pdf", "email", "oletools")}
        js_res = run("javascript: extraction · static analysis · STPyV8 sandbox",
                     lambda: javascript.analyze(original, paths.extracted_dir,
                                                {k: v for k, v in js_mods.items() if v}))
        if js_res.get("scripts"):
            write_subresult(paths, "javascript", js_res)
            ran.append("javascript")
            findings_total += js_res.get("counts", {}).get("findings", 0)

    # YARA runs only on demand (YARA tab / re-run "yara"), never automatically.
    # A previous on-demand scan of this case is kept across full re-analyses.
    prev_yara = read_json(paths.subresult("yara"))
    if prev_yara and prev_yara.get("rule_count"):
        if "yara" not in ran:
            ran.append("yara")
        findings_total += prev_yara.get("counts", {}).get("findings", 0)

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
        overall_counts["findings"] = len(consolidated)
        steps[-1]["findings"] = len(consolidated)

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
               "officerules", "vbatools", "vipermonkey", "pdftools", "mailrules", "javascript")
# Modules whose findings feed the consolidated view (includes derived ones).
_COLLECTABLE = _RERUNNABLE + ("nested",)


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
    return ioc_result.get("counts", {}).get("total", 0), len(consolidated)


def run_module(case_root: Path, module: str) -> dict[str, Any]:
    """Re-run ONE parser/tool module over an existing case, then recompute the
    derived IOC + findings. Isolated: other modules' results are left as-is."""
    case_root = Path(case_root)
    paths = CasePaths(case_root.name, cases_dir=case_root.parent)
    manifest = read_json(paths.manifest)
    if manifest is None:
        raise FileNotFoundError(f"No case.json in {case_root}")
    if module not in _RERUNNABLE:
        raise ValueError(f"Module not re-runnable: {module!r}")

    original = paths.root / manifest["original"]["stored_path"]
    declared_ext = manifest["original"].get("declared_extension", "")
    family = _family(manifest)
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
    elif module == "oletools":
        from .parsers import oletools_suite
        res = oletools_suite.analyze(original, ed)
    elif module == "msoffcrypto":
        from .parsers import crypto
        res = crypto.analyze(original, ed)
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
    elif module == "mailrules":
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
    summary["steps"] = [
        {"step": f"rerun: {written}", "status": res.get("status", "ok"),
         "findings": res.get("counts", {}).get("findings", 0)},
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
        cmd = [str(portable), "-m", "docutracex.analyze", str(case_root)]
        if module:
            cmd += ["--module", module]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                # Generous: every tool (incl. ViperMonkey emulation) runs per case.
                timeout=1800, env=native.subprocess_env(),
            )
            if proc.returncode == 0:
                return
            log.warning("Analysis on portable failed (%s): %s",
                        proc.returncode, proc.stderr.strip()[:300])
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not run analysis on portable: %s", exc)
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
    if "--module" in argv:
        idx = argv.index("--module")
        run_module(case_root, argv[idx + 1])
    else:
        analyze_case(case_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
