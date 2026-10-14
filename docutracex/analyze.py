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
    if family == "ooxml":
        from .parsers import ooxml, office

        res = ooxml.analyze(original, paths.extracted_dir)
        write_subresult(paths, "ooxml", res)
        ran.append("ooxml")
        overall_counts["components"] = res.get("counts", {}).get("components", 0)
        if res.get("status") == "error":
            state = "error"
        elif res.get("anomalies"):
            state = "partial"

        # Semantic parser for the specific Office app (Word/Excel/PowerPoint).
        declared_ext = manifest["original"].get("declared_extension", "")
        sem = office.analyze(original, declared_ext, paths.extracted_dir)
        if sem is not None:
            module = sem["module"]
            write_subresult(paths, module, sem)
            ran.append(module)
            findings_total += sem.get("counts", {}).get("findings", 0)
            if sem.get("status") == "error" and state != "error":
                state = "partial"
            elif sem.get("findings") and state == "completed":
                state = "partial"

        # External tool: Excel 4.0 (XLM) macro deobfuscation — Excel only.
        if sem is not None and sem.get("module") == "excel":
            from .parsers import xlm

            xlm_res = xlm.analyze(original)
            write_subresult(paths, "xlmdeobf", xlm_res)
            ran.append("xlmdeobf")
            findings_total += xlm_res.get("counts", {}).get("findings", 0)
            if xlm_res.get("findings") and state == "completed":
                state = "partial"

        # External tools: the oletools suite (olevba, oleid, mraptor, msodde,
        # oleobj) — runs on the portable.
        from .parsers import crypto, didier, oletools_suite

        ole_res = oletools_suite.analyze(original, paths.extracted_dir)
        write_subresult(paths, "oletools", ole_res)
        ran.append("oletools")
        findings_total += ole_res.get("counts", {}).get("findings", 0)
        if ole_res.get("findings") and state == "completed":
            state = "partial"

        # External tool: encrypted-document detection / default-password decrypt.
        crypto_res = crypto.analyze(original, paths.extracted_dir)
        write_subresult(paths, "msoffcrypto", crypto_res)
        ran.append("msoffcrypto")
        findings_total += crypto_res.get("counts", {}).get("findings", 0)
        if crypto_res.get("findings") and state == "completed":
            state = "partial"

        # External scripts: Didier Stevens Suite (zipdump, oledump) — raw output.
        didier_res = didier.analyze(original, "ooxml")
        if didier_res.get("available"):
            write_subresult(paths, "didier", didier_res)
            ran.append("didier")

        # External binary: OfficeMalScanner (optional, Windows) — inflate+scan/info.
        from .parsers import officemalscanner

        oms_res = officemalscanner.analyze(original, "ooxml", paths.extracted_dir)
        if oms_res.get("available"):
            write_subresult(paths, "officemalscanner", oms_res)
            ran.append("officemalscanner")
            findings_total += oms_res.get("counts", {}).get("findings", 0)
            if oms_res.get("findings") and state == "completed":
                state = "partial"
    else:
        # No parser for this family yet.
        state = "completed"

    overall_counts["findings"] = findings_total

    # Common IOC extraction: a single phase AFTER all parsers, over their outputs.
    if ran:
        from . import ioc

        modules: dict[str, Any] = {}
        for m in ran:
            data = read_json(paths.subresult(m))
            if data is not None:
                modules[m] = data
        ioc_result = ioc.extract(ioc.sources_from_modules(modules))
        write_subresult(paths, "iocs", ioc_result)
        overall_counts["iocs"] = ioc_result.get("counts", {}).get("total", 0)

        # Consolidated findings with stable ids (source of truth for marks).
        # Written separately; never touches marks.json.
        from . import findings as findings_mod

        consolidated = findings_mod.consolidate(modules)
        write_subresult(paths, "findings", {"findings": consolidated,
                                            "counts": {"total": len(consolidated)}})
        overall_counts["findings"] = len(consolidated)

    # Update summary.json (fast-read view) and the manifest.
    summary = read_json(paths.summary) or {}
    summary["counts"] = overall_counts
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


def run_analysis(case_root: Path) -> None:
    """Trigger analysis for a case, preferring the portable tool interpreter."""
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
        try:
            proc = subprocess.run(
                [str(portable), "-m", "docutracex.analyze", str(case_root)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=600, env=native.subprocess_env(),
            )
            if proc.returncode == 0:
                return
            log.warning("Analysis on portable failed (%s): %s",
                        proc.returncode, proc.stderr.strip()[:300])
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not run analysis on portable: %s", exc)
        # fall through to in-process

    try:
        analyze_case(case_root)
    except Exception as exc:  # noqa: BLE001  (analysis failure must not break upload)
        log.warning("In-process analysis failed for %s: %s", case_root, exc)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m docutracex.analyze <case_root>")
        return 2
    analyze_case(Path(argv[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
