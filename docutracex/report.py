"""Self-contained HTML report for a case.

Renders the consolidated findings (with their evidence and manual marks), IOCs,
the recursive child tree, document metadata and the case/identification header
into one standalone HTML page. It is printable (Ctrl+P → PDF) and carries no
external resources, so it can be archived or attached to a ticket as-is.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

# id: pzFQkCWMlr
from . import marks as marks_service
from .storage import CasePaths, read_json

_SEV_ORDER = ["high", "medium", "low", "info"]
_SEV_COLOR = {"high": "#e8795a", "medium": "#e0b65a", "low": "#9bb0c9", "info": "#5fd38b"}
_MARK_LABEL = {
    "true_positive": "True positive", "false_positive": "False positive",
    "suspicious": "Suspicious", "informational": "Informational", "unreviewed": "Unreviewed",
}


def _e(v: Any) -> str:
    return html.escape(str(v if v is not None else ""))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _row(cells: list[str]) -> str:
    return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def _findings_section(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "<p class='muted'>No findings.</p>"
    rows = []
    for f in findings:
        sev = f.get("severity", "info")
        chip = f"<span class='chip' style='border-color:{_SEV_COLOR.get(sev, '#888')};color:{_SEV_COLOR.get(sev, '#888')}'>{_e(sev)}</span>"
        ev = f"<div class='evidence'>{_e(f.get('evidence'))}</div>" if f.get("evidence") else ""
        # k: gmzpt
        mark = (f.get("mark") or {}).get("state", "unreviewed")
        comment = (f.get("mark") or {}).get("comment", "")
        mcell = _MARK_LABEL.get(mark, mark) + (f"<div class='muted'>{_e(comment)}</div>" if comment else "")
        rows.append(_row([
            chip, _e(f.get("source")), f"<code>{_e(f.get('rule'))}</code>",
            _e(f.get("detail")) + ev, f"<code>{_e(f.get('location'))}</code>", mcell,
        ]))
    return ("<table><thead><tr><th>Severity</th><th>Source</th><th>Rule</th>"
            "<th>Detail / evidence</th><th>Location</th><th>Mark</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _iocs_section(iocs: dict[str, Any] | None) -> str:
    items = (iocs or {}).get("iocs", [])
    if not items:
        return "<p class='muted'>No IOCs.</p>"
    rows = []
    for i in items:
        where = ", ".join(sorted({f"{o.get('module')}/{o.get('location')}"
                                  for o in i.get("occurrences", [])}))
        rows.append(_row([_e(i.get("type")), f"<code>{_e(i.get('value'))}</code>",
                          _e(i.get("count")), _e(where)]))
    return ("<table><thead><tr><th>Type</th><th>Value</th><th>Count</th><th>Provenance</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _nested_section(nested: dict[str, Any] | None) -> str:
    tree = (nested or {}).get("tree", [])
    if not tree:
        return ""

    def node(n: dict[str, Any]) -> str:
        fnd = n.get("findings", [])
        head = (f"<div class='nnode'><b>{_e(n.get('filename'))}</b> "
                f"<span class='chip'>{_e(n.get('kind'))}</span> "
                f"<span class='muted'>{len(fnd)} finding(s)</span>")
        if n.get("decrypted_from"):
            recipe = " → ".join(n.get("recipe") or [])
            head += (f"<div class='muted'>decoded/decrypted from {_e(n['decrypted_from'])}"
                     + (f"<br>recipe: <code>{_e(recipe)}</code>" if recipe else "") + "</div>")
        inner = "".join(
            f"<div class='nfind'><span class='chip' style='border-color:{_SEV_COLOR.get(f.get('severity'), '#888')};"
            f"color:{_SEV_COLOR.get(f.get('severity'), '#888')}'>{_e(f.get('severity'))}</span> "
            f"<code>{_e(f.get('tool'))}/{_e(f.get('rule'))}</code> {_e(f.get('detail'))}</div>"
            for f in fnd)
        children = "".join(node(c) for c in n.get("children", []))
        return head + inner + (f"<div class='nchildren'>{children}</div>" if children else "") + "</div>"

    return "<h2>Nested (recursive) analysis</h2>" + "".join(node(n) for n in tree)


def _metadata_section(modules: dict[str, Any]) -> str:
    md: dict[str, Any] = {}
    for key in ("word", "excel", "powerpoint"):
        m = modules.get(key)
        if m and m.get("metadata"):
            md = m["metadata"]
            break
    if not md and modules.get("pdf", {}).get("metadata"):
        md = modules["pdf"]["metadata"]
    if not md:
        return ""
    rows = "".join(_row([_e(k), _e(v)]) for k, v in md.items())
    return "<h2>Document metadata</h2><table><tbody>" + rows + "</tbody></table>"


def _ml_enriched(paths: CasePaths) -> dict[str, Any] | None:
    from .ml.family_info import enrich
    return enrich(read_json(paths.subresult("ml")))


def _ml_section(ml: dict[str, Any] | None, marks: dict[str, dict[str, Any]]) -> str:
    """Every object scored by the EMBER2024 models: score against the calibrated
    threshold, hints and the analyst's mark. An indicator, not a verdict — the
    results marked True positive are also in the findings above."""
    from .ml_csv import family_hints, tag_hints

    items = (ml or {}).get("items") or []
    if not items:
        return ""
    rows = []
    for it in items:
        mk = marks.get(it.get("finding_id") or "") or {}
        state = mk.get("state", "unreviewed") if it.get("finding_id") else ""
        if it.get("status") != "ok":
            rows.append(_row([_e(it.get("label")), _e(it.get("format") or it.get("file_type") or ""), "",
                              f"<span class='muted'>{_e(it.get('status'))}: {_e(it.get('detail'))}</span>", "", ""]))
            continue
        above = it.get("threshold") is not None and it["score"] >= it["threshold"]
        color = "#e8795a" if above else "#5fd38b"
        verdict = f"<span class='chip' style='border-color:{color};color:{color}'>{_e(it.get('verdict'))}</span>"
        thr = f" / {it['threshold']:.4f}" if it.get("threshold") is not None else ""
        hints = tag_hints(it) + [f"family: {h}" for h in family_hints(it, only_high=True)]
        why = ", ".join(f"{t.get('plain') or t['feature']} ({t['contribution']:+.2f})"
                        for t in (it.get("top_features") or [])[:3])
        rows.append(_row([
            _e(it.get("label")) + (f"<div class='muted'><code>{_e(it.get('sha256'))}</code></div>" if it.get("sha256") else ""),
            _e(it.get("model", "").replace("EMBER2024_", "")),
            f"<code style='white-space:nowrap'>{it['score']:.4f}{thr}</code>",
            verdict + (f"<div class='muted'>why: {_e(why)}</div>" if why else ""),
            (_e(", ".join(hints)) or "<span class='muted'>—</span>")
            + (f"<div class='muted'>⚠ {_e(it['family_note'])}</div>" if it.get("family_note") else ""),
            _e(_MARK_LABEL.get(state, state)) + (f"<div class='muted'>{_e(mk.get('comment'))}</div>" if mk.get("comment") else ""),
        ]))
    above_n = sum(1 for it in items if it.get("verdict") == "above threshold")
    return (f"<h2>Machine Learning — EMBER2024 ({above_n} of {len(items)} above threshold)</h2>"
            "<p class='muted'>Static classifier on every PE, .NET, PDF, ELF and APK object of the case. The score is "
            "compared with a threshold calibrated at a 1% false-positive rate; it is a complementary indicator, "
            "not a verdict. Results marked True positive also appear in the confirmed findings.</p>"
            "<table><thead><tr><th>Object</th><th>Model</th><th>Score / threshold</th><th>Verdict</th>"
            "<th>Hints (tags, family)</th><th>Mark</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def build_report_html(analysis_id: str, cases_dir=None) -> str:
    paths = CasePaths(analysis_id, cases_dir=cases_dir)
    manifest = read_json(paths.manifest) or {}
    summary = read_json(paths.summary) or {}
    findings = marks_service.case_findings(paths)  # automatic + manual
    marked = marks_service.apply(findings, marks_service.read_marks(paths))
    findings = marked["findings"]
    iocs = read_json(paths.subresult("iocs"))

    from .analyze import _COLLECTABLE
    modules = {m: read_json(paths.subresult(m)) for m in _COLLECTABLE
               if read_json(paths.subresult(m)) is not None}

    orig = manifest.get("original", {})
    fmt = manifest.get("format", {})
    disc = fmt.get("discrepancy", {})
    det = fmt.get("detected", {})

    # The report shows only the analyst-confirmed (True positive) findings.
    tp_findings = [f for f in findings if (f.get("mark") or {}).get("state") == "true_positive"]
    tp_count = len(tp_findings)
    sev_counts = {s: 0 for s in _SEV_ORDER}
    for f in tp_findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1
    mk = marked["counts"]

    header_rows = "".join(_row([k, v]) for k, v in [
        ("Analysis ID", _e(analysis_id)),
        ("File", _e(orig.get("filename"))),
        ("Declared extension", _e(orig.get("declared_extension"))),
        ("Detected type", f"{_e(det.get('mime'))} <span class='muted'>{_e(det.get('name'))}</span>"),
        ("Type match", _e(disc.get("status"))),
        ("Size", _e(orig.get("size_bytes")) + " bytes"),
        ("SHA-256", f"<code>{_e(orig.get('sha256'))}</code>"),
        ("State", _e(manifest.get("state"))),
        ("Modules run", _e(", ".join(summary.get("modules_run", [])))),
    ])

    sev_chips = " ".join(
        f"<span class='chip' style='border-color:{_SEV_COLOR[s]};color:{_SEV_COLOR[s]}'>{sev_counts[s]} {s}</span>"
        for s in _SEV_ORDER if sev_counts[s])
    ioc_total = (iocs or {}).get("counts", {}).get("total", 0)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DocuTraceX report — {_e(orig.get('filename'))}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1016; color:#e6edf3; font:14px/1.5 "Segoe UI",system-ui,sans-serif; margin:0; padding:32px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }} h2 {{ font-size:17px; margin:28px 0 10px; border-bottom:1px solid #263040; padding-bottom:6px; }}
  .muted {{ color:#8a98ab; font-size:12px; }}
  table {{ width:100%; border-collapse:collapse; margin:8px 0; font-size:13px; }}
  th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #1c2430; vertical-align:top; }}
  th {{ color:#8a98ab; font-weight:600; }}
  code {{ font-family:"Cascadia Code",Consolas,monospace; color:#b9c6d6; word-break:break-all; }}
  .chip {{ display:inline-block; border:1px solid #3a4658; border-radius:10px; padding:1px 9px; font-size:12px; color:#9bb0c9; }}
  .evidence {{ margin-top:5px; padding:5px 8px; background:#0b0e12; border:1px solid #1c2430; border-radius:6px; font-family:"Cascadia Code",Consolas,monospace; font-size:12px; white-space:pre-wrap; word-break:break-all; }}
  .summary-chips {{ display:flex; gap:8px; flex-wrap:wrap; margin:10px 0; }}
  .nnode {{ margin:8px 0; }} .nfind {{ margin:3px 0 3px 16px; font-size:12px; color:#b9c6d6; }}
  .nchildren {{ margin-left:16px; padding-left:10px; border-left:2px solid #263040; }}
  @media print {{ body {{ background:#fff; color:#000; }} .evidence,code {{ color:#111; }} }}
</style></head><body>
<h1>DocuTraceX — static forensic report</h1>
<div class="muted">Generated {_now()} · analysis {_e(analysis_id)}</div>
<div class="summary-chips">{sev_chips or "<span class='chip'>no confirmed findings</span>"}
  <span class="chip">{tp_count} confirmed (TP)</span>
  <span class="chip">{len(findings)} total reviewed</span>
  <span class="chip">{ioc_total} IOCs</span></div>
<h2>Case</h2>
<table><tbody>{header_rows}</tbody></table>
<h2>Confirmed findings — True positive ({tp_count} of {len(findings)})</h2>
<p class="muted">This report lists only the findings marked <b>True positive</b>, from any source (YARA included). The other {len(findings) - tp_count} finding(s) were reviewed and not confirmed.</p>
{_findings_section(tp_findings)}
<h2>Indicators of compromise ({ioc_total})</h2>
{_iocs_section(iocs)}
{_ml_section(_ml_enriched(paths), marks_service.read_marks(paths))}
{_nested_section(modules.get('nested'))}
{_metadata_section(modules)}
<div class="muted" style="margin-top:32px">DocuTraceX · static analysis only — nothing in the sample was executed.</div>
</body></html>"""
