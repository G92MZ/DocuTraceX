"""PDF tools and DocuTraceX's own PDF rules, alongside the raw-scan PDF parser.

Tools (separate processes, time limits, raw output kept):
- peepdf-3 (GPL-3.0, run as a tool): per-version objects, triggers
  (/OpenAction, /AA, /Names), actions (/JS, /Launch...), suspicious elements
  and the CVEs it associates with them. Run with -m (no automatic JavaScript
  execution) on a copy in a temp folder, so it writes nothing next to the case.
- pdf-parser (Didier Stevens): targeted dumps of the objects carrying each
  dangerous keyword (/JS, /OpenAction, /Launch, /EmbeddedFile, /URI, ...).
- pdfid -e (extended): counts incl. obfuscated names and "after %%EOF" data.
- pyhanko: digital signatures (signer, time, coverage of the file).
- QR codes: pages rendered by pdfium and decoded with zxing-cpp (pdf_qr.py).

Own rules: forms submitting data to external URLs (credential phishing),
/Launch commands, incremental updates that add active content or change a
signed file, phishing-lure layout (short text + link/QR), encrypted with an
empty user password, QR codes pointing to URLs.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .. import quiet, toolrun
from ..logging_config import get_logger
from .didier import didier_dir

log = get_logger(__name__)

_TARGETED = ("/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
             "/URI", "/SubmitForm", "/GoToR", "/GoToE", "/RichMedia", "/XFA")
_ACTIVE = (b"/JS", b"/JavaScript", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile",
           b"/SubmitForm", b"/GoToR", b"/RichMedia", b"/XFA")
_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.DOTALL)
_SCAN_BOUND = 30 * 1024 * 1024


def _finding(rule: str, severity: str, detail: str, location: str = "pdf", evidence: str = "") -> dict:
    return {"tool": "pdftools", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


def _py(target: str, args: list[str], shown: str, script: bool = False, timeout: int = 180,
        cwd: Path | None = None) -> dict[str, Any]:
    return toolrun.run(quiet.python_tool_cmd(target, args, script), shown, timeout=timeout,
                       cwd=cwd, extra_env=toolrun.with_package_path())


# --- tools ---------------------------------------------------------------------------

def _peepdf(path: Path, res: dict[str, Any]) -> None:
    work = Path(tempfile.mkdtemp(prefix="dtx_peepdf_"))
    try:
        copy = work / path.name
        shutil.copyfile(path, copy)
        rec = _py("peepdf", ["-f", "-l", "-g", "-j", "-m", copy.name], f"peepdf -f -l -g -j -m {path.name}",
                  timeout=240, cwd=work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    res["tools"]["peepdf"] = rec
    out = rec.get("output") or ""
    start = out.find("{")
    try:
        data = json.loads(out[start:]) if start >= 0 else {}
    except ValueError:
        data = {}
    pa = data.get("peepdf_analysis") or {}
    versions = []
    cves: list[tuple[str, str]] = []
    for adv in pa.get("advanced") or []:
        vi = adv.get("version_info") or {}
        sus = vi.get("suspicious_elements") or {}
        versions.append({
            "version": vi.get("version_number"), "type": vi.get("version_type"),
            "objects": len(vi.get("objects") or []), "js_objects": vi.get("js_objects") or [],
            "triggers": sus.get("triggers") or {}, "actions": sus.get("actions") or {},
            "elements": [e.get("name") for e in sus.get("elements") or []],
            "urls": sus.get("urls") or [],
        })
        for e in (sus.get("elements") or []) + (sus.get("js_vulns") or []):
            for cve in e.get("vuln_cve_list") or []:
                cves.append((e.get("name", ""), cve))
    res["peepdf"] = {"basic": {k: (pa.get("basic") or {}).get(k) for k in
                               ("pdf_version", "num_objects", "num_streams", "updates", "linearized", "errors")},
                     "versions": versions, "cves": sorted({f"{c} ({n})" for n, c in cves})}
    if cves:
        res["findings"].append(_finding("peepdf_known_cve", "high",
                                        f"peepdf associates {len(set(c for _, c in cves))} known CVE(s) "
                                        "with elements of this PDF", "peepdf",
                                        "\n".join(sorted({f"{c}: {n}" for n, c in cves}))[:1500]))


def _pdfparser_targeted(path: Path, res: dict[str, Any]) -> None:
    script = didier_dir() / "pdf-parser.py"
    if not script.is_file():
        return
    dumps: dict[str, Any] = {}
    for key in _TARGETED:
        rec = _py(str(script), ["--search", key, "--filter", "--raw", str(path)],
                  f"pdf-parser.py --search {key} --filter --raw {path.name}", script=True,
                  timeout=120)
        if re.search(r"^obj \d+ \d+", rec.get("output") or "", re.MULTILINE):
            dumps[key] = rec
    res["tools"].update({f"pdf-parser {k}": v for k, v in dumps.items()})


def _pdfid_extended(path: Path, res: dict[str, Any]) -> None:
    script = didier_dir() / "pdfid.py"
    if not script.is_file():
        return
    rec = _py(str(script), ["-e", str(path)], f"pdfid.py -e {path.name}", script=True, timeout=120)
    res["tools"]["pdfid -e"] = rec
    out = rec.get("output") or ""
    m = re.search(r"After last %%EOF\s+(\d+)", out)
    if m and int(m.group(1)) > 0:
        res["findings"].append(_finding("data_after_eof", "medium",
                                        f"{m.group(1)} byte(s) after the last %%EOF (appended data)",
                                        "pdfid", m.group(0)))


def _signatures(path: Path, res: dict[str, Any]) -> None:
    sigs: list[dict[str, Any]] = []
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        with path.open("rb") as fh:
            reader = PdfFileReader(fh, strict=False)
            for s in reader.embedded_signatures:
                rec: dict[str, Any] = {"field": s.field_name}
                try:
                    rec["signer"] = s.signer_cert.subject.human_friendly
                    rec["issuer"] = s.signer_cert.issuer.human_friendly
                except Exception:  # noqa: BLE001
                    pass
                try:
                    ts = s.self_reported_timestamp
                    rec["signing_time"] = ts.isoformat() if ts else None
                except Exception:  # noqa: BLE001
                    pass
                try:
                    rec["coverage"] = str(s.evaluate_signature_coverage()).split(".")[-1]
                except Exception as exc:  # noqa: BLE001
                    rec["coverage"] = f"unknown ({exc})"
                sigs.append(rec)
    except Exception as exc:  # noqa: BLE001
        res["signature_error"] = str(exc)
    res["signatures"] = sigs
    for s in sigs:
        if s.get("coverage") and "ENTIRE_FILE" not in s["coverage"]:
            res["findings"].append(_finding(
                "signature_not_covering_file", "medium",
                f"Signature '{s.get('field')}' does not cover the whole file "
                f"(content added after signing)", "signatures",
                f"signer: {s.get('signer', '?')}\ncoverage: {s['coverage']}"))


def _qr(path: Path, res: dict[str, Any]) -> None:
    rec = toolrun.run([sys.executable, "-m", "docutracex.parsers.pdf_qr", str(path)],
                      f"pdf_qr (pdfium + zxing-cpp) {path.name}", timeout=180,
                      extra_env=toolrun.with_package_path())
    try:
        data = json.loads(rec.get("output") or "{}")
    except ValueError:
        data = {"error": rec.get("error") or "no output"}
    res["qr"] = data.get("codes") or []
    if data.get("error") or rec.get("error"):
        res["qr_error"] = data.get("error") or rec.get("error")
    for c in res["qr"]:
        url = re.match(r"(?i)^(https?://|www\.)", c.get("text", "") or "")
        res["findings"].append(_finding(
            "qr_code_url" if url else "qr_code", "high" if url else "low",
            f"{c.get('format', 'QR')} code on page {c.get('page')}"
            + (" points to a URL (QR phishing)" if url else ""), f"page {c.get('page')}", c.get("text", "")))


# --- own rules -------------------------------------------------------------------------

def _rules(data: bytes, pdf_res: dict[str, Any], res: dict[str, Any]) -> None:
    # Forms submitting data to an external URL (credential phishing).
    for m in re.finditer(rb"/SubmitForm.{0,300}?/F\s*(?:<<.{0,200}?)?\(([^)]{4,500})\)", data, re.DOTALL):
        target = m.group(1).decode("latin-1", "replace")
        if re.match(r"(?i)https?://|mailto:", target):
            res["findings"].append(_finding("form_submits_externally", "high",
                                            "Form submits its fields to an external URL (credential phishing)",
                                            "AcroForm", target))
    for m in re.finditer(rb"<submit\b[^>]*target=\"([^\"]+)\"", data, re.IGNORECASE):
        res["findings"].append(_finding("form_submits_externally", "high",
                                        "XFA form submits its fields to an external URL",
                                        "XFA", m.group(1).decode("latin-1", "replace")))
    # /Launch with a command line.
    for m in re.finditer(rb"/Launch.{0,400}?/F\s*\(([^)]{1,300})\)(?:.{0,200}?/P\s*\(([^)]{0,500})\))?", data, re.DOTALL):
        prog = m.group(1).decode("latin-1", "replace")
        params = (m.group(2) or b"").decode("latin-1", "replace")
        sev = "high"
        res["findings"].append(_finding("launch_command", sev,
                                        f"/Launch runs '{prog}'", "Launch action",
                                        f"{prog} {params}".strip()))
    # Incremental updates: what each update adds.
    parts = re.split(rb"%%EOF", data)
    revisions = []
    offset_signed = False
    for i, seg in enumerate(parts[:-1] if len(parts) > 1 else parts):
        objs = [(m.group(1).decode(), m.group(3)) for m in _OBJ_RE.finditer(seg)]
        active = sorted({t.decode() for _, body in objs for t in _ACTIVE if t in body})
        signed = any(b"/ByteRange" in body for _, body in objs)
        revisions.append({"revision": i, "objects": len(objs), "active": active, "signed": signed})
        if i > 0 and active:
            res["findings"].append(_finding(
                "update_adds_active_content", "high",
                f"Incremental update #{i} adds active content: {', '.join(active)}",
                f"revision {i}", ", ".join(o for o, _ in objs[:30])))
        if i > 0 and offset_signed:
            res["findings"].append(_finding(
                "modified_after_signing", "medium",
                f"Incremental update #{i} after a signed revision (shadow attack / later edit)",
                f"revision {i}", f"{len(objs)} object(s) in the update"))
        offset_signed = offset_signed or signed
    res["revisions"] = revisions
    # Phishing lure: little text, a link or QR, few pages.
    pages = pdf_res.get("page_count") or 0
    text_len = pdf_res.get("text_length")
    if text_len is None:
        text_len = len(pdf_res.get("text_sample") or "")
    if 0 < pages <= 2 and text_len < 400 and (pdf_res.get("uris") or res.get("qr")):
        res["findings"].append(_finding(
            "phishing_lure_layout", "medium",
            f"Phishing-lure layout: {pages} page(s), {text_len} chars of text and a link/QR",
            "pdf", "\n".join((pdf_res.get("uris") or [])[:5] + [c.get("text", "") for c in res.get("qr", [])][:5])))
    # Encrypted with an empty user password (encryption used only to evade scanners).
    if pdf_res.get("encrypted"):
        try:
            from pypdf import PdfReader
            r = PdfReader(str(pdf_res.get("_path")), strict=False) if pdf_res.get("_path") else None
            if r is not None and r.is_encrypted and r.decrypt("") != 0:
                res["findings"].append(_finding("encrypted_empty_password", "medium",
                                                "Encrypted with an empty user password (evasion: opens without a "
                                                "password but hides content from scanners)", "Encrypt"))
        except Exception:  # noqa: BLE001
            pass


def analyze(original_path: Path, pdf_res: dict[str, Any] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "pdftools", "status": "ok", "tools": {}, "findings": [],
                           "signatures": [], "qr": [], "revisions": []}
    try:
        with original_path.open("rb") as fh:
            data = fh.read(_SCAN_BOUND)
    except OSError as exc:
        res["status"] = "error"
        res["error"] = str(exc)
        return res
    _peepdf(original_path, res)
    _pdfparser_targeted(original_path, res)
    _pdfid_extended(original_path, res)
    _signatures(original_path, res)
    _qr(original_path, res)
    _rules(data, {**(pdf_res or {}), "_path": str(original_path)}, res)
    res["counts"] = {"findings": len(res["findings"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
