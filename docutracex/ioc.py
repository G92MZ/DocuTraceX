"""Common IOC extractor.

Runs as a single phase AFTER all parsers, over the textual/structured data they
produced (reconstructed text, metadata, field codes, formulas, relationship
targets, ...). It detects IPv4/IPv6, URLs, domains and hash-like strings,
normalizes and deduplicates them while keeping every occurrence with its
provenance, and never contacts the network or executes anything.

Hashes computed by the app to identify files/components are kept separate from
hash-like strings found in content: this module only reports the latter, tagged
as "hash_like".
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

# --- patterns ---------------------------------------------------------------
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]}]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])",
    re.IGNORECASE,
)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

# Extensions that look like "label.tld" but are filenames, not domains.
_FILE_TLDS = {
    "xml", "rels", "bin", "png", "jpeg", "jpg", "gif", "emf", "wmf", "bmp", "tiff",
    "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb",
    "pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam", "sldx", "sldm",
    "doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "pdf", "eml", "emlx", "msg",
    "txt", "json", "html", "htm", "css", "js", "exe", "dll", "zip", "jar", "mgc",
}
_CONTEXT = 32


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)]}'\"")


def _domain_of(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
        return host.lower() if host else None
    except ValueError:
        return None


def _looks_like_filename(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in _FILE_TLDS


class _Collector:
    def __init__(self) -> None:
        self.iocs: dict[tuple[str, str], dict[str, Any]] = {}

    def add(self, ioc_type: str, value: str, module: str, location: str, context: str) -> None:
        key = (ioc_type, value)
        entry = self.iocs.get(key)
        occ = {"module": module, "location": location, "context": context}
        if entry is None:
            self.iocs[key] = {"type": ioc_type, "value": value, "occurrences": [occ]}
        else:
            entry["occurrences"].append(occ)

    def result(self) -> dict[str, Any]:
        iocs = sorted(self.iocs.values(), key=lambda i: (i["type"], i["value"]))
        for i in iocs:
            i["count"] = len(i["occurrences"])
        counts: dict[str, int] = {}
        for i in iocs:
            counts[i["type"]] = counts.get(i["type"], 0) + 1
        counts["total"] = len(iocs)
        return {"iocs": iocs, "counts": counts}


def _ctx(text: str, start: int, end: int) -> str:
    a = max(0, start - _CONTEXT)
    b = min(len(text), end + _CONTEXT)
    snippet = text[a:b].replace("\n", " ").strip()
    return snippet


def _scan_text(text: str, module: str, location: str, col: _Collector) -> None:
    if not text:
        return
    # URLs first (and derive their domains).
    url_spans: list[tuple[int, int]] = []
    for m in _URL_RE.finditer(text):
        url = _clean_url(m.group(0))
        url_spans.append((m.start(), m.start() + len(url)))
        col.add("url", url, module, location, _ctx(text, m.start(), m.end()))
        dom = _domain_of(url)
        if dom and not _looks_like_filename(dom):
            col.add("domain", dom, module, location, _ctx(text, m.start(), m.end()))

    for m in _IPV4_RE.finditer(text):
        if _valid_ipv4(m.group(0)):
            col.add("ipv4", m.group(0), module, location, _ctx(text, m.start(), m.end()))

    for m in _IPV6_RE.finditer(text):
        # Require at least one group separator run to reduce false positives.
        if m.group(0).count(":") >= 2:
            col.add("ipv6", m.group(0).lower(), module, location, _ctx(text, m.start(), m.end()))

    for m in _HASH_RE.finditer(text):
        col.add("hash_like", m.group(0).lower(), module, location, _ctx(text, m.start(), m.end()))

    # Standalone domains (skip those inside a URL span or that are filenames).
    for m in _DOMAIN_RE.finditer(text):
        if any(s <= m.start() < e for s, e in url_spans):
            continue
        dom = m.group(1).lower()
        if _looks_like_filename(dom):
            continue
        col.add("domain", dom, module, location, _ctx(text, m.start(), m.end()))


def extract(sources: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract IOCs from a list of {module, location, text} sources."""
    col = _Collector()
    for src in sources:
        _scan_text(src.get("text") or "", src.get("module", ""), src.get("location", ""), col)
    return col.result()


# --- building sources from parser sub-results --------------------------------

def sources_from_modules(modules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Collect text sources to scan from each parser's sub-result."""
    sources: list[dict[str, Any]] = []

    def add(module: str, location: str, text: Any) -> None:
        if isinstance(text, str) and text.strip():
            sources.append({"module": module, "location": location, "text": text})

    # OOXML engine: external relationship targets.
    ooxml = modules.get("ooxml")
    if ooxml:
        for r in ooxml.get("relationships", []):
            if r.get("mode") == "External" and r.get("target"):
                add("ooxml", r.get("rels_file", "relationship"), r["target"])

    # Office semantic parsers.
    for mod_name in ("word", "excel", "powerpoint"):
        mod = modules.get(mod_name)
        if not mod:
            continue
        add(mod_name, "text", mod.get("text_sample"))
        for fc in mod.get("field_codes", []) or []:
            add(mod_name, "field_code", fc)
        for fx in mod.get("formulas", []) or []:
            add(mod_name, "formula", fx)
        meta = mod.get("metadata") or {}
        for k, v in meta.items():
            if isinstance(v, str):
                add(mod_name, f"metadata/{k}", v)

    # oletools suite: VBA macro source and DDE links.
    ole = modules.get("oletools")
    if ole:
        if ole.get("code_text"):
            add("oletools", "vba_code", ole["code_text"])
        for link in ole.get("dde_links", []) or []:
            add("oletools", "dde_link", link)

    # XLMMacroDeobfuscator: deobfuscated Excel 4.0 (XLM) formulas.
    xlm = modules.get("xlmdeobf")
    if xlm and xlm.get("code_text"):
        add("xlmdeobf", "xlm_formula", xlm["code_text"])

    # PDF: reconstructed text and the URIs found in the body/actions.
    pdf = modules.get("pdf")
    if pdf:
        add("pdf", "text", pdf.get("text_sample"))
        for u in pdf.get("uris", []) or []:
            add("pdf", "uri", u)

    # Email: body, header values, Received hops and attachment names.
    email = modules.get("email")
    if email:
        add("email", "body", email.get("body_sample"))
        for h in email.get("headers", []) or []:
            if h.get("name") in ("Received", "Received-SPF", "Authentication-Results",
                                 "Return-Path", "Reply-To", "From", "To", "X-Mailer"):
                add("email", f"header/{h['name']}", h.get("value"))
        for hop in email.get("received_chain", []) or []:
            for key in ("from", "by", "ip"):
                add("email", f"received/{key}", hop.get(key))
        for att in email.get("attachments", []) or []:
            add("email", "attachment_name", att.get("filename"))
    return sources
