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

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

# --- patterns ---------------------------------------------------------------
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]}]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 candidates (full or "::"-compressed); each one is then validated with
# ipaddress, which rejects look-alikes such as times ("15:56:42") or MACs.
_IPV6_RE = re.compile(r"(?<![\w:.])(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}(?![\w:])", re.IGNORECASE)
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
    "rtf", "txt", "json", "html", "htm", "css", "js", "exe", "dll", "zip", "jar", "mgc",
}
_CONTEXT = 32

# Standalone "label.tld" matches must end in a real TLD: any two-letter ccTLD or
# one of these generic ones. Keeps code (``x.Open``, ``MSXML2.XMLHTTP``) and
# text joins (``invoice.Loading``) out of the domain list. URLs are always kept.
_GENERIC_TLDS = set("""
com net org info biz edu gov mil int arpa name pro aero coop museum mobi asia tel travel jobs cat
xyz top online site club app dev cloud store shop live life world today tech space website fun
icu vip work link click download zip mov win bid loan date racing review stream trade party
science cricket faith accountant men gdn kim ooo rest host press email news blog page one
digital network center company solutions services agency group media studio design support
systems software email services finance financial bank money pay cash credit capital fund
academy education school college university global international ltd llc inc gmbh
microsoft google apple amazon office windows live azure aws
example test invalid localhost local onion
""".split())

# XML namespace / schema hosts: never indicators.
_NAMESPACE_HOSTS = {"schemas.microsoft.com", "schemas.openxmlformats.org", "www.w3.org", "w3.org",
                    "purl.org", "ns.adobe.com", "schemas.xmlsoap.org", "www.microsoft.com/office"}
_VERSION_BEFORE = re.compile(r"(?i)(?:version|ver|v)\s*[=:]?\s*[\"']?$")


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _valid_ipv6(value: str) -> str | None:
    """Normalized IPv6 address, or None if ``value`` is not one (e.g. a time)."""
    if not any(c.isalnum() for c in value):
        return None
    try:
        return ipaddress.IPv6Address(value).compressed
    except ValueError:
        return None


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)]}'\"")


def _domain_of(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
        return host.lower() if host else None
    except ValueError:
        return None


def _is_gateway(domain: str) -> bool:
    """Link-rewriting hosts of mail gateways: their URL is kept, the domain is noise."""
    return domain in ("urldefense.com", "urldefense.proofpoint.com", "linkprotect.cudasvc.com") or \
        domain.endswith(("safelinks.protection.outlook.com", ".mimecast.com"))


# In code (JS/VBA/p-code/formulas) "obj.member" looks like a domain: there,
# only the most common TLDs count ("a.download", "x.click" are code).
_CODE_TLDS = {"com", "net", "org", "info", "biz", "io", "co", "gov", "edu", "mil", "int", "xyz",
              "top", "online", "site", "club", "app", "dev", "example", "test", "onion", "ru", "cn"}
_CODE_LOCATION = re.compile(r"code|vba|sandbox|decoded|pcode|formula|xlm|macro|script", re.IGNORECASE)


def _known_tld(domain: str, strict: bool = False) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld.startswith("xn--"):
        return True
    if strict:
        return tld in _CODE_TLDS or (len(tld) == 2 and len(domain.split(".")) >= 3)
    return len(tld) == 2 or tld in _GENERIC_TLDS


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
        dom = _domain_of(url)
        if dom in _NAMESPACE_HOSTS:
            continue
        col.add("url", url, module, location, _ctx(text, m.start(), m.end()))
        if dom and not _looks_like_filename(dom) and not _valid_ipv4(dom) and ":" not in dom \
                and not _is_gateway(dom):
            col.add("domain", dom, module, location, _ctx(text, m.start(), m.end()))

    for m in _IPV4_RE.finditer(text):
        if not _valid_ipv4(m.group(0)):
            continue
        before = text[max(0, m.start() - 14):m.start()]
        if _VERSION_BEFORE.search(before) or text[m.end():m.end() + 2][:1] == "." and \
                text[m.end() + 1:m.end() + 2].isdigit():
            continue  # a version number (version="1.0.0.0", 10.0.19041.1), not an address
        col.add("ipv4", m.group(0), module, location, _ctx(text, m.start(), m.end()))

    for m in _IPV6_RE.finditer(text):
        addr = _valid_ipv6(m.group(0))
        if addr:
            col.add("ipv6", addr, module, location, _ctx(text, m.start(), m.end()))

    for m in _HASH_RE.finditer(text):
        col.add("hash_like", m.group(0).lower(), module, location, _ctx(text, m.start(), m.end()))

    # Standalone domains (skip those inside a URL span or that are filenames).
    for m in _DOMAIN_RE.finditer(text):
        if any(s <= m.start() < e for s, e in url_spans):
            continue
        dom = m.group(1).lower()
        strict = bool(_CODE_LOCATION.search(location or "")) or module in ("javascript", "vipermonkey")
        if _looks_like_filename(dom) or not _known_tld(dom, strict) or dom in _NAMESPACE_HOSTS:
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

    # ViperMonkey: what the emulated macro did (deobfuscated URLs, commands...).
    vm = modules.get("vipermonkey")
    if vm:
        for a in vm.get("actions", []) or []:
            add("vipermonkey", f"action/{a.get('action', '')}", a.get("parameters"))
        for x in vm.get("potential_iocs", []) or []:
            add("vipermonkey", "potential_ioc", x)

    # VBA rebuilt from p-code (may differ from the visible source) and URLs that
    # oledump's HTTP heuristics recovered from obfuscated strings.
    vt = modules.get("vbatools")
    if vt:
        tools = vt.get("tools") or {}
        add("vbatools", "pcode2code", (tools.get("pcode2code") or {}).get("output"))
        add("vbatools", "http_heuristics", (tools.get("oledump plugin_http_heuristics") or {}).get("output"))

    # Own Office rules: external targets (templates, OLE objects, fields, add-ins).
    rules = modules.get("officerules")
    if rules:
        for f in rules.get("findings", []) or []:
            if f.get("rule") not in ("author_local_path", "vba_project_locked"):
                add("officerules", f"{f.get('rule')}", f.get("evidence"))

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
        for js in pdf.get("javascript", []) or []:
            add("pdf", "javascript", js.get("code"))

    # JavaScript: the code, what decoding revealed and what the sandbox recorded.
    js = modules.get("javascript")
    if js:
        for sc in js.get("scripts", []) or []:
            loc = sc.get("location", "script")
            add("javascript", f"{loc}/code", sc.get("code"))
            for d in sc.get("decoded", []) or []:
                add("javascript", f"{loc}/decoded", d.get("decoded"))
            for e in (sc.get("sandbox") or {}).get("log", []) or []:
                add("javascript", f"{loc}/sandbox", " ".join(e.get("args") or []))

    # Email rules: original destinations behind gateway-rewritten links, QR codes.
    mr = modules.get("mailrules")
    if mr:
        for d in mr.get("decoded_urls", []) or []:
            add("mailrules", "decoded_link", d.get("original"))
        for c in mr.get("qr", []) or []:
            add("mailrules", f"qr/{c.get('image')}", c.get("text"))

    # RTF: visible text, field instructions (INCLUDEPICTURE/HYPERLINK...), the
    # attached template and the targets the object rules recovered (OLE2Link).
    rtf = modules.get("rtf")
    if rtf:
        add("rtf", "text", rtf.get("text"))
        for i, fl in enumerate(rtf.get("fields", []) or [], 1):
            add("rtf", f"field#{i}", fl.get("instr"))
        add("rtf", "template", rtf.get("template"))
        for f in rtf.get("findings", []) or []:
            if f.get("rule") in ("ole2link", "remote_template", "unc_file_target"):
                add("rtf", f.get("rule"), f.get("evidence"))

    # PDF tools: decoded QR codes and the targets of the own PDF rules.
    pt = modules.get("pdftools")
    if pt:
        for c in pt.get("qr", []) or []:
            add("pdftools", f"qr/page {c.get('page')}", c.get("text"))
        for f in pt.get("findings", []) or []:
            if f.get("rule") in ("form_submits_externally", "launch_command"):
                add("pdftools", f.get("rule"), f.get("evidence"))

    # Email: message content only (plain-text body, HTML body as text and its links).
    # Headers, Received hops and attachment names are deliberately not scanned.
    email = modules.get("email")
    if email:
        add("email", "body", email.get("body_sample"))
        add("email", "body_html", email.get("html_text_sample"))
        for link in email.get("html_links", []) or []:
            add("email", "body_html_link", link)
    return sources
