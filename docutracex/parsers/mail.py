"""Email parser: .eml / .emlx (RFC 822) and .msg (Outlook MAPI over OLE).

All static, no network and nothing executed:
- .eml / .emlx : Python's stdlib ``email`` (``.emlx`` has its Apple byte-count
  prefix and trailing plist stripped first, reusing the structure recognizer).
- .msg         : minimal MAPI-over-OLE reader built on ``olefile`` (BSD; already
  present via oletools) — no GPL ``extract-msg`` dependency. The Outlook message
  carries the full RFC 822 headers in the transport-headers MAPI stream, so the
  same header/auth/spoofing analysis runs for both families. The HTML body comes
  from PR_HTML or, failing that, is de-encapsulated from the compressed RTF
  (see ``msg_rtf``).

Surfaces: the Received hop chain (origin -> destination, with inter-hop Δt),
authentication results (SPF/DKIM/DMARC as stated in the headers — not re-checked
against DNS), sender/recipient mismatches, the MIME structure, body sample and
extracted attachments (hashed, type-identified, flagged).
"""

from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from datetime import datetime
from email import message_from_bytes, message_from_string
from email.message import Message
from email.policy import default as _POLICY
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any

from ..logging_config import get_logger
from ..structure import looks_like_emlx  # noqa: F401  (kept for symmetry)

log = get_logger(__name__)

_BODY_SAMPLE = 20000
_MAX_ATTACH = 200
_MAX_HOPS = 100

# MAPI property tags (stream suffixes). Prefer the Unicode (001F) variants.
_MAPI = {
    "subject": ("0037001F", "0037001E"),
    "transport_headers": ("007D001F", "007D001E"),
    "body": ("1000001F", "1000001E"),
    "html": ("10130102", "1013001F", "1013001E"),
    "rtf_compressed": ("10090102",),
    "sender_name": ("0C1A001F", "0C1A001E"),
    "sender_email": ("5D01001F", "5D01001E", "0C1F001F", "0C1F001E"),
    "display_to": ("0E04001F", "0E04001E"),
}
_MAPI_RECIP_EMAIL = ("39FE001F", "39FE001E", "3003001F", "3003001E")
_MAPI_RECIP_NAME = ("3001001F", "3001001E")
_MAPI_ATTACH_NAME = ("3707001F", "3707001E", "3704001F", "3704001E")
_MAPI_ATTACH_DATA = "37010102"


def _finding(rule: str, severity: str, detail: str, location: str = "headers") -> dict[str, Any]:
    return {"rule": rule, "severity": severity, "detail": detail, "location": location}


# --- Received chain ----------------------------------------------------------

_RE_FROM = re.compile(r"\bfrom\s+([^\s;()]+)", re.IGNORECASE)
_RE_BY = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
_RE_WITH = re.compile(r"\bwith\s+([A-Z0-9./]+)", re.IGNORECASE)
_RE_IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\]")


def _parse_received(values: list[str]) -> list[dict[str, Any]]:
    """Parse Received headers into chronological hops (origin first) with Δt."""
    hops: list[dict[str, Any]] = []
    # Received headers are prepended on each hop; reverse for origin -> destination.
    for raw in reversed(values[:_MAX_HOPS]):
        flat = " ".join(raw.split())
        ts = None
        dt = None
        if ";" in flat:
            tail = flat.rsplit(";", 1)[1].strip()
            try:
                dt = parsedate_to_datetime(tail)
                ts = tail
            except (TypeError, ValueError, IndexError):
                ts = tail or None
        m_from = _RE_FROM.search(flat)
        # gmzpt
        m_by = _RE_BY.search(flat)
        m_with = _RE_WITH.search(flat)
        m_ip = _RE_IP.search(flat)
        hops.append({
            "from": m_from.group(1) if m_from else "",
            "by": m_by.group(1) if m_by else "",
            "with": m_with.group(1) if m_with else "",
            "ip": m_ip.group(1) if m_ip else "",
            "timestamp": ts or "",
            "_dt": dt,
        })
    # Inter-hop delta (seconds), from the previous hop's time.
    prev = None
    for h in hops:
        dt = h.pop("_dt", None)
        if isinstance(dt, datetime) and isinstance(prev, datetime):
            try:
                h["delta_seconds"] = int((dt - prev).total_seconds())
            except (OverflowError, ValueError):
                h["delta_seconds"] = None
        else:
            h["delta_seconds"] = None
        if isinstance(dt, datetime):
            prev = dt
    return hops


# --- address helpers ---------------------------------------------------------

def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def _first_addr(value: str | None) -> tuple[str, str]:
    """Return (display_name, email) for the first address in a header value."""
    if not value:
        return "", ""
    pairs = getaddresses([value])
    if not pairs:
        return "", ""
    name, addr = pairs[0]
    return name.strip(), addr.strip().lower()


# --- header / auth / spoofing analysis (shared by .eml and .msg) -------------

def _analyze_message(msg: Message, result: dict[str, Any]) -> None:
    headers = [{"name": k, "value": v} for k, v in msg.items()]
    result["headers"] = headers[:500]

    hops = _parse_received(msg.get_all("Received", []))
    result["received_chain"] = hops
    result["hop_count"] = len(hops)

    # Authentication results, as stated in the headers (no DNS re-check).
    auth = {}
    ar = msg.get_all("Authentication-Results", [])
    joined = " ".join(ar).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", joined)
        if m:
            auth[mech] = m.group(1)
    if msg.get("Received-SPF"):
        auth.setdefault("spf", (msg.get("Received-SPF").split() or ["?"])[0].lower())
    auth["dkim_signature_present"] = bool(msg.get("DKIM-Signature"))
    result["authentication"] = auth
    for mech in ("spf", "dkim", "dmarc"):
        if auth.get(mech) in ("fail", "softfail"):
            sev = "high" if auth[mech] == "fail" else "medium"
            result["findings"].append(_finding(f"{mech}_{auth[mech]}", sev,
                                                f"{mech.upper()} = {auth[mech]}", "authentication"))

    from_name, from_addr = _first_addr(msg.get("From"))
    _, return_path = _first_addr(msg.get("Return-Path"))
    _, reply_to = _first_addr(msg.get("Reply-To"))
    _, sender = _first_addr(msg.get("Sender"))
    result["addresses"] = {
        "from": from_addr, "from_display": from_name, "return_path": return_path,
        "reply_to": reply_to, "sender": sender,
        "to": [a for _, a in getaddresses(msg.get_all("To", [])) if a],
        "subject": msg.get("Subject", ""),
        "message_id": msg.get("Message-ID", ""),
        "date": msg.get("Date", ""),
        "x_mailer": msg.get("X-Mailer", "") or msg.get("User-Agent", ""),
    }

    if from_addr and return_path and _domain(from_addr) != _domain(return_path):
        result["findings"].append(_finding("from_returnpath_mismatch", "medium",
            f"From domain ({_domain(from_addr)}) != Return-Path domain ({_domain(return_path)})"))
    if from_addr and reply_to and _domain(from_addr) != _domain(reply_to):
        result["findings"].append(_finding("replyto_mismatch", "low",
            f"Reply-To domain ({_domain(reply_to)}) != From domain ({_domain(from_addr)})"))
    # Display-name that itself contains a different address (classic spoof).
    m_addr_in_name = re.search(r"[\w.+-]+@([\w.-]+)", from_name or "")
    if m_addr_in_name and from_addr and m_addr_in_name.group(1).lower() != _domain(from_addr):
        result["findings"].append(_finding("display_name_spoof", "medium",
            f"From display-name shows {m_addr_in_name.group(0)} but address is {from_addr}"))


# --- MIME body + attachments (.eml) ------------------------------------------

_DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".hta", ".jar", ".ps1", ".lnk", ".iso", ".img", ".msi", ".reg",
    ".vhd", ".vhdx", ".cpl", ".scf", ".chm", ".xll", ".iqy", ".slk", ".one", ".url",
    ".appx", ".msix", ".appinstaller", ".application", ".library-ms", ".settingcontent-ms",
}
# HTML-like attachments: typical vehicle for credential phishing and HTML smuggling.
_HTML_EXT = {".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml"}
_MACRO_EXT = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam",
              ".sldm", ".xls", ".doc", ".ppt"}
# Extensions used as a decoy before the real one ("invoice.pdf.exe",
# "RFQ - xlsx.html", "scan_pdf   .js").
_DECOY_EXT = (
    "pdf doc docx docm xls xlsx xlsm xlsb csv ppt pptx pptm odt ods odp rtf txt "
    "jpg jpeg png gif bmp tif tiff heic webp mp3 mp4 wav avi mov zip rar 7z eml msg"
).split()
_RE_DOUBLE_EXT = re.compile(
    r"(?:^|([.\s_\-()\[\]]))(" + "|".join(_DECOY_EXT) + r")[\s_\-.)\]]*\.([a-z0-9_-]{1,20})$",
    re.IGNORECASE,
)
# Unicode controls used to spoof the visible extension (RTLO, zero-width, ...).
_SPOOF_CHARS = {"\u202e", "\u202d", "\u202a", "\u202b", "\u2066", "\u2067", "\u2068",
                "\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\ufeff"}


def _identify_bytes(data: bytes) -> str:
    try:
        import magic
        return magic.from_buffer(data[:4096], mime=True)
    except Exception:  # noqa: BLE001
        return ""


def _flag_attachment(name: str, result: dict[str, Any]) -> None:
    low = name.lower().strip()
    ext = ("." + low.rsplit(".", 1)[1]) if "." in low else ""
    if ext in _DANGEROUS_EXT:
        result["findings"].append(_finding("dangerous_attachment", "high",
            f"Attachment '{name}' has an executable/script extension", "attachment"))
    if ext in _HTML_EXT:
        result["findings"].append(_finding("html_attachment", "medium",
            f"Attachment '{name}' is HTML-like (credential phishing / HTML smuggling vehicle)",
            "attachment"))
    risky = ext in _DANGEROUS_EXT or ext in _HTML_EXT
    m = _RE_DOUBLE_EXT.search(low)
    # A dot always separates a decoy extension; a space/dash/underscore
    # ("RFQ - xlsx.html") only counts when the real extension is risky.
    if m and m.group(2) != m.group(3) and (m.group(1) == "." or risky):
        severity = "high" if risky else "medium"
        result["findings"].append(_finding("double_extension", severity,
            f"Attachment '{name}' uses a double extension (looks like .{m.group(2)}, "
            f"is {ext or 'no extension'})", "attachment"))
    elif re.search(r"\s{3,}\.[a-z0-9]{1,20}$", low):
        result["findings"].append(_finding("double_extension", "high",
            f"Attachment '{name}' pads the name with whitespace to hide its extension",
            "attachment"))
    if any(c in name for c in _SPOOF_CHARS):
        result["findings"].append(_finding("filename_spoofing", "high",
            f"Attachment '{name}' contains Unicode direction/invisible characters "
            "that can disguise its real extension", "attachment"))
    if ext in _MACRO_EXT:
        result["findings"].append(_finding("macro_capable_attachment", "medium",
            f"Attachment '{name}' is a macro-capable Office type", "attachment"))


def _collect_attachment(name: str, data: bytes, extracted_dir: Path | None,
                        result: dict[str, Any]) -> None:
    rec: dict[str, Any] = {
        "filename": name or "(unnamed)",
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "detected_mime": _identify_bytes(data),
    }
    if extracted_dir is not None:
        out_dir = extracted_dir / "attachments"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name or "attachment")[:120] or "attachment"
        dest = out_dir / f"{len(result['attachments']):02d}_{safe}"
        try:
            dest.write_bytes(data)
            rec["stored_path"] = dest.relative_to(extracted_dir.parent).as_posix()
        except OSError as exc:
            rec["store_error"] = str(exc)
    result["attachments"].append(rec)
    _flag_attachment(name or "", result)


def _analyze_eml_body(msg: Message, extracted_dir: Path | None, result: dict[str, Any]) -> None:
    texts: list[str] = []
    html: list[str] = []
    structure: list[str] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        structure.append(ctype)
        disp = (part.get_content_disposition() or "")
        if part.is_multipart():
            continue
        if disp == "attachment" or part.get_filename():
            if len(result["attachments"]) >= _MAX_ATTACH:
                continue
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001
                payload = b""
            _collect_attachment(part.get_filename() or "", payload, extracted_dir, result)
            continue
        try:
            body = part.get_content()
        except Exception:  # noqa: BLE001
            body = ""
        if ctype == "text/plain":
            texts.append(str(body))
        elif ctype == "text/html":
            html.append(str(body))
    result["mime_structure"] = structure
    text = "\n".join(texts)
    result["body_sample"] = text[:_BODY_SAMPLE]
    result["body_length"] = len(text)
    _set_html_body("\n".join(html), result)


def _set_html_body(html_text: str, result: dict[str, Any]) -> None:
    """Store the HTML body interpreted as text, its links and a source sample."""
    result["has_html"] = bool(html_text.strip())
    if not result["has_html"]:
        return
    result["html_text_sample"] = _html_to_text(html_text)[:_BODY_SAMPLE]
    result["html_source_sample"] = html_text[:_BODY_SAMPLE]
    result["html_links"] = list(dict.fromkeys(_RE_HREF.findall(html_text)))[:_MAX_LINKS]
    _html_link_mismatch(html_text, result)


class _HtmlToText(HTMLParser):
    """Static HTML -> readable text (no scripts run, nothing fetched)."""

    _BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6",
              "table", "ul", "ol", "blockquote", "hr", "section", "article"}
    _SKIP = {"script", "style", "head", "title", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0
        self._href: list[str | None] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip += 1
        elif tag in self._BLOCK:
            self.parts.append("\n")
        if tag == "a":
            # AeWckx3pKh
            self._href.append(dict(attrs).get("href"))
        elif tag == "img":
            alt = dict(attrs).get("alt")
            if alt and not self._skip:
                self.parts.append(f"[image: {alt}]")

    def handle_endtag(self, tag):
        if tag in self._SKIP:
            self._skip = max(0, self._skip - 1)
        elif tag in self._BLOCK:
            self.parts.append("\n")
        if tag == "a" and self._href:
            href = self._href.pop()
            if href and not self._skip and not href.lower().startswith("mailto:"):
                self.parts.append(f" <{href}>")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts).replace("\xa0", " ")
        lines = [re.sub(r"[ \t\r\f\v]+", " ", ln).strip() for ln in raw.split("\n")]
        return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def _html_to_text(html: str) -> str:
    if not html:
        return ""
    parser = _HtmlToText()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001
        pass
    return parser.text()


_RE_HREF = re.compile(r'href=["\']?((?:https?|ftp)://[^"\'>\s]+)', re.IGNORECASE)
_MAX_LINKS = 500
_RE_ANCHOR = re.compile(r'<a\s[^>]*href=["\']?(https?://[^"\'>\s]+)["\']?[^>]*>(.*?)</a>',
                        re.IGNORECASE | re.DOTALL)


def _html_link_mismatch(html: str, result: dict[str, Any]) -> None:
    if not html:
        return
    from .. import urlwrap

    for href, text in _RE_ANCHOR.findall(html)[:200]:
        shown = re.search(r"https?://([\w.-]+)", re.sub(r"<[^>]+>", "", text or ""))
        if shown:
            chain = urlwrap.unwrap_all(href)   # compare with the real destination,
            if chain:                          # not the mail gateway's wrapper
                href = chain[-1][1]
            href_host = re.search(r"https?://([\w.-]+)", href)
            if href_host and shown.group(1).lower() != href_host.group(1).lower():
                result["findings"].append(_finding("url_display_mismatch", "medium",
                    f"Link text shows {shown.group(1)} but points to {href_host.group(1)}", "body"))


# --- .msg (MAPI over OLE) ----------------------------------------------------

def _mapi_stream(ole, path_prefix: str, suffixes) -> bytes | None:
    for suf in suffixes:
        name = f"{path_prefix}__substg1.0_{suf}"
        parts = name.split("/")
        if ole.exists(parts):
            try:
                with ole.openstream(parts) as s:
                    return s.read()
            except Exception:  # noqa: BLE001
                return None
    return None


def _mapi_text(ole, prefix: str, suffixes) -> str:
    raw = _mapi_stream(ole, prefix, suffixes)
    if raw is None:
        return ""
    # 001F streams are UTF-16-LE; 001E are 8-bit.
    try:
        return raw.decode("utf-16-le").rstrip("\x00") if b"\x00" in raw[:4] or len(raw) % 2 == 0 \
            else raw.decode("latin-1")
    except Exception:  # noqa: BLE001
        return raw.decode("latin-1", "replace")


def _msg_html(ole) -> str:
    """HTML body of a .msg: PR_HTML, else HTML encapsulated in the compressed RTF."""
    from . import msg_rtf

    for suf in _MAPI["html"]:
        raw = _mapi_stream(ole, "", (suf,))
        if raw:
            if suf.endswith("0102"):
                return msg_rtf.decode_html_bytes(raw)
            # ref: iOA1JtNL0m
            return _mapi_text(ole, "", (suf,))
    raw = _mapi_stream(ole, "", _MAPI["rtf_compressed"])
    if raw:
        # ref: gmzpt
        try:
            return msg_rtf.html_from_rtf(msg_rtf.decompress_rtf(raw))
        except Exception:  # noqa: BLE001
            return ""
    return ""


def _parse_msg(path: Path, extracted_dir: Path | None, result: dict[str, Any]) -> None:
    import olefile

    if not olefile.isOleFile(str(path)):
        result["status"] = "error"
        result["findings"].append(_finding("not_ole", "high", "Not a valid OLE/.msg container"))
        return
    ole = olefile.OleFileIO(str(path))
    try:
        entries = ["/".join(e) if isinstance(e, list) else e for e in ole.listdir(streams=True, storages=True)]
        result["ole_entries"] = sorted(entries)[:500]

        headers = _mapi_text(ole, "", _MAPI["transport_headers"])
        subject = _mapi_text(ole, "", _MAPI["subject"])
        body = _mapi_text(ole, "", _MAPI["body"])

        # Reuse the full header/auth analysis when transport headers exist.
        if headers.strip():
            msg = message_from_string(headers, policy=_POLICY)
            if subject and not msg.get("Subject"):
                msg["Subject"] = subject
            _analyze_message(msg, result)
        else:
            # Minimal view from MAPI props when headers are absent.
            sender = _mapi_text(ole, "", _MAPI["sender_email"])
            result["headers"] = []
            result["received_chain"] = []
            result["hop_count"] = 0
            result["authentication"] = {}
            result["addresses"] = {"from": sender.lower(), "subject": subject,
                                   "from_display": _mapi_text(ole, "", _MAPI["sender_name"])}

        result["mime_structure"] = ["message/rfc822 (MAPI)"]
        result["body_sample"] = body[:_BODY_SAMPLE]
        result["body_length"] = len(body)
        _set_html_body(_msg_html(ole), result)

        # Recipients and attachments live in __recip_*/__attach_* storages.
        for entry in ole.listdir(streams=False, storages=True):
            top = entry[0] if isinstance(entry, list) else entry
            if top.lower().startswith("__attach_") and len(result["attachments"]) < _MAX_ATTACH:
                name = _mapi_text(ole, f"{top}/", _MAPI_ATTACH_NAME)
                data = b""
                data_parts = [top, f"__substg1.0_{_MAPI_ATTACH_DATA}"]
                if ole.exists(data_parts):
                    try:
                        with ole.openstream(data_parts) as s:
                            data = s.read()
                    except Exception:  # noqa: BLE001
                        data = b""
                _collect_attachment(name or top, data, extracted_dir, result)
    finally:
        ole.close()


# --- entry point -------------------------------------------------------------

def analyze(original_path: Path, declared_ext: str,
            extracted_dir: Path | None = None) -> dict[str, Any] | None:
    """Analyze an email file. Returns the sub-result (module 'email')."""
    ext = (declared_ext or "").lower()
    result: dict[str, Any] = {
        "module": "email", "format": "email", "status": "ok",
        "headers": [], "received_chain": [], "hop_count": 0,
        "authentication": {}, "addresses": {}, "mime_structure": [],
        "body_sample": "", "body_length": 0, "has_html": False, "html_links": [],
        "html_text_sample": "", "html_source_sample": "",
        "attachments": [], "findings": [],
    }
    try:
        if ext == ".msg":
            _parse_msg(original_path, extracted_dir, result)
        else:
            raw = original_path.read_bytes()
            if ext == ".emlx":
                nl = raw.find(b"\n")
                if nl != -1 and raw[:nl].strip().isdigit():
                    count = int(raw[:nl].strip())
                    raw = raw[nl + 1: nl + 1 + count]
            msg = message_from_bytes(raw, policy=_POLICY)
            _analyze_message(msg, result)
            _analyze_eml_body(msg, extracted_dir, result)
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["findings"].append(_finding("parse_error", "medium", f"Email parse failed: {exc}"))

    result["attachment_count"] = len(result["attachments"])
    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"] and result["status"] == "ok":
        result["status"] = "ok_with_findings"
    return result
