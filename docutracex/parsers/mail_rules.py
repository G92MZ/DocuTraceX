"""DocuTraceX's own email rules, on top of the email parser.

- Gateway-rewritten links (Proofpoint, Safe Links, Barracuda, Mimecast...)
  decoded back to the original destination.
- Phishing in the HTML body: credential forms, forms posting elsewhere, meta
  refresh redirects, scripts, javascript: links, data: payloads, HTML smuggling
  (Blob + download), tracking pixels, zero-size/hidden text.
- Offline DKIM: the body hash (bh=) recomputed with dkimpy's canonicalization
  (detects a body modified after signing), signed-header coverage and the
  alignment of the signing domain with From. No DNS: the signature itself
  cannot be verified offline, the body hash can.
- Look-alike domains: punycode/IDN, mixed-script homoglyphs
  (confusable_homoglyphs) and near-misses of well-known brands
  (``rnicrosoft``, ``paypa1``, ``micros0ft-login``...).
- Received chain coherence: time going backwards, long delays, broken chain,
  Date header far from the first hop, private IPs after public hops.
- Sender fingerprint: mass-mailer/scripting clients, Message-ID domain vs From.
- QR codes in image attachments/inline images; emldump of each MIME part.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from datetime import datetime
from email import message_from_bytes
from email.policy import compat32
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .. import quiet, toolrun, urlwrap
from ..logging_config import get_logger
from .didier import didier_dir
from . import mail as _mail_mod
from ..config import tmo

log = get_logger(__name__)

BRANDS: dict[str, tuple[str, ...]] = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com"),
    "office365": ("office.com", "office365.com"), "outlook": ("outlook.com",),
    "onedrive": ("onedrive.live.com", "live.com"), "sharepoint": ("sharepoint.com",),
    "paypal": ("paypal.com",), "apple": ("apple.com", "icloud.com"), "icloud": ("icloud.com",),
    "amazon": ("amazon.com", "amazon.es", "amazon.de", "amazon.co.uk"), "google": ("google.com", "gmail.com"),
    "gmail": ("gmail.com",), "docusign": ("docusign.com", "docusign.net"), "dropbox": ("dropbox.com",),
    "adobe": ("adobe.com",), "dhl": ("dhl.com", "dhl.es", "dhl.de"), "fedex": ("fedex.com",),
    "ups": ("ups.com",), "linkedin": ("linkedin.com",), "netflix": ("netflix.com",),
    "wetransfer": ("wetransfer.com",), "facebook": ("facebook.com",), "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",), "santander": ("santander.com", "bancosantander.es"),
    "bbva": ("bbva.com", "bbva.es"), "caixabank": ("caixabank.com", "caixabank.es"),
    "bankinter": ("bankinter.com",), "sabadell": ("bancsabadell.com",), "ing": ("ing.com", "ing.es"),
    "correos": ("correos.es",), "agenciatributaria": ("agenciatributaria.gob.es",),
    "binance": ("binance.com",), "coinbase": ("coinbase.com",), "zoom": ("zoom.us",),
}
# Official domains of the same companies (a Microsoft brand on office.com is fine).
_OFFICIAL = {d for ds in BRANDS.values() for d in ds} | {
    "microsoft.com", "microsoftonline.com", "office.com", "office.net", "office365.com", "outlook.com",
    "live.com", "msn.com", "bing.com", "sharepoint.com", "onedrive.com", "windows.net", "azure.com",
    "microsoft365.com", "skype.com", "apple.com", "icloud.com", "me.com", "google.com", "gmail.com",
    "googleusercontent.com", "youtube.com", "amazon.com", "amazonaws.com", "paypal.com", "paypal.me",
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "linkedin.com", "lnkd.in"}
_HOMO_SUBS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"),
              ("5", "s"), ("4", "a"), ("7", "t"), ("@", "a"), ("$", "s"))
# Scripting / bulk tools typical of phishing kits. Legitimate email service
# providers (SendGrid, Mailchimp, Brevo…) are NOT here: they are a legitimacy
# signal of the verdict (mailintel.ESP_HEADERS), not a finding.
_MASS_MAILERS = ("phpmailer", "swiftmailer", "swift mailer", "python", "microsoft cdo", "the bat",
                 "leaf phpmailer", "massmail", "powermta", "atomic mail", "gammadyne", "emkei", "anonymousemail",
                 "x-php-originating-script")
# Tracking-pixel vendors (by host), shown with the finding.
_PIXEL_VENDORS = (("list-manage.com", "Mailchimp"), ("mailchimp", "Mailchimp"), ("hubspot", "HubSpot"),
                  ("hs-analytics", "HubSpot"), ("sendgrid", "SendGrid"), ("mandrillapp", "Mailchimp Transactional"),
                  ("mailgun", "Mailgun"), ("sparkpost", "SparkPost"), ("exacttarget", "Salesforce Marketing Cloud"),
                  ("sfmc", "Salesforce Marketing Cloud"), ("pardot", "Salesforce Pardot"), ("eloqua", "Oracle Eloqua"),
                  ("en25.com", "Oracle Eloqua"), ("marketo", "Marketo"), ("mktoresp", "Marketo"), ("klaviyo", "Klaviyo"),
                  ("mailjet", "Mailjet"), ("sendinblue", "Brevo"), ("brevo", "Brevo"), ("sendibt", "Brevo"),
                  ("constantcontact", "Constant Contact"), ("createsend", "Campaign Monitor"), ("cmail", "Campaign Monitor"),
                  ("yesware", "Yesware"), ("mailtrack", "Mailtrack"), ("streak", "Streak"), ("mixmax", "Mixmax"),
                  ("superhuman", "Superhuman"), ("bananatag", "Bananatag"), ("getnotify", "GetNotify"),
                  ("awstrack", "Amazon SES"), ("google-analytics", "Google Analytics"), ("pixel", "generic pixel"))
_MAX_QR_IMAGES = 15
_IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff")


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "mailrules", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


# --- links --------------------------------------------------------------------------

def _all_links(email: dict[str, Any]) -> list[str]:
    links = list(email.get("html_links") or [])
    for text in (email.get("body_sample") or "", email.get("html_text_sample") or ""):
        links += re.findall(r"https?://[^\s<>\"')\]]+", text)
    seen: set[str] = set()
    return [u for u in links if not (u in seen or seen.add(u))]


def _decode_links(links: list[str], res: dict[str, Any]) -> list[str]:
    finals = []
    for u in links:
        chain = urlwrap.unwrap_all(u)
        if chain:
            dest, services, exact = urlwrap.original(u)
            if not exact and services and services[-1].startswith("Mimecast"):
                dest = urlparse(dest).hostname or dest          # only the domain is known
            res["decoded_urls"].append({"wrapped": u, "services": services, "original": dest, "exact": exact})
            finals.append(chain[-1][1])
        else:
            finals.append(u)
    # rewritten links are the recipient's own gateways at work: legitimate, so
    # no finding — the decoded destination is kept (``decoded_urls``) and every
    # rule below judges that destination, never the wrapper
    return finals


# --- HTML body ---------------------------------------------------------------------

def analyze_html(html: str, location: str = "body") -> list[dict[str, Any]]:
    """Phishing / smuggling patterns in an HTML document (body or attachment)."""
    out: list[dict[str, Any]] = []
    if not html:
        return out
    low = html.lower()
    for m in re.finditer(r"<form\b[^>]*>", html, re.IGNORECASE):
        tag = m.group(0)
        action = re.search(r"action\s*=\s*[\"']?([^\"'\s>]+)", tag, re.IGNORECASE)
        target = action.group(1) if action else ""
        segment = low[m.start(): m.start() + 4000]
        has_pw = re.search(r"type\s*=\s*[\"']?password", segment) is not None
        if has_pw:
            out.append(_finding("html_credential_form", "high",
                                "HTML form asking for a password" + (f" posted to {target}" if target else ""),
                                location, tag[:300]))
        elif target.lower().startswith(("http:", "https:")):
            out.append(_finding("html_external_form", "medium", f"HTML form posts data to {target}",
                                location, tag[:300]))
    for m in re.finditer(r"<meta\b[^>]*http-equiv\s*=\s*[\"']?refresh[^>]*>", html, re.IGNORECASE):
        url = re.search(r"url\s*=\s*([^\"'>;\s]+)", m.group(0), re.IGNORECASE)
        # tag: MH22fELbKP
        out.append(_finding("meta_refresh_redirect", "medium",
                            "Meta refresh redirects the reader" + (f" to {url.group(1)}" if url else ""),
                            location, m.group(0)[:300]))
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL)
    ext_scripts = re.findall(r"<script\b[^>]*\bsrc\s*=\s*[\"']?([^\"'\s>]+)", html, re.IGNORECASE)
    if scripts or ext_scripts:
        out.append(_finding("html_script", "medium",
                            f"{len(scripts)} inline script(s), {len(ext_scripts)} external script(s) in HTML",
                            location, "\n".join(ext_scripts[:5]) or (scripts[0][:300] if scripts else "")))
    js_links = re.findall(r"href\s*=\s*[\"']?\s*javascript:[^\"'>]{0,200}", html, re.IGNORECASE)
    if js_links:
        out.append(_finding("javascript_link", "medium", f"{len(js_links)} javascript: link(s)",
                            location, "\n".join(js_links[:5])))
    data_uris = re.findall(r"data:(?!image/(?:png|jpe?g|gif|webp|svg\+xml))([\w.+-]+/[\w.+-]+)[^\"'\s>]{0,80}",
                           html, re.IGNORECASE)
    if data_uris:
        out.append(_finding("data_uri_payload", "high",
                            f"data: URI carrying non-image content ({', '.join(sorted(set(data_uris))[:5])})",
                            location, ", ".join(sorted(set(data_uris)))))
    smuggle = [k for k in ("new blob(", "createobjecturl", "mssaveoropenblob", ".download", "atob(",
                           "uint8array", "fromcharcode") if k in low]
    if ("new blob(" in low or "mssaveoropenblob" in low) and ("createobjecturl" in low or "mssaveoropenblob" in low):
        out.append(_finding("html_smuggling", "high",
                            "HTML smuggling: script builds a file in the browser and triggers its download",
                            location, ", ".join(smuggle)))
    pixels = re.findall(r"<img\b[^>]*(?:width\s*=\s*[\"']?[01]\b[^>]*height\s*=\s*[\"']?[01]\b|"
                        r"height\s*=\s*[\"']?[01]\b[^>]*width\s*=\s*[\"']?[01]\b)[^>]*>", html, re.IGNORECASE)
    remote_px = [p for p in pixels if re.search(r"src\s*=\s*[\"']?https?://", p, re.IGNORECASE)]
    if remote_px:
        vendors = sorted({v for px in remote_px for k, v in _PIXEL_VENDORS if k in str(px).lower()})
        out.append(_finding("tracking_pixel", "low", f"{len(remote_px)} remote 1x1 tracking image(s)"
                            + (f" — {', '.join(vendors)}" if vendors else "") + " (opening the email tells the sender)",
                            location, remote_px[0][:300]))
    hidden = re.findall(r"<[^>]+style\s*=\s*[\"'][^\"']*(?:font-size\s*:\s*0(?:px|pt)?\b|display\s*:\s*none|"
                        r"color\s*:\s*(?:#fff(?:fff)?|white)\b[^\"']*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white))",
                        html, re.IGNORECASE)
    if len(hidden) >= 2:
        out.append(_finding("hidden_text", "low",
                            f"{len(hidden)} element(s) with zero-size/hidden/invisible text (filter evasion)",
                            location, hidden[0][:300]))
    return out


# --- DKIM (offline) ----------------------------------------------------------------

def _dkim(raw: bytes, from_domain: str, res: dict[str, Any]) -> None:
    try:
        import dkim  # noqa: F401
        from dkim.canonicalization import CanonicalizationPolicy
    except Exception:  # noqa: BLE001
        return
    msg = message_from_bytes(raw, policy=compat32)
    sigs = msg.get_all("DKIM-Signature") or []
    if not sigs:
        return
    sep = raw.find(b"\r\n\r\n")
    sep_len = 4
    if sep < 0 or (raw.find(b"\n\n") >= 0 and raw.find(b"\n\n") < sep):
        sep, sep_len = raw.find(b"\n\n"), 2
    body = raw[sep + sep_len:] if sep >= 0 else b""
    body = body.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    for s in sigs:
        tags = {}
        for part in re.sub(r"\s+", "", str(s)).split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.lower()] = v
        rec: dict[str, Any] = {"domain": tags.get("d", ""), "selector": tags.get("s", ""),
                               "algorithm": tags.get("a", ""), "canonicalization": tags.get("c", "simple/simple"),
                               "signed_headers": [h.lower() for h in tags.get("h", "").split(":") if h]}
        try:
            pol = CanonicalizationPolicy.from_c_value(rec["canonicalization"].encode())
            cbody = pol.canonicalize_body(body)
            if "l" in tags:
                cbody = cbody[:int(tags["l"])]
                rec["length_limit"] = int(tags["l"])
            import hashlib
            h = hashlib.sha1 if rec["algorithm"].endswith("sha1") else hashlib.sha256
            computed = __import__("base64").b64encode(h(cbody).digest()).decode()
            rec["body_hash_ok"] = computed == tags.get("bh", "")
        except Exception as exc:  # noqa: BLE001
            rec["body_hash_ok"] = None
            rec["error"] = str(exc)
        res["dkim"].append(rec)
        loc = "DKIM-Signature"
        if rec["body_hash_ok"] is False:
            res["findings"].append(_finding("dkim_body_hash_mismatch", "high",
                                            f"DKIM body hash does not match (d={rec['domain']}): the body was "
                                            "modified after signing", loc, f"s={rec['selector']} c={rec['canonicalization']}"))
        missing = [x for x in ("subject", "date", "to") if x not in rec["signed_headers"]]
        if missing:
            res["findings"].append(_finding("dkim_weak_coverage", "low",
                                            f"DKIM signature (d={rec['domain']}) does not cover: {', '.join(missing)}",
                                            loc, "h=" + ":".join(rec["signed_headers"])))
        if "l" in tags:
            res["findings"].append(_finding("dkim_length_limit", "medium",
                                            f"DKIM l= tag: only the first {tags['l']} body bytes are signed "
                                            "(content can be appended)", loc, f"l={tags['l']}"))
        if from_domain and rec["domain"] and not (from_domain == rec["domain"].lower()
                                                  or from_domain.endswith("." + rec["domain"].lower())):
            res["findings"].append(_finding("dkim_not_aligned", "medium",
                                            f"DKIM signing domain {rec['domain']} is not aligned with From {from_domain}",
                                            loc, f"d={rec['domain']}"))


# --- look-alike domains -------------------------------------------------------------

def _registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "gob", "gov", "org", "net", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def check_domain(host: str) -> list[tuple[str, str, str]]:
    """(rule, severity, explanation) for a suspicious-looking domain."""
    out: list[tuple[str, str, str]] = []
    host = (host or "").lower().strip(".")
    if not host or re.fullmatch(r"[\d.]+|[0-9a-f:]+", host):
        return out
    uni = host
    if "xn--" in host:
        # sJkzUVgDiA
        try:
            uni = host.encode("ascii").decode("idna")
            out.append(("idn_domain", "medium", f"Internationalised (punycode) domain: {host} = {uni}"))
        except Exception:  # noqa: BLE001
            pass
    try:
        from confusable_homoglyphs import confusables
        if any(ord(c) > 127 for c in uni) and (confusables.is_mixed_script(uni) or confusables.is_dangerous(uni)):
            out.append(("homoglyph_domain", "high", f"Domain mixes look-alike characters from several scripts: {uni}"))
    except Exception:  # noqa: BLE001
        pass
    reg = _registrable(host)
    if reg in _OFFICIAL:
        return out
    label = reg.split(".")[0]
    norm = label
    for a, b in _HOMO_SUBS:
        norm = norm.replace(a, b)
    from .. import similarity
    th = similarity.thresholds()
    sub = host[: -len(reg)].rstrip(".")           # subdomains also carry brands
    words = set(re.split(r"[-_.]", f"{sub}.{norm}")) - {""}
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        hit = None
        if norm == brand and label != brand:
            hit = f"'{label}' imitates '{brand}' with look-alike characters"
        elif label != brand and (dist := similarity.lookalike_distance(norm, brand, th)):
            hit = f"'{label}' is {dist} edit{'s' if dist > 1 else ''} away from '{brand}'"
        elif len(brand) >= 4 and (brand in words or brand in norm):
            how = " with look-alike characters" if brand not in label and brand in norm else ""
            hit = f"uses the brand '{brand}'{how} in a domain that is not {brand}'s ({reg})"
        if hit:
            out.append(("lookalike_domain", "high", f"Look-alike of {brand}: {hit}"))
            break
    return out


def _lookalikes(email: dict[str, Any], links: list[str], res: dict[str, Any]) -> None:
    addrs = email.get("addresses") or {}
    targets: list[tuple[str, str]] = []
    for field in ("from", "reply_to", "return_path", "sender"):
        a = addrs.get(field) or ""
        if "@" in a:
            targets.append((field, a.rsplit("@", 1)[1]))
    for u in links:
        try:
            h = urlparse(u).hostname
        except ValueError:
            h = None
        if h:
            targets.append(("link", h))
    seen: set[tuple[str, str]] = set()
    for where, host in targets:
        for rule, sev, why in check_domain(host):
            # AeWckx3pKh
            if (rule, host) in seen:
                continue
            seen.add((rule, host))
            res["lookalikes"].append({"where": where, "domain": host, "rule": rule, "why": why})
            res["findings"].append(_finding(rule, sev, f"{why} ({where})", where, host))


# --- Received chain / sender fingerprint -----------------------------------------------

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _received(email: dict[str, Any], res: dict[str, Any]) -> None:
    hops = email.get("received_chain") or []
    for i, h in enumerate(hops):
        d = h.get("delta_seconds")
        if d is not None and d < -120:
            res["findings"].append(_finding("received_time_reversed", "medium",
                                            f"Hop {i + 1} is timestamped {abs(d)}s before the previous hop "
                                            "(forged or clock-skewed Received header)", "received", h.get("timestamp", "")))
        elif d is not None and d > 86400:
            res["findings"].append(_finding("received_long_delay", "low",
                                            f"Hop {i + 1} arrives {d // 3600}h after the previous one",
                                            "received", h.get("timestamp", "")))
    seen_public = False
    for i, h in enumerate(hops):
        ip = h.get("ip") or ""
        if ip and not _is_private(ip):
            seen_public = True
        elif ip and _is_private(ip) and seen_public and i < len(hops) - 1:
            res["findings"].append(_finding("received_private_after_public", "low",
                                            f"Hop {i + 1} shows a private IP ({ip}) after public hops",
                                            "received", f"from {h.get('from')} by {h.get('by')}"))
    # gmzpt
    for i in range(len(hops) - 1):
        by, nxt = (hops[i].get("by") or "").lower(), (hops[i + 1].get("from") or "").lower()
        if by and nxt and by != nxt and by.split(".")[-2:] != nxt.split(".")[-2:]:
            res["findings"].append(_finding("received_chain_break", "low",
                                            f"Hop {i + 1} was received by {by} but hop {i + 2} claims to come from {nxt}",
                                            "received", f"{by} -> {nxt}"))
            break
    addrs = email.get("addresses") or {}
    date = addrs.get("date") or ""
    first_ts = hops[0].get("timestamp") if hops else ""
    try:
        dd = parsedate_to_datetime(date) if date else None
        ft = parsedate_to_datetime(first_ts) if first_ts else None
        if isinstance(dd, datetime) and isinstance(ft, datetime) and abs((ft - dd).total_seconds()) > 86400:
            res["findings"].append(_finding("date_header_mismatch", "medium",
                                            "Date header is more than a day away from the first Received hop",
                                            "headers", f"Date: {date}\nfirst hop: {first_ts}"))
    except (TypeError, ValueError):
        pass


def _fingerprint(email: dict[str, Any], res: dict[str, Any]) -> None:
    addrs = email.get("addresses") or {}
    mailer = (addrs.get("x_mailer") or "").strip()
    fp: dict[str, Any] = {"mailer": mailer}
    if mailer and any(k in mailer.lower() for k in _MASS_MAILERS):
        res["findings"].append(_finding("mass_mailer_client", "low",
                                        f"Sent with a scripting / mass-mailing client: {mailer}", "headers", mailer))
    mid = addrs.get("message_id") or ""
    from_dom = (addrs.get("from") or "").rsplit("@", 1)[-1].lower() if "@" in (addrs.get("from") or "") else ""
    m = re.search(r"@([^>\s]+)>?\s*$", mid)
    fp["message_id_domain"] = m.group(1).lower() if m else ""
    if not mid:
        res["findings"].append(_finding("missing_message_id", "low", "No Message-ID header", "headers"))
    elif m and from_dom and _registrable(fp["message_id_domain"]) != _registrable(from_dom) and \
            not fp["message_id_domain"].endswith(("outlook.com", "prod.outlook.com", "mail.gmail.com",
                                                  "googlemail.com", "amazonses.com") + _mail_mod._ESP_BOUNCE):
        res["findings"].append(_finding("messageid_domain_mismatch", "low",
                                        f"Message-ID domain ({fp['message_id_domain']}) differs from From ({from_dom})",
                                        "headers", mid))
    res["fingerprint"] = fp


# --- QR codes in images ------------------------------------------------------------------

def _qr_images(email: dict[str, Any], case_root: Path | None, res: dict[str, Any]) -> None:
    if case_root is None:
        return
    imgs = [a for a in email.get("attachments") or []
            if a.get("stored_path") and ((a.get("detected_mime") or "").startswith("image/")
                                         or (a.get("filename") or "").lower().endswith(_IMG_EXT))]
    for a in imgs[:_MAX_QR_IMAGES]:
        path = case_root / a["stored_path"]
        rec = toolrun.run([sys.executable, "-m", "docutracex.parsers.pdf_qr", str(path)],
                          f"qr {a.get('filename')}", timeout=tmo(60), extra_env=toolrun.with_package_path())
        try:
            data = json.loads(rec.get("output") or "{}")
        except ValueError:
            continue
        for c in data.get("codes") or []:
            res["qr"].append({"image": a.get("filename"), "format": c.get("format"), "text": c.get("text")})
            url = re.match(r"(?i)^(https?://|www\.)", c.get("text") or "")
            res["findings"].append(_finding(
                "qr_code_url" if url else "qr_code", "high" if url else "low",
                f"QR code in image '{a.get('filename')}'" + (" points to a URL (QR phishing)" if url else ""),
                "attachment", c.get("text") or ""))


_HTML_ATT_EXT = (".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml")


def _html_attachments(email: dict[str, Any], case_root: Path | None, res: dict[str, Any]) -> None:
    """The same HTML phishing checks on HTML/SVG attachments (the usual lure)."""
    if case_root is None:
        return
    for a in email.get("attachments") or []:
        name = (a.get("filename") or "").lower().strip()
        if not a.get("stored_path") or not (name.endswith(_HTML_ATT_EXT)
                                            or "html" in (a.get("detected_mime") or "")
                                            or "svg" in (a.get("detected_mime") or "")):
            continue
        try:
            text = (case_root / a["stored_path"]).read_bytes()[:2_000_000].decode("utf-8", "replace")
        except OSError:
            continue
        loc = f"attachment:{a.get('filename')}"
        found = analyze_html(text, loc)
        for f in found:
            f["detail"] = f"[{a.get('filename')}] {f['detail']}"
        res["findings"] += found
        res["html"] += [{"rule": f["rule"], "detail": f["detail"]} for f in found]
        links = re.findall(r"https?://[^\s<>\"')\]]+", text)
        _lookalikes({"addresses": {}}, [u for u in links][:200], res)


def _emldump_parts(path: Path, ext: str, res: dict[str, Any]) -> None:
    script = didier_dir() / "emldump.py"
    if ext == ".msg" or not script.is_file():
        return
    listing = toolrun.run(quiet.python_tool_cmd(str(script), [str(path)], script=True),
                          f"emldump.py {path.name}", timeout=tmo(60), extra_env=toolrun.with_package_path())
    res["tools"]["emldump"] = listing
    for line in (listing.get("output") or "").splitlines():
        m = re.match(r"\s*(\d+):\s+\S+\s+(text/[\w.+-]+|application/[\w.+-]+|image/[\w.+-]+)", line)
        if not m or len(res["tools"]) > 10:
            continue
        idx = m.group(1)
        res["tools"][f"emldump part {idx} ({m.group(2)})"] = toolrun.run(
            quiet.python_tool_cmd(str(script), ["-s", idx, "-d", str(path)], script=True),
            f"emldump.py -s {idx} -d {path.name}", timeout=tmo(60), bound=20000,
            extra_env=toolrun.with_package_path())


# --- entry point ----------------------------------------------------------------------

def analyze(original_path: Path, declared_ext: str, email: dict[str, Any],
            case_root: Path | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "mailrules", "status": "ok", "findings": [], "decoded_urls": [],
                           "dkim": [], "lookalikes": [], "qr": [], "html": [], "tools": {}, "fingerprint": {}}
    ext = (declared_ext or "").lower()
    links = _all_links(email)
    finals = _decode_links(links, res)
    html_findings = analyze_html(email.get("html_source_sample") or "", "body")
    res["html"] = [{"rule": f["rule"], "detail": f["detail"]} for f in html_findings]
    res["findings"] += html_findings
    if ext != ".msg":
        try:
            raw = original_path.read_bytes()
            if ext == ".emlx":
                nl = raw.find(b"\n")
                if nl != -1 and raw[:nl].strip().isdigit():
                    raw = raw[nl + 1: nl + 1 + int(raw[:nl].strip())]
            from_addr = (email.get("addresses") or {}).get("from") or ""
            _dkim(raw, from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else "", res)
        except Exception as exc:  # noqa: BLE001
            res["dkim_error"] = str(exc)
    _lookalikes(email, finals, res)
    _received(email, res)
    _fingerprint(email, res)
    _qr_images(email, case_root, res)
    _html_attachments(email, case_root, res)
    _emldump_parts(original_path, ext, res)
    _engine(email, res, case_root)
    res["counts"] = {"findings": len(res["findings"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res


# --- declarative rules + verdict (mailengine) -------------------------------------------

def _rule_finding(m: dict[str, Any]) -> dict[str, Any]:
    f = _finding(m["id"], m["severity"], m["title"], "rules", m.get("evidence", ""))
    if m.get("attack"):
        f["attack"] = m["attack"]
    return f


def _signals(email: dict[str, Any], res: dict[str, Any], matched: list[dict[str, Any]],
             legit: bool) -> list[dict[str, Any]]:
    from .. import mailengine
    sig = []
    seen = set()
    for f in list(email.get("findings") or []) + [x for x in res["findings"] if x.get("location") != "rules"]:
        key = f.get("rule", "")
        if key in seen:
            continue
        seen.add(key)
        w = mailengine.weight(key, f.get("severity", "info"))
        if legit and key in ("from_returnpath_mismatch", "messageid_domain_mismatch", "replyto_mismatch",
                             "tracking_pixel", "received_long_delay"):
            w = 0                       # normal for authenticated bulk mail
        if w:
            sig.append({"id": key, "score": w, "why": f.get("detail", ""), "kind": "check"})
    for m in matched:
        if m["score"]:
            sig.append({"id": m["id"], "score": m["score"], "why": m.get("evidence") or m["title"], "kind": "rule"})
    return sig


def _engine(email: dict[str, Any], res: dict[str, Any], case_root: Path | None) -> None:
    from .. import mailengine
    try:
        f = mailengine.facts(email, res, case_root)
        fired = {x.get("rule", "") for x in list(email.get("findings") or []) + res["findings"]}
        matched = mailengine.run(f, "email", {"rules_fired": fired})
    except Exception as exc:  # noqa: BLE001  (the rules never break the email analysis)
        log.warning("email rules failed: %s", exc)
        res["engine"] = {"error": str(exc)[:300]}
        return
    for m in matched:
        if m["score"] > 0 and m["severity"] != "info":
            res["findings"].append(_rule_finding(m))
    legit = bool(f["esp"]["known"] and (f["auth"]["dkim_aligned_pass"] or f["auth"]["dmarc"] == "pass"))
    facts_view = {k: ({kk: vv for kk, vv in v.items() if kk != "all"} if isinstance(v, dict) else v)
                  for k, v in f.items()}
    res["engine"] = {"facts": facts_view, "matched": matched, "legit_bulk": legit}
    res["verdict"] = mailengine.verdict(_signals(email, res, matched, legit))


def case_stage(case_root: Path) -> dict[str, Any] | None:
    """After the whole case ran: rules over what the attachments' / links'
    analysis found, then the final verdict (written into the mailrules result,
    plus an ``email_verdict`` finding)."""
    from .. import mailengine
    from ..storage import CasePaths, read_json, write_subresult
    paths = CasePaths(case_root.name, cases_dir=case_root.parent)
    res = read_json(paths.subresult("mailrules"))
    email = read_json(paths.subresult("email")) or {}
    if not res or "engine" not in res or res["engine"].get("error"):
        return None
    case: list[dict[str, Any]] = []

    def walk(nodes: list[dict[str, Any]], chain: str) -> None:
        for n in nodes or []:
            here = f"{chain} › {n.get('filename', '')}" if chain else n.get("filename", "")
            for x in n.get("findings") or []:
                case.append({"rule": x.get("rule", ""), "severity": x.get("severity", "info"), "location": here,
                             "nested": True})
            walk(n.get("children") or [], here)
    walk((read_json(paths.subresult("nested")) or {}).get("tree") or [], "")
    for x in (read_json(paths.subresult("c2")) or {}).get("findings") or []:
        case.append({"rule": x.get("rule", ""), "severity": x.get("severity", "info"), "location": x.get("location", ""),
                     "nested": True})
    f = res["engine"].get("facts") or {}
    matched = mailengine.run(f, "case", {"case_findings": case})
    res["findings"] = [x for x in res["findings"] if x.get("rule") != "email_verdict"
                       and not any(x.get("rule") == m["id"] for m in matched)]
    for m in matched:
        res["findings"].append(_rule_finding(m))
    em_matched = [m for m in res["engine"].get("matched") or [] if not m.get("stage")]
    all_matched = [m for m in em_matched if all(m["id"] != c["id"] for c in matched)] + matched
    res["engine"]["case_matched"] = matched
    res["verdict"] = v = mailengine.verdict(_signals(email, {"findings": [x for x in res["findings"]
                                                                        if x.get("location") != "rules"]},
                                                     all_matched, bool(res["engine"].get("legit_bulk"))))
    sev = {"malicious": "high", "phishing": "high", "suspicious": "medium", "clean": "info"}[v["verdict"]]
    top = "; ".join(f"{s['id']} (+{s['score']})" for s in v["raised"][:5])
    low = "; ".join(f"{s['id']} ({s['score']})" for s in v["lowered"][:3])
    res["findings"].append(_finding("email_verdict", sev, f"Email verdict: {v['verdict']} (score {v['score']})",
                                    "verdict", f"raised by: {top or '—'}" + (f" · lowered by: {low}" if low else "")))
    res["counts"] = {"findings": len(res["findings"])}
    res["status"] = "ok_with_findings" if res["findings"] else "ok"
    write_subresult(paths, "mailrules", res)
    return v
