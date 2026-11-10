"""Declarative email rules + a verdict per message.

Rules live in YAML (``docutracex/rules/email/*.yml``, plus the analyst's own in
``config/rules/email/*.yml``): a condition over the message's *facts* (below),
a severity, a score and ATT&CK ids. Two stages:

* ``email`` — on the message itself (headers, bodies, links decoded from the
  gateways, attachments' names / bytes), right after the email modules;
* ``case`` — after the whole case ran, so a rule can use what the attachments'
  and links' analysis found (nested children, C2 configurations…).

The **verdict** adds the scores of the rules that matched and of the findings
the built-in checks raised (``weights``), minus the legitimacy signals
(negative scores: an authenticated newsletter from a known ESP is not
"suspicious"), and maps it to clean / suspicious / phishing / malicious —
listing which signals weighed and how much.

Facts (dotted paths): sender.{address, domain, display, freemail, disposable,
tld_abused, reputation, exec_title, brand_in_display, own_domain, own_lookalike,
external_with_own_configured}, reply_to.{address, domain, differs, freemail,
disposable, reputation, own_lookalike}, auth.{spf, dkim, dmarc, dmarc_fail,
dmarc_policy, dkim_domain, dkim_aligned_pass, arc_pass, arc_summary,
untrusted_pass}, esp.{known, name, list_unsubscribe}, thread.{subject,
reply_prefix, has_in_reply_to, has_references}, recipients.{to_count,
undisclosed, in_subject}, text.{length}, body.{phones, ibans, password_hint,
mailto_freemail}, links.{count, domains, abused_tld, reputation, hosting,
download, ip, redirects, own_lookalike}, attachments.{count, names, encrypted,
archives, svg_script, ics_links, images}, invisible.{subject, display},
content.{image_only}."""

from __future__ import annotations

import fnmatch
import re
import zipfile
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .logging_config import get_logger

log = get_logger(__name__)

RULES_DIR = Path(__file__).parent / "rules" / "email"
SEVERITIES = ("info", "low", "medium", "high")
_INVISIBLE = re.compile("[​‌‍‎‏‪-‮⁦-⁩﻿­]")
_PHONE = re.compile(r"(?<![\w/.$€£-])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]\d{2,4}){1,4}(?![\w/.-])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_PASSWORD = re.compile(r"(?i)\b(?:contrase[nñ]a|password|passwort|kennwort|mot de passe|clave|pwd|pass|code)\b"
                       r"\s*(?:del? (?:archivo|fichero|documento|zip)\s*)?[:=]?\s*[\"'«]?([^\s\"'»<>]{3,40})")
_MAILTO = re.compile(r"(?i)(?:mailto:)?([\w.+-]{1,64}@([\w-]+(?:\.[\w-]+)+))")
_EXEC = re.compile(r"(?i)\b(ceo|cfo|coo|cto|director[a]? (general|financier[oa]|ejecutiv[oa])|presidente?|chairman|chief "
                   r"\w+ officer|managing director|consejer[oa] delegad[oa]|gerente|founder|fundador[a]?|owner)\b")
_REPLY = re.compile(r"(?i)^\s*(re|fw|fwd|rv|aw|wg|tr|sv|vs|r)\s*(\[\d+\])?\s*:")
_DOWNLOAD_EXT = (".exe", ".scr", ".msi", ".js", ".jse", ".vbs", ".vbe", ".hta", ".ps1", ".bat", ".cmd", ".lnk", ".iso",
                 ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z", ".cab", ".jar", ".apk", ".dll", ".one", ".wsf", ".xll",
                 ".appx", ".msix", ".appinstaller", ".svg")
_REDIRECT_PARAMS = ("url", "u", "redirect", "redirect_uri", "redir", "dest", "destination", "next", "target", "goto",
                    "returnurl", "return", "continue", "link", "r", "q")
_ARCHIVE_EXT = (".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".iso", ".img", ".pdf", ".docx", ".xlsx", ".doc", ".xls")


# --- rules ----------------------------------------------------------------------------
@lru_cache(maxsize=4)
def _load_rules(extra_dir: str | None) -> dict[str, Any]:
    import yaml
    merged: dict[str, Any] = {"verdict": {}, "weights": {"default": {}, "rules": {}}, "lexicons": {}, "rules": []}
    dirs = [RULES_DIR] + ([Path(extra_dir)] if extra_dir else [])
    for d in dirs:
        for f in sorted(d.glob("*.yml")) if d.is_dir() else []:
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except Exception as exc:  # noqa: BLE001  (a broken user file never breaks the analysis)
                log.warning("email rules: %s unreadable: %s", f, exc)
                continue
            merged["verdict"].update(data.get("verdict") or {})
            w = data.get("weights") or {}
            merged["weights"]["default"].update(w.get("default") or {})
            merged["weights"]["rules"].update(w.get("rules") or {})
            merged["lexicons"].update(data.get("lexicons") or {})
            for r in data.get("rules") or []:
                if isinstance(r, dict) and r.get("id") and r.get("when"):
                    r = dict(r, source=f.name)
                    merged["rules"] = [x for x in merged["rules"] if x["id"] != r["id"]] + [r]   # user file overrides
    merged["_lex"] = {k: re.compile(v, re.I) for k, v in merged["lexicons"].items()}
    return merged


def rules() -> dict[str, Any]:
    try:
        from .appsettings import config_dir
        extra = str(config_dir() / "rules" / "email")
    except Exception:  # noqa: BLE001
        extra = None
    return _load_rules(extra)


# --- facts ----------------------------------------------------------------------------
# --- typical phishing-kit URLs -------------------------------------------------
# Stems kits glue into their paths (".../servesyncerrorcertwerts/he-opas.html").
_LURE_STEMS = ("secure", "verif", "account", "login", "logon", "signin", "webmail", "mailserv", "mailbox",
               "office", "o365", "owa", "outlook", "sharepoint", "onedrive", "docusign", "adobe", "wetransfer",
               "dropbox", "update", "auth", "valid", "confirm", "cert", "sync", "error", "unlock", "suspend",
               "recover", "passw", "wallet", "billing", "invoice", "payment", "factura", "banco", "support",
               "alert", "notice", "secur", "portal", "server", "upgrade", "quota", "storage", "expire", "renew")
# Merge tags a campaign tool failed to fill in ([[-Email-], {{email}}, %EMAIL%, *|EMAIL|*, ##email##).
_PLACEHOLDER = re.compile(r"(?i)\[\[-?\s*(?:e-?mail|user|name|domain)\b|\{\{\s*(?:e-?mail|user|name|domain)\w*\s*\}\}|"
                          r"%(?:e-?mail|user|name|domain)%|\*\|(?:e-?mail|user|fname|name)\|\*|##(?:e-?mail|user)##|"
                          r"\$\{?(?:e-?mail|recipient)\}?\b|\[(?:e-?mail|recipient)\]")
_EMAIL_IN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_EMAIL_PARAMS = {"email", "e", "mail", "em", "user", "username", "login", "u", "id", "uid", "usr", "acct", "account",
                 "address", "recipient", "rcpt", "to", "target", "victim", "userid", "loginid"}
_LEGIT_PERSONAL = re.compile(r"(?i)unsub|opt-?out|preferen|manage|subscri|newsletter|confirm-?subscription|"
                             r"/baja|darse-de-baja|abmelden|desinscri")


def _recipient_forms(addr: str) -> set[str]:
    import base64
    from urllib.parse import quote
    forms = {addr, quote(addr, safe=""), quote(addr, safe="@")}
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        forms.add(enc(addr.encode()).decode().rstrip("="))
    return {f.lower() for f in forms if f}


def _phish_url_patterns(links: list[str], recipients: list[str], sdom: str) -> dict[str, list[str]]:
    """Facts on the links' shape: recipient pre-filled in the URL, kit-style
    paths, unfilled campaign merge tags, user-info and punycode tricks."""
    from . import mailintel, urlwrap
    forms = {f for r in recipients for f in _recipient_forms(r)}
    rcpt, kitp, holes, userinfo, puny = [], [], [], [], []
    for u in links:
        try:
            p = urlparse(u)
            host = (p.hostname or "").lower()
        except ValueError:
            continue
        low = unquote(u).lower()
        if _PLACEHOLDER.search(unquote(u)):
            holes.append(u)
        if p.username or ("@" in (p.netloc or "") and not p.netloc.startswith("@")):
            userinfo.append(u)
        if any(lbl.startswith("xn--") for lbl in host.split(".")):
            puny.append(u)
        legit = (mailintel.tracker(host) or urlwrap.is_gateway_host(host)
                 or (sdom and _registrable(host) == _registrable(sdom))
                 or _LEGIT_PERSONAL.search(p.path + "?" + p.query))
        if not legit:
            tail = (p.path + "?" + p.query + "#" + p.fragment).lower()
            params = parse_qs(p.query) | parse_qs(p.fragment)
            if (any(f in tail or f in low for f in forms)
                    or any(k.lower() in _EMAIL_PARAMS and any(_EMAIL_IN.fullmatch(unquote(v).strip()) for v in vs)
                           for k, vs in params.items())
                    or _EMAIL_IN.fullmatch(unquote(p.fragment).strip("/!#= "))):
                rcpt.append(u)
            segs = [x for x in unquote(p.path).lower().split("/") if x]
            stems = {st for x in segs for st in _LURE_STEMS if st in x}
            long_glued = any(len(x) >= 25 and re.fullmatch(r"[a-z0-9-]+", x)
                             and sum(st in x for st in _LURE_STEMS) >= 2 for x in segs)
            wp = re.search(r"/wp-(?:content|includes|admin)/", p.path.lower()) and (
                re.search(r"\.(?:html?|php)$", p.path.lower()) and stems)
            if long_glued or len(stems) >= 3 or wp:
                kitp.append(u)
    return {"recipient_in_url": rcpt[:10], "kit_path": kitp[:10], "placeholder": holes[:10],
            "userinfo": userinfo[:10], "punycode": puny[:10]}


def _dom(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">").strip() if addr and "@" in addr else ""


def _registrable(host: str) -> str:
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gob", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def own_lookalike(host: str, own: list[str]) -> str:
    """``host`` imitates one of the organisation's domains (not one of them)."""
    if not host or not own:
        return ""
    h = host.lower().strip(".")
    reg = _registrable(h)
    for d in own:
        if h == d or h.endswith("." + d):
            return ""
    from . import similarity
    th = similarity.thresholds()
    for d in own:
        label, dl = reg.split(".")[0], d.split(".")[0]
        dist = similarity.lookalike_distance(label, dl, th)
        if dist:
            return f"{host} ≈ {d} ({dist} edit{'s' if dist > 1 else ''})"
        if len(dl) >= th["min_len"] and reg != d and (label == dl or dl in h.replace("-", "")):
            return f"{host} ≈ {d}"
    return ""


def _brand_in_display(display: str, domain: str, brands: list[str]) -> str:
    try:
        from .parsers.mail_rules import BRANDS, _OFFICIAL
    except Exception:  # noqa: BLE001
        BRANDS, _OFFICIAL = {}, set()
    disp = (display or "").lower()
    reg = _registrable(domain)
    for b in list(BRANDS) + list(brands):
        if len(b) >= 4 and re.search(rf"(?<![a-z]){re.escape(b)}(?![a-z])", disp):
            official = set(BRANDS.get(b, ())) | {d for d in _OFFICIAL if b in d}
            if reg in official or b in reg:
                return ""
            return b
    return ""


def _auth(email: dict[str, Any], mailrules: dict[str, Any]) -> dict[str, Any]:
    headers = [(h.get("name", ""), h.get("value", "")) for h in email.get("headers") or []]
    ars = [v for n, v in headers if n.lower() == "authentication-results"]
    top = ars[0].lower() if ars else ""
    a: dict[str, Any] = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", top)
        a[mech] = m.group(1) if m else (email.get("authentication") or {}).get(mech, "")
    pm = re.search(r"dmarc=\w+[^;]*\bp=(\w+)", top)
    a["dmarc_policy"] = pm.group(1).lower() if pm else ""
    a["dmarc_fail"] = a["dmarc"] == "fail"
    untrusted = []
    for v in ars[1:]:
        if re.search(r"\b(dmarc|dkim|spf)=pass\b", v.lower()) and not re.search(r"\b(dmarc|spf)=pass\b", top):
            untrusted.append(v[:160])
    a["untrusted_pass"] = untrusted
    arc = [v for n, v in headers if n.lower() == "arc-authentication-results"]
    a["arc_pass"] = any(re.search(r"\bi=1\b", v) and re.search(r"\b(dmarc|dkim)=pass\b", v.lower()) for v in arc)
    a["arc_summary"] = arc[0][:200] if arc else ""
    from_dom = _dom((email.get("addresses") or {}).get("from") or "")
    dk = [d for d in mailrules.get("dkim") or [] if d.get("body_hash_ok")]
    aligned = [d for d in dk if d.get("domain") and from_dom and
               (_registrable(d["domain"].lower()) == _registrable(from_dom))]
    a["dkim_domain"] = (aligned or dk or [{}])[0].get("domain", "")
    a["dkim_aligned_pass"] = bool(aligned) and a["dkim"] in ("pass", "")
    return a


def _esp(email: dict[str, Any]) -> dict[str, Any]:
    from . import mailintel
    names = {h.get("name", "").lower(): h.get("value", "") for h in email.get("headers") or []}
    esp = next((v for k, v in mailintel.ESP_HEADERS.items() if k in names), "")
    if not esp and "feedback-id" in names:
        esp = "ESP (Feedback-ID)"
    unsub = "list-unsubscribe" in names
    return {"known": bool(esp) or (unsub and "list-id" in names), "name": esp or ("mailing list" if unsub else ""),
            "list_unsubscribe": unsub}


def _attachments(email: dict[str, Any], case_root: Path | None) -> dict[str, Any]:
    names = [a.get("filename") or "" for a in email.get("attachments") or []]
    enc, svg, ics, archives, images = [], [], [], [], 0
    for a in email.get("attachments") or []:
        name = (a.get("filename") or "").lower()
        data = b""
        if case_root and a.get("stored_path"):
            try:
                data = (case_root / a["stored_path"]).read_bytes()[:8 * 1024 * 1024]
            except OSError:
                data = b""
        if name.endswith(_ARCHIVE_EXT):
            archives.append(a.get("filename"))
        if name.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")):
            images += 1
        if data:
            if data[:4] == b"PK\x03\x04":
                try:
                    with zipfile.ZipFile(__import__("io").BytesIO(data)) as z:
                        if any(i.flag_bits & 0x1 for i in z.infolist()):
                            enc.append(a.get("filename"))
                except (zipfile.BadZipFile, OSError, ValueError):
                    pass
            elif data[:6] == b"7z\xbc\xaf\x27\x1c" and b"\x06\xf1\x07\x01" in data[:4096]:
                enc.append(a.get("filename"))          # 7z with an AES coder
            elif data[:4] == b"Rar!":
                enc.append(a.get("filename")) if b"\x04\x00" in data[:64] else None
            elif data[:5] == b"%PDF-" and b"/Encrypt" in data:
                enc.append(a.get("filename"))
            if name.endswith(".svg") or data.lstrip()[:5] in (b"<svg ", b"<?xml") and b"<svg" in data[:2048]:
                low = data[:2_000_000].lower()
                hits = [m for m in (b"<script", b"foreignobject", b"onload=", b"onclick=", b"javascript:", b"atob(",
                                    b"window.location", b"document.write", b"<iframe", b"<embed") if m in low]
                if hits:
                    svg.append(f"{a.get('filename')}: {', '.join(h.decode() for h in hits[:5])}")
            if name.endswith(".ics") or data[:15] == b"BEGIN:VCALENDAR":
                urls = re.findall(rb"https?://[^\s\"'<>\\]+", data[:2_000_000])
                if urls:
                    ics.append(f"{a.get('filename')}: {urls[0].decode('latin-1')[:120]}")
    return {"count": len(names), "names": names, "encrypted": enc, "svg_script": svg, "ics_links": ics,
            "archives": archives, "images": images}


def _real_images(html: str) -> int:
    """<img> tags that are pictures, not 1x1 tracking pixels."""
    n = 0
    for tag in re.findall(r"(?is)<img\b[^>]*>", html or ""):
        if re.search(r"(?i)\b(width|height)\s*=\s*[\"']?[01](px)?[\"'\s>/]", tag):
            continue
        n += 1
    return n


def facts(email: dict[str, Any], mailrules: dict[str, Any], case_root: Path | None = None) -> dict[str, Any]:
    from . import mailintel, urlwrap
    from .appsettings import email_settings
    cfg = email_settings()
    own = cfg["own_domains"]
    addrs = email.get("addresses") or {}
    sender, reply = (addrs.get("from") or "").lower(), (addrs.get("reply_to") or "").lower()
    sdom, rdom = _dom(sender), _dom(reply)
    display = addrs.get("from_display") or ""
    subject = addrs.get("subject") or ""
    body = (email.get("body_sample") or "") + "\n" + (email.get("html_text_sample") or "")
    html = email.get("html_source_sample") or ""
    links = []
    for u in list(email.get("html_links") or []) + re.findall(r"https?://[^\s<>\"')\]]+", body):
        if urlwrap.is_opaque_infrastructure(u):     # a report-phish button, an opaque gateway token
            continue
        dest = urlwrap.original(u)[0]
        if dest not in links:
            links.append(dest)
    hosts = []
    for u in links:
        try:
            h = (urlparse(u).hostname or "").lower()
        except ValueError:
            h = ""
        if h and h not in hosts:
            hosts.append(h)
    import ipaddress

    def is_ip(h: str) -> bool:
        try:
            ipaddress.ip_address(h)
            return True
        except ValueError:
            return False
    reputation = [f"{h} ({', '.join(r)})" for h in hosts for r in [mailintel.bad_reputation(h)] if r]
    redirects = []
    for u in links:
        try:
            p = urlparse(u)
        except ValueError:
            continue
        if mailintel.tracker(p.hostname or "") or urlwrap.is_gateway_host(p.hostname or ""):
            continue
        for k, vs in parse_qs(p.query).items():
            if k.lower() in _REDIRECT_PARAMS and any(re.match(r"(?i)^(https?:)?//[\w.-]+\.", v) for v in vs):
                tgt = next(v for v in vs if re.match(r"(?i)^(https?:)?//", v))
                th = (urlparse(tgt if tgt.startswith("http") else "http:" + tgt).hostname or "").lower()
                if th and _registrable(th) != _registrable(p.hostname or ""):
                    redirects.append(f"{p.hostname} → {th}")
                    break
    recipients = [a.lower() for a in (addrs.get("to") or []) + (addrs.get("cc") or []) if "@" in a]
    kit = _phish_url_patterns(links, recipients, sdom)
    mailtos = sorted({m.group(1).lower() for m in _MAILTO.finditer(html + "\n" + body)})
    text_all = f"{subject}\n{body}"
    pw = _PASSWORD.search(body)
    phones = []
    for m in _PHONE.finditer(body):
        digits = re.sub(r"\D", "", m.group(0))
        if 9 <= len(digits) <= 15 and not re.fullmatch(r"(19|20)\d{6}", digits) and m.group(0) not in phones:
            phones.append(m.group(0).strip())
    to = [a.lower() for a in addrs.get("to") or []]
    to_raw = next((h.get("value", "") for h in email.get("headers") or [] if h.get("name", "").lower() == "to"), "")
    att = _attachments(email, case_root)
    text_len = len(re.sub(r"\s+", " ", body).strip())
    f: dict[str, Any] = {
        "sender": {"address": sender, "domain": sdom, "display": display,
                   "freemail": mailintel.is_freemail(sdom), "disposable": mailintel.is_disposable(sdom),
                   "tld_abused": mailintel.tld_abused(sdom), "reputation": mailintel.bad_reputation(sdom),
                   "exec_title": bool(_EXEC.search(display)),
                   "brand_in_display": _brand_in_display(display, sdom, cfg["brands"]),
                   "own_domain": bool(own) and any(sdom == d or sdom.endswith("." + d) for d in own),
                   "own_lookalike": own_lookalike(sdom, own),
                   "external_with_own_configured": bool(own) and not any(sdom == d or sdom.endswith("." + d) for d in own)},
        "reply_to": {"address": reply, "domain": rdom, "differs": bool(rdom) and rdom != sdom,
                     "freemail": mailintel.is_freemail(rdom), "disposable": mailintel.is_disposable(rdom),
                     "reputation": mailintel.bad_reputation(rdom), "own_lookalike": own_lookalike(rdom, own)},
        "auth": _auth(email, mailrules),
        "esp": _esp(email),
        "thread": {"subject": subject, "reply_prefix": bool(_REPLY.match(subject)),
                   "has_in_reply_to": any(h.get("name", "").lower() == "in-reply-to" for h in email.get("headers") or []),
                   "has_references": any(h.get("name", "").lower() == "references" for h in email.get("headers") or [])},
        "recipients": {"to_count": len(to),
                       "undisclosed": not to or "undisclosed" in to_raw.lower(),
                       "in_subject": any(a and (a in subject.lower() or (len(a.split("@")[0]) >= 5 and
                                                                           a.split("@")[0] in subject.lower()))
                                         for a in to)},
        "text": {"length": text_len, "all": text_all},
        "body": {"phones": phones[:5], "ibans": sorted({i.replace(" ", "") for i in _IBAN.findall(body)})[:5],
                 "password_hint": pw.group(1) if pw else "",
                 "mailto_freemail": [m for m in mailtos if mailintel.is_freemail(_dom(m)) and m != sender][:10]},
        "links": {"count": len(links), "domains": hosts[:50],
                  "abused_tld": [h for h in hosts if mailintel.tld_abused(h)][:10],
                  "reputation": reputation[:10],
                  "hosting": [f"{h} ({mailintel.hosting_service(h)})" for h in hosts
                              if mailintel.hosting_service(h) and _registrable(h) != _registrable(sdom)][:10],
                  "download": [u for u in links if urlparse(u).path.lower().endswith(_DOWNLOAD_EXT)][:10],
                  "ip": [h for h in hosts if is_ip(h)][:10], "redirects": redirects[:10],
                  "own_lookalike": next((x for x in (own_lookalike(h, own) for h in hosts) if x), ""),
                  **kit},
        "attachments": att,
        "invisible": {"subject": "subject" if _INVISIBLE.search(subject) else "",
                      "display": "sender name" if _INVISIBLE.search(display) else ""},
        "content": {"image_only": text_len < 120 and (att["images"] > 0 or _real_images(html) > 0)
                    and (len(links) > 0 or bool(mailrules.get("qr")))},
    }
    return f


# --- evaluation -------------------------------------------------------------------------
def _get(f: dict[str, Any], path: str) -> Any:
    cur: Any = f
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _sev_ge(a: str, b: str) -> bool:
    return SEVERITIES.index(a) >= SEVERITIES.index(b) if a in SEVERITIES and b in SEVERITIES else False


def evaluate(cond: Any, f: dict[str, Any], ctx: dict[str, Any]) -> bool:
    if not isinstance(cond, dict):
        return False
    if "all" in cond:
        return all(evaluate(c, f, ctx) for c in cond["all"])
    if "any" in cond:
        return any(evaluate(c, f, ctx) for c in cond["any"])
    if "not" in cond:
        return not evaluate(cond["not"], f, ctx)
    if "fact" in cond:
        v = _get(f, cond["fact"])
        if "eq" in cond:
            return v == cond["eq"]
        if "ne" in cond:
            return v != cond["ne"]
        if "in" in cond:
            return v in cond["in"]
        if "gte" in cond:
            return isinstance(v, (int, float)) and v >= cond["gte"]
        if "lte" in cond:
            return isinstance(v, (int, float)) and v <= cond["lte"]
        return bool(v)
    if "text" in cond:
        rx = ctx["lex"].get(cond["text"])
        return bool(rx and rx.search(_get(f, "text.all") or ""))
    if "finding" in cond:
        return any(fnmatch.fnmatch(r, cond["finding"]) for r in ctx.get("rules_fired") or ())
    if "case_finding" in cond:
        hits = [x for x in ctx.get("case_findings") or []
                if fnmatch.fnmatch(x["rule"], cond["case_finding"])
                and _sev_ge(x.get("severity", "info"), cond.get("min_severity", "info"))
                and (not cond.get("nested_only") or x.get("nested"))]
        if hits:
            ctx.setdefault("case_matched", []).extend(f"{x['rule']} @ {x.get('location', '')}" for x in hits[:5])
        return bool(hits)
    return False


def _render(tpl: str, f: dict[str, Any], ctx: dict[str, Any]) -> str:
    def rep(m: re.Match) -> str:
        if m.group(1) == "case.matched":
            return ", ".join(ctx.get("case_matched") or [])[:500]
        v = _get(f, m.group(1))
        if isinstance(v, list):
            return ", ".join(map(str, v))[:500]
        return "" if v in (None, False) else str(v)[:300]
    return re.sub(r"\{([\w.]+)\}", rep, tpl or "").strip()


def run(f: dict[str, Any], stage: str, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Rules of ``stage`` that match: [{id, title, severity, score, attack, evidence}]."""
    rs = rules()
    ctx = dict(ctx, lex=rs["_lex"])
    out = []
    for r in rs["rules"]:
        if (r.get("stage") or "email") != stage:
            continue
        ctx.pop("case_matched", None)
        try:
            ok = evaluate(r["when"], f, ctx)
        except Exception as exc:  # noqa: BLE001
            log.warning("email rule %s failed: %s", r["id"], exc)
            ok = False
        if ok:
            out.append({"id": r["id"], "title": r.get("title", r["id"]), "severity": r.get("severity", "info"),
                        "score": int(r.get("score", 0)), "attack": list(r.get("attack") or []),
                        "evidence": _render(r.get("evidence", ""), f, ctx), "source": r.get("source", "")})
    return out


def weight(rule: str, severity: str) -> int:
    w = rules()["weights"]
    if rule in w["rules"]:
        return int(w["rules"][rule])
    return int(w["default"].get(severity, 0))


def verdict(signals: list[dict[str, Any]]) -> dict[str, Any]:
    """signals = [{id, score, why, kind}] → {score, verdict, raised, lowered}."""
    th = rules()["verdict"]
    score = sum(s["score"] for s in signals)
    v = "malicious"
    for name in ("clean", "suspicious", "phishing"):
        if score < int(th.get(name, 0)):
            v = name
            break
    needs = set(th.get("malicious_requires") or [])
    if v == "malicious" and needs and not any(s["id"] in needs and s["score"] > 0 for s in signals):
        v = "phishing"                  # a lot of phishing signals, but no payload / known-bad infrastructure
    raised = sorted((s for s in signals if s["score"] > 0), key=lambda s: -s["score"])
    lowered = sorted((s for s in signals if s["score"] < 0), key=lambda s: s["score"])
    return {"score": score, "verdict": v, "raised": raised, "lowered": lowered,
            "thresholds": {k: th.get(k) for k in ("clean", "suspicious", "phishing")},
            "malicious_requires": sorted(needs)}
