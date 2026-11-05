"""Reputation lists the email rules compare against.

Feeds (downloaded into ``tools/mailintel/``; refreshed on start when older than a
day, and from Settings → *Email reputation lists*). Only permissive licences:

* **free webmail** — Kikobeats/free-email-domains (MIT): Gmail, Outlook, GMX, the
  ~200 mail.com vanity domains (accountant.com, engineer.com, usa.com…);
* **disposable** — disposable-email-domains (CC0);
* **phishing domains / IPs** — Phishing-Database/Phishing.Database (MIT);
* **malware hosts** — URLhaus by abuse.ch (CC0).

Built-in fallbacks keep the rules working offline: a short list of the big free
webmail providers, commonly abused TLDs (Spamhaus / Interisle public reports on
the most abused TLDs), email service providers (ESPs) and their click trackers,
and the legitimate hosting / document services abused to host phishing pages.
Nothing is fetched for a sample: the lists are only compared locally."""

from __future__ import annotations

import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from .config import settings
from .logging_config import get_logger

log = get_logger(__name__)

MAX_AGE = 86400
FEEDS: dict[str, dict[str, Any]] = {
    "freemail": {"label": "Free webmail providers", "license": "MIT", "kind": "domains",
                 "url": "https://raw.githubusercontent.com/Kikobeats/free-email-domains/master/domains.json",
                 "source": "github.com/Kikobeats/free-email-domains"},
    "disposable": {"label": "Disposable email domains", "license": "CC0-1.0", "kind": "domains",
                   "url": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/"
                          "disposable_email_blocklist.conf",
                   "source": "github.com/disposable-email-domains/disposable-email-domains"},
    "phishing_domains": {"label": "Phishing domains (active)", "license": "MIT", "kind": "domains",
                         "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                                "phishing-domains-ACTIVE.txt",
                         "source": "github.com/Phishing-Database/Phishing.Database"},
    "phishing_ips": {"label": "Phishing IPs (active)", "license": "MIT", "kind": "ips",
                     "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                            "phishing-IPs-ACTIVE.txt",
                     "source": "github.com/Phishing-Database/Phishing.Database"},
    "urlhaus_hosts": {"label": "Malware distribution hosts (URLhaus)", "license": "CC0-1.0", "kind": "domains",
                      "url": "https://urlhaus.abuse.ch/downloads/hostfile/", "source": "urlhaus.abuse.ch"},
}

# --- built-in lists -----------------------------------------------------------------
FREEMAIL_BUILTIN = set("""
gmail.com googlemail.com outlook.com hotmail.com hotmail.es hotmail.fr hotmail.co.uk hotmail.it live.com
live.es live.fr msn.com yahoo.com yahoo.es yahoo.fr yahoo.co.uk yahoo.de ymail.com rocketmail.com aol.com
icloud.com me.com mac.com gmx.com gmx.de gmx.net gmx.es web.de mail.com email.com usa.com accountant.com
consultant.com engineer.com techie.com writeme.com post.com europe.com asia.com myself.com dr.com iname.com
workmail.com cheerful.com contractor.net protonmail.com proton.me pm.me tutanota.com tuta.io zoho.com
zohomail.com yandex.com yandex.ru mail.ru inbox.ru bk.ru list.ru qq.com 163.com 126.com sina.com
naver.com daum.net terra.com.br uol.com.br bol.com.br libero.it virgilio.it orange.fr laposte.net
wanadoo.fr free.fr t-online.de freenet.de seznam.cz wp.pl o2.pl interia.pl rediffmail.com mailfence.com
hushmail.com fastmail.com
""".split())

# TLDs repeatedly at the top of public "most abused TLD" reports (Spamhaus,
# Interisle Phishing Landscape). A signal to combine, never a verdict alone.
ABUSED_TLDS = set("""
top xyz cfd sbs click shop buzz rest cyou icu online site live work support bond lat mom beauty quest
monster autos boats hair skin makeup lol cam surf tk ml ga cf gq pw cc ws today cloud run fun space best
""".split())

# Email service providers: header markers and their click-tracking hosts.
ESP_HEADERS = {
    "x-sg-eid": "SendGrid", "x-sg-id": "SendGrid", "x-mailgun-sid": "Mailgun", "x-mailgun-tag": "Mailgun",
    "x-mc-user": "Mailchimp", "x-mandrill-user": "Mailchimp Transactional", "x-ses-outgoing": "Amazon SES",
    "x-campaign": "generic ESP", "x-campaignid": "generic ESP", "x-hs-cid": "HubSpot", "x-mailjet-campaign": "Mailjet",
    "x-sib-id": "Brevo / Sendinblue", "x-mailin-campaign": "Brevo / Sendinblue", "x-sfmc-stack": "Salesforce Marketing Cloud",
    "x-klaviyo": "Klaviyo", "x-csa-complaints": "certified sender (CSA)", "x-msfbl": "SparkPost",
    "x-cmae-score": "Cloudmark-scored ESP", "x-pm-message-id": "Postmark", "x-postmark-tag": "Postmark",
}
ESP_TRACKERS = (
    "sendgrid.net", "ct.sendgrid.net", "list-manage.com", "mailchi.mp", "mandrillapp.com", "mailgun.org",
    "hubspotlinks.com", "hs-sites.com", "hubspotemail.net", "mjt.lu", "sendibt2.com", "sendibt3.com", "brevo.com",
    "r.sender.net", "rs6.net", "createsend.com", "cmail19.com", "cmail20.com", "exacttarget.com", "sfmc-content.com",
    "klaviyomail.com", "klclick.com", "awstrack.me", "sparkpostmail.com", "mlsend.com", "pstmrk.it",
    "constantcontact.com", "e.customeriomail.com", "ct.messagebird.com", "click.mailerlite.com", "links.iterable.com",
    "trk.klclick1.com", "mktoweb.com", "mkt.com", "eloqua.com", "en25.com", "pardot.com", "salesforce.com",
)
# Legitimate services abused to host the phishing page / lure (the link, not the sender).
HOSTING_ABUSE = {
    "sharepoint.com": "SharePoint", "onedrive.live.com": "OneDrive", "1drv.ms": "OneDrive", "dropbox.com": "Dropbox",
    "dropboxusercontent.com": "Dropbox", "docs.google.com": "Google Docs", "drive.google.com": "Google Drive",
    "forms.gle": "Google Forms", "sites.google.com": "Google Sites", "storage.googleapis.com": "Google Cloud Storage",
    "firebaseapp.com": "Firebase", "web.app": "Firebase Hosting", "appspot.com": "Google App Engine",
    "docusign.net": "DocuSign", "na2.docusign.net": "DocuSign", "workers.dev": "Cloudflare Workers",
    "pages.dev": "Cloudflare Pages", "r2.dev": "Cloudflare R2", "trycloudflare.com": "Cloudflare tunnel",
    "blob.core.windows.net": "Azure Blob", "web.core.windows.net": "Azure static site", "azurewebsites.net": "Azure App Service",
    "netlify.app": "Netlify", "vercel.app": "Vercel", "github.io": "GitHub Pages", "glitch.me": "Glitch",
    "weebly.com": "Weebly", "wixsite.com": "Wix", "webflow.io": "Webflow", "notion.site": "Notion",
    "canva.com": "Canva", "figma.com": "Figma", "typeform.com": "Typeform", "jotform.com": "Jotform",
    "wetransfer.com": "WeTransfer", "we.tl": "WeTransfer", "mediafire.com": "MediaFire", "box.com": "Box",
    "ipfs.io": "IPFS gateway", "dweb.link": "IPFS gateway", "cf-ipfs.com": "IPFS gateway", "ipfs.w3s.link": "IPFS gateway",
    "s3.amazonaws.com": "Amazon S3", "amazonaws.com": "AWS", "000webhostapp.com": "000webhost", "ngrok.io": "ngrok",
    "ngrok-free.app": "ngrok", "replit.app": "Replit", "repl.co": "Replit", "zohopublic.com": "Zoho",
}

_lock = threading.Lock()
_cache: dict[str, tuple[float, set[str]]] = {}
_refresh: dict[str, Any] = {"running": False, "last": None, "error": None}


def folder() -> Path:
    return settings.tools_dir / "mailintel"


def _file(name: str) -> Path:
    return folder() / f"{name}.txt"


def parse(name: str, text: str) -> set[str]:
    out: set[str] = set()
    if name == "freemail" and text.lstrip().startswith("["):
        import json
        try:
            return {str(d).strip().lower() for d in json.loads(text) if d}
        except ValueError:
            return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        parts = line.split()
        tok = parts[1] if len(parts) >= 2 and parts[0] in ("127.0.0.1", "0.0.0.0") else parts[0]
        tok = tok.strip().lower().rstrip(".")
        if tok and tok not in ("localhost",):
            out.add(tok)
    return out


def _load(name: str) -> set[str]:
    p = _file(name)
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return set()
    with _lock:
        got = _cache.get(name)
        if got and got[0] == mtime:
            return got[1]
    try:
        vals = parse("plain", p.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        vals = set()
    with _lock:
        _cache[name] = (mtime, vals)
    return vals


def _suffixes(domain: str) -> list[str]:
    parts = (domain or "").lower().strip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def in_list(name: str, domain: str) -> bool:
    """``domain`` or a parent of it is in feed ``name``."""
    vals = _load(name)
    if name == "freemail":
        vals = vals | FREEMAIL_BUILTIN
    if not vals:
        return False
    if name == "phishing_ips":
        return domain in vals
    # freemail / disposable: exact domain (subdomains of gmail.com are not webmail)
    if name in ("freemail", "disposable"):
        return domain.lower() in vals
    return any(s in vals for s in _suffixes(domain))


def is_freemail(domain: str) -> bool:
    return in_list("freemail", domain)


def is_disposable(domain: str) -> bool:
    return in_list("disposable", domain)


def tld_abused(domain: str) -> bool:
    return (domain or "").rsplit(".", 1)[-1].lower() in ABUSED_TLDS


def tracker(host: str) -> bool:
    h = (host or "").lower()
    return any(h == t or h.endswith("." + t) for t in ESP_TRACKERS)


def hosting_service(host: str) -> str:
    h = (host or "").lower()
    for dom, name in HOSTING_ABUSE.items():
        if h == dom or h.endswith("." + dom):
            return name
    return ""


def bad_reputation(host: str) -> list[str]:
    """The reputation feeds that list ``host`` (domain or IP)."""
    out = []
    if not host:
        return out
    import ipaddress
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        if in_list("phishing_ips", host):
            out.append(FEEDS["phishing_ips"]["label"])
        if in_list("urlhaus_hosts", host):
            out.append(FEEDS["urlhaus_hosts"]["label"])
        return out
    for name in ("phishing_domains", "urlhaus_hosts"):
        if in_list(name, host):
            out.append(FEEDS[name]["label"])
    return out


# --- refresh ------------------------------------------------------------------------
def status() -> dict[str, Any]:
    feeds = []
    for name, f in FEEDS.items():
        p = _file(name)
        try:
            st = p.stat()
            updated, count = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)), len(_load(name))
        except OSError:
            updated, count = None, 0
        feeds.append({"id": name, "label": f["label"], "license": f["license"], "source": f["source"],
                      "updated": updated, "count": count})
    return {"feeds": feeds, "running": _refresh["running"], "last": _refresh["last"], "error": _refresh["error"],
            "builtin": {"freemail": len(FREEMAIL_BUILTIN), "abused_tlds": sorted(ABUSED_TLDS)}}


def _download(name: str, proxy: str | None, timeout: int) -> int:
    f = FEEDS[name]
    handlers = []
    if proxy and proxy.startswith(("http://", "https://")):
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(f["url"], headers={"User-Agent": "DocuTraceX"})
    with opener.open(req, timeout=timeout) as r:
        text = r.read(64 * 1024 * 1024).decode("utf-8", "replace")
    vals = parse(name, text)
    if len(vals) < 10:
        raise ValueError(f"{name}: list looks empty")
    p = _file(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text("\n".join(sorted(vals)) + "\n", encoding="utf-8")
    tmp.replace(p)
    return len(vals)


def stale(name: str) -> bool:
    try:
        return time.time() - _file(name).stat().st_mtime > MAX_AGE
    except OSError:
        return True


def refresh(proxy: str | None = None, only_stale: bool = False, timeout: int = 60) -> dict[str, Any]:
    """Download every feed (or the stale ones). A failed feed keeps its old copy."""
    with _lock:
        if _refresh["running"]:
            return status()
        _refresh["running"] = True
    errors = []
    try:
        for name in FEEDS:
            if only_stale and not stale(name):
                continue
            try:
                n = _download(name, proxy, timeout)
                log.info("mailintel: %s refreshed (%d entries)", name, n)
            except Exception as exc:  # noqa: BLE001  (offline: the old copy stays)
                errors.append(f"{name}: {exc}"[:200])
    finally:
        _refresh.update(running=False, last=time.strftime("%Y-%m-%d %H:%M"), error="; ".join(errors) or None)
    return status()


def refresh_in_background(proxy: str | None = None) -> None:
    if all(not stale(n) for n in FEEDS):
        return
    threading.Thread(target=refresh, kwargs={"proxy": proxy, "only_stale": True}, name="mailintel-refresh",
                     daemon=True).start()
