"""Decode URLs rewritten by email security gateways back to the original link.

Mail gateways wrap every link so clicks go through their scanner first; the
analyst needs the original destination. Supported (all offline, string work):

- Proofpoint URL Defense v1, v2 and v3 (``urldefense.proofpoint.com`` /
  ``urldefense.com``), following Proofpoint's published decoding algorithm.
- Microsoft Defender Safe Links (``*.safelinks.protection.outlook.com``).
- Barracuda Link Protection (``linkprotect.cudasvc.com``).
- Trend Micro click-time protection (``*.trendmicro.com/wis/clicktime``).
- Google / Facebook / LinkedIn style redirectors (``?q=`` / ``?u=`` / ``?url=``).
- Mimecast URL Protect: the target is resolved server-side, so only the hinted
  domain (``domain=`` parameter) can be recovered.
"""

from __future__ import annotations

import re
import string
from base64 import urlsafe_b64decode
from urllib.parse import parse_qs, unquote, urlparse

_V3 = re.compile(r"v3/__(?P<url>.+?)__;(?P<enc>.*?)!")
_V3_TOKEN = re.compile(r"\*(\*.)?")
_V3_RUN = {c: i + 2 for i, c in enumerate(string.ascii_uppercase + string.ascii_lowercase
                                          + string.digits + "-_")}


def _proofpoint_v3(url: str) -> str | None:
    m = _V3.search(url)
    if not m:
        return None
    try:
        dec = urlsafe_b64decode(m.group("enc") + "==").decode("utf-8")
    except Exception:  # noqa: BLE001
        dec = ""
    encoded = unquote(m.group("url"))
    out, pos, marker = [], 0, 0
    for t in _V3_TOKEN.finditer(encoded):
        out.append(encoded[pos:t.start()])
        token = t.group(0)
        if token == "*":
            out.append(dec[marker:marker + 1])
            marker += 1
        else:
            n = _V3_RUN.get(token[-1], 0)
            out.append(dec[marker:marker + n])
            marker += n
        pos = t.end()
    out.append(encoded[pos:])
    return "".join(out)


def _q(url: str, *names: str) -> str | None:
    qs = parse_qs(urlparse(url).query)
    for n in names:
        if qs.get(n):
            return qs[n][0]
    return None


def unwrap(url: str) -> tuple[str, str] | None:
    """Return (service, original_url) when ``url`` is a gateway-wrapped link."""
    try:
        p = urlparse(url)
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    path = p.path or ""
    if host in ("urldefense.proofpoint.com", "urldefense.com", "urldefense.us"):
        if "/v3/" in path or "/v3/" in url:
            orig = _proofpoint_v3(url)
            return ("Proofpoint URL Defense v3", orig) if orig else None
        u = _q(url, "u")
        if not u:
            # gmzpt
            return None
        if "/v2/" in path:
            return "Proofpoint URL Defense v2", unquote(u.replace("-", "%").replace("_", "/"))
        return "Proofpoint URL Defense v1", unquote(u)
    if host.endswith("safelinks.protection.outlook.com"):
        u = _q(url, "url")
        return ("Microsoft Safe Links", u) if u else None
    if host == "linkprotect.cudasvc.com":
        u = _q(url, "a")
        return ("Barracuda Link Protection", u) if u else None
    if "trendmicro.com" in host and "clicktime" in path:
        u = _q(url, "url")
        return ("Trend Micro click-time", u) if u else None
    if host.endswith("mimecast.com") and "/s/" in path:
        d = _q(url, "domain")
        return ("Mimecast URL Protect (domain hint only)", f"http://{d}/") if d else None
    if host in ("www.google.com", "google.com") and path == "/url":
        u = _q(url, "q", "url")
        return ("Google redirect", u) if u else None
    if host in ("l.facebook.com", "lm.facebook.com") and path.startswith("/l.php"):
        u = _q(url, "u")
        return ("Facebook redirect", u) if u else None
    if host == "www.linkedin.com" and path.startswith("/redir/redirect"):
        u = _q(url, "url")
        return ("LinkedIn redirect", u) if u else None
    return None


def unwrap_all(url: str, max_depth: int = 4) -> list[tuple[str, str]]:
    """Follow nested wrappers (e.g. Safe Links around Proofpoint)."""
    chain: list[tuple[str, str]] = []
    cur = url
    for _ in range(max_depth):
        res = unwrap(cur)
        if not res or res[1] == cur:
            break
        chain.append(res)
        cur = res[1]
    return chain
