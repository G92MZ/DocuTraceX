"""URLs rewritten by email security gateways, decoded back to the original link.

Mail gateways wrap every link so clicks go through their scanner first. That is
legitimate infrastructure, not an indicator: the analyst needs the original
destination, the IOCs must be the original, and rules judge the destination —
never the wrapper. All decoding is offline string work (nothing is fetched).

Providers (``PROVIDERS``): Proofpoint URL Defense v1 / v2 / v3, Microsoft
Defender Safe Links (Outlook, Teams, GCC), Barracuda Link Protection, Mimecast
URL Protect (only the domain hint: the target is resolved server-side), Cisco
Secure Email, Check Point Harmony / Avanan (v1 / v2), Sophos Email, OpenText /
EdgePilot, Libraesva URLSand, Egress Defend (base64 + zlib), Trellix / FireEye,
Symantec / Broadcom ClickTime, Trend Micro click-time, Hornetsecurity,
Trustwave MailMarshal, Intermedia, Amazon SES click tracking, and the Google /
Facebook / LinkedIn redirectors. Wrappers nest (several gateways in a row):
``unwrap_all`` peels them all.
"""

from __future__ import annotations

import base64
import binascii
import re
import string
import zlib
from base64 import urlsafe_b64decode
from typing import Callable
from urllib.parse import parse_qs, unquote, urlparse

_V3 = re.compile(r"v3/__(?P<url>.+?)__;(?P<enc>.*?)!")
_V3_TOKEN = re.compile(r"\*(\*.)?")
_V3_RUN = {c: i + 2 for i, c in enumerate(string.ascii_uppercase + string.ascii_lowercase
                                          + string.digits + "-_")}
_HTTP = re.compile(r"(?i)^(?:https?|ftp)://[^\s/?#]+[^\r\n]*$")       # a host, then anything on one line


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


def _qs(url: str) -> dict[str, list[str]]:
    try:
        return parse_qs(urlparse(url).query, keep_blank_values=False)
    except ValueError:
        return {}


def _q(url: str, *names: str) -> str | None:
    qs = _qs(url)
    low = {k.lower(): v for k, v in qs.items()}
    for n in names:
        v = qs.get(n) or low.get(n.lower())
        if v:
            return v[0]
    return None


def _as_url(value: str | None) -> str | None:
    """A parameter value → an http(s) URL: as is, URL-decoded (once or twice),
    base64 / base64url, or base64url + zlib (Egress). None when it is not one."""
    if not value:
        return None
    cands = [value, unquote(value), unquote(unquote(value))]
    for v in list(cands):
        s = re.sub(r"\s+", "", v)
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = dec(s + "=" * (-len(s) % 4))
            except (binascii.Error, ValueError):
                continue
            for blob in (raw, _inflate(raw)):
                if blob:
                    try:
                        cands.append(blob.decode("utf-8"))
                    except UnicodeDecodeError:
                        pass
    for c in cands:
        c = c.strip()
        if _HTTP.match(c):
            return c
        if re.match(r"(?i)^www\.[\w-]+\.", c):          # "www.example.com/x" without a scheme
            return "http://" + c
    return None


def _inflate(raw: bytes) -> bytes:
    for wbits in (15, -15, 31):
        try:
            return zlib.decompress(raw, wbits)
        except zlib.error:
            continue
    return b""


def _params(*names: str) -> Callable[[str], str | None]:
    def dec(url: str) -> str | None:
        for n in names:
            got = _as_url(_q(url, n))
            if got:
                return got
        return None
    return dec


def _proofpoint(url: str) -> str | None:
    p = urlparse(url)
    if "/v3/" in p.path or "/v3/" in url:
        return _proofpoint_v3(url)
    u = _q(url, "u")
    if not u:
        return None
    if "/v2/" in p.path:
        return unquote(u.replace("-", "%").replace("_", "/"))
    return unquote(u)


def _cisco(url: str) -> str | None:
    """``secure-web.cisco.com/<token>/<URL-encoded original>``."""
    p = urlparse(url)
    m = re.match(r"^/[^/]+/(.+)$", p.path)
    if m:
        got = _as_url(m.group(1))
        if got:
            return got
    return _params("url", "u")(url)


def _avanan(url: str) -> str | None:
    """``url.avanan.click/v2/___<original>___.<blob>`` (also /v1/). The obfuscated
    variant keeps only the original's scheme and host."""
    m = re.search(r"/v[12]/___(.+?)___", url)
    if not m:
        return None
    got = _as_url(m.group(1)) or _as_url(m.group(1).replace("{}", "").replace("{_}", ""))
    return got


def _awstrack(url: str) -> str | None:
    m = re.match(r"^/L0/([^/]+)", urlparse(url).path)
    return _as_url(m.group(1)) if m else None


def _mimecast(url: str) -> str | None:
    d = _q(url, "domain")
    return f"http://{d}/" if d else None


def _egress(url: str) -> str | None:
    return _params("@OriginalLink", "OriginalLink", "Base64Url", "url", "u")(url)


def _host_is(host: str, *names: str) -> bool:
    return any(host == n or host.endswith("." + n) for n in names)


# (service, host test, path test or None, decoder, exact) — "exact" = the decoder
# returns the real destination; False = only a hint (Mimecast's domain).
PROVIDERS: list[tuple[str, Callable[[str], bool], Callable[[str], bool] | None, Callable[[str], str | None], bool]] = [
    ("Proofpoint URL Defense", lambda h: h in ("urldefense.proofpoint.com", "urldefense.com", "urldefense.us"),
     None, _proofpoint, True),
    ("Microsoft Safe Links", lambda h: h.endswith(("safelinks.protection.outlook.com",
                                                     "safelinks.protection.office365.us",
                                                     "safelinks.protection.apps.mil")), None,
     _params("url"), True),
    ("Microsoft Safe Links (Teams)", lambda h: h == "statics.teams.cdn.office.net",
     lambda p: "safelinks" in p, _params("url"), True),
    ("Barracuda Link Protection", lambda h: h == "linkprotect.cudasvc.com", None, _params("a", "u", "url"), True),
    ("Mimecast URL Protect (domain hint only)", lambda h: _host_is(h, "mimecast.com", "mimecastprotect.com"),
     lambda p: p.startswith("/s/"), _mimecast, False),
    ("Cisco Secure Email", lambda h: h in ("secure-web.cisco.com", "protected.res.cisco.com")
     or h.endswith(".iphmx.com"), None, _cisco, True),
    ("Check Point Harmony / Avanan", lambda h: h in ("url.avanan.click", "avanan.url-protection.com"),
     None, _avanan, True),
    ("Sophos Email", lambda h: _host_is(h, "protection.sophos.com"), None, _params("u", "url"), True),
    ("OpenText / EdgePilot", lambda h: _host_is(h, "edgepilot.com"), None, _params("u", "url", "dest"), True),
    ("Libraesva URLSand", lambda h: _host_is(h, "esvalabs.com"), None, _params("u", "url"), True),
    ("Egress Defend", lambda h: _host_is(h, "defend.egress.com", "egressdefend.com"), None, _egress, True),
    ("Trellix / FireEye", lambda h: _host_is(h, "fireeye.com", "trellix.com") and h.startswith("protect"),
     None, _params("u", "url"), True),
    ("Symantec / Broadcom ClickTime", lambda h: _host_is(h, "clicktime.symantec.com"), None,
     _params("u", "url", "continue"), True),
    ("Trend Micro click-time", lambda h: _host_is(h, "trendmicro.com", "trendmicro.eu", "tmurl.net"),
     lambda p: "clicktime" in p or "wis" in p, _params("url", "u", "URL"), True),
    ("Hornetsecurity", lambda h: _host_is(h, "hornetsecurity.com", "atpurl.com"), None, _params("u", "url"), True),
    ("Trustwave MailMarshal", lambda h: _host_is(h, "mailmarshal.com", "trustwave.com") and "mail" in h,
     None, _params("url", "u"), True),
    ("Intermedia", lambda h: _host_is(h, "webscan.intermedia.net"), None, _params("url", "u"), True),
    ("Amazon SES click tracking", lambda h: h.endswith("awstrack.me"), None, _awstrack, True),
    ("Google redirect", lambda h: h in ("www.google.com", "google.com"), lambda p: p == "/url",
     _params("q", "url"), True),
    ("Facebook redirect", lambda h: h in ("l.facebook.com", "lm.facebook.com"),
     lambda p: p.startswith("/l.php"), _params("u"), True),
    ("LinkedIn redirect", lambda h: h == "www.linkedin.com", lambda p: p.startswith("/redir/redirect"),
     _params("url"), True),
]
# Redirectors that are not security gateways (shown as such, still unwrapped).
_REDIRECTORS = {"Google redirect", "Facebook redirect", "LinkedIn redirect", "Amazon SES click tracking"}


def _provider(url: str):
    try:
        p = urlparse(url)
    except ValueError:
        return None, None
    host = (p.hostname or "").lower()
    for prov in PROVIDERS:
        name, htest, ptest, _dec, _exact = prov
        if htest(host) and (ptest is None or ptest(p.path or "")):
            return prov, p
    return None, None


def is_gateway_host(host: str) -> bool:
    """A mail security gateway's link-rewriting host (its URLs are never IOCs)."""
    h = (host or "").lower().rstrip(".")
    for name, htest, _p, _d, _e in PROVIDERS:
        if name not in _REDIRECTORS and htest(h):
            return True
    return False


def is_wrapper(url: str) -> bool:
    """A link-rewriting / click-tracking URL of a known provider (gateway or redirector)."""
    return _provider(url)[0] is not None


def unwrap(url: str) -> tuple[str, str] | None:
    """(service, original_url) when ``url`` is a gateway-wrapped link."""
    prov, _p = _provider(url)
    if prov is None:
        return None
    name, _h, _pt, dec, _exact = prov
    try:
        orig = dec(url)
    except Exception:  # noqa: BLE001  (a malformed wrapper is left as it is)
        orig = None
    if not orig or orig == url:
        return None
    if name == "Proofpoint URL Defense":
        ver = "v3" if "/v3/" in url else ("v2" if "/v2/" in url else "v1")
        name = f"{name} {ver}"
    return name, orig


def unwrap_all(url: str, max_depth: int = 8) -> list[tuple[str, str]]:
    """Follow nested wrappers (e.g. Safe Links around Proofpoint, or the six
    gateways a forwarded phishing link can collect)."""
    chain: list[tuple[str, str]] = []
    cur = url
    for _ in range(max_depth):
        res = unwrap(cur)
        if not res or res[1] == cur:
            break
        chain.append(res)
        cur = res[1]
    return chain


def original(url: str) -> tuple[str, list[str], bool]:
    """(destination, services peeled, exact). ``exact`` False when the last layer
    only hints the destination (Mimecast) or a gateway URL could not be decoded."""
    chain = unwrap_all(url)
    if not chain:
        prov, _p = _provider(url)
        return url, [], prov is None
    last = chain[-1][1]
    exact = not chain[-1][0].startswith("Mimecast")
    prov, _p = _provider(last)
    if prov is not None and prov[0] not in _REDIRECTORS:   # an inner gateway we could not open
        exact = False
    return last, [c[0] for c in chain], exact
