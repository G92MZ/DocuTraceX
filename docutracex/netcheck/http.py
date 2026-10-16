"""HTTP fetching that looks like a real browser, with hard limits.

- Browser profiles (desktop Edge on Windows, Safari on iPhone) send the headers
  a real navigation sends, in the browser's order (``sec-ch-ua``,
  ``Sec-Fetch-*``, ``Accept-Language``...). Version numbers follow the date so
  the user-agent never looks years old.
- Redirects are followed by hand (max 10) so every hop is recorded; a
  ``<meta http-equiv="refresh">`` with a short delay counts as a hop too (a
  browser follows it without JavaScript).
- No JavaScript, no sub-resources: only the document itself is downloaded,
  bounded in size and time. The server's TLS certificate is recorded; an
  invalid certificate does not stop the fetch (it is reported instead).
- Everything goes through the proxy configured in Settings, if any.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from datetime import date
from typing import Any
from urllib.parse import urljoin, urlsplit

MAX_BYTES = 5 * 1024 * 1024
MAX_HOPS = 10
TIMEOUT = (10, 20)  # connect, read

_META_REFRESH = re.compile(r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*(\d+)\s*;\s*url\s*=\s*['"]?([^"'>\s]+)""",
                           re.IGNORECASE)


def _chrome_major(today: date | None = None) -> int:
    """Stable Chrome/Edge major for a date (130 on 2024-10-15, a release every 4 weeks)."""
    d = today or date.today()
    return 130 + max(0, (d - date(2024, 10, 15)).days // 28)


def _safari_major(today: date | None = None) -> int:
    d = today or date.today()
    return (d.year - 2000) + (1 if d.month >= 9 else 0)  # Safari 26 shipped Sept 2025


def _accept_encoding() -> str:
    enc = "gzip, deflate"
    try:
        import brotli  # noqa: F401
        enc += ", br"
    except ImportError:
        pass
    try:
        import zstandard  # noqa: F401
        enc += ", zstd"
    except ImportError:
        pass
    return enc


def profile(name: str, referer: str | None = None) -> dict[str, str]:
    """Navigation headers of a real browser, in its order."""
    site = "cross-site" if referer else "none"
    if name == "iphone":
        v = _safari_major()
        h = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Sec-Fetch-Site": site,
            "Accept-Encoding": _accept_encoding(),
            "Sec-Fetch-Mode": "navigate",
            "User-Agent": (f"Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 "
                           f"(KHTML, like Gecko) Version/{v}.0 Mobile/15E148 Safari/604.1"),
            "Accept-Language": "es-ES,es;q=0.9",
            "Sec-Fetch-Dest": "document",
        }
        if referer:
            h["Referer"] = referer
        return h
    m = _chrome_major()
    h = {
        "sec-ch-ua": f'"Microsoft Edge";v="{m}", "Chromium";v="{m}", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                       f"Chrome/{m}.0.0.0 Safari/537.36 Edg/{m}.0.0.0"),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,"
                   "*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        "Sec-Fetch-Site": site,
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
    }
    if referer:
        h["Referer"] = referer
    h["Accept-Encoding"] = _accept_encoding()
    h["Accept-Language"] = "es-ES,es;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"
    return h


def api_headers(accept: str = "application/json") -> dict[str, str]:
    """Headers for public lookup services (RDAP, crt.sh...): a normal browser UA."""
    return {"User-Agent": profile("desktop")["User-Agent"], "Accept": accept,
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8"}


def session(proxy: str | None):
    import requests
    import urllib3

    urllib3.disable_warnings()  # invalid certificates are reported, not warned about
    s = requests.Session()
    s.trust_env = False  # only the proxy configured in DocuTraceX, never env vars
    s.headers.clear()
    # A TLS-inspecting corporate proxy needs its CA: DOCUTRACEX_CA_BUNDLE=<pem>.
    ca = os.environ.get("DOCUTRACEX_CA_BUNDLE")
    if ca and os.path.isfile(ca):
        s.verify = ca
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def _cert_info(resp) -> dict[str, Any] | None:
    """The peer certificate of the connection that served ``resp`` (stream mode)."""
    try:
        conn = getattr(resp.raw, "connection", None) or getattr(resp.raw, "_connection", None)
        sock = getattr(conn, "sock", None)
        der = sock.getpeercert(binary_form=True) if sock is not None else None
    except Exception:  # noqa: BLE001
        der = None
    if not der:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import ExtensionOID, NameOID

        c = x509.load_der_x509_certificate(der)

        def name(n, oid):
            v = n.get_attributes_for_oid(oid)
            return v[0].value if v else ""
        try:
            sans = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
        except Exception:  # noqa: BLE001
            sans = []
        nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before
        na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
        return {"subject": name(c.subject, NameOID.COMMON_NAME), "issuer": name(c.issuer, NameOID.COMMON_NAME),
                "issuer_org": name(c.issuer, NameOID.ORGANIZATION_NAME), "not_before": nb.strftime("%Y-%m-%d"),
                "not_after": na.strftime("%Y-%m-%d"), "sans": list(sans)[:30],
                "sha256": c.fingerprint(hashes.SHA256()).hex()}
    except Exception:  # noqa: BLE001
        return None


def _read(resp) -> tuple[bytes, bool]:
    buf = bytearray()
    for chunk in resp.iter_content(65536):
        buf += chunk
        if len(buf) > MAX_BYTES:
            return bytes(buf[:MAX_BYTES]), True
    return bytes(buf), False


def fetch(s, url: str, headers: dict[str, str], method: str = "GET",
          data: dict[str, str] | None = None) -> dict[str, Any]:
    """Navigate to ``url`` like a browser would (without JavaScript)."""
    import requests

    hops: list[dict[str, Any]] = []
    cur, body_data = url, data
    out: dict[str, Any] = {"requested_url": url, "hops": hops, "error": None}
    t0 = time.time()
    for _ in range(MAX_HOPS + 1):
        tls_error = None
        try:
            try:
                r = s.request(method, cur, headers=headers, data=body_data, allow_redirects=False,
                              stream=True, timeout=TIMEOUT, verify=s.verify)
            except requests.exceptions.SSLError as exc:
                tls_error = str(exc)[:300]
                r = s.request(method, cur, headers=headers, data=body_data, allow_redirects=False,
                              stream=True, timeout=TIMEOUT, verify=False)
        except requests.RequestException as exc:
            out["error"] = f"{exc.__class__.__name__}: {str(exc)[:300]}"
            break
        hop = {"url": cur, "method": method, "status": r.status_code,
               "headers": {k: v[:500] for k, v in list(r.headers.items())[:60]},
               "tls": _cert_info(r) if cur.lower().startswith("https") else None, "tls_error": tls_error}
        hops.append(hop)
        loc = r.headers.get("Location")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            r.close()
            nxt = urljoin(cur, loc)
            hop["redirect_to"] = nxt
            if r.status_code in (301, 302, 303):
                method, body_data = "GET", None
            headers = {**headers, "Sec-Fetch-Site": "cross-site" if _host(nxt) != _host(cur) else "same-origin"}
            cur = nxt
            continue
        body, truncated = _read(r)
        r.close()
        ctype = r.headers.get("Content-Type", "")
        hop.update(size=len(body), truncated=truncated, content_type=ctype,
                   sha256=hashlib.sha256(body).hexdigest())
        out.update(final_url=cur, status=r.status_code, content_type=ctype, body=body, truncated=truncated,
                   disposition=r.headers.get("Content-Disposition", ""))
        # A short meta refresh is followed like a browser without JavaScript does.
        if "html" in ctype.lower() or body[:200].lstrip().lower().startswith((b"<!doctype html", b"<html")):
            m = _META_REFRESH.search(body[:65536].decode("utf-8", "replace"))
            if m and int(m.group(1)) <= 10 and len(hops) <= MAX_HOPS:
                nxt = urljoin(cur, m.group(2))
                if nxt != cur:
                    hop["redirect_to"] = nxt
                    hop["meta_refresh"] = True
                    method, body_data, cur = "GET", None, nxt
                    continue
        break
    else:
        out["error"] = f"more than {MAX_HOPS} redirects"
    out["elapsed_s"] = round(time.time() - t0, 2)
    out["cookies"] = {c.name: c.value[:300] for c in s.cookies}
    return out


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def egress_ip(proxy: str | None) -> dict[str, Any]:
    """Public IP seen by the outside world (to test the proxy)."""
    s = session(proxy)
    t0 = time.time()
    try:
        r = s.get("https://api.ipify.org?format=json", headers=profile("desktop"), timeout=TIMEOUT)
        return {"ok": True, "ip": r.json().get("ip"), "elapsed_s": round(time.time() - t0, 2)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{exc.__class__.__name__}: {str(exc)[:300]}"}
