"""Free public proxies (ProxyScrape) for the network checks.

The list is downloaded from ProxyScrape's free API at startup (cached for a day
under ``tools/cache``). "Connect to free proxy" shuffles the list for the chosen
protocol (and country, if any), tests candidates in parallel and keeps the
first that works. A candidate only passes if a **strictly verified HTTPS**
request through it returns the expected answer — a proxy that intercepts TLS
or alters the content is discarded. Checks made through a free proxy are
labelled as such and never accept an invalid certificate (see ``http``), so an
untrusted proxy can't inject content into the evidence.

Free proxies die often: before each check the active one is re-tested and, if
it is dead, another is picked automatically (same protocol/country).
"""

from __future__ import annotations

import json
import random
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

from ..config import settings

API = "https://api.proxyscrape.com/v4/free-proxy-list/get"
PROTOCOLS = ("http", "socks4", "socks5")
MAX_AGE = 86400
TEST_URL = "https://api.ipify.org?format=json"
TEST_TIMEOUT = 8
_LOCK = threading.Lock()


def cache_path(protocol: str) -> Path:
    return settings.tools_dir / "cache" / f"freeproxies-{protocol}.json"


def download(protocol: str) -> list[dict[str, Any]]:
    """Fetch ProxyScrape's free list for ``protocol`` (direct connection: it is
    just a public list) and cache it."""
    import requests

    r = requests.get(API, params={"request": "display_proxies", "protocol": protocol, "format": "json",
                                  "timeout": 10000}, timeout=(15, 60),
                     headers={"User-Agent": "DocuTraceX (free proxy list)"})
    r.raise_for_status()
    items = []
    for p in (r.json().get("proxies") or []):
        if not p.get("alive", True) or not p.get("ip") or not p.get("port"):
            continue
        ipd = p.get("ip_data") or {}
        items.append({"protocol": protocol, "host": p["ip"], "port": int(p["port"]),
                      "country": ipd.get("countryCode", ""), "anonymity": p.get("anonymity", ""),
                      "uptime": round(float(p.get("uptime") or 0), 1),
                      "latency_ms": round(float(p.get("average_timeout") or 0))})
    path = cache_path(protocol)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"fetched": time.time(), "proxies": items}), encoding="utf-8")
    return items


def load(protocol: str, max_age: int = MAX_AGE) -> list[dict[str, Any]]:
    """The cached list, downloaded again when missing or older than ``max_age``."""
    try:
        data = json.loads(cache_path(protocol).read_text(encoding="utf-8"))
        if time.time() - data.get("fetched", 0) < max_age:
            return data.get("proxies", [])
    except (OSError, ValueError):
        pass
    return download(protocol)


def status() -> dict[str, Any]:
    out = {}
    for proto in PROTOCOLS:
        try:
            data = json.loads(cache_path(proto).read_text(encoding="utf-8"))
            out[proto] = {"count": len(data.get("proxies", [])),
                          "fetched": time.strftime("%Y-%m-%d %H:%M", time.localtime(data.get("fetched", 0)))}
        except (OSError, ValueError):
            out[proto] = {"count": 0, "fetched": None}
    return out


def refresh_all_async() -> None:
    """Startup prefetch (non-blocking): refresh stale lists in the background."""
    def run() -> None:
        for proto in PROTOCOLS:
            try:
                load(proto)
            except Exception:  # noqa: BLE001  (offline / API down: try again on demand)
                pass
    threading.Thread(target=run, name="dtx-freeproxy-prefetch", daemon=True).start()


def proxy_url(p: dict[str, Any]) -> str:
    # gmzpt
    scheme = {"socks5": "socks5h", "socks4": "socks4"}.get(p["protocol"], "http")
    return f"{scheme}://{p['host']}:{p['port']}"


def test(p: dict[str, Any], timeout: float = TEST_TIMEOUT) -> dict[str, Any] | None:
    """Strict HTTPS request through the proxy: certificate verified, expected
    JSON answer with an IP. Returns {egress_ip, latency_ms} or None."""
    import requests

    from . import http

    s = http.session(proxy_url(p), strict_tls=True)
    t0 = time.time()
    try:
        r = s.get(TEST_URL, headers=http.api_headers(), timeout=(timeout, timeout))
        ip = r.json().get("ip") if r.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return None
    finally:
        s.close()
    if not ip or not isinstance(ip, str) or len(ip) > 45:
        return None
    return {"egress_ip": ip, "latency_ms": round((time.time() - t0) * 1000)}


def find_working(protocol: str, country: str = "", exclude: set[str] | None = None,
                 max_tries: int = 120, workers: int = 24, budget_s: float = 90,
                 tester=None) -> dict[str, Any] | None:
    """Test random candidates in parallel; return the first working one."""
    if protocol not in PROTOCOLS:
        raise ValueError(f"protocol must be one of {', '.join(PROTOCOLS)}")
    tester = tester or test
    cands = [p for p in load(protocol) if not country or p.get("country", "").upper() == country.upper()]
    cands = [p for p in cands if f"{p['host']}:{p['port']}" not in (exclude or set())]
    if not cands:
        return None
    # Random, but give proxies with good uptime a head start.
    random.shuffle(cands)
    cands.sort(key=lambda p: -(p.get("uptime") or 0) // 25)
    cands = cands[:max_tries]
    t0 = time.time()
    tried = 0
    # Not a `with` block: on success (or when the budget runs out) return at once
    # instead of waiting for the candidates still being tested.
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dtx-freeproxy")
    try:
        pending = {}
        it = iter(cands)
        for p in it:
            pending[pool.submit(tester, p)] = p
            if len(pending) >= workers:
                break
        while pending and time.time() - t0 < budget_s:
            done, _ = wait(pending, timeout=1, return_when=FIRST_COMPLETED)
            for fut in done:
                p = pending.pop(fut)
                tried += 1
                res = fut.result()
                if res:
                    return {**p, **res, "tried": tried, "search_s": round(time.time() - t0, 1)}
                nxt = next(it, None)
                if nxt is not None:
                    pending[pool.submit(tester, nxt)] = nxt
        return None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def connect(protocol: str, country: str = "", rotate: bool = False, tester=None) -> dict[str, Any]:
    """Find a working free proxy and make it the app's proxy."""
    from .. import appsettings

    with _LOCK:
        data = appsettings.load()
        cur = data["network"]["proxy"]
        exclude = {f"{cur.get('host')}:{cur.get('port')}"} if rotate and cur.get("free") else set()
        found = find_working(protocol, country, exclude, tester=tester)
        if not found:
            raise LookupError(f"no working {protocol} free proxy found"
                              + (f" in {country.upper()}" if country else "") + " — try again or another protocol")
        data["network"]["proxy"] = {
            "enabled": True, "scheme": protocol, "host": found["host"], "port": found["port"],
            "username": "", "password": "", "free": True,
            "free_info": {k: found.get(k) for k in ("country", "anonymity", "uptime", "egress_ip", "latency_ms")}
            | {"connected": time.strftime("%Y-%m-%d %H:%M"), "country_filter": country.upper()},
        }
        appsettings.save(data)
        return found


def ensure_alive(tester=None) -> str | None:
    """Before a check: if the active proxy is a free one and it died, pick another
    (same protocol/country). Returns the proxy URL to use."""
    # ref: gmzpt
    from .. import appsettings

    net = appsettings.load()["network"]
    p = net["proxy"]
    url = appsettings.proxy_url(net)
    if not url or not p.get("free"):
        return url
    tester = tester or test
    if tester({"protocol": p["scheme"], "host": p["host"], "port": p["port"]}):
        return url
    connect(p["scheme"], (p.get("free_info") or {}).get("country_filter", ""), rotate=True, tester=tester)
    return appsettings.proxy_url()
