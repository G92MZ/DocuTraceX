"""Free public proxies (ProxyScrape) for the network checks.

The list is downloaded from ProxyScrape's free API and refreshed on every
``run.py`` start (so it never goes stale), cached under ``tools/cache`` for
on-demand use between starts. "Connect to free proxy" shuffles the list for the chosen
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

import base64
import json
import random
import subprocess
import sys
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


# --- portable delegation -----------------------------------------------------
# requests / PySocks live on the portable (the [tools] extra), not on the web
# service's Python. The network operations (list download, proxy validation)
# therefore run on the portable interpreter — like the main netcheck — and the
# web service only reads the cache and saves the chosen proxy. When no portable
# is bundled (or this IS the portable), the in-process body runs instead.
def _portable_or_none() -> Path | None:
    portable = settings.portable_python()
    try:
        same = portable is not None and portable.resolve() == Path(sys.executable).resolve()
    except OSError:
        same = False
    return None if (portable is None or same) else portable


def _delegate(args: list[str], timeout: int = 150) -> str | None:
    """Run a free-proxy op on the portable; return stdout, or None to signal the
    caller to run in-process (no portable / already on it). Raises on tool error."""
    portable = _portable_or_none()
    if portable is None:
        return None
    from .. import native
    try:
        proc = subprocess.run([str(portable), "-m", "docutracex.netcheck.freeproxy", *args],
                              capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, env=native.subprocess_env())
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("free-proxy operation timed out") from exc
    if proc.returncode == 0:
        return proc.stdout
    raise RuntimeError((proc.stderr or "").strip()[-300:] or f"exit {proc.returncode}")


def _enc_set(exclude: set[str] | None) -> str:
    return base64.b64encode(json.dumps(sorted(exclude or [])).encode()).decode()


def _dec_set(blob: str) -> set[str]:
    try:
        return set(json.loads(base64.b64decode(blob).decode()))
    except Exception:  # noqa: BLE001
        return set()


def download(protocol: str) -> list[dict[str, Any]]:
    """ProxyScrape's free list for ``protocol``, cached. Runs on the portable
    (requests lives there); the web service reads the cache it writes."""
    out = _delegate(["download", protocol])
    if out is not None:
        try:
            return json.loads(cache_path(protocol).read_text(encoding="utf-8")).get("proxies", [])
        except (OSError, ValueError):
            return (json.loads(out).get("proxies", []) if out.strip() else [])
    return _download_inproc(protocol)


def _download_inproc(protocol: str) -> list[dict[str, Any]]:
    """Fetch + cache the list in-process (runs on the portable)."""
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


def refresh_all_async(force: bool = True) -> threading.Thread:
    """Startup prefetch (non-blocking): refresh the free-proxy lists from the
    source so they never go stale. ``force`` (the default, used on every run.py
    start) re-downloads even a still-fresh cache; ``force=False`` downloads only
    when the cache is missing or older than ``MAX_AGE``. Runs in the background
    and delegates to the portable, so startup is never blocked or broken."""
    def run() -> None:
        for proto in PROTOCOLS:
            try:
                download(proto) if force else load(proto)
            except Exception:  # noqa: BLE001  (offline / API down: try again on demand)
                pass
    t = threading.Thread(target=run, name="dtx-freeproxy-prefetch", daemon=True)
    t.start()
    return t


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
    # In production (no injected tester) the search — which needs requests/
    # PySocks to validate proxies — runs on the portable.
    if tester is None:
        out = _delegate(["find", protocol, country, _enc_set(exclude)])
        if out is not None:
            out = out.strip()
            return json.loads(out) if out and out != "null" else None
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
    probe = {"protocol": p["scheme"], "host": p["host"], "port": p["port"]}
    if tester is not None:
        alive = bool(tester(probe))
    else:
        out = _delegate(["test", p["scheme"], p["host"], str(p["port"])])
        alive = (out.strip() == "ok") if out is not None else bool(test(probe))
    if alive:
        return url
    connect(p["scheme"], (p.get("free_info") or {}).get("country_filter", ""), rotate=True, tester=tester)
    return appsettings.proxy_url()


def main(argv: list[str]) -> int:
    """Portable-side entry: run the network op that needs requests/PySocks and
    print the result as JSON/text for the web service to consume."""
    op = argv[0] if argv else ""
    if op == "download":
        print(json.dumps({"proxies": _download_inproc(argv[1])}))
    elif op == "find":
        country = argv[2] if len(argv) > 2 else ""
        exclude = _dec_set(argv[3]) if len(argv) > 3 else set()
        found = find_working(argv[1], country, exclude)   # tester=None → in-process here
        print(json.dumps(found) if found else "null")
    elif op == "test":
        ok = test({"protocol": argv[1], "host": argv[2], "port": int(argv[3])})
        print("ok" if ok else "dead")
    else:
        print(f"unknown op: {op}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
