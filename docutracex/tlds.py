"""Top-level domains from the official IANA list.

``tlds-alpha-by-domain.txt`` is downloaded on install (``install.py``) into
``tools/iana/`` and can be refreshed from Settings. It is the single source the
IOC extractor uses to decide whether a domain / URL host / email domain ends in
a real TLD. If the file is missing or unreadable, a small built-in list plus
"any two-letter TLD" is used instead, so extraction never breaks offline.
"""

from __future__ import annotations

import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from .config import settings

IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
FILENAME = "tlds-alpha-by-domain.txt"
MAX_AGE = 30 * 86400

# Special-use names (RFC 2606 / 6761 / 7686): not delegated by IANA but used
# on purpose (samples use *.example; .onion is Tor).
SPECIAL = {"example", "test", "invalid", "localhost", "local", "onion"}

# Fallback when the IANA file is not available (no network on install).
_FALLBACK = set("""
com net org info biz edu gov mil int arpa name pro aero coop museum mobi
asia tel travel jobs cat xyz top online site club app dev cloud store shop
live life world today tech space website fun icu vip work link click download
zip mov win bid loan date racing review stream trade party science cricket
faith accountant men gdn kim ooo rest host press email news blog page one
digital network center company solutions services agency group media studio
support systems software finance financial bank money pay cash credit capital
fund academy education school college university global international ltd llc
inc gmbh microsoft google apple amazon office windows azure aws
""".split())

_lock = threading.Lock()
_cache: dict[str, Any] = {"mtime": None, "tlds": None}


def path() -> Path:
    return settings.tools_dir / "iana" / FILENAME


def parse(text: str) -> set[str]:
    """TLDs (lower-case, punycode kept as ``xn--…``) from the IANA file."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.replace("-", "").isalnum():
            out.add(line.lower())
    return out


def _load() -> set[str] | None:
    p = path()
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return None
    with _lock:
        if _cache["mtime"] != mtime:
            try:
                tlds = parse(p.read_text(encoding="ascii", errors="replace"))
            except OSError:
                return None
            _cache.update(mtime=mtime, tlds=tlds if len(tlds) > 100 else None)
        return _cache["tlds"]


def is_known(tld: str) -> bool:
    tld = tld.lower().strip(".")
    if not tld or tld in SPECIAL:
        return bool(tld)
    official = _load()
    if official is not None:
        return tld in official
    return tld.startswith("xn--") or (len(tld) == 2 and tld.isalpha()) or tld in _FALLBACK


def status() -> dict[str, Any]:
    official = _load()
    p = path()
    return {
        "source": "iana" if official is not None else "builtin",
        "count": len(official) if official is not None else None,
        "updated": time.strftime("%Y-%m-%d", time.localtime(p.stat().st_mtime))
        if official is not None else None,
        "url": IANA_URL,
    }


def download(proxy: str | None = None, timeout: int = 30) -> dict[str, Any]:
    """Fetch the IANA list (through an HTTP(S) proxy if given) and store it.
    Raises on network error or an implausible file; the old copy is kept."""
    handlers = []
    if proxy and proxy.startswith(("http://", "https://")):
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(IANA_URL, headers={"User-Agent": "DocuTraceX"})
    with opener.open(req, timeout=timeout) as r:
        text = r.read().decode("ascii", "replace")
    if len(parse(text)) < 100:
        raise ValueError("IANA list looks empty or invalid")
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(text, encoding="ascii", errors="replace")
    tmp.replace(p)
    return status()


def stale() -> bool:
    try:
        return time.time() - path().stat().st_mtime > MAX_AGE
    except OSError:
        return True
