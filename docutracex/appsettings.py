"""User settings that persist across runs (``config/settings.json``, git-ignored).

Currently the network section:

- ``proxy``: optional HTTP/HTTPS/SOCKS4/SOCKS5 proxy (``free``: picked from the
  ProxyScrape free list, see ``netcheck.freeproxy``) used by every feature of the app
  that goes to the Internet (URL/domain/IP checks). The installer and
  ``update.py`` never use it.
- ``risk_accepted``: the analyst chose, once, to run network checks without a
  proxy (from their own IP). Can be reset from the Settings tab.

The password is stored in plain text in this local file (it never leaves the
machine); the UI says so.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .config import APP_ROOT

_LOCK = threading.Lock()
_SCHEMES = ("http", "https", "socks4", "socks5")

DEFAULTS: dict[str, Any] = {
    "network": {
        "proxy": {"enabled": False, "scheme": "http", "host": "", "port": 8080, "username": "", "password": "",
                  "free": False, "free_info": {}},
        "risk_accepted": False,
    },
    "analysis": {
        # How many files are analysed at once (the rest queue). Editable from the
        # UI; env ``DOCUTRACEX_MAX_CONCURRENCY`` sets the initial default.
        "concurrency": max(1, min(8, int(os.environ.get("DOCUTRACEX_MAX_CONCURRENCY", "4")))),
    },
}

MIN_CONCURRENCY, MAX_CONCURRENCY = 1, 8


def analysis_concurrency() -> int:
    try:
        n = int(load().get("analysis", {}).get("concurrency", 4))
    except (TypeError, ValueError):
        n = 4
    return max(MIN_CONCURRENCY, min(MAX_CONCURRENCY, n))


def set_concurrency(n: int) -> int:
    n = max(MIN_CONCURRENCY, min(MAX_CONCURRENCY, int(n)))
    data = load()
    data.setdefault("analysis", {})["concurrency"] = n
    save(data)
    return n


def config_dir() -> Path:
    return Path(os.environ.get("DOCUTRACEX_CONFIG_DIR") or APP_ROOT / "config")


def settings_path() -> Path:
    return config_dir() / "settings.json"


def _merge(base: dict, over: dict) -> dict:
    """Deep merge into a *copy* of ``base`` (never hand out DEFAULTS itself)."""
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load() -> dict[str, Any]:
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return _merge(DEFAULTS, data if isinstance(data, dict) else {})


def save(data: dict[str, Any]) -> dict[str, Any]:
    merged = _merge(DEFAULTS, data)
    with _LOCK:
        p = settings_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        tmp.replace(p)
    # id: gmzpt
    return merged


def validate_proxy(proxy: dict[str, Any]) -> dict[str, Any]:
    """Normalise and check a proxy dict coming from the UI. Raises ValueError."""
    scheme = str(proxy.get("scheme") or "http").lower()
    if scheme not in _SCHEMES:
        raise ValueError(f"proxy type must be one of {', '.join(_SCHEMES)}")
    host = str(proxy.get("host") or "").strip()
    enabled = bool(proxy.get("enabled"))
    # id: gmzpt
    try:
        port = int(proxy.get("port") or 0)
    except (TypeError, ValueError):
        raise ValueError("port must be a number") from None
    if enabled and (not host or not 0 < port < 65536):
        raise ValueError("host and a valid port are required")
    if any(c in host for c in "/@ "):
        raise ValueError("host must be a hostname or IP, without scheme or path")
    # A proxy typed in by the analyst is not a "free proxy" any more.
    return {"enabled": enabled, "scheme": scheme, "host": host, "port": port or 8080,
            "username": str(proxy.get("username") or ""), "password": str(proxy.get("password") or ""),
            "free": False, "free_info": {}}


def proxy_url(net: dict[str, Any] | None = None) -> str | None:
    """requests-style proxy URL, or None when no proxy is enabled.
    SOCKS5 uses ``socks5h`` so host names are resolved by the proxy too."""
    p = (net or load()["network"])["proxy"]
    if not p.get("enabled") or not p.get("host"):
        return None
    scheme = {"socks5": "socks5h", "socks4": "socks4"}.get(p["scheme"], p["scheme"])
    auth = ""
    if p.get("username"):
        auth = quote(p["username"], safe="") + (":" + quote(p.get("password") or "", safe="")) + "@"
    return f"{scheme}://{auth}{p['host']}:{p['port']}"


def proxy_is_free(net: dict[str, Any] | None = None) -> bool:
    """The active proxy is a free public one (untrusted: strict TLS, labelled)."""
    n = net or load()["network"]
    return bool(proxy_url(n) and n["proxy"].get("free"))


def public_network() -> dict[str, Any]:
    """Network settings for the UI (password masked)."""
    net = load()["network"]
    p = dict(net["proxy"])
    p["password_set"] = bool(p.pop("password", ""))
    return {"proxy": p, "risk_accepted": net["risk_accepted"], "proxy_active": proxy_url(net) is not None}
