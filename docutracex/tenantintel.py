"""Microsoft 365 tenant → organisation, via AZMap (https://azmap.dev).

Automatic (the owner's decision): only the tenant ID from
``X-MS-Exchange-CrossTenant-Id`` is sent, nothing else about the sample. It can
be turned off in Settings → *Email rules: your organisation*.

Never blocks the analysis: short timeout, every error becomes a status, and
answers are cached (7 days; failures for 10 minutes) in
``tools/mailintel/azmap_cache.json``. The raw answer is kept. The tenant is an
attribution clue, not proof of who sent the message.
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Any

from .config import settings
from .msheaders import GUID

API = "https://azmap.dev/api/tenant?tenant_id={tid}"
PAGE = "https://azmap.dev/?tenant_id={tid}"
TTL_OK = 7 * 86400
TTL_FAIL = 600
TIMEOUT = 6
MAX_TENANTS = 3


def _cache_file() -> Path:
    return settings.tools_dir / "mailintel" / "azmap_cache.json"


def _load_cache() -> dict[str, Any]:
    try:
        return json.loads(_cache_file().read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _save_cache(c: dict[str, Any]) -> None:
    try:
        p = _cache_file()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(c, ensure_ascii=True), encoding="utf-8")
        tmp.replace(p)
    except Exception:  # noqa: BLE001
        pass


def enabled() -> bool:
    try:
        from . import appsettings
        return bool(appsettings.load().get("tenant_lookup", True))
    except Exception:  # noqa: BLE001
        return True


_FORMER_KEYS = ("former_domains", "removed_domains", "previous_domains", "historical_domains")
_FORMER_WORDS = {"removed", "former", "previous", "historical", "deleted"}


def _domain_entry(d: Any, former: bool = False) -> dict[str, Any] | None:
    """One tenant domain, as a string or as an object (``domain`` / ``name``,
    ``type`` Managed / Federated, ``removed`` / ``status`` / ``current``)."""
    if isinstance(d, dict):
        name = d.get("domain") or d.get("name") or d.get("id") or ""
        typ = str(d.get("type") or d.get("authentication") or d.get("kind") or "")
        status = str(d.get("status") or d.get("state") or "").lower()
        former = former or bool(d.get("removed") or d.get("former")) or status in _FORMER_WORDS \
            or d.get("current") is False
    else:
        name, typ = d, ""
    name = str(name).strip().lower().rstrip(".")
    if not name or "." not in name:
        return None
    return {"domain": name, "type": typ, "current": not former,
            "microsoft": name.endswith((".onmicrosoft.com", ".mail.onmicrosoft.com"))}


def _normalise(raw: Any) -> dict[str, Any]:
    """AZMap's answer: tenant name, brand, and every domain it lists for the
    tenant — current ones in ``related_domains`` (as before), former / removed
    ones in ``former_domains``, all of them with their type in ``domains``."""
    if not isinstance(raw, dict):
        raise ValueError("unexpected answer")
    entries: list[dict[str, Any]] = []
    for d in raw.get("related_domains") or raw.get("domains") or []:
        if (e := _domain_entry(d)) is not None:
            entries.append(e)
    for k in _FORMER_KEYS:
        for d in raw.get(k) or []:
            if (e := _domain_entry(d, former=True)) is not None:
                entries.append(e)
    seen: dict[str, dict[str, Any]] = {}
    for e in entries:
        if e["domain"] not in seen or (e["current"] and not seen[e["domain"]]["current"]):
            seen[e["domain"]] = e
    entries = list(seen.values())[:500]
    cur = [e["domain"] for e in entries if e["current"]]
    return {"tenant_name": raw.get("tenant_name") or "", "brand_name": raw.get("brand_name") or "",
            "related_domains": cur, "former_domains": [e["domain"] for e in entries if not e["current"]],
            "domains": entries, "related_count": raw.get("related_count", len(cur))}


def lookup(tid: str, proxy: str | None = None, timeout: int = TIMEOUT) -> dict[str, Any]:
    """{tenant_id, status: ok|not_found|error|invalid, data?, raw?, error?, cached, source}"""
    tid = (tid or "").strip().lower()
    base = {"tenant_id": tid, "source": PAGE.format(tid=tid)}
    if not GUID.match(tid):
        return {**base, "status": "invalid", "cached": False}
    cache = _load_cache()
    hit = cache.get(tid)
    if hit and time.time() - hit.get("ts", 0) < (TTL_OK if hit.get("status") in ("ok", "not_found") else TTL_FAIL):
        return {**hit, "cached": True}
    from .mailintel import _routes, _short
    rec: dict[str, Any] = {**base, "status": "error", "error": "no route"}
    errors = []
    for label, opener in _routes(proxy):
        req = urllib.request.Request(API.format(tid=tid), headers={"User-Agent": "DocuTraceX", "Accept": "application/json"})
        try:
            with opener.open(req, timeout=timeout) as r:
                body = r.read(2 * 1024 * 1024).decode("utf-8", "replace")
            raw = json.loads(body)
            data = _normalise(raw)
            found = bool(data["tenant_name"] or data["brand_name"] or data["related_domains"])
            rec = {**base, "status": "ok" if found else "not_found", "data": data, "raw": raw, "route": label}
            break
        except Exception as exc:  # noqa: BLE001
            reason = _short(exc) if not isinstance(exc, ValueError) else f"invalid answer ({exc})"
            if reason.startswith("HTTP 404"):
                rec = {**base, "status": "not_found", "route": label}
                break
            errors.append(f"{label}: {reason}")
            rec = {**base, "status": "error", "error": "; ".join(errors)[:300]}
    rec["ts"] = time.time()
    cache[tid] = rec
    if len(cache) > 5000:
        for k in sorted(cache, key=lambda k: cache[k].get("ts", 0))[:1000]:
            cache.pop(k, None)
    _save_cache(cache)
    return {**rec, "cached": False}


def _reg(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "gob", "gov", "org", "net", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def resolve(ms: dict[str, Any], email_domains: list[str], own_domains: list[str],
            proxy: str | None = None) -> dict[str, Any]:
    """Look up the message's tenants and cross them with the message's domains."""
    tids = list(dict.fromkeys(ms.get("tenant_ids") or []))[:MAX_TENANTS]
    if not tids:
        return {}
    if not enabled():
        return {"status": "disabled", "tenants": [{"tenant_id": t, "status": "disabled", "source": PAGE.format(tid=t)}
                                                   for t in tids]}
    roles = {b["tenant_id"]: b["role"] for b in ms.get("tenant_blocks") or []}
    own = {_reg(d) for d in own_domains}
    mine = {_reg(d) for d in email_domains if d}
    out = []
    for t in tids:
        try:
            r = lookup(t, proxy)
        except Exception as exc:  # noqa: BLE001  (never breaks the analysis)
            r = {"tenant_id": t, "status": "error", "error": str(exc)[:200], "source": PAGE.format(tid=t)}
        rel = {_reg(d) for d in ((r.get("data") or {}).get("related_domains") or [])}
        r["role"] = roles.get(t, "unknown")
        r["own_tenant"] = bool(own & rel)
        if r["own_tenant"]:
            r["role"] = "receiver (your organisation)"
        r["matched_domains"] = sorted(mine & rel)
        out.append(r)
    return {"status": "ok", "tenants": out}
