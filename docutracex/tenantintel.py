"""Microsoft 365 tenant → organisation, via AZMap (https://azmap.dev), and the
message's domains → their tenant, via Microsoft's public sign-in endpoints.

Automatic (the owner's decision), and only these values leave the machine:

- to AZMap: the tenant ID from ``X-MS-Exchange-CrossTenant-Id`` (its brand and
  current domains);
- to tenant.fyi (https://tenant.fyi, public API, no key): the same tenant ID —
  its names over time and every domain it has held, current *and former*
  (first / last seen). The answer is stored in the case and kept in the cache
  for good: if the site, or the tenant's data, disappears later, the last
  answer is still there;
- to Microsoft (login.microsoftonline.com, no account, no token): the sender's
  domains (From / Reply-To / Return-Path / Sender, never your own; at most 10;
  answers cached 7 days like AZMap's), to learn
  which tenant each one is registered to (OpenID configuration) and whether it
  is a Managed or Federated domain (``getuserrealm``, with a made-up user).

Nothing else about the sample is sent. Each can be turned off in Settings →
*Email rules: your organisation* (AZMap + Microsoft, and tenant.fyi apart).

Never blocks the analysis: short timeout, every error becomes a status, and
answers are cached (7 days; failures for 10 minutes) in
``tools/mailintel/azmap_cache.json``. The raw answer is kept. The tenant is an
attribution clue, not proof of who sent the message.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Any

from .config import settings
from .msheaders import GUID

_GUID_IN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

API = "https://azmap.dev/api/tenant?tenant_id={tid}"
MS_OPENID = "https://login.microsoftonline.com/{dom}/v2.0/.well-known/openid-configuration"
MS_REALM = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{dom}&json=1"
MAX_DOMAINS = 10
PAGE = "https://azmap.dev/?tenant_id={tid}"
TTL_OK = 7 * 86400
TTL_FAIL = 600
TIMEOUT = 6
MAX_TENANTS = 3
FYI_API = "https://tenant.fyi/api/tenants/{tid}?status=all&size=500&page={page}"
FYI_PAGE = "https://tenant.fyi/tenants/{tid}"
FYI_MAX_PAGES = 4


def _cache_file(name: str = "azmap_cache.json") -> Path:
    return settings.tools_dir / "mailintel" / name


def _load_cache(name: str = "azmap_cache.json") -> dict[str, Any]:
    try:
        return json.loads(_cache_file(name).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _save_cache(c: dict[str, Any], name: str = "azmap_cache.json") -> None:
    try:
        p = _cache_file(name)
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


def fyi_enabled() -> bool:
    try:
        from . import appsettings
        return bool(appsettings.load().get("tenant_fyi_lookup", True))
    except Exception:  # noqa: BLE001
        return True


def _fyi_normalise(pages: list[Any]) -> dict[str, Any]:
    """tenant.fyi's ``/api/tenants/{id}`` pages → names over time and every domain
    (``active`` false = former, with first / last seen)."""
    names: list[str] = []
    domains: list[dict[str, Any]] = []
    head = pages[0] if pages and isinstance(pages[0], dict) else {}
    if not head:
        raise ValueError("unexpected answer")
    t = head.get("tenant")
    if isinstance(t, dict):
        names += [str(t.get(k)) for k in ("name", "tenant_name", "brand", "current_name") if t.get(k)]
    for n in head.get("tenant_names") or []:
        v = n.get("name") or n.get("tenant_name") or n.get("brand") if isinstance(n, dict) else n
        if v:
            names.append(str(v))
    for pg in pages:
        for d in (pg or {}).get("domains") or [] if isinstance(pg, dict) else []:
            if not isinstance(d, dict):
                d = {"domain": d, "active": True}
            name = str(d.get("domain") or d.get("name") or "").strip().lower().rstrip(".")
            if not name or "." not in name:
                continue
            active = d.get("active")
            if active is None:
                active = str(d.get("status") or "").lower() not in ("inactive", "former", "removed", "moved")
            domains.append({"domain": name, "current": bool(active), "status": str(d.get("status") or ""),
                            "first_seen": str(d.get("first_seen") or ""), "last_seen": str(d.get("last_seen") or ""),
                            "microsoft": name.endswith((".onmicrosoft.com", ".mail.onmicrosoft.com"))})
    seen: dict[str, dict[str, Any]] = {}
    for d in domains:
        if d["domain"] not in seen or (d["current"] and not seen[d["domain"]]["current"]):
            seen[d["domain"]] = d
    domains = list(seen.values())
    onms = next((d["domain"].split(".")[0] for d in domains if d["domain"].endswith(".onmicrosoft.com")
                 and not d["domain"].endswith(".mail.onmicrosoft.com")), "")
    return {"names": list(dict.fromkeys(n for n in names if n and n != "None")), "tenant_name": onms,
            "current_domains": [d["domain"] for d in domains if d["current"]],
            "former_domains": [d["domain"] for d in domains if not d["current"]], "domains": domains,
            "total": head.get("total", len(domains))}


def fyi_lookup(tid: str, proxy: str | None = None, timeout: int = TIMEOUT) -> dict[str, Any]:
    """tenant.fyi: {tenant_id, status: ok|not_found|error|invalid, data?, raw?, error?, cached, stale?, source}.

    Answers are kept for good (``tenantfyi_cache.json``): a fresh one is reused
    for 7 days, and when the site fails or no longer has the tenant, the last good
    answer is returned (``stale``) instead of losing it."""
    tid = (tid or "").strip().lower()
    base = {"tenant_id": tid, "source": FYI_PAGE.format(tid=tid), "provider": "tenant.fyi"}
    if not GUID.match(tid):
        return {**base, "status": "invalid", "cached": False}
    cache = _load_cache("tenantfyi_cache.json")
    hit = cache.get(tid)
    if hit and time.time() - hit.get("ts", 0) < (TTL_OK if hit.get("status") in ("ok", "not_found") else TTL_FAIL):
        return {**hit, "cached": True}
    pages: list[Any] = []
    route, err, missing = "", "", False
    for page in range(1, FYI_MAX_PAGES + 1):
        raw, route, err = _get_json(FYI_API.format(tid=tid, page=page), proxy, timeout)
        if raw is None:
            break
        if isinstance(raw, dict) and raw.get("detail") and not raw.get("domains"):
            missing = page == 1                               # {"detail": "..."}: 404 / not known
            break
        pages.append(raw)
        if not isinstance(raw, dict) or len(raw.get("domains") or []) < int(raw.get("size") or 500) \
                or page * int(raw.get("size") or 500) >= int(raw.get("total") or 0):
            break
    if pages:
        try:
            data = _fyi_normalise(pages)
            rec = {**base, "status": "ok" if data["domains"] or data["names"] else "not_found", "data": data,
                   "raw": pages[0] if len(pages) == 1 else pages, "route": route}
        except Exception as exc:  # noqa: BLE001
            rec = {**base, "status": "error", "error": f"invalid answer ({exc})"[:300]}
    elif missing:
        rec = {**base, "status": "not_found", "route": route}
    else:
        rec = {**base, "status": "error", "error": err or "no answer"}
    rec["ts"] = time.time()
    if rec["status"] != "ok" and hit and hit.get("status") == "ok":
        # keep what we had: the site may be down, or the tenant gone from it
        kept = {**hit, "stale": True, "stale_reason": rec.get("error") or rec["status"], "checked": rec["ts"]}
        cache[tid] = kept
        _save_cache(cache, "tenantfyi_cache.json")
        return {**kept, "cached": True}
    cache[tid] = rec
    _save_cache(cache, "tenantfyi_cache.json")
    return {**rec, "cached": False}


def _merge_fyi(r: dict[str, Any], f: dict[str, Any]) -> None:
    """tenant.fyi's names and domains into the AZMap record (it fills what AZMap lacks;
    former domains come mainly from it)."""
    r["fyi"] = f
    fd = f.get("data") or {}
    if f.get("status") != "ok" or not fd:
        return
    if r.get("status") != "ok":                        # AZMap failed or did not know it: tenant.fyi alone
        r["status"] = "ok"
        r["data"] = {"tenant_name": "", "brand_name": "", "related_domains": [], "former_domains": [],
                     "domains": [], "related_count": 0}
    d = r["data"]
    d.setdefault("domains", [])
    if not d.get("tenant_name") and fd.get("tenant_name"):
        d["tenant_name"] = fd["tenant_name"]
    if not d.get("brand_name") and fd.get("names"):
        d["brand_name"] = fd["names"][0]
    d["names"] = list(dict.fromkeys([*(d.get("names") or []), *fd.get("names", [])]))
    cur = list(d.get("related_domains") or [])
    former = list(d.get("former_domains") or [])
    known = {e["domain"] for e in d["domains"] if isinstance(e, dict)}
    for e in fd.get("domains") or []:
        if e["current"] and e["domain"] not in cur and e["domain"] not in former:
            cur.append(e["domain"])
        elif not e["current"] and e["domain"] not in former and e["domain"] not in cur:
            former.append(e["domain"])
        if e["domain"] not in known:
            d["domains"].append({**e, "type": "", "source": "tenant.fyi"})
        else:
            for x in d["domains"]:
                if x.get("domain") == e["domain"]:
                    x.update({k: e[k] for k in ("first_seen", "last_seen") if e.get(k)})
    d["related_domains"], d["former_domains"] = cur, former
    d["sources"] = list(dict.fromkeys([*(d.get("sources") or ["AZMap"]), "tenant.fyi"]))


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


def _get_json(url: str, proxy: str | None, timeout: int) -> tuple[Any, str, str]:
    """(answer, route, error): the first route that answers; an HTTP 400 / 404
    with a JSON body is an answer too (Microsoft's "tenant not found")."""
    import urllib.error

    from .mailintel import _routes, _short
    errors = []
    for label, opener in _routes(proxy):
        req = urllib.request.Request(url, headers={"User-Agent": "DocuTraceX", "Accept": "application/json"})
        try:
            with opener.open(req, timeout=timeout) as r:
                return json.loads(r.read(512 * 1024).decode("utf-8", "replace")), label, ""
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 404):
                try:
                    return json.loads(exc.read(64 * 1024).decode("utf-8", "replace") or "{}"), label, ""
                except Exception:  # noqa: BLE001
                    return {}, label, ""
            errors.append(f"{label}: {_short(exc)}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{label}: {_short(exc) if not isinstance(exc, ValueError) else 'invalid answer'}")
    return None, "", "; ".join(errors)[:300] or "no route"


def domain_lookup(domain: str, proxy: str | None = None, timeout: int = TIMEOUT) -> dict[str, Any]:
    """Which Microsoft 365 / Entra tenant ``domain`` is registered to, straight
    from Microsoft. {domain, status: ok|not_in_entra|error, tenant_id,
    namespace (Managed / Federated), brand, cached, source} — cached 7 days like AZMap."""
    dom = (domain or "").strip().lower().rstrip(".")
    base = {"domain": dom, "source": MS_OPENID.format(dom=dom)}
    if not dom or "." not in dom or "/" in dom:
        return {**base, "status": "invalid", "cached": False}
    cache = _load_cache()
    key = "dom:" + dom
    hit = cache.get(key)
    if hit and time.time() - hit.get("ts", 0) < (TTL_OK if hit.get("status") in ("ok", "not_in_entra") else TTL_FAIL):
        return {**hit, "cached": True}
    oid, route, err = _get_json(MS_OPENID.format(dom=dom), proxy, timeout)
    if oid is None:
        rec = {**base, "status": "error", "error": err}
    else:
        m = _GUID_IN.search(str((oid or {}).get("issuer") or (oid or {}).get("token_endpoint") or ""))
        rec = {**base, "status": "ok" if m else "not_in_entra", "tenant_id": m.group(0).lower() if m else "",
               "region": (oid or {}).get("tenant_region_scope", ""), "route": route}
        realm, _r, _e = _get_json(MS_REALM.format(dom=dom), proxy, timeout)
        if isinstance(realm, dict):
            rec.update(namespace=str(realm.get("NameSpaceType") or ""),
                       brand=str(realm.get("FederationBrandName") or ""),
                       federation=str(realm.get("AuthURL") or "").split("/")[2] if realm.get("AuthURL") else "")
    rec["ts"] = time.time()
    cache[key] = rec
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
    azmap_on, fyi_on = enabled(), fyi_enabled()
    if not azmap_on and not fyi_on:
        return {"status": "disabled", "tenants": [{"tenant_id": t, "status": "disabled", "source": PAGE.format(tid=t)}
                                                   for t in tids]}
    roles = {b["tenant_id"]: b["role"] for b in ms.get("tenant_blocks") or []}
    own = {_reg(d) for d in own_domains}
    mine = {_reg(d) for d in email_domains if d}
    out = []
    for t in tids:
        try:
            r = lookup(t, proxy) if azmap_on else {"tenant_id": t, "status": "disabled", "source": FYI_PAGE.format(tid=t)}
        except Exception as exc:  # noqa: BLE001  (never breaks the analysis)
            r = {"tenant_id": t, "status": "error", "error": str(exc)[:200], "source": PAGE.format(tid=t)}
        if fyi_on:
            try:
                _merge_fyi(r, fyi_lookup(t, proxy))
            except Exception as exc:  # noqa: BLE001
                r["fyi"] = {"tenant_id": t, "status": "error", "error": str(exc)[:200], "provider": "tenant.fyi",
                            "source": FYI_PAGE.format(tid=t)}
        rel = {_reg(d) for d in ((r.get("data") or {}).get("related_domains") or [])}
        r["role"] = roles.get(t, "unknown")
        r["own_tenant"] = bool(own & rel)
        if r["own_tenant"]:
            r["role"] = "receiver (your organisation)"
        r["matched_domains"] = sorted(mine & rel)
        out.append(r)
    doms = []
    for d in [] if not azmap_on else [x for x in dict.fromkeys(_reg(e) for e in email_domains if e) if x not in own][:MAX_DOMAINS]:
        try:
            doms.append(domain_lookup(d, proxy))
        except Exception as exc:  # noqa: BLE001
            doms.append({"domain": d, "status": "error", "error": str(exc)[:200]})
    return {"status": "ok", "tenants": out, "domains": doms}


def add_iocs(ioc_result: dict[str, Any], mailrules: dict[str, Any] | None) -> int:
    """The sender's tenant into the IOCs (in place): its ID (type ``ms_tenant``, with
    its names), its ``*.onmicrosoft.com`` name and every *former* domain it held
    (AZMap / tenant.fyi), tagged ``tenant``. Never the own organisation's tenant;
    current domains stay context (the tenant card), not indicators. Returns how many."""
    t = (mailrules or {}).get("tenant") or {}
    iocs = ioc_result.setdefault("iocs", [])
    by_key = {(i.get("type"), i.get("value")): i for i in iocs}
    n = 0

    def add(typ: str, value: str, ctx: str, tag: dict[str, Any]) -> None:
        nonlocal n
        occ = {"module": "mailrules", "location": f"tenant/{tag['tenant_id']}", "context": ctx[:300]}
        i = by_key.get((typ, value))
        if i is None:
            i = {"type": typ, "value": value, "occurrences": []}
            iocs.append(i)
            by_key[(typ, value)] = i
        i["occurrences"].append(occ)
        i["count"] = len(i["occurrences"])
        i["tenant"] = tag
        n += 1

    for r in t.get("tenants") or []:
        if r.get("status") != "ok" or r.get("own_tenant") or str(r.get("role", "")).startswith("receiver"):
            continue
        d = r.get("data") or {}
        tid = r.get("tenant_id", "")
        who = " · ".join(x for x in (d.get("brand_name"), d.get("tenant_name")) if x) or tid
        names = list(dict.fromkeys([x for x in (d.get("brand_name"), d.get("tenant_name")) if x] + (d.get("names") or [])))
        base = {"tenant_id": tid, "name": who, "names": names[:10], "role": r.get("role", "")}
        add("ms_tenant", tid, f"Microsoft 365 tenant {who} ({r.get('role', 'unknown')}) — names: {', '.join(names) or '?'}",
            {**base, "why": "tenant ID"})
        if d.get("tenant_name"):
            add("domain", f"{d['tenant_name'].lower()}.onmicrosoft.com", f"initial domain of tenant {who}",
                {**base, "why": "tenant name"})
        seen = {e.get("domain"): e for e in d.get("domains") or [] if isinstance(e, dict)}
        for dom in d.get("former_domains") or []:
            e = seen.get(dom, {})
            when = " → ".join(x for x in (e.get("first_seen"), e.get("last_seen")) if x)
            add("domain", dom, f"former domain of tenant {who}" + (f" ({when})" if when else ""),
                {**base, "why": "former domain" + (f" ({when})" if when else "")})
    counts: dict[str, int] = {}
    for i in iocs:
        counts[i["type"]] = counts.get(i["type"], 0) + 1
    counts["total"] = len(iocs)
    ioc_result["counts"] = counts
    iocs.sort(key=lambda i: (i["type"], i["value"]))
    return n
