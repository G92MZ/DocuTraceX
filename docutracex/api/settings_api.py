"""Settings API: network (proxy, risk acknowledgement) and its test."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Body, HTTPException

from .. import appsettings

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/analysis")
async def get_analysis() -> dict:
    return {"concurrency": appsettings.analysis_concurrency(),
            "min": appsettings.MIN_CONCURRENCY, "max": appsettings.MAX_CONCURRENCY}


@router.put("/analysis")
async def put_analysis(payload: dict = Body(...)) -> dict:
    if "concurrency" not in payload:
        raise HTTPException(status_code=400, detail="concurrency is required")
    try:
        n = int(payload["concurrency"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="concurrency must be a number") from exc
    n = appsettings.set_concurrency(n)
    from ..tasks import manager
    manager.reconcile()
    return {"concurrency": n, "min": appsettings.MIN_CONCURRENCY, "max": appsettings.MAX_CONCURRENCY}


@router.get("/network")
async def get_network() -> dict:
    from ..netcheck import freeproxy, ipinfo, shot

    from .. import tlds

    return {**appsettings.public_network(), "ipdb": ipinfo.db_status(), "tlds": tlds.status(),
            "chromium": shot.browsers_path().is_dir(), "free_lists": freeproxy.status()}


@router.put("/network")
async def put_network(payload: dict = Body(...)) -> dict:
    data = appsettings.load()
    net = data["network"]
    if "proxy" in payload:
        incoming = dict(payload["proxy"] or {})
        if incoming.get("password") is None:  # not sent: keep the stored one
            incoming["password"] = net["proxy"].get("password", "")
        try:
            net["proxy"] = appsettings.validate_proxy(incoming)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if "risk_accepted" in payload:
        net["risk_accepted"] = bool(payload["risk_accepted"])
    appsettings.save(data)
    return appsettings.public_network()


@router.post("/network/test")
async def test_network(payload: dict = Body(default={})) -> dict:
    """Public IP seen through the proxy (the one in the form, or the saved one)."""
    from ..netcheck import http

    proxy = appsettings.proxy_url()
    if payload.get("proxy"):
        p = dict(payload["proxy"])
        if p.get("password") is None:
            p["password"] = appsettings.load()["network"]["proxy"].get("password", "")
        try:
            p = appsettings.validate_proxy({**p, "enabled": True})
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        proxy = appsettings.proxy_url({"proxy": p})
    res = await asyncio.to_thread(http.egress_ip, proxy)
    res["via"] = "proxy" if proxy else "direct"
    return res


@router.post("/network/free-proxy")
async def free_proxy(payload: dict = Body(default={})) -> dict:
    """Pick a working proxy from the ProxyScrape free list and make it the app's
    proxy (``rotate``: skip the current one). Tests candidates in parallel."""
    from ..netcheck import freeproxy

    # tag: gmzpt
    protocol = str(payload.get("protocol") or "http").lower()
    country = str(payload.get("country") or "").strip()[:2]
    try:
        found = await asyncio.to_thread(freeproxy.connect, protocol, country, bool(payload.get("rotate")))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001  (list download failed, offline…)
        raise HTTPException(status_code=502, detail=f"free proxy list unavailable: {exc}") from exc
    return {"found": found, **appsettings.public_network()}


@router.post("/tlds/refresh")
async def refresh_tlds() -> dict:
    """Download the IANA TLD list again (through the HTTP proxy if one is set)."""
    from .. import tlds

    try:
        return await asyncio.to_thread(tlds.download, appsettings.proxy_url())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Could not download the IANA list: {exc}") from exc


@router.get("/mailintel")
async def mailintel_status() -> dict:
    """Email reputation lists (free webmail, disposable, phishing, URLhaus): state."""
    from .. import mailintel
    return mailintel.status()


@router.post("/mailintel/refresh")
async def mailintel_refresh() -> dict:
    """Download the email reputation lists again (through the HTTP proxy if one is set)."""
    from .. import mailintel
    return await asyncio.to_thread(mailintel.refresh, appsettings.proxy_url())


@router.get("/abusech")
async def abusech_get() -> dict:
    """Whether an abuse.ch Auth-Key is set (never returned in full)."""
    return appsettings.public_abusech()


@router.put("/abusech")
async def abusech_put(body: dict = Body(...)) -> dict:
    """Store the free abuse.ch Auth-Key used to download the URLhaus export ("" removes it)."""
    try:
        return appsettings.set_abusech_key(str(body.get("auth_key") or ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/tenant-lookup")
async def tenant_lookup_get() -> dict:
    """Whether X-MS-Exchange-CrossTenant-Id is resolved with AZMap (on by default)."""
    return {"enabled": bool(appsettings.load().get("tenant_lookup", True))}


@router.put("/tenant-lookup")
async def tenant_lookup_put(body: dict = Body(...)) -> dict:
    data = appsettings.load()
    data["tenant_lookup"] = bool(body.get("enabled", True))
    appsettings.save(data)
    return {"enabled": data["tenant_lookup"]}


@router.get("/tenant-fyi-lookup")
async def tenant_fyi_lookup_get() -> dict:
    """Whether the tenant ID is also looked up in tenant.fyi (names, current and former domains; on by default)."""
    return {"enabled": bool(appsettings.load().get("tenant_fyi_lookup", True))}


@router.put("/tenant-fyi-lookup")
async def tenant_fyi_lookup_put(body: dict = Body(...)) -> dict:
    data = appsettings.load()
    data["tenant_fyi_lookup"] = bool(body.get("enabled", True))
    appsettings.save(data)
    return {"enabled": data["tenant_fyi_lookup"]}


@router.get("/c2-families")
async def c2_families() -> dict:
    """The families the C2 tab covers in depth, with what each one is and what is read from it."""
    from ..c2.families import FAMILIES
    return {"families": [{k: v for k, v in f.items() if k != "match"} for f in FAMILIES]}


@router.get("/lolrmm")
async def lolrmm_status() -> dict:
    """The LOLRMM catalogue the RMM extractor uses: source, size, date."""
    from .. import lolrmm
    return lolrmm.status()


@router.post("/lolrmm/refresh")
async def lolrmm_refresh() -> dict:
    """Download the LOLRMM catalogue again (through the HTTP proxy if one is set)."""
    from .. import lolrmm
    from ..c2 import registry
    try:
        st = await asyncio.to_thread(lolrmm.download, appsettings.proxy_url())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Could not download the LOLRMM catalogue: {exc}") from exc
    registry.dependency_status("rmm", refresh=True)
    return st


@router.get("/c2-shared")
async def c2_shared_get() -> dict:
    """Cobalt Strike watermarks / public-key SHA-256 known to be shared (leaked, cracked):
    shown with their note, never used to link cases. One per line: ``value note``."""
    from ..c2.cobalt import KNOWN_WATERMARKS
    st = appsettings.load().get("c2_shared") or {}
    lines = [f"{k} {v}".strip() for k, v in (st.get("watermarks") or {}).items()]
    lines += [f"{k} {v}".strip() for k, v in (st.get("pubkeys") or {}).items()]
    return {"text": "\n".join(lines), "builtin": {str(k): v for k, v in KNOWN_WATERMARKS.items()}}


@router.put("/c2-shared")
async def c2_shared_put(body: dict = Body(...)) -> dict:
    import re as _re
    wms: dict[str, str] = {}
    keys: dict[str, str] = {}
    bad = []
    for ln in str(body.get("text") or "").splitlines()[:1000]:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        val, _, note = ln.partition(" ")
        note = note.strip()[:200]
        if val.isdigit() and len(val) <= 10:
            wms[val] = note
        elif _re.fullmatch(r"[0-9a-fA-F]{64}", val):
            keys[val.lower()] = note
        else:
            bad.append(val[:80])
    data = appsettings.load()
    data["c2_shared"] = {"watermarks": wms, "pubkeys": keys}
    appsettings.save(data)
    return {"watermarks": len(wms), "pubkeys": len(keys), "ignored": bad[:20]}


@router.get("/allowed-countries")
async def allowed_countries_get() -> dict:
    """ISO country codes the organisation expects mail servers in (empty = no check)."""
    return {"countries": list(appsettings.load().get("allowed_countries") or [])}


@router.put("/allowed-countries")
async def allowed_countries_put(body: dict = Body(...)) -> dict:
    import re as _re
    raw = body.get("countries") or []
    if isinstance(raw, str):
        raw = _re.split(r"[\s,;]+", raw)
    codes = sorted({str(c).strip().upper() for c in raw if _re.fullmatch(r"[A-Za-z]{2}", str(c).strip())})
    data = appsettings.load()
    data["allowed_countries"] = codes[:250]
    appsettings.save(data)
    return {"countries": data["allowed_countries"]}


@router.get("/email")
async def email_settings_get() -> dict:
    return appsettings.email_settings()


@router.put("/email")
async def email_settings_put(body: dict = Body(...)) -> dict:
    """Own domains, extra brands and the look-alike thresholds (``similarity``)."""
    def norm(v):  # noqa: ANN001
        if isinstance(v, str):
            v = v.splitlines()
        return [str(x).strip() for x in v or [] if str(x).strip()]
    sim = body.get("similarity")
    return appsettings.set_email_settings(norm(body.get("own_domains")), norm(body.get("brands")),
                                          sim if isinstance(sim, dict) else None)


@router.get("/trusted-domains")
async def trusted_domains_get() -> dict:
    return appsettings.trusted_domains()


@router.put("/trusted-domains")
async def trusted_domains_put(body: dict = Body(...)) -> dict:
    """Generic legitimate domains: ``services`` and ``platforms`` (lists or one
    per line), or ``{"restore": true}`` for the built-in defaults."""
    def norm(v):  # noqa: ANN001
        if isinstance(v, str):
            v = v.splitlines()
        return [str(x).strip() for x in v or [] if str(x).strip()]
    return appsettings.set_trusted_domains(norm(body.get("services")), norm(body.get("platforms")),
                                           restore=bool(body.get("restore")))


@router.get("/ml/family")
async def ml_family_status() -> dict:
    """Optional EMBER2024 family model (Machine Learning tab): download state."""
    from ..ml import family_download
    return family_download.status()


@router.post("/ml/family")
async def ml_family_download() -> dict:
    """Start downloading the EMBER2024 family model (459 MB, SHA-256 pinned)."""
    from ..ml import family_download
    return family_download.start(appsettings.proxy_url())
