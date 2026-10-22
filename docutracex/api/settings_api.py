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

    return {**appsettings.public_network(), "ipdb": ipinfo.db_status(),
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
