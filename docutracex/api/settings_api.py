"""Settings API: network (proxy, risk acknowledgement) and its test."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Body, HTTPException

from .. import appsettings

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/network")
async def get_network() -> dict:
    from ..netcheck import ipinfo, shot

    return {**appsettings.public_network(), "ipdb": ipinfo.db_status(),
            "chromium": shot.browsers_path().is_dir()}


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
