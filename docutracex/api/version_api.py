"""Newer version on GitHub, what changed, and the one-click update (admin)."""

from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Request

from .. import users, versioninfo
from ..config import settings

router = APIRouter(prefix="/api/version", tags=["version"])


def _admin(request: Request) -> str:
    me = getattr(request.state, "user", "") or ""
    if not me or users.role(me) != "admin":
        raise HTTPException(status_code=403, detail="Only the admin can update DocuTraceX.")
    return me


@router.get("")
async def version_status(refresh: bool = False) -> dict:
    """Running version, the latest on GitHub (checked in the background) and whether
    an update is available."""
    return versioninfo.status(force=refresh)


@router.get("/upcoming")
async def version_upcoming() -> dict:
    """The changelog of the newer version(s) not installed yet."""
    st = versioninfo.status()
    return {**st, "entries": versioninfo.upcoming() if st["update_available"] else []}


@router.get("/whatsnew")
async def version_whatsnew() -> dict:
    """What changed since the version this installation last showed (after an update)."""
    return versioninfo.whats_new()


@router.post("/seen")
async def version_seen() -> dict:
    versioninfo.mark_seen()
    return {"ok": True}


@router.post("/check")
async def version_check(request: Request, payload: dict = Body(default={})) -> dict:
    """Turn the background check on or off (``{"enabled": bool}``, admin)."""
    _admin(request)
    if "enabled" in payload:
        versioninfo.set_check(bool(payload["enabled"]))
    return versioninfo.status(force=bool(payload.get("enabled")))


@router.post("/update")
async def version_update(request: Request, payload: dict = Body(default={})) -> dict:
    """Stop DocuTraceX, update without asking, re-provision and start it again
    (``run.py --update``). Refused while analyses run unless ``force``."""
    _admin(request)   # the audit trail records who (middleware)
    from ..tasks import manager
    busy = manager.active_count()
    if busy and not payload.get("force"):
        raise HTTPException(status_code=409,
                            detail=f"{busy} analysis task(s) still running: they would be cut off.")
    try:
        out = versioninfo.start_update(settings.host, settings.port)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not start the update: {exc}") from exc
    versioninfo.stop_soon()
    return {**out, "from": versioninfo.__version__}
