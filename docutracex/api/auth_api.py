"""Sign-in, first start, the user list, the audit trail and the MCP token.

Everyone signed in uses every feature; only the admin role manages users,
reads the audit trail and regenerates the MCP token.
"""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from .. import audit, users

router = APIRouter(prefix="/api", tags=["auth"])


def _addr(request: Request) -> str:
    return request.client.host if request.client else ""


def _me(request: Request) -> str:
    return getattr(request.state, "user", "") or ""


def _admin(request: Request) -> str:
    me = _me(request)
    if not me or users.role(me) != "admin":
        raise HTTPException(status_code=403, detail="Only the admin can do this.")
    return me


def _cookie(resp: Response, token: str) -> None:
    resp.set_cookie(users.COOKIE, token, httponly=True, samesite="strict", path="/",
                    max_age=users.SESSION_IDLE_HOURS * 3600 * 14)


# --- sign-in --------------------------------------------------------------------
@router.get("/auth/status")
async def status(request: Request) -> dict:
    me = users.session_user(request.cookies.get(users.COOKIE))
    return {"setup_required": users.needs_setup(), "user": me or "",
            "role": users.role(me) if me else "", "min_password": users.MIN_PASSWORD}


@router.post("/auth/setup")
async def setup(request: Request, payload: dict = Body(...)) -> JSONResponse:
    """First start: set the admin password (only while none is set)."""
    if not users.needs_setup():
        raise HTTPException(status_code=409, detail="The admin password is already set.")
    try:
        users.setup_admin(str(payload.get("password") or ""))
    except users.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit.record(users.ADMIN, "set the admin password (first start)", addr=_addr(request),
                 request="POST /api/auth/setup", status=200)
    resp = JSONResponse({"user": users.ADMIN, "role": "admin"})
    _cookie(resp, users.create_session(users.ADMIN))
    return resp


@router.post("/auth/login")
async def login(request: Request, payload: dict = Body(...)) -> JSONResponse:
    name = str(payload.get("username") or "").strip()
    addr = _addr(request)
    wait = users.locked_out(addr)
    if wait:
        audit.record(name, "sign-in refused (too many failures)", addr=addr, request="POST /api/auth/login",
                     status=429)
        raise HTTPException(status_code=429,
                            detail=f"Too many failed attempts: try again in {max(1, wait // 60)} minute(s).")
    if not users.authenticate(name, str(payload.get("password") or ""), addr):
        audit.record(name, "failed sign-in", addr=addr, request="POST /api/auth/login", status=401)
        raise HTTPException(status_code=401, detail="Wrong user name or password.")
    audit.record(name, "signed in", addr=addr, request="POST /api/auth/login", status=200)
    resp = JSONResponse({"user": name, "role": users.role(name)})
    _cookie(resp, users.create_session(name))
    return resp


@router.post("/auth/logout")
async def logout(request: Request) -> JSONResponse:
    users.drop_session(request.cookies.get(users.COOKIE))
    if _me(request):
        audit.record(_me(request), "signed out", addr=_addr(request), request="POST /api/auth/logout", status=200)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(users.COOKIE, path="/")
    return resp


@router.post("/auth/password")
async def own_password(request: Request, payload: dict = Body(...)) -> JSONResponse:
    """Any user: change their own password (the current one is required)."""
    me = _me(request)
    try:
        users.change_own_password(me, str(payload.get("current") or ""), str(payload.get("new") or ""))
    except users.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    resp = JSONResponse({"ok": True})
    _cookie(resp, users.create_session(me))            # the other sessions were closed
    return resp


# --- users (admin) ----------------------------------------------------------------
@router.get("/users")
async def list_users(request: Request) -> dict:
    _admin(request)
    return {"users": users.list_users(), "me": _me(request)}


@router.post("/users")
async def create_user(request: Request, payload: dict = Body(...)) -> dict:
    _admin(request)
    try:
        return users.create_user(str(payload.get("username") or ""), str(payload.get("password") or ""),
                                 str(payload.get("role") or "user"))
    except users.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/users/{name}")
async def update_user(name: str, request: Request, payload: dict = Body(...)) -> dict:
    _admin(request)
    try:
        return users.update_user(name, password=payload.get("password"),
                                 active=payload.get("active"), user_role=payload.get("role"))
    except users.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/users/{name}")
async def delete_user(name: str, request: Request) -> dict:
    _admin(request)
    try:
        users.delete_user(name)
    except users.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"deleted": name}


# --- audit (admin) ----------------------------------------------------------------
@router.get("/audit")
async def audit_log(request: Request, user: str = Query(""), action: str = Query(""), case: str = Query(""),
                    limit: int = Query(500, ge=1, le=20000)) -> dict:
    _admin(request)
    return {"entries": audit.read(user=user, action=action, case=case, limit=limit)}


@router.get("/audit.csv")
async def audit_csv(request: Request, user: str = Query(""), action: str = Query(""),
                    case: str = Query("")) -> Response:
    _admin(request)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["time", "user", "action", "case", "detail", "addr", "request", "status"]
    w.writerow(cols)
    for e in audit.read(user=user, action=action, case=case, limit=1_000_000):
        w.writerow([e.get(c, "") for c in cols])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="docutracex_audit.csv"'})


# --- MCP token ---------------------------------------------------------------------
@router.get("/mcp/token")
async def mcp_token(request: Request) -> dict:
    """Every signed-in user may read it (they all see the same cases); the admin regenerates it."""
    return {"token": users.mcp_token(), "can_regenerate": users.role(_me(request)) == "admin"}


@router.post("/mcp/token")
async def regenerate_mcp_token(request: Request) -> dict:
    _admin(request)
    return {"token": users.regenerate_mcp_token()}
