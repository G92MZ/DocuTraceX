"""Sign-in gate and audit trail for every request (a plain ASGI middleware).

- Until the admin password is set, every page leads to the first-start screen
  and every API call answers 401 ``setup_required``.
- Without a valid session, pages redirect to ``/login`` and API calls answer
  401; the static files, ``/health`` and the sign-in endpoints stay open.
- Requests that change something (POST / PUT / PATCH / DELETE on ``/api``) must
  carry the ``X-DTX: 1`` header the app's own pages add: another site cannot
  forge them with the user's cookie (CSRF), on top of the SameSite cookie.
- Every such request is written to the audit trail (``audit.py``) with the user,
  the action in words, the case, a short detail taken from the request (the
  module run, the IOC checked, the mark set, the settings changed — never a
  password) and the HTTP status.
"""

from __future__ import annotations

import json
import os
import sys
from http.cookies import SimpleCookie
from typing import Any

from . import audit, users

_OPEN = ("/health", "/login", "/favicon.ico", "/api/auth/status", "/api/auth/login", "/api/auth/setup")
_UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
# audited by their own handlers (they know the case created / the user name typed)
_SELF_AUDITED = ("/api/auth/", "/api/cases/quick")
_MAX_BODY = 64 * 1024
# bodies never looked at (they hold passwords, keys or proxy credentials)
_SECRET_BODIES = ("/api/auth/", "/api/users", "/api/settings/network", "/api/settings/abusech", "/api/ai/")


def _test_bypass() -> bool:
    """The test suite exercises the API without signing in. Honoured only while
    pytest is loaded, so it cannot open a real installation."""
    return os.environ.get("DOCUTRACEX_TEST_NO_AUTH") == "1" and "pytest" in sys.modules


def _cookie(scope: dict, name: str) -> str | None:
    for k, v in scope.get("headers") or []:
        if k == b"cookie":
            c = SimpleCookie()
            try:
                c.load(v.decode("latin-1"))
            except Exception:  # noqa: BLE001
                return None
            if name in c:
                return c[name].value
    return None


def _header(scope: dict, name: bytes) -> str:
    for k, v in scope.get("headers") or []:
        if k == name:
            return v.decode("latin-1")
    return ""


def _detail(path: str, body: bytes) -> str:
    """A short, password-free note of what was asked."""
    if not body or any(path.startswith(p) for p in _SECRET_BODIES):
        return ""
    try:
        data: Any = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ""
    if not isinstance(data, dict):
        return ""
    if path.endswith("/rerun"):
        mod = data.get("module") or "full analysis"
        objs = data.get("objects")
        return f"{mod}" + (f" on {len(objs)} object(s)" if isinstance(objs, list) and objs else "")
    if "/netcheck" in path:
        return f"{data.get('kind') or ''} {data.get('target') or ''}".strip()[:200]
    if "/marks/" in path:
        return " ".join(str(data.get(k)) for k in ("state", "comment") if data.get(k))[:200]
    if path.startswith("/api/settings/"):
        return "fields: " + ", ".join(sorted(map(str, data)))[:200]
    if "/manual-findings" in path:
        return str(data.get("detail") or "")[:200]
    return ""


class AuthAudit:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        method: str = scope.get("method", "GET")
        if _test_bypass():
            scope.setdefault("state", {})["user"] = "tester"
            await self.app(scope, receive, send)
            return
        is_api = path.startswith("/api/")
        open_path = path.startswith("/static/") or path in _OPEN
        user = users.session_user(_cookie(scope, users.COOKIE))
        scope.setdefault("state", {})["user"] = user or ""

        if not open_path:
            if users.needs_setup() or not user:
                if is_api:
                    await _json(send, 401, {"error": "Sign in first.", "setup_required": users.needs_setup()})
                else:
                    await _redirect(send, "/login")
                return
        if is_api and method in _UNSAFE and _header(scope, b"x-dtx") != "1":
            await _json(send, 403, {"error": "Missing X-DTX header (requests must come from the DocuTraceX page)."})
            return

        audited = (is_api and method in _UNSAFE and user
                   and not any(path.startswith(p) for p in _SELF_AUDITED)
                   and not (method == "POST" and path.rstrip("/") == "/api/cases"))
        if not audited:
            await self.app(scope, receive, send)
            return

        body = bytearray()

        async def recv() -> dict:
            msg = await receive()
            if msg.get("type") == "http.request" and len(body) < _MAX_BODY:
                body.extend(msg.get("body", b"")[: _MAX_BODY - len(body)])
            return msg

        status = {"code": 500}

        async def snd(msg: dict) -> None:
            if msg.get("type") == "http.response.start":
                status["code"] = msg.get("status", 500)
            await send(msg)

        try:
            await self.app(scope, recv, snd)
        finally:
            client = scope.get("client") or ("", 0)
            try:
                audit.record(user, audit.describe(method, path), case=audit.case_of(path), addr=client[0] or "",
                             request=f"{method} {path}", status=status["code"], detail=_detail(path, bytes(body)))
            except OSError:
                pass


async def _json(send: Any, code: int, data: dict) -> None:
    raw = json.dumps(data).encode()
    await send({"type": "http.response.start", "status": code,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())]})
    await send({"type": "http.response.body", "body": raw})


async def _redirect(send: Any, to: str) -> None:
    await send({"type": "http.response.start", "status": 303,
                "headers": [(b"location", to.encode()), (b"content-length", b"0")]})
    await send({"type": "http.response.body", "body": b""})
