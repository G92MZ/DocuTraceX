"""AI tab API: chat with an OpenAI-compatible endpoint, and MCP connection info."""

from __future__ import annotations

import asyncio
import json
import sys

from fastapi import APIRouter, Body, HTTPException

from ..config import APP_ROOT, settings

router = APIRouter(prefix="/api", tags=["ai"])


@router.post("/ai/chat")
async def ai_chat(payload: dict = Body(...)) -> dict:
    """Ask a question; the model uses DocuTraceX's read-only tools to answer.
    The endpoint config comes from the browser (keys are not stored server-side)."""
    from .. import ai

    cfg = {k: payload.get(k) for k in ("base_url", "model", "api_key", "user", "extra_headers")}
    try:
        return await asyncio.to_thread(ai.chat, str(payload.get("message") or ""), cfg,
                                       payload.get("history") or [], payload.get("case_id") or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"AI endpoint error: {exc}") from exc


@router.get("/mcp/info")
async def mcp_info() -> dict:
    """Everything needed to connect an MCP client to this installation."""
    from .. import ai_tools

    python = settings.portable_python() or sys.executable
    try:
        import importlib.metadata as md
        mcp_version = md.version("mcp")
    except Exception:  # noqa: BLE001
        mcp_version = None
    env = {"PYTHONPATH": str(APP_ROOT), "DOCUTRACEX_CASES_DIR": str(settings.cases_dir)}
    desktop = {"mcpServers": {"docutracex": {"command": str(python), "args": ["-m", "docutracex.mcp_server"],
                                              "env": env}}}
    q = (lambda s: f'"{s}"') if sys.platform.startswith("win") else (lambda s: f"'{s}'")
    code = (f"claude mcp add docutracex -e PYTHONPATH={q(APP_ROOT)} -e DOCUTRACEX_CASES_DIR={q(settings.cases_dir)} "
            f"-- {q(python)} -m docutracex.mcp_server")
    return {"python": str(python), "app_root": str(APP_ROOT), "cases_dir": str(settings.cases_dir),
            "mcp_installed": mcp_version is not None, "mcp_version": mcp_version,
            "run": f"{q(python)} -m docutracex.mcp_server", "env": env,
            "claude_desktop": json.dumps(desktop, indent=2), "claude_code": code,
            "tools": [{"signature": s, "description": d} for s, d in ai_tools.TOOLS_DOC]}
