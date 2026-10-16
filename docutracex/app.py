"""FastAPI application factory.

Serves the local web UI and a health endpoint. Analysis modules and the case
lifecycle are wired in later phases.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .api.ai_api import router as ai_router
from .api.cases import router as cases_router
from .api.settings_api import router as settings_router
from .api.yara import router as yara_router
from .config import settings
from .deps import log_startup_report, run_checks
from .errors import DocuTraceXError
from .logging_config import configure_logging, get_logger

log = get_logger(__name__)

_WEB_DIR = Path(__file__).resolve().parent / "web"
_TEMPLATES = Jinja2Templates(directory=str(_WEB_DIR / "templates"))


def _asset_version(static_dir: Path) -> str:
    """Cache-busting token for /static assets: changes whenever a file changes,
    so browsers never keep running a stale app.js/app.css after an update."""
    try:
        return str(max(int(f.stat().st_mtime) for f in static_dir.iterdir() if f.is_file()))
    except (OSError, ValueError):
        return __version__


def create_app() -> FastAPI:
    configure_logging(settings.log_level)
    settings.ensure_dirs()

    # Check dependencies at startup and log a concise report.
    log_startup_report()

    app = FastAPI(title="DocuTraceX", version=__version__)

    static_dir = _WEB_DIR / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.exception_handler(DocuTraceXError)
    async def _app_error_handler(_request: Request, exc: DocuTraceXError) -> JSONResponse:
        log.warning("Application error: %s", exc)
        return JSONResponse(status_code=400, content={"error": str(exc)})

    app.include_router(cases_router)
    app.include_router(yara_router)
    app.include_router(settings_router)
    app.include_router(ai_router)

    @app.get("/health", response_class=JSONResponse)
    async def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/api/diagnostics", response_class=JSONResponse)
    async def diagnostics() -> dict:
        return {"version": __version__, **run_checks()}

    @app.get("/api/tasks", response_class=JSONResponse)
    async def tasks() -> dict:
        from .tasks import manager
        items = manager.list()
        return {"tasks": items, "active": sum(1 for t in items if t["state"] in
                                              ("queued", "running", "cancelling"))}

    @app.post("/api/tasks/{task_id}/cancel", response_class=JSONResponse)
    async def cancel_task(task_id: str) -> JSONResponse:
        from .tasks import manager
        ok = manager.cancel(task_id)
        if not ok:
            return JSONResponse(status_code=409,
                                content={"error": "Task cannot be cancelled (unknown or already finished)."})
        return JSONResponse(content={"cancelled": task_id, "task": manager.get(task_id)})

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return _TEMPLATES.TemplateResponse(
            request, "index.html",
            {"version": __version__, "asset_version": _asset_version(static_dir)},
        )

    log.info("DocuTraceX %s ready", __version__)
    return app


app = create_app()
