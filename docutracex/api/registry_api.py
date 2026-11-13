"""Registry tab: browse, search and query the case's registry database (read-only)."""

from __future__ import annotations

import asyncio
import csv
import io
import re

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import Response, StreamingResponse

from .. import cases as case_service
from ..errors import CaseError

router = APIRouter(prefix="/api/cases", tags=["registry"])


def _db(analysis_id: str):  # noqa: ANN202
    from ..registry import remote, store
    from ..storage import CasePaths
    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    p = store.db_path(CasePaths(analysis_id).root)
    if not p.is_file():
        raise HTTPException(status_code=404, detail="This case has no registry data (no hive / .reg was analysed).")
    if not remote.available():
        raise HTTPException(status_code=503, detail="DuckDB is not installed (run scripts/setup_portable_python.py).")
    return p


async def _call(fn: str, **kw):  # noqa: ANN003, ANN202
    """``store.<fn>`` in-process or on the portable Python (``registry.remote``), off the event loop."""
    from ..registry import remote
    try:
        return await asyncio.to_thread(remote.call, fn, **kw)
    except (ValueError, re.error) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001  (DuckDB errors: a bad query, an interrupted one)
        raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}"[:500]) from exc


@router.get("/{analysis_id}/registry/sources")
async def registry_sources(analysis_id: str) -> dict:
    return await _call("query", path=_db(analysis_id), sql="SELECT * FROM sources ORDER BY id")


@router.get("/{analysis_id}/registry/key")
async def registry_key(analysis_id: str, src: int = 0, path: str = "") -> dict:
    """Subkeys and values of one key (no path: each source's root)."""
    return await _call("children", path=_db(analysis_id), src=src, key=path)


@router.get("/{analysis_id}/registry/value")
async def registry_value(analysis_id: str, src: int, path: str, name: str) -> dict:
    """One value in full (the data text and, for binary values, all the bytes as hex)."""
    return await _call("value", path=_db(analysis_id), src=src, key=path, name=name)


@router.get("/{analysis_id}/registry/search")
async def registry_search(analysis_id: str, q: str, where: str = "any", src: int = 0, regex: bool = False,
                          limit: int = 500, offset: int = 0) -> dict:
    return await _call("search", path=_db(analysis_id), q=q, where=where, src=src, regex=regex,
                       limit=min(max(limit, 1), 5000), offset=max(offset, 0))


@router.get("/{analysis_id}/registry/bookmarks")
async def registry_bookmarks(analysis_id: str, src: int) -> dict:
    """Keys the RECmd batch files point at in one source, by category."""
    return await _call("bookmarks", path=_db(analysis_id), src=src)


@router.get("/{analysis_id}/registry/artifacts")
async def registry_artifacts(analysis_id: str) -> dict:
    """Catalogue categories and decoded artifacts (regipy plugins) per source, with counts."""
    from ..registry import catalog
    res = await _call("artifact_summary", path=_db(analysis_id))
    res["catalogue"] = catalog.status()
    return res


@router.get("/{analysis_id}/registry/artifacts/rows")
async def registry_artifact_rows(analysis_id: str, src: int, plugin: str = "", category: str = "",
                                 limit: int = 2000, offset: int = 0) -> dict:
    return await _call("artifact_rows", path=_db(analysis_id), src=src, plugin=plugin, category=category,
                       limit=min(max(limit, 1), 5000), offset=max(offset, 0))


@router.get("/{analysis_id}/registry/recovered")
async def registry_recovered(analysis_id: str, src: int = 0, limit: int = 2000, offset: int = 0) -> dict:
    """Deleted keys and values recovered from free cells."""
    return await _call("recovered", path=_db(analysis_id), src=src, limit=min(max(limit, 1), 5000),
                       offset=max(offset, 0))


@router.get("/{analysis_id}/registry/timeline")
async def registry_timeline(analysis_id: str, src: int = 0, limit: int = 2000, offset: int = 0) -> dict:
    """Key last-writes and artifact timestamps, newest first."""
    return await _call("timeline", path=_db(analysis_id), src=src, limit=min(max(limit, 1), 5000),
                       offset=max(offset, 0))


@router.get("/{analysis_id}/registry/timeline.export")
async def registry_timeline_export(analysis_id: str, fmt: str = "bodyfile", src: int = 0) -> StreamingResponse:
    """The whole timeline, streamed: bodyfile (mactime / Plaso) or CSV."""
    from ..registry import export, remote
    db = _db(analysis_id)
    fmt = "csv" if fmt == "csv" else "bodyfile"

    def fetch(limit: int, offset: int) -> dict:
        return remote.call("timeline", path=db, src=src, limit=limit, offset=offset)
    name = f"{analysis_id}_registry_timeline.{'csv' if fmt == 'csv' else 'body'}"
    return StreamingResponse(export.timeline_chunks(fetch, fmt), media_type="text/csv" if fmt == "csv" else "text/plain",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/{analysis_id}/registry/export.reg")
async def registry_export_reg(analysis_id: str, src: int, path: str) -> Response:
    """A key and everything under it as a .reg file (as regedit writes it)."""
    from ..registry import export
    if not path:
        raise HTTPException(status_code=400, detail="Pick a key first.")
    tree = await _call("subtree", path=_db(analysis_id), src=src, key=path)
    if not tree["keys"] and not tree["values"]:
        raise HTTPException(status_code=404, detail="No such key in this source.")
    note = f"DocuTraceX case {analysis_id}, source {src}: {path}" + (" (truncated)" if tree.get("truncated") else "")
    leaf = re.sub(r"[^A-Za-z0-9._-]+", "_", path.rsplit("\\", 1)[-1])[:60] or "key"
    return Response(export.reg_text(tree, note), media_type="text/plain; charset=utf-16",
                    headers={"Content-Disposition": f'attachment; filename="{analysis_id}_{leaf}.reg"'})


@router.post("/{analysis_id}/registry/sql")
async def registry_sql(analysis_id: str, payload: dict = Body(...)) -> dict:
    """A read-only SQL query (SELECT / WITH / DESCRIBE) over sources, keys and vals."""
    from ..registry import store
    return await _call("user_query", path=_db(analysis_id), sql=str(payload.get("sql") or ""),
                       limit=min(int(payload.get("limit") or store.MAX_ROWS), store.MAX_ROWS))


@router.post("/{analysis_id}/registry/export.csv")
async def registry_export(analysis_id: str, payload: dict = Body(...)) -> Response:
    """CSV of a search ({q, where, src, regex}) or of a SQL query ({sql})."""
    from ..registry import store
    db = _db(analysis_id)
    if payload.get("sql"):
        res = await _call("user_query", path=db, sql=str(payload["sql"]), limit=store.MAX_ROWS)
    else:
        res = await _call("search", path=db, q=str(payload.get("q") or ""), where=str(payload.get("where") or "any"),
                          src=int(payload.get("src") or 0), regex=bool(payload.get("regex")), limit=store.MAX_ROWS,
                          offset=0)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(res["columns"])
    w.writerows(res["rows"])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{analysis_id}_registry.csv"'})
