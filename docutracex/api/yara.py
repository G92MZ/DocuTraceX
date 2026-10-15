"""YARA rule management API: upload / register path / list / enable / remove."""

from __future__ import annotations

import json

from fastapi import APIRouter, Body, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from .. import yara_engine

router = APIRouter(prefix="/api/yara", tags=["yara"])


@router.get("")
async def list_yara() -> dict:
    """List known rules with source, tags, meta, compile status and enabled flag."""
    return yara_engine.list_rules()


@router.post("/compile/stream")
async def compile_stream() -> StreamingResponse:
    """Compile the ruleset file-by-file, streaming progress as NDJSON."""
    def gen():
        for ev in yara_engine.compile_stream():
            yield json.dumps(ev, default=str) + "\n"
    return StreamingResponse(gen(), media_type="application/x-ndjson")


@router.post("/upload")
async def upload_yara(file: UploadFile = File(...)) -> JSONResponse:
    """Add rules from an uploaded .yar/.yara file or a .zip/.tar.gz archive."""
    data = await file.read()
    try:
        added = yara_engine.add_upload(file.filename or "rules.yar", data)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Could not add rules: {exc}") from exc
    report = yara_engine.compile_rules()[1]
    return JSONResponse(status_code=201, content={**added, "compile": report})


@router.post("/path")
async def register_yara_path(payload: dict = Body(...)) -> dict:
    """Register a rule file or directory already present on the server."""
    path = str(payload.get("path", "")).strip()
    if not path:
        raise HTTPException(status_code=400, detail="Missing 'path'")
    try:
        res = yara_engine.register_path(path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {**res, "compile": yara_engine.compile_rules()[1]}


@router.delete("/path")
async def unregister_yara_path(payload: dict = Body(...)) -> dict:
    yara_engine.unregister_path(str(payload.get("path", "")))
    return {"ok": True}


@router.delete("/source/{name}")
async def remove_yara_source(name: str) -> dict:
    return {"removed": yara_engine.remove_source(name)}


@router.post("/enabled")
async def set_yara_enabled(payload: dict = Body(...)) -> dict:
    """Enable/disable rules for findings (only enabled rules reach the report)."""
    rules = payload.get("rules") or []
    if isinstance(rules, str):
        rules = [rules]
    enabled = bool(payload.get("enabled", True))
    current = yara_engine.set_enabled([str(r) for r in rules], enabled)
    return {"enabled": sorted(current), "count": len(current)}
