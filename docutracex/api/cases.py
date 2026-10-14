"""Case API endpoints: upload (create), list and read."""

from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from .. import analyze as analysis
from .. import cases as case_service
from ..config import settings
from ..errors import CaseError

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.post("")
async def create_case(file: UploadFile = File(...)) -> JSONResponse:
    """Upload a file, create a case, and run the applicable analysis."""
    manifest = case_service.create_case(file.file, file.filename or "upload.bin")
    case_root = settings.cases_dir / manifest["analysis_id"]
    analysis.run_analysis(case_root)
    # Return the updated manifest (analysis may have changed state/counts).
    updated = case_service.get_case(manifest["analysis_id"])
    return JSONResponse(status_code=201, content=updated)


@router.get("")
async def list_cases() -> list[dict]:
    """List case summaries, newest first."""
    return case_service.list_cases()


@router.get("/{analysis_id}")
async def get_case(analysis_id: str) -> dict:
    """Read a case manifest."""
    try:
        return case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
