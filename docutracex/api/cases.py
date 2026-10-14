"""Case API endpoints: upload (create), list, read, components and marks."""

from __future__ import annotations

from fastapi import APIRouter, Body, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from .. import analyze as analysis
from .. import cases as case_service
from .. import marks as marks_service
from ..config import settings
from ..errors import CaseError

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _load_findings_with_marks(analysis_id: str) -> dict:
    """Consolidated findings for a case, each enriched with its mark."""
    from ..storage import CasePaths, read_json

    paths = CasePaths(analysis_id)
    stored = read_json(paths.subresult("findings")) or {}
    findings = stored.get("findings", []) if isinstance(stored, dict) else []
    return marks_service.apply(findings, marks_service.read_marks(paths))


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


@router.get("/{analysis_id}/components")
async def get_components(analysis_id: str) -> dict:
    """Return the component/relationship analysis for a case (OOXML for now)."""
    from ..storage import CasePaths, read_json

    try:
        manifest = case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    paths = CasePaths(analysis_id)
    ran = (manifest.get("analysis") or {}).get("modules_run", [])
    modules: dict = {}
    for module in ran:
        data = read_json(paths.subresult(module))
        if data is not None:
            modules[module] = data
    iocs = read_json(paths.subresult("iocs"))
    marked = _load_findings_with_marks(analysis_id)
    return {
        "analysis_id": analysis_id,
        "filename": manifest["original"]["filename"],
        "state": manifest.get("state"),
        "modules": modules,
        "iocs": iocs,
        "findings": marked["findings"],
        "marks_counts": marked["counts"],
        "marks_orphans": marked["orphans"],
    }


@router.get("/{analysis_id}/marks")
async def get_marks(analysis_id: str) -> dict:
    """Return the case's findings each enriched with its mark, plus counts."""
    try:
        manifest = case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    marked = _load_findings_with_marks(analysis_id)
    return {
        "analysis_id": analysis_id,
        "filename": manifest["original"]["filename"],
        "state": manifest.get("state"),
        "states": list(marks_service.STATES),
        "findings": marked["findings"],
        "counts": marked["counts"],
        "orphans": marked["orphans"],
    }


@router.put("/{analysis_id}/marks/{finding_id}")
async def set_mark(analysis_id: str, finding_id: str,
                   payload: dict = Body(...)) -> dict:
    """Create or update the mark for one finding (TP/FP/Suspicious/...)."""
    from ..storage import CasePaths

    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    try:
        mark = marks_service.set_mark(
            CasePaths(analysis_id), finding_id,
            str(payload.get("state", "")), str(payload.get("comment", "") or ""),
        )
    except marks_service.MarkError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"finding_id": finding_id, "mark": mark}
