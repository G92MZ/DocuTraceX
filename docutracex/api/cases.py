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
    """Upload a file, create a case, and queue its analysis (runs in the
    background worker — one analysis per instance, the rest queued)."""
    from ..tasks import manager

    manifest = case_service.create_case(file.file, file.filename or "upload.bin")
    task = manager.submit("analyze", manifest["analysis_id"],
                          manifest["original"]["filename"], target="full",
                          cases_dir=settings.cases_dir)
    manifest["task"] = task.public()
    return JSONResponse(status_code=201, content=manifest)


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


@router.get("/{analysis_id}/report")
async def case_report(analysis_id: str):
    """Render a self-contained HTML report for the case (printable to PDF)."""
    from fastapi.responses import HTMLResponse

    from .. import report as report_mod

    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    html = report_mod.build_report_html(analysis_id, cases_dir=settings.cases_dir)
    # Persist a copy under reports/ as the single current report for the case.
    try:
        from ..storage import CasePaths
        paths = CasePaths(analysis_id)
        paths.reports_dir.mkdir(parents=True, exist_ok=True)
        (paths.reports_dir / "report.html").write_text(html, encoding="utf-8")
    except OSError:
        pass
    return HTMLResponse(content=html)


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


def _safe_target(analysis_id: str, rel: str):
    """Resolve a case-relative path and ensure it stays inside the case folder."""
    from ..storage import CasePaths

    paths = CasePaths(analysis_id)
    root = paths.root.resolve()
    target = (paths.root / (rel or "")).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(status_code=400, detail="Path escapes the case directory")
    if not target.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return target


@router.post("/{analysis_id}/reveal")
async def reveal_path(analysis_id: str, payload: dict = Body(...)) -> dict:
    """Open the extracted file's containing folder in the OS file manager.

    Local tool only: this acts on the machine running the web app.
    """
    import subprocess
    import sys

    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    target = _safe_target(analysis_id, str(payload.get("path", "")))
    try:
        if sys.platform.startswith("win"):
            subprocess.run(["explorer", f"/select,{target}"], check=False)  # non-zero on success
        elif sys.platform == "darwin":
            subprocess.run(["open", "-R", str(target)], check=False)
        else:
            subprocess.run(["xdg-open", str(target.parent)], check=False)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Could not open file manager: {exc}") from exc
    return {"opened": True, "path": str(target)}


@router.get("/{analysis_id}/file")
async def download_file(analysis_id: str, path: str):
    """Download an extracted file (fallback when the file manager isn't local)."""
    from fastapi.responses import FileResponse

    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    target = _safe_target(analysis_id, path)
    if not target.is_file():
        raise HTTPException(status_code=400, detail="Not a file")
    return FileResponse(str(target), filename=target.name,
                        media_type="application/octet-stream")


@router.post("/{analysis_id}/rerun")
async def rerun_case(analysis_id: str, payload: dict = Body(default={})) -> dict:
    """Queue a re-analysis of a case: the whole case, or one module in isolation
    (``{"module": "oletools"}``). Marks are preserved (stable finding ids)."""
    from ..tasks import manager

    try:
        manifest = case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    module = (payload or {}).get("module")
    task = manager.submit(
        "rerun_module" if module else "rerun", analysis_id,
        manifest["original"]["filename"], target=module or "full",
        cases_dir=settings.cases_dir,
    )
    return {"task": task.public()}


@router.get("/{analysis_id}/tasks")
async def case_tasks(analysis_id: str) -> dict:
    """Attempt history for a case (results/tasks.json) plus its live tasks."""
    from ..storage import CasePaths, read_json
    from ..tasks import manager

    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    history = read_json(CasePaths(analysis_id).tasks) or {"attempts": []}
    return {"analysis_id": analysis_id, "attempts": history.get("attempts", []),
            "live": manager.list(analysis_id)}


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
