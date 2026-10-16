"""Case API endpoints: upload (create), list, read, components and marks."""

from __future__ import annotations

from fastapi import APIRouter, Body, File, Form, HTTPException, UploadFile
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
    findings = marks_service.case_findings(paths)
    return marks_service.apply(findings, marks_service.read_marks(paths))


def _save_unlock(analysis_id: str, **changes) -> dict:
    """Update the case's unlock options — ``password`` (the analyst's) and
    ``wordlist`` (try every word of the email). Stored in the case folder,
    apart from case.json, so they aren't served with it."""
    from ..storage import CasePaths, read_json, write_json

    paths = CasePaths(analysis_id)
    data = read_json(paths.password) or {}
    data.update(changes)
    data = {k: v for k, v in data.items() if v}
    if data:
        write_json(paths.password, data)
    else:
        paths.password.unlink(missing_ok=True)
    return data


def _save_password(analysis_id: str, password: str) -> None:
    _save_unlock(analysis_id, password=password)


@router.post("")
async def create_case(file: UploadFile = File(...), password: str = Form("")) -> JSONResponse:
    """Upload a file, create a case, and queue its analysis (runs in the
    background worker — one analysis per instance, the rest queued).
    ``password`` (optional) unlocks an encrypted document/archive."""
    from ..tasks import manager

    manifest = case_service.create_case(file.file, file.filename or "upload.bin")
    if password:
        _save_password(manifest["analysis_id"], password)
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


@router.post("/{analysis_id}/password")
async def set_password(analysis_id: str, payload: dict = Body(...)) -> dict:
    """Give (or clear) the password of an encrypted original / archive and
    queue a full re-analysis that decrypts it first. Marks are preserved."""
    from ..tasks import manager

    try:
        manifest = case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    password = (payload or {}).get("password", "")
    if not isinstance(password, str) or len(password) > 512:
        raise HTTPException(status_code=400, detail="password must be a string (max 512 chars)")
    _save_password(analysis_id, password)
    task = manager.submit("rerun", analysis_id, manifest["original"]["filename"], target="full",
                          cases_dir=settings.cases_dir)
    return {"password_set": bool(password), "task": task.public()}


@router.post("/{analysis_id}/wordlist")
async def set_wordlist(analysis_id: str, payload: dict = Body(default={})) -> dict:
    """Try every word of the email (body, subject, attachment names, addresses)
    as the password of its encrypted attachments: queue a full re-analysis with
    that option on (``{"enabled": false}`` turns it off). No time limit."""
    from ..tasks import manager

    try:
        manifest = case_service.get_case(analysis_id)
    # bhd1Sl5iFX
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    enabled = bool((payload or {}).get("enabled", True))
    _save_unlock(analysis_id, wordlist=enabled)
    task = manager.submit("rerun", analysis_id, manifest["original"]["filename"], target="full",
                          cases_dir=settings.cases_dir)
    return {"wordlist": enabled, "task": task.public()}


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


@router.post("/{analysis_id}/manual-findings")
async def add_manual_finding(analysis_id: str, payload: dict = Body(...)) -> dict:
    """Add a component item (IOC, attachment, header, ...) as a finding by hand,
    optionally marking it right away (e.g. true_positive)."""
    from ..storage import CasePaths

    try:
        case_service.get_case(analysis_id)
    # id: c9omYR6Yrv
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    paths = CasePaths(analysis_id)
    try:
        f = marks_service.add_manual(
            paths, str(payload.get("kind", "item")), str(payload.get("detail", "")),
            str(payload.get("location", "") or ""), str(payload.get("evidence", "") or ""),
            str(payload.get("severity", "medium") or "medium"))
        state = str(payload.get("state", "") or "")
        mark = None
        if state:
            mark = marks_service.set_mark(paths, f["id"], state, str(payload.get("comment", "") or ""))
    except marks_service.MarkError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # sJkzUVgDiA
    return {"finding": f, "mark": mark}


@router.delete("/{analysis_id}/manual-findings/{finding_id}")
async def remove_manual_finding(analysis_id: str, finding_id: str) -> dict:
    from ..storage import CasePaths

    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not marks_service.remove_manual(CasePaths(analysis_id), finding_id):
        raise HTTPException(status_code=404, detail="Manual finding not found")
    return {"removed": finding_id}


# --- network checks (on demand, through the configured proxy) -----------------------

_NET_KINDS = ("url", "domain", "ip", "submit", "shot_live")


@router.post("/{analysis_id}/netcheck")
async def queue_netcheck(analysis_id: str, payload: dict = Body(...)) -> dict:
    """Queue a network check: ``{"kind": "url"|"domain"|"ip", "target": ...}``,
    ``{"kind": "submit", "check_id": ..., "form": n}`` or
    ``{"kind": "shot_live", "check_id": ...}``."""
    import ipaddress
    import re as _re

    from ..tasks import manager

    try:
        manifest = case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    kind = str(payload.get("kind") or "")
    if kind not in _NET_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {', '.join(_NET_KINDS)}")
    params: dict = {"kind": kind}
    target = str(payload.get("target") or "").strip()
    if kind == "url":
        if not _re.match(r"^https?://[^\s/]+", target, _re.I):
            raise HTTPException(status_code=400, detail="target must be an http(s) URL")
        params["target"] = target
    elif kind == "domain":
        if not _re.match(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$", target.lower().rstrip(".")):
            raise HTTPException(status_code=400, detail="target must be a domain name")
        params["target"] = target.lower().rstrip(".")
    elif kind == "ip":
        try:
            params["target"] = str(ipaddress.ip_address(target))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="target must be an IP address") from exc
    else:
        params["check_id"] = str(payload.get("check_id") or "")
        if not _re.fullmatch(r"[0-9a-f]{12}", params["check_id"]):
            raise HTTPException(status_code=400, detail="check_id required")
        if kind == "submit":
            params["form"] = int(payload.get("form") or 0)
    task = manager.submit("netcheck", analysis_id, manifest["original"]["filename"],
                          target=f"netcheck:{kind}", cases_dir=settings.cases_dir, params=params)
    return {"task": task.public()}


@router.get("/{analysis_id}/netcheck")
async def get_netcheck(analysis_id: str) -> dict:
    from ..storage import CasePaths, read_json

    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return read_json(CasePaths(analysis_id).subresult("netcheck")) or {"checks": []}


@router.get("/{analysis_id}/netcheck/asset")
async def netcheck_asset(analysis_id: str, path: str):
    """Serve a check's screenshot (PNG) or safe preview (HTML) inline. Previews
    get a CSP that blocks scripts and every network load; the UI also shows
    them in a sandboxed iframe."""
    from fastapi.responses import FileResponse

    try:
        case_service.get_case(analysis_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not path.startswith("extracted/netcheck/") or not path.endswith((".png", ".preview.html")):
        # id: gmzpt
        raise HTTPException(status_code=400, detail="Not a network-check asset")
    target = _safe_target(analysis_id, path)
    if path.endswith(".png"):
        return FileResponse(str(target), media_type="image/png")
    return FileResponse(str(target), media_type="text/html; charset=utf-8", headers={
        "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                                    "font-src data:; form-action 'none'; sandbox"),
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})
