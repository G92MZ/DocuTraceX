"""Tests for the task queue, isolated re-run and attempt history."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from docutracex import analyze, cases
from docutracex.app import create_app
from docutracex.config import settings
from docutracex.storage import CasePaths, read_json
from docutracex.tasks import TaskManager

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
has_samples = pytest.mark.skipif(not (SAMPLES / "sample.xlsm").exists(),
                                 reason="samples not generated")


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    return TestClient(create_app())


def _wait(fn, ok, tries: int = 200, delay: float = 0.05):
    for _ in range(tries):
        v = fn()
        if ok(v):
            return v
        time.sleep(delay)
    return fn()


# --- TaskManager unit --------------------------------------------------------

def test_queue_runs_sequentially_and_records(tmp_path: Path) -> None:
    order: list[str] = []
    mgr = TaskManager()

    def fake_run_analysis(case_root, module=None):  # noqa: ANN001
        order.append(f"{Path(case_root).name}:{module}")
        time.sleep(0.02)

    import docutracex.analyze as az
    mgr_mod = __import__("docutracex.tasks", fromlist=["_append_attempt", "_snapshot_history"])
    orig = az.run_analysis
    az.run_analysis = fake_run_analysis
    try:
        a = mgr.submit("analyze", "c1", "a.docx", cases_dir=tmp_path)
        b = mgr.submit("analyze", "c2", "b.docx", cases_dir=tmp_path)
        _wait(lambda: mgr.get(b.id)["state"], lambda s: s in ("completed", "partial", "failed"))
    finally:
        az.run_analysis = orig
    assert mgr.get(a.id)["state"] in ("completed", "partial")
    assert mgr.get(b.id)["state"] in ("completed", "partial")
    # Sequential: c1 ran before c2.
    assert order == ["c1:None", "c2:None"]


def test_cancel_queued_task(tmp_path: Path) -> None:
    mgr = TaskManager()
    blocker_done = []

    def slow(case_root, module=None):  # noqa: ANN001
        time.sleep(0.3)
        blocker_done.append(1)

    import docutracex.analyze as az
    orig = az.run_analysis
    az.run_analysis = slow
    try:
        mgr.submit("analyze", "c1", "a", cases_dir=tmp_path)   # occupies the worker
        queued = mgr.submit("analyze", "c2", "b", cases_dir=tmp_path)  # waits
        assert mgr.cancel(queued.id) is True
        _wait(lambda: mgr.get(queued.id)["state"], lambda s: s == "cancelled", tries=20)
        assert mgr.get(queued.id)["state"] == "cancelled"
    finally:
        az.run_analysis = orig


# --- API integration ---------------------------------------------------------

@has_samples
def test_upload_queues_and_completes(client: TestClient) -> None:
    with (SAMPLES / "sample.xlsm").open("rb") as fh:
        r = client.post("/api/cases", files={"file": ("sample.xlsm", fh.read())}).json()
    assert r["task"]["state"] in ("queued", "running")
    cid = r["analysis_id"]
    state = _wait(lambda: client.get(f"/api/cases/{cid}").json().get("state"),
                  lambda s: s in ("completed", "partial", "error"))
    assert state in ("completed", "partial")
    tasks = client.get("/api/tasks").json()
    assert any(t["analysis_id"] == cid for t in tasks["tasks"])


@has_samples
def test_module_rerun_preserves_marks_and_records_history(client: TestClient) -> None:
    with (SAMPLES / "sample.xlsm").open("rb") as fh:
        cid = client.post("/api/cases", files={"file": ("sample.xlsm", fh.read())}).json()["analysis_id"]
    _wait(lambda: client.get(f"/api/cases/{cid}").json().get("state"),
          lambda s: s in ("completed", "partial", "error"))

    comp = client.get(f"/api/cases/{cid}/components").json()
    fid = comp["findings"][0]["id"]
    client.put(f"/api/cases/{cid}/marks/{fid}", json={"state": "true_positive", "comment": "keep"})

    rr = client.post(f"/api/cases/{cid}/rerun", json={"module": "oletools"}).json()
    tid = rr["task"]["id"]
    _wait(lambda: next((t for t in client.get("/api/tasks").json()["tasks"] if t["id"] == tid), {}).get("state"),
          lambda s: s in ("completed", "partial", "failed"))

    mk = client.get(f"/api/cases/{cid}/marks").json()
    assert mk["counts"]["reviewed"] == 1  # mark survived the isolated re-run

    hist = client.get(f"/api/cases/{cid}/tasks").json()
    types = [(a["type"], a["target"]) for a in hist["attempts"]]
    assert ("analyze", "full") in types
    assert ("rerun_module", "oletools") in types


@has_samples
def test_history_snapshot_written_on_rerun(client: TestClient, tmp_path: Path) -> None:
    with (SAMPLES / "sample.docx").open("rb") as fh:
        cid = client.post("/api/cases", files={"file": ("sample.docx", fh.read())}).json()["analysis_id"]
    _wait(lambda: client.get(f"/api/cases/{cid}").json().get("state"),
          lambda s: s in ("completed", "partial", "error"))
    client.post(f"/api/cases/{cid}/rerun", json={})
    _wait(lambda: client.get("/api/tasks").json()["active"], lambda a: a == 0)
    hist_dir = CasePaths(cid).results_dir / "history"
    assert hist_dir.exists() and any(hist_dir.iterdir())
