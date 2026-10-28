"""Tasks tab: finished tasks survive a restart (with their sub-step timings);
nested depth / node limits."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from docutracex import nested, tasks
from docutracex.app import create_app
from docutracex.config import settings


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    return TestClient(create_app())


def _wait(client: TestClient, tid: str) -> dict:
    for _ in range(1200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            return t
        time.sleep(0.05)
    return {}


def test_finished_tasks_survive_restart_with_step_timings(client: TestClient) -> None:
    (Path(settings.cases_dir) / ".gitkeep").write_text("")      # stray file in cases/
    r = client.post("/api/cases", files={"file": ("a.bat", b"@echo off\r\nrem invoice\r\n")}).json()
    done = _wait(client, r["task"]["id"])
    assert done["state"] == "completed" and done["duration_s"] is not None
    # a fresh manager = the app after a restart: nothing in memory
    fresh = tasks.TaskManager()
    listed = fresh.list()
    h = next(t for t in listed if t["analysis_id"] == r["analysis_id"])
    assert h["history"] and h["state"] == "completed" and h["filename"] == "a.bat"
    assert h["duration_s"] is not None and h["steps"] and all("duration_s" in s for s in h["steps"])


def test_history_not_listed_twice_in_the_same_session(client: TestClient) -> None:
    r = client.post("/api/cases", files={"file": ("b.bat", b"@echo off\r\n")}).json()
    _wait(client, r["task"]["id"])
    ids = [t["id"] for t in client.get("/api/tasks").json()["tasks"] if t["analysis_id"] == r["analysis_id"]]
    assert len(ids) == len(set(ids)) == 1


def test_nested_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex.storage import CasePaths
    assert nested.MAX_DEPTH == 12
    monkeypatch.setattr(nested, "MAX_NODES", 3)
    root = tmp_path / "cases" / "c1"
    (root / "extracted").mkdir(parents=True)
    items = []
    for i in range(6):
        f = root / "extracted" / f"f{i}.txt"
        f.write_text("plain text", encoding="utf-8")
        items.append({"path": str(f), "filename": f.name})
    res = nested.scan_children(items, CasePaths("c1", cases_dir=root.parent))
    assert len(res["tree"]) == 3 and res["truncated_children"] == 3


def test_steps_are_reported_live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """While a task runs, each step appears as 'running' and is replaced by its
    timed record when it ends."""
    from docutracex import analyze
    seen: list[list[dict]] = []
    mgr = tasks.TaskManager()
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()

    def fake_run_analysis(root, module=None):  # noqa: ANN001
        t = next(iter(mgr._tasks.values()))
        for name in ("javascript: x", "nested: y"):
            analyze._notify_step("start", {"step": name})
            seen.append([dict(s) for s in t.steps])
            analyze._notify_step("end", {"step": name, "status": "ok", "duration_s": 0.01})
        seen.append([dict(s) for s in t.steps])

    monkeypatch.setattr(analyze, "run_analysis", fake_run_analysis)
    (tmp_path / "cases" / "c1" / "results").mkdir(parents=True)
    tid = mgr.submit("analyze", "c1", "x.js", cases_dir=tmp_path / "cases").id
    for _ in range(200):
        if (mgr.get(tid) or {}).get("state") in ("completed", "failed"):
            break
        time.sleep(0.02)
    assert seen[0][-1]["status"] == "running" and seen[0][-1]["started_utc"].endswith("Z")
    assert seen[1][0]["status"] == "ok" and seen[1][-1]["status"] == "running"
    assert [s["status"] for s in seen[-1]] == ["ok", "ok"]
