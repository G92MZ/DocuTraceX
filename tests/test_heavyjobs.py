"""FLOSS / capa use a lot of memory: background jobs run one at a time (queued in Tasks
until a slot is free); one cancelled while queued never runs."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from docutracex import heavyjobs, tasks


def _wait(pred, s: float = 20) -> None:  # noqa: ANN001
    end = time.monotonic() + s
    while time.monotonic() < end:
        if pred():
            return
        time.sleep(0.05)
    raise AssertionError("timed out")


@pytest.fixture()
def one_slot(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # noqa: ANN201
    monkeypatch.setattr(heavyjobs, "SLOTS", 1)
    monkeypatch.setattr(heavyjobs, "MIN_FREE_MB", 0)
    (tmp_path / "cases" / "c1").mkdir(parents=True)
    return tmp_path / "cases"


def _job(cases: Path, gate: threading.Event, ran: list[str], name: str) -> tasks.Task:
    def fn() -> dict:
        ran.append(name)
        gate.wait(20)
        return {"status": "ok"}
    return tasks.manager.start_background("floss", "c1", f"{name}.exe", "floss (background)",
                                          lambda t, c: heavyjobs.run(t, c, "FLOSS", fn)["status"],
                                          step=f"FLOSS · {name}", cases_dir=cases)


def test_heavy_jobs_run_one_at_a_time(one_slot: Path) -> None:
    g1, g2, ran = threading.Event(), threading.Event(), []
    a = _job(one_slot, g1, ran, "a")
    _wait(lambda: ran == ["a"])
    b = _job(one_slot, g2, ran, "b")
    _wait(lambda: tasks.manager.get(b.id)["state"] == tasks.QUEUED)
    assert "one runs at a time" in tasks.manager.get(b.id)["steps"][0]["detail"]
    time.sleep(0.3)
    assert ran == ["a"]                                  # b waits for a's slot
    g1.set()
    _wait(lambda: ran == ["a", "b"])
    assert tasks.manager.get(b.id)["state"] == tasks.RUNNING
    g2.set()
    _wait(lambda: tasks.manager.get(b.id)["state"] == tasks.COMPLETED)
    assert tasks.manager.get(a.id)["state"] == tasks.COMPLETED and heavyjobs.running() == 0


def test_cancelled_while_queued_never_runs(one_slot: Path) -> None:
    g1, g2, ran = threading.Event(), threading.Event(), []
    a = _job(one_slot, g1, ran, "a")
    _wait(lambda: ran == ["a"])
    b = _job(one_slot, g2, ran, "b")
    _wait(lambda: tasks.manager.get(b.id)["state"] == tasks.QUEUED)
    assert tasks.manager.cancel(b.id)                    # a queued job can be cancelled
    _wait(lambda: tasks.manager.get(b.id)["state"] == tasks.CANCELLED)
    g1.set()
    _wait(lambda: tasks.manager.get(a.id)["state"] == tasks.COMPLETED)
    assert ran == ["a"] and heavyjobs.running() == 0


def test_waits_for_free_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    free = [500.0]
    monkeypatch.setattr(heavyjobs, "MIN_FREE_MB", 1000)
    monkeypatch.setattr(heavyjobs, "_free_mb", lambda: free[0])
    notes: list[str] = []
    cancel = threading.Event()
    got: list[bool] = []
    th = threading.Thread(target=lambda: got.append(heavyjobs.acquire(cancel, notes.append, slots=0)))
    th.start()
    _wait(lambda: any("free memory" in n for n in notes))
    free[0] = 4000.0
    th.join(15)
    assert got == [True]
    heavyjobs.release()


def test_progress_shown_in_tasks(one_slot: Path) -> None:
    gate = threading.Event()
    t = tasks.manager.start_background(
        "floss", "c1", "p.exe", "floss (background)",
        lambda task, c: heavyjobs.run(task, c, "FLOSS", lambda: (gate.wait(20), {"status": "ok"})[1],
                                      progress=lambda: "stack strings 1200/4800")["status"],
        step="FLOSS · p", cases_dir=one_slot)
    _wait(lambda: "stack strings 1200/4800" in (tasks.manager.get(t.id)["steps"][0].get("detail") or ""), 15)
    assert tasks.manager.get(t.id)["steps"][0]["detail"].startswith("FLOSS running · ")
    gate.set()
    _wait(lambda: tasks.manager.get(t.id)["state"] == tasks.COMPLETED)
