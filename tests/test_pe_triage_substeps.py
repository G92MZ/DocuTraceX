"""PE triage: each tool (LIEF, debloat, unpacking, FLOSS, capa) is a sub-step of the step
with its time and status, and FLOSS + capa report how long they have been running."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
ms = pytest.importorskip("make_samples")


def test_tools_are_substeps_of_the_pe_triage_step(tmp_path: Path) -> None:
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths
    m = cases.create_case(io.BytesIO(ms.family_yara_exe()), "x.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    s = json.loads(CasePaths(m["analysis_id"], cases_dir=tmp_path).summary.read_text())
    step = next(x for x in s["steps"] if "PE triage" in x["step"])
    names = [x["chain"] for x in step["substeps"]]
    assert names[0].startswith("LIEF") and names[-2:] == ["FLOSS", "capa"]
    assert any(n.startswith("packer detection") for n in names)
    assert all({"duration_s", "status"} <= set(x) for x in step["substeps"])
    msi = json.loads((tmp_path / m["analysis_id"] / "results" / "msi.json").read_text())
    assert "timings" not in msi and "timings" not in msi["items"][0]      # in the step record, not the result


def test_floss_capa_heartbeat_and_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze
    from docutracex.parsers import pe
    seen: list[str] = []
    monkeypatch.setattr(pe, "HEARTBEAT_S", 0.05)
    analyze._step_local.fn = lambda ev, rec: seen.append(rec.get("detail") or "") if ev == "progress" else None
    analyze._step_local.current = "binary: PE triage"
    try:
        clock = pe._Clock("dropper.exe")

        def slow():  # noqa: ANN202
            time.sleep(0.3)
            return ({"status": "ok", "duration_s": 0.3}, {"status": "timeout", "detail": "capa timed out after 1800s"})
        floss, capa = clock.tools(slow)
    finally:
        analyze._step_local.fn = None
        analyze._step_local.current = None
    assert any("FLOSS + capa running · 0m 00s" in d for d in seen)
    rows = {r["chain"]: r for r in clock.rows}
    assert rows["FLOSS"]["status"] == "ok" and rows["FLOSS"]["duration_s"] == 0.3
    assert rows["capa"]["status"] == "timeout" and "timed out" in rows["capa"]["detail"]


def test_heartbeat_says_which_tool_is_still_running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FLOSS finished, capa still going: "capa running · … (FLOSS done in …)"."""
    from docutracex import analyze
    from docutracex.parsers import pe
    exe = tmp_path / "dense.exe"
    exe.write_bytes(b"MZ dense inert stub")
    monkeypatch.setattr(pe, "HEARTBEAT_S", 0.05)
    monkeypatch.setattr(pe, "_trusted_signer", lambda p: None)
    monkeypatch.setattr(pe, "_cache_get", lambda *a: None)
    monkeypatch.setattr(pe, "_cache_file", lambda *a: tmp_path / "nocache" / "x.json")
    monkeypatch.setattr(pe, "_run_floss", lambda p, *a, **k: {"status": "ok", "duration_s": 0.0, "strings": []})

    def slow_capa(p, *a):  # noqa: ANN001, ANN002, ANN202
        time.sleep(0.5)
        return {"status": "ok", "duration_s": 0.5, "capabilities": []}
    monkeypatch.setattr(pe, "_run_capa", slow_capa)
    seen: list[str] = []
    analyze._step_local.fn = lambda ev, rec: seen.append(rec.get("detail") or "") if ev == "progress" else None
    analyze._step_local.current = "binary: PE triage"
    try:
        pe._Clock("dense.exe", exe).tools(lambda: pe._both(exe))
    finally:
        analyze._step_local.fn = None
        analyze._step_local.current = None
    assert any(d.endswith(")") and "capa running" in d and "FLOSS done in 0m 00s" in d for d in seen), seen
