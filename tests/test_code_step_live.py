"""Code step: live detail in Tasks (phase and time), and FLOSS tight on the priority
functions of a large binary as a background task merged into Strings and IOCs."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

from docutracex import tasks
from docutracex.codeanalysis import case
from docutracex.parsers import pe as pe_mod

URL = "https://facturas-cdn.example/tight.php"


def _wait(pred, s: float = 30) -> None:  # noqa: ANN001
    end = time.monotonic() + s
    while time.monotonic() < end:
        if pred():
            return
        time.sleep(0.05)
    raise AssertionError("timed out")


def test_live_detail_reports_phase_and_time(monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze
    seen: list[str] = []
    analyze._step_local.fn = lambda ev, rec: seen.append(rec.get("detail") or "") if ev == "progress" else None
    analyze._step_local.current = "code: functions"
    try:
        live = case._Live("visor.exe")
        live.set("Rizin analysis")
        live.set("decompiling 40/120")
        live.close()
    finally:
        analyze._step_local.fn = None
        analyze._step_local.current = None
    assert seen[0] == "code · visor.exe · Rizin analysis · 0m 00s"
    assert seen[-1].startswith("code · visor.exe · decompiling 40/120 · ")


def test_priority_tight_in_the_background(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json, write_subresult
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    m = cases.create_case(io.BytesIO(b"MZ" + b"\0" * 64), "visor.exe", cases_dir=tmp_path / "cases")
    root = tmp_path / "cases" / m["analysis_id"]
    analyze.analyze_case(root)
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path / "cases")
    sha = "ab" * 32
    write_subresult(paths, "code", {"module": "code", "objects": [{"label": "visor.exe", "sha256": sha,
                                                                   "ioc_sources": []}]})
    res_file = tmp_path / "code_result.json"
    full = {"functions": [{"addr": 0x402000, "name": "decode", "size": 0x100, "rank": 1, "loops": 2,
                           "xor_ops": 4, "user": True}]}
    monkeypatch.setattr(case, "result_file", lambda *a: res_file)
    monkeypatch.setattr(case, "binary_item", lambda *a: {"floss": {"status": "ok", "tight_skipped": True}})
    monkeypatch.setattr(pe_mod, "FLOSS_BACKGROUND_BYTES", 8)
    monkeypatch.setattr(pe_mod, "_tools_available", lambda: True)
    monkeypatch.setattr(pe_mod, "tight_cached", lambda p, a: False)
    monkeypatch.setattr(pe_mod, "tight_on_functions", lambda p, a, cancel=None: {
        "status": "ok", "located": [{"kind": "tight", "string": URL, "function": 0x402000}]})
    exe = root / "original" / "visor.exe"
    if not exe.exists():
        exe = next((root / "original").iterdir())
    item = {"label": "visor.exe", "stored_path": "original/visor.exe", "original": True}
    got = case.priority_tight(root, exe, full, item, None, sha, "native")
    assert got == [] and full["floss_priority"]["status"] == "background"
    tid = full["floss_priority"]["task_id"]
    res_file.write_text(json.dumps(full))                    # what enrich writes at the end of the step
    _wait(lambda: tasks.manager.get(tid)["state"] == tasks.COMPLETED)
    done = json.loads(res_file.read_text())
    assert done["floss_priority"]["status"] == "ok" and done["floss_priority"]["background"]
    assert [x["value"] for x in done["floss"]] == [URL]
    assert done["floss"][0]["source"].endswith("(priority functions, background)")
    assert URL in {i["value"] for i in (read_json(paths.subresult("iocs")) or {}).get("iocs") or []}
