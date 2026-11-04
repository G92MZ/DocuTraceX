"""YARA / ML / C2 over the objects the analyst picks, in parallel."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402


@pytest.fixture()
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    # a .NET loader hiding the AgentTesla-like stealer: original + resources + stage 2
    m = cases.create_case(io.BytesIO(ms.dotnet_bitmap_loader_exe(ms.dotnet_stealer_exe())), "gallery.exe",
                          cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    return CasePaths(m["analysis_id"], cases_dir=tmp_path), tmp_path / m["analysis_id"]


def test_objects_selection_and_partial_runs(case, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, objects
    from docutracex.storage import read_json
    paths, root = case
    manifest = read_json(paths.manifest)
    objs = objects.case_objects(paths, paths.root / manifest["original"]["stored_path"])
    ids = [o["id"] for o in objs]
    assert ids[0] == "original" and len(ids) >= 3 and len(set(ids)) == len(ids)
    stealer = next(o["id"] for o in objs if o["id"].endswith(".pixels.exe"))
    assert next(o for o in objs if o["id"] == stealer)["kind"] == "PE"

    # C2 over the stealer only (in parallel workers when there are several)
    monkeypatch.setenv("DOCUTRACEX_SCAN_WORKERS", "2")
    objects.save_selection(paths, "c2", [stealer])
    analyze.run_module(root, "c2")
    c2 = read_json(paths.subresult("c2"))
    assert c2["objects_scanned"] == 1 and c2["selection"] == [stealer]
    assert any("smtp.billing-portal.example" in (c.get("c2") or []) for c in c2["configs"])
    assert not objects.selection_file(paths, "c2").exists()            # one-shot

    # then the original only: the stealer's config is kept (partial run merged)
    objects.save_selection(paths, "c2", ["original"])
    analyze.run_module(root, "c2")
    c2 = read_json(paths.subresult("c2"))
    assert any(c.get("stored_path") == stealer for c in c2["configs"])
    assert c2["counts"]["configs"] == len(c2["configs"])

    # a full run (no selection) scans everything again, in parallel
    analyze.run_module(root, "c2")
    full = read_json(paths.subresult("c2"))
    assert full["objects_scanned"] == len(ids) and full.get("selection") is None
    assert [c["family"] for c in full["configs"]] == [c["family"] for c in c2["configs"]]


def test_yara_selection(case) -> None:
    from docutracex import analyze, objects
    from docutracex.storage import read_json
    paths, root = case
    objects.save_selection(paths, "yara", ["original"])
    analyze.run_module(root, "yara")
    y = read_json(paths.subresult("yara"))
    if not y.get("rule_count"):
        pytest.skip("no YARA rules compiled here")
    assert y["files_scanned"] == 1 and y["selection"] == ["original"]


def test_workers_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex.objects import workers
    monkeypatch.delenv("DOCUTRACEX_SCAN_WORKERS", raising=False)
    assert workers(1) == 1 and 1 <= workers(50) <= 4 and workers(50, 2) <= 2
    monkeypatch.setenv("DOCUTRACEX_SCAN_WORKERS", "3")
    assert workers(50) == 3 and workers(2) == 2


def test_api_objects_and_rerun_selection(case, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from docutracex import objects
    from docutracex.app import create_app
    from docutracex.tasks import manager
    paths, root = case
    monkeypatch.setattr(manager, "submit", lambda *a, **k: type("T", (), {"public": lambda self: {"id": "t"}})())
    c = TestClient(create_app())
    objs = c.get(f"/api/cases/{paths.root.name}/objects").json()["objects"]
    assert objs[0]["id"] == "original"
    r = c.post(f"/api/cases/{paths.root.name}/rerun", json={"module": "ml", "objects": ["original"]})
    assert r.status_code == 200 and objects.take_selection(paths, "ml") == {"original"}
    assert c.post(f"/api/cases/{paths.root.name}/rerun", json={"module": "c2", "objects": "x"}).status_code == 400
