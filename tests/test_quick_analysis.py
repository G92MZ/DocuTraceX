"""Quick analysis: a loose file analysed from an engine tab (YARA, ML, C2, Hex)
becomes a light case that runs only that engine; it can later become a full one."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

import make_samples as ms


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    return TestClient(create_app())


def _wait(c, ids: list[str]) -> list[dict]:
    for _ in range(1200):
        tasks = {t["id"]: t for t in c.get("/api/tasks").json()["tasks"]}
        mine = [tasks.get(i, {}) for i in ids]
        if all(t.get("state") in ("completed", "failed", "cancelled") for t in mine):
            return mine
        time.sleep(0.1)
    raise AssertionError("tasks did not finish")


def test_quick_c2_runs_only_that_engine(client, tmp_path: Path) -> None:
    r = client.post("/api/cases/quick", data={"tool": "c2"},
                    files={"file": ("agent", ms.go_sliver_like_elf())})
    assert r.status_code == 201
    m = r.json()
    assert m["quick"] == {"tool": "c2", "extract": False} and len(m["tasks"]) == 1
    assert _wait(client, [m["task"]["id"]])[0]["state"] == "completed"
    aid = m["analysis_id"]
    comp = client.get(f"/api/cases/{aid}/components").json()
    assert set(comp["modules"]) - {"iocs", "findings", "domainsim"} == {"c2"}           # only the engine ran
    assert [c["family"] for c in comp["modules"]["c2"]["configs"]] == ["Sliver"]
    summ = next(c for c in client.get("/api/cases").json() if c["analysis_id"] == aid)
    assert summ["quick"] == "c2"
    # "Run the full analysis": the quick case becomes a full one
    t = client.post(f"/api/cases/{aid}/rerun", json={}).json()["task"]
    _wait(client, [t["id"]])
    assert "quick" not in client.get(f"/api/cases/{aid}").json()
    assert next(c for c in client.get("/api/cases").json() if c["analysis_id"] == aid)["quick"] == ""


def test_quick_with_contents_runs_the_full_analysis_first(client) -> None:
    m = client.post("/api/cases/quick", data={"tool": "yara", "extract": "true"},
                    files={"file": ("factura.txt", b"invoice text")}).json()
    assert [t["target"] for t in m["tasks"]] == ["full", "yara"] and m["quick"]["extract"] is True
    _wait(client, [t["id"] for t in m["tasks"]])


def test_quick_hex_only_stores_and_bad_tool_is_refused(client) -> None:
    m = client.post("/api/cases/quick", data={"tool": "hex", "extract": "true"},
                    files={"file": ("blob.bin", b"MZ\x90\x00" * 64)}).json()
    assert m["tasks"] == [] and m["quick"] == {"tool": "hex", "extract": False}
    assert client.get(f"/api/cases/{m['analysis_id']}").json()["original"]["size_bytes"] == 256
    assert client.post("/api/cases/quick", data={"tool": "ai"}, files={"file": ("x", b"x")}).status_code == 400


def test_quick_hex_case_opens_in_the_hex_view(client) -> None:
    m = client.post("/api/cases/quick", data={"tool": "hex"}, files={"file": ("blob.bin", b"MZ\x90\x00" * 64)}).json()
    files = client.get(f"/api/cases/{m['analysis_id']}/hex/files").json()
    assert any(f.get("original") or "blob.bin" in str(f) for f in (files.get("files") if isinstance(files, dict) else files))
