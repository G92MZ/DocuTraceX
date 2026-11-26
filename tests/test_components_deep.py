"""/components serves results nested deeper than pydantic's serializer allows (long stage chains)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_deeply_nested_result_is_served(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json, write_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    c = TestClient(create_app())
    r = c.post("/api/cases", data={"engines": ""}, files={"file": ("factura.txt", b"Factura 2026-0187")})
    aid = r.json()["analysis_id"]
    deep: dict = {"leaf": "Factura 2026-0187"}
    for _ in range(400):
        deep = {"child": deep}
    paths = CasePaths(aid)
    write_json(paths.subresult("vbscript"), deep)
    man = read_json(paths.root / "case.json")
    man.setdefault("analysis", {})["modules_run"] = ["vbscript"]
    write_json(paths.root / "case.json", man)
    g = c.get(f"/api/cases/{aid}/components")
    assert g.status_code == 200 and "vbscript" in g.json()["modules"]
