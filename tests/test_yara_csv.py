"""YARA CSV export: endpoint, RFC 4180 shape, dynamic meta_* columns."""

from __future__ import annotations

import csv
import io
import time
from pathlib import Path

import pytest

pytest.importorskip("yara")

from fastapi.testclient import TestClient  # noqa: E402

from docutracex.app import create_app  # noqa: E402
from docutracex.config import settings  # noqa: E402


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(settings, "yara_dir", tmp_path / "yara")
    (tmp_path / "cases").mkdir()
    return tmp_path


@pytest.fixture()
def client(env) -> TestClient:
    return TestClient(create_app())


def _compile(client: TestClient) -> None:
    client.post("/api/yara/compile/stream")


def _wait_case(client: TestClient, cid: str) -> None:
    for _ in range(1200):
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            return
        time.sleep(0.05)


def _run_yara(client: TestClient, cid: str) -> None:
    tid = client.post(f"/api/cases/{cid}/rerun", json={"module": "yara"}).json()["task"]["id"]
    for _ in range(400):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            return
        time.sleep(0.05)


RULE = ('rule Dropper { meta: description="test dropper" author="g" severity="high" '
        'strings: $marker="DropMarker" condition: $marker }')


def _parse(resp) -> tuple[list[str], list[dict]]:
    text = resp.content.decode("utf-8")
    assert text.startswith("﻿")                      # UTF-8 BOM
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    rows = list(reader)
    header = rows[0]
    dicts = [dict(zip(header, r)) for r in rows[1:]]
    return header, dicts


def test_yara_csv_export(client: TestClient) -> None:
    client.post("/api/yara/upload", files={"file": ("r.yar", RULE.encode())})
    _compile(client)
    cid = client.post("/api/cases",
                      files={"file": ("p.bin", b"xxDropMarkerxxDropMarkerxx")}).json()["analysis_id"]
    _wait_case(client, cid)
    _run_yara(client, cid)

    r = client.get(f"/api/cases/{cid}/yara.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert r.headers["content-disposition"].startswith('attachment; filename="yara_matches_p_')

    header, rows = _parse(r)
    # dynamic meta columns + the fixed fields
    assert {"file", "rule", "namespace", "tags", "enabled", "string_id", "offset",
            "length", "data_hex", "data_text", "context_start", "context_hex"} <= set(header)
    assert "meta_description" in header and "meta_severity" in header
    assert len(rows) >= 1
    row = rows[0]
    assert row["rule"] == "Dropper"
    assert row["string_id"] == "$marker"
    assert row["meta_description"] == "test dropper" and row["meta_severity"] == "high"
    assert row["data_text"].strip() and row["offset"] != ""


def test_yara_csv_header_only_when_no_matches(client: TestClient) -> None:
    client.post("/api/yara/upload", files={"file": ("r.yar", RULE.encode())})
    _compile(client)
    cid = client.post("/api/cases",
                      files={"file": ("clean.bin", b"nothing to see here")}).json()["analysis_id"]
    _wait_case(client, cid)
    _run_yara(client, cid)
    r = client.get(f"/api/cases/{cid}/yara.csv")
    assert r.status_code == 200
    header, rows = _parse(r)
    assert header[0] == "file" and "rule" in header
    assert rows == []   # header only, no matches


def test_yara_csv_rfc4180_quoting(client: TestClient) -> None:
    # a meta value with a comma must be quoted, not split
    rule = 'rule Q { meta: note="a, b, c" strings: $m="DropMarker" condition: $m }'
    client.post("/api/yara/upload", files={"file": ("q.yar", rule.encode())})
    _compile(client)
    cid = client.post("/api/cases", files={"file": ("p.bin", b"DropMarker")}).json()["analysis_id"]
    _wait_case(client, cid)
    _run_yara(client, cid)
    _, rows = _parse(client.get(f"/api/cases/{cid}/yara.csv"))
    assert rows and rows[0]["meta_note"] == "a, b, c"
