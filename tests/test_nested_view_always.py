"""Every Nested node opens as an analysis — even one with nothing but the file.

A plain-text child, an opaque blob and a file only listed (over the limits) all get a
``view_id``; the view shows the file itself (type, size, hash, folder, Hex) in its File tab.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from docutracex import cases as case_service
from docutracex import nested
from docutracex.api import cases as api
from docutracex.config import settings
from docutracex.storage import CasePaths, write_json


def _walk(nodes):  # noqa: ANN001, ANN202
    for n in nodes:
        yield n
        yield from _walk(n.get("children") or [])


def test_every_node_has_a_view(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nested, "MAX_CHILDREN", 2)
    cp = CasePaths("c1", cases_dir=tmp_path / "cases")
    d = cp.extracted_dir / "attachments"
    d.mkdir(parents=True)
    (d / "notes.txt").write_text("pay to https://invoice-portal.example/pay now\n")
    (d / "blob.bin").write_bytes(bytes(range(256)) * 64)
    (d / "later.txt").write_text("listed only\n")
    items = [{"path": str(d / n), "filename": n} for n in ("notes.txt", "blob.bin", "later.txt")]
    res = nested.scan_children(items, cp)
    nodes = list(_walk(res["tree"]))
    assert len(nodes) == 3
    assert all(n.get("view_id") for n in nodes)
    listed = next(n for n in nodes if n["filename"] == "later.txt")
    assert listed.get("listed_only") and listed["view_modules"] == []
    for n in nodes:
        assert nested.view_path(cp, n["view_id"]).is_file()
    text = next(n for n in nodes if n["filename"] == "notes.txt")
    view = (nested.view_path(cp, text["view_id"])).read_text()
    assert "invoice-portal.example" in view               # the text mined for IOCs is in its own view


def test_empty_view_shows_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(case_service, "get_case", lambda aid: {"analysis_id": aid})
    cp = CasePaths("20261125-100000-abcdef12")
    vid = "0123456789abcdef-a1b2c3"
    write_json(cp.subresult("nested"), {"tree": [{"filename": "later.txt", "kind": "other", "view_id": vid,
                                                   "stored_path": "extracted/attachments/later.txt", "size": 12,
                                                   "sha256": "ab" * 32, "listed_only": True,
                                                   "note": "listed, not analysed in depth"}]})
    write_json(nested.view_path(cp, vid), {"view_id": vid, "filename": "later.txt", "kind": "other",
                                           "chain": "later.txt", "stored_path": "extracted/attachments/later.txt",
                                           "sha256": "ab" * 32, "modules": {}, "findings": [], "iocs": {}})
    out = asyncio.run(api.get_nested_components("20261125-100000-abcdef12", vid))
    f = out["modules"]["file"]
    assert f["stored_path"] == "extracted/attachments/later.txt" and f["size_bytes"] == 12
    assert f["hashes"]["sha256"] == "ab" * 32 and "listed" in f["note"]
