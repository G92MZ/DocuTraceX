"""MCP: nothing cut — every tool answers in pages (offset / next_offset) with the whole
content; and the C2 / YARA / raw tools."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
ms = pytest.importorskip("make_samples")


def _all(fn, key, *a, **kw):  # noqa: ANN001, ANN002, ANN003, ANN202
    """Follow next_offset to the end: every item (or, for text, the joined slices)."""
    from docutracex import ai_tools
    out, off, pages = [], 0, 0
    with ai_tools.paged():
        while off is not None:
            r = fn(*a, offset=off, **kw)
            assert "error" not in r, r
            out.append(r[key]) if isinstance(r[key], str) else out.extend(r[key])
            off = r["next_offset"]
            pages += 1
            assert pages < 500
    return ("".join(out) if out and isinstance(out[0], str) else out), pages


@pytest.fixture()
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    """A case with C2 configurations (AsyncRAT sample) analysed with C2 and a YARA scan."""
    from docutracex import analyze, cases, yara_engine
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(settings, "yara_dir", tmp_path / "yara")
    yara_engine.add_upload("dtx_test.yar", b'rule DTX_MZ_Test { meta: description = "test" '
                                            b'strings: $mz = "MZ" condition: $mz at 0 }')
    for _ in yara_engine.compile_stream():
        pass
    data = ms.c2_samples()["c2/sample_asyncrat.exe"] if "c2/sample_asyncrat.exe" in ms.c2_samples() else ms.family_yara_exe()
    m = cases.create_case(io.BytesIO(data), "sample.exe", cases_dir=settings.cases_dir)
    root = settings.cases_dir / m["analysis_id"]
    analyze.analyze_case(root)
    analyze.run_module(root, "c2")
    analyze.run_module(root, "yara")
    return m["analysis_id"], root


def test_get_module_pages_join_to_the_whole_json(case, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from docutracex import ai_tools
    cid, root = case
    monkeypatch.setattr(ai_tools, "PAGE_CHARS", 1500)          # small pages: many of them
    for mod in ("c2", "dotnet", "file"):
        text, pages = _all(ai_tools.get_module, "json", cid, mod)
        assert json.loads(text) == json.loads((root / "results" / f"{mod}.json").read_text())
        assert pages > 1 or len(text) <= 1500
    assert {m["module"] for m in ai_tools.list_modules(cid)["modules"]} >= {"c2", "yara", "dotnet", "file"}


def test_findings_iocs_nested_every_item(case, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from docutracex import ai_tools, marks
    from docutracex.storage import CasePaths
    from docutracex.config import settings
    cid, root = case
    monkeypatch.setattr(ai_tools, "PAGE_CHARS", 600)
    total = len(marks.case_findings(CasePaths(cid, cases_dir=settings.cases_dir)))
    got, pages = _all(ai_tools.get_findings, "findings", cid)
    assert len(got) == total and pages > 1
    assert all("…" not in (f.get("evidence") or "")[-30:] or "(+" not in (f.get("evidence") or "") for f in got)
    nodes, _ = _all(ai_tools.get_nested_tree, "nodes", cid)

    def count(ns):  # noqa: ANN001, ANN202
        return sum(1 + count(n.get("children")) for n in ns or [])
    nj = root / "results" / "nested.json"
    assert len(nodes) == (count(json.loads(nj.read_text())["tree"]) if nj.is_file() else 0)


def test_c2_tools(case) -> None:  # noqa: ANN001
    from docutracex import ai_tools
    cid, root = case
    c2 = json.loads((root / "results" / "c2.json").read_text())
    with ai_tools.paged():
        r = ai_tools.get_c2(cid)
    assert r["total"] == len(c2["configs"]) and r["extractor_status"] == c2["extractor_status"]
    if c2["configs"]:                                   # every field, not a summary
        assert set(c2["configs"][0]) - {"_raw"} <= set(r["configs"][0]) | {"_raw"}
    objs, _ = _all(ai_tools.get_c2_raw, "objects", cid)
    assert objs and objs[0]["index"] == "0000" and "family_yara" in objs[0]["extractors"]
    text, _ = _all(ai_tools.get_c2_raw, "json", cid, object="0")
    assert json.loads(text)["extractors"]


def test_yara_tools(case) -> None:  # noqa: ANN001
    from docutracex import ai_tools
    cid, _root = case
    hits, _ = _all(ai_tools.get_yara, "hits", cid)
    assert hits and hits[0]["rule"] == "DTX_MZ_Test" and "rule DTX_MZ_Test" in hits[0]["rule_source"]
    assert hits[0]["strings"] and hits[0]["mark"] == "unreviewed"
    rules, _ = _all(ai_tools.list_yara_rules, "rules")
    assert [r["name"] for r in rules] == ["DTX_MZ_Test"]


def test_chat_keeps_its_caps(case) -> None:  # noqa: ANN001
    """Outside the MCP pages, the AI chat still gets short answers."""
    from docutracex import ai_tools
    cid, _ = case
    r = ai_tools.get_findings(cid, limit=2)
    assert r["returned"] <= 2 and r["total"] >= r["returned"]
    r = ai_tools.get_module(cid, "c2", max_chars=1000)
    assert len(r["json"]) <= 1000


def test_mcp_server_lists_every_tool() -> None:
    import asyncio

    from docutracex import ai_tools, mcp_server
    names = {t.name for t in asyncio.run(mcp_server.build_server().list_tools())}
    assert names == set(ai_tools.TOOLS)
    assert {"get_c2", "get_c2_raw", "get_yara", "list_yara_rules", "list_modules"} <= names


def test_nested_tree_flat_pages_every_node(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import ai_tools, analyze, cases
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(ai_tools, "PAGE_CHARS", 400)
    m = cases.create_case(io.BytesIO(ms.disguised_samples()["sample_disguised_autoit.au3"]), "loader.au3",
                          cases_dir=settings.cases_dir)
    root = settings.cases_dir / m["analysis_id"]
    analyze.analyze_case(root)
    nodes, pages = _all(ai_tools.get_nested_tree, "nodes", m["analysis_id"])

    def count(ns):  # noqa: ANN001, ANN202
        return sum(1 + count(n.get("children")) for n in ns or [])
    assert pages > 1 and len(nodes) == count(json.loads((root / "results" / "nested.json").read_text())["tree"])
    assert any(n["path"].endswith("› script.au3") and n["depth"] == 2 for n in nodes)
