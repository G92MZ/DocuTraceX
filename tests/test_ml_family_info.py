"""Family context for the EMBER2024 family hints (no models needed)."""

from __future__ import annotations

import json
from pathlib import Path

from docutracex.ml import family_info


def test_every_model_output_has_a_kind() -> None:
    labels = json.loads((Path(family_info.__file__).with_name("ember_labels.json")).read_text())
    names = {v["name"] for v in labels["models"]["family"]["labels"].values()}
    table = family_info._table()
    assert names <= set(table), sorted(names - set(table))[:10]
    assert all(e.get("type") for e in table.values())
    assert sum(1 for e in table.values() if e.get("about")) >= 500


def test_info_links_and_generic_names() -> None:
    w = family_info.info("wacatac")
    assert w["generic"] and w["type"] == "generic AV name" and "/api/find/family/wacatac" in w["link"]
    a = family_info.info("asyncrat")
    assert a["type"] == "RAT / backdoor" and a["link"].endswith("/details/win.asyncrat") and a["about"]
    u = family_info.info("unnamed class #166")
    assert u["unnamed"] and u["type"] == "unknown"
    assert family_info.info("not-in-the-table")["type"] == "unknown"


def test_notes_tie_low_and_generic() -> None:
    tie = [{"name": "wacatac", "prob": 0.33}, {"name": "darktortilla", "prob": 0.30}]
    n = family_info.note(tie)
    assert "can't tell wacatac and darktortilla apart (33% vs 30%)" in n and "generic AV detection name" in n
    assert "low confidence (25%)" in family_info.note([{"name": "asyncrat", "prob": 0.25}, {"name": "njrat", "prob": 0.05}])
    assert family_info.note([{"name": "asyncrat", "prob": 0.91}, {"name": "njrat", "prob": 0.04}]) == ""


def test_enrich_keeps_original_and_flows_to_csv_and_report(tmp_path, monkeypatch) -> None:
    import csv
    import io
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from fastapi.testclient import TestClient
    from test_js_techniques import _analyze

    from docutracex.app import create_app
    from docutracex.config import settings

    item = {"label": "4489a0ba.exe", "status": "ok", "file_type": "Dot_Net", "format": ".NET", "model": "EMBER2024_Dot_Net",
            "score": 0.999995, "threshold": 0.9330, "calibrated": True, "verdict": "above threshold", "finding_id": "f1",
            "labels": {"family": [{"name": "wacatac", "prob": 0.33, "confidence": "high"},
                                  {"name": "darktortilla", "prob": 0.30, "confidence": "high"},
                                  {"name": "unnamed class #166", "prob": 0.09, "confidence": "none"}],
                       "file_property": [{"name": "msil", "prob": 0.99, "confidence": "high"}]}}
    out = family_info.enrich({"items": [item]})["items"][0]
    assert "type" not in item["labels"]["family"][0]                       # original untouched
    assert out["labels"]["family"][1]["type"] == "crypter / packer" and out["family_note"]

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    client = TestClient(create_app())
    cid, res = _analyze(client, "x.txt", b"hola")
    (res / "ml.json").write_text(json.dumps({"module": "ml", "status": "ok", "items": [item]}))
    comps = client.get(f"/api/cases/{cid}/components").json()
    assert "ml" not in comps["modules"] or comps["modules"]["ml"]["items"][0]["family_note"]
    rows = list(csv.DictReader(io.StringIO(client.get(f"/api/cases/{cid}/ml.csv").content.decode("utf-8-sig"))))
    assert "wacatac (0.33, high, generic AV name)" in rows[0]["family"]
    assert "darktortilla (0.30, high, crypter / packer)" in rows[0]["family"]
    assert "apart" in rows[0]["family_note"]
    html = client.get(f"/api/cases/{cid}/report").text
    assert "can&#x27;t tell wacatac and darktortilla apart" in html
    from docutracex import ai_tools
    got = ai_tools.get_module(cid, "ml")
    assert '"type": "crypter / packer"' in got["json"] and "family_note" in got["json"]
