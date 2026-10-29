"""Machine Learning results in the CSV export and the HTML report (no models
needed: a recorded ml.json is enough)."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, client  # noqa: E402,F401

ITEMS = [
    {"label": "factura.exe", "stored_path": "original/factura.exe", "sha256": "ab" * 32, "status": "ok",
     "file_type": "Win32", "format": "PE (Win32)", "model": "EMBER2024_Win32", "score": 0.9991,
     "threshold": 0.5322, "calibrated": True, "verdict": "above threshold",
     "metrics": {"tpr_at_fpr_0.01": 0.97, "challenge_detected_at_1pct_fpr": 0.71},
     "blocks": {"imports": 2.1, "header": -0.4},
     "top_features": [{"block": "imports", "feature": "imported function #12", "contribution": 1.5,
                       "matches": ["urlmon.dll:URLDownloadToFileA"]}],
     "labels": {"behavior": [{"name": "downloader", "prob": 0.91, "confidence": "high"}],
                "family": [{"name": "guloader", "prob": 0.62, "confidence": "high"},
                           {"name": "unnamed class #3", "prob": 0.1, "confidence": "none"}]},
     "finding_id": "f1"},
    {"label": "nested › helper.dll", "stored_path": "extracted/helper.dll", "status": "ok", "file_type": "Win64",
     "format": "PE (Win64)", "model": "EMBER2024_Win64", "score": 0.0131, "threshold": 0.5595, "calibrated": True,
     "verdict": "below threshold", "labels": {}, "finding_id": "f2"},
    {"label": "nested › broken.pdf", "status": "error", "detail": "parse error"},
]


def test_ml_csv_and_report(client) -> None:  # noqa: F811
    from docutracex.config import settings

    cid, res = _analyze(client, "factura.txt", b"Factura 2026-0187")
    (res / "ml.json").write_text(json.dumps({"module": "ml", "status": "ok", "items": ITEMS}))
    from docutracex.storage import CasePaths
    marks = CasePaths(cid, cases_dir=settings.cases_dir).marks
    marks.write_text(json.dumps({"marks": {"f1": {"state": "true_positive", "comment": "downloader, confirmed"}}}))

    r = client.get(f"/api/cases/{cid}/ml.csv")
    assert r.status_code == 200 and r.content.startswith(b"\xef\xbb\xbf")
    assert "ml_results_factura_" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert [x["object"] for x in rows] == ["factura.exe", "nested › helper.dll", "nested › broken.pdf"]
    a, b, c = rows
    assert a["verdict"] == "above threshold" and a["score"] == "0.999100" and a["model"] == "EMBER2024_Win32"
    assert a["tags"] == "behavior:downloader (0.91)" and a["family"].startswith("guloader (0.62, high, unknown)")
    assert "imports: imported function #12 (+1.500)" in a["top_features"]
    assert a["mark"] == "true_positive" and a["mark_comment"] == "downloader, confirmed"
    assert b["mark"] == "unreviewed" and b["verdict"] == "below threshold"
    assert c["status"] == "error" and c["detail"] == "parse error" and c["mark"] == ""

    html = client.get(f"/api/cases/{cid}/report").text
    assert "Machine Learning — EMBER2024 (1 of 3 above threshold)" in html
    assert "behavior:downloader (0.91)" in html and "family: guloader (0.62, high, unknown)" in html
    assert "unnamed class" not in html                       # only high-confidence families in the report
    assert "True positive" in html and "parse error" in html


def test_ml_csv_empty_and_missing_case(client) -> None:  # noqa: F811
    cid, _ = _analyze(client, "nota.txt", b"hola")
    r = client.get(f"/api/cases/{cid}/ml.csv")
    assert r.status_code == 200 and r.content.decode("utf-8-sig").startswith("object,stored_path,sha256")
    assert "Machine Learning — EMBER2024" not in client.get(f"/api/cases/{cid}/report").text
    assert client.get("/api/cases/nope/ml.csv").status_code == 404
