"""ML extras: similar objects across cases, atypical objects, highest score of a chain."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402

from docutracex.ml import ember_ml  # noqa: E402

pytestmark = pytest.mark.skipif(not ember_ml.status()["models"], reason="EMBER2024 models not provisioned")


def _case(tmp_path: Path, data: bytes, name: str):
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json
    m = cases.create_case(io.BytesIO(data), name, cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    analyze.run_module(tmp_path / m["analysis_id"], "ml")
    return m["analysis_id"], read_json(CasePaths(m["analysis_id"], cases_dir=tmp_path).subresult("ml"))


def test_similar_across_cases_and_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    a_id, a = _case(tmp_path, ms.dotnet_stealer_exe(), "mailsync.exe")
    assert all(not x.get("similar") for x in a["items"])                      # first case: nothing to compare
    assert all("_leaves" not in x for x in a["items"])
    b_id, b = _case(tmp_path, ms.dotnet_bitmap_loader_exe(ms.dotnet_stealer_exe()), "gallery.exe")
    stage = next(x for x in b["items"] if x["label"].endswith("pixels.exe"))
    top = stage["similar"][0]
    assert top["case"] == a_id and top["same_file"] and top["similarity"] == 1.0
    assert b["chain"]["max_score"] == max(x["score"] for x in b["items"] if x.get("score") is not None)
    # a variant (other literals, same builder) is close but not the same file
    c_id, c = _case(tmp_path, ms.dotnet_loader_exe(), "viewer.exe")
    sims = c["items"][0]["similar"]
    assert all(not s["same_file"] for s in sims)
    assert (tmp_path / ".ml_index").is_dir()


def test_atypical_flag(tmp_path: Path) -> None:
    import binkit as bk
    stub = tmp_path / "stub.exe"
    stub.write_bytes(ms.dotnet_stealer_exe())
    r = ember_ml.classify([stub])[0]
    a = r["atypicality"]
    assert a["checked"] > 100 and a["share"] >= ember_ml.ATYPICAL_SHARE and a["atypical"]
    assert a["examples"]
