"""Score / feature context against EMBER2024 test files (synthetic reference)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from docutracex.ml import dist


@pytest.fixture()
def ref(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    Q = [1, 5, 10, 25, 50, 75, 90, 95, 99]
    model = {
        "n": {"malicious": 1000, "benign": 1000}, "quantiles": Q,
        # malware mostly scores high, goodware low
        "score": {"malicious": [0.5 + i / 200 for i in range(101)], "benign": [i / 200 for i in range(101)]},
        "feat": {
            "malicious": {"nz": [0.9, 0.3, 1.0], "q": [[1] * 9, [0, 0, 0, 0, 0, 1, 1, 1, 1], [5, 6, 6.5, 7, 7.5, 7.8, 7.9, 7.95, 8]]},
            "benign": {"nz": [0.1, 0.8, 1.0], "q": [[0] * 9, [0, 0, 1, 1, 1, 1, 1, 1, 1], [1, 2, 3, 4, 5, 6, 6.5, 7, 7.5]]},
        },
    }
    f = tmp_path / "ember_dist.json"
    f.write_text(json.dumps({"models": {"EMBER2024_Win32": model}}))
    monkeypatch.setattr(dist, "DIST_FILE", f)
    dist._all.cache_clear()
    yield
    dist._all.cache_clear()


def test_score_reference(ref) -> None:
    r = dist.score_ref("EMBER2024_Win32", 0.75)
    assert r["malicious_ge"] == pytest.approx(0.5, abs=0.02) and r["benign_ge"] == pytest.approx(0.0, abs=0.01)
    low = dist.score_ref("EMBER2024_Win32", 0.25)
    assert low["malicious_ge"] == 1.0 and low["benign_ge"] == pytest.approx(0.5, abs=0.02)
    assert len(r["q"]["malicious"]) == 101
    assert dist.score_ref("EMBER2024_ELF", 0.5) is None          # no reference for that model


def test_feature_reference_presence_and_percentiles(ref) -> None:
    present = dist.feature_ref("EMBER2024_Win32", 0, -1.0)      # hashed sign ignored
    assert present["text"] == "also in 90% of malware · 10% of goodware"
    absent = dist.feature_ref("EMBER2024_Win32", 1, 0.0)
    assert absent["text"] == "not here; found in 30% of malware · 80% of goodware"
    ent = dist.feature_ref("EMBER2024_Win32", 2, 7.6)
    assert 50 < ent["mal_pct"] < 75 and ent["ben_pct"] >= 99       # above every benign quantile
    assert ent["text"].startswith("≈ p") and "of goodware" in ent["text"]
    assert dist.feature_ref("EMBER2024_Win32", 2, 2.0, "subsystem") is None       # a code, not a quantity
    assert dist.feature_ref("EMBER2024_Win32", 99, 1.0) is None


def test_reading_in_plain_words() -> None:
    grey = dist.reading(0.1933, 0.5595, {"malicious_ge": 0.994, "benign_ge": 0.027})
    assert grey.startswith("Below the threshold (0.5595): not flagged.") and "grey zone" in grey and "97.3%" in grey
    strong = dist.reading(0.9993, 0.5322, {"malicious_ge": 0.592, "benign_ge": 0.0, "n": {"benign": 20000}})
    assert strong.startswith("Above the threshold") and "none of the 20,000 test goodware files" in strong
    fp = dist.reading(0.70, 0.5322, {"malicious_ge": 0.96, "benign_ge": 0.006})
    assert "false positive is possible" in fp
    typical = dist.reading(0.01, 0.5322, {"malicious_ge": 0.999, "benign_ge": 0.42})
    assert "typical of legitimate software" in typical
    assert dist.reading(0.5, 0.5, None) == ""


def test_enrich_adds_the_reading() -> None:
    from docutracex.ml import family_info
    ml = {"items": [{"status": "ok", "score": 0.1933, "threshold": 0.5595,
                     "score_ref": {"malicious_ge": 0.994, "benign_ge": 0.027}},
                    {"status": "error", "detail": "x"}]}
    out = family_info.enrich(ml)
    assert "grey zone" in out["items"][0]["score_ref"]["reading"] and "reading" not in ml["items"][0]["score_ref"]
