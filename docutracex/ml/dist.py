"""Where a score and a feature value sit among EMBER2024 test files.

``ember_dist.json`` (computed once on GitHub Actions, see scripts/ember) holds,
per detection model, the score quantiles of malicious and benign test files
and, per feature, the share of files where it is non-zero plus quantiles of
its absolute value. From that:

  score_ref(model, s)        → share of malicious / benign files scoring >= s
  feature_ref(model, i, v)   → how typical value v of feature i is in each class,
                               with a one-line text for the UI
"""

from __future__ import annotations

import bisect
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DIST_FILE = Path(__file__).with_name("ember_dist.json")


@lru_cache(maxsize=1)
def _all() -> dict[str, Any]:
    try:
        return json.loads(DIST_FILE.read_text(encoding="utf-8")).get("models") or {}
    except (OSError, ValueError):
        return {}


def _share(x: float) -> str:
    return "<1%" if 0 < x < 0.005 else (">99%" if 0.995 < x < 1 else f"{x:.0%}")


def model_stats(model: str) -> dict[str, Any] | None:
    return _all().get(model)


def score_ref(model: str, score: float) -> dict[str, Any] | None:
    st = model_stats(model)
    if not st or not st.get("score"):
        return None
    sc = st["score"]
    # share at or above: 1 - P(X < s); with ties at the top (scores of 1.0) use <= on the left
    mal = 1.0 - _cdf_strict(sc["malicious"], score)
    ben = 1.0 - _cdf_strict(sc["benign"], score)
    return {"malicious_ge": round(mal, 4), "benign_ge": round(ben, 4), "n": st.get("n", {}),
            "q": {"malicious": sc["malicious"], "benign": sc["benign"]}}


def _cdf_strict(qs: list[float], x: float) -> float:
    """Fraction of files with a value < x."""
    n = len(qs) - 1
    if x <= qs[0]:
        return 0.0
    if x > qs[-1]:
        return 1.0
    i = bisect.bisect_left(qs, x) - 1                   # qs[i] < x <= qs[i+1]
    lo, hi = qs[i], qs[i + 1]
    frac = (x - lo) / (hi - lo) if hi > lo else 0.0
    return (i + frac) / n


def _pct(qs: list[float], Q: list[int], x: float) -> float:
    """Approximate percentile of x given values at the percentiles Q."""
    if x <= qs[0]:
        return float(Q[0]) if x == qs[0] else 0.0
    if x >= qs[-1]:
        return float(Q[-1]) if x == qs[-1] else 100.0
    i = bisect.bisect_right(qs, x) - 1
    lo, hi = qs[i], qs[i + 1]
    frac = (x - lo) / (hi - lo) if hi > lo else 0.0
    return Q[i] + frac * (Q[i + 1] - Q[i])


# Codes, not quantities: a percentile of 'subsystem' or 'machine' means nothing.
_CATEGORICAL = {"machine", "subsystem", "first byte", "second byte", "third byte", "fourth byte"}


def feature_ref(model: str, idx: int, value: float, name: str = "") -> dict[str, Any] | None:
    """{mal_nz, ben_nz, mal_pct, ben_pct, text} for feature column ``idx``."""
    st = model_stats(model)
    if not st or name in _CATEGORICAL or name.startswith("DOS header "):
        return None
    fm, fb = st["feat"]["malicious"], st["feat"]["benign"]
    if idx >= len(fm["nz"]):
        return None
    Q = st.get("quantiles") or [1, 5, 10, 25, 50, 75, 90, 95, 99]
    v = abs(float(value))
    mnz, bnz = fm["nz"][idx], fb["nz"][idx]
    qm, qb = fm["q"][idx], fb["q"][idx]
    binary = set(qm) | set(qb) <= {0.0, 1.0}
    out: dict[str, Any] = {"mal_nz": mnz, "ben_nz": bnz}
    if binary or v == 0:
        # presence / absence: how many files of each class have it
        text = (f"{'also in' if v > 0 else 'not here; found in'} {_share(mnz)} of malware · {_share(bnz)} of goodware")
    else:
        pm, pb = _pct(qm, Q, v), _pct(qb, Q, v)
        out.update(mal_pct=round(pm, 1), ben_pct=round(pb, 1))
        text = f"≈ p{pm:.0f} of malware · p{pb:.0f} of goodware"
    out["text"] = text
    return out


def _p(x: float) -> str:
    if x <= 0:
        return "0%"
    if x < 0.001:
        return "<0.1%"
    if x > 0.999 and x < 1:
        return ">99.9%"
    return f"{x * 100:.1f}%".replace(".0%", "%")


def reading(score: float, threshold: float | None, ref: dict[str, Any] | None) -> str:
    """One plain-language reading of a score against the threshold and the
    EMBER2024 test files (what the curve shows for this file)."""
    if not ref:
        return ""
    mal, ben = float(ref.get("malicious_ge", 0)), float(ref.get("benign_ge", 0))
    nben = int((ref.get("n") or {}).get("benign") or 0)
    ben_txt = (f"none of the {nben:,} test goodware files" if ben == 0 and nben else f"{_p(ben)} of test goodware")
    s = f"{score:.4f}"
    above = threshold is not None and score >= threshold
    head = (f"Above the threshold ({threshold:.4f}): flagged. " if above else
            f"Below the threshold ({threshold:.4f}): not flagged. " if threshold is not None else "")
    if above:
        if ben < 0.001:
            body = (f"Hardly any goodware scores this high ({ben_txt}), while {_p(mal)} of test "
                    "malware does — a strong indication, still to be confirmed with the other findings.")
        else:
            body = (f"{_p(ben)} of test goodware also scores {s} or more, so a false positive is possible; "
                    f"{_p(mal)} of test malware does.")
        if mal < 0.5:
            body += " Few malware samples score this high: this is among the most clearly malicious-looking files."
    elif ben <= 0.05:
        body = (f"But {s} is higher than {_p(1 - ben)} of test goodware, while {_p(mal)} of test malware scores at "
                "least this — a grey zone: weigh the top features and the other findings.")
    elif ben <= 0.25:
        body = (f"{_p(ben)} of test goodware scores at least {s}: uncommon but not rare for legitimate software; "
                f"{_p(mal)} of test malware scores at least this.")
    else:
        body = (f"A score typical of legitimate software: {_p(ben)} of test goodware scores {s} or more. "
                f"Malware evading the model can also score this low ({_p(1 - mal)} of test malware scores lower).")
    return head + body

