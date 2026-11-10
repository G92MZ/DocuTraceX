"""Name similarity shared by every module that looks for look-alike domains
(own domains, brands; later the global domain engine).

Thresholds live in Settings → *Email rules: your organisation* and are read only
here: a name of up to ``short_len`` letters may differ by ``short_dist`` edits,
a longer one by ``long_dist``; names shorter than ``min_len`` are not compared
(``ups`` / ``ing`` at distance 1 would match half the internet).
"""

from __future__ import annotations

from typing import Any

DEFAULTS: dict[str, int] = {"short_len": 4, "short_dist": 1, "long_dist": 2, "min_len": 4}
LIMITS: dict[str, tuple[int, int]] = {"short_len": (1, 30), "short_dist": (0, 5), "long_dist": (0, 5), "min_len": (1, 30)}


def clean(values: dict[str, Any] | None) -> dict[str, int]:
    out = dict(DEFAULTS)
    for k, (lo, hi) in LIMITS.items():
        try:
            v = int((values or {}).get(k, out[k]))
        except (TypeError, ValueError):
            continue
        out[k] = min(hi, max(lo, v))
    return out


def thresholds() -> dict[str, int]:
    try:
        from . import appsettings
        return clean(appsettings.load().get("similarity"))
    except Exception:  # noqa: BLE001  (settings unreadable: defaults)
        return dict(DEFAULTS)


def max_distance(name: str, th: dict[str, int] | None = None) -> int:
    """Edits allowed for a look-alike of ``name`` (0 = not compared)."""
    th = th or thresholds()
    n = len(name)
    if n < th["min_len"]:
        return 0
    return th["short_dist"] if n <= th["short_len"] else th["long_dist"]


def levenshtein(a: str, b: str, cap: int = 9) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_distance(candidate: str, reference: str, th: dict[str, int] | None = None) -> int:
    """Edit distance when ``candidate`` is a look-alike of ``reference`` within
    the configured threshold; 0 when it is not (or is the same name)."""
    limit = max_distance(reference, th)
    if not limit or candidate == reference:
        return 0
    d = levenshtein(candidate, reference, cap=limit)
    return d if 0 < d <= limit else 0
