"""Name similarity shared by every module that looks for look-alike domains
(own domains, brands; later the global domain engine).

Thresholds live in Settings → *Email rules: your organisation* and are read only
here: a name of up to ``short_len`` letters may differ by ``short_dist`` edits,
one of up to ``long_len`` by ``long_dist`` and a longer one by ``xlong_dist``;
names shorter than ``min_len`` are not compared (``ups`` / ``ing`` at distance 1
would match half the internet). A distance is a maximum: 2 also catches 1.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

DEFAULTS: dict[str, int] = {"short_len": 4, "short_dist": 1, "long_len": 9, "long_dist": 2, "xlong_dist": 3,
                            "min_len": 4}
LIMITS: dict[str, tuple[int, int]] = {"short_len": (1, 30), "short_dist": (0, 5), "long_len": (1, 60),
                                      "long_dist": (0, 5), "xlong_dist": (0, 6), "min_len": (1, 30)}
EMBED_LEN = 6            # brands this long are looked for anywhere in a name, and as a word with EMBED_DIST
                         # edits (shorter: whole word / prefix only — pineapple is not apple)
EMBED_DIST = 1           # edits allowed for a brand written inside a longer name
FUZZY_INSIDE_LEN = 7     # brands this long also match with EMBED_DIST edits glued to other text (myoutlok365);
                         # shorter ones would hit words (amazing → amazon)


def clean(values: dict[str, Any] | None) -> dict[str, int]:
    out = dict(DEFAULTS)
    values = dict(values or {})
    if "long_dist" in values and "xlong_dist" not in values and str(values["long_dist"]) != "2":
        values["xlong_dist"] = values["long_dist"]     # saved before the third tier with a custom distance: keep it
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
    if n <= th["short_len"]:
        return th["short_dist"]
    return th["long_dist"] if n <= th.get("long_len", DEFAULTS["long_len"]) else th.get("xlong_dist", th["long_dist"])


def embedded_distance(ref: str, text: str, cap: int | None = None) -> int:
    """Fewest edits that turn some piece of ``text`` into ``ref`` (approximate
    substring match): 0 when ``ref`` is inside ``text`` as written. With ``cap``,
    exact up to it and ``cap + 1`` beyond (stops early)."""
    if not ref:
        return 0
    if cap is not None and len(ref) > len(text) + cap:
        return cap + 1
    prev = [0] * (len(text) + 1)                      # the match may start anywhere in text
    for i, c in enumerate(ref, 1):
        cur = [i]
        for j, t in enumerate(text, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (c != t)))
        prev = cur
        if cap is not None and min(prev) > cap:
            return cap + 1
    return min(prev)


def levenshtein(a: str, b: str, cap: int = 9) -> int:
    """Edit distance, exact up to ``cap``; ``cap + 1`` when it is larger. Banded
    (only cells within ``cap`` of the diagonal) and stops as soon as a row has
    nothing within ``cap``: thousands of own domains × the domains of a case
    stay fast."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if len(a) > len(b):
        a, b = b, a
    over = cap + 1
    lb = len(b)
    prev = [j if j <= cap else over for j in range(lb + 1)]
    for i in range(1, len(a) + 1):
        lo, hi = max(1, i - cap), min(lb, i + cap)
        cur = [over] * (lb + 1)
        cur[0] = i if i <= cap else over
        ca = a[i - 1]
        best = cur[0] if lo == 1 else over
        for j in range(lo, hi + 1):
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != b[j - 1]))
            v = v if v <= cap else over
            cur[j] = v
            if v < best:
                best = v
        if best > cap:
            return over
        prev = cur
    return prev[lb]


def lookalike_distance(candidate: str, reference: str, th: dict[str, int] | None = None) -> int:
    """Edit distance when ``candidate`` is a look-alike of ``reference`` within
    the configured threshold; 0 when it is not (or is the same name)."""
    limit = max_distance(reference, th)
    if not limit or candidate == reference:
        return 0
    d = levenshtein(candidate, reference, cap=limit)
    return d if 0 < d <= limit else 0


def damerau(a: str, b: str, cap: int = 9) -> int:
    """Optimal-string-alignment distance: like Levenshtein, but swapping two
    adjacent letters (docusign → docusing) costs 1. Exact up to ``cap``,
    ``cap + 1`` beyond (stops as soon as a row has nothing within ``cap``)."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    la, lb = len(a), len(b)
    big = la + lb + 1
    d = [[big] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        best = d[i][0]
        for j in range(max(1, i - cap - 1), min(lb, i + cap + 1) + 1):
            cost = a[i - 1] != b[j - 1]
            v = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, d[i - 2][j - 2] + 1)
            d[i][j] = v
            best = min(best, v)
        if best > cap:
            return cap + 1
    return min(d[la][lb], cap + 1)


# Look-alike ASCII sequences and Unicode confusables, folded to the letters they imitate.
HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("4", "a"),
              ("7", "t"), ("@", "a"), ("$", "s"))
CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l",
    "ɡ": "g", "ո": "n", "ս": "u", "օ": "o", "ց": "g",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ω": "w",
    # other look-alikes
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ß": "ss", "æ": "ae", "œ": "oe",
}


@lru_cache(maxsize=65536)
def unicode_skeleton(label: str) -> str:
    """Unicode look-alikes folded to ASCII (Cyrillic а → a, accents dropped)."""
    import unicodedata
    out = "".join(CONFUSABLES.get(c, c) for c in label.lower())
    return "".join(c for c in unicodedata.normalize("NFKD", out) if not unicodedata.combining(c))


@lru_cache(maxsize=65536)
def homoglyph_fold(label: str) -> str:
    out = unicode_skeleton(label)
    for a, b in HOMOGLYPHS:
        out = out.replace(a, b)
    return out


def idn_decode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except (UnicodeError, ValueError):
        return host
