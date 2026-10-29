"""Context for the EMBER2024 family hints: what each family is, whether the
name is an AV generic detection rather than a family, a Malpedia link, and a
note when the model cannot tell its top guesses apart.

The descriptions are the project's own (``family_info.json``); the model's
outputs are a closed set, so the table covers all of them. Added when results
are served (UI, report, CSV, AI tools), so older cases get it too.
"""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote

INFO_FILE = Path(__file__).with_name("family_info.json")
MALPEDIA = "https://malpedia.caad.fkie.fraunhofer.de"
# Why a family carries no description (shown instead of one).
UNNAMED_ABOUT = ("The model points to one specific family it was trained on, but which one is not known: "
                 "the authors never published the output names, and on 175,059 labelled EMBER2024 files no "
                 "family raised this output clearly and specifically enough to name it (76 of 2,538 outputs).")
UNKNOWN_ABOUT = ("A family name taken from antivirus labels; DocuTraceX does not describe it because what it "
                 "is (stealer, RAT, adware…) could not be confirmed. Search Malpedia or your own sources.")
TIE_GAP = 0.10          # top two closer than this → the model can't tell them apart
LOW_PROB = 0.40         # top guess below this → low confidence


@lru_cache(maxsize=1)
def _table() -> dict[str, dict[str, Any]]:
    try:
        return (json.loads(INFO_FILE.read_text(encoding="utf-8")).get("families") or {})
    except (OSError, ValueError):
        return {}


def info(name: str) -> dict[str, Any]:
    """``{type, generic?, about?, link, link_label}`` for one family name."""
    name = (name or "").strip()
    if not name or name.startswith("unnamed class"):
        return {"type": "unknown", "unnamed": True, "about": UNNAMED_ABOUT}
    e = dict(_table().get(name.lower()) or {"type": "unknown"})
    if e.get("type") == "unknown" and not e.get("about"):
        e["about"] = UNKNOWN_ABOUT
    mid = e.pop("malpedia", None)
    if mid:
        e["link"], e["link_label"] = f"{MALPEDIA}/details/{mid}", "Malpedia"
    else:
        e["link"], e["link_label"] = f"{MALPEDIA}/api/find/family/{quote(name.lower())}", "Search Malpedia"
    return e


def note(families: list[dict[str, Any]]) -> str:
    """Why the family hint should be read with care ('' when it is clear)."""
    fam = [f for f in families or [] if isinstance(f, dict)]
    if not fam:
        return ""
    top = fam[0]
    p1 = float(top.get("prob") or 0)
    parts = []
    if len(fam) > 1:
        p2 = float(fam[1].get("prob") or 0)
        if p1 - p2 < TIE_GAP:
            parts.append(f"the model can't tell {top.get('name')} and {fam[1].get('name')} apart "
                         f"({p1:.0%} vs {p2:.0%})")
    if p1 < LOW_PROB and not parts:
        parts.append(f"low confidence ({p1:.0%})")
    if info(str(top.get("name"))).get("generic"):
        parts.append(f"{top.get('name')} is a generic AV detection name, not a family")
    return "; ".join(parts)


def enrich_item(item: dict[str, Any]) -> dict[str, Any]:
    """Copy of an ml.json item with context on every family guess + a note."""
    fam = ((item.get("labels") or {}).get("family")) or []
    if not fam:
        return item
    out = copy.deepcopy(item)
    out["labels"]["family"] = [{**f, **{k: v for k, v in info(str(f.get("name"))).items() if k not in f}}
                               for f in out["labels"]["family"]]
    n = note(out["labels"]["family"])
    if n:
        out["family_note"] = n
    return out


def _with_reading(item: dict[str, Any]) -> dict[str, Any]:
    """Plain-language reading of the score vs. threshold and EMBER2024 test files."""
    ref = item.get("score_ref")
    if not isinstance(ref, dict) or ref.get("reading") or item.get("status") != "ok":
        return item
    from .dist import reading
    return {**item, "score_ref": {**ref, "reading": reading(float(item.get("score") or 0), item.get("threshold"), ref)}}


def enrich(ml: dict[str, Any] | None) -> dict[str, Any] | None:
    """ml.json as served: family context on every item and the reading of each
    score (no-op for what an item lacks)."""
    if not isinstance(ml, dict) or not ml.get("items"):
        return ml
    return {**ml, "items": [_with_reading(enrich_item(it)) if isinstance(it, dict) else it for it in ml["items"]]}
