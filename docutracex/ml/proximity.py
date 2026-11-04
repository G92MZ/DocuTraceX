"""What the EMBER2024 trees say about an object besides its score.

* **Proximity** (Breiman): two files are close when the trees route them to the
  same leaves — the share of trees where their leaves match. Model-aware and
  free of feature scales, so it compares *how the detector sees* two files.
  Every scored object is kept in a small index (``<cases>/.ml_index/``) and a
  new one is compared with the objects of earlier cases: "92 % like X of case Y".
Nothing here changes the score."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import numpy as np

MAX_INDEX = 20000         # objects kept per model
TOP_K = 5
MIN_SIMILARITY = 0.6

def pack(leaves: np.ndarray) -> str:
    return base64.b64encode(np.asarray(leaves, dtype=np.uint16).tobytes()).decode()


def unpack(s: str) -> np.ndarray:
    return np.frombuffer(base64.b64decode(s), dtype=np.uint16)


# --- index of scored objects across cases ----------------------------------------
def _index_file(cases_dir: Path, model: str) -> Path:
    return cases_dir / ".ml_index" / f"{model}.jsonl"


def _load(cases_dir: Path, model: str) -> list[dict[str, Any]]:
    f = _index_file(cases_dir, model)
    out = []
    try:
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        pass
    return out


def similar_and_index(cases_dir: Path, case_id: str, items: list[dict[str, Any]]) -> None:
    """Adds ``similar`` to every item that has ``_leaves`` (objects of other cases
    the trees see alike) and records this case's objects in the index (replacing
    its previous entries). Pops ``_leaves``."""
    by_model: dict[str, list[dict[str, Any]]] = {}
    for it in items:
        if it.get("_leaves") and it.get("model"):
            by_model.setdefault(it["model"], []).append(it)
    for model, its in by_model.items():
        mine = {it.get("sha256") for it in its}
        everything = _load(cases_dir, model)
        entries = [e for e in everything if e.get("case") != case_id                # compared with
                   and (cases_dir / str(e.get("case"))).is_dir()]                     # (deleted cases drop out)
        kept_mine = [e for e in everything if e.get("case") == case_id and e.get("sha256") not in mine]
        mats = [unpack(e["leaves"]) for e in entries]
        ok = [i for i, m in enumerate(mats) if len(m) == len(unpack(its[0]["_leaves"]))]
        M = np.stack([mats[i] for i in ok]) if ok else None
        new = []
        for it in its:
            v = unpack(it["_leaves"])
            sims: list[dict[str, Any]] = []
            if M is not None:
                score = (M == v).mean(axis=1)
                for j in np.argsort(-score)[:TOP_K * 3]:
                    e = entries[ok[int(j)]]
                    s = float(score[j])
                    if s < MIN_SIMILARITY:
                        break
                    if any(x["case"] == e["case"] and x["sha256"] == e["sha256"] for x in sims):
                        continue
                    sims.append({"similarity": round(s, 3), "case": e["case"], "label": e.get("label", ""),
                                 "sha256": e.get("sha256", ""), "score": e.get("score"),
                                 "same_file": bool(it.get("sha256")) and e.get("sha256") == it.get("sha256")})
                    if len(sims) >= TOP_K:
                        break
            it["similar"] = sims
            new.append({"case": case_id, "sha256": it.get("sha256", ""), "label": it.get("label", ""),
                        "score": it.get("score"), "leaves": it.pop("_leaves"), "t": int(time.time())})
        keep = (entries + kept_mine + new)[-MAX_INDEX:]          # a partial run keeps the case's other objects
        f = _index_file(cases_dir, model)
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            tmp = f.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps(e) + "\n" for e in keep), encoding="utf-8")
            tmp.replace(f)
        except OSError:
            pass
    for it in items:
        it.pop("_leaves", None)
