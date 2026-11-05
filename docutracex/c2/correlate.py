"""Configurations of other cases that share an operator fingerprint.

Every configuration found is kept in a small index (``<cases>/.c2_index.jsonl``)
with the values that tie implants to one operator or one server:

* **RSA public key** (Cobalt Strike): generated per team server — the same key
  in two cases is the same team server (strong);
* **watermark / licence id**: per licence — the same licence, but cracked /
  leaked builds share theirs (medium);
* **C2 host**: the same server (strong for an IP / domain, nothing when it is a
  big shared service).

A new run compares its configurations with the other cases' and adds
``related`` = [{case, object, family, match, strength}]. Nothing here changes
a configuration's content."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

MAX_INDEX = 50000
MAX_RELATED = 10
# watermark 0 = trial / "no licence": shared by everyone, not a fingerprint
_NO_WATERMARK = {"", "0", "None"}


def _index(cases_dir: Path) -> Path:
    return cases_dir / ".c2_index.jsonl"


def fingerprints(cfg: dict[str, Any]) -> dict[str, Any]:
    s = cfg.get("summary") or {}
    pub = str(s.get("Public key SHA-256") or "")
    wm = str(s.get("Watermark") or "").split(" ", 1)[0]
    hosts = sorted({str(h).split(":", 1)[0].lower() for h in cfg.get("c2") or [] if h})
    return {"pubkey": pub, "watermark": "" if wm in _NO_WATERMARK else wm, "hosts": hosts}


def _load(cases_dir: Path) -> list[dict[str, Any]]:
    out = []
    try:
        for line in _index(cases_dir).read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        pass
    return out


def relate_and_index(cases_dir: Path, case_id: str, configs: list[dict[str, Any]], partial: bool = False) -> None:
    """Adds ``related`` to each configuration and records this case's
    configurations (replacing its previous entries, unless ``partial``)."""
    everything = _load(cases_dir)
    others = [e for e in everything if e.get("case") != case_id and (cases_dir / str(e.get("case"))).is_dir()]
    mine_old = [e for e in everything if e.get("case") == case_id] if partial else []
    new = []
    for cfg in configs:
        if cfg.get("kind") == "indicators":
            continue
        fp = fingerprints(cfg)
        rel: list[dict[str, Any]] = []
        for e in others:
            match, strength = "", ""
            if fp["pubkey"] and e.get("pubkey") == fp["pubkey"]:
                match, strength = "same RSA public key (same team server)", "strong"
            elif fp["hosts"] and set(fp["hosts"]) & set(e.get("hosts") or []):
                match, strength = f"same C2 host ({', '.join(sorted(set(fp['hosts']) & set(e['hosts'])))[:120]})", "strong"
            elif fp["watermark"] and e.get("watermark") == fp["watermark"] and e.get("family") == cfg.get("family"):
                match, strength = (f"same watermark {fp['watermark']} (same licence — cracked / leaked builds "
                                   "share theirs)"), "medium"
            if match and not any(r["case"] == e["case"] and r["object"] == e.get("object") for r in rel):
                rel.append({"case": e["case"], "object": e.get("object", ""), "family": e.get("family", ""),
                            "match": match, "strength": strength})
        rel.sort(key=lambda r: r["strength"] != "strong")
        cfg["related"] = rel[:MAX_RELATED]
        new.append({"case": case_id, "object": cfg.get("object", ""), "family": cfg.get("family", ""),
                    "t": int(time.time()), **fp})
    keep = (others + mine_old + new)[-MAX_INDEX:]
    try:
        f = _index(cases_dir)
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_suffix(".tmp")
        tmp.write_text("".join(json.dumps(e) + "\n" for e in keep), encoding="utf-8")
        tmp.replace(f)
    except OSError:
        pass
