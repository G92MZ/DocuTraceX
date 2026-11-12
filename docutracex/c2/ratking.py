"""rat-king-parser (jeFF0Falltrades, MIT) as the second engine of the .NET RAT
extractor (AsyncRAT, DcRAT, VenomRAT, QuasarRAT, XWorm, Xeno RAT and clones),
next to the own decoder — the same way dissect.cobaltstrike sits next to 1768.py.

It runs in a child process (``_ratking_worker.py``) with a timeout and is
optional: without it the own decoder works alone (the run is marked degraded).
``DOCUTRACEX_RATKING=0`` disables it. Static only.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

TOOL = "rat-king-parser"
TIMEOUT = 60
_WORKER = Path(__file__).with_name("_ratking_worker.py")
_HOSTPORT = re.compile(r"^[A-Za-z0-9.\-\[\]:]+$")


def enabled() -> bool:
    return os.environ.get("DOCUTRACEX_RATKING", "1") != "0"


def _run(path: Path) -> dict[str, Any]:
    try:
        r = subprocess.run([sys.executable, str(_WORKER), str(path)], capture_output=True, text=True,
                           errors="replace", timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": f"rat-king-parser took longer than {TIMEOUT} s"}
    except OSError as exc:
        return {"status": "error", "error": str(exc)[:300]}
    line = (r.stdout or "").strip().splitlines()[-1:] or [""]
    try:
        return json.loads(line[0])
    except ValueError:
        return {"status": "error", "error": (r.stderr or r.stdout or "no output")[-300:]}


def _split(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


def view(raw: dict[str, Any]) -> dict[str, Any]:
    """Worker JSON → a view: status, method, summary, fields, hosts."""
    st = raw.get("status", "error")
    rep = raw.get("report") or {}
    if st == "found" and str(rep.get("key") or "None") == "None":
        # it located the settings but did not decrypt them: what it shows is ciphertext
        st, raw = "nothing", {**raw, "error": "found the settings class but could not decrypt it"}
        rep = {**rep, "config": raw["error"]}
    v: dict[str, Any] = {"tool": TOOL, "status": st, "lib_version": raw.get("lib") or ""}
    if st != "found":
        cfg = rep.get("config")
        v["note"] = {"not_installed": "rat-king-parser is not installed in the portable Python "
                                      "(pip install rat-king-parser, or re-run setup).",
                     "disabled": "Disabled (DOCUTRACEX_RATKING=0).",
                     }.get(st, (cfg if isinstance(cfg, str) else "") or raw.get("error") or "No configuration found.")
        v["note"] = str(v["note"]).replace(str(rep.get("file_path") or "\0"), "the file")[:400]
        return v
    cfg = rep.get("config") or {}
    hosts = _split(cfg.get("Hosts"))
    ports = _split(cfg.get("Ports"))
    c2 = [h if ":" in h or not ports else f"{h}:{p}" for h in hosts for p in (ports if ":" not in h else [""])][:50]
    c2 = [x.rstrip(":") for x in c2]
    summary = {"Family (YARA)": rep.get("yara_possible_family") or "",
               "C2": c2, "Version": cfg.get("Version") or "", "Mutex": cfg.get("Mutex") or "",
               "Group": cfg.get("Group") or ""}
    v.update({"method": f"{TOOL} {raw.get('lib') or ''}".strip()
                        + (f" (key {str(rep.get('key'))[:40]})" if rep.get("key") else ""),
              "summary": {k: x for k, x in summary.items() if x not in ("", [], None)},
              "fields": {str(k): (", ".join(map(str, x)) if isinstance(x, list) else str(x))[:500]
                         for k, x in cfg.items()},
              "hosts": [h for h in hosts if _HOSTPORT.match(h)], "family": rep.get("yara_possible_family") or ""})
    return v


def extract(path: Path) -> dict[str, Any]:
    if not enabled():
        return view({"status": "disabled"})
    return view(_run(path))


def _norm(hosts: list[str]) -> set[str]:
    return {h.lower().split(":", 1)[0].strip("[]") for h in hosts}


def combine(own: dict[str, Any] | None, rk: dict[str, Any]) -> dict[str, Any] | None:
    """Own decoder + rat-king-parser → one configuration with a sub-tab per engine."""
    if own is not None and own.get("kind") == "indicators":
        if rk.get("status") == "found":                # traces only on our side: rat-king's configuration wins
            own = None
        else:
            return {**own, "tools": {"own": {"tool": "own decoder", "status": "indicators", "note": own.get("note")},
                                     "ratking": rk}}
    if own is None and rk.get("status") != "found":
        return None
    own_view = ({"tool": "own decoder", "status": "found", "method": own.get("method"), "summary": own.get("summary"),
                 "fields": own.get("fields"), "hosts": own.get("c2") or []} if own else
                {"tool": "own decoder", "status": "nothing", "note": "No AES-encrypted settings it could decrypt."})
    tools = {"own": own_view, "ratking": rk}
    if own is None:                                   # only rat-king-parser read it
        fam = rk.get("family") if rk.get("family") not in ("", "No match", None) else "AsyncRAT / Quasar family"
        return {"family": fam, "kind": "RAT", "method": rk["method"], "confidence": "high",
                "summary": rk.get("summary") or {}, "c2": rk.get("hosts") or [], "fields": rk.get("fields") or {},
                "agreement": f"only {TOOL}", "tools": tools}
    out = dict(own)
    out["tools"] = tools
    if rk.get("status") != "found":
        out["agreement"] = "only own decoder"
        return out
    a, b = _norm(own.get("c2") or []), _norm(rk.get("hosts") or [])
    out["agreement"] = "agree" if a == b else ("partial" if a & b else "differ")
    out["method"] = f"{own.get('method')} + {rk['method']}"
    if out["agreement"] == "differ":
        out["confidence"] = "medium"
        out["note"] = "The own decoder and rat-king-parser report different C2 hosts: compare both sub-tabs."
        out["summary"] = {**(own.get("summary") or {}), "C2 (other tool)": (rk.get("summary") or {}).get("C2", [])}
    out["c2"] = list(dict.fromkeys((own.get("c2") or []) + (rk.get("hosts") or [])))
    return out
