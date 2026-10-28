"""Download the optional EMBER2024 family model (459 MB) from the UI.

Runs in a background thread of the web service (plain urllib, no LightGBM
needed): streams to ``tools/ember/EMBER2024_family.model.part``, checks the
pinned SHA-256 while downloading and only then moves it into place. Uses the
app proxy when one is configured (like the IANA TLD refresh)."""

from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

URL = "https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/main/EMBER2024_family.model"
_lock = threading.Lock()
_state: dict[str, Any] = {"state": "idle"}


def _meta() -> dict[str, Any]:
    f = Path(__file__).with_name("ember_thresholds.json")
    try:
        return (json.loads(f.read_text(encoding="utf-8")).get("extra_models") or {}).get("family") or {}
    except (OSError, ValueError):
        return {}


def target() -> Path:
    from ..config import settings
    return settings.tools_dir / "ember" / "EMBER2024_family.model"


def status() -> dict[str, Any]:
    with _lock:
        st = dict(_state)
    st["installed"] = target().is_file()
    st["size"] = _meta().get("size")
    return st


def start(proxy: str | None = None) -> dict[str, Any]:
    with _lock:
        if _state.get("state") == "downloading":
            return dict(_state)
        if target().is_file():
            return {"state": "done", "installed": True}
        _state.clear()
        _state.update(state="downloading", done=0, total=_meta().get("size") or 0, started=time.time())
    threading.Thread(target=_run, args=(proxy,), daemon=True).start()
    return status()


def _run(proxy: str | None) -> None:
    meta = _meta()
    dest = target()
    part = dest.with_suffix(".model.part")
    try:
        if not meta.get("sha256"):
            raise RuntimeError("pinned SHA-256 missing (docutracex/ml/ember_thresholds.json)")
        handlers = []
        if proxy and proxy.startswith(("http://", "https://")):
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(URL, headers={"User-Agent": "DocuTraceX"})
        dest.parent.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256()
        with opener.open(req, timeout=120) as r, part.open("wb") as out:
            total = int(r.headers.get("Content-Length") or meta.get("size") or 0)
            with _lock:
                _state["total"] = total
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                h.update(chunk)
                with _lock:
                    _state["done"] = _state.get("done", 0) + len(chunk)
        if h.hexdigest() != meta["sha256"]:
            raise RuntimeError("SHA-256 mismatch — file discarded")
        part.replace(dest)
        with _lock:
            _state.update(state="done", finished=time.time())
    except Exception as exc:  # noqa: BLE001
        part.unlink(missing_ok=True)
        with _lock:
            _state.update(state="error", error=str(exc)[:300])
