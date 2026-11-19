"""HijackLibs (Wietze Beukema, GPL-3.0): the community catalogue of DLLs abused
for side-loading and search-order hijacking — each DLL's name, vendor, the
folders it is expected in and the legitimate programs known to load it from
their own folder. Used by ``sideload`` so the list of names stays current
without a release.

The catalogue is **downloaded, never shipped** (its licence is GPL-3.0, this
project's Apache-2.0): ``hijacklibs.json`` from hijacklibs.net (or, failing
that, the repository's YAML files from GitHub when PyYAML is available) into
``tools/hijacklibs/``, refreshed in the background when older than 7 days
(Settings: *Refresh now*). Only the catalogue is downloaded; nothing about a
sample is ever sent. Without it ``sideload`` uses its built-in list.
"""

from __future__ import annotations

import io
import json
import re
import threading
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from .config import settings
from .logging_config import get_logger

log = get_logger(__name__)

JSON_URL = "https://hijacklibs.net/api/hijacklibs.json"
ZIP_URL = "https://codeload.github.com/wietze/HijackLibs/zip/refs/heads/main"
SITE = "https://hijacklibs.net"
FILENAME = "hijacklibs.json"
MAX_AGE = 7 * 86400
MIN_ENTRIES = 200
_KEYS = ("Name", "Vendor", "ExpectedLocations", "VulnerableExecutables", "Resources", "url")

_lock = threading.Lock()
_cache: dict[str, Any] = {"mtime": None, "dlls": None, "count": 0}


def path() -> Path:
    return settings.tools_dir / "hijacklibs" / FILENAME


def _base(p: str) -> str:
    return re.split(r"[\\/]", str(p or "").strip().strip("'\""))[-1].lower()


def parse(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """dll name (lower case) → {name, vendor, locations, system, hosts: {exe → {path, type,
    condition}}, url}."""
    out: dict[str, dict[str, Any]] = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        name = _base(e.get("Name") or "")
        if not name.endswith((".dll", ".ocx", ".cpl", ".drv")):
            continue
        locs = [str(x) for x in e.get("ExpectedLocations") or [] if x]
        rec = out.setdefault(name, {"name": e.get("Name"), "vendor": e.get("Vendor") or "", "locations": [],
                                    "system": False, "hosts": {}, "url": e.get("url") or ""})
        rec["locations"] = sorted(set(rec["locations"]) | set(locs))
        rec["system"] = rec["system"] or any(re.match(r"(?i)%(?:system32|syswow64|windir)%", x) for x in locs)
        for v in e.get("VulnerableExecutables") or []:
            if not isinstance(v, dict) or not v.get("Path"):
                continue
            exe = _base(v["Path"])
            if exe.endswith(".exe") and "%" not in exe:
                rec["hosts"].setdefault(exe, {"path": str(v["Path"]), "type": str(v.get("Type") or ""),
                                              "condition": str(v.get("Condition") or "")[:200]})
    return out


def dlls() -> dict[str, dict[str, Any]] | None:
    """The parsed catalogue, or None without a usable file (the built-in list is used)."""
    p = path()
    try:
        mtime = (str(p), p.stat().st_mtime)
    except OSError:
        return None
    with _lock:
        if _cache["mtime"] != mtime:
            try:
                entries = json.loads(p.read_text(encoding="utf-8"))
                parsed = parse(entries) if isinstance(entries, list) and len(entries) >= MIN_ENTRIES else None
            except (OSError, ValueError) as exc:
                log.warning("HijackLibs catalogue unreadable: %s", exc)
                parsed, entries = None, []
            _cache.update(mtime=mtime, dlls=parsed, count=len(entries) if parsed else 0)
        return _cache["dlls"]


def status() -> dict[str, Any]:
    d = dlls()
    p = path()
    return {"source": "hijacklibs" if d is not None else "builtin", "entries": _cache["count"] if d else 0,
            "dlls": len(d) if d else 0,
            "system": sum(1 for r in d.values() if r["system"]) if d else 0,
            "updated": time.strftime("%Y-%m-%d", time.localtime(p.stat().st_mtime)) if d is not None else None,
            "url": SITE}


def _from_repo_zip(body: bytes) -> list[dict[str, Any]]:
    """The repository's ``yml/**.yml`` as the same records the JSON has (needs PyYAML)."""
    import yaml  # optional: only for this fallback
    out = []
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        for n in z.namelist():
            if "/yml/" in n and n.endswith(".yml"):
                try:
                    d = yaml.safe_load(z.read(n))
                except yaml.YAMLError:
                    continue
                if isinstance(d, dict):
                    rel = n.split("/yml/", 1)[1][:-4]
                    out.append({k: d.get(k) for k in _KEYS[:-1]} | {"url": f"{SITE}/entries/{rel}.html"})
    return out


def download(proxy: str | None = None, timeout: int = 60) -> dict[str, Any]:
    """Fetch the catalogue (hijacklibs.net JSON, then the GitHub repository) and store it
    as JSON. Raises on failure; the old copy is kept."""
    from .mailintel import _routes, _short
    entries, errors = None, []
    for url in (JSON_URL, ZIP_URL):
        for label, opener in _routes(proxy):
            req = urllib.request.Request(url, headers={"User-Agent": "DocuTraceX"})
            try:
                with opener.open(req, timeout=timeout) as r:
                    body = r.read(64 * 1024 * 1024)
                got = json.loads(body) if url == JSON_URL else _from_repo_zip(body)
                if not isinstance(got, list) or len(got) < MIN_ENTRIES:
                    raise ValueError(f"{len(got) if isinstance(got, list) else 0} entries: looks incomplete")
                entries = [{k: e.get(k) for k in _KEYS} for e in got if isinstance(e, dict)]
                break
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url.split('/')[2]} {label}: {_short(exc)}")
        if entries is not None:
            break
    if entries is None:
        raise ConnectionError("; ".join(errors))
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries), encoding="utf-8")
    tmp.replace(p)
    return status()


def stale() -> bool:
    try:
        return time.time() - path().stat().st_mtime > MAX_AGE
    except OSError:
        return True


def refresh_in_background(proxy: str | None = None) -> None:
    if not stale():
        return

    def run() -> None:
        try:
            download(proxy)
            log.info("HijackLibs catalogue updated")
        except Exception as exc:  # noqa: BLE001  (offline: the previous copy or the built-in list)
            log.warning("HijackLibs catalogue not updated: %s", exc)
    threading.Thread(target=run, name="hijacklibs-refresh", daemon=True).start()
