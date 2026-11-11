"""LOLRMM (magicsword-io, Apache-2.0): the community catalogue of RMM and
remote-access tools — names, PE metadata, installation paths, network domains
and code-signing certificates — used by the C2 "rmm" extractor so its product
list stays current without a release.

``rmm_tools.json`` is downloaded on install into ``tools/lolrmm/`` and refreshed
in the background when older than 7 days (Settings → C2 view: *Refresh now*).
Only the catalogue is downloaded; nothing about a sample is ever sent. Without
the file the extractor uses its built-in list, so it never breaks offline.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from .config import settings
from .logging_config import get_logger

log = get_logger(__name__)

URLS = ("https://lolrmm.io/api/rmm_tools.json",
        "https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/website/public/api/rmm_tools.json")
SITE = "https://lolrmm.io"
FILENAME = "rmm_tools.json"
MAX_AGE = 7 * 86400
MIN_TOOLS = 50

# Names too generic to identify a product on their own (installers, updaters,
# OS components) and signers shared by many unrelated programs.
_GENERIC_FILES = {
    "setup.exe", "install.exe", "installer.exe", "uninstall.exe", "unins000.exe", "update.exe", "updater.exe",
    "agent.exe", "client.exe", "server.exe", "service.exe", "launcher.exe", "helper.exe", "host.exe", "viewer.exe",
    "remote.exe", "support.exe", "msiexec.exe", "rundll32.exe", "cmd.exe", "powershell.exe", "svchost.exe",
    "explorer.exe", "java.exe", "javaw.exe", "python.exe", "node.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "vnc.exe", "winvnc.exe", "tray.exe", "app.exe", "main.exe", "run.exe", "start.exe", "config.exe",
}
_GENERIC_SIGNERS = {"microsoft corporation", "microsoft windows", "google llc", "google inc", "apple inc.",
                    "oracle america, inc.", "mozilla corporation"}
_GENERIC_DOMAINS = {
    "amazonaws.com", "cloudfront.net", "azureedge.net", "azurewebsites.net", "windows.net", "microsoft.com",
    "google.com", "googleapis.com", "gstatic.com", "github.com", "githubusercontent.com", "cloudflare.com",
    "akamaihd.net", "akamaized.net", "fastly.net", "digicert.com", "sectigo.com", "letsencrypt.org",
    "apple.com", "icloud.com", "live.com", "office.com", "office365.com", "skype.com", "teams.microsoft.com",
}

_lock = threading.Lock()
_cache: dict[str, Any] = {"mtime": None, "products": None, "count": 0}


def path() -> Path:
    return settings.tools_dir / "lolrmm" / FILENAME


def _base(p: str) -> str:
    b = re.split(r"[\\/]", str(p).strip().strip("'\""))[-1].lower()
    return "" if any(c in b for c in "*?<>%") else b


def _domain(d: str) -> str:
    d = str(d).strip().lower().strip(".")
    if d.startswith("*."):
        d = d[2:]
    if not d or "*" in d or "/" in d or " " in d or "." not in d:
        return ""
    if d in _GENERIC_DOMAINS or any(d.endswith("." + g) for g in _GENERIC_DOMAINS):
        return ""
    return d


def parse(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """name → {category, website, files, descriptions, domains, signers}: the needles per product."""
    out: dict[str, dict[str, Any]] = {}
    signer_count: dict[str, int] = {}
    for t in tools:
        for c in ((t.get("CodeSigning") or {}).get("certificates") or []):
            s = str(c.get("signer_name") or "").strip().lower()
            if s:
                signer_count[s] = signer_count.get(s, 0) + 1
    for t in tools:
        name = str(t.get("Name") or "").strip()
        if not name:
            continue
        det = t.get("Details") or {}
        pe = det.get("PEMetadata") or []
        pe = [pe] if isinstance(pe, dict) else pe
        files, descs = set(), set()
        for m in pe:
            if not isinstance(m, dict):
                continue
            for k in ("Filename", "OriginalFileName"):
                b = _base(m.get(k) or "")
                if len(b) >= 8 and b not in _GENERIC_FILES:
                    files.add(b)
            d = str(m.get("Description") or "").strip().lower()
            if len(d) >= 10:
                descs.add(d)
        for p in det.get("InstallationPaths") or []:
            b = _base(p)
            if len(b) >= 8 and b not in _GENERIC_FILES and b.endswith((".exe", ".dll", ".msi", ".sys", ".jar")):
                files.add(b)
        doms = set()
        for n in ((t.get("Artifacts") or {}).get("Network") or []):
            for d in (n.get("Domains") or []) if isinstance(n, dict) else []:
                d = _domain(d)
                if d:
                    doms.add(d)
        signers = {s for c in ((t.get("CodeSigning") or {}).get("certificates") or [])
                   for s in [str(c.get("signer_name") or "").strip()]
                   if s and s.lower() not in _GENERIC_SIGNERS and signer_count.get(s.lower(), 0) <= 2}
        if not (files or descs or doms or signers):
            continue
        out[name] = {"category": t.get("Category") or "", "website": det.get("Website") or "",
                     "files": sorted(files), "descriptions": sorted(descs), "domains": sorted(doms),
                     "signers": sorted(signers)}
    return out


def products() -> dict[str, dict[str, Any]] | None:
    """The parsed catalogue, or None without a usable file (the built-in list is used)."""
    p = path()
    try:
        mtime = (str(p), p.stat().st_mtime)
    except OSError:
        return None
    with _lock:
        if _cache["mtime"] != mtime:
            try:
                tools = json.loads(p.read_text(encoding="utf-8"))
                prods = parse(tools) if isinstance(tools, list) and len(tools) >= MIN_TOOLS else None
            except (OSError, ValueError) as exc:
                log.warning("LOLRMM catalogue unreadable: %s", exc)
                prods = None
                tools = []
            _cache.update(mtime=mtime, products=prods, count=len(tools) if prods else 0)
        return _cache["products"]


def status() -> dict[str, Any]:
    prods = products()
    p = path()
    return {"source": "lolrmm" if prods is not None else "builtin", "tools": _cache["count"] if prods else 0,
            "usable": len(prods) if prods else 0,
            "updated": time.strftime("%Y-%m-%d", time.localtime(p.stat().st_mtime)) if prods is not None else None,
            "url": SITE}


def download(proxy: str | None = None, timeout: int = 60) -> dict[str, Any]:
    """Fetch the catalogue (lolrmm.io, then its GitHub copy) and store it. Raises on
    failure; the old copy is kept."""
    from .mailintel import _routes, _short
    body, errors = None, []
    for url in URLS:
        for label, opener in _routes(proxy):
            req = urllib.request.Request(url, headers={"User-Agent": "DocuTraceX"})
            try:
                with opener.open(req, timeout=timeout) as r:
                    body = r.read(64 * 1024 * 1024)
                tools = json.loads(body)
                if not isinstance(tools, list) or len(tools) < MIN_TOOLS:
                    raise ValueError(f"{len(tools) if isinstance(tools, list) else 0} tools: looks incomplete")
                break
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url.split('/')[2]} {label}: {_short(exc)}")
                body = None
        if body is not None:
            break
    if body is None:
        raise ConnectionError("; ".join(errors))
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_bytes(body)
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
            log.info("LOLRMM catalogue updated")
        except Exception as exc:  # noqa: BLE001  (offline: the previous copy or the built-in list)
            log.warning("LOLRMM catalogue not updated: %s", exc)
    threading.Thread(target=run, name="lolrmm-refresh", daemon=True).start()
