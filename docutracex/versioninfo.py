"""Is there a newer DocuTraceX, what changed, and the one-click update.

* **Newer version.** ``VERSION`` on GitHub's ``main`` is compared with this one, the
  same way ``update.py`` does it (and with its token for a private repo). It is
  checked in the background, at most every few hours; offline or rate-limited
  simply means "unknown".
* **What changed.** ``CHANGELOG.md`` ships with the code: after an update the app
  shows the entries between the version this installation last showed and the
  running one (remembered in ``config/``). The changes of a version not installed
  yet are read from the remote ``CHANGELOG.md``.
* **Update.** A detached ``run.py --update --wait-port`` is started; this process
  exits; the new one waits for the port, updates without asking, re-provisions
  and serves again.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .config import APP_ROOT

CHECK_EVERY_S = 6 * 3600
_LOCK = threading.Lock()
_STATE: dict[str, Any] = {"latest": None, "checked": 0.0, "error": "", "remote_changelog": "", "running": False}
_HEAD = re.compile(r"(?m)^##\s+v?(\d+(?:\.\d+){1,3})\b[^\n]*$")


def _config_dir() -> Path:
    from .appsettings import config_dir
    return config_dir()


def _state_file() -> Path:
    return _config_dir() / "version_state.json"


def _read_state() -> dict[str, Any]:
    try:
        data = json.loads(_state_file().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(**kw: Any) -> None:
    data = {**_read_state(), **kw}
    p = _state_file()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(p)
    except OSError:
        pass


def vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) if x.isdigit() else 0 for x in (v or "0").strip().lstrip("vV").replace("-", ".").split("."))


def newer(a: str, b: str) -> bool:
    """``a`` is a later version than ``b``."""
    return vtuple(a) > vtuple(b)


# --------------------------------------------------------------------------- changelog

def parse_changelog(text: str) -> list[dict[str, str]]:
    """[{version, title, body}] from a CHANGELOG.md (newest first, as written)."""
    out = []
    heads = list(_HEAD.finditer(text or ""))
    for k, m in enumerate(heads):
        end = heads[k + 1].start() if k + 1 < len(heads) else len(text)
        out.append({"version": m.group(1), "title": m.group(0).lstrip("# ").strip(),
                    "body": text[m.end():end].strip()})
    return out


def between(entries: list[dict[str, str]], after: str, upto: str) -> list[dict[str, str]]:
    """Entries with ``after`` < version ≤ ``upto``, newest first."""
    return [e for e in entries if newer(e["version"], after) and not newer(e["version"], upto)]


def local_changelog() -> list[dict[str, str]]:
    try:
        return parse_changelog((APP_ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    except OSError:
        return []


def whats_new() -> dict[str, Any]:
    """What changed since the version this installation last showed. The first time
    ever there is nothing to show (no flood of history): the running version is
    remembered."""
    seen = _read_state().get("seen")
    if not seen:
        _write_state(seen=__version__)
        return {"since": __version__, "current": __version__, "entries": []}
    if not newer(__version__, seen):
        return {"since": seen, "current": __version__, "entries": []}
    return {"since": seen, "current": __version__, "entries": between(local_changelog(), seen, __version__)}


def mark_seen() -> None:
    _write_state(seen=__version__)


# --------------------------------------------------------------------------- newer version

def _updater() -> Any:
    """``update.py`` (repo root) as a module: its remote check and token handling."""
    spec = importlib.util.spec_from_file_location("_dtx_update", APP_ROOT / "update.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("update.py not found")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_enabled() -> bool:
    if os.environ.get("DOCUTRACEX_NO_UPDATE_CHECK") == "1":
        return False
    return _read_state().get("check", True) is not False


def set_check(enabled: bool) -> None:
    _write_state(check=bool(enabled))


def _refresh() -> None:
    try:
        up = _updater()
        latest = up.remote_version()
        if not re.fullmatch(r"\d+(?:\.\d+){1,3}", latest or ""):
            raise ValueError(f"unexpected VERSION on GitHub: {latest[:40]!r}")
        log = ""
        if newer(latest, __version__):
            try:
                url = f"https://raw.githubusercontent.com/{up.OWNER}/{up.REPO}/{up.BRANCH}/CHANGELOG.md"
                log = up._get(url, timeout=30).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                log = ""
        with _LOCK:
            _STATE.update(latest=latest, error="", remote_changelog=log)
    except Exception as exc:  # noqa: BLE001  (offline, rate limit, proxy: just unknown)
        with _LOCK:
            _STATE["error"] = str(exc)[:200]
    finally:
        with _LOCK:
            _STATE["checked"] = time.time()
            _STATE["running"] = False


def status(force: bool = False) -> dict[str, Any]:
    """Current / latest version; starts a background check when the last one is stale.
    ``force`` (the "Check now" button) checks at once, even with the automatic check off."""
    enabled = check_enabled()
    with _LOCK:
        stale = force or time.time() - _STATE["checked"] > CHECK_EVERY_S
        if (force or enabled and stale) and not _STATE["running"]:
            _STATE["running"] = True
            threading.Thread(target=_refresh, name="version-check", daemon=True).start()
        latest = _STATE["latest"]
        out = {"current": __version__, "latest": latest, "check_enabled": enabled,
               "checking": _STATE["running"], "error": _STATE["error"],
               "checked_utc": datetime.fromtimestamp(_STATE["checked"], UTC).isoformat()
               if _STATE["checked"] else None}
    # a version fetched by "Check now" counts even with the automatic check off
    out["update_available"] = bool(latest and newer(latest, __version__))
    return out


def upcoming() -> list[dict[str, str]]:
    """The changes of the newer version(s) on GitHub, from its CHANGELOG.md."""
    with _LOCK:
        latest, text = _STATE["latest"], _STATE["remote_changelog"]
    if not latest or not text:
        return []
    return between(parse_changelog(text), __version__, latest)


# --------------------------------------------------------------------------- update now

def start_update(host: str, port: int) -> dict[str, Any]:
    """Start ``run.py --update`` detached (it waits until this process has freed the
    port, updates without asking, re-provisions and serves again); the caller then
    stops this process. The new process logs to ``config/update.log``."""
    run_py = APP_ROOT / "run.py"
    if not run_py.is_file():
        raise RuntimeError("run.py not found next to the app")
    log_path = _config_dir() / "update.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(run_py), "--update", "--wait-port", f"{host}:{port}",
           "--host", host, "--port", str(port)]
    kw: dict[str, Any] = {"cwd": str(APP_ROOT), "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        # its own console window: the update's progress stays visible, as when run by hand
        kw["creationflags"] = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10)
        subprocess.Popen(cmd, **kw)
    else:
        logf = log_path.open("ab")
        kw.update(stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
        subprocess.Popen(cmd, **kw)
    _write_state(update_started=datetime.now(UTC).isoformat(), update_from=__version__)
    return {"started": True, "log": str(log_path), "command": " ".join(cmd[1:])}


def stop_soon(delay: float = 1.5) -> None:
    """Stop this process shortly (after the HTTP answer has gone out)."""
    def _bye() -> None:
        time.sleep(delay)
        os._exit(0)
    threading.Thread(target=_bye, name="update-exit", daemon=True).start()
