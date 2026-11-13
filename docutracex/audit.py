"""A light audit trail: who did what, on which case (``config/audit.log``).

One JSON object per line, appended and never rewritten: time, user, client
address, the action in plain words, the case, the request (method + path) and
its HTTP status. The web middleware records every request that changes
something (uploads, analyses and modules run on demand, network checks, marks
and comments, settings, users) and every sign-in; reading pages is not
recorded. Passwords and request bodies are never written.

The file rotates at MAX_BYTES (``audit.log.1`` … ``.KEEP``).
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

from .appsettings import config_dir

MAX_BYTES = 20 * 1024 * 1024
KEEP = 5
_lock = threading.Lock()

_CASE = re.compile(r"^/api/cases/([0-9A-Za-z_-]{6,})(?:/|$)")

# (method, path pattern) → what the analyst did, in words. The first match wins.
_ACTIONS: list[tuple[str, str, str]] = [
    ("POST", r"^/api/cases/?$", "uploaded a file for analysis"),
    ("POST", r"^/api/cases/quick$", "analysed a loose file (quick)"),
    ("POST", r"^/api/cases/[^/]+/rerun$", "re-ran the analysis"),
    ("POST", r"^/api/cases/[^/]+/modules/([^/]+)", r"ran module \1"),
    ("POST", r"^/api/cases/[^/]+/netcheck", "ran a network check"),
    ("POST", r"^/api/cases/[^/]+/c2/reinterpret", "re-interpreted the C2 results"),
    ("POST", r"^/api/cases/[^/]+/code/[^/]+/[^/]+/fn/[^/]+/decompile", "decompiled a function"),
    ("POST", r"^/api/cases/[^/]+/code/[^/]+/[^/]+/decompile-all", "decompiled every function"),
    ("POST", r"^/api/cases/[^/]+/code/[^/]+/[^/]+/floss-full", "ran full FLOSS"),
    ("POST", r"^/api/cases/[^/]+/dotnet/[^/]+/decompile", "decompiled .NET code"),
    ("POST", r"^/api/cases/[^/]+/hex/extract", "extracted bytes from the hex view"),
    ("POST", r"^/api/cases/[^/]+/registry/sql$", "queried the registry (SQL)"),
    ("POST", r"^/api/cases/[^/]+/registry/export\.csv$", "exported registry rows (CSV)"),
    ("POST", r"^/api/cases/[^/]+/password", "gave a password to unlock a file"),
    ("POST", r"^/api/cases/[^/]+/wordlist", "tried a password list"),
    ("POST", r"^/api/cases/[^/]+/reveal", "opened the case folder"),
    ("PUT", r"^/api/cases/[^/]+/marks/", "marked a finding / IOC"),
    ("POST", r"^/api/cases/[^/]+/manual-findings", "added a manual finding"),
    ("DELETE", r"^/api/cases/[^/]+/manual-findings/", "deleted a manual finding"),
    ("DELETE", r"^/api/cases/[^/]+/?$", "deleted the case"),
    ("PUT", r"^/api/cases/[^/]+/comment", "commented"),
    ("POST", r"^/api/yara/", "changed YARA rules"),
    ("DELETE", r"^/api/yara/", "removed YARA rules"),
    ("PUT", r"^/api/settings/", "changed settings"),
    ("POST", r"^/api/settings/", "ran a settings action"),
    ("POST", r"^/api/diagnostics/retry", "reinstalled a component (Diagnostics)"),
    ("POST", r"^/api/tasks/[^/]+/cancel", "cancelled a task"),
    ("POST", r"^/api/ai/chat", "asked the AI"),
    ("POST", r"^/api/users/?$", "created a user"),
    ("PUT", r"^/api/users/", "changed a user"),
    ("DELETE", r"^/api/users/", "deleted a user"),
    ("POST", r"^/api/mcp/token", "regenerated the MCP token"),
    ("POST", r"^/api/auth/password", "changed their own password"),
    ("POST", r"^/api/auth/setup", "set the admin password (first start)"),
]
_COMPILED = [(m, re.compile(p), w) for m, p, w in _ACTIONS]


def _path() -> Path:
    return config_dir() / "audit.log"


def describe(method: str, path: str) -> str:
    for m, rx, words in _COMPILED:
        if m == method:
            hit = rx.search(path)
            if hit:
                return hit.expand(words) if "\\" in words else words
    return f"{method} {path}"


def case_of(path: str) -> str:
    m = _CASE.match(path)
    return m.group(1) if m and m.group(1) not in ("quick", "upload") else ""


def record(user: str, action: str, *, case: str = "", addr: str = "", request: str = "",
           status: int | None = None, detail: str = "") -> None:
    entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "user": user or "-", "action": action,
             "case": case, "addr": addr, "request": request}
    if status is not None:
        entry["status"] = status
    if detail:
        entry["detail"] = detail[:300]
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with _lock:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            if p.stat().st_size > MAX_BYTES:
                _rotate(p)
        except OSError:
            pass
        with p.open("a", encoding="utf-8") as fh:
            fh.write(line)


def _rotate(p: Path) -> None:
    """audit.log → .1 → .2 … → .KEEP (the oldest is dropped)."""
    for i in range(KEEP - 1, 0, -1):
        src = p.with_name(f"{p.name}.{i}")
        if src.exists():
            src.replace(p.with_name(f"{p.name}.{i + 1}"))
    p.replace(p.with_name(f"{p.name}.1"))


def read(*, user: str = "", action: str = "", case: str = "", limit: int = 500) -> list[dict[str, Any]]:
    """Newest first, filtered (substring, case-insensitive) — the current file only."""
    try:
        lines = _path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for ln in reversed(lines):
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if user and user.lower() not in str(e.get("user", "")).lower():
            continue
        if action and action.lower() not in str(e.get("action", "")).lower():
            continue
        if case and case.lower() not in str(e.get("case", "")).lower():
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out
