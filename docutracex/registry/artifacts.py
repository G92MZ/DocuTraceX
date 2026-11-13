"""Forensic artifacts decoded from hives by regipy's plugins (MIT): UserAssist (ROT13
names, run counts, last run), ShimCache / AppCompatCache, Amcache, BAM / DAM, ShellBags,
USB / USBSTOR, mounted devices, network lists, typed paths and URLs, WordWheelQuery,
terminal services history, SAM accounts, services… — whatever the installed regipy
offers for the hive type, so new plugins arrive with a regipy update.

Each entry becomes an ``artifacts`` row: the plugin, a timestamp when the entry has one
(for the timeline), the key, a one-line summary and the whole entry as JSON.
Only plugins regipy marks as validated run.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

MAX_PER_PLUGIN = 20000
_TS_FIELDS = ("last_run", "last_executed", "last_execution", "timestamp", "last_write", "last_modified",
              "last_connected", "last_login", "last_logon", "first_installed", "install_date", "date",
              "last_written_timestamp", "last_mod_date", "created", "first_connected")
_KEY_FIELDS = ("key_path", "path", "key")
_SKIP_SUMMARY = {"key_path", "path", "key", "raw", "data", "value_data", "slack"}


def _ts(v: Any) -> str | None:
    if isinstance(v, _dt.datetime):
        return v.replace(tzinfo=None).isoformat(sep=" ")
    if isinstance(v, str) and len(v) >= 10 and v[:4].isdigit() and v[4] == "-":
        try:
            d = _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
            if d.year < 1971:
                return None
            return d.replace(tzinfo=None).isoformat(sep=" ")
        except ValueError:
            return None
    return None


def _flatten(obj: Any, ctx: dict[str, Any], depth: int = 0) -> list[dict[str, Any]]:
    """Plugin output (lists, {path: {…, values: [...]}}, {last_write, entries: [...]}) → flat entries."""
    if depth > 4:
        return [{**ctx, "value": obj}]
    if isinstance(obj, list):
        out: list[dict[str, Any]] = []
        for it in obj:
            out += _flatten(it, ctx, depth + 1) if isinstance(it, (dict, list)) else [{**ctx, "value": it}]
        return out
    if not isinstance(obj, dict):
        return [{**ctx, "value": obj}]
    scalars = {k: v for k, v in obj.items() if not isinstance(v, (dict, list))}
    lists = {k: v for k, v in obj.items() if isinstance(v, list)}
    dicts = {k: v for k, v in obj.items() if isinstance(v, dict)}
    if dicts and not scalars and not lists:            # keyed by key path / name
        out = []
        for k, v in dicts.items():
            label = "key_path" if str(k).startswith("\\") else "group"
            out += _flatten(v, {**ctx, label: k}, depth + 1)
        return out
    base = {**ctx, **scalars, **dicts}
    if lists:
        out = []
        for k, v in lists.items():
            head = {"group": k} if len(lists) > 1 else {}
            out += _flatten(v, {**base, **head}, depth + 1) if v else [{**base, **head}]
        return out
    return [base]


def _rows(plugin: str, entries: Any) -> list[tuple[Any, ...]]:
    """(plugin, ts, key, summary, json) for each entry, whatever shape the plugin returns."""
    if isinstance(entries, dict) and set(entries) == {"error"}:
        return []
    items, seen = [], set()
    for e in _flatten(entries, {}):
        j = json.dumps(e, default=str, sort_keys=True)
        if j not in seen:                               # (regipy lists some UserAssist GUIDs twice)
            seen.add(j)
            items.append(e)
    out = []
    for e in items[:MAX_PER_PLUGIN]:
        ts = next((t for f in _TS_FIELDS if (t := _ts(e.get(f)))), None)
        key = next((str(e[f]) for f in _KEY_FIELDS if isinstance(e.get(f), str)), "")
        summary = " · ".join(f"{k}={str(v)[:80]}" for k, v in e.items()
                             if k not in _SKIP_SUMMARY and v not in (None, "", [], {}) and not isinstance(v, (dict, list)))
        out.append((plugin, ts, key, summary[:500], json.dumps(e, default=str, ensure_ascii=False)[:200000]))
    return out


def run(hive_path: Path, hive_type: str | None) -> tuple[list[tuple[Any, ...]], list[str]]:
    """(rows, plugins that ran) for one hive."""
    try:
        from regipy.hive_types import SUPPORTED_HIVE_TYPES
        from regipy.plugins.utils import run_relevant_plugins
        from regipy.registry import RegistryHive
    except ImportError:
        return [], []
    if not hive_type or hive_type not in SUPPORTED_HIVE_TYPES:
        return [], []
    logging.getLogger("regipy").setLevel(logging.CRITICAL)
    try:
        hive = RegistryHive(str(hive_path), hive_type=hive_type)
        res = run_relevant_plugins(hive, as_json=True, continue_on_error=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("registry artifacts: %s: %s", hive_path, exc)
        return [], []
    rows: list[tuple[Any, ...]] = []
    for name, entries in res.items():
        rows += _rows(name, entries)
    return rows, sorted(res)


def store(con, src: int, rows: list[tuple[Any, ...]], mount: str = "") -> None:  # noqa: ANN001
    """Key paths of the plugins are relative to the hive: stored under its mount (HKCU\\…)
    so they read and link like every other path of the case."""
    if rows:
        con.executemany("INSERT INTO artifacts VALUES (?, ?, CAST(? AS TIMESTAMP), ?, ?, ?)",
                        [[src, plugin, ts, (mount + key if mount and key.startswith("\\") else key), summary, entry]
                         for plugin, ts, key, summary, entry in rows])
