"""What each registry key means: the RECmd batch files (Eric Zimmerman, MIT).

``Kroll_Batch.reb`` and ``DFIRBatch.reb`` list, per hive type, the keys and values a
forensic examiner looks at (system info, devices, program execution, user activity,
autoruns, third-party applications…), with a category, a description and a comment.
They are downloaded into ``tools/recmd/`` on install and refreshed in the background
when older than 7 days, so the list stays current without a release. Only the batch
files are downloaded; nothing about a case is ever sent. Without them the Registry
tab still works (no bookmarks / catalogue).

At ingest every entry is matched against the case database: the matching keys become
bookmarks (``catalog`` rows without a value name) and their values catalogue rows,
binary values converted as the entry says (FILETIME, EPOCH, SYSTEMTIME, IP).
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from ..config import settings

BASE = "https://raw.githubusercontent.com/EricZimmerman/RECmd/master/BatchExamples/"
FILES = ("Kroll_Batch.reb", "DFIRBatch.reb")
SITE = "https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples"
MAX_AGE = 7 * 86400
MIN_ENTRIES = 50

# RECmd HiveType → our hive type (parse.MOUNTS keys)
_HIVE = {"ntuser": "ntuser", "user": "ntuser", "usrclass": "usrclass", "software": "software", "system": "system",
         "sam": "sam", "security": "security", "default": "default", "amcache": "amcache",
         "components": "components", "drivers": "drivers", "bcd": "bcd"}

_lock = threading.Lock()
_cache: dict[str, Any] = {"key": None, "entries": []}


def directory() -> Path:
    return settings.tools_dir / "recmd"


def paths() -> list[Path]:
    return [p for p in (directory() / f for f in FILES) if p.is_file()]


def load() -> list[dict[str, Any]]:
    """Every entry of the batch files present (deduplicated), cached per file mtime."""
    files = paths()
    key = tuple((str(p), p.stat().st_mtime) for p in files)
    with _lock:
        if _cache["key"] == key:
            return _cache["entries"]
        entries = []
        for p in files:
            try:
                entries += parse_reb(p.read_text(encoding="utf-8", errors="replace"), p.name)
            except Exception:  # noqa: BLE001  (a broken download: ignore that file)
                continue
        seen, out = set(), []
        for e in entries:
            k = (e["hive"], e["key"].lower(), (e["value"] or "").lower(), e["recursive"])
            if k not in seen:
                seen.add(k)
                out.append(e)
        _cache.update(key=key, entries=out)
        return out


def parse_reb(text: str, source: str = "") -> list[dict[str, Any]]:
    import yaml
    doc = yaml.safe_load(text) or {}
    out = []
    for k in doc.get("Keys") or []:
        if not isinstance(k, dict) or not k.get("KeyPath") or not k.get("HiveType"):
            continue
        hive = _HIVE.get(str(k["HiveType"]).strip().lower())
        if not hive:
            continue
        out.append({"hive": hive, "key": str(k["KeyPath"]).strip().strip("\\"),
                    "value": str(k["ValueName"]).strip() if k.get("ValueName") not in (None, "") else None,
                    "recursive": bool(k.get("Recursive")), "category": str(k.get("Category") or "Other").strip(),
                    "description": str(k.get("Description") or "").strip(),
                    "comment": str(k.get("Comment") or "").strip(),
                    "convert": str(k.get("BinaryConvert") or "").strip().upper() or None,
                    "batch": source})
    return out


def _count(text: str) -> int:
    """Entries in a batch file without parsing the YAML (the web app's Python has no PyYAML)."""
    return len(re.findall(r"(?m)^\s*KeyPath\s*:", text))


def status() -> dict[str, Any]:
    files = paths()
    entries = sum(_count(p.read_text(encoding="utf-8", errors="replace")) for p in files)
    newest = max((p.stat().st_mtime for p in files), default=None)
    return {"files": [p.name for p in files], "entries": entries,
            "updated": _dt.datetime.fromtimestamp(newest).isoformat(timespec="minutes") if newest else None,
            "url": SITE}


# --- download ------------------------------------------------------------------------------
def download(proxy: str | None = None, timeout: int = 60) -> dict[str, Any]:
    """Fetch the batch files; a file that fails keeps its previous copy. Raises if none came."""
    try:
        from ..mailintel import _routes, _short
        routes = _routes(proxy)
    except Exception:  # noqa: BLE001  (setup script: no app settings)
        routes = [("direct", urllib.request.build_opener())]
        _short = str  # noqa: N806
    got, errors = 0, []
    for name in FILES:
        body = None
        for label, opener in routes:
            req = urllib.request.Request(BASE + name, headers={"User-Agent": "DocuTraceX"})
            try:
                with opener.open(req, timeout=timeout) as r:
                    body = r.read(16 * 1024 * 1024)
                if _count(body.decode("utf-8", "replace")) < MIN_ENTRIES:
                    raise ValueError("looks incomplete")
                break
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{name} {label}: {_short(exc)}")
                body = None
        if body is not None:
            d = directory()
            d.mkdir(parents=True, exist_ok=True)
            tmp = d / (name + ".tmp")
            tmp.write_bytes(body)
            tmp.replace(d / name)
            got += 1
    if not got:
        raise ConnectionError("; ".join(errors))
    return status()


def stale() -> bool:
    fs = paths()
    return len(fs) < len(FILES) or any(time.time() - p.stat().st_mtime > MAX_AGE for p in fs)


def refresh_in_background(proxy: str | None = None) -> None:
    if not stale():
        return

    def run() -> None:
        import logging
        try:
            download(proxy)
            logging.getLogger(__name__).info("RECmd batch files updated")
        except Exception as exc:  # noqa: BLE001  (offline: the previous copy, or none)
            logging.getLogger(__name__).warning("RECmd batch files not updated: %s", exc)
    threading.Thread(target=run, name="recmd-refresh", daemon=True).start()


# --- matching against the case database -----------------------------------------------------
def key_regex(mount: str, keypath: str, recursive: bool) -> tuple[str, str]:
    """(literal lower-case prefix, regex) of the full key paths an entry covers under ``mount``.
    ``ControlSet00*`` also matches the ``CurrentControlSet`` of a .reg export."""
    parts = []
    for seg in keypath.split("\\"):
        if re.fullmatch(r"ControlSet\d*\*", seg, re.I):
            parts.append(r"(?:ControlSet\d{3}|CurrentControlSet)")
        else:
            parts.append(re.escape(seg).replace(r"\*", r"[^\\]*").replace(r"\?", r"[^\\]"))
    rx = "^" + re.escape(mount) + r"\\" + r"\\".join(parts) + (r"(?:\\.*)?$" if recursive else "$")
    lit = keypath.split("*", 1)[0].split("?", 1)[0]
    if re.match(r"(?i)ControlSet", keypath):
        lit = ""
    return (mount + "\\" + lit).lower(), rx


def convert(kind: str | None, raw: bytes | None, text: str) -> str:
    """A binary value as the batch entry reads it (an MRU-style UTF-16 string as text)."""
    if raw is None:
        return text
    if not kind:
        return _utf16(raw) or text
    try:
        if kind == "FILETIME" and len(raw) >= 8:
            v = int.from_bytes(raw[:8], "little")
            return (_dt.datetime(1601, 1, 1) + _dt.timedelta(microseconds=v // 10)).isoformat(sep=" ") if v else text
        if kind == "EPOCH" and len(raw) >= 4:
            v = int.from_bytes(raw[:8] if len(raw) >= 8 else raw[:4], "little")
            return _dt.datetime.fromtimestamp(v, _dt.timezone.utc).replace(tzinfo=None).isoformat(sep=" ") \
                if 0 < v < 4102444800 else text
        if kind == "SYSTEMTIME" and len(raw) >= 16:
            y, mo, _dow, d, h, mi, s, ms = (int.from_bytes(raw[i:i + 2], "little") for i in range(0, 16, 2))
            return _dt.datetime(y, mo, d, h, mi, s, ms * 1000).isoformat(sep=" ")
        if kind == "IP" and len(raw) in (4, 16):
            return str(ipaddress.ip_address(raw))
    except (ValueError, OverflowError):
        pass
    return text


def _utf16(raw: bytes) -> str | None:
    """A binary value holding one UTF-16 string (WordWheelQuery, RecentDocs names…)."""
    if len(raw) < 4 or len(raw) % 2:
        return None
    try:
        t = raw.decode("utf-16-le").split("\0", 1)[0]
    except UnicodeDecodeError:
        return None
    return t if len(t) >= 2 and t.isprintable() and len(t) * 2 >= len(raw) // 2 else None


def match(con, sources: list[dict[str, Any]], entries: list[dict[str, Any]] | None = None) -> int:  # noqa: ANN001
    """Fill ``catalog`` for every source; returns the rows added."""
    from .parse import MOUNTS
    entries = load() if entries is None else entries
    if not entries:
        return 0
    n = 0
    for s in sources:
        if s.get("error") and not s.get("keys"):
            continue
        if s.get("kind") == "hive":
            todo = [(e, s.get("mount") or "") for e in entries if e["hive"] == s.get("hive_type")]
        else:                              # a .reg: every entry, under the mount of its hive type
            todo = [(e, MOUNTS[e["hive"]]) for e in entries if MOUNTS.get(e["hive"])]
        for e, mount in todo:
            if not mount:
                continue
            lit, rx = key_regex(mount, e["key"], e["recursive"])
            meta = [s["id"], e["category"], e["description"], e["comment"], e["batch"]]
            if not e["value"]:            # a key entry: the key is the bookmark
                n += _ins_keys(con, meta, lit, rx)
            n += _ins_vals(con, meta, lit, rx, e)
    return n


def _ins_keys(con, meta: list, lit: str, rx: str) -> int:  # noqa: ANN001
    before = con.execute("SELECT count(*) FROM catalog").fetchone()[0]
    con.execute("""INSERT INTO catalog SELECT k.src, ?, ?, ?, ?, k.path, NULL, NULL, NULL, k.last_write
        FROM keys k WHERE k.src = ? AND starts_with(lower(k.path), ?) AND regexp_matches(k.path, ?, 'i')
        AND k.op = ''""", meta[1:] + [meta[0], lit, rx])
    return con.execute("SELECT count(*) FROM catalog").fetchone()[0] - before


def _ins_vals(con, meta: list, lit: str, rx: str, e: dict[str, Any]) -> int:  # noqa: ANN001
    name_cond, args = "", []
    if e["value"]:
        if "*" in e["value"]:
            name_cond = "AND regexp_matches(v.name, ?, 'i')"
            args = ["^" + re.escape(e["value"]).replace(r"\*", ".*") + "$"]
        else:
            name_cond = "AND lower(v.name) = lower(?)"
            args = [e["value"]]
    rows = con.execute(f"""SELECT v.src, v."key", v.name, v.type, v.data, v.raw, k.last_write FROM vals v
        LEFT JOIN keys k ON k.src = v.src AND k.path = v."key"
        WHERE v.src = ? AND starts_with(lower(v."key"), ?) AND regexp_matches(v."key", ?, 'i') AND v.op = ''
        {name_cond} LIMIT 5000""", [meta[0], lit, rx] + args).fetchall()
    if rows and e["value"]:                # a value entry: its keys become bookmarks only where the value exists
        con.executemany("INSERT INTO catalog VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)",
                        list({(src, key): [src, meta[1], meta[2], meta[3], meta[4], key, lw]
                              for src, key, _n, _t, _d, _r, lw in rows}.values()))
    if rows:
        con.executemany("INSERT INTO catalog VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [[src, meta[1], meta[2], meta[3], meta[4], key, name, vtype,
                          convert(e["convert"], bytes(raw) if raw is not None else None, data or "")[:4000], lw]
                         for src, key, name, vtype, data, raw, lw in rows])
    return len(rows)
