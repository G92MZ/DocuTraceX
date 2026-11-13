"""The case's registry database (DuckDB, ``results/registry.duckdb``): every key and
value of every hive / .reg of the case, loaded once and queried as often as needed —
reopening the case months later needs no re-parsing.

Tables
- ``sources(id, label, file, kind, hive_type, mount, keys, vals, logs, error)``
- ``keys(src, path, parent, name, last_write, subkeys, nvalues, op)``
- ``vals(src, key, name, type, data, size, raw, op)`` — ``data`` is readable text
  (strings, numbers, multi-strings one per line, binary as hex), ``raw`` the bytes of
  binary values (payloads stored in the registry).
- ``catalog(src, category, description, comment, batch, key, name, type, data, last_write)``
  — what the RECmd batch files say to look at (``catalog``): rows without ``name`` are
  the keys (bookmarks), the others their values, binary ones converted.
- ``context(src, item, value)`` — the machine (src 0: computer name, Windows, install date,
  time zone, control set, users) and the user of each NTUSER (``context``).
- ``artifacts(src, plugin, ts, key, summary, entry)`` — regipy plugin entries
  (``artifacts``): UserAssist, ShimCache, BAM, ShellBags, USB… ``entry`` is JSON.

Reads go through read-only connections with external access disabled: a query can
look at these tables and nothing else on the machine.
"""

from __future__ import annotations

import csv
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterable

DB_NAME = "registry.duckdb"
MAX_ROWS = 5000
MAX_CHILDREN = 3000
QUERY_TIMEOUT = 30.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (id INTEGER, label VARCHAR, file VARCHAR, kind VARCHAR, hive_type VARCHAR,
    mount VARCHAR, keys BIGINT, vals BIGINT, logs VARCHAR, error VARCHAR);
CREATE TABLE IF NOT EXISTS keys (src INTEGER, path VARCHAR, parent VARCHAR, name VARCHAR, last_write TIMESTAMP,
    subkeys INTEGER, nvalues INTEGER, op VARCHAR);
CREATE TABLE IF NOT EXISTS vals (src INTEGER, "key" VARCHAR, name VARCHAR, type VARCHAR, data VARCHAR,
    size BIGINT, raw BLOB, op VARCHAR);
CREATE TABLE IF NOT EXISTS catalog (src INTEGER, category VARCHAR, description VARCHAR, comment VARCHAR,
    batch VARCHAR, "key" VARCHAR, name VARCHAR, type VARCHAR, data VARCHAR, last_write TIMESTAMP);
CREATE TABLE IF NOT EXISTS artifacts (src INTEGER, plugin VARCHAR, ts TIMESTAMP, "key" VARCHAR, summary VARCHAR,
    entry VARCHAR);
CREATE TABLE IF NOT EXISTS context (src INTEGER, item VARCHAR, value VARCHAR);
"""


def available() -> bool:
    try:
        import duckdb  # noqa: F401
        return True
    except ImportError:
        return False


def db_path(case_root: Path) -> Path:
    return case_root / "results" / DB_NAME


def create(path: Path):  # noqa: ANN201
    import duckdb
    path.parent.mkdir(parents=True, exist_ok=True)
    for p in (path, path.with_name(path.name + ".wal")):
        p.unlink(missing_ok=True)
    con = duckdb.connect(str(path))
    con.execute(SCHEMA)
    return con


class Loader:
    """Bulk loads rows through CSV files (COPY is orders of magnitude faster than INSERTs)."""

    def __init__(self, con, src: int) -> None:  # noqa: ANN001
        self.con, self.src = con, src
        self.tmp = Path(tempfile.mkdtemp(prefix="dtx_reg_"))
        self.kf = (self.tmp / "k.csv").open("w", newline="", encoding="utf-8")
        self.vf = (self.tmp / "v.csv").open("w", newline="", encoding="utf-8")
        self.kw = csv.writer(self.kf)
        self.vw = csv.writer(self.vf)
        self.nk = self.nv = 0

    def key(self, row: tuple) -> None:
        path, parent, name, lw, subkeys, nvalues, op = row
        path, parent, name = _vis(path), _vis(parent), _vis(name)
        self.kw.writerow([self.src, path, parent, name, lw.strftime("%Y-%m-%d %H:%M:%S") if lw else "",
                          subkeys, nvalues, op])
        self.nk += 1

    def value(self, row: tuple) -> None:
        key, name, vtype, data, size, raw, op = row
        self.vw.writerow([self.src, _vis(key), _vis(name), vtype, _clean(data), size, raw.hex() if raw else "", op])
        self.nv += 1

    def finish(self) -> tuple[int, int]:
        self.kf.close()
        self.vf.close()
        opts = "header=false, quote='\"', escape='\"', all_varchar=true, delim=','"
        self.con.execute(f"""INSERT INTO keys SELECT CAST(column0 AS INTEGER), column1, column2, column3,
            TRY_CAST(NULLIF(column4, '') AS TIMESTAMP), CAST(column5 AS INTEGER), CAST(column6 AS INTEGER),
            COALESCE(column7, '') FROM read_csv('{_sq(self.tmp / 'k.csv')}', {opts})""") if self.nk else None
        self.con.execute(f"""INSERT INTO vals SELECT CAST(column0 AS INTEGER), column1, COALESCE(column2, ''), column3,
            COALESCE(column4, ''), CAST(column5 AS BIGINT), CASE WHEN column6 IS NULL OR column6 = '' THEN NULL
            ELSE unhex(column6) END, COALESCE(column7, '') FROM read_csv('{_sq(self.tmp / 'v.csv')}', {opts})""") \
            if self.nv else None
        for p in self.tmp.iterdir():
            p.unlink()
        self.tmp.rmdir()
        return self.nk, self.nv


def bulk_insert(con, table: str, columns: list[tuple[str, str]], rows: Iterable[Iterable[Any]]) -> int:  # noqa: ANN001
    """Many rows at once through a CSV file (DuckDB's executemany goes row by row: minutes
    for tens of thousands of artifacts)."""
    tmp = Path(tempfile.mkdtemp(prefix="dtx_regb_"))
    f = tmp / "rows.csv"
    n = 0
    try:
        with f.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            for r in rows:
                w.writerow(["" if v is None else (v.isoformat(sep=" ") if hasattr(v, "isoformat") else v) for v in r])
                n += 1
        if n:
            cols = ", ".join(f"'c{i}': 'VARCHAR'" for i in range(len(columns)))
            sel = ", ".join(f"TRY_CAST(NULLIF(c{i}, '') AS {t})" if t != "VARCHAR" else f"NULLIF(c{i}, '')"
                            for i, (_n, t) in enumerate(columns))
            con.execute(f"""INSERT INTO {table} ({", ".join('"' + c + '"' for c, _t in columns)})
                SELECT {sel} FROM read_csv('{_sq(f)}', header=false, quote='"', escape='"', delim=',',
                    columns={{{cols}}})""")
    finally:
        f.unlink(missing_ok=True)
        tmp.rmdir()
    return n


def _clean(s: str) -> str:
    return (s or "").replace("\0", "")


def _vis(s: str | None) -> str | None:
    """Key / value names keep a NUL as a visible ␀ (names hidden from regedit with a NUL, the
    Poweliks / Kovter trick): CSV and DuckDB text cannot hold the byte itself."""
    return s.replace("\0", "\u2400") if s and "\0" in s else s


def _sq(p: Path) -> str:
    return str(p).replace("\\", "/").replace("'", "''")


def ensure_schema(con) -> None:  # noqa: ANN001
    """Tables added after a case was analysed (older databases): empty, so queries work."""
    con.execute(SCHEMA)


def finish_db(con) -> None:  # noqa: ANN001
    con.execute("CREATE INDEX IF NOT EXISTS keys_path ON keys(path)")
    con.execute("CREATE INDEX IF NOT EXISTS keys_parent ON keys(parent)")
    con.execute('CREATE INDEX IF NOT EXISTS vals_key ON vals("key")')
    con.execute('CREATE INDEX IF NOT EXISTS catalog_key ON catalog("key")')
    con.execute("CHECKPOINT")
    con.close()


# --- reads ---------------------------------------------------------------------------------
def connect_ro(path: Path):  # noqa: ANN201
    import duckdb
    con = duckdb.connect(str(path), read_only=True)
    try:
        con.execute("SET enable_external_access = false")
        con.execute("SET lock_configuration = true")
    except duckdb.Error:
        # another read of the same file is open: DuckDB shares that database instance, whose
        # configuration is already locked. Use it only if it is locked down the same way.
        if con.execute("SELECT current_setting('enable_external_access')").fetchone()[0] not in (False, "false"):
            con.close()
            raise
    return con


def _rows(cur, limit: int) -> dict[str, Any]:  # noqa: ANN001
    cols = [d[0] for d in cur.description or []]
    rows = cur.fetchmany(limit + 1)
    more = len(rows) > limit
    return {"columns": cols, "rows": [[_cell(v) for v in r] for r in rows[:limit]], "truncated": more}


def _cell(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return b[:512].hex() + ("…" if len(b) > 512 else "")
    if hasattr(v, "isoformat"):
        return v.isoformat(sep=" ")
    return v


def query(path: Path, sql: str, params: Iterable[Any] = (), limit: int = MAX_ROWS) -> dict[str, Any]:
    con = connect_ro(path)
    timer = threading.Timer(QUERY_TIMEOUT, con.interrupt)
    timer.start()
    try:
        return _rows(con.execute(sql, list(params)), limit)
    finally:
        timer.cancel()
        con.close()


_SQL_OK = re.compile(r"^\s*(?:--[^\n]*\n\s*)*(select|with|describe|summarize|show|pragma\s+table_info)\b", re.I)
_SQL_BAD = re.compile(r"\b(attach|copy|export|import|install|load|pragma(?!\s+table_info)|set|call|create|insert|update|"
                      r"delete|drop|alter|checkpoint|vacuum|read_\w+|glob|write_\w+)\b", re.I)


def user_query(path: Path, sql: str, limit: int = MAX_ROWS) -> dict[str, Any]:
    """An analyst's read-only SQL (one SELECT / WITH / DESCRIBE statement)."""
    s = (sql or "").strip().rstrip(";")
    if not s or ";" in s or not _SQL_OK.match(s) or _SQL_BAD.search(re.sub(r"'(?:[^']|'')*'", "''", s)):
        raise ValueError("Only one read-only SELECT / WITH / DESCRIBE query over sources, keys and vals.")
    return query(path, s, (), limit)


def children(path: Path, src: int, key: str) -> dict[str, Any]:
    """Subkeys and values of one key (``key`` = "" lists each source's root key)."""
    con = connect_ro(path)
    try:
        if not key:
            # each hive's root key; a .reg's top-level roots (HKCU, HKLM…) as virtual keys
            subs = con.execute("""SELECT s.id, k.path, k.name, k.last_write, k.subkeys, k.nvalues, k.op
                FROM sources s JOIN keys k ON k.src = s.id AND k.path = s.mount WHERE s.kind = 'hive' AND (? = 0 OR s.id = ?)
                UNION ALL SELECT DISTINCT k.src, split_part(k.path, '\\', 1), split_part(k.path, '\\', 1),
                    NULL::TIMESTAMP, NULL::INTEGER, NULL::INTEGER, ''
                FROM keys k JOIN sources s ON s.id = k.src AND s.kind = 'reg' WHERE (? = 0 OR k.src = ?)
                ORDER BY 1, 2""", [src, src, src, src]).fetchall()
            vals: list = []
        else:
            # real children, plus the implicit ones of a .reg (it only lists the keys it touches)
            subs = con.execute("""SELECT src, path, name, last_write, subkeys, nvalues, op FROM keys
                WHERE src = ? AND parent = ?
                UNION ALL SELECT DISTINCT src, ? || '\\' || split_part(substr(path, length(?) + 2), '\\', 1),
                    split_part(substr(path, length(?) + 2), '\\', 1), NULL::TIMESTAMP, NULL::INTEGER, NULL::INTEGER, ''
                FROM keys k WHERE src = ? AND starts_with(path, ? || '\\') AND parent <> ?
                    AND NOT EXISTS (SELECT 1 FROM keys c WHERE c.src = k.src AND c.parent = ?
                                    AND c.path = ? || '\\' || split_part(substr(k.path, length(?) + 2), '\\', 1))
                ORDER BY 3""", [src, key, key, key, key, src, key, key, key, key, key]).fetchall()
            vals = con.execute("""SELECT name, type, data, size, op, raw IS NOT NULL FROM vals WHERE src = ? AND "key" = ?
                ORDER BY lower(name)""", [src, key]).fetchall()
        meta = con.execute("SELECT path, last_write, subkeys, nvalues, op FROM keys WHERE src = ? AND path = ?",
                           [src, key]).fetchone() if key else None
    finally:
        con.close()
    return {"key": key, "src": src,
            "meta": dict(zip(("path", "last_write", "subkeys", "values", "op"), map(_cell, meta))) if meta else None,
            "subkeys_total": len(subs),          # a key such as Classes\CLSID has tens of thousands
            "subkeys": [dict(zip(("src", "path", "name", "last_write", "subkeys", "values", "op"), map(_cell, r)))
                        for r in subs[:MAX_CHILDREN]],
            "values": [dict(zip(("name", "type", "data", "size", "op", "has_raw"), map(_cell, r))) for r in vals]}


def _has(con, table: str) -> bool:  # noqa: ANN001
    return bool(con.execute("SELECT count(*) FROM information_schema.tables WHERE table_name = ?", [table]).fetchone()[0])


def bookmarks(path: Path, src: int) -> dict[str, Any]:
    """The catalogue keys of a source, by category (Browse → Bookmarks)."""
    con = connect_ro(path)
    try:
        if not _has(con, "catalog"):
            return {"bookmarks": []}
        rows = con.execute("""SELECT category, description, "key", any_value(comment), count(name)
            FROM catalog WHERE src = ? GROUP BY ALL ORDER BY category, description, "key" LIMIT 3000""", [src]).fetchall()
    finally:
        con.close()
    return {"bookmarks": [dict(zip(("category", "description", "key", "comment", "values"), r)) for r in rows]}


def artifact_summary(path: Path) -> dict[str, Any]:
    """Per source: catalogue categories and regipy plugins with their row counts."""
    con = connect_ro(path)
    try:
        cat = con.execute("""SELECT src, category, count(*) FILTER (WHERE name IS NOT NULL), count(DISTINCT "key")
            FROM catalog GROUP BY ALL ORDER BY 1, 2""").fetchall() if _has(con, "catalog") else []
        art = con.execute("""SELECT src, plugin, count(*), min(ts), max(ts) FROM artifacts GROUP BY ALL ORDER BY 1, 2""") \
            .fetchall() if _has(con, "artifacts") else []
    finally:
        con.close()
    return {"catalog": [dict(zip(("src", "category", "values", "keys"), r)) for r in cat],
            "plugins": [dict(zip(("src", "plugin", "rows", "first", "last"), map(_cell, r))) for r in art]}


def artifact_rows(path: Path, src: int, plugin: str = "", category: str = "", limit: int = 2000,
                  offset: int = 0) -> dict[str, Any]:
    """The rows of one regipy plugin (entries flattened into columns) or one catalogue category."""
    import json as _json
    con = connect_ro(path)
    try:
        if plugin:
            rows = con.execute("""SELECT ts, "key", entry FROM artifacts WHERE src = ? AND plugin = ?
                ORDER BY ts DESC NULLS LAST LIMIT ? OFFSET ?""", [src, plugin, limit + 1, offset]).fetchall()
            more = len(rows) > limit
            ents = [{**_json.loads(r[2]), **({"key": r[1]} if r[1] else {})} for r in rows[:limit]]
            for e in ents:
                e.pop("key_path", None)
            cols: list[str] = []
            for e in ents:
                for k, v in e.items():
                    if k not in cols and not isinstance(v, (dict, list)):
                        cols.append(k)
            cols = cols[:24]
            return {"columns": cols, "rows": [[_cell(e.get(c)) for c in cols] for e in ents], "truncated": more}
        res = _rows(con.execute("""SELECT description, "key", name, data, last_write, comment FROM catalog
            WHERE src = ? AND category = ? AND name IS NOT NULL ORDER BY description, "key", name LIMIT ? OFFSET ?""",
                                [src, category, limit + 1, offset]), limit)
        return res
    finally:
        con.close()


def timeline(path: Path, src: int = 0, limit: int = 2000, offset: int = 0) -> dict[str, Any]:
    """Key last-writes and artifact timestamps, newest first."""
    con = connect_ro(path)
    try:
        art = """UNION ALL SELECT ts, src, 'artifact: ' || plugin, "key", summary FROM artifacts
            WHERE ts IS NOT NULL AND (? = 0 OR src = ?)""" if _has(con, "artifacts") else ""
        args = [src, src] + ([src, src] if art else []) + [limit + 1, offset]
        return _rows(con.execute(f"""SELECT * FROM (SELECT last_write AS ts, src, 'key written' AS what, path AS "key",
            '' AS detail FROM keys WHERE last_write IS NOT NULL AND (? = 0 OR src = ?) {art})
            ORDER BY ts DESC, src, what, "key", detail LIMIT ? OFFSET ?""", args), limit)
    finally:
        con.close()


RECOVERED_SQL = """SELECT v.src, v."key", v.name, v.type, v.data, v.size, k.last_write AS key_last_write
FROM vals v LEFT JOIN keys k ON k.src = v.src AND k.path = v."key" WHERE v.op = 'recovered'
UNION ALL SELECT k.src, k.path, NULL, NULL, NULL, NULL, k.last_write FROM keys k
WHERE k.op = 'recovered' AND NOT EXISTS (SELECT 1 FROM vals v WHERE v.src = k.src AND v."key" = k.path AND v.op = 'recovered')
ORDER BY 1, 2, 3 NULLS FIRST"""


def recovered(path: Path, src: int = 0, limit: int = 2000, offset: int = 0) -> dict[str, Any]:
    """Every deleted key and value recovered from free cells (a key with recovered values is
    listed through them; an empty one on its own)."""
    sql = f"SELECT * FROM ({RECOVERED_SQL}) WHERE (? = 0 OR src = ?) LIMIT {int(limit) + 1} OFFSET {int(offset)}"
    return query(path, sql, [src, src], limit)


def subtree(path: Path, src: int, key: str, limit: int = 200_000) -> dict[str, Any]:
    """A key and everything under it (for a .reg export): keys and values, binary data as hex."""
    con = connect_ro(path)
    try:
        cond = '(k.path = ? OR starts_with(k.path, ? || \'\\\'))'
        keys = con.execute(f"""SELECT k.path, k.op FROM keys k WHERE k.src = ? AND {cond} AND k.op <> 'delete'
            ORDER BY k.path LIMIT ?""", [src, key, key, limit]).fetchall()
        vals = con.execute(f"""SELECT v."key", v.name, v.type, v.data, hex(v.raw), v.op FROM vals v
            WHERE v.src = ? AND (v."key" = ? OR starts_with(v."key", ? || \'\\\')) AND v.op <> 'delete'
            ORDER BY v."key", v.name LIMIT ?""", [src, key, key, limit]).fetchall()
    finally:
        con.close()
    return {"keys": [list(r) for r in keys], "values": [list(r) for r in vals], "truncated": len(vals) >= limit}


def value(path: Path, src: int, key: str, name: str) -> dict[str, Any]:
    """One value in full (the data text and, for binary values, up to 1 MB of the bytes as hex)."""
    con = connect_ro(path)
    try:
        r = con.execute('SELECT type, data, size, raw FROM vals WHERE src = ? AND "key" = ? AND name = ?',
                        [src, key, name]).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError("No such value.")
    raw = bytes(r[3]) if r[3] is not None else None
    return {"type": r[0], "data": r[1], "size": r[2], "hex": raw[:1 << 20].hex() if raw else None}


def search(path: Path, q: str, where: str = "any", src: int = 0, regex: bool = False,
           limit: int = 500, offset: int = 0) -> dict[str, Any]:
    """Keys and values whose path / value name / data contain ``q`` (or match it as a regex)."""
    if not q:
        return {"columns": [], "rows": [], "truncated": False}
    if regex:
        re.compile(q)
        cond = "regexp_matches({f}, ?, 'i')"
        arg = q
    else:
        cond = "{f} ILIKE ? ESCAPE '\\'"
        arg = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    parts, args = [], []
    if where in ("any", "key"):
        parts.append(f"""SELECT src, path AS "key", NULL AS name, NULL AS type, NULL AS data, last_write, op
            FROM keys WHERE {cond.format(f='path')} AND (? = 0 OR src = ?)""")
        args += [arg, src, src]
    fields = {"any": ["name", "data"], "name": ["name"], "data": ["data"], "key": []}[where if where in
                                                                                        ("any", "name", "data", "key") else "any"]
    if fields:
        ors = " OR ".join(cond.format(f="v." + f) for f in fields)
        parts.append(f"""SELECT v.src, v."key", v.name, v.type, v.data, k.last_write, v.op FROM vals v
            LEFT JOIN keys k ON k.src = v.src AND k.path = v."key"
            WHERE ({ors}) AND (? = 0 OR v.src = ?)""")
        args += [arg] * len(fields) + [src, src]
    sql = " UNION ALL ".join(parts) + f" ORDER BY 2, 3 NULLS FIRST LIMIT {int(limit) + 1} OFFSET {int(offset)}"
    return query(path, sql, args, limit)
