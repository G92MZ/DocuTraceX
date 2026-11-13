"""The case's registry database (DuckDB, ``results/registry.duckdb``): every key and
value of every hive / .reg of the case, loaded once and queried as often as needed —
reopening the case months later needs no re-parsing.

Tables
- ``sources(id, label, file, kind, hive_type, mount, keys, vals, logs, error)``
- ``keys(src, path, parent, name, last_write, subkeys, nvalues, op)``
- ``vals(src, key, name, type, data, size, raw, op)`` — ``data`` is readable text
  (strings, numbers, multi-strings one per line, binary as hex), ``raw`` the bytes of
  binary values (payloads stored in the registry).

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
QUERY_TIMEOUT = 30.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (id INTEGER, label VARCHAR, file VARCHAR, kind VARCHAR, hive_type VARCHAR,
    mount VARCHAR, keys BIGINT, vals BIGINT, logs VARCHAR, error VARCHAR);
CREATE TABLE IF NOT EXISTS keys (src INTEGER, path VARCHAR, parent VARCHAR, name VARCHAR, last_write TIMESTAMP,
    subkeys INTEGER, nvalues INTEGER, op VARCHAR);
CREATE TABLE IF NOT EXISTS vals (src INTEGER, "key" VARCHAR, name VARCHAR, type VARCHAR, data VARCHAR,
    size BIGINT, raw BLOB, op VARCHAR);
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
        self.kw.writerow([self.src, path, parent, name, lw.strftime("%Y-%m-%d %H:%M:%S") if lw else "",
                          subkeys, nvalues, op])
        self.nk += 1

    def value(self, row: tuple) -> None:
        key, name, vtype, data, size, raw, op = row
        self.vw.writerow([self.src, key, name, vtype, _clean(data), size, raw.hex() if raw else "", op])
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


def _clean(s: str) -> str:
    return (s or "").replace("\0", "")


def _sq(p: Path) -> str:
    return str(p).replace("\\", "/").replace("'", "''")


def finish_db(con) -> None:  # noqa: ANN001
    con.execute("CREATE INDEX IF NOT EXISTS keys_path ON keys(path)")
    con.execute("CREATE INDEX IF NOT EXISTS keys_parent ON keys(parent)")
    con.execute('CREATE INDEX IF NOT EXISTS vals_key ON vals("key")')
    con.execute("CHECKPOINT")
    con.close()


# --- reads ---------------------------------------------------------------------------------
def connect_ro(path: Path):  # noqa: ANN201
    import duckdb
    con = duckdb.connect(str(path), read_only=True)
    con.execute("SET enable_external_access = false")
    con.execute("SET lock_configuration = true")
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
            "subkeys": [dict(zip(("src", "path", "name", "last_write", "subkeys", "values", "op"), map(_cell, r)))
                        for r in subs],
            "values": [dict(zip(("name", "type", "data", "size", "op", "has_raw"), map(_cell, r))) for r in vals]}


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
