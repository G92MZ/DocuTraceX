"""Sigma registry rules (``registry_set`` / ``registry_add`` / ``registry_delete`` /
``registry_event``) run on the case's registry database.

The rules come from a folder the analyst sets in Settings (a SigmaHQ clone, their
own rules, or both); nothing is downloaded. Each rule is translated to one SQL
query over the case's keys and values, the way Sysmon would have reported them:

- **TargetObject**: the key path, or ``key\\value`` for a value (``(Default)`` for
  the unnamed one); ``HKCU`` as ``HKU\\<SID>`` (``…_Classes`` for UsrClass) and
  ``ControlSet00N`` as ``CurrentControlSet``, so the rules' paths match;
- **Details**: the data, with Sysmon's spelling for numbers and binaries
  (``DWORD (0x00000001)``, ``QWORD (0x…-0x…)``, ``Binary Data``, ``(Empty)``);
- **EventType**: ``SetValue`` for a value, ``CreateKey`` for a key, and
  ``DeleteValue`` / ``DeleteKey`` for what was recovered from deleted cells
  (``registry_delete`` rules look only there).

Modifiers ``contains`` / ``startswith`` / ``endswith`` / ``all`` / ``re`` / ``cased`` /
``windash`` and Sigma's ``*`` / ``?`` wildcards are supported; conditions with
``and`` / ``or`` / ``not``, parentheses, ``1 of`` / ``all of`` (``them`` or a
pattern). Whatever cannot be translated faithfully — keywords, aggregations,
other modifiers, a process field (``Image``, ``User``…) a hive cannot show — makes
the rule *skipped*, listed with why. Process fields used only to exclude
(``filter_*``) can be left unapplied when the analyst allows it in Settings; such
findings say so.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from pathlib import Path
from typing import Any

CATEGORIES = ("registry_set", "registry_add", "registry_delete", "registry_event")
MAX_FILE = 512 * 1024
_SID = "S-1-5-21-0-0-0-1001"
# Fields a key or value has: Sysmon's (TargetObject, Details, EventType, NewName — the name a
# renamed key has now) and the Security log's 4657 (ObjectName in kernel form, ObjectValueName,
# NewValue). Anything else (Image, User, EventID, ProcessId…) is not in a hive.
_FIELDS = {"targetobject": "target", "details": "details", "eventtype": "event_type", "newname": "target",
           "objectname": "objname", "objectvaluename": "vname", "newvalue": "details"}
_SEVERITY = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "high"}
_WINDASH = ("-", "/", "\u2013", "\u2014", "\u2015")
_CACHE: dict[str, tuple[str, dict[str, Any]]] = {}


class Skip(Exception):
    """The rule cannot be translated faithfully: why."""


def _lit(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _wild_regex(v: str) -> tuple[str, bool]:
    """(RE2 pattern, has wildcards) of a Sigma value: * and ? are wildcards, \\* \\? \\\\ literals."""
    out, wild, i = [], False, 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v) and v[i + 1] in "*?\\":
            out.append(re.escape(v[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
            wild = True
        elif c == "?":
            out.append(".")
            wild = True
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out), wild


def _plain(v: str) -> str:
    """The value without Sigma escapes (no wildcard in it)."""
    return re.sub(r"\\([*?\\])", r"\1", v)


def _value_sql(col: str, v: Any, mods: list[str]) -> str:
    if v is None:                          # "the field is missing": every key and value has its fields
        return "FALSE"
    if isinstance(v, bool) or not isinstance(v, (str, int, float)):
        raise Skip(f"value of type {type(v).__name__}")
    v = str(v)
    if "re" in mods:
        try:
            re.compile(v)
        except re.error as exc:
            raise Skip(f"regular expression: {exc}") from exc
        return f"regexp_matches({col}, {_lit(v)})"
    cased = "cased" in mods
    c = col if cased else f"lower({col})"
    rx, wild = _wild_regex(v)
    kind = next((m for m in ("contains", "startswith", "endswith") if m in mods), "")
    if not wild:
        p = _plain(v) if cased else _plain(v).lower()
        return {"contains": f"contains({c}, {_lit(p)})", "startswith": f"starts_with({c}, {_lit(p)})",
                "endswith": f"ends_with({c}, {_lit(p)})", "": f"{c} = {_lit(p)}"}[kind]
    rx = {"contains": f".*{rx}.*", "startswith": f"{rx}.*", "endswith": f".*{rx}", "": rx}[kind]
    return f"regexp_full_match({c}, {_lit(('' if cased else '(?is)') + rx)})"


def _field_sql(field: str, values: Any, et_expr: str) -> str:
    name, *mods = field.split("|")
    mods = [m.lower() for m in mods]
    known = {"contains", "startswith", "endswith", "all", "re", "cased", "windash"}
    bad = [m for m in mods if m not in known]
    if bad:
        raise Skip(f"modifier {'|'.join(bad)}")
    lname = name.lower()
    if lname not in _FIELDS:
        raise ProcessField(name)
    col = et_expr if lname == "eventtype" else _FIELDS[lname]
    vals = values if isinstance(values, list) else [values]
    if not vals:
        raise Skip(f"empty value list for {name}")
    if "windash" in mods:
        vals = list(dict.fromkeys(str(x).replace("-", d) for x in vals for d in _WINDASH))
        mods = [m for m in mods if m != "windash"]
    parts = [_value_sql(col, x, mods) for x in vals]
    return "(" + (" AND " if "all" in mods else " OR ").join(parts) + ")"


class ProcessField(Skip):
    def __init__(self, field: str) -> None:
        super().__init__(f"field {field} (not in a hive: process, event ID…)")
        self.field = field


# Fields that only say which log / event the record came from: dropping them changes nothing on
# the registry. The others a hive lacks (Image, User, a misspelt field…) are what a selection is
# about, so a selection that needs one cannot be confirmed on a hive.
_META = {"eventid", "channel", "provider_name", "providername", "provider", "product", "service",
         "computer", "computername", "hostname", "eventrecordid", "sourcename", "logname"}


def _selection(sel: Any, et_expr: str) -> dict[str, Any]:
    """A selection as {pos, neg, ignored, needs, registry}.

    ``pos``: event-metadata fields (EventID, Channel…) are dropped; a selection with any other field
    a hive lacks is FALSE (it cannot be confirmed: matching on the rest would match far more than
    the rule means). ``neg`` (under a ``not``) is FALSE when such a field is in it: the exclusion
    cannot be applied, so it excludes nothing."""
    if isinstance(sel, dict):
        if not sel:
            raise Skip("empty selection")
        parts, ignored, needs = [], [], []
        for k, v in sel.items():
            try:
                parts.append(_field_sql(k, v, et_expr))
            except ProcessField as exc:
                (ignored if exc.field.lower() in _META else needs).append(exc.field)
        pos = "FALSE" if needs else ("(" + " AND ".join(parts) + ")" if parts else "TRUE")
        return {"pos": pos, "neg": "FALSE" if ignored or needs else pos, "ignored": ignored, "needs": needs,
                "registry": bool(parts) and not needs}
    if isinstance(sel, list) and sel and all(isinstance(x, dict) for x in sel):
        subs = [_selection(x, et_expr) for x in sel]
        return {"pos": "(" + " OR ".join(x["pos"] for x in subs) + ")",
                "neg": "(" + " OR ".join(x["neg"] for x in subs) + ")",
                "ignored": [f for x in subs for f in x["ignored"]],
                "needs": [f for x in subs for f in x["needs"]],
                "registry": any(x["registry"] for x in subs)}
    raise Skip("keyword search (no field)")


# --- condition -----------------------------------------------------------------------------

_TOK = re.compile(r"\s*(\(|\)|\b(?:1|all|any)\s+of\s+[\w*-]+|\band\b|\bor\b|\bnot\b|[\w*-]+)", re.I)


def _tokens(cond: str) -> list[str]:
    if "|" in cond:
        raise Skip("aggregation in the condition")
    out, pos = [], 0
    while pos < len(cond.rstrip()):
        m = _TOK.match(cond, pos)
        if not m:
            raise Skip(f"condition syntax near '{cond[pos:pos + 20]}'")
        out.append(m.group(1))
        pos = m.end()
    return out


def _condition(cond: str, sels: dict[str, dict[str, Any]]) -> tuple[str, dict[str, set[bool]]]:
    """(SQL, polarity of each selection used: True = asked to match, False = under a not)."""
    toks = _tokens(cond)
    pol: dict[str, set[bool]] = {}
    i = 0

    def ref(names: list[str], positive: bool, join: str) -> str:
        if not names:
            raise Skip("condition names no selection")
        for n in names:
            pol.setdefault(n, set()).add(positive)
        parts = [sels[n]["pos" if positive else "neg"] for n in names]
        return "(" + f" {join} ".join(parts) + ")"

    def expand(pat: str) -> list[str]:
        if pat.lower() == "them":
            return [n for n in sels]
        got = [n for n in sels if fnmatch.fnmatchcase(n, pat)]
        if not got:
            raise Skip(f"no selection matches {pat}")
        return got

    def or_(positive: bool) -> str:
        nonlocal i
        left = and_(positive)
        while i < len(toks) and toks[i].lower() == "or":
            i += 1
            left = f"({left} OR {and_(positive)})"
        return left

    def and_(positive: bool) -> str:
        nonlocal i
        left = not_(positive)
        while i < len(toks) and toks[i].lower() == "and":
            i += 1
            left = f"({left} AND {not_(positive)})"
        return left

    def not_(positive: bool) -> str:
        nonlocal i
        if i < len(toks) and toks[i].lower() == "not":
            i += 1
            return f"(NOT {not_(not positive)})"
        return atom(positive)

    def atom(positive: bool) -> str:
        nonlocal i
        if i >= len(toks):
            raise Skip("condition ends early")
        t = toks[i]
        i += 1
        if t == "(":
            e = or_(positive)
            if i >= len(toks) or toks[i] != ")":
                raise Skip("unbalanced parentheses")
            i += 1
            return e
        m = re.match(r"(1|all|any)\s+of\s+([\w*-]+)$", t, re.I)
        if m:
            return ref(expand(m.group(2)), positive, "AND" if m.group(1).lower() == "all" else "OR")
        if t not in sels:
            raise Skip(f"unknown selection {t}")
        return ref([t], positive, "AND")

    sql = or_(True)
    if i != len(toks):
        raise Skip("condition syntax")
    return sql, pol


# --- rules ---------------------------------------------------------------------------------

def _attack(tags: list[Any]) -> list[str]:
    out = []
    for t in tags or []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(t).strip().lower())
        if m:
            out.append(m.group(1).upper())
    return out


def compile_rule(doc: dict[str, Any], allow_process_filters: bool = False) -> dict[str, Any]:
    """The rule as {id, title, level, …, category, where, process_filters}; raises Skip."""
    cat = str((doc.get("logsource") or {}).get("category") or "")
    if cat not in CATEGORIES:
        raise Skip(f"category {cat or '(none)'}")
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise Skip("no detection / condition")
    cond = det["condition"]
    if isinstance(cond, list):
        if len(cond) != 1:
            raise Skip("several conditions")
        cond = cond[0]
    et = {"registry_set": "'setvalue'", "registry_add": "'createkey'",
          "registry_delete": "CASE WHEN kind = 'key' THEN 'deletekey' ELSE 'deletevalue' END",
          "registry_event": "CASE WHEN kind = 'key' THEN 'createkey' ELSE 'setvalue' END"}[cat]
    sels: dict[str, dict[str, Any]] = {}
    for name, sel in det.items():
        if name == "condition" or name == "timeframe":
            continue
        sels[name] = _selection(sel, f"({et})")
    where, pol = _condition(str(cond), sels)
    used = {n: sels[n] for n in pol}
    meta = sorted({f for x in used.values() for f in x["ignored"]})
    needs = sorted({f for x in used.values() for f in x["needs"]})
    if needs and not allow_process_filters:
        n, x = next((n, x) for n, x in used.items() if x["needs"])
        raise Skip(f"field {x['needs'][0]} in {n} (not in a hive; rules with fields like this run only when the "
                   "option is on in Settings)")
    if not any(x["registry"] for n, x in used.items() if True in pol[n]):
        raise Skip("nothing left to match on the registry: every selection needs "
                   + (", ".join(needs) if needs else "a field a hive does not have"))
    # what was not checked: metadata dropped anywhere, other fields only in exclusions (not applied);
    # selections that need a missing field are left out (FALSE)
    unapplied = sorted(set(meta) | {f for n, x in used.items() if False in pol[n] for f in x["needs"]})
    skipped_sels = sorted(n for n, x in used.items() if True in pol[n] and x["needs"])
    rows = {"registry_set": "kind = 'value'", "registry_add": "kind = 'key'",
            "registry_delete": "op = 'recovered'", "registry_event": "TRUE"}[cat]
    return {"id": str(doc.get("id") or ""), "title": str(doc.get("title") or "(untitled)"),
            "level": str(doc.get("level") or "medium").lower(), "status": str(doc.get("status") or ""),
            "author": str(doc.get("author") or ""), "description": str(doc.get("description") or "")[:600],
            "references": [str(x) for x in (doc.get("references") or [])][:5], "attack": _attack(doc.get("tags")),
            "category": cat, "where": f"({rows}) AND ({where})", "process_filters_unapplied": unapplied,
            "ignored_fields": unapplied, "selections_left_out": skipped_sels}


_LOOSE = re.compile(rb"^(\s*(?:title|description|name|author|falsepositives|-)\s*:?\s*)([^'\"\n|>][^\n]*:\s[^\n]*)$",
                    re.M | re.I)


def _quote_scalars(raw: bytes) -> bytes:
    """A common slip in hand-written rules: a title / description with ": " in it, unquoted.
    Quote those values and read the rule again (only text fields, never the detection)."""
    def fix(m: re.Match) -> bytes:
        head, val = m.group(1), m.group(2).rstrip()
        if not re.match(rb"\s*(?:title|description|name|author)\s*:", head, re.I):
            return m.group(0)
        return head + b"'" + val.replace(b"'", b"''") + b"'"
    return _LOOSE.sub(fix, raw)


def _signature(folder: Path) -> str:
    h = hashlib.sha1()
    for p in sorted(folder.rglob("*.y*ml")):
        try:
            st = p.stat()
        except OSError:
            continue
        h.update(f"{p}|{st.st_mtime_ns}|{st.st_size}\n".encode("utf-8", "replace"))
    return h.hexdigest()


def load(folder: str | Path | None, allow_process_filters: bool = False) -> dict[str, Any]:
    """{folder, rules: [compiled], skipped: [{file, title, reason}], files, error} for a folder."""
    out: dict[str, Any] = {"folder": str(folder or ""), "rules": [], "skipped": [], "files": 0, "error": ""}
    if not folder:
        return out
    root = Path(folder).expanduser()
    if not root.is_dir():
        out["error"] = f"not a folder: {root}"
        return out
    key = f"{root.resolve()}|{allow_process_filters}"
    sig = _signature(root)
    if key in _CACHE and _CACHE[key][0] == sig:
        return _CACHE[key][1]
    import yaml
    for p in sorted(root.rglob("*.y*ml")):
        try:
            if p.stat().st_size > MAX_FILE:
                continue
            raw = p.read_bytes()
        except OSError:
            continue
        if b"registry_" not in raw:           # most of a SigmaHQ clone: not registry rules
            continue
        out["files"] += 1
        try:
            try:
                docs = [d for d in yaml.safe_load_all(raw) if isinstance(d, dict)]
            except yaml.YAMLError:
                docs = [d for d in yaml.safe_load_all(_quote_scalars(raw)) if isinstance(d, dict)]
        except yaml.YAMLError as exc:
            out["skipped"].append({"file": str(p.relative_to(root)), "title": "", "reason": f"YAML: {str(exc)[:120]}"})
            continue
        for d in docs:
            if str((d.get("logsource") or {}).get("category") or "") not in CATEGORIES:
                continue
            try:
                r = compile_rule(d, allow_process_filters)
                r["file"] = str(p.relative_to(root))
                out["rules"].append(r)
            except Skip as exc:
                out["skipped"].append({"file": str(p.relative_to(root)), "title": str(d.get("title") or ""),
                                       "reason": str(exc)})
    _CACHE[key] = (sig, out)
    return out


def summary(loaded: dict[str, Any]) -> dict[str, Any]:
    return {"folder": loaded["folder"], "error": loaded["error"], "files": loaded["files"],
            "loaded": len(loaded["rules"]), "skipped": loaded["skipped"][:500], "skipped_count": len(loaded["skipped"])}


# --- running ---------------------------------------------------------------------------------

_EVENTS = r"""CREATE TEMP TABLE ev AS
WITH t AS (
  SELECT v.src, v."key" AS key, v.name, v.data, k.last_write, v.op, s.label, v.type, 'value' AS kind,
         v."key" || '\' || CASE WHEN coalesce(v.name, '') IN ('', '(default)') THEN '(Default)' ELSE v.name END AS raw,
         CASE WHEN v.type IN ('REG_DWORD', 'REG_DWORD_BIG_ENDIAN') AND regexp_full_match(coalesce(v.data, ''), '\d+')
                THEN printf('DWORD (0x%08x)', CAST(v.data AS UBIGINT))
              WHEN v.type = 'REG_QWORD' AND regexp_full_match(coalesce(v.data, ''), '\d+')
                THEN printf('QWORD (0x%08x-0x%08x)', CAST(v.data AS UBIGINT) >> 32, CAST(v.data AS UBIGINT) & 4294967295)
              WHEN v.type IN ('REG_BINARY', 'REG_NONE') OR v.type LIKE 'REG_RESOURCE%' OR v.type LIKE 'REG_FULL%'
                THEN 'Binary Data'
              WHEN coalesce(v.data, '') = '' THEN '(Empty)'
              ELSE v.data END AS details
  FROM vals v JOIN sources s ON s.id = v.src LEFT JOIN keys k ON k.src = v.src AND k.path = v."key"
  UNION ALL
  SELECT k.src, k.path, NULL, NULL, k.last_write, k.op, s.label, NULL, 'key', k.path, ''
  FROM keys k JOIN sources s ON s.id = k.src
)
SELECT src, key, name, data, last_write, op, label, type, kind, details,
  regexp_replace(regexp_replace(regexp_replace(raw,
    '^HKCU\\Software\\Classes(\\|$)', 'HKU\\__SID___Classes\1', 'i'),
    '^HKCU(\\|$)', 'HKU\\__SID__\1', 'i'),
    '\\ControlSet\d{3}(\\|$)', '\\CurrentControlSet\1', 'i') AS target,
  regexp_replace(regexp_replace(regexp_replace(regexp_replace(key,
    '^HKLM(\\|$)', '\\REGISTRY\\MACHINE\1', 'i'),
    '^HKU(\\|$)', '\\REGISTRY\\USER\1', 'i'),
    '^HKCU\\Software\\Classes(\\|$)', '\\REGISTRY\\USER\\__SID___Classes\1', 'i'),
    '^HKCU(\\|$)', '\\REGISTRY\\USER\\__SID__\1', 'i') AS objname,
  coalesce(name, '') AS vname
FROM t"""


def run(dbp: Path, loaded: dict[str, Any]) -> list[dict[str, Any]]:
    """Hits of the loaded rules over a case database.

    Hunting, not alerts: the registry tab lists them, but they raise no case finding and give no IOCs
    (most SigmaHQ registry rules describe changes, so on a hive's state they match a lot of the baseline).
    """
    hits: list[dict[str, Any]] = []
    if not loaded.get("rules"):
        return hits
    from . import store
    con = store.connect_ro(dbp)
    try:
        con.execute(_EVENTS.replace("__SID__", _SID))
        for r in loaded["rules"]:
            try:
                rows = con.execute(f"""SELECT src, key, name, data, last_write, op, label, type FROM ev
                                       WHERE {r['where']} ORDER BY src, key, name""").fetchall()
            except Exception as exc:  # noqa: BLE001  (a pattern RE2 does not take: that rule only)
                r.setdefault("error", str(exc)[:200])
                continue
            if not rows:
                continue
            rid = "sigma:" + (r["id"] or hashlib.sha1(r["title"].encode()).hexdigest()[:12])
            items = [{"src": x[0], "key": x[1], "name": x[2], "data": (x[3] or "")[:400],
                      "last_write": str(x[4]) if x[4] else None, "source": x[6], "type": x[7],
                      **({"op": x[5]} if x[5] else {})} for x in rows]
            hits.append({"rule": rid, "title": f"Sigma: {r['title']}", "severity": _SEVERITY.get(r["level"], "medium"),
                         "attack": r["attack"], "count": len(items), "suspicious": 0, "items": items, "hunting": True,
                         "sigma": {k: r[k] for k in ("id", "file", "author", "status", "level", "description",
                                                     "references", "category", "process_filters_unapplied", "ignored_fields",
                                                     "selections_left_out")}})
    finally:
        con.close()
    return hits
