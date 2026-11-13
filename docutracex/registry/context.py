"""The machine behind the hives of a case: SYSTEM + SOFTWARE (+ NTUSER) read together.

- SYSTEM: the control set in use (``Select\\Current``), computer name, time zone (name and the
  bias in force when the hive was saved), last shutdown;
- SOFTWARE: Windows edition, version / build, install date, registered owner and the user
  profiles (``ProfileList``: SID → profile folder → user name);
- each NTUSER / UsrClass: its user, from the path embedded in the hive (or the file path)
  matched against the profiles.

Stored as ``context(src, item, value)`` (``src`` 0 = the machine) and returned for the tab.
Times stay UTC in the database; the tab can show them in the machine's local time.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

_CS = r"(?:ControlSet\d{3}|CurrentControlSet)"


def _val(con, key_rx: str, name: str, src: int | None = None) -> tuple[int, str, str, bytes | None] | None:  # noqa: ANN001
    row = con.execute("""SELECT src, "key", data, raw FROM vals WHERE regexp_matches("key", ?, 'i')
        AND lower(name) = lower(?) AND op = '' AND (? IS NULL OR src = ?) ORDER BY src LIMIT 1""",
                      [key_rx, name, src, src]).fetchone()
    return (row[0], row[1], row[2] or "", bytes(row[3]) if row[3] is not None else None) if row else None


def _signed(v: str) -> int | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n - (1 << 32) if n >= 1 << 31 else n


def _filetime(raw: bytes | None, text: str) -> str | None:
    b = raw if raw else (bytes.fromhex(text) if re.fullmatch(r"[0-9a-fA-F]{16,}", text or "") else None)
    if not b or len(b) < 8:
        return None
    v = int.from_bytes(b[:8], "little")
    try:
        return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=v // 10)).isoformat(sep=" ") if v else None
    except OverflowError:
        return None


def build(con, sources: list[dict[str, Any]]) -> dict[str, Any]:  # noqa: ANN001
    """Fill ``context`` and return {machine: {...}, users: [...], owners: {src: user}}."""
    m: dict[str, Any] = {}
    cur = _val(con, r"\\SYSTEM\\Select$|^HKLM\\SYSTEM\\Select$", "Current")
    cs = f"ControlSet{int(cur[2]):03d}" if cur and (cur[2] or "").isdigit() else None
    if cs:
        m["control_set"] = cs
    csrx = re.escape(cs) if cs else _CS
    for item, key, name in (("computer_name", rf"\\{csrx}\\Control\\ComputerName\\ComputerName$", "ComputerName"),
                            ("timezone", rf"\\{csrx}\\Control\\TimeZoneInformation$", "TimeZoneKeyName"),
                            ("timezone_std", rf"\\{csrx}\\Control\\TimeZoneInformation$", "StandardName")):
        v = _val(con, key, name)
        if v and v[2]:
            m[item] = v[2]
    bias = _val(con, rf"\\{csrx}\\Control\\TimeZoneInformation$", "ActiveTimeBias") \
        or _val(con, rf"\\{csrx}\\Control\\TimeZoneInformation$", "Bias")
    if bias and _signed(bias[2]) is not None:
        m["utc_offset_min"] = -_signed(bias[2])
    sd = _val(con, rf"\\{csrx}\\Control\\Windows$", "ShutdownTime")
    if sd and (t := _filetime(sd[3], sd[2])):
        m["last_shutdown"] = t
    nt = r"\\Microsoft\\Windows NT\\CurrentVersion$"
    for item, name in (("product", "ProductName"), ("display_version", "DisplayVersion"), ("build", "CurrentBuild"),
                       ("owner", "RegisteredOwner"), ("organization", "RegisteredOrganization")):
        v = _val(con, nt, name)
        if v and v[2]:
            m[item] = v[2]
    inst = _val(con, nt, "InstallDate")
    if inst and (inst[2] or "").isdigit() and int(inst[2]) > 0:
        m["install_date"] = dt.datetime.fromtimestamp(int(inst[2]), dt.timezone.utc).replace(tzinfo=None).isoformat(sep=" ")

    users = []
    for _src, key, data in con.execute("""SELECT src, "key", data FROM vals WHERE
            regexp_matches("key", '\\\\ProfileList\\\\S-1-[0-9-]+$', 'i') AND lower(name) = 'profileimagepath'
            AND op = '' ORDER BY "key" """).fetchall():
        sid = key.rsplit("\\", 1)[1]
        name = re.split(r"[\\/]", (data or "").rstrip("\\/"))[-1] if data else ""
        users.append({"sid": sid, "profile": data or "", "name": name})

    owners: dict[int, str] = {}
    for s in sources:
        if s.get("hive_type") not in ("ntuser", "usrclass"):
            continue
        hint = " ".join(str(s.get(k) or "") for k in ("embedded_name", "label", "file"))
        m_user = re.search(r"(?i)[\\/](?:Users|Documents and Settings)[\\/]([^\\/]+)[\\/]", hint)
        uname = m_user.group(1) if m_user else None
        match = next((u for u in users if uname and u["name"].lower() == uname.lower()), None)
        if match:
            owners[s["id"]] = f"{match['name']} ({match['sid']})"
        elif uname:
            owners[s["id"]] = uname

    rows = [[0, k, str(v)] for k, v in m.items()]
    rows += [[0, "user", f"{u['sid']}|{u['name']}|{u['profile']}"] for u in users]
    rows += [[src, "owner", u] for src, u in owners.items()]
    if rows:
        con.executemany("INSERT INTO context VALUES (?, ?, ?)", rows)
    return {"machine": m, "users": users, "owners": {str(k): v for k, v in owners.items()}}
