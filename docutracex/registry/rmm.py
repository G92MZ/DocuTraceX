"""Remote-access (RMM) tools in the registry: installed, portable, run, scheduled.

A portable AnyDesk never writes an Uninstall entry or a service, but Windows keeps
traces of it running. The products' executables, signers and names (the built-in
list of the C2 ``rmm`` extractor plus the LOLRMM catalogue) are looked for in every
value of the case's hives and in the artifacts regipy decoded, and each trace is
classified by where it is:

* **executed** — Amcache, BAM / DAM, UserAssist, Compatibility Assistant (PCA),
  MUICache, FeatureUsage;
* **seen** — ShimCache (on Windows 10 / 11 it does not prove a run on its own);
* **persistence** — Run / RunOnce, Winlogon, services, scheduled tasks (the
  *Actions* of ``TaskCache\\Tasks`` decoded, with the task's name);
* **installed** — Uninstall entries, the product's own key (``SOFTWARE\\TeamViewer``);
* **typed / opened** — RunMRU, TypedPaths, open / save dialogs, recent documents;
* **allowed** — firewall rules and Defender exclusions.

One finding per product, with every trace (key, value, time) as a timeline. High
when it is portable (run from Downloads, Desktop, Temp, AppData, Public…), renamed
(Amcache's original name or product is the tool, the file is called otherwise) or
launched by a scheduled task; medium when it is only installed or run from its
own folder. The software is legitimate: who deployed it decides.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import store

# executables too generic to name a product on their own (several products ship them)
_GENERIC_FILE = re.compile(
    r"(?i)^(?:agent|client|server|service|svc|setup|update|updater|autoupdate|launcher|install|installer|uninstall"
    r"|connect|remote|support|supporttool|helper|host|viewer|monitor|app|main|run|start|tray|ui|core|appcore"
    r"|installshield setup|setup_\w+)(?:[-_ ]?(?:32|64|x64|x86|amd64|win|windows))?\.(?:exe|dll|msi)$")
_USER_DIR = re.compile(
    r"(?i)(?:\\users\\[^\\]+\\(?:downloads|desktop|documents|appdata|onedrive|videos|music|pictures)\\"
    r"|\\(?:windows\\)?temp\\|\\users\\public\\|\\programdata\\(?!microsoft\\)|\\\$recycle\.bin\\|\\perflogs\\)")
_KIND = [
    ("allowed", "firewall rule", re.compile(r"(?i)\\FirewallPolicy\\(?:FirewallRules|RestrictedServices)")),
    ("allowed", "Defender exclusion", re.compile(r"(?i)\\Windows Defender\\Exclusions\\")),
    ("executed", "BAM / DAM", re.compile(r"(?i)\\Services\\[bd]am\\(?:State\\)?UserSettings\\")),
    ("executed", "Compatibility Assistant", re.compile(r"(?i)\\AppCompatFlags\\Compatibility Assistant\\")),
    ("executed", "MUICache", re.compile(r"(?i)\\(?:Shell\\MuiCache|ShellNoRoam\\MUICache)$")),
    ("executed", "FeatureUsage", re.compile(r"(?i)\\Explorer\\FeatureUsage\\")),
    ("executed", "Amcache", re.compile(r"(?i)^Amcache\\|\\Root\\(?:InventoryApplicationFile|InventoryApplicationShortcut"
                                       r"|File|Programs|InventoryApplication)\\")),
    ("executed", "RecentApps", re.compile(r"(?i)\\Search\\RecentApps\\")),
    ("persistence", "scheduled task", re.compile(r"(?i)\\Schedule\\TaskCache\\")),
    ("persistence", "Run key", re.compile(r"(?i)\\CurrentVersion\\(?:Run|RunOnce|RunOnceEx|RunServices|Policies\\Explorer\\Run)"
                                          r"(?:\\|$)")),
    ("persistence", "Winlogon", re.compile(r"(?i)\\Winlogon(?:\\|$)")),
    ("persistence", "service", re.compile(r"(?i)\\(?:CurrentControlSet|ControlSet\d{3})\\Services\\")),
    ("installed", "Uninstall", re.compile(r"(?i)\\CurrentVersion\\Uninstall\\")),
    ("typed", "Run dialog", re.compile(r"(?i)\\Explorer\\RunMRU$")),
    ("typed", "address bar", re.compile(r"(?i)\\Explorer\\TypedPaths$")),
    ("typed", "open / save dialog", re.compile(r"(?i)\\ComDlg32\\")),
    ("typed", "recent documents", re.compile(r"(?i)\\Explorer\\RecentDocs\\")),
]
_PLUGIN_KIND = {"amcache": ("executed", "Amcache"), "bam": ("executed", "BAM / DAM"),
                "background_activity_moderator": ("executed", "BAM / DAM"), "user_assist": ("executed", "UserAssist"),
                "userassist": ("executed", "UserAssist"), "shimcache": ("seen", "ShimCache"),
                "appcompatcache": ("seen", "ShimCache"), "pca": ("executed", "Compatibility Assistant"),
                "muicache": ("executed", "MUICache")}
_RANK = {"executed": 0, "persistence": 1, "installed": 2, "allowed": 3, "typed": 4, "seen": 5, "other": 6}
MAX_TRACES = 400


def _catalogue() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """(executable → product, product name → product, signer → product), generic entries left out."""
    from ..c2.rmm import _GENERIC_SIGNERS
    from ..rmmintel import _GENERIC_NAMES, catalogue
    files: dict[str, str] = {}
    names: dict[str, str] = {}
    signers: dict[str, str] = {}
    for product, c in catalogue().items():
        for f in c.get("files") or []:
            f = f.strip().lower()
            if re.fullmatch(r"[\w .+-]{3,80}\.(?:exe|dll|msi|scr)", f) and not _GENERIC_FILE.match(f) and len(f) >= 8:
                files.setdefault(f, product)
        short = product.split(" (")[0].split(" /")[0].strip()
        for n in {short, c.get("lolrmm") or short}:
            if n and len(n) >= 6 and n.lower() not in _GENERIC_NAMES:
                names.setdefault(n.lower(), product)
    try:
        from .. import lolrmm
        for name, c in (lolrmm.products() or {}).items():
            from ..c2.rmm import _builtin_for
            product = _builtin_for(name) or name
            for s in c.get("signers") or []:
                if len(s) >= 6 and not _GENERIC_SIGNERS.match(s):
                    signers.setdefault(s.lower(), product)
    except Exception:  # noqa: BLE001  (catalogue unreadable: executables and names only)
        pass
    return files, names, signers


def _kind(key: str) -> tuple[str, str]:
    for kind, label, rx in _KIND:
        if rx.search(key):
            return kind, label
    return "other", "registry"


def _filetime(raw: bytes | None) -> str | None:
    """BAM / DAM: the value's first 8 bytes are the last run (FILETIME)."""
    if not raw or len(raw) < 8:
        return None
    import datetime as dt
    ft = int.from_bytes(raw[:8], "little")
    if not 116444736000000000 < ft < 159000000000000000:
        return None
    return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ft // 10)).isoformat(sep=" ", timespec="seconds")


def _utf16_strings(raw: bytes) -> str:
    """The UTF-16 strings of a binary value (a scheduled task's Actions: program and arguments)."""
    return " ".join(m.group().decode("utf-16-le", "ignore") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){3,}", raw or b""))


def run(dbp: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """(hits, findings, IOC sources): one per product found."""
    files, names, signers = _catalogue()
    if not files and not names:
        return [], [], []
    by: dict[str, list[dict[str, Any]]] = {}

    def add(product: str, trace: dict[str, Any]) -> None:
        lst = by.setdefault(product, [])
        if len(lst) < MAX_TRACES and not any(t["key"] == trace["key"] and t["name"] == trace["name"] for t in lst):
            lst.append(trace)

    con = store.connect_ro(dbp)
    try:
        labels = dict(con.execute("SELECT id, label FROM sources").fetchall())
        # Amcache first: the original name / product / publisher of a file whose own name says otherwise —
        # a renamed tool's file name then counts wherever else it shows up (a task, a Run key, BAM)
        amc = con.execute("""SELECT v.src, v."key", lower(v.name), v.data, k.last_write FROM vals v
            LEFT JOIN keys k ON k.src = v.src AND k.path = v."key"
            WHERE v.src IN (SELECT id FROM sources WHERE hive_type = 'amcache')
              AND lower(v.name) IN ('originalfilename', 'productname', 'publisher', 'lowercaselongpath', 'name')""").fetchall()
        groups: dict[tuple[int, str], dict[str, str]] = {}
        times: dict[tuple[int, str], Any] = {}
        for src, key, name, data, lw in amc:
            groups.setdefault((src, key), {})[name] = data or ""
            times[(src, key)] = lw
        for (src, key), v in groups.items():
            orig = (v.get("originalfilename") or "").lower()
            prod = (v.get("productname") or "").lower()
            pub = (v.get("publisher") or "").lower()
            path = v.get("lowercaselongpath") or v.get("name") or ""
            base = path.replace("/", "\\").rsplit("\\", 1)[-1].lower()
            product = files.get(orig) or names.get(prod) or signers.get(pub) or files.get(base)
            if not product:
                continue
            renamed = bool(base) and base not in files and base.endswith((".exe", ".scr", ".com"))
            if renamed and not _GENERIC_FILE.match(base):
                files.setdefault(base, product)
            add(product, {"kind": "executed", "where": "Amcache", "src": src, "source": labels.get(src, ""), "key": key,
                          "name": "OriginalFileName / ProductName / Publisher",
                          "data": f"{path} (original {v.get('originalfilename') or '?'}, product {v.get('productname') or '?'}, "
                                  f"publisher {v.get('publisher') or '?'})", "time": times[(src, key)], "path": path,
                          **({"renamed": True} if renamed else {})})
        alts = "|".join(re.escape(f).replace("\\ ", " ") for f in sorted(files, key=len, reverse=True))
        rx_file = re.compile(r"(?i)(?<![\w.-])(" + alts + r")(?![\w-])")
        pre = alts.replace("'", "''")
        # values whose name or data names one of the executables (paths in BAM / MUICache / PCA / firewall rules are
        # value names; Run keys, services, Uninstall, RunMRU hold them in the data)
        rows = con.execute(f"""SELECT v.src, v."key", v.name, v.data, v.raw, v.type, v.op, k.last_write FROM vals v
            LEFT JOIN keys k ON k.src = v.src AND k.path = v."key"
            WHERE v.src NOT IN (SELECT id FROM sources WHERE hive_type = 'amcache')
              AND regexp_matches(coalesce(v.name, '') || ' ' || coalesce(v.data, ''), '({pre})', 'i')""").fetchall()
        # scheduled tasks: the program and arguments are UTF-16 inside the binary Actions value
        tasks = con.execute("""SELECT v.src, v."key", v.raw, k.last_write,
                (SELECT p.data FROM vals p WHERE p.src = v.src AND p."key" = v."key" AND lower(p.name) = 'path' LIMIT 1)
            FROM vals v LEFT JOIN keys k ON k.src = v.src AND k.path = v."key"
            WHERE lower(v.name) = 'actions' AND v.raw IS NOT NULL
              AND regexp_matches(v."key", '(?i)\\\\Schedule\\\\TaskCache\\\\Tasks\\\\')""").fetchall()
        # the product's own key under SOFTWARE (TeamViewer, AnyDesk…) or its Uninstall entry by name
        own = con.execute("""SELECT k.src, k.path, k.last_write,
                (SELECT d.data FROM vals d WHERE d.src = k.src AND d."key" = k.path AND lower(d.name) = 'displayname' LIMIT 1)
            FROM keys k WHERE regexp_matches(k.path,
                '(?i)\\\\Software\\\\(?:WOW6432Node\\\\)?[^\\\\]+$|\\\\CurrentVersion\\\\Uninstall\\\\[^\\\\]+$')""").fetchall()
        arts = con.execute(f"""SELECT src, plugin, ts, "key", summary, entry FROM artifacts
            WHERE regexp_matches(coalesce(summary, '') || ' ' || coalesce(entry, ''), '({pre})', 'i')""").fetchall()
    finally:
        con.close()

    for src, key, name, data, raw, _typ, op, lw in rows:
        text = f"{name or ''} {data or ''}"
        for m in rx_file.finditer(text):
            kind, label = _kind(key)
            when = _filetime(bytes(raw)) if raw is not None and label == "BAM / DAM" else None
            add(files[m.group(1).lower()], {"kind": kind, "where": label, "src": src, "source": labels.get(src, ""),
                                            "key": key, "name": name or "",
                                            "data": f"last run {when}" if when else (data or "")[:300], "time": when or lw,
                                            "path": name if label in ("BAM / DAM", "MUICache", "Compatibility Assistant",
                                                                     "FeatureUsage") else (data or ""),
                                            **({"op": op} if op else {})})
            break
    for src, key, raw, lw, tpath in tasks:
        text = _utf16_strings(bytes(raw))
        m = rx_file.search(text)
        if m:
            add(files[m.group(1).lower()], {"kind": "persistence", "where": "scheduled task", "src": src,
                                            "source": labels.get(src, ""), "key": key, "name": "Actions",
                                            "data": (f"task {tpath}: " if tpath else "") + text[:300], "time": lw,
                                            "path": text, "task": tpath or ""})
    for src, path, lw, display in own:
        seg = path.rsplit("\\", 1)[-1].lower()
        dn = (display or "").lower()
        product = names.get(seg) or next((p for n, p in names.items() if re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", dn)), None)
        if product:
            kind, label = ("installed", "Uninstall") if "\\uninstall\\" in path.lower() else ("installed", "product key")
            add(product, {"kind": kind, "where": label, "src": src, "source": labels.get(src, ""), "key": path,
                          "name": "DisplayName" if display else "", "data": display or "", "time": lw, "path": ""})
    for src, plugin, ts, key, summary, entry in arts:
        if any(x in str(plugin).lower() for x in ("amcache", "bam", "background_activity")):
            continue                               # read from their values above (original name, run time)
        kind, label = _PLUGIN_KIND.get(str(plugin).lower(), ("other", str(plugin)))
        text = f"{summary or ''} {entry or ''}"
        m = rx_file.search(text)
        if not m:
            continue
        try:
            e = json.loads(entry or "{}")
        except ValueError:
            e = {}
        path = next((str(e[k]) for k in ("path", "full_path", "lower_case_long_path", "name", "program_name") if e.get(k)), "")
        add(files[m.group(1).lower()], {"kind": kind, "where": label, "src": src, "source": labels.get(src, ""),
                                        "key": key or plugin, "name": label, "data": (summary or "")[:300], "time": ts,
                                        "path": path or summary or ""})
    return _report(by)


def _report(by: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    hits, findings, iocs = [], [], []
    for product, traces in sorted(by.items()):
        traces.sort(key=lambda t: (str(t.get("time") or "9999"), _RANK.get(t["kind"], 9)))
        portable = [t for t in traces if _USER_DIR.search(str(t.get("path") or "")) and t["kind"] != "installed"]
        renamed = [t for t in traces if t.get("renamed")]
        tasked = [t for t in traces if t["where"] == "scheduled task"]
        kinds = sorted({t["kind"] for t in traces}, key=lambda k: _RANK.get(k, 9))
        why = (["portable (" + str(portable[0]["path"])[:120] + ")"] if portable else []) + \
              (["renamed (" + str(renamed[0]["path"])[:120] + ")"] if renamed else []) + \
              (["launched by a scheduled task" + (f" ({tasked[0]['task']})" if tasked[0].get("task") else "")] if tasked else [])
        severity = "high" if why else "medium"
        items = []
        for t in traces:
            items.append({"src": t["src"], "key": t["key"], "name": t["name"], "data": f"[{t['kind']} · {t['where']}] {t['data']}",
                          "last_write": str(t["time"]) if t.get("time") else None, "source": t["source"], "type": "",
                          **({"op": t["op"]} if t.get("op") else {}),
                          **({"suspicious": True} if t in portable or t in renamed or t in tasked else {})})
        title = f"Remote-access tool {product}: " + ", ".join(kinds)
        rule = "reg_rmm:" + re.sub(r"[^a-z0-9]+", "_", product.lower()).strip("_")   # one per product (the tab keys by rule)
        hits.append({"rule": rule, "title": title, "severity": severity, "attack": ["T1219"], "count": len(items),
                     "suspicious": len(portable) + len(renamed) + len(tasked), "items": items, "product": product})
        firsts = [t for t in traces if t.get("time")]
        when = f" · first {str(firsts[0]['time'])[:16]}, last {str(firsts[-1]['time'])[:16]}" if firsts else ""
        findings.append({"tool": "registry", "rule": rule, "severity": severity,
                         "detail": f"RMM: {product} — " + ", ".join(kinds) + (f" · {'; '.join(why)}" if why else "")
                                   + f" · {len(traces)} trace(s){when} · T1219",
                         "location": f"registry:{traces[0]['source']}",
                         "evidence": "\n".join(f"{str(t.get('time') or '')[:19]:19}  [{t['kind']} · {t['where']}] {t['key']}"
                                               + (f" :: {t['name']}" if t["name"] else "") + (f" = {t['data'][:160]}" if t["data"] else "")
                                               for t in traces[:12])})
        iocs.extend({"location": f"registry:{t['key']}", "text": str(t["path"])} for t in traces if t.get("path"))
    return hits, findings, iocs
