"""Family YARA: name the malware family of an object with the rule sets that do
that best, downloaded and kept current — never shipped with DocuTraceX.

* **CAPE** (kevoreilly/CAPEv2, ``data/yara/CAPE``, GPL-3.0): the rules CAPE uses
  to pick a configuration extractor; one per family, written against the
  unpacked payload (Formbook, GuLoader, Lumma, Latrodectus, BumbleBee, Pure…).
* **ditekSHen** (ditekshen/detection, ``yara/malware.yar``, BSD-2-Clause):
  ~500 ``MALWARE_*`` family rules, strong on commodity RATs and stealers.

They are downloaded into ``tools/c2rules/`` (GitHub; ``GITHUB_TOKEN`` lifts the
API rate limit) and refreshed weekly in the background; the C2 view has
*Refresh now*. Each file is compiled on its own on first use, so a rule that
needs a module this YARA lacks costs only that file. The C2 analysis runs them
on every object: a hit names the family (an *indicators* entry, or the
corroboration of a configuration an extractor recovered).

A tiny built-in rule set (``builtin``) holds only the marker of the inert sample,
so the feature can be exercised offline.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from ..config import settings
from ..logging_config import get_logger

log = get_logger(__name__)

SOURCES: dict[str, dict[str, Any]] = {
    "cape": {"name": "CAPE", "repo": "kevoreilly/CAPEv2", "branch": "master", "dir": "data/yara/CAPE",
             "licence": "GPL-3.0", "url": "https://github.com/kevoreilly/CAPEv2/tree/master/data/yara/CAPE"},
    "ditekshen": {"name": "ditekSHen", "repo": "ditekshen/detection", "branch": "master",
                  "files": ["yara/malware.yar"], "licence": "BSD-2-Clause",
                  "url": "https://github.com/ditekshen/detection/tree/master/yara"},
}
MAX_AGE = 7 * 86400
_RULE_EXT = (".yar", ".yara")
# the inert sample's marker: the only built-in rule (DocuTraceX's own, Apache-2.0)
BUILTIN = '''rule DocuTraceX_Sample_FacturaLoader
{
    meta:
        description = "DocuTraceX inert sample: invoice loader marker (not real malware)"
        family = "FacturaLoader (sample)"
    strings:
        $m1 = "DTX-SAMPLE-FAMILY-YARA" ascii wide
        $m2 = "FacturaLoader" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
'''

_lock = threading.Lock()
_loaded: dict[str, Any] = {"key": None, "rules": None}


def base() -> Path:
    return settings.tools_dir / "c2rules"


def _compiled() -> Path:
    return base() / "compiled.yarc"


def _report() -> Path:
    return base() / "compiled.json"


def _meta() -> Path:
    return base() / "sources.json"


def _read(p: Path) -> dict[str, Any]:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def rule_files() -> list[tuple[str, Path]]:
    """(source, file) of every downloaded rule file, plus the built-in one."""
    out = []
    for src in SOURCES:
        d = base() / src
        if d.is_dir():
            out += [(src, p) for p in sorted(d.iterdir()) if p.suffix.lower() in _RULE_EXT]
    b = base() / "builtin.yar"
    if not b.is_file() or b.read_text(encoding="utf-8") != BUILTIN:
        try:
            b.parent.mkdir(parents=True, exist_ok=True)
            b.write_text(BUILTIN, encoding="utf-8")
        except OSError:
            return out
    return out + [("builtin", b)]


def status() -> dict[str, Any]:
    meta, rep = _read(_meta()), _read(_report())
    srcs = []
    for k, s in SOURCES.items():
        m = meta.get(k) or {}
        d = base() / k
        n = sum(1 for p in d.iterdir() if p.suffix.lower() in _RULE_EXT) if d.is_dir() else 0
        srcs.append({"id": k, "name": s["name"], "licence": s["licence"], "url": s["url"], "files": n,
                     "updated": m.get("updated"), "error": m.get("error", "")})
    return {"sources": srcs, "downloaded": any(s["files"] for s in srcs),
            "rules": rep.get("rule_count"), "compile_errors": len(rep.get("errors") or []),
            "compiled_utc": rep.get("compiled_utc")}


# --------------------------------------------------------------------------- download

def _token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def _get(url: str, proxy: str | None, timeout: int = 60, api: bool = False) -> bytes:
    from ..mailintel import _routes, _short
    headers = {"User-Agent": "DocuTraceX"}
    if api:
        headers["Accept"] = "application/vnd.github+json"
        if _token():
            headers["Authorization"] = f"Bearer {_token()}"
    errors = []
    for label, opener in _routes(proxy):
        try:
            with opener.open(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
                return r.read(32 * 1024 * 1024)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{label}: {_short(exc)}")
    raise ConnectionError(f"{url.split('/')[2]}: " + "; ".join(errors))


def _files_of(src: dict[str, Any], proxy: str | None) -> list[str]:
    if "files" in src:
        return list(src["files"])
    api = f"https://api.github.com/repos/{src['repo']}/contents/{src['dir']}?ref={src['branch']}"
    try:
        listing = json.loads(_get(api, proxy, api=True))
    except ConnectionError as exc:
        hint = "" if _token() else " (GitHub API limit? set GITHUB_TOKEN)"
        raise ConnectionError(f"{exc}{hint}") from exc
    return [f"{src['dir']}/{e['name']}" for e in listing
            if isinstance(e, dict) and e.get("type") == "file" and e.get("name", "").lower().endswith(_RULE_EXT)]


def download(proxy: str | None = None, only: str | None = None) -> dict[str, Any]:
    """Fetch the rule sets (all, or ``only`` one) into ``tools/c2rules/<source>/``.
    A source that fails keeps its previous copy; the compiled set is rebuilt on next use."""
    meta = _read(_meta())
    ok = 0
    for key, src in SOURCES.items():
        if only and key != only:
            continue
        try:
            names = _files_of(src, proxy)
            if not names:
                raise ValueError("no rule files listed")
            got: dict[str, bytes] = {}
            for rel in names:
                url = f"https://raw.githubusercontent.com/{src['repo']}/{src['branch']}/{rel}"
                got[Path(rel).name] = _get(url, proxy)
            d = base() / key
            tmp = base() / f".{key}.tmp"
            tmp.mkdir(parents=True, exist_ok=True)
            for p in tmp.iterdir():
                p.unlink()
            for n, b in got.items():
                if re.fullmatch(r"[\w.\-]+", n):
                    (tmp / n).write_bytes(b)
            if d.is_dir():
                for p in d.iterdir():
                    p.unlink()
                d.rmdir()
            tmp.rename(d)
            meta[key] = {"updated": time.strftime("%Y-%m-%d %H:%M"), "files": len(got), "error": ""}
            ok += 1
        except Exception as exc:  # noqa: BLE001  (the other source still updates)
            meta.setdefault(key, {})["error"] = str(exc)[:300]
            log.warning("family YARA %s not updated: %s", key, exc)
    base().mkdir(parents=True, exist_ok=True)
    _meta().write_text(json.dumps(meta, indent=2), encoding="utf-8")
    if not ok:
        raise ConnectionError("; ".join(f"{k}: {v.get('error')}" for k, v in meta.items() if v.get("error")))
    return status()


def stale() -> bool:
    meta = _read(_meta())
    try:
        newest = max((base() / k).stat().st_mtime for k in SOURCES if (base() / k).is_dir())
    except ValueError:
        return True
    return time.time() - newest > MAX_AGE or not meta


def refresh_in_background(proxy: str | None = None) -> None:
    if not stale():
        return

    def run() -> None:
        try:
            download(proxy)
            log.info("family YARA rules updated")
        except Exception as exc:  # noqa: BLE001
            log.warning("family YARA rules not updated: %s", exc)
    threading.Thread(target=run, name="c2rules-refresh", daemon=True).start()


# --------------------------------------------------------------------------- compile / match

def _snapshot(files: list[tuple[str, Path]]) -> str:
    return "|".join(f"{s}/{p.name}:{p.stat().st_size}:{int(p.stat().st_mtime)}" for s, p in files)


def ensure_compiled() -> dict[str, Any]:
    """Compile the rule files when they changed since the last compilation (each file on
    its own first: a broken or unsupported one is skipped and reported). Needs yara-python
    (the portable Python, where the analysis runs)."""
    try:
        import yara
    except ImportError:
        return {"error": "yara-python not available"}
    files = rule_files()
    snap = _snapshot(files)
    rep = _read(_report())
    if rep.get("snapshot") == snap and _compiled().is_file():
        return rep
    ok: dict[str, str] = {}
    errors = []
    for src, p in files:
        ns = f"{src}__{re.sub(r'[^A-Za-z0-9_]', '_', p.stem)}"
        try:
            yara.compile(filepath=str(p))
            ok[ns] = str(p)
        except Exception as exc:  # noqa: BLE001
            errors.append({"file": f"{src}/{p.name}", "error": str(exc)[:200]})
    count = 0
    if ok:
        rules = yara.compile(filepaths=ok)
        tmp = _compiled().with_suffix(".tmp")
        rules.save(str(tmp))
        tmp.replace(_compiled())
        count = sum(1 for _ in rules)
    rep = {"snapshot": snap, "rule_count": count, "errors": errors,
           "compiled_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _report().write_text(json.dumps(rep), encoding="utf-8")
    return rep


def _rules() -> Any:
    if not _compiled().is_file():                 # first use without a C2 run (a single object)
        try:
            ensure_compiled()
        except Exception as exc:  # noqa: BLE001
            log.warning("family YARA rules not compiled: %s", exc)
    try:
        import yara
        st = _compiled().stat()
    except (ImportError, OSError):
        return None
    key = (st.st_size, st.st_mtime)
    with _lock:
        if _loaded["key"] != key:
            try:
                _loaded.update(key=key, rules=yara.load(str(_compiled())))
            except Exception as exc:  # noqa: BLE001
                log.warning("family YARA rules not loadable: %s", exc)
                _loaded.update(key=key, rules=None)
        return _loaded["rules"]


def available() -> bool:
    return _compiled().is_file()


# family names: our own where they match, else the rule's own name, tidied
_PREFIX = re.compile(r"^(?:MALWARE|INDICATOR|HUNT)_(?:Win|Linux|Lnx|Osx|MacOS|Multi|Android|Py|PS|JS|Doc)?_?",
                     re.IGNORECASE)
_SUFFIX = re.compile(r"(?:_?v\d+[a-z]?|_(?:payload|loader|stage\d?|dropper|config|beacon|stager|downloader|"
                     r"unpacked|packed|plugin|module|dll|exe|x64|x86|\d+))+$", re.IGNORECASE)
# names the rule sets spell differently from ours
_ALIASES = {"purelogsstealer": "Pure family", "purelogs": "Pure family", "purehvnc": "Pure family",
            "purecrypter": "Pure family", "purerat": "Pure family", "pureminer": "Pure family",
            "cobaltstrikebeacon": "Cobalt Strike", "cobaltstrikestager": "Cobalt Strike", "bumblebee": "Bumblebee",
            "brc4": "Brute Ratel C4", "bruteratel": "Brute Ratel C4", "havoc": "Havoc (Demon)", "demon": "Havoc (Demon)",
            "warzonerat": "Warzone / AveMaria", "avemaria": "Warzone / AveMaria", "redline": "RedLine / META",
            "redlinestealer": "RedLine / META", "metastealer": "RedLine / META", "snakekeylogger": "Snake Keylogger",
            "404keylogger": "Snake Keylogger", "raccoon": "Raccoon Stealer v2", "raccoonstealer": "Raccoon Stealer v2",
            "quasar": "QuasarRAT", "venomrat": "AsyncRAT", "metasploit": "Metasploit / Meterpreter",
            "meterpreter": "Metasploit / Meterpreter", "qakbot": "QakBot", "guloader": "GuLoader"}


def _key(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def family_name(rule: str, meta: dict[str, Any]) -> str:
    """CAPE's ``cape_type`` / the rule name, ditekSHen's ``MALWARE_Win_X``: ours where it matches."""
    if meta.get("family"):
        return str(meta["family"])
    raw = str(meta.get("cape_type") or rule)
    raw = re.sub(r"(?i)\s+(payload|loader|config|beacon|stager)$", "", raw.strip())   # CAPE's "Formbook Payload"
    raw = _SUFFIX.sub("", _PREFIX.sub("", raw)) or raw
    k = _key(raw)
    if k in _ALIASES:
        return _ALIASES[k]
    from . import FAMILIES
    for fam in FAMILIES:
        fk = _key(fam.split(" /")[0].split(" (")[0])
        if len(k) >= 4 and len(fk) >= 4 and (fk.startswith(k) or k.startswith(fk)):
            return fam
    pretty = raw.replace("_", " ").strip()
    return pretty[:1].upper() + pretty[1:]


def extract(data: bytes) -> list[dict[str, Any]]:
    """One *indicators* entry per family the rules name in ``data``."""
    rules = _rules()
    if rules is None or not data:
        return []
    try:
        matches = rules.match(data=data, timeout=60)
    except Exception as exc:  # noqa: BLE001
        log.warning("family YARA scan failed: %s", exc)
        return []
    by_fam: dict[str, list[dict[str, Any]]] = {}
    for m in matches:
        src = str(m.namespace).split("__", 1)[0]
        meta = dict(getattr(m, "meta", {}) or {})
        fam = family_name(m.rule, meta)
        name = SOURCES.get(src, {}).get("name") or ("DocuTraceX built-in" if src == "builtin" else src)
        by_fam.setdefault(fam, []).append({"source": name, "rule": m.rule,
                                           "description": str(meta.get("description") or "")[:160]})
    out = []
    for fam, hits in by_fam.items():
        srcs = sorted({h["source"] for h in hits})
        named = [f"{h['source']}: {h['rule']}" + (f" — {h['description']}" if h["description"] else "")
                 for h in hits]
        strong = "CAPE" in srcs or len(srcs) > 1 or "DocuTraceX built-in" in srcs
        out.append({"family": fam, "kind": "indicators", "method": "family YARA",
                    "confidence": "medium" if strong else "low", "status": "identified by YARA",
                    "c2": [], "fields": {}, "indicators": named, "yara": hits,
                    "summary": {"YARA": named, "Sources": ", ".join(srcs),
                                "Configuration": "not read (no extractor for it, or it found nothing here)"},
                    "note": f"{fam} named by {' and '.join(srcs)} YARA rules."})
    return out
