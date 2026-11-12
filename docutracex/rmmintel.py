"""RMM / remote-access tools in the IOCs and in the text of a case (LOLRMM).

Three things, all from the LOLRMM catalogue (``docutracex.lolrmm``, refreshed
weekly) plus the built-in list of the C2 ``rmm`` extractor:

* **IOC tags** — a domain / URL on a product's domain, or a file path whose
  executable is one of the product's files, gets ``rmm = {product, …}``. It is
  context only: the IOC is not raised or scored, the software is legitimate.
* **Mentions** — the product's *name* in the text of a document, email or script
  ("download AnyDesk and send me your ID") is a finding ``rmm:mention``, one per
  product (its strongest context, every place listed): *info* for the name alone, *low* next to install / run /
  ID / password words, *medium* next to a link or file that is its installer.
  Not repeated when the C2 extractor already found that product bound to an
  instance (``c2:rmm`` says more).

* **Objects** — every analysed object (original, extracted, nested) goes
  through the C2 ``rmm`` extractor in every IOC extraction, so an RMM client
  or a trojanised installer shows up without running C2: the product, and the
  instance it is bound to (relay, account, gateway…), whose hosts join the IOCs.
  The finding is the C2 one (``c2:rmm``, same id), so running C2 later does not
  duplicate it; once C2 has run, its card owns the product.

Names that are ordinary words (Level, Remote PC, Atlas…) are never matched on
their own; names shorter than 6 characters need two words.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .logging_config import get_logger

log = get_logger(__name__)

MAX_FINDINGS = 50
_WINDOW = 220            # where its installer may be named
_NEAR = 120              # where install / ID / password words count
# product names that are ordinary words or phrases (never matched as a mention)
_GENERIC_NAMES = {
    "level", "remote pc", "remote desktop", "remote access", "remote utilities", "remote support", "access",
    "atlas", "connect", "support", "helpdesk", "help desk", "assist", "control", "desktop", "viewer", "action",
    "beyond", "meeting", "screen", "pulse", "bomgar", "domotz", "kickidler", "syncro", "ammyy", "goverlan",
    "chrome remote desktop", "microsoft remote desktop", "quick assist", "windows remote assistance",
    "remote desktop connection", "rdp", "vnc", "ssh", "netop", "radmin", "dameware", "naverisk", "fixme",
    "parsec", "mikogo", "rport", "comodo", "itarian", "sophos", "manageengine", "solarwinds", "zoho", "kaseya",
    "connectwise", "n-able", "goto", "logmein", "pdq", "datto", "auvik", "addigy", "jumpcloud", "action1",
    "airdroid", "anyplace control", "teamdesk", "showmypc", "supremo", "tightvnc", "ultravnc", "realvnc",
    # ordinary words / vendors of unrelated products
    "remotely", "absolute", "overlord", "centurion", "borealis", "basecamp", "barracuda", "roster", "beacon",
    "fortra", "rapid7", "insync", "idrive", "it agent", "take control", "remote ripple", "netmaster", "runsmart",
    "electric ai", "adobe connect", "pocket cloud", "royal apps", "setme pro", "trustconnect", "echoware",
}
_ACTION = re.compile(r"(?i)\b(?:instal\w*|descarg\w*|download\w*|ejecut\w*|run\b|abr[ae]\w*|open\b|conect\w*|connect\w*"
                     r"|setup)\b")
_SECRET = re.compile(r"(?i)\b(?:id|código|codigo|code|password|contraseña|clave|pin)\b\W{0,12}[\d ]{6,14}")
# modules whose text is the app's own reading of an RMM (C2 card, YARA rule names)
_SKIP_MODULES = {"c2", "yara", "rmm", "domainsim", "ml"}


def _builtin() -> dict[str, dict[str, Any]]:
    """The C2 extractor's built-in products as catalogue entries (name → files, domains)."""
    from .c2 import rmm
    vendor_domains = {"ScreenConnect (ConnectWise Control)": ["screenconnect.com"], "AnyDesk": ["anydesk.com", "net.anydesk.com"],
                      "TeamViewer": ["teamviewer.com"], "Atera": ["atera.com", "ateraagent.com"],
                      "Splashtop": ["splashtop.com"], "RustDesk": ["rustdesk.com"], "SimpleHelp": ["simple-help.com"],
                      "NinjaOne": ["ninjarmm.com", "ninjaone.com"], "Zoho Assist": ["zohoassist.com"],
                      "Tactical RMM": [], "MeshCentral": ["meshcentral.com"]}
    out = {}
    for name, (strong, _weak, vendor) in rmm.PRODUCTS.items():
        out[name] = {"category": "RMM", "website": vendor, "domains": vendor_domains.get(name, []),
                     "files": [s for s in strong if s.endswith(".exe")], "builtin": True}
    return out


def catalogue() -> dict[str, dict[str, Any]]:
    """Built-in products, merged with LOLRMM when it has been downloaded."""
    cat = _builtin()
    try:
        from . import lolrmm
        from .c2.rmm import _builtin_for
        lol = lolrmm.products() or {}
    except Exception as exc:  # noqa: BLE001  (catalogue unreadable: built-in only)
        log.warning("LOLRMM catalogue unreadable: %s", exc)
        return cat
    for name, c in lol.items():
        key = _builtin_for(name) or name
        cur = cat.setdefault(key, {"category": c.get("category") or "RMM", "website": c.get("website") or "",
                                   "domains": [], "files": []})
        cur["lolrmm"] = name
        cur["domains"] = sorted(set(cur["domains"]) | set(c.get("domains") or []))
        cur["files"] = sorted(set(cur["files"]) | set(c.get("files") or []))
    return cat


def _host(v: str) -> str:
    v = v.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    return v.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].strip(".")


def _tag(product: str, c: dict[str, Any], why: str) -> dict[str, Any]:
    t = {"product": product, "category": c.get("category") or "RMM", "why": why}
    if c.get("lolrmm"):
        t["lolrmm"] = c["lolrmm"]
    return t


def tag_iocs(ioc_result: dict[str, Any], cat: dict[str, dict[str, Any]] | None = None) -> int:
    """Adds ``rmm`` to the domain / URL / file-path / command IOCs of a product. Returns how many."""
    cat = catalogue() if cat is None else cat
    by_domain: dict[str, str] = {}
    by_file: dict[str, str] = {}
    for name, c in cat.items():
        for d in c.get("domains") or []:
            by_domain.setdefault(d, name)
        for f in c.get("files") or []:
            by_file.setdefault(f.lower(), name)
    n = 0
    for i in ioc_result.get("iocs") or []:
        t, v = i.get("type"), str(i.get("value") or "")
        hit, why = None, ""
        if t in ("domain", "url"):
            h = _host(v)
            labels = h.split(".")
            for k in range(len(labels) - 1):
                d = ".".join(labels[k:])
                if d in by_domain:
                    hit, why = by_domain[d], f"domain {d}"
                    break
            if hit is None and t == "url":
                base = re.split(r"[/?#]", v.split("://", 1)[-1])
                f = next((x.lower() for x in base if x.lower() in by_file), None)
                if f:
                    hit, why = by_file[f], f"file {f}"
        elif t in ("filepath", "command"):
            for tok in re.split(r"[\\/\s\"']+", v.lower()):
                if tok in by_file:
                    hit, why = by_file[tok], f"file {tok}"
                    break
        if hit:
            i["rmm"] = _tag(hit, cat[hit], why)
            n += 1
    return n


def _names(cat: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Matchable name (lower-case) → product."""
    out: dict[str, str] = {}
    for name, c in cat.items():
        cands = {name, name.split(" (")[0], c.get("lolrmm") or ""}
        for m in re.finditer(r"\(([^)]+)\)", name):       # "ScreenConnect (ConnectWise Control)", "(aka …)"
            cands.add(m.group(1).removeprefix("aka ").strip())
        for x in list(cands):
            cands.update(p.strip() for p in x.split(" / "))
        for x in cands:
            low = x.strip().lower()
            if low.startswith(("now ", "formerly ", "also known as ", "aka ")) or low.count("(") != low.count(")"):
                continue
            if not low or low in _GENERIC_NAMES or (len(low) < 6 and " " not in low):
                continue
            if not re.search(r"[a-z]", low) or len(low) > 60:
                continue
            out.setdefault(low, name)
    return out


def mentions(sources: list[dict[str, Any]], c2_result: dict[str, Any] | None = None,
             cat: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Findings ``rmm:mention`` from the text the case's modules extracted."""
    cat = catalogue() if cat is None else cat
    names = _names(cat)
    res: dict[str, Any] = {"module": "rmm", "status": "ok", "products": len(cat),
                           "source": "LOLRMM + built-in" if any(c.get("lolrmm") for c in cat.values()) else "built-in",
                           "mentions": [], "findings": []}
    if not names:
        return res
    rx = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
                    + r")(?![\w-])", re.IGNORECASE)
    # the C2 extractor already found the product bound to an instance: c2:rmm says more
    bound = {str(c.get("family") or "")[5:] for c in (c2_result or {}).get("configs") or []
             if str(c.get("family") or "").startswith("RMM: ") and c.get("c2")}
    seen: dict[str, dict[str, Any]] = {}
    rank = {"info": 0, "low": 1, "medium": 2}
    for s in sources:
        if s.get("module") in _SKIP_MODULES:
            continue
        text = s.get("text") or ""
        if not text or len(text) > 20 * 1024 * 1024:
            continue
        for m in rx.finditer(text):
            product = names[m.group(1).lower()]
            if product in bound:
                continue
            win = text[max(0, m.start() - _WINDOW):m.end() + _WINDOW]
            near = text[max(0, m.start() - _NEAR):m.end() + _NEAR]
            low_win = win.lower()
            token = re.sub(r"[^a-z0-9]", "", m.group(1).lower())
            own_file = any(f in low_win for f in cat[product].get("files") or [])
            # its installer: one of its own files, a link whose file carries its name, or ScreenConnect's guest link
            own_link = any(token and token in re.sub(r"[^a-z0-9]", "", u.group(0).lower())
                           for u in re.finditer(r"(?i)\S+\.(?:exe|msi|zip|dmg|pkg)\b", win))
            if own_file or own_link or re.search(r"(?i)[?&]e=(?:access|support)&|clientsetup\.\w{3}", win):
                sev, why = "medium", "next to a link or file that installs it"
            elif _SECRET.search(near) or _ACTION.search(near):
                sev, why = "low", "next to install / run / ID / password words"
            else:
                sev, why = "info", "name only"
            # one finding per product: the strongest context, every place it was seen
            loc = f"{s.get('module')}/{s.get('location')}" if s.get("module") else str(s.get("location") or "")
            cur = seen.get(product)
            snippet = (near if sev != "medium" else win).replace("\n", " ").strip()[:300]
            if cur is None:
                seen[product] = cur = {"product": product, "location": loc, "locations": [],
                                       "severity": sev, "why": why, "count": 0, "snippet": snippet}
            elif rank[sev] > rank[cur["severity"]]:
                cur.update(severity=sev, why=why, snippet=snippet, location=loc)
            if loc not in cur["locations"] and len(cur["locations"]) < 10:
                cur["locations"].append(loc)
            cur["count"] += 1
    for m in sorted(seen.values(), key=lambda x: -rank[x["severity"]])[:MAX_FINDINGS]:
        c = cat[m["product"]]
        res["mentions"].append(m)
        res["findings"].append({
            "tool": "rmm", "rule": "rmm:mention", "severity": m["severity"],
            "detail": f"Remote-access tool mentioned: {m['product']} ({m['why']})",
            "location": m["location"],
            "evidence": (f"{m['count']} mention(s) in {len(m['locations'])} place(s); "
                         + (f"LOLRMM: {c['lolrmm']}; " if c.get("lolrmm") else "")
                         + f"…{m['snippet']}…")[:1500]})
    return res


def scan_objects(original: Path, extracted_dir: Path) -> list[dict[str, Any]]:
    """The C2 rmm extractor over every object of the case (the original first)."""
    from . import c2
    from .c2 import rmm
    out: list[dict[str, Any]] = []
    seen: dict[str, dict[str, Any]] = {}
    for label, path, stored in c2._targets(original, extracted_dir):
        try:
            if path.stat().st_size > c2.MAX_SIZE:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        for cfg in rmm.extract(data, path.name):
            cur = seen.get(cfg["family"])
            if cur is not None:                       # one per product: the one bound to an instance wins
                if cfg.get("c2") and not cur.get("c2"):
                    out.remove(cur)
                else:
                    cur.setdefault("also_in", []).append(label)
                    continue
            cfg["object"], cfg["stored_path"] = label, stored
            seen[cfg["family"]] = cfg
            out.append(cfg)
    return out


def _ioc_type(h: str) -> str:
    return "ipv4" if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", h) else "domain"


def objects_step(original: Path, extracted_dir: Path, ioc_result: dict[str, Any],
                 c2_result: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(configs, findings) for the RMM products in the objects; adds their instance hosts to the IOCs."""
    from . import c2
    from .findings import finding_id
    owned = {str(c.get("family") or "") for c in (c2_result or {}).get("configs") or []}
    cfgs = [c for c in scan_objects(original, extracted_dir) if c["family"] not in owned]
    findings = []
    have = {(i.get("type"), i.get("value")) for i in ioc_result.get("iocs") or []}
    c2_rmm = [c for c in (c2_result or {}).get("configs") or [] if str(c.get("family") or "").startswith("RMM: ")]
    for c in cfgs + c2_rmm:
        if c in cfgs:
            f = c2._finding(c)
            c["finding_id"] = finding_id(f["tool"], f["rule"], f["location"], f["detail"])
            findings.append(f)
        tag = {"product": c["family"][5:], "category": "RMM", "why": "instance the client is bound to"}
        for h in c.get("c2") or []:
            t = _ioc_type(h)
            if (t, h) in have:                         # already mined from the text: tag it
                for i in ioc_result.get("iocs") or []:
                    if i.get("type") == t and i.get("value") == h:
                        i["rmm"] = tag
                continue
            if c not in cfgs:                          # C2's own configuration: its hosts are already IOCs
                continue
            have.add((t, h))
            ioc_result.setdefault("iocs", []).append({
                "type": t, "value": h, "count": 1,
                "occurrences": [{"module": "rmm", "location": c["object"],
                                 "context": f"{c['family'][5:]} instance ({c.get('method')})"}],
                "rmm": tag})
            counts = ioc_result.setdefault("counts", {})
            counts[t] = counts.get(t, 0) + 1
            counts["total"] = counts.get("total", 0) + 1
    return cfgs, findings
