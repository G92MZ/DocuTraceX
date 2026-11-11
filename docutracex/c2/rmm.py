"""Remote monitoring & management (RMM) / remote-access tools inside a file:
installers (MSI, setup EXE), archives' children, scripts.

Legitimate products, abused by intrusions and fake-invoice lures alike: what
matters is *which* product and *whose* instance it calls home to. This reader
names the product from its strings (ASCII and UTF-16) and, when the installer
carries it, the instance it is bound to — the ScreenConnect relay, the Atera
account, the NetSupport gateway, the MeshCentral server, the Tactical RMM API —
the "C2" of a deployment. Static only: nothing is installed or run.

The product list is the built-in one below plus the LOLRMM catalogue
(``docutracex.lolrmm``, refreshed weekly) when it has been downloaded: its file
names, PE metadata, code-signing signers and network domains, matched as whole
strings of the file (so hundreds of products cost one pass).

A product name on its own is reported as *indicators* (an RMM client is no
proof of an intrusion); the instance it is bound to is a configuration.
"""

from __future__ import annotations

import re
from typing import Any

MAX_SCAN = 32 * 1024 * 1024

# name → (strong needles: one is enough; weak needles: two needed; vendor)
PRODUCTS: dict[str, tuple[tuple[str, ...], tuple[str, ...], str]] = {
    "ScreenConnect (ConnectWise Control)": (("screenconnect.clientservice", "screenconnect.windowsclient",
                                             "screenconnect.core", "screenconnect client"), ("screenconnect", "connectwise"),
                                            "ConnectWise"),
    "AnyDesk": (("anydesk.exe", "philandro software", "anydesk software gmbh"), ("anydesk", "anynet"), "AnyDesk Software"),
    "TeamViewer": (("teamviewer_service.exe", "teamviewer germany gmbh", "teamviewer_desktop.exe"), ("teamviewer",),
                   "TeamViewer"),
    "Atera": (("ateraagent", "atera networks", "integratorlogin="), ("atera", "agentpackageupgrader"), "Atera"),
    "NetSupport Manager": (("client32.ini", "netsupport ltd", "pcicfgui.exe", "netsupport manager"), ("client32.exe", "nsm.lic",
                                                                                                    "netsupport"), "NetSupport"),
    "Splashtop": (("splashtop inc", "srservice.exe", "splashtop streamer"), ("splashtop",), "Splashtop"),
    "Remote Utilities": (("rutserv.exe", "rfusclient.exe", "remote utilities llc"), ("remote utilities",), "Remote Utilities"),
    "MeshCentral": (("meshagent.exe", "meshserver=", "meshcentral"), ("meshagent", "meshid="), "MeshCentral (open source)"),
    "Tactical RMM": (("tacticalrmm", "tacticalagent", "tactical rmm"), ("trmm",), "AmidaWare (open source)"),
    "SimpleHelp": (("simplehelp", "simple-help.com"), ("jwrapper",), "SimpleHelp"),
    "RustDesk": (("rustdesk", "custom-rendezvous-server"), ("rendezvous",), "RustDesk (open source)"),
    "Level": (("level.io", "level-agent", "levelagent"), (), "Level"),
    "NinjaOne": (("ninjarmmagent", "ninjaone", "ninjarmm"), (), "NinjaOne"),
    "Datto RMM (CentraStage)": (("centrastage", "cagservice"), ("datto",), "Datto"),
    "N-able (N-central / Take Control)": (("n-able technologies", "basupsrvc", "take control agent"), ("n-able",), "N-able"),
    "Kaseya VSA": (("kaseya", "agentmon.exe"), (), "Kaseya"),
    "Zoho Assist": (("zoho assist", "zohoassist", "zaservice.exe"), (), "Zoho"),
    "GoTo / LogMeIn": (("logmein", "gotoassist", "goto resolve"), (), "GoTo"),
    "PDQ Connect": (("pdq connect", "pdqconnectagent"), (), "PDQ"),
    "ManageEngine Endpoint Central": (("manageengine", "dcagentservice"), (), "Zoho / ManageEngine"),
}

_HOST = r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}\.)+[A-Za-z]{2,24}|(?:\d{1,3}\.){3}\d{1,3}"
# product → [(field, regex with one group)] — the instance the client is bound to
CONFIG: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "ScreenConnect (ConnectWise Control)": [
        ("Relay", re.compile(r"[?&]h=(" + _HOST + r")&p=\d{2,5}")),
        ("Relay port", re.compile(r"[?&]h=(?:" + _HOST + r")&p=(\d{2,5})")),
        ("Session type", re.compile(r"[?&]e=(Access|Support|Meeting)\b")),
        ("Instance", re.compile(r"\b(instance-[a-z0-9]+-relay\.screenconnect\.com)\b", re.I)),
    ],
    "Atera": [("Account e-mail", re.compile(r"IntegratorLogin=([^&\s\"'<>]{3,120}@[^&\s\"'<>]{3,120})")),
              ("Company ID", re.compile(r"CompanyId=(\d{1,10})")),
              ("Account ID", re.compile(r"AccountId=([A-Za-z0-9]{8,64})"))],
    "NetSupport Manager": [("Gateway", re.compile(r"GatewayAddress=([^\r\n\x00\"]{4,200})")),
                           ("Secondary gateway", re.compile(r"SecondaryGateway=([^\r\n\x00\"]{4,200})")),
                           ("Gateway key (GSK)", re.compile(r"GSK=([^\r\n\x00\"]{4,200})"))],
    "MeshCentral": [("Server", re.compile(r"MeshServer=((?:wss?|https?)://[^\s\r\n\x00\"]{4,200})")),
                    ("Mesh name", re.compile(r"MeshName=([^\r\n\x00\"]{1,120})"))],
    "Tactical RMM": [("API", re.compile(r"--api\s+\"?(https?://[^\s\"]{4,200})")),
                     ("Client ID", re.compile(r"--client-id\s+\"?(\d{1,10})")),
                     ("Site ID", re.compile(r"--site-id\s+\"?(\d{1,10})"))],
    "RustDesk": [("Rendezvous server", re.compile(r"(?:custom-rendezvous-server|host)\s*[=:]\s*['\"]?(" + _HOST + r")")),
                 ("Key", re.compile(r"\bkey\s*=\s*['\"]?([A-Za-z0-9+/=]{20,64})"))],
    "AnyDesk": [("Relay", re.compile(r"ad\.anynet\.relay[^=]*=\s*([^\r\n\x00]{4,120})"))],
    "SimpleHelp": [("Server", re.compile(r"(?:serverAddress|server)\s*=\s*((?:https?://)?" + _HOST + r"(?::\d{2,5})?)", re.I))],
}
_SERVER_FIELDS = ("Relay", "Instance", "Gateway", "Secondary gateway", "Server", "API", "Rendezvous server")


def _texts(data: bytes) -> tuple[str, str]:
    """(lower-case search text, original-case text) over ASCII and UTF-16LE."""
    d = data[:MAX_SCAN]
    a = d.decode("latin-1")
    u = ""
    if b"\x00" in d[:4096]:                          # UTF-16 strings, at both alignments
        u = "\n".join(x.decode("utf-16-le", "ignore") for x in (d[: len(d) & ~1], d[1:][: (len(d) - 1) & ~1]))
    t = a + "\n" + u.encode("latin-1", "ignore").decode("latin-1")
    return t.lower(), t


def identify(low: str) -> list[tuple[str, list[str]]]:
    out = []
    for name, (strong, weak, _v) in PRODUCTS.items():
        s = [n for n in strong if n in low]
        w = [n for n in weak if n in low]
        if s or len(w) >= 2:
            out.append((name, s + w))
    return out


_STR = re.compile(r"[\x20-\x7e]{6,}")
_SPLIT = re.compile(r"[\\/\s\"'=,;()<>|*?&\[\]{}]+")


def _tokens(text: str) -> tuple[set[str], set[str]]:
    """(whole printable strings, their pieces), lower-case — for exact lookups."""
    whole = {m.group(0).strip().lower() for m in _STR.finditer(text)}
    pieces = set()
    for w in whole:
        pieces.update(x.strip(".:") for x in _SPLIT.split(w) if len(x) >= 4)
    return whole, pieces


def _builtin_for(name: str) -> str | None:
    low = name.lower()
    for k in PRODUCTS:
        short = k.split(" (")[0].split(" /")[0].lower()
        if low == short or low.startswith(short + " ") or short.startswith(low + " "):
            return k
    return None


def identify_lolrmm(whole: set[str], pieces: set[str], catalogue: dict[str, dict[str, Any]]) -> list[tuple[str, list[str], dict[str, Any]]]:
    """Products of the LOLRMM catalogue: a code-signing signer of the product, a file
    name that carries the product's name, or two of its file names / descriptions /
    domains."""
    out = []
    for name, c in catalogue.items():
        tok = {t for t in re.split(r"[^a-z0-9]+", name.lower()) if len(t) >= 4}
        files = [f for f in c["files"] if f in pieces]
        descs = [d for d in c["descriptions"] if d in whole]
        signers = [x for x in c["signers"] if x.lower() in whole]
        doms = [d for d in c["domains"] if d in pieces or any(p.endswith("." + d) for p in pieces if d in p)]
        # a vendor's domain alone is weak: it shows up in any mail or page that links to the vendor
        strong = signers or [f for f in files if any(t in f for t in tok)]
        if strong or len(set(files) | set(descs) | set(doms)) >= 2:
            out.append((name, [*signers, *doms, *files, *descs][:8], c))
    return out


def extract(data: bytes, filename: str = "") -> list[dict[str, Any]]:
    low, text = _texts(data)
    low_name = filename.lower()
    hits = identify(low + "\n" + low_name)
    lol: dict[str, dict[str, Any]] = {}
    try:
        from .. import lolrmm
        cat = lolrmm.products()
    except Exception:  # noqa: BLE001  (catalogue unreadable: built-in list only)
        cat = None
    if cat:
        whole, pieces = _tokens(text + "\n" + filename)
        for name, why, c in identify_lolrmm(whole, pieces, cat):
            key = _builtin_for(name)
            if key:                                    # a built-in product: its config regexes stay
                cur = next((h for h in hits if h[0] == key), None)
                if cur is None:
                    hits.append((key, why))
                else:
                    cur[1].extend(w for w in why if w not in cur[1])
                lol[key] = {"name": name, **c}
            else:
                hits.append((name, why))
                lol[name] = {"name": name, **c}
    res = []
    for name, why in hits[:4]:
        fields: dict[str, str] = {}
        for field, rx in CONFIG.get(name, []):
            m = rx.search(text) or rx.search(filename)
            if m:
                fields[field] = m.group(1).strip()[:200]
        servers = [fields[f] for f in _SERVER_FIELDS if f in fields]
        hosts = []
        for s in servers:
            h = re.sub(r"^[a-z]+://", "", s).split("/", 1)[0].split(",")[0].strip()
            if field_port := fields.get("Relay port") if s == fields.get("Relay") else "":
                h = f"{h}:{field_port}"
            hosts.append(h)
        lc = lol.get(name) or {}
        vendor = PRODUCTS[name][2] if name in PRODUCTS else (lc.get("website") or "")
        summary: dict[str, Any] = {"Product": name, "Vendor": vendor, **fields,
                                   "Seen": ", ".join(why[:6]),
                                   **({"LOLRMM": f"{lc['name']} ({lc.get('category') or 'RMM'})"} if lc else {}),
                                   "Note": ("legitimate remote-access software: who deployed it, and to whose "
                                            "instance it connects, decides whether it is an intrusion")}
        if hosts:
            summary["C2"] = hosts
        res.append({"family": f"RMM: {name}", "kind": "rmm" if fields else "indicators",
                    "method": "product strings" + (" + installer / launch parameters" if fields else ""),
                    "confidence": "high" if fields else "medium", "summary": summary,
                    "c2": [h.split(":", 1)[0] for h in hosts], "fields": fields,
                    "indicators": [] if fields else why[:10]})
    return res
