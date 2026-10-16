"""Domain checks that never touch the attacker's servers.

- DNS (A/AAAA/CNAME/MX/NS/TXT) through the system resolver.
- RDAP (the modern WHOIS) via rdap.org: registrar, creation/expiry dates,
  status, name servers -> domain age.
- Certificate Transparency (crt.sh): first certificate seen and the other
  names issued with it (subdomains of the same kit).

RDAP and crt.sh go through the configured proxy. Reserved names (``.example``,
``.test``, ``.invalid``, ``.localhost``) are not looked up.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

RESERVED_TLDS = ("example", "test", "invalid", "localhost", "local")
_RTYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def _h(accept: str = "application/json") -> dict[str, str]:
    from .http import api_headers
    return api_headers(accept)


def registrable(host: str) -> str:
    try:
        import tldextract
        ext = tldextract.TLDExtract(suffix_list_urls=())(host)  # bundled list, no download
        return ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    except Exception:  # noqa: BLE001
        parts = host.split(".")
        return ".".join(parts[-2:])


def is_reserved(host: str) -> bool:
    return host.rstrip(".").rsplit(".", 1)[-1].lower() in RESERVED_TLDS


def dns_records(host: str) -> dict[str, Any]:
    import dns.resolver

    res = dns.resolver.Resolver()
    res.lifetime = 6
    out: dict[str, Any] = {"records": {}, "nxdomain": False, "error": None}
    for rt in _RTYPES:
        try:
            ans = res.resolve(host, rt)
            out["records"][rt] = [a.to_text().strip('"')[:300] for a in ans][:20]
        except dns.resolver.NXDOMAIN:
            out["nxdomain"] = True
            break
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"{exc.__class__.__name__}: {str(exc)[:200]}"
    return out


def _date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def rdap_domain(s, domain: str) -> dict[str, Any]:
    try:
        r = s.get(f"https://rdap.org/domain/{domain}", headers=_h("application/rdap+json, application/json"), timeout=(10, 20))
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}
    if r.status_code == 404:
        return {"error": "not found in RDAP (unregistered, or a registry without RDAP)"}
    # rev: sJkzUVgDiA
    try:
        d = r.json()
    except ValueError:
        return {"error": f"HTTP {r.status_code}, not RDAP JSON"}
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", []) or []}
    registrar = ""
    abuse = ""
    for ent in d.get("entities", []) or []:
        roles = ent.get("roles", [])
        vc = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
        fn = next((x[3] for x in vc if x and x[0] == "fn"), "")
        if "registrar" in roles:
            registrar = fn or ent.get("handle", "")
            for sub in ent.get("entities", []) or []:
                if "abuse" in sub.get("roles", []):
                    svc = sub.get("vcardArray", [None, []])[1]
                    abuse = next((x[3] for x in svc if x and x[0] == "email"), abuse)
    created = _date(ev.get("registration"))
    age = (datetime.now(timezone.utc) - created).days if created else None
    return {"registrar": registrar, "abuse_email": abuse, "created": ev.get("registration"),
            "expires": ev.get("expiration"), "updated": ev.get("last changed"), "age_days": age,
            "status": d.get("status", [])[:10],
            "nameservers": [n.get("ldhName", "") for n in d.get("nameservers", []) or []][:10]}


# gmzpt
def _issuer_org(dn: str) -> str:
    m = re.search(r'O=(?:"([^"]+)"|([^,]+))', dn)
    return (m.group(1) or m.group(2)).strip() if m else ""


def crtsh(s, domain: str) -> dict[str, Any]:
    try:
        r = s.get("https://crt.sh/", params={"q": domain, "output": "json"}, headers=_h(), timeout=(10, 30))
        rows = r.json() if r.status_code == 200 else []
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}
    if not rows:
        return {"count": 0, "first_seen": None, "names": []}
    firsts = sorted(x.get("not_before", "") for x in rows if x.get("not_before"))
    names: set[str] = set()
    for x in rows:
        for n in str(x.get("name_value", "")).split("\n"):
            if n:
                names.add(n.lower())
    first = firsts[0] if firsts else None
    first_dt = _date(first + "+00:00" if first and "+" not in first else first)
    age = (datetime.now(timezone.utc) - first_dt).days if first_dt else None
    issuers = sorted({_issuer_org(str(x.get("issuer_name", ""))) for x in rows} - {""})[:8]
    return {"count": len(rows), "first_seen": first, "first_seen_days": age, "names": sorted(names)[:60],
            "issuers": issuers}


def check(s, host: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run every domain check. Returns (data, findings)."""
    from ..parsers.mail_rules import check_domain

    host = host.lower().rstrip(".")
    reg = registrable(host)
    data: dict[str, Any] = {"host": host, "registrable": reg}
    out: list[dict[str, Any]] = []
    loc = f"netcheck:domain:{host}"

    def add(rule, sev, detail, evidence=""):
        out.append({"tool": "netcheck", "rule": rule, "severity": sev, "detail": detail, "location": loc,
                    "evidence": evidence})

    for rule, sev, why in check_domain(host):
        add(rule, sev, why, host)
    if is_reserved(host):
        data["note"] = "reserved documentation/test name: not looked up"
        return data, out
    data["dns"] = dns_records(host)
    if data["dns"]["nxdomain"]:
        add("domain_nxdomain", "info", f"{host} does not resolve (taken down, or never configured)")
    data["rdap"] = rdap_domain(s, reg)
    age = data["rdap"].get("age_days")
    if age is not None and age < 30:
        add("domain_newly_registered", "high", f"{reg} was registered {age} day(s) ago", data["rdap"].get("created", ""))
    elif age is not None and age < 180:
        add("domain_recently_registered", "medium", f"{reg} was registered {age} days ago", data["rdap"].get("created", ""))
    if data["dns"]["nxdomain"] and "error" in data["rdap"]:
        data["ct"] = {"note": "skipped: the domain does not exist"}
        return data, out
    data["ct"] = crtsh(s, reg)
    fs = data["ct"].get("first_seen_days")
    if fs is not None and fs < 30 and not (age is not None and age < 30):
        add("domain_new_certificates", "medium", f"First certificate for {reg} issued {fs} day(s) ago",
            data["ct"].get("first_seen") or "")
    return data, out
