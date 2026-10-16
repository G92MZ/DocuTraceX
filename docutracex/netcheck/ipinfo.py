"""IP address enrichment.

Offline first, from databases downloaded at install time into ``tools/ipdb``:

- **DB-IP Lite** (ASN + country, ``.mmdb``) — "IP Geolocation by DB-IP",
  https://db-ip.com, licensed CC BY 4.0.
- **iptoasn.com** ``ip2asn-combined`` (public domain) as a fallback when DB-IP
  has no AS for the address.

Then, online (through the proxy): RDAP for the network (name, owner, CIDR,
abuse contact) and the Tor exit list; reverse DNS (PTR) through the system
resolver. Private, reserved and documentation ranges are never looked up.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import time
from pathlib import Path
from typing import Any

from ..config import settings

ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0; AS fallback: iptoasn.com (public domain)"

# Hosting / cloud / VPS providers often used to host phishing kits and C2.
HOSTING_ASNS = {
    16509: "Amazon AWS", 14618: "Amazon AWS", 15169: "Google", 396982: "Google Cloud", 8075: "Microsoft Azure",
    14061: "DigitalOcean", 16276: "OVH", 24940: "Hetzner", 63949: "Akamai/Linode", 20473: "Vultr/Choopa",
    51167: "Contabo", 13335: "Cloudflare", 45102: "Alibaba Cloud", 132203: "Tencent Cloud", 9009: "M247",
    60781: "Leaseweb", 16265: "Leaseweb", 12876: "Scaleway", 46606: "Unified Layer", 26496: "GoDaddy",
    22612: "Namecheap", 8560: "IONOS", 47583: "Hostinger", 31898: "Oracle Cloud", 53667: "FranTech/BuyVM",
    36352: "ColoCrossing", 55286: "Server Mania", 62904: "Eonix", 211252: "Delis", 399629: "BL Networks",
    44477: "Stark Industries", 210644: "Aeza", 209588: "Flyservers", 49981: "WorldStream", 206264: "Amarutu",
    14576: "Hosting Solution", 30633: "Leaseweb USA", 40021: "Contabo US", 197540: "netcup", 202425: "IP Volume",
}
_HOSTING_WORDS = ("hosting", "cloud", "server", "datacenter", "data center", "vps", "colo", "dedicated")


def _h(accept: str = "application/json") -> dict[str, str]:
    from .http import api_headers
    return api_headers(accept)


def ipdb_dir() -> Path:
    return settings.tools_dir / "ipdb"


def db_status() -> dict[str, Any]:
    d = ipdb_dir()
    files = {"dbip_asn": d / "dbip-asn-lite.mmdb", "dbip_country": d / "dbip-country-lite.mmdb",
             "ip2asn": d / "ip2asn-combined.tsv.gz"}
    out = {k: (time.strftime("%Y-%m-%d", time.localtime(p.stat().st_mtime)) if p.is_file() else None)
           for k, p in files.items()}
    out["attribution"] = ATTRIBUTION
    return out


def _mmdb(name: str, ip: str) -> dict[str, Any] | None:
    p = ipdb_dir() / name
    if not p.is_file():
        return None
    try:
        import maxminddb
        with maxminddb.open_database(str(p)) as r:
            return r.get(ip)
    except Exception:  # noqa: BLE001
        return None


_IP2ASN: tuple[list[int], list[tuple[int, int, str, str]]] | None = None


def _ip2asn(ip: str) -> dict[str, Any] | None:
    global _IP2ASN
    p = ipdb_dir() / "ip2asn-combined.tsv.gz"
    if not p.is_file():
        return None
    if _IP2ASN is None:
        starts, rows = [], []
        with gzip.open(p, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5 or parts[2] == "0":
                    continue
                try:
                    a, b = int(ipaddress.ip_address(parts[0])), int(ipaddress.ip_address(parts[1]))
                except ValueError:
                    continue
                # v4 and v6 share the list: offset v6 so ranges never overlap.
                off = 0 if ":" not in parts[0] else 1 << 40
                starts.append(a + off)
                rows.append((b + off, int(parts[2]), parts[3], parts[4]))
        order = sorted(range(len(starts)), key=starts.__getitem__)
        _IP2ASN = ([starts[i] for i in order], [rows[i] for i in order])
    starts, rows = _IP2ASN
    n = int(ipaddress.ip_address(ip)) + (0 if ":" not in ip else 1 << 40)
    i = bisect.bisect_right(starts, n) - 1
    if i >= 0 and n <= rows[i][0]:
        return {"asn": rows[i][1], "country": rows[i][2], "as_org": rows[i][3]}
    return None


def offline(ip: str) -> dict[str, Any]:
    out: dict[str, Any] = {"asn": None, "as_org": "", "country": "", "source": ""}
    a = _mmdb("dbip-asn-lite.mmdb", ip) or {}
    if a.get("autonomous_system_number"):
        out.update(asn=a["autonomous_system_number"], as_org=a.get("autonomous_system_organization", ""),
                   source="DB-IP Lite")
    c = _mmdb("dbip-country-lite.mmdb", ip) or {}
    country = (c.get("country") or {}).get("iso_code", "")
    names = (c.get("country") or {}).get("names", {})
    out["country"] = country
    out["country_name"] = names.get("es") or names.get("en", "")
    if not out["asn"]:
        fb = _ip2asn(ip)
        if fb:
            out.update(asn=fb["asn"], as_org=fb["as_org"], source="iptoasn")
            out["country"] = out["country"] or fb["country"]
    return out


def rdap_ip(s, ip: str) -> dict[str, Any]:
    try:
        r = s.get(f"https://rdap.org/ip/{ip}", headers=_h("application/rdap+json, application/json"), timeout=(10, 20))
        d = r.json()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}
    org, abuse = "", ""

    def walk(ents):
        nonlocal org, abuse
        for ent in ents or []:
            vc = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
            if "registrant" in ent.get("roles", []) and not org:
                org = next((x[3] for x in vc if x and x[0] == "fn"), "")
            if "abuse" in ent.get("roles", []) and not abuse:
                abuse = next((x[3] for x in vc if x and x[0] == "email"), "")
            walk(ent.get("entities"))
    walk(d.get("entities"))
    cidr = ", ".join(f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in d.get("cidr0_cidrs", []) or [])
    return {"network": d.get("name", ""), "handle": d.get("handle", ""), "range": f"{d.get('startAddress', '')} - {d.get('endAddress', '')}",
            "cidr": cidr, "country": d.get("country", ""), "org": org, "abuse_email": abuse,
            "type": d.get("type", "")}


def ptr(ip: str) -> str:
    try:
        import dns.resolver
        import dns.reversename
        res = dns.resolver.Resolver()
        res.lifetime = 5
        return str(res.resolve(dns.reversename.from_address(ip), "PTR")[0]).rstrip(".")
    except Exception:  # noqa: BLE001
        return ""


def tor_exit(s, ip: str) -> bool | None:
    cache = ipdb_dir() / "tor_exits.txt"
    try:
        if not cache.is_file() or time.time() - cache.stat().st_mtime > 86400:
            r = s.get("https://check.torproject.org/torbulkexitlist", headers=_h("text/plain"), timeout=(10, 20))
            if r.status_code == 200:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(r.text, encoding="utf-8")
        return ip in set(cache.read_text(encoding="utf-8").split())
    except Exception:  # noqa: BLE001
        return None


def check(s, ip: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    out: list[dict[str, Any]] = []
    loc = f"netcheck:ip:{ip}"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "error": "not an IP address"}, out
    data: dict[str, Any] = {"ip": ip, "version": addr.version, "attribution": ATTRIBUTION}
    doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    if any(addr in n for n in doc_nets if n.version == addr.version):
        data["note"] = "documentation range (RFC 5737 / RFC 3849): not looked up"
        return data, out
    if not addr.is_global:
        data["note"] = "private / reserved address: not looked up"
        return data, out
    data["offline"] = offline(ip)
    data["ptr"] = ptr(ip)
    data["rdap"] = rdap_ip(s, ip)
    data["tor_exit"] = tor_exit(s, ip)
    asn = data["offline"].get("asn")
    org = (data["offline"].get("as_org") or "") + " " + (data["rdap"].get("org") or "")
    hosting = HOSTING_ASNS.get(asn or -1) or (org.strip() if any(w in org.lower() for w in _HOSTING_WORDS) else "")
    data["hosting"] = hosting
    if data["tor_exit"]:
        out.append({"tool": "netcheck", "rule": "ip_tor_exit", "severity": "high", "detail": f"{ip} is a Tor exit node",
                    "location": loc, "evidence": "check.torproject.org bulk exit list"})
    if hosting:
        out.append({"tool": "netcheck", "rule": "ip_hosting_provider", "severity": "low",
                    "detail": f"{ip} belongs to a hosting/cloud provider ({hosting}, AS{asn})", "location": loc,
                    "evidence": f"AS{asn} {data['offline'].get('as_org', '')}"})
    return data, out
