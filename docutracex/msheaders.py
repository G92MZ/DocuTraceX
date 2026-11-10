"""Microsoft 365 / Exchange Online headers, decoded (static).

Values follow Microsoft's documentation ("Anti-spam message headers in
Microsoft 365", Microsoft Learn; "Demystifying hybrid mail flow", Exchange Team
blog). Fields Microsoft does not document (dest, OFR, RF in
X-Microsoft-Antispam-Mailbox-Delivery, SCL meaning in the cloud…) are shown as
raw values with that caveat — never as facts. The full inventory, with DFIR use,
forgery notes and correlations, is in ``docs/microsoft-headers.md``.

Trust: headers above the receiving tenant's own stamps can be written by the
sender. Exchange Online strips ``X-MS-Exchange-Organization-*`` from mail coming
from outside and re-stamps it, and the recipient's EOP adds
``X-Forefront-Antispam-Report`` / ``X-Microsoft-Antispam`` / ``Authentication-Results``
on top. So the **first** (topmost) occurrence is the receiving side's; a second,
lower copy came with the message and is reported as such.
"""

from __future__ import annotations

import re
from typing import Any

GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

CAT = {
    "AMP": "anti-malware", "BIMP": "brand impersonation (Defender)", "BULK": "bulk", "DIMP": "domain impersonation (Defender)",
    "FTBP": "anti-malware common attachments filter", "GIMP": "mailbox intelligence impersonation (Defender)",
    "HPHSH": "high confidence phishing", "HPHISH": "high confidence phishing", "HSPM": "high confidence spam",
    "INTOS": "intra-organization phishing", "MALW": "malware", "OSPM": "outbound spam", "PHSH": "phishing",
    "SAP": "Safe Attachments (Defender)", "SPM": "spam", "SPOOF": "spoofing", "UIMP": "user impersonation (Defender)",
    "NONE": "no threat policy applied",
}
CAT_MALICIOUS = {"AMP", "MALW", "FTBP", "SAP"}
CAT_PHISH = {"PHSH", "HPHSH", "HPHISH", "SPOOF", "BIMP", "DIMP", "GIMP", "UIMP", "INTOS"}
SFV = {
    "BLK": "skipped filtering: sender in the user's Blocked Senders", "NSPM": "not spam",
    "SFE": "skipped filtering: sender in the user's Safe Senders",
    "SKA": "skipped spam filtering: allowed sender / domain in an anti-spam policy",
    "SKB": "marked as spam: blocked sender / domain in an anti-spam policy",
    "SKI": "skipped spam filtering: source IP in the connection filter IP Allow List",
    "SKN": "bypassed spam filtering: Exchange mail flow (transport) rule",
    "SKQ": "released from quarantine", "SKS": "marked as spam before filtering (transport rule / on-premises)",
    "SPM": "marked as spam by spam filtering",
}
SFV_BYPASS = {"SFE", "SKA", "SKI", "SKN", "SKQ"}
SFTY = {"9.19": "domain impersonation (protected domain)", "9.20": "user impersonation (protected user)",
        "9.25": "first contact safety tip"}
IPV = {"CAL": "spam filtering skipped: source IP in the IP Allow List", "NLI": "IP not on any reputation list"}
DIR = {"INB": "inbound", "OUT": "outbound", "INT": "internal"}


def compauth_reason(code: str) -> str:
    c = (code or "").strip()
    exact = {
        "000": "explicit fail: DMARC fail with p=quarantine / reject",
        "001": "implicit fail: no or weak authentication records (SPF ~all/?all, DMARC p=none)",
        "002": "sender / domain pair prohibited from spoofing by the admin",
        "010": "DMARC fail with p=reject/quarantine on one of the organisation's accepted domains (intra-org spoofing)",
        "100": "SPF pass, or DKIM pass with aligned MAIL FROM / From", "101": "DKIM signed by the From domain",
        "102": "MAIL FROM and From aligned and SPF passed", "103": "From domain aligns with the connecting IP's PTR",
        "104": "connecting IP's PTR aligns with the From domain",
        "108": "DKIM failed by a legitimate body change on an earlier hop",
        "109": "no DMARC record, but it would have passed", "111": "DMARC temp/permerror, but SPF or DKIM aligns",
        "112": "DNS timeout fetching DMARC", "115": "sent from a Microsoft 365 org that owns the From domain",
        "116": "From domain's MX aligns with the connecting IP's PTR", "130": "a trusted ARC sealer overrode a DMARC fail",
        "201": "From domain's PTR in the connecting IP's PTR subnet", "202": "From domain aligns with the connecting IP's PTR domain",
        "501": "DMARC not enforced: valid NDR with prior contact", "502": "DMARC not enforced: NDR of a message sent by this org",
        "601": "the sending domain is one of the organisation's accepted domains (intra-org spoofing)",
        "905": "DMARC not enforced: complex routing (on-premises / non-Microsoft service)",
    }
    if c in exact:
        return exact[c]
    ranges = {"1": "explicit or implicit pass", "2": "soft pass (implicit authentication)", "3": "not checked",
              "4": "bypassed", "6": "implicit fail", "7": "implicit pass (history of legitimate mail from this infrastructure)",
              "9": "bypassed"}
    return ranges.get(c[:1], "") if len(c) == 3 and c.isdigit() else ""


def _all(headers: list[dict[str, str]], name: str) -> list[str]:
    n = name.lower()
    return [str(h.get("value", "")) for h in headers if str(h.get("name", "")).lower() == n]


def _first(headers: list[dict[str, str]], name: str) -> str:
    v = _all(headers, name)
    return v[0].strip() if v else ""


def _fields(value: str) -> dict[str, str]:
    """``A:x;B:y`` → {A: x, B: y} (first occurrence wins)."""
    out: dict[str, str] = {}
    for part in re.split(r";", value or ""):
        if ":" in part:
            k, v = part.split(":", 1)
            k = k.strip()
            if k and k not in out:
                out[k] = v.strip()
    return out


_CT = "x-ms-exchange-crosstenant-"


def tenant_blocks(headers: list[dict[str, str]]) -> list[dict[str, str]]:
    """The X-MS-Exchange-CrossTenant-* headers grouped per stamping tenant, top
    (latest) first: each tenant writes its own Id / AuthAs / AuthSource /
    FromEntityHeader / OriginalArrivalTime / Network-Message-Id together.
    AuthAs ``Internal`` = the message authenticated inside that tenant (the
    sender's tenant); ``Anonymous`` = it came in from outside (the receiver's)."""
    blocks: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    for h in headers:
        n = str(h.get("name", "")).lower()
        if not n.startswith(_CT):
            continue
        key = n[len(_CT):]
        if key in cur:
            blocks.append(cur)
            cur = {}
        cur[key] = str(h.get("value", "")).strip()
    if cur:
        blocks.append(cur)
    out = []
    for b in blocks:
        tid = b.get("id", "").lower()
        if not GUID.match(tid):
            continue
        auth = b.get("authas", "")
        role = "sender" if auth.lower() == "internal" else "receiver" if auth.lower() == "anonymous" else "unknown"
        out.append({"tenant_id": tid, "auth_as": auth, "auth_source": b.get("authsource", ""),
                    "from_entity": b.get("fromentityheader", ""), "arrival": b.get("originalarrivaltime", ""),
                    "network_message_id": b.get("network-message-id", ""), "role": role})
    return out


def parse(headers: list[dict[str, str]]) -> dict[str, Any]:
    """Decoded Microsoft headers; ``{}`` when the message carries none."""
    names = {str(h.get("name", "")).lower() for h in headers}
    ms = sorted(n for n in names if n.startswith(("x-ms-", "x-microsoft-", "x-forefront-", "x-originatororg",
                                                   "x-eopattributedmessage", "x-eoptenantattributedmessage")))
    if not ms:
        return {}
    tenants = []
    for v in _all(headers, "X-MS-Exchange-CrossTenant-Id"):
        v = v.strip().lower()
        if GUID.match(v) and v not in tenants:
            tenants.append(v)
    blocks = tenant_blocks(headers)
    sender_t = next((b["tenant_id"] for b in reversed(blocks) if b["role"] == "sender"), "")
    out: dict[str, Any] = {
        "present": ms,
        # the sender's tenant when a block says so; otherwise the only one seen
        # (which may well be the receiving tenant: see tenant_blocks)
        "tenant_id": sender_t or (tenants[0] if tenants else ""),
        "tenant_role": "sender" if sender_t else (blocks[0]["role"] if blocks else "unknown"),
        "tenant_ids": tenants,
        "tenant_blocks": blocks,
        "originator_org": _first(headers, "X-OriginatorOrg"),
        "network_message_id": _first(headers, "X-MS-Exchange-CrossTenant-Network-Message-Id")
        or _first(headers, "X-MS-Exchange-Organization-Network-Message-Id"),
        "original_arrival_time": _first(headers, "X-MS-Exchange-CrossTenant-OriginalArrivalTime"),
        "crosstenant_auth_as": _first(headers, "X-MS-Exchange-CrossTenant-AuthAs"),
        "crosstenant_auth_source": _first(headers, "X-MS-Exchange-CrossTenant-AuthSource"),
        "from_entity": _first(headers, "X-MS-Exchange-CrossTenant-FromEntityHeader"),
        "mailbox_type": _first(headers, "X-MS-Exchange-CrossTenant-MailboxType"),
        "user_principal_name": _first(headers, "X-MS-Exchange-CrossTenant-UserPrincipalName"),
        "org_auth_as": _first(headers, "X-MS-Exchange-Organization-AuthAs"),
        "org_auth_source": _first(headers, "X-MS-Exchange-Organization-AuthSource"),
        "org_auth_mechanism": _first(headers, "X-MS-Exchange-Organization-AuthMechanism"),
        "directionality": _first(headers, "X-MS-Exchange-Organization-MessageDirectionality"),
        "org_scl": _first(headers, "X-MS-Exchange-Organization-SCL"),
        "originating_ip": _first(headers, "X-Originating-IP").strip("[] "),
        "external_original_sender": _first(headers, "X-MS-Exchange-ExternalOriginalInternetSender"),
        "atp_properties": _first(headers, "X-MS-Exchange-AtpMessageProperties"),
        "first_contact_tip": _first(headers, "X-MS-Exchange-EnableFirstContactSafetyTip"),
        "public_traffic_type": _first(headers, "X-MS-PublicTrafficType"),
        "eop_attributed": _first(headers, "X-EOPAttributedMessage"),
        "eop_tenant_attributed": _first(headers, "X-EOPTenantAttributedMessage"),
        "mailbox_delivery": _fields(_first(headers, "X-Microsoft-Antispam-Mailbox-Delivery")),
        "notes": [],
    }
    fare = _all(headers, "X-Forefront-Antispam-Report")
    if fare:
        f = _fields(fare[0])
        rep = {k: f.get(k, "") for k in ("CIP", "CTRY", "LANG", "SCL", "SRV", "IPV", "SFV", "PTR", "CAT", "SFTY",
                                         "H", "DIR", "SFS")}
        rep["CAT_meaning"] = CAT.get(rep["CAT"].upper(), "")
        rep["SFV_meaning"] = SFV.get(rep["SFV"].upper(), "")
        rep["SFTY_meaning"] = SFTY.get(rep["SFTY"], "")
        rep["IPV_meaning"] = IPV.get(rep["IPV"].upper(), "")
        rep["DIR_meaning"] = DIR.get(rep["DIR"].upper(), "")
        out["antispam"] = rep
        if len(fare) > 1:
            out["notes"].append(f"{len(fare)} X-Forefront-Antispam-Report headers: the topmost is the receiving "
                                "tenant's; the others came with the message (another tenant's, or forged)")
    msa = _first(headers, "X-Microsoft-Antispam")
    if msa:
        f = _fields(msa)
        out["bcl"] = f.get("BCL", "")
        out["pcl"] = f.get("PCL", "")
    ar = " ".join(_all(headers, "Authentication-Results")[:1]).lower()
    m = re.search(r"compauth=(\w+)(?:\s+reason=(\d{3}))?", ar)
    if m:
        out["compauth"] = {"result": m.group(1), "reason": m.group(2) or "",
                           "reason_text": compauth_reason(m.group(2) or "")}
    act = re.search(r"dmarc=\w+[^;]*?action=([\w.]+)", ar)
    if act:
        out["dmarc_action"] = act.group(1)
    if len(tenants) > 1:
        out["notes"].append(f"{len(tenants)} different X-MS-Exchange-CrossTenant-Id values (sender and receiver "
                            "tenants, or a relay through another tenant)")
    out["mailbox_delivery_note"] = ("undocumented by Microsoft: dest:I / dest:J are commonly read as Inbox / Junk"
                                    if out["mailbox_delivery"] else "")
    return out
