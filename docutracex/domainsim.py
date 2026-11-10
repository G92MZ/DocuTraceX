"""Global domain similarity: every Domain IOC of a case, whatever file it came
from, compared with the organisation's own domains, the protected brands and the
other domains of the same case.

Static and local. Thresholds come from Settings (``similarity``). Each match
records both domains, the algorithm, the distance / score, the threshold and
where each domain was found. Findings are raised only for look-alikes of your
domains or brands (high) and for near-identical domains inside the case (low);
a domain the email rules already reported as a look-alike is listed but not
reported twice.
"""

from __future__ import annotations

import re
from typing import Any

from . import similarity

MAX_DOMAINS = 2000
MAX_CASE_PAIRS = 200
_LOOKALIKE_RULES = ("lookalike_domain", "own_domain_lookalike", "homoglyph_domain", "idn_domain")


def registrable(host: str) -> str:
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gob", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def normalise(value: str) -> str:
    """URL / host / domain → lower-case host without scheme, credentials, port or path; IDN decoded."""
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    v = v.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[-1]
    v = re.sub(r":\d+$", "", v).strip(".[]")
    return similarity.idn_decode(v)


def _host_raw(value: str) -> str:
    """Like normalise(), without decoding IDN (xn-- stays visible)."""
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    v = v.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[-1]
    return re.sub(r":\d+$", "", v).strip(".[]")


def _label(reg: str) -> str:
    return reg.split(".")[0]


def compare(candidate: str, reference: str, kind: str, th: dict[str, int],
            ref_domains: tuple[str, ...] = ()) -> dict[str, Any] | None:
    """Why ``candidate`` (a host) looks like ``reference`` (a domain or a brand
    name), or None. ``ref_domains`` = the reference's legitimate domains."""
    host = normalise(candidate)
    reg = registrable(host)
    if not reg or "." not in reg:
        return None
    ref = reference.lower()
    ref_reg = registrable(ref) if "." in ref else ""
    legit = {registrable(d) for d in ref_domains} | ({ref_reg} if ref_reg else set())
    if reg in legit:
        return None                                       # the real thing
    label, ref_label = _label(reg), (_label(ref_reg) if ref_reg else ref)
    limit = similarity.max_distance(ref_label, th)
    if not limit and len(ref_label) < th["min_len"]:
        return None
    raw = re.sub(r"^[a-z][a-z0-9+.-]*://", "", (candidate or "").strip().lower()).split("/", 1)[0]
    m: dict[str, Any] = {"candidate": host if host == raw or "xn--" not in raw else f"{raw} ({host})",
                         "candidate_registrable": reg, "reference": reference,
                         "reference_kind": kind, "threshold": limit}
    lev = similarity.levenshtein(label, ref_label, cap=max(limit, 1))
    osa = similarity.damerau(label, ref_label, cap=max(limit, 1))
    folded = similarity.homoglyph_fold(label)
    if label == ref_label and ref_reg and reg != ref_reg:
        m.update(algorithm="same name, other TLD", distance=0, reason=f"{reg} uses the name of {ref_reg} under another TLD")
    elif folded == ref_label:
        how = "Unicode look-alike characters" if similarity.unicode_skeleton(label) == ref_label else "look-alike characters"
        m.update(algorithm="homoglyph", distance=0, reason=f"'{label}' reads as '{ref_label}' ({how})")
    elif limit and 0 < osa <= limit and osa < lev:
        m.update(algorithm="Damerau-Levenshtein", distance=osa,
                 reason=f"'{label}' is {osa} edit(s) from '{ref_label}' counting a swap of adjacent letters as one")
    elif limit and 0 < lev <= limit:
        m.update(algorithm="Levenshtein", distance=lev, reason=f"'{label}' is {lev} edit(s) from '{ref_label}'")
    elif limit and 0 < similarity.levenshtein(folded, ref_label, cap=limit) <= limit:
        d = similarity.levenshtein(folded, ref_label, cap=limit)
        m.update(algorithm="homoglyph + Levenshtein", distance=d,
                 reason=f"'{label}' is {d} edit(s) from '{ref_label}' once look-alike characters are folded")
    elif len(ref_label) >= th["min_len"] and kind != "case" and label != ref_label and any(
            w == ref_label or w.startswith(ref_label)          # microsoft-login, microsoftonline; not pineapple
            for w in re.split(r"[.-]", similarity.homoglyph_fold(host.removesuffix("." + reg.split(".", 1)[1]))) if w):
        disguised = ref_label not in host
        m.update(algorithm="embedded name" + (" + homoglyph" if disguised else ""), distance=0,
                 reason=f"{host} carries '{ref_label}'{' written with look-alike characters' if disguised else ''} "
                        f"inside a domain that is not {ref_reg or ref_label}'s")
    else:
        return None
    longest = max(len(label), len(ref_label)) or 1
    m["score"] = round(1 - m["distance"] / longest, 3)
    return m


def run(iocs: dict[str, Any], own_domains: list[str], brands: list[str],
        mail_findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    from .parsers.mail_rules import BRANDS
    th = similarity.thresholds()
    where: dict[str, list[str]] = {}
    for i in (iocs or {}).get("iocs") or []:
        if i.get("type") not in ("domain", "url", "email"):
            continue
        host = _host_raw(i["value"].rsplit("@", 1)[-1] if i["type"] == "email" else i["value"])
        if not host or "." not in host or re.fullmatch(r"[\d.]+", host):
            continue
        locs = where.setdefault(host, [])
        for o in i.get("occurrences") or []:
            loc = f"{o.get('module', '')}/{o.get('location', '')}"
            if loc not in locs and len(locs) < 8:
                locs.append(loc)
    hosts = sorted(where)[:MAX_DOMAINS]
    refs: list[tuple[str, str, tuple[str, ...]]] = [(d.lower(), "own", ()) for d in own_domains]
    refs += [(b.lower(), "brand", tuple(BRANDS.get(b.lower(), ()))) for b in list(BRANDS) + list(brands)]
    already = " ".join(f"{f.get('detail', '')} {f.get('evidence', '')}" for f in mail_findings or []
                       if f.get("rule") in _LOOKALIKE_RULES).lower()
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for h in hosts:
        reg = registrable(h)
        if any(reg == registrable(d) for d in own_domains):
            continue
        for ref, kind, legit in refs:
            m = compare(h, ref, kind, th, legit)
            if m and (m["candidate_registrable"], ref) not in seen:
                seen.add((m["candidate_registrable"], ref))
                m["candidate_sources"] = where[h]
                m["reported_by_email"] = m["candidate_registrable"] in already or h in already
                matches.append(m)
                break
    # near-identical domains inside the case (shared infrastructure, typo-squats of each other)
    regs = sorted({registrable(h) for h in hosts})
    pairs = 0
    for i, a in enumerate(regs):
        if pairs >= MAX_CASE_PAIRS:
            break
        for b in regs[i + 1:]:
            la, lb = _label(a), _label(b)
            if la == lb or abs(len(la) - len(lb)) > 2 or len(min(la, lb, key=len)) < th["min_len"]:
                continue
            m = compare(a, b, "case", th)
            if m and m["algorithm"] != "same name, other TLD":
                m["candidate_sources"] = next((where[h] for h in hosts if registrable(h) == a), [])
                m["reference_sources"] = next((where[h] for h in hosts if registrable(h) == b), [])
                matches.append(m)
                pairs += 1
    findings = []
    for m in matches:
        if m.get("reported_by_email"):
            continue
        sev, rule = {"own": ("high", "domain_lookalike_own"), "brand": ("high", "domain_lookalike_brand"),
                     "case": ("low", "domain_similar_in_case")}[m["reference_kind"]]
        what = {"own": "your domain", "brand": "the brand", "case": "another domain of this case"}[m["reference_kind"]]
        findings.append({
            "rule": rule, "severity": sev,
            "detail": f"{m['candidate']} looks like {what} {m['reference']} — {m['algorithm']}: {m['reason']} "
                      f"(score {m['score']}, threshold {m['threshold']} edit(s))",
            "location": (m.get("candidate_sources") or ["iocs"])[0],
            "evidence": "found in: " + ", ".join(m.get("candidate_sources") or [])
                        + (f"; {m['reference']} found in: " + ", ".join(m["reference_sources"])
                           if m.get("reference_sources") else ""),
        })
    return {"module": "domainsim", "status": "ok_with_findings" if findings else "ok", "thresholds": th,
            "compared": len(hosts), "references": {"own": len(own_domains), "brands": len(refs) - len(own_domains)},
            "matches": matches, "findings": findings, "counts": {"findings": len(findings), "matches": len(matches)}}
