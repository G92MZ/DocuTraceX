"""Normalizer (C2 roadmap 3.5 / 6.4): every value a C2 extractor recovered as
one field with where it came from and how sure it is.

A field = {name, value, type, status, extractor, extractor_version, run_id,
raw_ref, evidence, confidence}. The structure is open: an extractor adds its
own names without a schema change. Statuses: ``extracted`` (read as is),
``decrypted`` (read after a decryption / decoding the extractor did),
``inferred`` (derived from other values — never mixed with the read ones),
``conflicting`` (two tools disagree: both kept)."""

from __future__ import annotations

import re
from typing import Any

_DECRYPT = re.compile(r"(?i)\b(?:xor|aes|rc4|des|decrypt|base64|rsa)\b")
# summary keys that are conclusions, not values read from the sample
_INFERRED = {"Domain fronting", "C2 (punycode)", "Version (guess)", "C2 (other tool)", "Carved at", "Configuration"}
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOSTPORT = re.compile(r"^(?:[\w.-]+|\[[0-9a-f:]+\]):\d{1,5}$", re.I)
_DOMAIN = re.compile(r"^(?:[\w-]{1,63}\.)+[a-z]{2,24}\.?$", re.I)


def value_type(v: Any) -> str:
    t = str(v).strip()
    if isinstance(v, bool):
        return "flag"
    if isinstance(v, int) or t.isdigit():
        return "number"
    if _IP.match(t):
        return "ip"
    if _HOSTPORT.match(t):
        return "host:port"
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", t):
        return "url"
    if "@" in t and _DOMAIN.match(t.split("@", 1)[1]):
        return "email"
    if _DOMAIN.match(t) or ("xn--" in t and "." in t):
        return "domain"
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", t):
        return "hash"
    if t.startswith("/") and " " not in t:
        return "uri"
    if re.match(r"^(?:[A-Za-z]:\\|%\w+%|\\\\)", t):
        return "path"
    return "text"


def _flat(name: str, v: Any) -> list[tuple[str, Any]]:
    if isinstance(v, list):
        return [(name, x) for x in v if x not in ("", None)]
    if isinstance(v, dict):
        return [(f"{name} / {k}", x) for k, x in v.items() if x not in ("", None)]
    return [(name, v)] if v not in ("", None) else []


def _field(name: str, value: Any, *, status: str, extractor: str, version: str, run_id: str, raw_ref: str,
           evidence: str, confidence: str) -> dict[str, Any]:
    return {"name": name, "value": value if isinstance(value, (int, float, bool)) else str(value),
            "type": value_type(value), "status": status, "extractor": extractor, "extractor_version": version,
            "run_id": run_id, "raw_ref": raw_ref, "evidence": evidence, "confidence": confidence}


def _norm(v: Any) -> str:
    return str(v).strip().lower().rstrip(".")


def normalize(cfg: dict[str, Any], extractor_id: str, version: str, run_id: str, raw_ref: str) -> list[dict[str, Any]]:
    conf = cfg.get("confidence") or "medium"
    common = {"version": version, "run_id": run_id, "raw_ref": raw_ref}
    out: list[dict[str, Any]] = []
    tools = {k: t for k, t in (cfg.get("tools") or {}).items() if isinstance(t, dict) and t.get("status") == "found"}
    if len(tools) >= 1 and cfg.get("kind") != "indicators":
        # one field per (name, value) across the tools that read it: agreeing
        # tools merge (high), disagreeing ones are both kept as conflicting
        per: dict[str, dict[str, list[str]]] = {}
        for t in tools.values():
            for k, v in (t.get("summary") or {}).items():
                for name, x in _flat(k, v):
                    per.setdefault(name, {}).setdefault(_norm(x), []).append(t.get("tool") or "")
        raw_vals: dict[tuple[str, str], Any] = {}
        for t in tools.values():
            for k, v in (t.get("summary") or {}).items():
                for name, x in _flat(k, v):
                    raw_vals.setdefault((name, _norm(x)), x)
        for name, vals in per.items():
            inferred = name.split(" / ")[0] in _INFERRED
            n_tools = len({tl for tls in vals.values() for tl in tls})
            for nv, tls in vals.items():
                if inferred:
                    st = "inferred"
                elif n_tools > 1 and len(vals) > 1 and len(tls) < n_tools:
                    st = "conflicting"
                else:
                    st = "decrypted" if _DECRYPT.search(str((tools.get(next(iter(tools)), {}) or {}).get("method") or "")) else "extracted"
                c = "high" if len(tls) > 1 else ("medium" if st in ("conflicting", "inferred") else conf)
                out.append(_field(name, raw_vals[(name, nv)], status=st, extractor=" + ".join(dict.fromkeys(tls)),
                                  **common, evidence=f"{' and '.join(dict.fromkeys(tls))}: {name}", confidence=c)
                           | {"extractor_version": version})
        for sec, kv in (cfg.get("sections") or {}).items():
            for k, v in kv.items():
                if k == "Note":
                    continue
                st = "decrypted" if (sec == "Guardrails" and k.startswith("Value")) else "extracted"
                out.append(_field(f"{sec} / {k}", v, status=st, extractor="dissect.cobaltstrike", **common,
                                  evidence=f"dissect.cobaltstrike settings ({sec})", confidence=conf)
                           | {"extractor_version": version})
    else:
        st0 = "decrypted" if _DECRYPT.search(str(cfg.get("method") or "")) else "extracted"
        for k, v in (cfg.get("summary") or {}).items():
            for name, x in _flat(k, v):
                st = "inferred" if name.split(" / ")[0] in _INFERRED else st0
                if cfg.get("kind") == "indicators":
                    st = "inferred"
                out.append(_field(name, x, status=st, extractor=extractor_id, **common,
                                  evidence=str(cfg.get("method") or extractor_id), confidence=conf)
                           | {"extractor_version": version})
    return out
