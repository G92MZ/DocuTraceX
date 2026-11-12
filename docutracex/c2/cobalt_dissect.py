"""Cobalt Strike beacon configuration with Fox-IT's ``dissect.cobaltstrike`` (MIT), the second parser
next to Didier Stevens' ``1768.py`` (see ``cobalt.py``, which runs both and shows one sub-tab each).

dissect finds the config by the RSA OID of ``SETTING_PUBKEY`` (single-byte, multi-byte and guardrail
XOR, ArtifactKit / xorencoded stages), reports the Cobalt Strike version, kill date, trial flag and
rebuilds the **malleable C2 profile**. It parses *beacons*: a stager carries no beacon config, so on a
stager only 1768.py (and the shellcode reader in cobalt.py) give results.

Runs in a child process (``_dissect_worker.py``) with a timeout. ``DOCUTRACEX_DISSECT_CS=0`` disables it.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

TOOL = "dissect.cobaltstrike"
TIMEOUT = 120
_WORKER = Path(__file__).with_name("_dissect_worker.py")


def enabled() -> bool:
    return os.environ.get("DOCUTRACEX_DISSECT_CS", "1") != "0"


def _run(path: Path, all_xor: bool) -> dict[str, Any]:
    try:
        r = subprocess.run([sys.executable, str(_WORKER), str(path), "1" if all_xor else "0"],
                           capture_output=True, text=True, check=False, encoding="utf-8",
                           errors="replace", timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        log.warning("dissect.cobaltstrike timed out on %s", path.name)
        return {"status": "timeout", "error": f"no result in {TIMEOUT} s"}
    except Exception as exc:  # noqa: BLE001
        log.warning("dissect.cobaltstrike failed on %s: %s", path.name, exc)
        return {"status": "error", "error": str(exc)}
    try:
        from . import cobalt as _cobalt
        _cobalt._record(TOOL, ["all_xor" if all_xor else "default_xor"], r.stdout or "", r.stderr or "", r.returncode)
    except Exception:  # noqa: BLE001
        pass
    try:
        return json.loads((r.stdout or "").strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        log.warning("dissect.cobaltstrike: unreadable output on %s (rc=%s): %s",
                    path.name, r.returncode, (r.stderr or "")[-300:])
        return {"status": "error", "error": f"unreadable output (rc={r.returncode})"}


def _sleep(ms: Any, jitter: Any) -> str:
    return f"{int(ms) // 1000}s / {jitter or 0}%" if isinstance(ms, int) else ""


def host_header(raw: Any) -> str:
    """``SETTING_HOST_HEADER`` is the header line as sent ("Host: x\\r\\n"): the value."""
    v = str(raw or "").strip()
    return v.split(":", 1)[1].strip() if v.lower().startswith("host:") else v


def idn(host: str) -> str:
    """The ASCII (punycode) form of an internationalised name, "" when it is ASCII already."""
    try:
        if host and not host.isascii():
            return host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return ""


def fronting(hosts: list[str], hdr: str) -> str:
    """Domain fronting: the TLS / DNS name (C2 host) differs from the Host header."""
    h = hdr.lower().strip().rstrip(".")
    if not h or not hosts:
        return ""
    if any(x.lower().rstrip(".") == h for x in hosts):
        return ""
    return (f"Host header {hdr} differs from the C2 host(s) {', '.join(hosts[:3])}: domain fronting / CDN "
            "redirector — the connection goes to the C2 host, the request is routed to the Host header")


_ALLOCATORS = {0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
_PERMS = {4: "RW", 32: "RX", 64: "RWX"}
_PROXY = {0: "direct", 1: "manual proxy", 2: "IE settings (default)"}


def _num(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _syscalls(v: Any) -> str:
    n = _num(v)
    if n is not None:
        return {0: "", 1: "direct", 2: "indirect"}.get(n, str(n))
    t = str(v or "")
    return "" if t.lower() in ("", "none", "0") else t


def _transform(steps: Any) -> str:
    out = []
    for st in steps or []:
        if isinstance(st, (list, tuple)) and len(st) == 2 and st[1] not in ("", None):
            out.append(f"{st[0]} {st[1]}")
    return ", ".join(out)


def sections(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The beacon's behaviour beyond the C2 endpoints, grouped for the card:
    DNS channel, process injection, evasion, guardrails, peer-to-peer."""
    s = raw.get("settings") or {}
    out: dict[str, dict[str, Any]] = {}
    proto = str(raw.get("protocol") or "").lower()
    dns = {
        "Idle IP (no tasks)": s.get("SETTING_DNS_IDLE") or "",
        "DNS sleep (ms)": s.get("SETTING_DNS_SLEEP") or "",
        "Max DNS name length": s.get("SETTING_MAXDNS") or "",
        "Resolver": s.get("SETTING_DNSRESOLVER") or "",
        "Subdomain prefixes": " · ".join(f"{k.rsplit('_', 1)[-1].lower() if 'BEACON_BEACON' not in k else 'beacon'}={v}"
                                         for k, v in s.items() if k.startswith("SETTING_DNS_BEACON_") and v),
    }
    if "dns" in proto or any(dns.values()) and proto in ("", "dns"):
        out["DNS channel"] = {k: v for k, v in dns.items() if v not in ("", None, 0)}
    if proto in ("smb", "tcp"):
        p2p = {"Named pipe": s.get("SETTING_PIPENAME") or "",
               "Frame header": s.get("SETTING_SMB_FRAME_HEADER") or s.get("SETTING_TCP_FRAME_HEADER") or ""}
        if proto == "tcp":
            p2p["Listens on port"] = raw.get("port") or ""
        p2p["Note"] = ("peer-to-peer beacon: talks to another beacon over the pipe / port, not to the "
                       "internet — the C2 is the parent beacon's")
        out["Peer-to-peer"] = {k: v for k, v in p2p.items() if v not in ("", None)}
    inj = {
        "Execute methods": ", ".join(map(str, s.get("SETTING_PROCINJ_EXECUTE") or [])),
        "Allocator": _ALLOCATORS.get(_num(s.get("SETTING_PROCINJ_ALLOCATOR")), s.get("SETTING_PROCINJ_ALLOCATOR") or ""),
        "Initial / final permissions": (f"{_PERMS.get(_num(s.get('SETTING_PROCINJ_PERMS_I')), s.get('SETTING_PROCINJ_PERMS_I'))}"
                                        f" → {_PERMS.get(_num(s.get('SETTING_PROCINJ_PERMS')), s.get('SETTING_PROCINJ_PERMS'))}"
                                        if s.get("SETTING_PROCINJ_PERMS") is not None else ""),
        "Min allocation": s.get("SETTING_PROCINJ_MINALLOC") or "",
        "Transform x86": _transform(s.get("SETTING_PROCINJ_TRANSFORM_X86")),
        "Transform x64": _transform(s.get("SETTING_PROCINJ_TRANSFORM_X64")),
        "BOF allocator": s.get("SETTING_BOF_ALLOCATOR") or "",
    }
    inj = {k: v for k, v in inj.items() if v not in ("", None, 0)}
    if inj:
        out["Process injection"] = inj
    ev = {
        "Sleep mask": (f"yes ({len(s.get('SETTING_GARGLE_SECTIONS') or [])} section(s) masked while sleeping)"
                       if _num(s.get("SETTING_GARGLE_NOOK")) else ""),
        "Syscalls": _syscalls(s.get("SETTING_SYSCALL_METHOD")),
        "Beacon Gate": ", ".join(map(str, s.get("SETTING_BEACON_GATE") or [])),
        "Cleanup": "yes" if _num(s.get("SETTING_CLEANUP")) else "",
        "Proxy": (s.get("SETTING_PROXY_CONFIG") or "") or (
            "" if _num(s.get("SETTING_PROXY_BEHAVIOR")) in (None, 2) else _PROXY.get(_num(s.get("SETTING_PROXY_BEHAVIOR")), "")),
        "Kill date": raw.get("killdate") or "",
    }
    ev = {k: v for k, v in ev.items() if v not in ("", None, 0)}
    if ev:
        out["Evasion / runtime"] = ev
    g = raw.get("guardrail") or {}
    if g.get("options"):
        out["Guardrails"] = {"Keyed to": ", ".join(g["options"]),
                             "Value (recovered)": g.get("key") or "(not recovered)",
                             "Note": "the beacon only decrypts its config on this target: who it was built for"}
    return out


_HOST_OK = __import__("re").compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,}$"
                                    r"|^\d{1,3}(?:\.\d{1,3}){3}$")


MIN_SETTINGS = 10            # a real beacon config carries ~30-70 settings


def _false_find(raw: dict[str, Any]) -> str:
    """dissect tries every XOR key, and a wrong key can still "parse" a few settings by chance:
    a found config with no C2, public key, watermark or version and only a handful of
    recognised settings is noise, not a beacon (seen with XOR 0x00 on packed AgentTesla,
    NanoCore and Raccoon samples). Returns why it is rejected, or ""."""
    s = raw.get("settings") or {}
    known = sum(1 for k in s if k.startswith("SETTING_"))
    hosts = [h for h in raw.get("domains") or [] if h and _HOST_OK.match(str(h).strip())]
    uris = [u for u in raw.get("uris") or [] if u]
    strong = (hosts or uris or raw.get("submit_uri") or raw.get("pubkey_sha256") or raw.get("pubkey_pem")
              or raw.get("watermark") is not None or (raw.get("version") or "Unknown") != "Unknown")
    if strong or known >= MIN_SETTINGS:
        return ""
    return (f"a decode with XOR 0x{raw.get('xorkey') or '?'} parsed {len(s)} setting(s) ({known} recognised) "
            "with no C2, public key, watermark or version — a real beacon carries dozens: discarded as a "
            "false find, not a beacon")


def view(raw: dict[str, Any]) -> dict[str, Any]:
    """Worker JSON → a view (same shape as the 1768.py one: status, method, summary, fields, hosts)."""
    st = raw.get("status", "error")
    if st == "found":
        why = _false_find(raw)
        if why:
            st = "nothing"
            raw = {"status": "nothing", "lib": raw.get("lib"), "rejected": why}
    lib = raw.get("lib") or ""
    v: dict[str, Any] = {"tool": TOOL, "status": st, "lib_version": lib}
    if st != "found":
        v["note"] = {
            "not_installed": "dissect.cobaltstrike is not installed in the portable Python "
                             "(pip install dissect.cobaltstrike, or re-run setup).",
            "nothing": "No beacon configuration found. dissect parses beacons (config block with the RSA "
                       "public key); stagers carry none.",
            "disabled": "Disabled (DOCUTRACEX_DISSECT_CS=0).",
            "timeout": raw.get("error", "timeout"),
            "error": raw.get("error", "error"),
        }.get(st, raw.get("error", ""))
        if raw.get("rejected"):
            v["note"] = raw["rejected"]
        return v
    s = raw.get("settings") or {}
    port = raw.get("port")
    hosts = list(dict.fromkeys(h.strip() for h in raw.get("domains") or []
                               if h and _HOST_OK.match(str(h).strip())))
    wm = raw.get("watermark")
    hdr = host_header(s.get("SETTING_HOST_HEADER"))
    punycode = [f"{h} = {idn(h)}" for h in hosts if idn(h)]
    summary: dict[str, Any] = {
        "Type": (raw.get("protocol") or "").upper(),
        "C2": [f"{h}:{port}" if port else h for h in hosts],
        "C2 (punycode)": punycode,
        "GET URI": list(dict.fromkeys(raw.get("uris") or [])),
        "POST URI": raw.get("submit_uri") or "",
        "User-Agent": s.get("SETTING_USERAGENT") or "",
        "Host header": hdr,
        "Domain fronting": fronting(hosts, hdr),
        "Sleep / jitter": _sleep(raw.get("sleeptime"), raw.get("jitter")),
        "Pipe": s.get("SETTING_PIPENAME") or "",
        "Spawn to": " · ".join(x for x in (s.get("SETTING_SPAWNTO_X86"), s.get("SETTING_SPAWNTO_X64")) if x),
        "Watermark": (f"{wm}" + (" (trial)" if raw.get("is_trial") else "")) if wm is not None else "",
        "Version": raw.get("version") or "",
        "Kill date": raw.get("killdate") or "",
        "Guardrails": (f"{', '.join((raw.get('guardrail') or {}).get('options') or [])} = "
                       f"{(raw.get('guardrail') or {}).get('key') or '?'}") if (raw.get("guardrail") or {}).get("options") else "",
        "Public key SHA-256": raw.get("pubkey_sha256") or "",
        "Architecture": raw.get("architecture") or "",
    }
    fields = {k: (", ".join(map(str, x)) if isinstance(x, list) else str(x)) for k, x in s.items()}
    for k in ("xorkey", "xorencoded", "stages", "pe_compile_stamp", "pe_export_stamp", "guardrails",
              "modifications"):
        if raw.get(k) not in (None, [], "", False):
            fields[k] = ", ".join(map(str, raw[k])) if isinstance(raw[k], list) else str(raw[k])
    v.update({
        "method": f"{TOOL} {lib}".strip() + (f" (XOR 0x{raw['xorkey']})" if raw.get("xorkey") else ""),
        "summary": {k: x for k, x in summary.items() if x not in ("", [], None)},
        "sections": sections(raw),
        "fields": fields, "hosts": hosts,
        "host_header": hdr,
        "public_key": raw.get("pubkey_pem") or "",
        "profile": raw.get("profile") or "",
        "kind": "beacon",
    })
    return v


def extract(path: Path, all_xor: bool = True) -> dict[str, Any]:
    if not enabled():
        return view({"status": "disabled"})
    return view(_run(path, all_xor))
