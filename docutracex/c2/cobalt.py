"""Cobalt Strike beacon / stager configuration.

Primary: Didier Stevens' ``1768.py`` (public domain, downloaded with the rest
of his suite into tools/didier/) with JSON output — it handles beacons in PE
files (the 4-byte-XOR "sleeve" in .data), raw shellcode, stagers and process
memory dumps. Fallback when the script is absent: a minimal decoder of the
TLV config block XOR-ed with 0x69 (3.x) or 0x2e (4.x).
"""

from __future__ import annotations

import ast
import json
import logging
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

HEADER = b"\x00\x01\x00\x01\x00\x02"          # setting 1 (payload type), type short, len 2
KEYS = (0x2E, 0x69)
PAYLOAD_TYPES = {0: "HTTP", 1: "DNS", 2: "SMB", 4: "TCP", 8: "HTTPS", 10: "TCP (bind)",
                 14: "External C2", 16: "HTTP (foreign)", 32: "HTTPS (foreign)"}
# id → name (subset; 1768.py knows them all).
NAMES = {1: "payload type", 2: "port", 3: "sleeptime", 4: "maxgetsize", 5: "jitter",
         7: "publickey", 8: "server,get-uri", 9: "useragent", 10: "post-uri",
         15: "pipename", 26: "get-verb", 27: "post-verb", 29: "spawnto_x86",
         30: "spawnto_x64", 37: "license-id", 50: "proxy_type", 54: "host_header"}


def prefilter(data: bytes) -> bool:
    """Cheap test: an XOR-encoded (or plain, memory-dump) config header."""
    return HEADER in data or any(bytes(b ^ k for b in HEADER) in data for k in KEYS)


def _script() -> Path | None:
    try:
        from ..parsers.didier import didier_dir
        p = didier_dir() / "1768.py"
        return p if p.is_file() else None
    except Exception:  # noqa: BLE001
        return None


def _is_pe(data: bytes) -> bool:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return False
    off = struct.unpack_from("<I", data, 0x3C)[0]
    return data[off:off + 4] == b"PE\x00\x00" if off < len(data) - 4 else False


def _run_1768(path: Path, data: bytes) -> dict[str, Any] | None:
    script = _script()
    if script is None:
        return None
    args = [sys.executable, str(script), "-J", "-n"]
    if not _is_pe(data):
        args.append("-r")
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, text=True, check=False,
                           encoding="utf-8", errors="replace", timeout=120,
                           stdin=subprocess.DEVNULL)
        out = json.loads(r.stdout or "{}")
    except Exception as exc:  # noqa: BLE001
        log.warning("1768.py failed on %s: %s", path.name, exc)
        return None
    cfg = out.get("config") or {}
    if not cfg:
        # No beacon config, but 1768.py may have decoded a stager (shellcode XOR-ed
        # with a 4-byte key inside a PE): it reports it as messages, not as config.
        msgs = [m for m in out.get("messages") or [] if isinstance(m, str)]
        stager = _stager_from_messages(msgs)
        if stager is None:
            err = next((m for m in msgs if m.startswith("Error")), "")
            if err:
                log.info("1768.py on %s: %s", path.name, err)
        return stager
    fields = {}
    for k, v in cfg.items():
        name = v.get("id") or f"0x{int(k):04x}"
        info = v.get("info")
        if isinstance(info, str) and len(info) >= 2 and info[0] == info[-1] == "'":
            info = info[1:-1].encode().decode("unicode_escape", "replace")
        fields[name] = {"value": info, "raw": v.get("rawvalue")}
    msgs = [m for m in out.get("messages") or [] if isinstance(m, str)]
    xor = next((m.split()[-1] for m in msgs if m.startswith("xorkey")), "")
    sanity = next((m for m in msgs if m.startswith("Sanity check")), "")
    return {"fields": fields, "method": "1768.py" + (f" (XOR 0x{xor})" if xor else ""),
            "sanity": sanity, "_messages": msgs}


_ALLOC_SIZES = {0x40, 0x1000, 0x2000, 0x3000, 0x4000, 0x400000}


def _bytes_lit(s: str) -> str:
    """b'...' repr printed by 1768.py → text."""
    s = s.strip()
    try:
        v = ast.literal_eval(s)
        return v.decode("latin-1") if isinstance(v, bytes) else str(v)
    except (ValueError, SyntaxError):
        return s


def _stager_from_messages(msgs: list[str]) -> dict[str, Any] | None:
    """Parse 1768.py's 'Probably found shellcode' report (stager in a PE).

    Lines used:  ``Parameter: <off> b'<host>'``, ``push : <off> <value> b'..'``,
    ``String: <off> b'<text>'`` and ``intxorkey: 0x........``.
    """
    if not any("Probably found shellcode" in m for m in msgs):
        return None
    hosts, ports, strings = [], [], []
    xor = ""
    for m in msgs:
        if m.startswith("Parameter:"):
            parts = m.split(None, 2)
            if len(parts) == 3:
                hosts.append(_bytes_lit(parts[2]))
        elif m.startswith("push"):
            parts = m.split(":", 1)[1].split()
            if len(parts) >= 2 and parts[1].isdigit():
                v = int(parts[1])
                if 0 < v < 65536 and v not in _ALLOC_SIZES:
                    ports.append(v)
        elif m.startswith("String:"):
            parts = m.split(None, 2)
            if len(parts) == 3:
                strings.append(_bytes_lit(parts[2]))
        elif m.startswith("intxorkey:") and not m.endswith("0x00000000"):
            xor = m.split()[-1]
    hosts = [h for h in dict.fromkeys(hosts) if h]
    if not hosts:
        return None
    port = ports[0] if ports else None
    fields: dict[str, Any] = {
        "payload type": {"value": "stager", "raw": None},
        "server,get-uri": {"value": ",".join(f"{h}," for h in hosts).rstrip(","), "raw": None},
    }
    if port:
        fields["port"] = {"value": str(port), "raw": port}
    ua = next((s.split(":", 1)[1].strip() for s in strings if s.lower().startswith("user-agent:")), "")
    if ua:
        fields["useragent"] = {"value": ua, "raw": None}
    uris = [s for s in strings if s.startswith("/")]
    if uris:
        fields["server,get-uri"]["value"] = ",".join(f"{h},{uris[0]}" for h in hosts)
    return {"fields": fields, "kind": "stager",
            "method": "1768.py stager shellcode" + (f" (XOR {xor})" if xor else ""),
            "sanity": "", "_messages": msgs}


def _decode_tlv(buf: bytes) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    i = 0
    while i + 6 <= len(buf):
        fid, ftype, flen = struct.unpack_from(">HHH", buf, i)
        if fid == 0:
            break
        if ftype not in (1, 2, 3) or flen > 0x2000:
            break
        val = buf[i + 6:i + 6 + flen]
        i += 6 + flen
        if ftype == 1:
            v: Any = struct.unpack(">H", val[:2])[0]
        elif ftype == 2:
            v = struct.unpack(">I", val[:4])[0]
        else:
            s = val.rstrip(b"\x00")
            v = s.decode("latin-1") if s and all(32 <= c < 127 or c in (9, 10, 13) for c in s) else s.hex()
        name = NAMES.get(fid, f"0x{fid:04x}")
        if fid == 1 and isinstance(v, int):
            v = f"{v} {PAYLOAD_TYPES.get(v, '')}".strip()
        fields[name] = {"value": str(v), "raw": v}
    return fields


def _fallback(data: bytes) -> dict[str, Any] | None:
    for key in (None, *KEYS):
        hdr = HEADER if key is None else bytes(b ^ key for b in HEADER)
        at = data.find(hdr)
        if at < 0:
            continue
        blob = data[at:at + 0x1000]
        plain = blob if key is None else bytes(b ^ key for b in blob)
        fields = _decode_tlv(plain)
        if len(fields) >= 4 and "port" in fields:
            return {"fields": fields, "method": "built-in decoder"
                    + ("" if key is None else f" (XOR 0x{key:02x})"), "sanity": ""}
    return None


def summarise(fields: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Key fields for the card + C2 endpoints."""
    v = {k: (f.get("value") if isinstance(f, dict) else f) for k, f in fields.items()}
    servers = str(v.get("server,get-uri") or "")
    parts = [p.strip() for p in servers.split(",") if p.strip()]
    hosts = parts[0::2]
    uris = parts[1::2]
    ptype = str(v.get("payload type") or "")
    port = str(v.get("port") or "")
    summary: dict[str, Any] = {
        "Type": ptype.split(" ", 1)[1] if " " in ptype else ptype,
        "C2": [f"{h}:{port}" if port else h for h in hosts],
        "GET URI": uris,
        "POST URI": v.get("post-uri") or "",
        "User-Agent": v.get("useragent") or "",
        "Sleep / jitter": (f"{int(v['sleeptime']) // 1000}s / {v.get('jitter', 0)}%"
                           if str(v.get("sleeptime") or "").isdigit() else ""),
        "Pipe": v.get("pipename") or "",
        "Spawn to": " · ".join(x for x in (v.get("spawnto_x86"), v.get("spawnto_x64")) if x),
        "Watermark": v.get("license-id") or v.get("watermark") or "",
    }
    return {k: x for k, x in summary.items() if x not in ("", [], None)}, hosts


def extract(path: Path, data: bytes) -> dict[str, Any] | None:
    if not (prefilter(data) or _is_pe(data)):
        return None
    res = _run_1768(path, data) or (_fallback(data) if prefilter(data) else None)
    if not res:
        return None
    summary, hosts = summarise(res["fields"])
    if not hosts and "Pipe" not in summary:
        return None
    kind = res.get("kind") or ("stager" if "stager" in json.dumps(res.get("_messages", [])).lower() else "beacon")
    ver = next((m.split(":", 1)[1].strip() for m in res.get("_messages", []) if m.startswith("Guessing Cobalt Strike version")), "")
    if ver:
        summary["Version (guess)"] = ver
    return {"family": "Cobalt Strike", "kind": kind, "method": res["method"],
            "confidence": "medium" if "fail" in res.get("sanity", "").lower() else "high",
            "summary": summary, "c2": hosts,
            "fields": {k: f.get("value") for k, f in res["fields"].items() if k != "publickey"},
            "_messages": res.get("_messages", [])}
