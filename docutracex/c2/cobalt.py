"""Cobalt Strike beacon / stager configuration — read by two independent parsers.

* Didier Stevens' ``1768.py`` (public domain, tools/didier/) with JSON output: beacons in PE files
  (the 4-byte-XOR "sleeve" in .data), raw shellcode, stagers and memory dumps. Stagers it reports
  as text (and a hex dump) are read here too. Fallback when the script is absent: a minimal decoder
  of the TLV config block XOR-ed with 0x69 (3.x) or 0x2e (4.x).
* Fox-IT's ``dissect.cobaltstrike`` (MIT, ``cobalt_dissect.py``): beacons, version, kill date,
  public key hash and the rebuilt malleable C2 profile.

Both always run; the configuration keeps one view per tool (``tools``) for the C2 / Beacons sub-tabs.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
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


# Retry cascade when the default 1768.py run finds nothing. Order matters: on a PE the parsed
# run comes first (with -r a stager in a PE is lost). -e is experimental: medium confidence.
# DOCUTRACEX_1768_DEEP=0 disables the retries; DOCUTRACEX_1768_DEEP_MAX_MB caps the file size.
_PE_RETRIES = (("-x",), ("-r", "-x"), ("-r", "-x", "-e"))
_RAW_RETRIES = (("-r", "-x"), ("-r", "-x", "-e"))


def _deep_enabled() -> bool:
    return os.environ.get("DOCUTRACEX_1768_DEEP", "1") != "0"


def _deep_max_size() -> int:
    try:
        return int(os.environ.get("DOCUTRACEX_1768_DEEP_MAX_MB", "16")) * 1024 * 1024
    except ValueError:
        return 16 * 1024 * 1024


def _binary_like(data: bytes) -> bool:
    """Worth a raw retry: not text (scripts, documents' XML, logs…)."""
    head = data[:4096]
    if not head:
        return False
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(head) < 0.85


# Media / font formats: binary but never a beacon carrier worth three 1768.py runs.
_SKIP_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM", b"RIFF", b"wOFF", b"wOF2",
               b"\x00\x01\x00\x00\x00", b"OTTO", b"ID3", b"fLaC", b"OggS")


def deep_candidate(data: bytes) -> bool:
    """Objects that get the -x / -e retries even without a config header."""
    return (_deep_enabled() and _script() is not None and len(data) <= _deep_max_size()
            and not data.startswith(_SKIP_MAGIC)
            and (_is_pe(data) or _binary_like(data)))


def _run_1768(path: Path, data: bytes) -> dict[str, Any] | None:
    script = _script()
    if script is None:
        return None
    base = [] if _is_pe(data) else ["-r"]
    attempts: list[tuple[str, ...]] = [tuple(base)]
    if deep_candidate(data):
        attempts += list(_PE_RETRIES if _is_pe(data) else _RAW_RETRIES)
    for extra in attempts:
        res = _run_1768_once(script, path, list(extra))
        if res:
            if extra != attempts[0]:
                res["method"] += f" [retry: {' '.join(extra)}]"
                log.info("1768.py found a configuration in %s only with %s", path.name, " ".join(extra))
            if "-e" in extra:
                res["experimental"] = True
            return res
    return None


def _run_1768_once(script: Path, path: Path, extra: list[str]) -> dict[str, Any] | None:
    args = [sys.executable, str(script), "-J", "-n", *extra]
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, text=True, check=False,
                           encoding="utf-8", errors="replace", timeout=120,
                           stdin=subprocess.DEVNULL)
        out = json.loads(r.stdout or "{}")
    except Exception as exc:  # noqa: BLE001
        log.warning("1768.py %s failed on %s: %s", " ".join(extra), path.name, exc)
        return None
    cfg = out.get("config") or {}
    if not cfg:
        # No beacon config, but 1768.py may have decoded a stager (shellcode XOR-ed
        # with a 4-byte key inside a PE): it reports it as messages, not as config.
        msgs = [m for m in out.get("messages") or [] if isinstance(m, str)]
        if (any("Probably found shellcode" in m for m in msgs)
                and not any(_HEXLINE.match(ln) for m in msgs for ln in m.splitlines())):
            # The JSON report may omit the hex dump: take it from the text report.
            msgs += _text_report(args[:2] + [a for a in args[2:] if a != "-J"], path)
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


def _text_report(args: list[str], path: Path) -> list[str]:
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, text=True, check=False,
                           encoding="utf-8", errors="replace", timeout=120,
                           stdin=subprocess.DEVNULL)
    except Exception as exc:  # noqa: BLE001
        log.warning("1768.py (text report) failed on %s: %s", path.name, exc)
        return []
    return r.stdout.splitlines()


_ALLOC_SIZES = {0x40, 0x1000, 0x2000, 0x3000, 0x4000, 0x400000}

# --- Stager shellcode (1768.py "Probably found shellcode") ------------------------------
# block_api prologues (Stephen Fewer's PEB walk + ROR13 hashing), shared by Metasploit and
# Cobalt Strike stagers.
_PROLOGUES = {
    "x86": (b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5", b"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5",
            b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5"),
    "x64": (b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00", b"\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00",
            b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00"),
}
# ROR13(module UTF-16 upper + NUL) + ROR13(function + NUL), as block_api computes them.
_API_HASHES = {
    0x0726774C: "kernel32!LoadLibraryA", 0xE553A458: "kernel32!VirtualAlloc",
    0x56A2B5F0: "kernel32!ExitProcess", 0x5DE2C5AA: "kernel32!GetLastError",
    0x0A2A1DE0: "kernel32!ExitThread", 0x9DBD95A6: "kernel32!GetVersion",
    0x6F721347: "ntdll!RtlExitUserThread", 0x315E2145: "user32!GetDesktopWindow",
    0xA779563A: "wininet!InternetOpenA", 0xC69F8957: "wininet!InternetConnectA",
    0x3B2E55EB: "wininet!HttpOpenRequestA", 0x7B18062D: "wininet!HttpSendRequestA",
    0x0BE057B7: "wininet!InternetErrorDlg", 0xE2899612: "wininet!InternetReadFile",
    0x869E4675: "wininet!InternetSetOptionA",
    0xC21E9B46: "winhttp!WinHttpConnect",
    0x006B8029: "ws2_32!WSAStartup", 0x6174A599: "ws2_32!connect",
}
# Bits of HttpOpenRequestA's dwFlags worth showing.
_HTTP_FLAGS = {
    0x80000000: "RELOAD", 0x04000000: "NO_CACHE_WRITE", 0x00800000: "SECURE",
    0x00400000: "KEEP_CONNECTION", 0x00200000: "NO_AUTO_REDIRECT",
    0x00002000: "IGNORE_CERT_DATE_INVALID", 0x00001000: "IGNORE_CERT_CN_INVALID",
    0x00000200: "NO_UI",
}
_HEXLINE = re.compile(r"^([0-9A-Fa-f]{8}): ")
_HOSTLIKE = re.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$|^\d{1,3}(?:\.\d{1,3}){3}$")


def _bytes_lit(s: str) -> str:
    """b'...' repr printed by 1768.py → text."""
    s = s.strip()
    try:
        v = ast.literal_eval(s)
        return v.decode("latin-1") if isinstance(v, bytes) else str(v)
    except (ValueError, SyntaxError):
        return s


def _hexdump_bytes(msgs: list[str]) -> bytes:
    """Rebuild the shellcode from 1768.py's hex dump lines (``00000140: E8 8B …  ascii``)."""
    chunks: dict[int, bytes] = {}
    for m in msgs:
        for line in m.splitlines():
            mo = _HEXLINE.match(line)
            if not mo:
                continue
            area = line[10:59]                      # 16 bytes: 8 × "XX " + " " + 8 × "XX "
            toks = [t for t in area.split() if len(t) == 2]
            try:
                chunks[int(mo.group(1), 16)] = bytes(int(t, 16) for t in toks)
            except ValueError:
                continue
    if not chunks:
        return b""
    out = bytearray()
    for off in sorted(chunks):
        if off != len(out):                         # gap: keep only the contiguous start
            break
        out += chunks[off]
    return bytes(out)


def _cstrings(sc: bytes, minlen: int = 4) -> list[tuple[int, str]]:
    """NUL-terminated printable ASCII strings (CR/LF allowed), with their offset."""
    out = []
    for mo in re.finditer(rb"[\x20-\x7e\r\n]{%d,}(?=\x00)" % minlen, sc):
        out.append((mo.start(), mo.group(0).decode("ascii")))
    return out


def _push_before(sc: bytes, at: int, window: int = 24) -> list[int]:
    """imm32 values pushed (``68 xx xx xx xx``) in the bytes just before ``at``, nearest first."""
    vals = []
    lo = max(0, at - window)
    for i in range(at - 5, lo - 1, -1):
        if sc[i] == 0x68:
            vals.append(struct.unpack_from("<I", sc, i + 1)[0])
    return vals


def _shellcode_config(sc: bytes) -> dict[str, Any]:
    """Everything a block_api stager carries: arch, APIs, transport, port, flags, URI,
    HTTP headers, host and allocation size."""
    cfg: dict[str, Any] = {}
    arch_at = None
    for arch, sigs in _PROLOGUES.items():
        for s in sigs:
            i = sc.find(s)
            if i >= 0 and (arch_at is None or i < arch_at[1]):
                arch_at = (arch, i)
    if arch_at:
        cfg["architecture"] = arch_at[0]
    # API hashes: push imm32 (68) followed by call ebp (FF D5) on x86; mov r10d (41 BA) on x64.
    apis: list[tuple[int, str]] = []
    for mo in re.finditer(rb"(?:\x68|\x41\xba)(.{4})", sc, re.DOTALL):
        h = struct.unpack("<I", mo.group(1))[0]
        if h in _API_HASHES:
            apis.append((mo.start(), _API_HASHES[h]))
    if apis:
        cfg["apis"] = list(dict.fromkeys(a for _, a in apis))
    names = {a for _, a in apis}
    if any(a.startswith("wininet!") for a in names):
        transport = "HTTP"
    elif any(a.startswith("winhttp!") for a in names):
        transport = "HTTP (WinHTTP)"
    elif any(a.startswith("ws2_32!") for a in names):
        transport = "TCP"
    else:
        transport = ""
    # Port: the imm pushed just before InternetConnectA's hash.
    for at, name in apis:
        if name == "wininet!InternetConnectA":
            port = next((v for v in _push_before(sc, at) if 0 < v < 65536), None)
            if port:
                cfg["port"] = port
        elif name == "wininet!HttpOpenRequestA":
            flags = next((v for v in _push_before(sc, at, 32) if v & 0xFF000000), None)
            if flags is not None:
                cfg["http flags"] = f"0x{flags:08x} " + "|".join(
                    n for b, n in _HTTP_FLAGS.items() if flags & b)
                if flags & 0x00800000:
                    transport = "HTTPS"
        elif name == "kernel32!VirtualAlloc":
            size = next((v for v in _push_before(sc, at, 16) if v >= 0x10000), None)
            if size:
                cfg["stage alloc size"] = f"0x{size:x}"
    if transport:
        cfg["transport"] = transport
    # Strings: URI, header block, host.
    for _, s in _cstrings(sc):
        if s.startswith("/") and "uri" not in cfg and " " not in s and "\r" not in s:
            cfg["uri"] = s
        elif "\r\n" in s or ":" in s.split("\r\n", 1)[0] and s.split(":", 1)[0].replace("-", "").isalpha():
            headers = [h.strip() for h in s.split("\r\n") if h.strip()]
            if headers and all(":" in h for h in headers):
                cfg.setdefault("headers", []).extend(headers)
        elif _HOSTLIKE.match(s):
            cfg.setdefault("hosts", []).append(s)
    return cfg


def _stager_from_messages(msgs: list[str]) -> dict[str, Any] | None:
    """Parse 1768.py's 'Probably found shellcode' report (stager in a PE).

    Lines used: ``Parameter: <off> b'<host>'``, ``push : <off> <value> b'..'``,
    ``String: <off> b'<text>'``, ``intxorkey`` / ``payloadSize`` and, when present, the
    hex dump of the shellcode — rebuilt and read for the URI, HTTP headers, transport,
    request flags and API hashes that 1768.py does not list.
    """
    if not any("Probably found shellcode" in m for m in msgs):
        return None
    hosts, ports, strings = [], [], []
    xor = size = ""
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
        elif m.startswith("payloadSize:") and not m.endswith("0x00000000"):
            size = m.split()[-1]
    sc = _hexdump_bytes(msgs)
    scfg = _shellcode_config(sc) if sc else {}
    hosts = [h for h in dict.fromkeys(hosts + scfg.get("hosts", [])) if h]
    if not hosts:
        return None
    port = scfg.get("port") or (ports[0] if ports else None)
    uri = scfg.get("uri") or next((s for s in strings if s.startswith("/")), "")
    headers = list(dict.fromkeys(scfg.get("headers", []) + [s.strip() for s in strings
                                                            if ":" in s and not s.startswith("/")]))
    hdr = {h.split(":", 1)[0].strip().lower(): h.split(":", 1)[1].strip() for h in headers}
    transport = scfg.get("transport", "")

    def f(value: Any) -> dict[str, Any]:
        return {"value": str(value), "raw": value if isinstance(value, int) else None}

    fields: dict[str, Any] = {
        "payload type": f(f"stager {transport}".strip()),
        "server,get-uri": f(",".join(f"{h},{uri}" if uri else h for h in hosts)),
    }
    if port:
        fields["port"] = f(port)
    if hdr.get("user-agent"):
        fields["useragent"] = f(hdr["user-agent"])
    if headers:
        other = [h for h in headers if not h.lower().startswith(("user-agent:", "referer:"))]
        if other:
            fields["http headers"] = f(" | ".join(other))
    for key in ("referer", "accept", "accept-language", "host", "cookie"):
        if hdr.get(key):
            fields[key] = f(hdr[key])
    for key in ("transport", "architecture", "http flags", "stage alloc size"):
        if scfg.get(key):
            fields[key] = f(scfg[key])
    if scfg.get("apis"):
        fields["apis (ror13)"] = f(", ".join(scfg["apis"]))
    if xor:
        fields["xor key"] = f(xor)
    if size:
        fields["shellcode size"] = f(f"{int(size, 16)} bytes")
    method = "1768.py stager shellcode" + (f" (XOR {xor})" if xor else "")
    if sc:
        method += " + shellcode parsed"
    return {"fields": fields, "kind": "stager", "method": method, "sanity": "", "_messages": msgs}


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
        # Stagers (shellcode parsed): the request they make to fetch the beacon.
        "Referer": v.get("referer") or "",
        "HTTP headers": v.get("http headers") or "",
        "Architecture": v.get("architecture") or "",
    }
    return {k: x for k, x in summary.items() if x not in ("", [], None)}, hosts


def _view_1768(path: Path, data: bytes) -> dict[str, Any]:
    """1768.py (or the built-in decoder) as a view: status, method, summary, fields, hosts."""
    res = _run_1768(path, data)
    tool = "1768.py"
    if not res and prefilter(data):
        res = _fallback(data)
        tool = "built-in decoder"
    if not res:
        note = ("1768.py not found (tools/didier) and no 1-byte-XOR config header."
                if _script() is None else "No configuration or stager found by 1768.py.")
        return {"tool": "1768.py", "status": "nothing", "note": note}
    summary, hosts = summarise(res["fields"])
    if not hosts and "Pipe" not in summary:
        return {"tool": tool, "status": "nothing",
                "note": "1768.py reported something, but no C2 could be read from it (see the raw output).",
                "_messages": res.get("_messages", [])}
    kind = res.get("kind") or ("stager" if "stager" in json.dumps(res.get("_messages", [])).lower() else "beacon")
    ver = next((m.split(":", 1)[1].strip() for m in res.get("_messages", [])
                if m.startswith("Guessing Cobalt Strike version")), "")
    if ver:
        summary["Version (guess)"] = ver
    return {"tool": tool, "status": "found", "kind": kind, "method": res["method"],
            "experimental": bool(res.get("experimental")), "sanity": res.get("sanity", ""),
            "summary": summary, "hosts": hosts,
            "fields": {k: f.get("value") for k, f in res["fields"].items() if k != "publickey"},
            "_messages": res.get("_messages", [])}


def _norm_hosts(view: dict[str, Any]) -> set[str]:
    return {h.strip().lower() for h in view.get("hosts") or [] if h}


def extract(path: Path, data: bytes) -> dict[str, Any] | None:
    """Cobalt Strike, read by BOTH parsers (1768.py and dissect.cobaltstrike).

    One configuration per object with ``tools = {"1768": view, "dissect": view}``: the UI shows one
    sub-tab per tool. The top-level summary / c2 (finding, IOCs, CSV, report) come from the tool that
    found something — 1768.py first — and the C2 hosts of both are merged into ``c2``.
    """
    if not (prefilter(data) or _is_pe(data) or deep_candidate(data)):
        return None
    from . import cobalt_dissect

    v1768 = _view_1768(path, data)
    vdis = cobalt_dissect.extract(path) if cobalt_dissect.enabled() else cobalt_dissect.view({"status": "disabled"})
    found = [v for v in (v1768, vdis) if v.get("status") == "found"]
    if not found:
        return None
    primary = found[0]
    hosts = list(dict.fromkeys([h for v in found for h in v.get("hosts") or []]))
    h1, h2 = _norm_hosts(v1768), _norm_hosts(vdis)
    if len(found) == 2:
        agreement = "agree" if h1 == h2 else ("partial" if h1 & h2 else "differ")
    else:
        agreement = f"only {primary['tool']}"
    confidence = "high"
    if primary.get("experimental") or "fail" in str(primary.get("sanity", "")).lower():
        confidence = "medium"
    if agreement == "agree":
        confidence = "high"
    elif agreement == "differ":
        confidence = "medium"
    summary = dict(primary.get("summary") or {})
    if len(found) == 2 and h1 != h2:
        summary["C2 (other tool)"] = [h for h in (found[1].get("summary") or {}).get("C2", [])]
    for k in ("Version", "Kill date", "Public key SHA-256"):          # dissect-only facts worth the card
        if k in (vdis.get("summary") or {}) and k not in summary:
            summary[k] = vdis["summary"][k]
    method = " + ".join(v["method"] for v in found)
    out = {"family": "Cobalt Strike", "kind": primary.get("kind", "beacon"), "method": method,
           "confidence": confidence, "summary": summary, "c2": hosts,
           "fields": primary.get("fields") or {},
           "agreement": agreement,
           "tools": {"1768": {k: x for k, x in v1768.items() if k != "_messages"},
                     "dissect": vdis},
           "_messages": v1768.get("_messages", [])}
    if agreement == "differ":
        out["note"] = ("1768.py and dissect.cobaltstrike report different C2 hosts: compare both sub-tabs "
                       "before acting on them.")
    return out
