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


def _run_1768(path: Path, data: bytes, deep: bool = True) -> dict[str, Any] | None:
    """``deep=False``: only the default run — dissect.cobaltstrike already has the
    configuration, so the -x / -e retries (seconds each on large files) are skipped."""
    script = _script()
    if script is None:
        return None
    base = [] if _is_pe(data) else ["-r"]
    attempts: list[tuple[str, ...]] = [tuple(base)]
    if deep and deep_candidate(data):
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


# RAW record of every tool run of one extract() call: what 1768.py / dissect
# printed, untouched — kept as evidence and re-interpreted without re-running.
_RAW: list[dict[str, Any]] | None = None


def _record(tool: str, args: list[str], stdout: str, stderr: str = "", rc: int | None = None) -> None:
    if _RAW is not None:
        _RAW.append({"tool": tool, "args": args, "stdout": stdout, "stderr": (stderr or "")[-4000:], "rc": rc})


def _run_1768_once(script: Path, path: Path, extra: list[str]) -> dict[str, Any] | None:
    args = [sys.executable, str(script), "-J", "-n", *extra]
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, text=True, check=False,
                           encoding="utf-8", errors="replace", timeout=120,
                           stdin=subprocess.DEVNULL)
        _record("1768.py", ["-J", "-n", *extra], r.stdout or "", r.stderr or "", r.returncode)
        out = json.loads(r.stdout or "{}")
    except Exception as exc:  # noqa: BLE001
        log.warning("1768.py %s failed on %s: %s", " ".join(extra), path.name, exc)
        return None
    text: list[str] = []
    msgs = [m for m in out.get("messages") or [] if isinstance(m, str)]
    if (not out.get("config") and any("Probably found shellcode" in m for m in msgs)
            and not any(_HEXLINE.match(ln) for m in msgs for ln in m.splitlines())):
        # The JSON report may omit the hex dump: take it from the text report.
        text = _text_report(args[:2] + [a for a in args[2:] if a != "-J"], path)
        _record("1768.py (text report)", [a for a in ["-n", *extra]], "\n".join(text))
    res = parse_1768(out, text)
    if res is None:
        err = next((m for m in msgs if m.startswith("Error")), "")
        if err:
            log.info("1768.py on %s: %s", path.name, err)
    return res


def parse_1768(out: dict[str, Any], text_report: list[str] | None = None) -> dict[str, Any] | None:
    """1768.py's JSON report (+ its text report for stagers) → fields. Pure: used
    on a fresh run and when a stored RAW report is re-interpreted."""
    cfg = out.get("config") or {}
    msgs = [m for m in out.get("messages") or [] if isinstance(m, str)]
    if not cfg:
        # No beacon config, but 1768.py may have decoded a stager (shellcode XOR-ed
        # with a 4-byte key inside a PE): it reports it as messages, not as config.
        return _stager_from_messages(msgs + list(text_report or []))
    fields = {}
    for k, v in cfg.items():
        name = v.get("id") or f"0x{int(k):04x}"
        info = v.get("info")
        if isinstance(info, str) and len(info) >= 2 and info[0] == info[-1] == "'":
            info = _demojibake(info[1:-1].encode().decode("unicode_escape", "replace"))
        fields[name] = {"value": info, "raw": v.get("rawvalue")}
    xor = next((m.split()[-1] for m in msgs if m.startswith("xorkey")), "")
    xor = xor[2:] if xor.lower().startswith("0x") else xor
    sanity = next((m for m in msgs if m.startswith("Sanity check")), "")
    return {"fields": fields, "method": "1768.py" + (f" (XOR 0x{xor})" if xor else ""),
            "sanity": sanity, "_messages": msgs}


def _demojibake(s: str) -> str:
    """1768.py prints UTF-8 names (an IDN C2: ``façade.example``) byte by byte: "faÃ§ade.example"."""
    try:
        return s.encode("latin-1").decode("utf-8") if not s.isascii() else s
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def channel(ptype: str) -> str:
    """1768.py's payload type ("windows-beacon_https-reverse_https") → HTTP / HTTPS / DNS / SMB / TCP."""
    t = (ptype or "").lower()
    for key, name in (("dns", "DNS"), ("smb", "SMB"), ("tcp", "TCP"), ("https", "HTTPS"), ("http", "HTTP"),
                      ("foreign", "foreign listener")):
        if key in t:
            return name + (" (stager)" if "stager" in t else "")
    return ptype.split(" ", 1)[1] if " " in ptype else ptype


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


def _checksum8(uri: str) -> int | None:
    """Cobalt Strike / Metasploit stage URI checksum: sum of the path bytes mod 256."""
    path = (uri or "").split("?", 1)[0].lstrip("/")
    return sum(path.encode("latin-1", "replace")) % 256 if path else None


def _block_api_head(data: bytes) -> bool:
    head = data[:64]
    return any(sig in head for sigs in _PROLOGUES.values() for sig in sigs)


def _stager_from_shellcode(data: bytes) -> dict[str, Any] | None:
    """A raw block_api stager (a decoded PowerShell / HTA payload, a .bin) read
    directly, when 1768.py gave nothing: same rules as its report."""
    if not _block_api_head(data):
        return None
    res = _stager_from_messages(["Probably found shellcode (DocuTraceX shellcode reader)"], sc=data[:0x2000])
    if res:
        res["method"] = "shellcode reader (block_api stager)"
    return res


def _stager_from_messages(msgs: list[str], sc: bytes | None = None) -> dict[str, Any] | None:
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
    sc = sc if sc is not None else _hexdump_bytes(msgs)
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
    # block_api shellcode alone is shared with Metasploit's stagers: call it Cobalt
    # Strike only with something specific to it — the artifact-kit header that
    # 1768.py decodes (payloadSize / intxorkey) or a checksum8 URI (92 x86, 93 x64).
    if not (xor or size or _checksum8(uri) in (92, 93)):
        return None

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


# Watermarks (licence IDs) with a well-known meaning. A watermark identifies a
# licence, never an actor: these are shared by unrelated users (trial, or
# leaked / cracked builds), so they are no fingerprint and get no attribution.
KNOWN_WATERMARKS: dict[int, str] = {
    0: "trial / no licence — shared by every trial or cracked build",
    305419896: "0x12345678 — widely reported in leaked / cracked builds, shared by unrelated users",
    1359593325: "widely reported in leaked / cracked builds, shared by unrelated users",
    1580103814: "widely reported in leaked / cracked builds, shared by unrelated users",
}


def watermark_note(value: Any) -> str:
    """'1359593325 — leaked / cracked builds…' for a known watermark; as is otherwise."""
    s = str(value).strip()
    head = s.split(" ", 1)[0]
    if not head.isdigit() or "—" in s:
        return s
    note = KNOWN_WATERMARKS.get(int(head))
    return f"{head} — {note}" if note else s


def summarise(fields: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Key fields for the card + C2 endpoints."""
    v = {k: (f.get("value") if isinstance(f, dict) else f) for k, f in fields.items()}
    servers = str(v.get("server,get-uri") or "")
    parts = [p.strip() for p in servers.split(",") if p.strip()]
    hosts = list(dict.fromkeys(parts[0::2]))
    uris = parts[1::2]
    ptype = str(v.get("payload type") or "")
    port = str(v.get("port") or "")
    from .cobalt_dissect import fronting, host_header, idn
    hdr = host_header(v.get("host_header"))
    summary: dict[str, Any] = {
        "Type": channel(ptype),
        "C2": [f"{h}:{port}" if port else h for h in hosts],
        "C2 (punycode)": [f"{h} = {idn(h)}" for h in hosts if idn(h)],
        "GET URI": list(dict.fromkeys(uris)),
        "Host header": hdr,
        "Domain fronting": fronting(hosts, hdr),
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


# --- Cobalt Strike indicators without a configuration ------------------------------
# (needle, what it is, strong). Strong = specific to Cobalt Strike on its own;
# the others count only together. Format strings, as they sit in the binary.
_INDICATORS = (
    (b"MSSE-%d-server", "artifact kit named pipe format (\\\\.\\pipe\\MSSE-%d-server)", True),
    (b"%c%c%c%c%c%c%c%c%cMSSE", "artifact kit pipe builder", True),
    (b"msagent_%x", "default SMB beacon pipe format (msagent_%x)", True),
    (b"postex_ssh_%04x", "default post-exploitation SSH pipe (postex_ssh_%04x)", True),
    (b"postex_%04x", "default post-exploitation pipe (postex_%04x)", True),
    (b"status_%x", "default named pipe (status_%x)", False),
    (b"beacon.x64.dll", "beacon DLL name (x64)", True),
    (b"beacon.dll", "beacon DLL name", False),
    (b"ReflectiveLoader", "reflective loader export", False),
    (b"%02d/%02d/%02d %02d:%02d:%02d", "beacon timestamp format", False),
    (b"$var_code", "Cobalt Strike PowerShell template variable ($var_code)", False),
    (b"-bxor 35", "PowerShell template XOR key 35", False),
    (b"func_get_delegate_type", "PowerShell / Metasploit template helper", False),
)


def indicators(data: bytes) -> list[str]:
    """Cobalt Strike traces in an object that has no readable configuration:
    named pipe formats, beacon DLL names, the PowerShell template. Never a
    configuration — at most "this looks like Cobalt Strike"."""
    hits = [(what, strong) for needle, what, strong in _INDICATORS if needle in data]
    if data[:2] == b"MZ" and data[2:6] == b"ARUH":
        hits.append(("reflective loader stub at offset 0 (MZARUH: Cobalt Strike or Meterpreter)", False))
    strong = any(st for _w, st in hits)
    if strong or len(hits) >= 2:
        return [w for w, _s in hits]
    return []


def _view_1768(path: Path, data: bytes, deep: bool = True) -> dict[str, Any]:
    """1768.py (or the built-in decoder) as a view: status, method, summary, fields, hosts."""
    res = _run_1768(path, data, deep)
    tool = "1768.py"
    if not res and prefilter(data):
        res = _fallback(data)
        tool = "built-in decoder"
    if not res:
        res = _stager_from_shellcode(data)
        tool = "shellcode reader"
    if res and tool != "1768.py":          # built-in readers: their output is the RAW
        _record(tool, [], json.dumps({k: v for k, v in res.items() if k != "_messages"}, default=str))
    return view_1768(res, tool)


def view_1768(res: dict[str, Any] | None, tool: str = "1768.py") -> dict[str, Any]:
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
        summary["Version (guess)"] = f"{ver} — inferred from which settings the configuration has, not read from the beacon"
    return {"tool": tool, "status": "found", "kind": kind, "method": res["method"],
            "experimental": bool(res.get("experimental")), "sanity": res.get("sanity", ""),
            "summary": summary, "hosts": hosts,
            "fields": {k: (f.get("value") if isinstance(f, dict) else f) for k, f in res["fields"].items()
                       if k != "publickey"},
            "_messages": res.get("_messages", [])}


def reinterpret(raw: list[dict[str, Any]], ind: list[str] | None = None) -> dict[str, Any] | None:
    """The configuration rebuilt from a stored RAW record (1768.py's and
    dissect's output as they printed it) — the tools are NOT run again."""
    from . import cobalt_dissect
    v1768: dict[str, Any] = view_1768(None)
    for i, r in enumerate(raw):
        if r.get("tool") == "1768.py":
            try:
                out = json.loads(r.get("stdout") or "{}")
            except ValueError:
                continue
            nxt = raw[i + 1] if i + 1 < len(raw) else {}
            text = (nxt.get("stdout") or "").splitlines() if nxt.get("tool") == "1768.py (text report)" else []
            res = parse_1768(out, text)
            if res:
                extra = [a for a in r.get("args") or [] if a not in ("-J", "-n")]
                if extra and extra != ["-r"]:
                    res["method"] += f" [retry: {' '.join(extra)}]"
                if "-e" in extra:
                    res["experimental"] = True
                v1768 = view_1768(res)
                break
        elif r.get("tool") in ("built-in decoder", "shellcode reader"):
            try:
                v1768 = view_1768(json.loads(r.get("stdout") or "{}"), r["tool"])
            except (ValueError, KeyError):
                continue
            break
    vdis = cobalt_dissect.view({"status": "nothing"})
    for r in raw:
        if r.get("tool") == cobalt_dissect.TOOL:
            try:
                vdis = cobalt_dissect.view(json.loads((r.get("stdout") or "").strip().splitlines()[-1]))
            except (ValueError, IndexError):
                vdis = cobalt_dissect.view({"status": "error", "error": "unreadable RAW output"})
    return combine(v1768, vdis, list(ind or []))


def _norm_hosts(view: dict[str, Any]) -> set[str]:
    """Hosts compared across tools: lower case, IDN as punycode (both spellings agree)."""
    from .cobalt_dissect import idn
    return {(idn(h.strip()) or h.strip()).lower() for h in view.get("hosts") or [] if h}


# Reflective loader stubs at the head of a beacon DLL ("MZ" doubling as code):
# x64 ``MZARUH`` (pop r10; push r10; push rbp; mov rbp, rsp), x86 ``MZRE``
# (dec ebp; pop edx; push edx; inc ebp) — Cobalt Strike's (and Meterpreter's).
_REFLECTIVE_HEADS = (b"MZARUH", b"MZRE\x89\xe5", b"MZ\xe8\x00\x00\x00\x00\x5b")
MAX_CARVE = 4


def carve_reflective(data: bytes) -> list[tuple[int, bytes]]:
    """Beacon DLLs embedded in something else — a shellcode loader, a dropper,
    a memory dump, sRDI (a bootstrap stub before the DLL): every reflective
    loader head, and every valid PE header, past offset 0."""
    offs: set[int] = set()
    for head in _REFLECTIVE_HEADS:
        i = data.find(head, 1)
        while i > 0 and len(offs) < MAX_CARVE * 4:
            offs.add(i)
            i = data.find(head, i + 1)
    i = data.find(b"MZ", 1)
    while 0 < i and len(offs) < MAX_CARVE * 4:
        if i + 0x40 < len(data):
            e = struct.unpack_from("<I", data, i + 0x3C)[0]
            if 0x40 <= e < 0x1000 and data[i + e:i + e + 4] == b"PE\x00\x00":
                offs.add(i)
        i = data.find(b"MZ", i + 2)
    return [(o, data[o:]) for o in sorted(offs)[:MAX_CARVE]]


def extract(path: Path, data: bytes, _depth: int = 0) -> dict[str, Any] | None:
    global _RAW
    own = _RAW is None
    if own:
        _RAW = []
    try:
        res = _extract_carving(path, data, _depth)
        if res is not None and own:
            res["_raw"] = list(_RAW or [])
        return res
    finally:
        if own:
            _RAW = None


def _extract_carving(path: Path, data: bytes, _depth: int) -> dict[str, Any] | None:
    res = _extract(path, data)
    if (res is None or res.get("kind") == "indicators") and _depth == 0:
        import tempfile
        for off, blob in carve_reflective(data):
            with tempfile.TemporaryDirectory() as t:
                cp = Path(t) / f"carved_{off:x}.bin"
                cp.write_bytes(blob)
                got = extract(cp, blob, _depth + 1)
            if got and got.get("kind") != "indicators":
                got["carved_at"] = off
                got["method"] = f"{got['method']} · beacon carved at offset 0x{off:x}"
                got["summary"] = {"Carved at": f"0x{off:x} (embedded reflective DLL / PE)", **(got.get("summary") or {})}
                return got
    return res


def applicable(data: bytes) -> bool:
    """In the Cobalt Strike extractor's scope (its quick tests)."""
    return bool(prefilter(data) or _is_pe(data) or deep_candidate(data) or indicators(data)
                or _block_api_head(data) or carve_reflective(data[:16 * 1024 * 1024])[:1])


def _extract(path: Path, data: bytes) -> dict[str, Any] | None:
    """Cobalt Strike, read by BOTH parsers (1768.py and dissect.cobaltstrike).

    One configuration per object with ``tools = {"1768": view, "dissect": view}``: the UI shows one
    sub-tab per tool. The top-level summary / c2 (finding, IOCs, CSV, report) come from the tool that
    found something — 1768.py first — and the C2 hosts of both are merged into ``c2``.
    """
    ind = indicators(data)
    if not (prefilter(data) or _is_pe(data) or deep_candidate(data) or ind or _block_api_head(data)):
        return None
    from . import cobalt_dissect

    # dissect first: when it already has the configuration, 1768.py runs once
    # (no -x / -e retries) — it still gives its own view to compare
    vdis = cobalt_dissect.extract(path) if cobalt_dissect.enabled() else cobalt_dissect.view({"status": "disabled"})
    v1768 = _view_1768(path, data, deep=vdis.get("status") != "found")
    if vdis.get("status") == "found" and v1768.get("status") != "found":
        v1768["note"] = "default run only: dissect.cobaltstrike had the configuration, the deep retries were skipped"
    return combine(v1768, vdis, ind)


def combine(v1768: dict[str, Any], vdis: dict[str, Any], ind: list[str]) -> dict[str, Any] | None:
    """The two tools' views → one configuration (or indicators only, or None)."""
    found = [v for v in (v1768, vdis) if v.get("status") == "found"]
    if not found:
        if not ind:
            return None
        # traces only: said as such, never as a configuration
        return {"family": "Cobalt Strike", "kind": "indicators", "method": "static indicators",
                "confidence": "low", "status": "indicators only",
                "summary": {"Indicators": ind,
                            "Configuration": "not recovered (1768.py and dissect.cobaltstrike found none)"},
                "c2": [], "fields": {}, "indicators": ind,
                "note": "Cobalt Strike traces without a beacon configuration: not proof of a beacon, and no C2.",
                "tools": {"1768": {k: x for k, x in v1768.items() if k != "_messages"}, "dissect": vdis}}
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
    for k in ("Version", "Kill date", "Guardrails", "Host header", "Domain fronting", "C2 (punycode)",
              "Public key SHA-256", "Architecture"):          # dissect-only facts worth the card
        if k in (vdis.get("summary") or {}) and k not in summary:
            summary[k] = vdis["summary"][k]
    if str(summary.get("Version") or "").lower() == "unknown" and summary.get("Version (guess)"):
        summary.pop("Version")
    elif summary.get("Version"):
        summary.pop("Version (guess)", None)              # dissect's version is exact, 1768's a guess
    if summary.get("Watermark") not in (None, ""):
        summary["Watermark"] = watermark_note(summary["Watermark"])
    method = " + ".join(v["method"] for v in found)
    p2p = str(summary.get("Type") or "").upper().startswith(("SMB", "TCP"))
    partial = ([k for k in ("C2", "Sleep / jitter") if k not in summary and not (k == "C2" and p2p)]
               if primary.get("kind") != "stager" else [])
    out = {"family": "Cobalt Strike", "kind": primary.get("kind", "beacon"), "method": method,
           "status": "partial configuration" if partial else "configuration",
           "indicators": ind,
           "confidence": confidence, "summary": summary, "c2": hosts,
           "fields": primary.get("fields") or {},
           "agreement": agreement,
           "sections": vdis.get("sections") or {},
           "public_key": vdis.get("public_key") or "",
           "tools": {"1768": {k: x for k, x in v1768.items() if k != "_messages"},
                     "dissect": vdis},
           "_messages": v1768.get("_messages", [])}
    if agreement == "differ":
        out["note"] = ("1768.py and dissect.cobaltstrike report different C2 hosts: compare both sub-tabs "
                       "before acting on them.")
    return out
