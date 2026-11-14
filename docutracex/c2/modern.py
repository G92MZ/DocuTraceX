"""Newer families whose configuration can be read statically from documented layouts:

- **Lumma Stealer**: each C2 domain is a base64 string whose first 32 bytes are the
  XOR key of the rest; the Steam profile / Telegram channel it falls back to; the
  build's request fields and user agent. Builds that moved the domains to ChaCha20
  or flattened their control flow give traces only.
- **Brute Ratel C4** (badger): the configuration is a base64 string encrypted with
  RC4; the key is a string of the badger (the builder default is tried first). The
  decrypted text is ``|``-separated: hosts, port, URIs, user agent, sleep…
- **Havoc** (Demon, the C agent): the configuration buffer of an unencrypted build —
  sleep / jitter, injection methods, the spawn-to processes, kill date, working
  hours, HTTP method, hosts and ports, TLS, user agent, headers, URIs, proxy.
- **Pure family** (PureCrypter / PureLogs / PureHVNC / PureRAT): .NET; the settings
  are a protobuf message compressed with GZip and stored as base64 in the
  assembly's strings — read here with a generic protobuf reader.

Everything is read from the bytes; nothing runs. Layouts come from public
analyses and are exercised by inert samples: real builds that differ give
"indicators" or nothing, never a guess.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import re
import struct
from typing import Any

from .dotnet_rats import _is_host, user_strings
from .remcos import rc4
from .stealers import _ksa, _rc4_prefix, native_strings

_B64 = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
_DOMAIN = re.compile(r"^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$", re.I)
_DEAD_DROP = re.compile(r"https?://(?:t\.me/[A-Za-z0-9_]{3,64}|steamcommunity\.com/(?:profiles/\d{10,20}|id/[A-Za-z0-9_-]{2,64}))")


def _b64(s: str) -> bytes | None:
    if not _B64.match(s):
        return None
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _printable(s: str) -> bool:
    return bool(s) and all(c.isprintable() for c in s)


# --- Lumma Stealer -------------------------------------------------------------------------
_LUMMA_TRACES = ((b"lid=", "lid= (build ID request field)"), (b"act=recive_message", "act=recive_message request"),
                 (b"TeslaBrowser/", "TeslaBrowser user agent"), (b"LummaC2", "LummaC2 string"),
                 (b"Lumma", "Lumma string"), (b"hwid=", "hwid= request field"), (b"pid=", "pid= request field"))


def lumma(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ":
        return None
    strings = native_strings(data)
    domains: list[str] = []
    for s in strings:
        raw = _b64(s)
        if not raw or not 36 <= len(raw) <= 32 + 128:
            continue
        key, body = raw[:32], raw[32:]
        pt = bytes(b ^ key[i % 32] for i, b in enumerate(body)).rstrip(b"\x00")
        try:
            d = pt.decode("ascii")
        except UnicodeDecodeError:
            continue
        if _DOMAIN.match(d) and _is_host(d):
            domains.append(d.lower())
    traces = list(dict.fromkeys(what for needle, what in _LUMMA_TRACES if needle in data))
    drops = list(dict.fromkeys(m.group(0) for m in _DEAD_DROP.finditer(data.decode("latin-1"))))
    if not domains:
        if len(traces) >= 2:
            return {"family": "Lumma Stealer", "kind": "indicators", "method": "traces of the family",
                    "confidence": "low", "summary": {"Traces": traces, **({"Dead drop": drops} if drops else {}),
                                                    "Note": "the C2 domains are not readable statically in this build "
                                                            "(ChaCha20 or flattened code): a memory dump shows them"},
                    "c2": [], "fields": {}}
        return None
    domains = list(dict.fromkeys(domains))
    summary: dict[str, Any] = {"C2": domains}
    if drops:
        summary["Dead drop (fallback)"] = drops
    if traces:
        summary["Traces"] = traces
    summary["Note"] = ("each domain is base64 with its own 32-byte XOR key in front; the stealer tries them in order "
                       "and asks the first that answers for what to steal")
    return {"family": "Lumma Stealer" if traces else "Lumma-like stealer", "kind": "stealer",
            "method": "base64 + 32-byte XOR key per C2 domain", "confidence": "high" if traces else "medium",
            "summary": summary, "c2": domains, "dead_drop": drops,
            "fields": {f"C2 {i + 1}": d for i, d in enumerate(domains)}}


# --- Brute Ratel C4 ---------------------------------------------------------------------------
BRC4_DEFAULT_KEY = "bYXJm/3#M?:XyMBF"
_BRC4_TRACES = ((b"badger_", "badger_ string"), (b"b\x00a\x00d\x00g\x00e\x00r", "badger string (UTF-16)"),
                (b"BRc4", "BRc4 string"), (b"bYXJm/3#M?:XyMBF", "the builder's default configuration key"))
_PORT = re.compile(r"^\d{1,5}$")


def brute_ratel(data: bytes) -> dict[str, Any] | None:
    strings = native_strings(data)
    blobs = [(s, b) for s in strings for b in [_b64(s)] if b and len(b) >= 24][:200]
    if not blobs:
        return None
    keys = [BRC4_DEFAULT_KEY] + [s for s in strings if 8 <= len(s) <= 40 and s != BRC4_DEFAULT_KEY and not _b64(s)][:150]
    for key in keys:
        ksa = _ksa(key.encode("latin-1"))
        for _s, blob in blobs:
            head = _rc4_prefix(ksa, blob, 12)              # cheap probe before the whole blob
            if not all(32 <= c < 127 for c in head):
                continue
            pt = rc4(key.encode("latin-1"), blob)
            try:
                text = pt.decode("ascii")
            except UnicodeDecodeError:
                continue
            if "|" not in text or not _printable(text):
                continue
            parts = text.split("|")
            hosts = [p for p in parts if _is_host(p) and ("." in p)]
            ports = [p for p in parts if _PORT.match(p) and 0 < int(p) < 65536]
            if not hosts or not ports:
                continue
            uris = [p for p in parts if p.startswith("/")]
            ua = next((p for p in parts if p.startswith("Mozilla/")), "")
            # the port is the field right after its host (the first fields are flags)
            after = {parts[i]: parts[i + 1] for i in range(len(parts) - 1)
                     if parts[i] in hosts and _PORT.match(parts[i + 1]) and 0 < int(parts[i + 1]) < 65536}
            summary: dict[str, Any] = {"C2": [f"{h}:{after.get(h, ports[-1])}" for h in hosts]}
            if uris:
                summary["URIs"] = uris
            if ua:
                summary["User agent"] = ua
            summary["Key"] = key + (" (builder default)" if key == BRC4_DEFAULT_KEY else "")
            traces = [what for needle, what in _BRC4_TRACES if needle in data]
            if traces:
                summary["Traces"] = traces
            return {"family": "Brute Ratel C4 (badger)", "kind": "RAT", "method": "base64 + RC4",
                    "confidence": "high" if (key == BRC4_DEFAULT_KEY or traces) else "medium", "summary": summary,
                    "c2": list(dict.fromkeys(hosts)),
                    "fields": {f"field {i + 1}": p for i, p in enumerate(parts) if p}}
    traces = [what for needle, what in _BRC4_TRACES if needle in data]
    if len(traces) >= 2:
        return {"family": "Brute Ratel C4 (badger)", "kind": "indicators", "method": "traces of the family",
                "confidence": "low", "summary": {"Traces": traces}, "c2": [], "fields": {}}
    return None


# --- Havoc (Demon) ------------------------------------------------------------------------------
_WEXE = re.compile(rb"((?:[\x20-\x7e]\x00){4,260}?\.\x00e\x00x\x00e\x00\x00\x00)", re.I)


class _Buf:
    def __init__(self, data: bytes, pos: int) -> None:
        self.d, self.p = data, pos

    def u32(self) -> int:
        if self.p + 4 > len(self.d):
            raise ValueError("end")
        v = struct.unpack_from("<I", self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self) -> int:
        if self.p + 8 > len(self.d):
            raise ValueError("end")
        v = struct.unpack_from("<Q", self.d, self.p)[0]
        self.p += 8
        return v

    def wstr(self) -> str:
        n = self.u32()
        if n > 4096 or n % 2 or self.p + n > len(self.d):
            raise ValueError("string")
        s = self.d[self.p:self.p + n].decode("utf-16-le", "strict").rstrip("\x00")
        self.p += n
        if not _printable(s) and s:
            raise ValueError("text")
        return s


_ALLOC = {0: "default", 1: "VirtualAllocEx", 2: "NtAllocateVirtualMemory (syscall)"}
_EXEC = {0: "default", 1: "CreateRemoteThread", 2: "NtCreateThreadEx (syscall)", 3: "NtQueueApcThread"}


def havoc(data: bytes) -> dict[str, Any] | None:
    for m in _WEXE.finditer(data):
        start = m.start() - 4
        if start < 16 or struct.unpack_from("<I", data, start)[0] != len(m.group(1)):
            continue
        try:
            b = _Buf(data, start - 16)
            sleep, jitter, alloc, execute = b.u32(), b.u32(), b.u32(), b.u32()
            if sleep > 86400 or jitter > 100 or alloc > 5 or execute > 5:
                continue
            spawn64, spawn32 = b.wstr(), b.wstr()
            if not spawn32.lower().endswith(".exe"):
                continue
            kill, hours = b.u64(), b.u32()
            method = b.wstr()
            if method.upper() not in ("POST", "GET"):
                continue
            rotation, count = b.u32(), b.u32()
            if not 1 <= count <= 32:
                continue
            hosts = []
            for _ in range(count):
                h = b.wstr()
                port = b.u32()
                if not _is_host(h) or not 0 < port < 65536:
                    raise ValueError("host")
                hosts.append((h, port))
            secure, ua = b.u32(), b.wstr()
            headers = [b.wstr() for _ in range(min(b.u32(), 32))]
            uris = [b.wstr() for _ in range(min(b.u32(), 32))]
            proxy = ""
            if b.u32() == 1:
                proxy = b.wstr()
        except (ValueError, UnicodeDecodeError, struct.error):
            continue
        scheme = "https" if secure else "http"
        summary: dict[str, Any] = {
            "C2": [f"{scheme}://{h}:{p}" for h, p in hosts], "Method": method, "URIs": uris or ["/"],
            "User agent": ua, "Sleep": f"{sleep} s, jitter {jitter} %", "Spawn to (x64)": spawn64,
            "Spawn to (x86)": spawn32, "Memory allocation": _ALLOC.get(alloc, str(alloc)),
            "Execution": _EXEC.get(execute, str(execute)),
            "Host rotation": {0: "round robin", 1: "random"}.get(rotation, str(rotation))}
        if headers:
            summary["Headers"] = headers
        if kill:
            summary["Kill date (epoch)"] = kill
        if hours:
            summary["Working hours (packed)"] = f"0x{hours:08x}"
        if proxy:
            summary["Proxy"] = proxy
        return {"family": "Havoc (Demon)", "kind": "RAT", "method": "the Demon's configuration buffer (unencrypted build)",
                "confidence": "high" if (b"Demon" in data or b"D\x00e\x00m\x00o\x00n" in data or uris) else "medium",
                "summary": summary, "c2": list(dict.fromkeys(h for h, _ in hosts)),
                "fields": {"sleep": sleep, "jitter": jitter, "spawn64": spawn64, "spawn32": spawn32, "method": method,
                           **{f"host {i + 1}": f"{h}:{p}" for i, (h, p) in enumerate(hosts)}, "secure": secure,
                           "user_agent": ua, **{f"uri {i + 1}": u for i, u in enumerate(uris)}}}
    return None


# --- Pure family (.NET, protobuf settings) ------------------------------------------------------
def _varint(b: bytes, i: int) -> tuple[int, int]:
    shift = v = 0
    while True:
        if i >= len(b) or shift > 63:
            raise ValueError("varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not c & 0x80:
            return v, i
        shift += 7


def protobuf(b: bytes, depth: int = 0) -> list[tuple[str, Any]]:
    """Generic protobuf reader: [(field path, value)] — strings, numbers, nested messages."""
    out: list[tuple[str, Any]] = []
    i = 0
    while i < len(b):
        key, i = _varint(b, i)
        num, wt = key >> 3, key & 7
        if not 1 <= num <= 536870911:
            raise ValueError("field")
        if wt == 0:
            v, i = _varint(b, i)
            out.append((str(num), v))
        elif wt == 2:
            n, i = _varint(b, i)
            if i + n > len(b):
                raise ValueError("length")
            chunk = b[i:i + n]
            i += n
            try:
                s = chunk.decode("utf-8")
                if _printable(s) or not s:
                    out.append((str(num), s))
                    continue
            except UnicodeDecodeError:
                pass
            if depth < 3:
                try:
                    out += [(f"{num}.{k}", v) for k, v in protobuf(chunk, depth + 1)]
                    continue
                except ValueError:
                    pass
            out.append((str(num), f"<{n} bytes>"))
        elif wt == 5:
            i += 4
        elif wt == 1:
            i += 8
        else:
            raise ValueError("wire type")
    return out


_PURE_TRACES = ((b"ProtoBuf", "protobuf-net"), (b"ProtoContract", "ProtoContract attribute"),
                (b"GZipStream", "GZipStream"), (b"PureHVNC", "PureHVNC string"), (b"PureLogs", "PureLogs string"),
                (b"PureCrypter", "PureCrypter string"), (b"PureRAT", "PureRAT string"))


def pure(data: bytes, strings: list[str] | None = None) -> dict[str, Any] | None:
    if data[:2] != b"MZ" or b"BSJB" not in data:
        return None
    strings = strings if strings is not None else user_strings(data)
    for s in strings:
        raw = _b64(s)
        if not raw or raw[:2] != b"\x1f\x8b":
            continue
        try:
            msg = gzip.decompress(raw)
            fields = protobuf(msg)
        except (OSError, EOFError, ValueError):
            continue
        texts = [(k, v) for k, v in fields if isinstance(v, str) and v]
        hosts = [v for _, v in texts if _is_host(v.split(":")[0]) and "." in v]
        ports = [v for _, v in fields if isinstance(v, int) and 0 < v < 65536]
        if not hosts:
            continue
        traces = list(dict.fromkeys(what for needle, what in _PURE_TRACES if needle in data))
        named = next((t for t in ("PureHVNC", "PureLogs", "PureCrypter", "PureRAT") if t.encode() in data), "")
        c2 = [h if ":" in h or not ports else f"{h}:{ports[0]}" for h in hosts]
        summary: dict[str, Any] = {"C2": c2, "Settings (protobuf)": {f"field {k}": v for k, v in fields[:40]}}
        if traces:
            summary["Traces"] = traces
        return {"family": f"Pure family ({named})" if named else "Pure family (PureLogs / PureHVNC / PureRAT)",
                "kind": "RAT", "method": "base64 + GZip + protobuf settings",
                "confidence": "high" if named else ("medium" if "protobuf-net" in traces else "low"),
                "summary": summary, "c2": list(dict.fromkeys(h.split(":")[0] for h in hosts)),
                "fields": {f"field {k}": v for k, v in fields[:60]}}
    return None


def extract_all(data: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fn in (havoc, brute_ratel, lumma, pure):
        try:
            r = fn(data)
        except Exception:  # noqa: BLE001  (one family never breaks the others)
            r = None
        if r:
            out.append(r)
            if r.get("kind") != "indicators":
                break
    return out
