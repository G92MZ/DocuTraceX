"""Stealers and RATs common in invoice-phishing chains.

* **RedLine / META** (.NET): ``IP`` (C2, ``host:port``, several joined by
  ``|``) and ``ID`` (build tag) are ``base64( xor( base64(value), key ) )``
  with the XOR key a plain string of the same class.
* **Snake Keylogger / 404** (.NET): strings DES-ECB encrypted with
  ``MD5(key string)[:8]``, base64; exfiltration over SMTP / FTP / Telegram.
* **Raccoon Stealer v2** (native): strings ``base64( RC4(key, value) )`` with
  the RC4 key a plain string in the binary; the C2 is an ``http(s)://`` URL.
* **Warzone / AveMaria** (native): ``.bss`` section = ``[key length DWORD]
  [RC4 key][RC4(config)]``; config = ``[host length DWORD][host UTF-16][port]``.
* **DarkGate**: settings base64-encoded with a *custom alphabet* (a 64-char
  permutation of the standard one stored in the binary / script).

Every one tries each candidate key it finds and only reports values that
decrypt into something meaningful (a C2 endpoint, an account), so a wrong key
gives nothing rather than noise.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from typing import Any

from .dotnet_more import _BOT, _EMAIL, _FTP, _TOKEN
from .dotnet_rats import _b64, _is_host, user_strings
from .remcos import rc4

_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_HOSTPORT = re.compile(r"^((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
_URL = re.compile(r"^https?://([A-Za-z0-9.\-]+)(?::(\d{1,5}))?(/\S*)?$")
_ASCII = re.compile(rb"[\x20-\x7e]{6,512}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){6,512}")


def _printable(s: str) -> bool:
    return bool(s) and all(c.isprintable() for c in s)


def native_strings(data: bytes, limit: int = 4000) -> list[str]:
    out = [m.group(0).decode("ascii") for m in _ASCII.finditer(data)]
    out += [m.group(0).decode("utf-16-le") for m in _WIDE.finditer(data)]
    return list(dict.fromkeys(out))[:limit]


def _hostport(v: str) -> tuple[str, str] | None:
    m = _HOSTPORT.match(v.strip())
    if m and _is_host(m.group(1)) and 0 < int(m.group(2)) < 65536:
        return m.group(1), m.group(2)
    return None


def _url_host(v: str) -> str | None:
    m = _URL.match(v.strip())
    return m.group(1) if m and _is_host(m.group(1)) else None


# --- RedLine / META --------------------------------------------------------------------
def _redline_dec(value: str, key: str) -> str | None:
    raw = _b64(value)
    if not raw:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    x = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s))
    inner = _b64(x) if len(x) >= 4 else None
    if not inner:
        return None
    try:
        out = inner.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return out if _printable(out) else None


def redline(data: bytes, strings: list[str]) -> dict[str, Any] | None:
    enc = [s for s in strings if _b64(s)]
    if not enc:
        return None
    keys = [s for s in strings if 3 <= len(s) <= 64 and _printable(s) and s not in enc][:80]
    for key in keys:
        values = [v for s in enc for v in [_redline_dec(s, key)] if v]
        c2 = [hp for v in values for part in v.split("|") for hp in [_hostport(part)] if hp]
        if not c2:
            continue
        build = next((v for v in values if not any(_hostport(p) for p in v.split("|"))), "")
        named = b"RedLine" in data or b"R\x00e\x00d\x00L\x00i\x00n\x00e" in data
        meta = b"META" in data and not named
        fam = "RedLine Stealer" if named or not meta else "META Stealer"
        summary = {"C2": [f"{h}:{p}" for h, p in c2]}
        if build:
            summary["Build ID"] = build
        summary["XOR key"] = key
        return {"family": fam, "kind": "stealer", "method": "base64 + XOR(key) + base64 (.NET strings)",
                "confidence": "high", "summary": summary, "c2": [h for h, _ in c2],
                "fields": {**{f"value {i + 1}": v for i, v in enumerate(values)}, "key": key}}
    return None


# --- Snake Keylogger -------------------------------------------------------------------
def _des_ecb(key8: bytes, ct: bytes) -> str | None:
    try:
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:  # older cryptography
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        d = Cipher(TripleDES(key8 * 3), modes.ECB()).decryptor()
        pt = d.update(ct) + d.finalize()
    except Exception:  # noqa: BLE001
        return None
    pad = pt[-1] if pt else 0
    if not 1 <= pad <= 8 or pt[-pad:] != bytes([pad]) * pad:
        return None
    try:
        s = pt[:-pad].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if _printable(s) else None


def snake(data: bytes, strings: list[str]) -> dict[str, Any] | None:
    enc = [(s, b) for s in strings for b in [_b64(s)] if b and len(b) % 8 == 0]
    if len(enc) < 2:
        return None
    keys = [s for s in strings if 8 <= len(s) <= 128 and _printable(s) and not _b64(s)][:80]
    for key in keys:
        k8 = hashlib.md5(key.encode("utf-8")).digest()[:8]
        values = [v for _, b in enc for v in [_des_ecb(k8, b)] if v]
        if len(values) < 2:
            continue
        summary: dict[str, Any] = {}
        hosts: list[str] = []
        for v in values:
            if _EMAIL.match(v):
                summary.setdefault("Accounts", []).append(v)
            elif _is_host(v) and re.match(r"^(smtp|mail|ftp)\d*\.", v, re.IGNORECASE):
                summary.setdefault("Servers", []).append(v)
                hosts.append(v)
            elif _TOKEN.match(v):
                summary["Telegram-style bot token"] = v
            elif _BOT.search(v) or _FTP.match(v):
                summary.setdefault("Exfil URL", v)
                h = re.sub(r"^(https?|ftp)://([^@/]*@)?", "", v, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
                if _is_host(h):
                    hosts.append(h)
            elif v in ("25", "465", "587", "2525", "21"):
                summary["Port"] = v
        if not hosts and "Accounts" not in summary:
            continue
        named = any("snake" in v.lower() for v in values) or b"Snake" in data
        return {"family": "Snake Keylogger" if named else "Snake-like keylogger", "kind": "stealer",
                "method": "DES-ECB, key MD5(string)[:8] (.NET strings)",
                "confidence": "high" if named else "medium", "summary": summary,
                "c2": list(dict.fromkeys(hosts)),
                "fields": {**{f"value {i + 1}": v for i, v in enumerate(values)}, "key string": key}}
    return None


# --- Raccoon Stealer v2 ------------------------------------------------------------------
def _ksa(key: bytes) -> list[int]:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def _rc4_prefix(ksa: list[int], data: bytes, n: int) -> bytes:
    s = ksa[:]
    i = j = 0
    out = bytearray()
    for c in data[:n]:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

def raccoon(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ":
        return None
    strings = [s for s in native_strings(data) if len(s) <= 256]
    enc = [(s, b) for s in strings for b in [_b64(s)] if b and 4 <= len(b) <= 512][:300]
    if not enc:
        return None
    keys = [s for s in strings if 6 <= len(s) <= 64 and not _b64(s)][:150]
    for key in keys:
        kb = key.encode("latin-1")
        ksa = _ksa(kb)
        if not any(_rc4_prefix(ksa, b, 4) in (b"http", b"HTTP") for _, b in enc):
            continue                                    # cheap probe: no URL with this key
        values = []
        for _, b in enc:
            pt = rc4(kb, b)
            try:
                v = pt.decode("ascii")
            except UnicodeDecodeError:
                continue
            if _printable(v):
                values.append(v)
        urls = [v for v in values if _url_host(v)]
        if not urls:
            continue
        markers = [v for v in values if v.startswith(("machineId=", "configId=")) or v in ("&configId=", "machineId=")]
        fam = "Raccoon Stealer v2" if markers else "RC4-encrypted C2 (Raccoon-like)"
        return {"family": fam, "kind": "stealer", "method": "base64 + RC4 with a key string from the binary",
                "confidence": "high" if markers else "medium",
                "summary": {"C2": urls, "RC4 key": key, **({"Markers": markers} if markers else {})},
                "c2": [h for u in urls for h in [_url_host(u)] if h],
                "fields": {f"value {i + 1}": v for i, v in enumerate(values[:60])}}
    return None


# --- Warzone / AveMaria --------------------------------------------------------------------
def _bss(data: bytes) -> bytes | None:
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
    except Exception:  # noqa: BLE001
        return None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".bss":
            return s.get_data()
    return None


def warzone(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ" or b".bss" not in data[:0x400]:
        return None
    blob = _bss(data)
    if not blob or len(blob) < 16:
        return None
    klen = struct.unpack_from("<I", blob, 0)[0]
    if not 4 <= klen <= 256 or 4 + klen + 8 > len(blob):
        return None
    cfg = rc4(blob[4:4 + klen], blob[4 + klen:4 + klen + 2048])
    hlen = struct.unpack_from("<I", cfg, 0)[0]
    if not 2 <= hlen <= 512 or hlen % 2 or 4 + hlen + 2 > len(cfg):
        return None
    try:
        host = cfg[4:4 + hlen].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    port = struct.unpack_from("<H", cfg, 4 + hlen)[0]
    if not _is_host(host) or not port:
        return None
    return {"family": "Warzone / AveMaria", "kind": "RAT", "method": f".bss: RC4 (key {klen} bytes)",
            "confidence": "high", "summary": {"C2": [f"{host}:{port}"]}, "c2": [host],
            "fields": {"host": host, "port": str(port), "key": blob[4:4 + klen].hex()}}


# --- DarkGate --------------------------------------------------------------------------------
_ALPHA = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{64,65}(?![A-Za-z0-9+/=])")


def _custom_b64(s: str, alphabet: str) -> bytes | None:
    table = str.maketrans(alphabet[:64], _STD)
    try:
        return base64.b64decode(s.translate(table) + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def darkgate(data: bytes) -> dict[str, Any] | None:
    alphabets = []
    for m in _ALPHA.finditer(data):
        a = m.group(0).decode()[:64]
        if len(set(a)) == 64 and set(a) <= set(_STD) and a != _STD:
            alphabets.append(a)
    if not alphabets:
        return None
    strings = [s for s in native_strings(data) if 8 <= len(s) <= 2048 and re.match(r"^[A-Za-z0-9+/=]+$", s)]
    for alpha in alphabets[:4]:
        values = []
        for s in strings:
            if s.startswith(alpha[:20]):
                continue
            b = _custom_b64(s, alpha)
            if not b:
                continue
            try:
                v = b.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if _printable(v.replace("\r", "").replace("\n", "")):
                values.append(v)
        urls, hosts = [], []
        for v in values:
            for part in re.split(r"[\r\n|,]+", v):
                part = part.strip()
                if "=" in part and part.split("=", 1)[0].isdigit():
                    part = part.split("=", 1)[1]
                h = _url_host(part)
                if h:
                    urls.append(part)
                    hosts.append(h)
        if not urls:
            continue
        return {"family": "DarkGate", "kind": "loader", "method": "base64 with a custom alphabet",
                "confidence": "medium", "summary": {"C2": list(dict.fromkeys(urls)), "Alphabet": alpha},
                "c2": list(dict.fromkeys(hosts)),
                "fields": {f"value {i + 1}": v[:300] for i, v in enumerate(values[:40])}}
    return None


def extract_all(data: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if data[:2] == b"MZ" and b"BSJB" in data:
        strings = user_strings(data)
        for fn in (redline, snake):
            r = fn(data, strings) if strings else None
            if r:
                out.append(r)
                break
    else:
        for fn in (warzone, raccoon):
            r = fn(data)
            if r:
                out.append(r)
                break
    if not out:
        r = darkgate(data)
        if r:
            out.append(r)
    return out
