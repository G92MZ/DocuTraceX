"""AsyncRAT / DcRAT / QuasarRAT (and forks) configuration from .NET assemblies.

Their ``Settings`` class keeps every value as a base64 string encrypted with
the same scheme (Quasar 1.4 → AsyncRAT → DcRAT):
``base64( HMAC-SHA256[32] | IV[16] | AES-256-CBC(ciphertext) )`` with
``key | hmac_key = PBKDF2-SHA1(master key, salt, 50000 iterations)``. The master
key is another string of the same class (AsyncRAT/DcRAT: base64 of an ASCII
key; Quasar: plain). All of them are user strings (#US heap), so the
extractor reads that heap, tries every plausible master key against one
encrypted value (the HMAC says when it is right) and then decrypts the rest.
Older Quasar (1.3) used AES-128-CBC with ``MD5(key)`` and no HMAC: tried too.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
from typing import Any

SALTS = (
    ("Quasar / AsyncRAT", bytes.fromhex("bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941")),
    ("DcRAT", b"DcRatByqwqdanchun"),
)
ITERATIONS = 50000
MAX_KEYS = 40
MARKERS = (("DcRAT", (b"DcRat", b"D\x00c\x00R\x00a\x00t")),
           ("AsyncRAT", (b"AsyncClient", b"AsyncRAT", b"A\x00s\x00y\x00n\x00c\x00R\x00A\x00T", b"Pastebin")),
           ("QuasarRAT", (b"Quasar", b"Q\x00u\x00a\x00s\x00a\x00r", b"xClient")))
_HOST = re.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$|^\d{1,3}(?:\.\d{1,3}){3}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _clr_metadata(data: bytes) -> bytes | None:
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]          # CLR runtime header
        if not d.VirtualAddress:
            return None
        cor = pe.get_data(d.VirtualAddress, 72)
        md_rva, md_size = struct.unpack_from("<II", cor, 8)
        return pe.get_data(md_rva, md_size)
    except Exception:  # noqa: BLE001
        return None


def user_strings(data: bytes) -> list[str]:
    """Every string of the #US heap of a .NET assembly."""
    md = _clr_metadata(data)
    if not md or md[:4] != b"BSJB":
        return []
    vlen = struct.unpack_from("<I", md, 12)[0]
    pos = 16 + vlen + 2
    nstreams = struct.unpack_from("<H", md, pos)[0]
    pos += 2
    us = None
    for _ in range(nstreams):
        off, size = struct.unpack_from("<II", md, pos)
        name_end = md.index(b"\x00", pos + 8)
        name = md[pos + 8:name_end]
        pos = pos + 8 + ((name_end - (pos + 8)) // 4 + 1) * 4
        if name == b"#US":
            us = md[off:off + size]
    if not us:
        return []
    out, i = [], 1
    while i < len(us):
        b = us[i]
        if b & 0x80 == 0:
            n, i = b, i + 1
        elif b & 0xC0 == 0x80 and i + 1 < len(us):
            n, i = ((b & 0x3F) << 8) | us[i + 1], i + 2
        elif i + 3 < len(us):
            n, i = ((b & 0x1F) << 24) | (us[i + 1] << 16) | (us[i + 2] << 8) | us[i + 3], i + 4
        else:
            break
        if n == 0:
            continue
        raw = us[i:i + n - 1] if n % 2 else us[i:i + n]
        out.append(raw.decode("utf-16-le", "replace"))
        i += n
    return out


def prefilter(data: bytes) -> bool:
    return data[:2] == b"MZ" and b"BSJB" in data


def _b64(s: str) -> bytes | None:
    if len(s) < 8 or len(s) % 4 or not _B64.match(s):
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _aes_cbc(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = d.update(ct) + d.finalize()
    except Exception:  # noqa: BLE001
        return None
    pad = pt[-1] if pt else 0
    if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    return pt[:-pad]


def _derive(master: bytes, salt: bytes) -> tuple[bytes, bytes]:
    k = hashlib.pbkdf2_hmac("sha1", master, salt, ITERATIONS, 96)
    return k[:32], k[32:]


def _dec_v14(blob: bytes, key: bytes, auth: bytes) -> str | None:
    if len(blob) < 64 or (len(blob) - 48) % 16:
        return None
    if not hmac.compare_digest(hmac.new(auth, blob[32:], hashlib.sha256).digest(), blob[:32]):
        return None
    pt = _aes_cbc(key, blob[32:48], blob[48:])
    return pt.decode("utf-8", "replace") if pt is not None else None


def _dec_v13(blob: bytes, master: bytes) -> str | None:
    if len(blob) < 32 or len(blob) % 16:
        return None
    pt = _aes_cbc(hashlib.md5(master).digest(), blob[:16], blob[16:])
    if pt is None:
        return None
    try:
        s = pt.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if s and all(c.isprintable() for c in s) else None


_FILE_EXT = {"exe", "dll", "dat", "bin", "txt", "log", "ps1", "vbs", "js", "bat", "cmd", "lnk", "zip",
             "tmp", "sys", "scr", "json", "xml", "db", "ini", "cfg", "pdb", "config"}


def _is_host(s: str) -> bool:
    if not _HOST.match(s):
        return False
    tld = s.rsplit(".", 1)[-1].lower()
    if tld.isdigit():
        return True
    if tld in _FILE_EXT:
        return False
    try:
        from ..tlds import is_known
        return is_known(tld)
    except Exception:  # noqa: BLE001
        return True


def _classify(values: list[str]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    hosts: list[str] = []
    for v in values:
        parts = [p.strip() for p in re.split(r"[;,]", v) if p.strip()]
        hp = [p for p in parts if ":" in p and _is_host(p.rsplit(":", 1)[0]) and p.rsplit(":", 1)[1].isdigit()]
        if hp:
            summary.setdefault("C2", []).extend(hp)
            hosts += [p.rsplit(":", 1)[0] for p in hp]
        elif parts and all(_is_host(p) for p in parts):
            summary.setdefault("Hosts", []).extend(parts)
            hosts += parts
        elif parts and all(p.isdigit() and 0 < int(p) < 65536 for p in parts):
            summary.setdefault("Ports", []).extend(parts)
        elif re.match(r"^v?\d+(\.\d+){1,3}$", v):
            summary.setdefault("Version", v)
        elif "mutex" in v.lower() or re.match(r"^[A-Za-z]+_[A-Za-z0-9]{6,}$", v):
            summary.setdefault("Mutex", v)
        elif v.lower().startswith("http"):
            summary.setdefault("URL", v)
        elif v.startswith("%") and v.endswith("%"):
            summary.setdefault("Install folder", v)
    if "Hosts" in summary and "Ports" in summary and "C2" not in summary:
        summary["C2"] = [f"{h}:{p}" for h in summary["Hosts"] for p in summary["Ports"]]
    return {"summary": summary, "hosts": list(dict.fromkeys(hosts))}


def _family(data: bytes, salt_name: str) -> str:
    if salt_name == "DcRAT":
        return "DcRAT"
    for name, marks in MARKERS:
        if any(m in data for m in marks):
            return name
    return "AsyncRAT / Quasar family"


def extract(data: bytes) -> dict[str, Any] | None:
    if not prefilter(data):
        return None
    strings = user_strings(data)
    if not strings:
        return None
    blobs = {s: b for s in strings for b in [_b64(s)] if b and len(b) >= 32}
    enc14 = [s for s, b in blobs.items() if len(b) >= 64 and (len(b) - 48) % 16 == 0]
    keys: list[bytes] = []
    for s in strings:
        if 8 <= len(s) <= 128:
            b = blobs.get(s) or _b64(s)
            if b and 8 <= len(b) <= 96 and all(32 <= c < 127 for c in b):
                keys.append(b)              # AsyncRAT / DcRAT: base64 of the key string
            keys.append(s.encode("utf-8"))   # Quasar: the key string itself
    keys = list(dict.fromkeys(keys))[:MAX_KEYS]
    if enc14:
        probe = blobs[enc14[0]]
        for salt_name, salt in SALTS:
            for master in keys:
                key, auth = _derive(master, salt)
                if _dec_v14(probe, key, auth) is None:
                    continue
                values = {s: v for s in enc14 for v in [_dec_v14(blobs[s], key, auth)] if v is not None}
                return _result(data, values, salt_name, "AES-256-CBC + HMAC-SHA256, PBKDF2 key", master)
    enc13 = [s for s, b in blobs.items() if len(b) % 16 == 0]
    for master in keys:
        values = {s: v for s in enc13 for v in [_dec_v13(blobs[s], master)] if v is not None}
        if len(values) >= 2:
            return _result(data, values, "", "AES-128-CBC, MD5(key) (Quasar 1.3)", master)
    return None


def _result(data: bytes, values: dict[str, str], salt_name: str, method: str, master: bytes) -> dict[str, Any] | None:
    plain = [v for v in values.values() if v]
    cls = _classify(plain)
    if not cls["hosts"]:
        return None
    fam = _family(data, salt_name)
    fields = {f"value {i + 1}": (v if len(v) <= 300 else v[:300] + "…") for i, v in enumerate(plain)}
    fields["master key"] = master.decode("latin-1")
    return {"family": fam, "kind": "RAT", "method": f"{method} — {len(plain)} values decrypted",
            "confidence": "high", "summary": cls["summary"], "c2": cls["hosts"], "fields": fields}
