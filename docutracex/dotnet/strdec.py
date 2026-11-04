"""Static string decryption for .NET (phase 2b). Nothing of the assembly is
run: the decryptor methods are *recognised* from their CIL (xor, Base64,
Rijndael / AES, MD5 of a key…) and the usual routines are re-implemented in
Python over the literals their callers pass (``ldstr x; call Decrypt``).

A result is kept only if it reads as text (printable, not the input again):
wrong guesses are simply discarded."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any, Iterable

MAX_INPUTS = 4000
MAX_RESULTS = 2000
_B64 = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")


def _printable(s: str) -> bool:
    if len(s) < 3:
        return False
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    letters = sum(1 for c in s if c.isalnum())
    return ok / len(s) >= 0.97 and letters / len(s) >= 0.4


def _text(b: bytes) -> str | None:
    for enc in ("utf-8", "utf-16-le"):
        try:
            s = b.decode(enc)
        except UnicodeDecodeError:
            continue
        s = s.rstrip("\x00")
        if _printable(s):
            return s
    return None


def _b64(s: str) -> bytes | None:
    if not _B64.match(s) or len(s) % 4:
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _xor_chars(s: str, key: str) -> str:
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s))


def _aes(data: bytes, key: bytes) -> Iterable[tuple[str, bytes]]:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(data) < 16 or len(data) % 16 or len(key) not in (16, 24, 32):
        return
    for mode, label in ((modes.ECB(), "ECB"), (modes.CBC(b"\x00" * 16), "CBC iv=0"), (modes.CBC(key[:16]), "CBC iv=key")):
        try:
            d = Cipher(algorithms.AES(key), mode).decryptor()
            out = d.update(data) + d.finalize()
        except ValueError:
            continue
        pad = out[-1]
        if 1 <= pad <= 16 and out.endswith(bytes([pad]) * pad):
            yield label, out[:-pad]


def _keys(raw: list[str]) -> list[tuple[str, bytes]]:
    """Key candidates from a key string: as text, MD5 / SHA-256 of it (Rijndael
    with MD5(key) is the classic of njRAT / Agent Tesla builders), Base64 of it."""
    out: list[tuple[str, bytes]] = []
    for k in raw:
        kb = k.encode()
        out += [(f'"{k[:24]}"', kb), (f'MD5("{k[:24]}")', hashlib.md5(kb).digest()),
                (f'SHA-256("{k[:24]}")', hashlib.sha256(kb).digest())]
        b = _b64(k)
        if b:
            out.append((f'Base64("{k[:24]}")', b))
    return out


def _attempts(s: str, keys: list[str], hints: set[str]) -> Iterable[tuple[str, str]]:
    raw = _b64(s)
    if raw is not None:
        t = _text(raw)
        if t:
            yield "Base64", t
    for kl, kb in _keys(keys):
        if raw is not None:
            if "aes" in hints:
                for ml, out in _aes(raw, kb):
                    t = _text(out)
                    if t:
                        yield f"AES-{len(kb) * 8} {ml}, key {kl}", t
            if "xor" in hints:
                t = _text(_xor(raw, kb))
                if t:
                    yield f"Base64 + XOR key {kl}", t
        if "xor" in hints and kl.startswith('"'):
            t = _xor_chars(s, kb.decode())
            if _printable(t):
                yield f"XOR chars key {kl}", t
    if "xor" in hints and not keys:                     # single-byte XOR, no key in sight
        data = raw if raw is not None else s.encode("latin-1", "ignore")
        for k in range(1, 256):
            t = _text(bytes(b ^ k for b in data))
            if t and t != s:
                yield f"{'Base64 + ' if raw is not None else ''}XOR 0x{k:02x}", t


_IOCISH = re.compile(r"(?i)[a-z0-9-]+\.[a-z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b|https?://|[a-z]:\\|%[a-z]+%|\w@\w+\.\w")


def _quality(s: str) -> int:
    """How much a candidate reads as real text: indicators, words, few symbols."""
    sym = sum(1 for c in s if not (c.isalnum() or c in " .:/\\-_@%,;=?&"))
    lower = sum(1 for c in s if c.islower() or c == " ")
    return (3 if _IOCISH.search(s) else 0) + (1 if lower / len(s) >= 0.5 else 0) + (1 if sym / len(s) < 0.05 else -1)


def _hints(m: dict[str, Any]) -> set[str]:
    calls = " ".join(m.get("calls") or [])
    h = set()
    if "xor" in m["_ops"]:
        h.add("xor")
    if re.search(r"Rijndael|Aes|SymmetricAlgorithm|ICryptoTransform|CreateDecryptor", calls):
        h.add("aes")
    if "FromBase64String" in calls:
        h.add("b64")
    return h


def decrypt(methods: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """methods: the internal CIL view (method, rid, calls, _ops, _sites, _all_strings)."""
    by_rid = {m["rid"]: m for m in methods}
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    n = 0
    for caller in methods:
        for rid, args in caller["_sites"]:
            dec = by_rid.get(rid)
            if dec is None:
                continue
            hints = _hints(dec)
            if not hints:
                continue
            data, extra = args[0], args[1:]
            keys = list(dict.fromkeys(extra + [k for k in dec["_all_strings"] if k != data]))[:6]
            n += 1
            if n > MAX_INPUTS or len(results) >= MAX_RESULTS:
                return results
            best = None
            for k, (how, out) in enumerate(_attempts(data, keys, hints)):
                if k > 400:
                    break
                if out == data:
                    continue
                sc = _quality(out) - (1 if how == "Base64" and hints - {"b64"} else 0)
                if "XOR 0x" in how and sc < 4:          # blind key: only clearly meaningful text
                    continue
                if best is None or sc > best[0]:
                    best = (sc, how, out)
            if best and best[0] >= 1 and (data, best[2]) not in seen:
                seen.add((data, best[2]))
                results.append({"decryptor": dec["method"], "caller": caller["method"], "input": data[:300],
                                "output": best[2][:4000], "how": best[1]})
    return results

