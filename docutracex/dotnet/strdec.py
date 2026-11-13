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


def _aes(data: bytes, key: bytes, any_pad: bool = False) -> Iterable[tuple[str, bytes]]:
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
        elif any_pad:                                   # zero / no padding (files are recognised by magic)
            yield label, out


def _keys(raw: list[Any]) -> list[tuple[str, bytes]]:
    """Key candidates from a key string: as text, MD5 / SHA-256 of it (Rijndael
    with MD5(key) is the classic of njRAT / Agent Tesla builders), Base64 of it;
    static byte[] arrays as they are."""
    out: list[tuple[str, bytes]] = []
    for k in raw:
        if isinstance(k, (bytes, bytearray)):
            if 1 <= len(k) <= 256:
                out += [(f"byte[{len(k)}] {bytes(k[:8]).hex()}…", bytes(k)),
                        (f"MD5(byte[{len(k)}])", hashlib.md5(k).digest())]
            continue
        kb = k.encode()
        out += [(f'"{k[:24]}"', kb), (f'MD5("{k[:24]}")', hashlib.md5(kb).digest()),
                (f'SHA-256("{k[:24]}")', hashlib.sha256(kb).digest())]
        b = _b64(k)
        if b:
            out.append((f'Base64("{k[:24]}")', b))
        if 2 <= len(k) <= 128 and len(k) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in k):
            out.append((f'hex "{k[:24]}"', bytes.fromhex(k)))   # keys handed between stages as hex text
    return out


def _rc4(key: bytes, data: bytes) -> bytes:
    """RC4, any key length (loaders write it inline; ``cryptography`` refuses odd sizes)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for n, c in enumerate(data):
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out[n] = c ^ S[(S[i] + S[j]) & 255]
    return bytes(out)


def _rc4_shape(m: dict[str, Any]) -> bool:
    """An inline RC4: a 256-entry state table, ``& 255`` and ``xor`` in one method."""
    ops = m.get("_ops") or ()
    return "xor" in ops and "and" in ops and ("rem" in ops or "rem.un" in ops) and 256 in (m.get("_ints") or ())


def _attempts(s: Any, keys: list[Any], hints: set[str]) -> Iterable[tuple[str, str]]:
    is_bytes = isinstance(s, (bytes, bytearray))
    raw = bytes(s) if is_bytes else _b64(s)
    if raw is not None and not is_bytes:
        t = _text(raw)
        if t:
            yield "Base64", t
    for kl, kb in _keys(keys):
        if raw is not None:
            if "aes" in hints:
                for ml, out in _aes(raw, kb):
                    t = _text(out)
                    if t:
                        yield f"{'' if is_bytes else 'Base64 + '}AES-{len(kb) * 8} {ml}, key {kl}", t
            if "xor" in hints:
                t = _text(_xor(raw, kb))
                if t:
                    yield f"{'byte[]' if is_bytes else 'Base64'} + XOR key {kl}", t
        if "xor" in hints and kl.startswith('"') and not is_bytes:
            t = _xor_chars(s, kb.decode())
            if _printable(t):
                yield f"XOR chars key {kl}", t
    if "xor" in hints and not keys:                     # single-byte XOR, no key in sight
        data = raw if raw is not None else s.encode("latin-1", "ignore")
        if is_bytes:
            t0 = _text(data)
            if t0:
                yield "byte[] (plain)", t0
        for k in range(1, 256):
            t = _text(bytes(b ^ k for b in data))
            if t and t != s:
                yield f"{'Base64 + ' if raw is not None and not is_bytes else ''}XOR 0x{k:02x}", t


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
            keys = [k for k in extra] + [k for k in dec.get("_arrays") or []] + [k for k in dec["_all_strings"] if k != data]
            keys = list({(type(k), k): k for k in keys}.values())[:8]
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
            if best and best[0] >= 1 and (str(data), best[2]) not in seen:
                seen.add((str(data), best[2]))
                shown = f"byte[{len(data)}] {bytes(data[:48]).hex()}" if isinstance(data, (bytes, bytearray)) else data[:300]
                results.append({"decryptor": dec["method"], "caller": caller["method"], "input": shown,
                                "output": best[2][:4000], "how": best[1]})
    return results



# --- encrypted resources --------------------------------------------------------
_MAGIC = (b"MZ", b"PK\x03\x04", b"%PDF", b"\x1f\x8b", b"\x89PNG", b"{\\rtf", b"\xd0\xcf\x11\xe0", b"Rar!", b"7z\xbc\xaf")


def _entropy(b: bytes) -> float:
    import math
    from collections import Counter
    b = b[:65536]
    return -sum(c / len(b) * math.log2(c / len(b)) for c in Counter(b).values()) if b else 0.0


def _payload(b: bytes) -> str | None:
    if not b.startswith(_MAGIC):
        return None
    # 2-byte magics come out of a wrong key by chance (1 in 65536 per try): ask for more
    if b[:2] == b"\x1f\x8b" and not (len(b) >= 4 and b[2] == 8 and b[3] < 0x20):
        return None
    if b[:2] == b"MZ" and len(b) >= 0x40:
        off = int.from_bytes(b[0x3C:0x40], "little")
        if off + 4 <= len(b) and b[off:off + 4] != b"PE\0\0" and b"This program" not in b[:256]:
            return None
    return {b"MZ": "exe", b"PK": "zip", b"%P": "pdf", b"\x1f\x8b": "gz", b"\x89P": "png"}.get(b[:2], "bin")


MAX_BLOB_KEYS = 300        # assembly-wide fallback: key strings tried at most


def _aes_head_ok(raw: bytes, key: bytes) -> bool:
    """Cheap pre-check: does block 1 decrypt to a known magic (ECB, CBC iv=0 or iv=key)?"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(raw) < 16 or len(raw) % 16:
        return False
    block = Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(raw[:16])
    return any(_payload(bytes(a ^ b for a, b in zip(block, iv))) for iv in (b"\x00" * 16, key[:16]))


def _type_of(m: dict[str, Any]) -> str:
    return str(m.get("method") or "").split("::")[0]


def decrypt_blob(raw: bytes, methods: list[dict[str, Any]]) -> tuple[str, bytes, str] | None:
    """Try the decryptors of the assembly (their key strings / static arrays and
    algorithm) on an encrypted resource; keep only a recognisable file.

    Key material is looked for in the decrypting method first, then in the rest
    of its class (loaders keep the key in a static field set by ``.cctor``), and
    last in every string of the assembly (bounded)."""
    if len(raw) < 16:
        return None
    crypto = [(m, (_hints(m) & {"aes", "xor"}) | ({"rc4"} if _rc4_shape(m) else set())) for m in methods]
    crypto = [(m, h) for m, h in crypto if h]
    if not crypto:
        return None

    def attempt(hints: set[str], material: list[Any], where: str) -> tuple[str, bytes, str] | None:
        for kl, kb in _keys(material):
            if "aes" in hints and len(kb) in (16, 24, 32) and _aes_head_ok(raw, kb):
                cands = [(ml, out) for ml, out in _aes(raw, kb, any_pad=True) if _payload(out)]
                if cands:                                 # ECB / CBC share block 1: keep the cleanest
                    ml, out = min(cands, key=lambda c: _entropy(c[1]))
                    return f"AES-{len(kb) * 8} {ml}, key {kl} ({where})", out, _payload(out) or "bin"
            if "rc4" in hints and kb and 1 <= len(kb) <= 256 and _payload(_rc4(kb, raw[:4])):
                out = _rc4(kb, raw)
                from ..stego import identify
                if identify(out):
                    return f"RC4 key {kl} ({where})", out, _payload(out) or "bin"
            if "xor" in hints and kb and _payload(_xor(raw[:4], kb)):
                out = _xor(raw, kb)
                ext = _payload(out)
                if ext:
                    return f"XOR key {kl} ({where})", out, ext
        return None

    for m, h in crypto:                                   # 1. the method itself
        got = attempt(h, list(m.get("_arrays") or []) + list(m["_all_strings"]), m["method"])
        if got:
            return got
    for m, h in crypto:                                   # 2. its class (static fields, .cctor)
        own = {id(m)}
        mat: list[Any] = []
        for o in methods:
            if id(o) not in own and _type_of(o) == _type_of(m):
                mat += list(o.get("_arrays") or []) + list(o["_all_strings"])
        got = attempt(h, list(dict.fromkeys(x if isinstance(x, str) else bytes(x) for x in mat)),
                      f"{m['method']}, key from its class")
        if got:
            return got
    every: list[Any] = []                                 # 3. the whole assembly
    for o in methods:
        every += [s for s in o["_all_strings"] if 4 <= len(s) <= 128]
    every = list(dict.fromkeys(every))[:MAX_BLOB_KEYS]
    hints = set().union(*(h for _m, h in crypto))
    return attempt(hints, every, f"{crypto[0][0]['method']}, key from the assembly's strings")
