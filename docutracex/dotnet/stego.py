"""Payloads hidden in the pixels of a Bitmap resource (the classic .NET crypter:
``GetPixel`` over the image, the R / G / B bytes form the next stage, often
XOR-ed with a key literal). Static: the PNG is decoded with Pillow and the
usual pixel orders are read; a result is kept only if it is a real PE (``MZ``
with a ``PE\\0\\0`` header) or a recognisable archive. Nothing is run."""

from __future__ import annotations

import hashlib
import io
import struct
import zlib
from typing import Any, Iterable

MAX_PIXELS = 25_000_000
_ORDERS = {"RGB": (0, 1, 2), "BGR": (2, 1, 0), "RGBA": (0, 1, 2, 3), "ARGB": (3, 0, 1, 2), "BGRA": (2, 1, 0, 3)}


def _pe_ok(b: bytes) -> bool:
    if len(b) < 0x100 or b[:2] != b"MZ":
        return False
    off = struct.unpack_from("<I", b, 0x3C)[0]
    return 0x40 <= off < min(len(b) - 4, 0x10000) and b[off:off + 4] == b"PE\x00\x00"


def _pe_size(b: bytes) -> int:
    """End of the last section (headers + raw data): where the PE really ends."""
    try:
        off = struct.unpack_from("<I", b, 0x3C)[0]
        nsec, opt = struct.unpack_from("<H", b, off + 6)[0], struct.unpack_from("<H", b, off + 20)[0]
        end = 0
        for i in range(min(nsec, 96)):
            sh = off + 24 + opt + 40 * i
            raw_size, raw_ptr = struct.unpack_from("<II", b, sh + 16)
            end = max(end, raw_ptr + raw_size)
        return end if 0 < end <= len(b) else len(b)
    except struct.error:
        return len(b)


def _kind(b: bytes) -> str | None:
    if _pe_ok(b):
        return "exe"
    if b[:4] == b"PK\x03\x04":
        return "zip"
    return None


def _streams(img: Any) -> Iterable[tuple[str, bytes]]:
    from PIL import Image
    rgba = img.convert("RGBA")
    for major, im in (("rows", rgba), ("columns", rgba.transpose(Image.Transpose.TRANSPOSE))):
        raw = im.tobytes()
        for name, idx in _ORDERS.items():
            if len(idx) == 4 and name == "RGBA":
                yield f"{major}, {name}", raw
                continue
            out = bytearray(len(raw) // 4 * len(idx))
            for j, c in enumerate(idx):
                out[j::len(idx)] = raw[c::4]
            yield f"{major}, {name}", bytes(out)


def _keys(strings: list[Any]) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for k in strings:
        if isinstance(k, (bytes, bytearray)):
            if 1 <= len(k) <= 256:
                out.append((f"byte[{len(k)}]", bytes(k)))
            continue
        if not k or len(k) > 128:
            continue
        kb = k.encode("utf-8", "ignore")
        out += [(f'"{k[:32]}"', kb), (f'MD5("{k[:32]}")', hashlib.md5(kb).digest())]
        if len(k) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in k):
            out.append((f'hex "{k[:32]}"', bytes.fromhex(k)))
    return out


def _xor(data: bytes, key: bytes) -> bytes:
    if len(key) == 1:
        k = key[0]
        return bytes(b ^ k for b in data)
    rep = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, rep))


def _tries(s: bytes, keys: list[tuple[str, bytes]]) -> Iterable[tuple[str, bytes]]:
    """Cheap tests on the head first; the whole stream only on a hit."""
    for skip, label in ((0, ""), (4, "length-prefixed, ")):
        body = s[skip:]
        if skip:
            n = struct.unpack_from("<I", s)[0]
            if not 0x100 <= n <= len(body):
                continue
            body = body[:n]
        yield f"{label}plain", body
        if body[:2] == b"\x1f\x8b" or body[:1] == b"\x78":
            try:
                yield f"{label}compressed", zlib.decompress(body, 47)
            except zlib.error:
                pass
        k0 = body[0] ^ 0x4D                                 # single-byte XOR: the key that makes "MZ"
        if k0 and body[1] ^ k0 == 0x5A:
            yield f"{label}XOR 0x{k0:02x}", _xor(body, bytes([k0]))
        for kl, kb in keys:
            if len(kb) > 1 and body[0] ^ kb[0] == 0x4D and body[1] ^ kb[1 % len(kb)] == 0x5A:
                yield f"{label}XOR key {kl}", _xor(body, kb)
            if len(kb) in (16, 24, 32) and len(body) >= 32:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                for mode, ml in ((modes.ECB(), "ECB"), (modes.CBC(b"\x00" * 16), "CBC iv=0")):
                    head = Cipher(algorithms.AES(kb), mode).decryptor().update(body[:16])
                    if head[:2] == b"MZ":
                        full = body[:len(body) // 16 * 16]
                        yield f"{label}AES-{len(kb) * 8} {ml} key {kl}", Cipher(algorithms.AES(kb), mode).decryptor().update(full)


def extract(png: bytes, strings: list[Any]) -> tuple[str, bytes, str] | None:
    """(how, payload, kind) of the first stage hidden in the image, or None."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(png))
        if img.width * img.height > MAX_PIXELS:
            return None
        img.load()
    except Exception:  # noqa: BLE001  (not an image Pillow can read)
        return None
    keys = _keys(strings)[:240]
    for order, s in _streams(img):
        for how, out in _tries(s, keys):
            kind = _kind(out)
            if kind:
                return f"pixels by {order}: {how}", out[:_pe_size(out)] if kind == "exe" else out, kind
    return None
