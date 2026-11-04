"""Payloads hidden in images, for any image of a case (a Bitmap resource of a
.NET loader, a PNG in an archive, a native RT_BITMAP, an e-mail attachment…).

Static and generic: the image is decoded with Pillow and its pixels are read
the ways loaders write them —

* **byte streams**: by rows or by columns, channels RGB / BGR / RGBA / ARGB /
  BGRA (one byte per channel);
* **LSB**: the 1 or 2 low bits of R, G, B (and A), by rows or columns, packed
  most- or least-significant bit first;

— then each stream is tried as it is, after a 4-byte length prefix (LE / BE),
as Base64 text, compressed (zlib / gzip / raw deflate), XOR-ed with the single
byte that makes a known magic appear, and, when the caller knows candidate
keys (literals and static arrays of the carrying assembly), XOR / AES with them.

A result is kept **only if it is a well-formed file** (PE, ELF, Mach-O, ZIP,
7z, RAR, gzip, PDF, OLE, a script with a shebang…), checked structurally and
cut to its real size: wrong guesses never reach the case. Nothing is run."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
import struct
import zlib
from typing import Any, Callable, Iterable

MAX_PIXELS = 40_000_000
MAX_KEYS = 240
IMAGE_MAGIC = (b"\x89PNG\r\n\x1a\n", b"BM", b"GIF87a", b"GIF89a", b"\xff\xd8\xff", b"II*\x00", b"MM\x00*",
               b"RIFF", b"\x00\x00\x01\x00")
_ORDERS = {"RGB": (0, 1, 2), "BGR": (2, 1, 0), "RGBA": (0, 1, 2, 3), "ARGB": (3, 0, 1, 2), "BGRA": (2, 1, 0, 3)}


# --- what a real payload looks like ----------------------------------------------
def _pe(b: bytes) -> int | None:
    if len(b) < 0x100 or b[:2] != b"MZ":
        return None
    off = struct.unpack_from("<I", b, 0x3C)[0]
    if not (0x40 <= off < min(len(b) - 0xF8, 0x10000)) or b[off:off + 4] != b"PE\x00\x00":
        return None
    nsec, opt = struct.unpack_from("<HH", b, off + 6)[0], struct.unpack_from("<H", b, off + 20)[0]
    end = 0
    for i in range(min(nsec, 96)):
        sh = off + 24 + opt + 40 * i
        if sh + 24 > len(b):
            break
        raw_size, raw_ptr = struct.unpack_from("<II", b, sh + 16)
        end = max(end, raw_ptr + raw_size)
    return end if 0 < end <= len(b) else len(b)


def _elf(b: bytes) -> int | None:
    if len(b) < 64 or b[:4] != b"\x7fELF" or b[4] not in (1, 2) or b[5] not in (1, 2) or b[6] != 1:
        return None
    e = "<" if b[5] == 1 else ">"
    if b[4] == 1:
        etype, mach = struct.unpack_from(e + "HH", b, 16)
        phoff, shoff = struct.unpack_from(e + "II", b, 28)
        phes, phn, shes, shn = struct.unpack_from(e + "HHHH", b, 42)
    else:
        etype, mach = struct.unpack_from(e + "HH", b, 16)
        phoff, shoff = struct.unpack_from(e + "QQ", b, 32)
        phes, phn, shes, shn = struct.unpack_from(e + "HHHH", b, 54)
    if etype not in (1, 2, 3, 4) or mach == 0 or mach > 0x200 or phoff > len(b):
        return None
    end = max(phoff + phes * phn, shoff + shes * shn if shoff else 0)
    return end if 0 < end <= len(b) else len(b)


def _macho(b: bytes) -> int | None:
    m = b[:4]
    if m in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        e = "<" if m[0] in (0xCE, 0xCF) else ">"
        cpu, _sub, ftype, ncmds = struct.unpack_from(e + "iIII", b, 4)
        return len(b) if 1 <= ftype <= 12 and 0 < ncmds < 512 and cpu in (7, 12, 18, 0x1000007, 0x100000C) else None
    return None


def _zip(b: bytes) -> int | None:
    if b[:4] != b"PK\x03\x04":
        return None
    eocd = b.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(b):
        return None
    return eocd + 22 + struct.unpack_from("<H", b, eocd + 20)[0]


def _magic_only(sig: bytes, min_len: int = 64) -> Callable[[bytes], int | None]:
    def f(b: bytes) -> int | None:
        return len(b.rstrip(b"\x00")) if b.startswith(sig) and len(b) >= min_len else None
    return f


def _script(b: bytes) -> int | None:
    head = b[:4096]
    if not head.startswith(b"#!/") and not re.match(rb"(?i)\s*(?:powershell|\$[a-z_]+\s*=|function\s|@echo off)", head):
        return None
    text = b.split(b"\x00", 1)[0]
    ok = sum(1 for c in text[:65536] if 32 <= c < 127 or c in (9, 10, 13))
    return len(text) if len(text) >= 32 and ok >= 0.98 * min(len(text), 65536) else None


KINDS: list[tuple[str, bytes, Callable[[bytes], int | None]]] = [
    ("exe", b"MZ", _pe), ("elf", b"\x7fELF", _elf), ("macho", b"", _macho), ("zip", b"PK\x03\x04", _zip),
    ("7z", b"7z\xbc\xaf\x27\x1c", _magic_only(b"7z\xbc\xaf\x27\x1c")),
    ("rar", b"Rar!\x1a\x07", _magic_only(b"Rar!\x1a\x07")),
    ("gz", b"\x1f\x8b\x08", _magic_only(b"\x1f\x8b\x08", 32)), ("pdf", b"%PDF-", _magic_only(b"%PDF-")),
    ("ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", _magic_only(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 512)),
    ("script", b"", _script),
]
_MAGICS = [m for _, m, _ in KINDS if len(m) >= 2]


def identify(b: bytes) -> tuple[str, int] | None:
    """(kind, real size) when ``b`` starts with a well-formed file."""
    for kind, _m, check in KINDS:
        try:
            n = check(b)
        except (struct.error, IndexError):
            n = None
        if n:
            return kind, n
    return None


def _plausible_head(h: bytes) -> bool:
    return any(h.startswith(m) for m in _MAGICS) or h[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") \
        or h.startswith((b"#!/", b"\x78", b"\x1f\x8b"))


# --- pixel streams ----------------------------------------------------------------
def _streams(img: Any) -> Iterable[tuple[str, bytes]]:
    from PIL import Image
    rgba = img.convert("RGBA")
    try:
        import numpy as np
    except ImportError:          # bytes only, no LSB
        np = None
    for major, im in (("rows", rgba), ("columns", rgba.transpose(Image.Transpose.TRANSPOSE))):
        raw = im.tobytes()
        for name, idx in _ORDERS.items():
            if name == "RGBA":
                yield f"{major}, {name} bytes", raw
                continue
            out = bytearray(len(raw) // 4 * len(idx))
            for j, c in enumerate(idx):
                out[j::len(idx)] = raw[c::4]
            yield f"{major}, {name} bytes", bytes(out)
        if np is None:
            continue
        a = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 4)
        for chans, cl in (((0, 1, 2), "RGB"), ((0, 1, 2, 3), "RGBA")):
            sub = a[:, chans].reshape(-1)
            for nb in (1, 2):
                bits = np.unpackbits(sub[:, None], axis=1)[:, 8 - nb:].reshape(-1)
                for order in ("big", "little"):
                    packed = np.packbits(bits[:len(bits) // 8 * 8], bitorder=order).tobytes()
                    yield f"{major}, LSB{nb} {cl} ({'MSB' if order == 'big' else 'LSB'} first)", packed


# --- decodings of one stream ------------------------------------------------------
_B64 = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")


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
    return out[:MAX_KEYS]


def _xor(data: bytes, key: bytes) -> bytes:
    if len(key) == 1:
        tbl = bytes(i ^ key[0] for i in range(256))
        return data.translate(tbl)
    rep = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, rep))


def _decodings(s: bytes, keys: list[tuple[str, bytes]]) -> Iterable[tuple[str, bytes]]:
    """Cheap head tests first; the whole stream is transformed only on a hit."""
    bodies = [("", s)]
    for fmt, lab in (("<I", "length LE"), (">I", "length BE")):
        if len(s) > 8:
            n = struct.unpack_from(fmt, s)[0]
            if 0x20 <= n <= len(s) - 4:
                bodies.append((f"{lab} {n}, ", s[4:4 + n]))
    for label, body in bodies:
        if body[:1] == b"\x78" or body[:2] == b"\x1f\x8b":      # compressed first: the file inside is the payload
            for wbits, zl in ((47, "zlib/gzip"), (-15, "deflate")):
                try:
                    yield f"{label}{zl}", zlib.decompressobj(wbits).decompress(body, 256 * 1024 * 1024)
                except zlib.error:
                    pass
        if _plausible_head(body[:8]):
            yield f"{label}plain", body
        m = _B64.match(body[:1 << 20]) if body[:1].isalnum() else None
        if m:
            text = _B64.match(body).group(0)
            try:
                dec = base64.b64decode(text[:len(text) // 4 * 4])
                yield f"{label}Base64", dec
                if dec[:1] == b"\x78" or dec[:2] == b"\x1f\x8b":
                    yield f"{label}Base64 + zlib/gzip", zlib.decompressobj(47).decompress(dec)
            except (binascii.Error, zlib.error, ValueError):
                pass
        for mg in _MAGICS:                          # single-byte XOR that makes a magic appear
            k0 = body[0] ^ mg[0]
            if k0 and all(body[i] ^ k0 == mg[i] for i in range(1, len(mg))):
                yield f"{label}XOR 0x{k0:02x}", _xor(body, bytes([k0]))
        for kl, kb in keys:
            if len(kb) > 1 and _plausible_head(_xor(body[:8], kb)):
                yield f"{label}XOR key {kl}", _xor(body, kb)
            if len(kb) in (16, 24, 32) and len(body) >= 32:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                for mode, ml in ((modes.ECB(), "ECB"), (modes.CBC(b"\x00" * 16), "CBC iv=0")):
                    if _plausible_head(Cipher(algorithms.AES(kb), mode).decryptor().update(body[:16])):
                        yield (f"{label}AES-{len(kb) * 8} {ml} key {kl}",
                               Cipher(algorithms.AES(kb), mode).decryptor().update(body[:len(body) // 16 * 16]))


def is_image(data: bytes) -> bool:
    return data.startswith(IMAGE_MAGIC) and (not data.startswith(b"RIFF") or data[8:12] == b"WEBP")


# --- data after the end of the image -----------------------------------------------
def image_end(b: bytes) -> int | None:
    """Offset where the image itself ends (PNG IEND, JPEG EOI after the scan,
    GIF trailer, BMP declared size), or None when unknown."""
    try:
        if b.startswith(b"\x89PNG\r\n\x1a\n"):
            i = 8
            while i + 12 <= len(b):
                n, t = struct.unpack_from(">I4s", b, i)
                i += 12 + n
                if t == b"IEND":
                    return i
            return None
        if b.startswith(b"BM"):
            n = struct.unpack_from("<I", b, 2)[0]
            return n if 54 <= n <= len(b) else None
        if b.startswith(b"\xff\xd8"):
            i = 2
            while i + 4 <= len(b):
                if b[i] != 0xFF:
                    return None
                m = b[i + 1]
                if m == 0xD9:
                    return i + 2
                if m == 0xDA:                                   # entropy-coded data: next marker that is not RSTn / stuffing
                    j = i + 2 + struct.unpack_from(">H", b, i + 2)[0]
                    while j + 1 < len(b):
                        if b[j] == 0xFF and b[j + 1] not in (0x00, *range(0xD0, 0xD8), 0xFF):
                            break
                        j += 1
                    i = j
                    continue
                if 0xD0 <= m <= 0xD7 or m == 0x01:
                    i += 2
                    continue
                i += 2 + struct.unpack_from(">H", b, i + 2)[0]
            return None
        if b.startswith((b"GIF87a", b"GIF89a")):
            i = 13
            flags = b[10]
            if flags & 0x80:
                i += 3 * (2 << (flags & 7))
            while i < len(b):
                c = b[i]
                if c == 0x3B:
                    return i + 1
                if c == 0x21:                                   # extension: label + sub-blocks
                    i += 2
                elif c == 0x2C:                                 # image descriptor (+ local table) + LZW min size
                    f = b[i + 9]
                    i += 10 + (3 * (2 << (f & 7)) if f & 0x80 else 0) + 1
                else:
                    return None
                while i < len(b) and b[i]:
                    i += 1 + b[i]
                i += 1
            return None
    except (struct.error, IndexError):
        return None
    return None


def trailing(image: bytes, strings: list[Any] | None = None) -> tuple[str, bytes, str] | None:
    """A file appended after the end of the image (directly, after some padding,
    or encoded the same ways as the pixel streams)."""
    end = image_end(image)
    if end is None or len(image) - end < 64:
        return None
    tail = image[end:]
    keys = _keys(list(strings or []))
    pad = len(tail[:4096]) - len(tail[:4096].lstrip(b"\x00\xff")) if tail[:1] in (b"\x00", b"\xff") else 0
    starts = sorted({0, pad} | {i for mg in _MAGICS for i in [tail.find(mg, 1, 4096)] if i > 0})
    for off in starts:
        for how, out in _decodings(tail[off:], keys):
            got = identify(out)
            if got:
                kind, n = got
                return f"appended after the image end (offset {end + off:#x}): {how}", out[:n], kind
    return None


def extract(image: bytes, strings: list[Any] | None = None) -> tuple[str, bytes, str] | None:
    """(how, payload, kind) of the first file hidden in the image — appended
    after its end, or in its pixels — or None."""
    got = trailing(image, strings)
    if got:
        return got
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image))
        if img.width * img.height > MAX_PIXELS:
            return None
        img.load()
    except Exception:  # noqa: BLE001  (not an image Pillow can read)
        return None
    keys = _keys(list(strings or []))
    lossy = (img.format or "").upper() in ("JPEG", "WEBP")
    for order, s in _streams(img):
        if lossy and not order.startswith("rows, RGB bytes"):
            continue                        # lossy compression destroys hidden bits: one cheap try
        for how, out in _decodings(s, keys):
            got = identify(out)
            if got:
                kind, n = got
                return f"pixels by {order}: {how}", out[:n], kind
    return None
