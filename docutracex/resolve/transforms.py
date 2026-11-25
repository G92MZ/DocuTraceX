"""The operations scripts use to hide their next stage, computed on data — never executed.

Every language's evaluator maps its calls to these (``[Convert]::FromBase64String``,
``base64.b64decode``, ``atob``, ``MIME::Base64::decode_base64``, ``base64_decode`` and
``base64 -d`` are all :func:`b64decode`), so each operation is written and tested once.

Pure functions on ``bytes`` / ``str``: no disk, network or process. Every output is bounded
(:data:`MAX_OUT`): a decompression bomb or a runaway repeat stops with :class:`TransformError`
instead of filling memory. Bad input raises :class:`TransformError` too, so a caller can try the
next interpretation.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import hashlib
import lzma
import re
import zlib
from typing import Any, Callable

MAX_OUT = 64 * 1024 * 1024        # bytes any single operation may produce


class TransformError(ValueError):
    """The input does not decode / decrypt / decompress with these parameters."""


def _bound(n: int) -> None:
    if n > MAX_OUT:
        raise TransformError(f"output over {MAX_OUT} bytes")


def as_bytes(v: bytes | bytearray | str | list[int], encoding: str = "utf-8") -> bytes:
    """A value as bytes: text in ``encoding`` (UTF-8 by default), a list of numbers as bytes."""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        return v.encode(encoding, "surrogatepass" if encoding.startswith("utf-16") else "replace")
    if isinstance(v, (list, tuple)):
        _bound(len(v))
        try:
            return bytes(int(x) & 0xFF for x in v)
        except (TypeError, ValueError) as exc:
            raise TransformError(f"not a byte list: {exc}") from exc
    raise TransformError(f"not bytes: {type(v).__name__}")


def as_text(v: bytes | str, encoding: str = "utf-8") -> str:
    """Bytes as text in ``encoding``; UTF-16 / UTF-8 BOMs honoured."""
    if isinstance(v, str):
        return v
    b = bytes(v)
    enc = encoding.lower().replace("_", "-")
    if enc in ("unicode", "utf-16", "utf16", "utf-16le", "utf16le"):
        enc = "utf-16-le"
    if enc in ("bigendianunicode", "utf-16be"):
        enc = "utf-16-be"
    if enc in ("ascii", "us-ascii", "default", "oem"):
        enc = "latin-1"
    if b.startswith(b"\xef\xbb\xbf") and enc in ("utf-8", "utf8"):
        b = b[3:]
    if b.startswith(b"\xff\xfe") and enc == "utf-16-le":
        b = b[2:]
    try:
        return b.decode(enc, "replace")
    except LookupError:
        return b.decode("utf-8", "replace")


# --- encodings -----------------------------------------------------------------------
_B64_JUNK = re.compile(r"[\s\x00]+")


def b64decode(v: bytes | str, urlsafe: bool | None = None, strict: bool = False) -> bytes:
    """Base64 (standard or URL-safe, with or without padding, with whitespace)."""
    t = _B64_JUNK.sub("", as_text(v, "latin-1"))
    if urlsafe or (urlsafe is None and ("-" in t or "_" in t)):
        t = t.replace("-", "+").replace("_", "/")
    if strict and not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", t):
        raise TransformError("not base64")
    t = re.sub(r"[^A-Za-z0-9+/=]", "", t).rstrip("=")
    if len(t) % 4 == 1:
        raise TransformError("base64 of an impossible length")
    try:
        return base64.b64decode(t + "=" * (-len(t) % 4))
    except (binascii.Error, ValueError) as exc:
        raise TransformError(f"not base64: {exc}") from exc


def b64encode(v: bytes | str) -> str:
    return base64.b64encode(as_bytes(v)).decode("ascii")


def b32decode(v: bytes | str) -> bytes:
    t = re.sub(r"[\s=]", "", as_text(v, "latin-1")).upper()
    try:
        return base64.b32decode(t + "=" * (-len(t) % 8))
    except (binascii.Error, ValueError) as exc:
        raise TransformError(f"not base32: {exc}") from exc


def b85decode(v: bytes | str) -> bytes:
    t = as_text(v, "latin-1").strip()
    fns = ((lambda x: base64.a85decode(x, adobe=True)),) if t.startswith("<~") else (base64.b85decode, base64.a85decode)
    for fn in fns:
        try:
            return fn(t)
        except (binascii.Error, ValueError):
            continue
    raise TransformError("not base85 / ascii85")


def hexdecode(v: bytes | str) -> bytes:
    """Hex with or without ``0x`` / ``\\x`` / separators (``4D 5A``, ``4D-5A``, ``0x4D,0x5A``)."""
    t = as_text(v, "latin-1")
    t = re.sub(r"(?i)0x|\\x|[\s,;:\-]", "", t)
    if len(t) % 2:
        raise TransformError("odd-length hex")
    try:
        return bytes.fromhex(t)
    except ValueError as exc:
        raise TransformError(f"not hex: {exc}") from exc


_NUM_TOKEN = re.compile(r"-?0[xX][0-9A-Fa-f]+|-?\d+")


def numbers(v: str, base: int = 10) -> list[int]:
    """The numbers of a list written in a script (``77,90,144``, ``0x4D, 0x5A``, ``-4,-24``)."""
    out = []
    for tok in _NUM_TOKEN.findall(v):
        out.append(int(tok, 16) if tok.lower().lstrip("-").startswith("0x") else int(tok, base))
        if len(out) > MAX_OUT:
            raise TransformError("number list too long")
    return out


def num_array(v: str | list[int], base: int = 10) -> bytes:
    """A list of byte values (negative ones as two's complement: VBA's ``Array(-4, -24…)``)."""
    vals = numbers(v, base) if isinstance(v, str) else list(v)
    _bound(len(vals))
    return bytes(int(x) & 0xFF for x in vals)


_ESC = re.compile(r"\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})|\\u\{([0-9A-Fa-f]{1,6})\}|%u([0-9A-Fa-f]{4})|%([0-9A-Fa-f]{2})"
                  r"|\\([0-7]{1,3})")


def unescape(v: str, as_bytes_: bool = False) -> str | bytes:
    """``\\xNN``, ``\\uNNNN``, ``\\u{N}``, ``%uNNNN``, ``%NN`` and octal escapes; with ``as_bytes_``
    the ``\\x`` / ``%NN`` ones become bytes (a shellcode string)."""
    if as_bytes_:
        out = bytearray()
        pos = 0
        for m in _ESC.finditer(v):
            out += v[pos:m.start()].encode("latin-1", "replace")
            if m.group(1) or m.group(5):
                out.append(int(m.group(1) or m.group(5), 16))
            elif m.group(6):
                out.append(int(m.group(6), 8) & 0xFF)
            else:
                out += chr(int(m.group(2) or m.group(3) or m.group(4), 16)).encode("utf-8")
            pos = m.end()
        out += v[pos:].encode("latin-1", "replace")
        return bytes(out)

    def repl(m: re.Match) -> str:
        if m.group(6):
            return chr(int(m.group(6), 8))
        return chr(int(next(g for g in m.groups()[:5] if g), 16))
    return _ESC.sub(repl, v)


# --- byte ciphers --------------------------------------------------------------------
def xor(data: bytes | str, key: bytes | str | int | list[int], skip_zero: bool = False) -> bytes:
    """Repeating-key XOR (``key`` a byte, text or bytes); ``skip_zero`` leaves 0x00 / key bytes
    unchanged (the "null-preserving" variant)."""
    d = as_bytes(data)
    k = bytes([key & 0xFF]) if isinstance(key, int) else as_bytes(key)
    if not k:
        raise TransformError("empty XOR key")
    if len(k) == 1 and not skip_zero:
        return d.translate(bytes(i ^ k[0] for i in range(256)))
    out = bytearray(len(d))
    kl = len(k)
    for i, b in enumerate(d):
        kb = k[i % kl]
        out[i] = b if skip_zero and (b == 0 or b == kb) else b ^ kb
    return bytes(out)


def xor_rolling(data: bytes | str, key: int, step: int = 1) -> bytes:
    """XOR with a key that grows by ``step`` each byte (``key + i``)."""
    d = as_bytes(data)
    return bytes(b ^ ((key + i * step) & 0xFF) for i, b in enumerate(d))


def add_bytes(data: bytes | str, n: int) -> bytes:
    """Add ``n`` to every byte (a negative ``n`` subtracts)."""
    d = as_bytes(data)
    return d.translate(bytes((i + n) & 0xFF for i in range(256)))


def rot(text: str, n: int = 13) -> str:
    """ROTn on letters (ROT13 by default); other characters unchanged."""
    def r(c: str) -> str:
        if "a" <= c <= "z":
            return chr((ord(c) - 97 + n) % 26 + 97)
        if "A" <= c <= "Z":
            return chr((ord(c) - 65 + n) % 26 + 65)
        return c
    return "".join(r(c) for c in text)


def rc4(data: bytes | str, key: bytes | str) -> bytes:
    d, k = as_bytes(data), as_bytes(key)
    if not k:
        raise TransformError("empty RC4 key")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + k[i % len(k)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(d))
    i = j = 0
    for n, b in enumerate(d):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def _unpad_pkcs7(b: bytes, block: int) -> bytes:
    if not b or len(b) % block:
        raise TransformError("not a whole number of blocks")
    n = b[-1]
    if not 1 <= n <= block or b[-n:] != bytes([n]) * n:
        raise TransformError("bad PKCS7 padding (wrong key / IV?)")
    return b[:-n]


def _cipher(alg: str, key: bytes, iv: bytes | None, mode: str):  # noqa: ANN202
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:                     # pragma: no cover - cryptography ships with the app
        raise TransformError("cryptography is not installed") from exc
    a = alg.lower()
    if a == "aes":
        if len(key) not in (16, 24, 32):
            raise TransformError(f"AES key of {len(key)} bytes")
        algo, block = algorithms.AES(key), 16
    elif a in ("3des", "tripledes", "des3", "des"):
        if a == "des":
            if len(key) != 8:
                raise TransformError(f"DES key of {len(key)} bytes")
            key = key * 3
        if len(key) == 16:
            key = key + key[:8]
        if len(key) != 24:
            raise TransformError(f"3DES key of {len(key)} bytes")
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:                        # older cryptography
            TripleDES = algorithms.TripleDES  # noqa: N806
        algo, block = TripleDES(key), 8
    elif a == "chacha20":
        if len(key) != 32 or not iv or len(iv) not in (12, 16):
            raise TransformError("ChaCha20 needs a 32-byte key and a 12/16-byte nonce")
        nonce = iv if len(iv) == 16 else b"\x00\x00\x00\x00" + iv
        return Cipher(algorithms.ChaCha20(key, nonce), mode=None), 1
    else:
        raise TransformError(f"unknown cipher {alg}")
    m = mode.lower()
    iv = iv or b"\x00" * block
    if m != "ecb" and len(iv) != block:
        raise TransformError(f"IV of {len(iv)} bytes for a {block}-byte block")
    md = {"cbc": lambda: modes.CBC(iv), "ecb": lambda: modes.ECB(), "cfb": lambda: modes.CFB(iv),
          "cfb8": lambda: modes.CFB8(iv), "ofb": lambda: modes.OFB(iv), "ctr": lambda: modes.CTR(iv)}.get(m)
    if md is None:
        raise TransformError(f"unknown mode {mode}")
    return Cipher(algo, md()), block


def decrypt(alg: str, data: bytes | str, key: bytes | str, iv: bytes | str | None = None, mode: str = "cbc",
            padding: str = "pkcs7") -> bytes:
    """Decrypt with AES / DES / 3DES / ChaCha20 (``mode`` cbc, ecb, cfb, cfb8, ofb, ctr; ``padding``
    pkcs7, zeros or none). Wrong key / IV → :class:`TransformError` (bad padding)."""
    d, k = as_bytes(data), as_bytes(key)
    ivb = as_bytes(iv) if iv is not None else None
    if alg.lower() == "aes" and mode.lower() == "gcm":
        return aes_gcm(d, k, ivb or b"")
    cipher, block = _cipher(alg, k, ivb, mode)
    _bound(len(d))
    dec = cipher.decryptor()
    out = dec.update(d) + dec.finalize()
    p = padding.lower()
    if p in ("pkcs7", "pkcs5") and mode.lower() in ("cbc", "ecb") and block > 1:
        return _unpad_pkcs7(out, block)
    if p in ("zeros", "zero"):
        return out.rstrip(b"\x00")
    return out


def aes_gcm(data: bytes, key: bytes, nonce: bytes, tag: bytes | None = None) -> bytes:
    """AES-GCM: the tag at the end of ``data`` unless given."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover
        raise TransformError("cryptography is not installed") from exc
    blob = data + (tag or b"")
    try:
        return AESGCM(key).decrypt(nonce, blob, None)
    except Exception as exc:  # noqa: BLE001
        raise TransformError(f"AES-GCM: {exc}") from exc


def pbkdf2(password: bytes | str, salt: bytes | str, iterations: int = 1000, length: int = 32,
           hash_name: str = "sha1") -> bytes:
    """``Rfc2898DeriveBytes`` / ``PBKDF2`` (SHA-1 by default, as .NET's)."""
    if iterations > 10_000_000:
        raise TransformError("PBKDF2: too many iterations")
    return hashlib.pbkdf2_hmac(hash_name, as_bytes(password), as_bytes(salt), int(iterations), int(length))


# --- compressions --------------------------------------------------------------------
def _zlib(data: bytes, wbits: int) -> bytes:
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data, MAX_OUT + 1)
    except zlib.error as exc:
        raise TransformError(f"not compressed ({exc})") from exc
    _bound(len(out))
    return out


def gunzip(data: bytes | str) -> bytes:
    """GZip (several members too)."""
    d = as_bytes(data)
    if d[:2] != b"\x1f\x8b":
        raise TransformError("no GZip header")
    out = bytearray()
    while d[:2] == b"\x1f\x8b":
        obj = zlib.decompressobj(31)
        try:
            out += obj.decompress(d, MAX_OUT + 1 - len(out))
        except zlib.error as exc:
            raise TransformError(f"bad GZip ({exc})") from exc
        _bound(len(out))
        d = obj.unused_data
    return bytes(out)


def inflate(data: bytes | str) -> bytes:
    """Raw Deflate (``DeflateStream``, ``gzinflate``)."""
    return _zlib(as_bytes(data), -15)


def zlib_decompress(data: bytes | str) -> bytes:
    """zlib (``zlib.decompress``, ``gzuncompress``, ``Compress::Zlib::uncompress``)."""
    return _zlib(as_bytes(data), 15)


def decompress_any(data: bytes | str) -> bytes:
    """Whatever compression ``data`` carries (GZip, zlib, raw Deflate, LZMA / XZ, bz2)."""
    d = as_bytes(data)
    for fn in (gunzip, zlib_decompress, unlzma, bunzip2, inflate):
        try:
            out = fn(d)
        except TransformError:
            continue
        if out:
            return out
    raise TransformError("no known compression")


def unlzma(data: bytes | str) -> bytes:
    d = as_bytes(data)
    for fmt in (lzma.FORMAT_XZ, lzma.FORMAT_ALONE):
        try:
            dec = lzma.LZMADecompressor(format=fmt)
            out = dec.decompress(d, max_length=MAX_OUT + 1)
            _bound(len(out))
            return out
        except lzma.LZMAError:
            continue
    raise TransformError("not LZMA / XZ")


def bunzip2(data: bytes | str) -> bytes:
    d = as_bytes(data)
    if d[:3] != b"BZh":
        raise TransformError("no bzip2 header")
    try:
        out = bz2.BZ2Decompressor().decompress(d, max_length=MAX_OUT + 1)
    except (OSError, ValueError) as exc:
        raise TransformError(f"bad bzip2 ({exc})") from exc
    _bound(len(out))
    return out


def brotli_decompress(data: bytes | str) -> bytes:
    try:
        import brotli  # type: ignore[import-not-found]
    except ImportError as exc:
        raise TransformError("brotli is not installed") from exc
    try:
        out = brotli.decompress(as_bytes(data))
    except Exception as exc:  # noqa: BLE001
        raise TransformError(f"not brotli ({exc})") from exc
    _bound(len(out))
    return out


def lznt1(data: bytes | str) -> bytes:
    """LZNT1 (``RtlDecompressBuffer`` with COMPRESSION_FORMAT_LZNT1)."""
    d = as_bytes(data)
    out = bytearray()
    pos = 0
    while pos + 2 <= len(d):
        hdr = d[pos] | d[pos + 1] << 8
        pos += 2
        if hdr == 0:
            break
        size = (hdr & 0x0FFF) + 1
        chunk = d[pos:pos + size]
        pos += size
        if not hdr & 0x8000:                       # stored chunk
            out += chunk
            _bound(len(out))
            continue
        start = len(out)
        i = 0
        while i < len(chunk):
            flags = chunk[i]
            i += 1
            for bit in range(8):
                if i >= len(chunk):
                    break
                if not flags >> bit & 1:
                    out.append(chunk[i])
                    i += 1
                    continue
                if i + 1 >= len(chunk):
                    raise TransformError("truncated LZNT1 token")
                tok = chunk[i] | chunk[i + 1] << 8
                i += 2
                # the split between offset and length bits grows with the position in the chunk
                p = len(out) - start - 1
                l_mask, o_shift = 0xFFF, 12
                while p >= 0x10:
                    l_mask >>= 1
                    o_shift -= 1
                    p >>= 1
                length = (tok & l_mask) + 3
                off = (tok >> o_shift) + 1
                if off > len(out) - start:
                    raise TransformError("bad LZNT1 back-reference")
                for _ in range(length):
                    out.append(out[-off])
                _bound(len(out))
    return bytes(out)


# --- strings -------------------------------------------------------------------------
def reverse(v: str | bytes) -> str | bytes:
    return v[::-1]


def chars(codes: list[int]) -> str:
    """Characters from their codes (``[char]`` arrays, ``String.fromCharCode``, ``chr()`` lists)."""
    _bound(len(codes))
    try:
        return "".join(chr(int(c)) for c in codes)
    except (ValueError, OverflowError) as exc:
        raise TransformError(f"bad character code: {exc}") from exc


def repeat(v: str | bytes, n: int) -> str | bytes:
    _bound(len(v) * max(0, int(n)))
    return v * int(n)


# --- hashes --------------------------------------------------------------------------
def digest(name: str, data: bytes | str) -> bytes:
    n = name.lower().replace("-", "")
    if n not in ("md5", "sha1", "sha256", "sha384", "sha512"):
        raise TransformError(f"unknown hash {name}")
    return hashlib.new(n, as_bytes(data)).digest()


# --- what a result is ----------------------------------------------------------------
_MAGIC = ((b"MZ", "pe"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"),
          (b"%PDF", "pdf"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"Rar!", "rar"),
          (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\xca\xfe\xba\xbe", "class"), (b"\xfe\xed\xfa", "macho"),
          (b"\xcf\xfa\xed\xfe", "macho"), (b"\xce\xfa\xed\xfe", "macho"), (b"{\\rtf", "rtf"),
          (b"MSCF", "cab"), (b"BZh", "bzip2"), (b"\xfd7zXZ", "xz"))


def magic(data: bytes) -> str | None:
    """The file type of ``data`` by its first bytes, or None."""
    for sig, kind in _MAGIC:
        if data.startswith(sig):
            return kind
    if len(data) > 0x40 and data[:2] == b"MZ":
        return "pe"
    return None


def is_text(data: bytes, min_printable: float = 0.9) -> bool:
    """Mostly printable UTF-8 / UTF-16 text."""
    if not data:
        return False
    sample = data[:65536]
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(sample) > 8 and sample[1::2].count(0) > len(sample) * 0.4):
        try:
            sample = sample.decode("utf-16-le" if sample[1::2].count(0) > len(sample) * 0.4 else "utf-16").encode()
        except UnicodeDecodeError:
            return False
    ok = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13) or b >= 0x80)
    return ok / len(sample) >= min_printable and b"\x00" not in sample


# --- the registry: one name per operation, shared by every language ------------------
REGISTRY: dict[str, Callable[..., Any]] = {
    "base64": b64decode, "base32": b32decode, "base85": b85decode, "hex": hexdecode,
    "number array": num_array, "unescape": unescape,
    "xor": xor, "xor-rolling": xor_rolling, "add": add_bytes, "rot": rot, "rc4": rc4,
    "decrypt": decrypt, "aes-gcm": aes_gcm, "pbkdf2": pbkdf2,
    "gzip": gunzip, "deflate": inflate, "zlib": zlib_decompress, "lzma": unlzma, "bzip2": bunzip2,
    "brotli": brotli_decompress, "lznt1": lznt1, "decompress": decompress_any,
    "reverse": reverse, "chars": chars, "repeat": repeat, "digest": digest,
}


def apply(name: str, *args: Any, **kwargs: Any) -> Any:
    """Run the operation ``name`` (a :data:`REGISTRY` key); errors as :class:`TransformError`."""
    fn = REGISTRY.get(name)
    if fn is None:
        raise TransformError(f"unknown operation {name}")
    try:
        out = fn(*args, **kwargs)
    except TransformError:
        raise
    except (ValueError, TypeError, OverflowError, MemoryError, IndexError) as exc:
        raise TransformError(f"{name}: {exc}") from exc
    if isinstance(out, (bytes, str)):
        _bound(len(out))
    return out
