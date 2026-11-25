"""The "MSAP" container a loader drops next to itself (seen with Lumma in 2025).

A PowerShell (or any dropper) writes two files: a small native loader and a data file that starts with
``MSAP``. The data file is ``"MSAP" | version 1 | 8-byte nonce | "MSAPTOK\\0" encrypted | payload
encrypted``; the cipher is a keystream generator of its own (an FNV-1a hash of the key and nonce seeds a
splitmix64 generator, which shuffles a byte S-box and a 128-bit permutation and draws nine round keys; each
16-byte block of nonce + counter goes through eight substitution / permutation / mixing rounds). The key
is a string the loader builds on its stack. The plaintext is a flag, the size, and a buffer of the Windows
Compression API (``CreateDecompressor`` + ``Decompress`` of cabinet.dll, XPRESS Huffman), which holds the
PE the loader injects.

Everything here is static: the cipher is reimplemented, the key is read from the loader's code (stack
strings), and the encrypted token tells which key is right. Nothing is run.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

MAGIC = b"MSAP\x01"
TOKEN = b"MSAPTOK\x00"
CAPI_MAGIC = b"\x0a\x51\xe5\xc0"
_M64 = (1 << 64) - 1
MAX_KEYS = 400


def _fnv(data: bytes, h: int = 0xCBF29CE484222325) -> int:
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & _M64
    return h


class Cipher:
    """The container's keystream (reimplemented from the loader)."""

    def __init__(self, key: bytes, nonce: bytes) -> None:
        self.seed = _fnv(nonce, _fnv(key))
        s = list(range(256))
        for i in range(255, 0, -1):
            j = self._rnd() % (i + 1)
            s[i], s[j] = s[j], s[i]
        p = list(range(128))
        for i in range(127, 0, -1):
            j = self._rnd() % (i + 1)
            p[i], p[j] = p[j], p[i]
        self.rk = [[((self._rnd() >> ((j & 7) * 8)) & 0xFF) + r * 0x11 + j * 0x1F & 0xFF for j in range(16)]
                   for r in range(9)]
        self.s, self.p, self.nonce, self.ctr = s, p, nonce, 1
        self.ks, self.pos = b"", 16

    def _rnd(self) -> int:
        self.seed = (self.seed + 0x9E3779B97F4A7C15) & _M64
        z = self.seed
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _M64
        return z ^ (z >> 31)

    def _block(self, b: bytes) -> bytes:
        t = list(b)
        s, p = self.s, self.p
        for r in range(8):
            t = [s[x ^ k] for x, k in zip(t, self.rk[r])]
            u = [0] * 16
            for k in range(128):
                if t[k >> 3] >> (k & 7) & 1:
                    q = p[k]
                    u[q >> 3] |= 1 << (q & 7)
            t = [((x << 3) | (x >> 5)) & 0xFF for x in ((u[j] + u[(j + 5) & 15] + r) & 0xFF for j in range(16))]
        return bytes(x ^ k for x, k in zip(t, self.rk[8]))

    def crypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, c in enumerate(data):
            if self.pos >= 16:
                self.ks = self._block(self.nonce + struct.pack("<Q", self.ctr))
                self.ctr += 1
                self.pos = 0
            out[i] = c ^ self.ks[self.pos]
            self.pos += 1
        return bytes(out)


def encrypt(key: bytes, nonce: bytes, payload: bytes) -> bytes:
    """Build a container (used by the samples)."""
    c = Cipher(key, nonce)
    return MAGIC + nonce + c.crypt(TOKEN) + c.crypt(payload)


def is_container(data: bytes) -> bool:
    return data[:5] == MAGIC and len(data) > 21


def is_loader(data: bytes) -> bool:
    return data[:2] == b"MZ" and b"MSAPTOK" in data


# -- the key: strings the loader writes byte by byte on its stack ---------------------------------------
_MOV_AL = re.compile(rb"\xb8(.)\x00\x00\x00(?:\x88\x45(.)|\x88\x85(....))", re.S)    # mov eax, imm; mov [rbp+d], al
_MOV_IMM = re.compile(rb"\xc6\x45(.)(.)|\xc6\x85(....)(.)|\xc6\x44\x24(.)(.)|\xc6\x84\x24(....)(.)", re.S)


def stack_strings(data: bytes, minlen: int = 8) -> list[str]:
    """Strings a native function builds one byte at a time in its frame (``mov byte [rbp-x], imm`` or
    ``mov eax, imm`` + ``mov [rbp-x], al``): the writes are grouped by where they sit in the code and the
    consecutive frame offsets read as text."""
    writes: list[tuple[int, int, int]] = []          # (code offset, frame displacement, byte)
    for m in _MOV_AL.finditer(data):
        d = struct.unpack("<b", m.group(2))[0] if m.group(2) is not None else struct.unpack("<i", m.group(3))[0]
        writes.append((m.start(), d, m.group(1)[0]))
    for m in _MOV_IMM.finditer(data):
        g = m.groups()
        if g[0] is not None:
            d, v = struct.unpack("<b", g[0])[0], g[1][0]
        elif g[2] is not None:
            d, v = struct.unpack("<i", g[2])[0], g[3][0]
        elif g[4] is not None:
            d, v = 0x10000 + g[4][0], g[5][0]                # rsp-relative: another frame base
        else:
            d, v = 0x10000 + struct.unpack("<i", g[6])[0], g[7][0]
        writes.append((m.start(), d, v))
    writes.sort()
    out: list[str] = []
    group: dict[int, int] = {}
    last = -1 << 30

    def flush() -> None:
        if len(group) < minlen:
            return
        ds = sorted(group)
        run = [ds[0]]
        for a, b in zip(ds, ds[1:]):
            if b == a + 1:
                run.append(b)
                continue
            _emit(run)
            run = [b]
        _emit(run)

    def _emit(run: list[int]) -> None:
        txt = bytes(group[d] for d in run)
        txt = txt.split(b"\x00", 1)[0]
        if len(txt) >= minlen and all(32 <= c < 127 for c in txt):
            out.append(txt.decode())
    for pos, d, v in writes:
        if pos - last > 96:
            flush()
            group = {}
        group[d] = v
        last = pos
    flush()
    return list(dict.fromkeys(out))


def _key_candidates(loader: bytes) -> list[bytes]:
    keys = [s.encode() for s in stack_strings(loader)]
    keys += [m.group() for m in re.finditer(rb"[\x21-\x7e]{12,64}", loader)]     # a key kept as plain text
    return list(dict.fromkeys(keys))[:MAX_KEYS]


def _decompress(plain: bytes) -> tuple[bytes, list[str]] | None:
    i = plain.find(CAPI_MAGIC, 0, 64)
    if i < 0:
        return (plain, []) if plain[:2] == b"MZ" else None
    size = struct.unpack_from("<I", plain, 1)[0] if i >= 5 else 0
    body = plain[i + 28:]
    try:
        from dissect.util.compression import lzxpress, lzxpress_huffman
    except ImportError:
        return None
    for name, fn in (("XPRESS Huffman", lzxpress_huffman.decompress), ("XPRESS", lzxpress.decompress)):
        try:
            out = fn(body)
        except Exception:  # noqa: BLE001
            continue
        if size and len(out) >= size:
            out = out[:size]
        if out[:2] == b"MZ":
            return out, [f"Windows Compression API ({name}, cabinet.dll Decompress)"]
    return None


def open_container(container: bytes, loader: bytes) -> dict[str, Any] | None:
    """The payload of an MSAP container, with the key found in the loader; None when no key opens it."""
    if not is_container(container):
        return None
    nonce, tok = container[5:13], container[13:21]
    for key in _key_candidates(loader):
        c = Cipher(key, nonce)
        if c.crypt(tok) != TOKEN:
            continue
        plain = c.crypt(container[21:])
        got = _decompress(plain)
        recipe = [f"MSAP container: key {key.decode('latin-1')!r} (a stack string of the loader), "
                  "checked by its encrypted MSAPTOK token"]
        if got is None:
            return {"data": plain, "key": key.decode("latin-1"), "recipe": recipe, "pe": False}
        return {"data": got[0], "key": key.decode("latin-1"), "recipe": recipe + got[1], "pe": True}
    return None


def open_pairs(items: list[dict[str, Any]], out_dir: Path) -> list[dict[str, Any]]:
    """Children written together (``{path, filename}``): every MSAP container opened with the loader beside
    it, the payload written to ``out_dir``. ``[{path, filename, origin, recipe}]``."""
    blobs = []
    for it in items:
        try:
            blobs.append((it, Path(it["path"]).read_bytes()))
        except (OSError, KeyError):
            continue
    loaders = [d for _, d in blobs if is_loader(d)]
    got: list[dict[str, Any]] = []
    for it, data in blobs:
        if not is_container(data):
            continue
        for ld in loaders:
            r = open_container(data, ld)
            if not r:
                continue
            out_dir.mkdir(parents=True, exist_ok=True)
            stem = Path(it.get("filename") or "container").stem
            name = f"{stem}_payload.{'exe' if r['pe'] else 'bin'}"
            p = out_dir / name
            p.write_bytes(r["data"])
            got.append({"path": str(p), "filename": name, "recipe": r["recipe"],
                        "origin": f"payload of the MSAP container {it.get('filename', '')}, opened with the key "
                                  "of the loader dropped with it"})
            break
    return got
