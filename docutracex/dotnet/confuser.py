"""ConfuserEx constants protection, decrypted statically.

ConfuserEx (MIT) moves the string / number / array literals of an assembly into
one encrypted ``uint[]`` (a static array initialised from a FieldRVA). At start
its ``Initialize`` derives a 16-word key from a seed with a xorshift (>>12,
<<25, >>27), decrypts the array block by block (``Normal`` mode: XOR with the
key, the key then XORed with the plain block), and LZMA-decompresses it. Each
use becomes ``ldc.i4 <id>; call Get<T>(uint)``, where Get decodes the id as
``(id * inv(k1)) ^ k2``: two bits of type, the rest the offset / 4 of a
``[length][UTF-8 bytes]`` record.

Nothing of the assembly is run: the seed, the array, the decoder constants and
the call sites are read from the CIL and the routine is re-implemented here.
The ``Dynamic`` and ``x86`` modes generate their own cipher as code: they are
recognised and reported, not decrypted.
"""

from __future__ import annotations

import lzma
import struct
from typing import Any

MAX_OUT = 64 * 1024 * 1024
MAX_STRINGS = 3000
_XORSHIFT = {12, 25, 27}


def _key(seed: int) -> list[int]:
    n, k = seed & 0xFFFFFFFF, []
    for _ in range(16):
        n ^= n >> 12
        n ^= (n << 25) & 0xFFFFFFFF
        n ^= n >> 27
        k.append(n)
    return k


def decrypt_normal(array: bytes, seed: int) -> bytes | None:
    """``Initialize`` of the Normal mode on the encrypted ``uint[]``; the LZMA
    stream if the result is one (a wrong seed never decompresses)."""
    if len(array) < 64 or len(array) % 4:
        return None
    q = struct.unpack(f"<{len(array) // 4}I", array)
    k = _key(seed)
    out = bytearray()
    for s in range(0, len(q) - 15, 16):
        for j in range(16):
            e = q[s + j] ^ k[j]
            out += struct.pack("<I", e)
            k[j] ^= e
    if len(out) < 13 or out[0] > 225:                 # LZMA props byte: (pb*5+lp)*9+lc ≤ 224
        return None
    try:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        b = d.decompress(bytes(out), max_length=MAX_OUT)
    except lzma.LZMAError:
        return None
    return b or None


def _text(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s or len(s) > 20000:
        return None
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return s if ok / len(s) >= 0.95 else None


def string_at(b: bytes, off: int) -> str | None:
    if off < 0 or off + 4 > len(b):
        return None
    n = struct.unpack_from("<i", b, off)[0]
    if not 1 <= n <= len(b) - off - 4:
        return None
    return _text(b[off + 4:off + 4 + n])


def all_strings(b: bytes) -> list[tuple[int, str]]:
    """Every ``[length][UTF-8]`` record at a 4-aligned offset (no id needed)."""
    out: list[tuple[int, str]] = []
    off = 0
    while off + 4 <= len(b) and len(out) < MAX_STRINGS:
        s = string_at(b, off)
        if s is not None and len(s) >= 2:
            out.append((off, s))
            off += 4 + ((len(s.encode()) + 3) // 4) * 4
        else:
            off += 4
    return out


def _looks_initialize(m: dict[str, Any]) -> bool:
    ops = m.get("_ops") or set()
    return bool(m.get("_arrays")) and _XORSHIFT <= set(m.get("_ints") or []) and {"shl", "xor"} <= ops \
        and ("shr.un" in ops or "shr" in ops)


def _decoder_keys(m: dict[str, Any]) -> tuple[int, int] | None:
    """Get<T>: ``ldarg.0; ldc.i4 inv(k1); mul; ldc.i4 k2; xor`` — the first two ints."""
    ops = m.get("_ops") or set()
    ints = [i for i in (m.get("_ints") or []) if i not in (0, 1, 2, 3, 4, 8, 30, 0x3FFFFFFF)]
    if {"mul", "xor"} <= ops and len(ints) >= 2:
        return ints[0], ints[1]
    return None


def constants(methods: list[dict[str, Any]], confused: bool = False) -> dict[str, Any] | None:
    """{mode, how, strings: [{caller, id, output}], records} — or None when the
    assembly shows no ConfuserEx constants structure."""
    inits = [m for m in methods if _looks_initialize(m)]
    if not inits:
        return None
    res: dict[str, Any] = {"initializer": inits[0]["method"], "mode": "", "how": "", "strings": [], "records": 0}
    for m in inits:
        arrays = sorted((a for a in m.get("_arrays") or [] if len(a) >= 64 and len(a) % 64 == 0), key=len, reverse=True)
        seeds = [i for i in dict.fromkeys(m.get("_ints") or []) if i > 0xFF and i not in _XORSHIFT]
        for arr in arrays[:3]:
            for seed in seeds[:64]:
                b = decrypt_normal(arr, seed)
                if b is None:
                    continue
                res.update(initializer=m["method"], mode="Normal", records=len(b),
                           how=f"ConfuserEx constants (Normal mode): xorshift key from seed 0x{seed:08x}, "
                               f"XOR over uint[{len(arr) // 4}], LZMA")
                by_rid = {x["rid"]: x for x in methods}
                found: dict[int, dict[str, Any]] = {}
                for caller in methods:                   # exact: the ids each method passes to Get<T>
                    for rid, raw_id in caller.get("_int_sites") or []:
                        dec = by_rid.get(rid)
                        keys = _decoder_keys(dec) if dec else None
                        if not keys:
                            continue
                        idv = ((raw_id * keys[0]) & 0xFFFFFFFF) ^ keys[1]
                        off = (idv & 0x3FFFFFFF) << 2
                        s = string_at(b, off)
                        if s is not None and off not in found:
                            found[off] = {"caller": caller["method"], "decoder": dec["method"],
                                          "id": f"0x{raw_id:08x}", "output": s}
                for off, s in all_strings(b):            # the rest, by walking the records
                    if off not in found:
                        found[off] = {"caller": "", "decoder": "", "id": f"offset 0x{off:x}", "output": s}
                res["strings"] = [found[k] for k in sorted(found)][:MAX_STRINGS]
                return res
    res.update(mode="Dynamic / x86 (cipher generated as code: not decrypted statically)" if confused or inits
               else "", how="ConfuserEx constants initializer found, but no seed decrypts it as the Normal mode")
    return res
