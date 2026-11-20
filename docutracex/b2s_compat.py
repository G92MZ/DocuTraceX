"""A pure-Python stand-in for ``binary2strings`` (FLOSS's Rust-string helper).

binary2strings is a C++ extension with no Windows wheel (installing it needs a C++
compiler), so the portable Python runs FLOSS without it — and without it FLOSS could not
split the strings of a Rust binary (Rust keeps them back to back, without a NUL, in
.rdata). This is the same algorithm in Python, with the same tables, giving the same
results (checked against the C++ module in tests/test_b2s_compat.py):

- ``extract_string(buffer, min_chars=4, only_interesting=False)``: the string at the start
  of ``buffer`` as ``(string, "UTF8" | "WIDE_STRING", (start, end), is_interesting)``, or
  ``("", "", (0, 0), False)``;
- ``extract_all_strings(buffer, min_chars=4, only_interesting=False)``: every string, as
  those tuples.

UTF-8: displayable ASCII, or 2-3 byte characters seen at least once in Common Crawl.
UTF-16LE: displayable ASCII plus characters of a single Unicode language group.
``is_interesting`` (a small gibberish model in the original) is approximated by the
string's length: FLOSS does not use it.

Ported from binary2strings 0.1.13 — Copyright (c) 2022 Geoff McDonald, MIT License
(https://github.com/glmcdona/binary2strings): permission is granted to use, copy, modify
and distribute it provided the copyright notice and permission notice are kept.
"""

from __future__ import annotations

import base64
import re
import zlib

_DISPLAYABLE = bytes(1 if c in (9, 10, 13) or 0x20 <= c <= 0x7E else 0 for c in range(256))
_ASCII_RUN = re.compile(rb"[\t\n\r\x20-\x7e]+")

# characters seen at least once in Common Crawl: a 65536-bit map
_SEEN = zlib.decompress(base64.b64decode(
    "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"
    "/r+cMz/b9s13q9Wrq/9cbfnX8FX/DUyyMNo="
))

# the language group of each block of 16 BMP characters (0: none, 1: Latin…), as runs
_GROUP_RUNS = (
    (1, 48), (2, 41), (3, 31), (4, 4), (5, 4), (3, 16), (4, 80), (6, 16), (4, 16), (6, 10), (2, 6), (7, 16), (5, 26), (8, 46), (2, 8), (9, 8), (6, 8), (4, 11), (8, 5), (4, 5), (6, 11), (9, 2), (6, 9), (2, 5), (9, 16), (4, 8), (2, 4), (9, 1), (4, 3), (1, 12), (2, 4), (1, 16), (2, 23), (0, 185), (2, 6), (1, 2), (2, 11), (5, 11), (2, 2), (0, 8), (12, 22), (0, 1), (12, 1), (7, 28), (12, 3), (7, 1), (0, 32), (12, 412), (0, 4), (12, 1312), (7, 80), (5, 20), (2, 6), (5, 6), (7, 2), (1, 14), (4, 3), (0, 1), (4, 12), (6, 3), (9, 3), (7, 2), (9, 6), (6, 16), (4, 2), (5, 3), (1, 4), (8, 5), (4, 4), (7, 704), (0, 528), (12, 32), (1, 1), (2, 1), (3, 46), (0, 1), (7, 1), (2, 1), (7, 4), (3, 9), (7, 15),
)
_GROUP = bytes(g for g, n in _GROUP_RUNS for _ in range(n)) + b"\x00"


def _seen(c: int) -> bool:
    return bool(_SEEN[c >> 3] >> (c & 7) & 1)


def _utf8_step(buf: bytes, n: int, i: int) -> int:
    """Length of a likely-valid UTF-8 character at ``i`` (displayable if ASCII), else 0."""
    if i >= n:
        return 0
    b0 = buf[i]
    if b0 < 0x80:
        return 1 if _DISPLAYABLE[b0] else 0
    if b0 < 0xC2 or b0 > 0xF4:
        return 0
    if b0 < 0xE0:
        if i + 2 > n or buf[i + 1] & 0xC0 != 0x80:
            return 0
        c = (b0 & 0x1F) << 6 | buf[i + 1] & 0x3F
        return 2 if _seen(c) else 0
    if b0 < 0xF0:
        if i + 3 > n or buf[i + 1] & 0xC0 != 0x80 or buf[i + 2] & 0xC0 != 0x80:
            return 0
        c = (b0 & 0x0F) << 12 | (buf[i + 1] & 0x3F) << 6 | buf[i + 2] & 0x3F
        if (b0 == 0xE0 and c < 0x800) or (b0 == 0xED and 0xD800 <= c <= 0xDFFF):
            return 0
        return 3 if _seen(c) else 0
    return 0                                       # 4 bytes: outside the BMP, not handled


def _try(buf: bytes, n: int, off: int, min_chars: int) -> tuple[str, str, int, int, int] | None:
    """(string, type, start, end, size in bytes) at ``off``, or None."""
    i, count = off, 0
    while i < n:
        m = _ASCII_RUN.match(buf, i)
        if m:
            count += m.end() - i
            i = m.end()
            continue
        step = _utf8_step(buf, n, i)
        if not step:
            break
        i += step
        count += 1
    if count >= min_chars:
        return buf[off:i].decode("utf-8", "replace"), "UTF8", off, i - 1, i - off
    group, i, count, chars = -1, off, 0, []
    while i + 1 < n:
        c = buf[i] | buf[i + 1] << 8
        if c == 0:
            break
        if c < 0x100:
            if not _DISPLAYABLE[c]:
                break
        else:
            if not _seen(c):
                break
            g = _GROUP[(c >> 4) & 0xFFF]
            if g == 0:
                break
            if group == -1:
                group = g
            elif g != group:
                break
        chars.append(c)
        i += 2
        count += 1
    if count >= min_chars:
        return "".join(map(chr, chars)), "WIDE_STRING", off, i - 2, i - off
    return None


def _interesting(s: str) -> bool:
    return len(s.encode("utf-8", "replace")) > 16


def extract_string(buffer: bytes, min_chars: int = 4, only_interesting: bool = False):  # noqa: ANN201
    if min_chars < 1:
        raise RuntimeError("min_chars must be 1 or larger")
    buf = bytes(buffer)
    got = _try(buf, len(buf), 0, min_chars)
    if got is not None:
        s, kind, start, end, _size = got
        if not only_interesting or _interesting(s):
            return s, kind, (start, end), _interesting(s)
    return "", "", (0, 0), False


def extract_all_strings(buffer: bytes, min_chars: int = 4, only_interesting: bool = False):  # noqa: ANN201
    if min_chars < 1:
        raise RuntimeError("min_chars must be 1 or larger")
    buf = bytes(buffer)
    n, off, out = len(buf), 0, []
    while off + min_chars <= n:
        got = _try(buf, n, off, min_chars)
        if got is None:
            off += 1
            continue
        s, kind, start, end, size = got
        if not only_interesting or _interesting(s):
            out.append((s, kind, (start, end), _interesting(s)))
        off += size
    return out
