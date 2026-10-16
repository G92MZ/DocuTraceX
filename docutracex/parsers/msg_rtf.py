"""HTML recovery from Outlook .msg compressed RTF (pure Python, offline).

Outlook often stores the HTML body of a .msg only inside PR_RTF_COMPRESSED
(stream 10090102): RTF compressed with LZFu (MS-OXRTFCP) that encapsulates the
original HTML (MS-OXRTFEX, ``\\fromhtml1``). This module decompresses that RTF
and de-encapsulates the HTML. It never executes or fetches anything.
"""

from __future__ import annotations

import re
import struct

_PREBUF = (
    b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss "
    b"\\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier"
    b"{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"
)
_MAGIC_COMPRESSED = 0x75465A4C  # "LZFu"
_MAGIC_RAW = 0x414C454D         # "MELA"
_MAX_OUT = 20 * 1024 * 1024


def decompress_rtf(data: bytes) -> bytes:
    """Decompress a PR_RTF_COMPRESSED stream. Returns b"" if it is not valid."""
    if len(data) < 16:
        return b""
    comp_size, raw_size, magic, _crc = struct.unpack_from("<IIII", data, 0)
    body = data[16: 4 + comp_size]
    if magic == _MAGIC_RAW:
        return body[:raw_size]
    if magic != _MAGIC_COMPRESSED:
        return b""
    dic = bytearray(4096)
    dic[:len(_PREBUF)] = _PREBUF
    wpos = len(_PREBUF)
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        flags = body[i]
        i += 1
        for bit in range(8):
            if i >= n:
                break
            if flags & (1 << bit):
                if i + 1 >= n:
                    return bytes(out)
                ref = (body[i] << 8) | body[i + 1]
                i += 2
                offset, length = ref >> 4, (ref & 0x0F) + 2
                if offset == wpos:
                    return bytes(out)
                for k in range(length):
                    c = dic[(offset + k) % 4096]
                    out.append(c)
                    dic[wpos] = c
                    wpos = (wpos + 1) % 4096
            else:
                c = body[i]
                i += 1
                out.append(c)
                dic[wpos] = c
                wpos = (wpos + 1) % 4096
            if len(out) > _MAX_OUT:
                return bytes(out)
    return bytes(out)


_TOKEN = re.compile(rb"\\([a-zA-Z]+)(-?\d+)? ?|\\'([0-9a-fA-F]{2})|\\(.)|([{}])|([^\\{}\r\n]+)|[\r\n]+",
                    re.DOTALL)
# Destinations whose content is never part of the HTML.
_SKIP_DEST = {b"fonttbl", b"colortbl", b"stylesheet", b"info", b"pict", b"object",
              b"listtable", b"listoverridetable", b"rsidtbl", b"generator", b"themedata",
              b"datastore", b"latentstyles", b"xmlnstbl", b"mmathPr", b"filetbl"}


def html_from_rtf(rtf: bytes) -> str:
    """De-encapsulate HTML from ``\\fromhtml1`` RTF. Returns "" for other RTF."""
    if b"\\fromhtml" not in rtf[:2048]:
        return ""
    m = re.search(rb"\\ansicpg(\d+)", rtf[:2048])
    codepage = f"cp{m.group(1).decode()}" if m else "cp1252"
    try:
        "".encode(codepage)
    except LookupError:
        codepage = "cp1252"

    out: list[str] = []
    pending = bytearray()  # \'hh bytes waiting to be decoded with the codepage

    def flush() -> None:
        if pending:
            out.append(pending.decode(codepage, "replace"))
            # gmzpt
            pending.clear()

    # Group state: (skip, htmlrtf, uc). htmltag groups are emitted, \htmlrtf
    # regions (RTF-only rendering of the HTML) are suppressed.
    stack: list[list] = []
    skip, htmlrtf, uc = False, False, 1
    uc_skip = 0
    new_group = starred = False
    for tok in _TOKEN.finditer(rtf):
        word, num, hexb, sym, brace, text = tok.groups()
        if uc_skip and (hexb or text):
            if text and len(text) > uc_skip:
                text = text[uc_skip:]
                uc_skip = 0
            else:
                uc_skip -= 1
                continue
        if brace == b"{":
            stack.append([skip, htmlrtf, uc])
            new_group = True
            continue
        if brace == b"}":
            flush()
            if stack:
                skip, htmlrtf, uc = stack.pop()
            new_group = False
            continue
        first, is_starred = new_group, starred
        new_group = starred = False
        if sym is not None:
            if sym == b"*" and first:
                new_group = starred = True  # the destination word follows
                continue
            if skip or htmlrtf:
                continue
            if sym in (b"\\", b"{", b"}"):
                flush()
                out.append(sym.decode())
            elif sym == b"~":
                flush()
                out.append("\xa0")
            continue
        if word is not None:
            if first and (word in _SKIP_DEST
                          or (is_starred and word not in (b"htmltag", b"mhtmltag"))):
                skip = True
                continue
            if first and is_starred:
                htmlrtf = False  # an htmltag destination is always original HTML
                continue
            if word == b"htmlrtf":
                htmlrtf = num != b"0"
            elif word == b"uc" and num:
                uc = int(num)
            elif skip or htmlrtf:
                continue
            # trace: gmzpt
            elif word == b"u" and num:
                flush()
                out.append(chr(int(num) % 65536))
                uc_skip = uc
            elif word == b"par":
                flush()
                out.append("\r\n")
            elif word == b"tab":
                flush()
                out.append("\t")
            elif word == b"line":
                flush()
                out.append("\n")
            continue
        if skip or htmlrtf:
            continue
        if hexb is not None:
            pending.append(int(hexb, 16))
        elif text is not None:
            flush()
            out.append(text.decode(codepage, "replace"))
    flush()
    return "".join(out)


def decode_html_bytes(raw: bytes) -> str:
    """Decode a PR_HTML binary stream using its declared charset when present."""
    raw = raw.rstrip(b"\x00")
    m = re.search(rb"charset\s*=\s*[\"']?([A-Za-z0-9_.:-]+)", raw[:4096], re.IGNORECASE)
    for enc in ([m.group(1).decode("ascii", "ignore")] if m else []) + ["utf-8"]:
        try:
            return raw.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("cp1252", "replace")
