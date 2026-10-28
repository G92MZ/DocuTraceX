"""Pure-Python PowerShell deobfuscation (layered, static).

PowerShell is detected all over the place today (VBA ``Shell``, DDE, the JS
sandbox command log, dropped ``.ps1``) but never *decoded*. This peels the
layers obfuscated loaders stack, statically — nothing is executed:

- ``-EncodedCommand`` / ``-enc`` / ``-e <base64>`` (UTF-16LE, the single most
  common case) and ``[Convert]::FromBase64String('..')`` (with or without an
  ``[Encoding]::Unicode/UTF8/ASCII.GetString`` wrapper);
- backtick noise (``p`o`w`e`r`shell`` -> ``powershell``);
- ``[char]0x41`` / ``[char]65`` char codes;
- string concatenation (``'a'+'b'``) and the format operator
  (``'{0}{1}' -f 'a','b'``);
- unwrapping ``Invoke-Expression`` / ``iex`` / ``&`` of a string literal;
- compressed stages: ``StreamReader(DeflateStream|GZipStream(MemoryStream(
  [Convert]::FromBase64String('..'))))`` -> the decompressed text;
- XOR: base64 bytes decrypted in a ``-bxor`` loop with a numeric or string key,
  and number arrays mapped through ``[char]($_ -bxor K)`` -> the plain text.
  Each decrypted stage is put back in place so the next pass keeps peeling.

``deobfuscate(cmd)`` returns ``{changed, code, methods}``.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from typing import Any, Callable

_MAX_PASSES = 30
_MAX_BYTES = 2_000_000

# PowerShell string literals: '...'' ...' (single, '' escapes) and "...`"..." .
_SQ = r"'(?:[^']|'')*'"
_DQ = r'"(?:`.|[^"`])*"'
_STRLIT = rf"(?:{_SQ}|{_DQ})"


def _sq_value(lit: str) -> str:
    return lit[1:-1].replace("''", "'")


def _dq_value(lit: str) -> str:
    body = lit[1:-1]
    # `-escapes inside a double-quoted string
    body = re.sub(r"`(.)", lambda m: {"n": "\n", "r": "\r", "t": "\t", "0": "\0",
                                      "a": "\a", "b": "\b", "f": "\f", "v": "\v"}.get(m.group(1), m.group(1)), body)
    return body


def _lit_value(lit: str) -> str:
    return _sq_value(lit) if lit[:1] == "'" else _dq_value(lit)


def _as_lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _b64_to_text(b64: str, encoding: str = "") -> str | None:
    b64 = re.sub(r"\s+", "", b64)
    try:
        raw = base64.b64decode(b64 + "===")
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    order = ([encoding] if encoding else []) + ["utf-16-le", "utf-8", "latin-1"]
    for enc in order:
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        # Heuristic: UTF-16LE PowerShell has very few control chars.
        if sum(1 for c in text if ord(c) < 9 or (13 < ord(c) < 32)) < max(2, len(text) // 20):
            return text
    try:
        return raw.decode("latin-1")
    except UnicodeDecodeError:
        return None


# --- transforms (each returns (code, count)) ---------------------------------

_ENC_FLAG = re.compile(r"(?i)-e(?:c|nc|ncod|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,}={0,2})")


def _t_encoded_command(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        text = _b64_to_text(m.group(1), "utf-16-le")
        if text is None:
            return m.group(0)
        n += 1
        return "\n" + text + "\n"

    return _ENC_FLAG.sub(repl, code), n


_ENC_MAP = {"unicode": "utf-16-le", "bigendianunicode": "utf-16-be",
            "utf8": "utf-8", "ascii": "ascii", "utf7": "utf-7", "utf32": "utf-32-le"}

_FROMB64_WRAPPED = re.compile(
    r"(?i)\[(?:System\.)?(?:Text\.)?Encoding\]::(\w+)\.GetString\(\s*"
    r"\[(?:System\.)?Convert\]::FromBase64String\(\s*(" + _STRLIT + r")\s*\)\s*\)"
)
_FROMB64_BARE = re.compile(
    r"(?i)\[(?:System\.)?Convert\]::FromBase64String\(\s*(" + _STRLIT + r")\s*\)"
)


def _t_frombase64(code: str) -> tuple[str, int]:
    n = 0

    def repl_wrapped(m: re.Match) -> str:
        nonlocal n
        enc = _ENC_MAP.get(m.group(1).lower(), "")
        text = _b64_to_text(_lit_value(m.group(2)), enc)
        if text is None:
            return m.group(0)
        n += 1
        return _as_lit(text)

    def repl_bare(m: re.Match) -> str:
        nonlocal n
        text = _b64_to_text(_lit_value(m.group(1)))
        # binary (compressed/encrypted bytes) stays as base64: a later stage
        # (decompress / XOR) or the analyst handles it, not latin-1 garbage
        if text is None or not _looks_text(text):
            return m.group(0)
        n += 1
        return _as_lit(text)

    code = _FROMB64_WRAPPED.sub(repl_wrapped, code)
    code = _FROMB64_BARE.sub(repl_bare, code)
    return code, n


def _t_strip_backticks(code: str) -> tuple[str, int]:
    """Drop PowerShell backtick escapes outside of strings — the classic
    ``p`o`w`e`r`shell`` noise. A backtick before a known escape char keeps its
    meaning; any other backtick is removed."""
    if "`" not in code:
        return code, 0
    before = code
    # `n `r `t -> real control chars; other `X -> X
    new = re.sub(r"`([nrt0abfv])",
                 lambda m: {"n": "\n", "r": "\r", "t": "\t", "0": "\0",
                            "a": "\a", "b": "\b", "f": "\f", "v": "\v"}[m.group(1)], code)
    new = re.sub(r"`(.)", r"\1", new, flags=re.DOTALL)
    new = new.replace("`", "")
    return (new, 1) if new != before else (new, 0)


_CHARCODE = re.compile(r"(?i)\[char\]\s*(0x[0-9a-fA-F]+|\d{1,7})")


def _t_charcode(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        try:
            ch = chr(int(m.group(1), 0) & 0x10FFFF)
        except ValueError:
            return m.group(0)
        n += 1
        return _as_lit(ch)

    return _CHARCODE.sub(repl, code), n


_CONCAT = re.compile(rf"({_STRLIT})\s*\+\s*({_STRLIT})")


def _t_concat(code: str) -> tuple[str, int]:
    n = 0
    while True:
        def repl(m: re.Match) -> str:
            nonlocal n
            n += 1
            return _as_lit(_lit_value(m.group(1)) + _lit_value(m.group(2)))

        new = _CONCAT.sub(repl, code)
        if new == code:
            break
        code = new
    return code, n


_FORMAT = re.compile(
    rf"\(?\s*({_STRLIT})\s*-f\s*((?:{_STRLIT}|\s|,)+)\)?"
)


def _t_format(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        fmt = _lit_value(m.group(1))
        args = [_lit_value(a.group(0)) for a in re.finditer(_STRLIT, m.group(2))]
        if not args or "{" not in fmt:
            return m.group(0)
        try:
            out = re.sub(r"\{(\d+)\}", lambda mm: args[int(mm.group(1))]
                         if int(mm.group(1)) < len(args) else mm.group(0), fmt)
        except (IndexError, ValueError):
            return m.group(0)
        n += 1
        return _as_lit(out)

    return _FORMAT.sub(repl, code), n


_IEX = re.compile(
    r"(?i)(?:Invoke-Expression|\biex\b|^\s*&)\s*\(?\s*(" + _STRLIT + r")\s*\)?\s*;?"
)


def _t_unwrap_iex(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return "\n" + _lit_value(m.group(1)) + "\n"

    return _IEX.sub(repl, code), n


# --- compression and XOR stages ---------------------------------------------

def _looks_text(text: str) -> bool:
    """Script-like text: almost all printable ASCII. Random bytes decoded as
    UTF-16 give "printable" CJK, so plain isprintable() is not enough."""
    if not text:
        return False
    ok = sum(1 for c in text if (" " <= c <= "~") or c in "\r\n\t")
    return ok >= len(text) * 0.85

def _bytes_text(raw: bytes) -> str | None:
    """Readable text from decrypted/decompressed bytes (UTF-16LE or 8-bit)."""
    if not raw:
        return None
    cands = []
    if len(raw) > 3 and raw[1:8:2] == b"\0" * len(raw[1:8:2]):
        cands.append("utf-16-le")
    cands += ["utf-8", "latin-1"]
    for enc in cands:
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if _looks_text(text):
            return text
    return None


_B64_LIT = r"\[(?:System\.)?Convert\]::FromBase64String\(\s*(" + _STRLIT + r")\s*\)"
_DECOMP_HEAD = (r"(?is)(?:\(\s*)?(?:New-Object\s+(?:System\.)?IO\.StreamReader\s*\(?\s*)?"
                r"\(?\s*New-Object\s+(?:System\.)?IO\.Compression\.(Deflate|GZip)Stream\s*\(?.{0,160}?" + _B64_LIT)
# with a StreamReader(...).ReadToEnd() wrapper (taken whole), or the bare stream
_DECOMPS = (re.compile(_DECOMP_HEAD + r"[^\n]{0,300}?\.ReadToEnd\(\s*\)\s*\)?"),
            re.compile(_DECOMP_HEAD + r"[^\n]{0,200}?\)"))


_MS_ASSIGN = re.compile(r"(?i)(\$[\w:]+)\s*=\s*(?:New-Object\s+(?:System\.)?IO\.MemoryStream\s*\(\s*,?\s*|"
                        r"\[(?:System\.)?IO\.MemoryStream\]\s*)" + _B64_LIT + r"\s*\)?")


def _t_decompress(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", _lit_value(m.group(2))) + "===")
            raw = zlib.decompress(raw, -15 if m.group(1).lower() == "deflate" else 31)
        except (binascii.Error, ValueError, zlib.error):
            return m.group(0)
        text = _bytes_text(raw)
        if text is None:
            return m.group(0)
        n += 1
        return _as_lit(text)

    for rx in _DECOMPS:
        code = rx.sub(repl, code)
    # MemoryStream in a variable, decompressed further down:
    #   $s = New-Object IO.MemoryStream(,[Convert]::FromBase64String('..'))
    #   ... New-Object IO.Compression.DeflateStream($s, ...)
    for am in list(_MS_ASSIGN.finditer(code)):
        sm = re.search(r"(?i)IO\.Compression\.(Deflate|GZip)Stream\s*\(\s*" + re.escape(am.group(1)) + r"\b",
                       code[am.end():am.end() + 1500])
        if not sm:
            continue
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", _lit_value(am.group(2))) + "===")
            raw = zlib.decompress(raw, -15 if sm.group(1).lower() == "deflate" else 31)
        except (binascii.Error, ValueError, zlib.error):
            continue
        text = _bytes_text(raw)
        if text is None:
            continue
        n += 1
        code = code.replace(am.group(0), f"{am.group(1)} = <# {sm.group(1)}-decompressed #> " + _as_lit(text), 1)
        code += "\n" + text + "\n"
    return code, n


_NUM = r"(?:0x[0-9a-fA-F]+|\d+)"
_VAR = r"\$[\w:]+"
_B64_ASSIGN = re.compile(r"(?i)(" + _VAR + r")\s*=\s*" + _B64_LIT)
_BXOR = re.compile(r"(?i)-bxor\s*(" + _NUM + r"|" + _VAR + r"(?:\s*\[[^\]]{1,60}\])?)")
_STR_ASSIGN = r"(?i)\{v}\s*=\s*(" + _STRLIT + r")"


def _key_bytes(code: str, key: str) -> bytes | None:
    if re.fullmatch(_NUM, key):
        return bytes([int(key, 0) & 0xFF])
    var = key.split("[", 1)[0].strip()
    m = re.search(r"(?i)" + re.escape(var) + r"\s*=\s*(" + _STRLIT + r")", code)
    if m:
        return _lit_value(m.group(1)).encode("latin-1", "replace") or None
    m = re.search(r"(?i)" + re.escape(var) + r"\s*=\s*(" + _NUM + r")\b", code)
    if m:
        return bytes([int(m.group(1), 0) & 0xFF])
    m = re.search(r"(?i)" + re.escape(var) + r"\s*=\s*(?:\[byte\[\]\]\s*)?\(?\s*(" + _NUM +
                  r"(?:\s*,\s*" + _NUM + r")+)\s*\)?", code)
    if m:
        return bytes(int(x, 0) & 0xFF for x in re.split(r"\s*,\s*", m.group(1)))
    return None


def _t_xor_base64(code: str) -> tuple[str, int]:
    """``$b = [Convert]::FromBase64String('..')`` + a ``$b[$i] -bxor KEY`` loop."""
    n = 0
    for am in list(_B64_ASSIGN.finditer(code)):
        var = am.group(1)
        tail = code[am.end():am.end() + 1500]
        xm = None
        for cand in _BXOR.finditer(tail):
            if re.escape(var.lower()) and var.lower() in tail[max(0, cand.start() - 120):cand.start()].lower():
                xm = cand
                break
        if not xm:
            continue
        key = _key_bytes(code, xm.group(1))
        if not key:
            continue
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", _lit_value(am.group(2))) + "===")
        except (binascii.Error, ValueError):
            continue
        text = _bytes_text(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)))
        if text is None:
            continue
        n += 1
        # Put the decrypted stage where the blob was; the loop stays as context.
        code = code.replace(am.group(0), f"{var} = <# XOR-decrypted (key {key!r}) #> " + _as_lit(text), 1)
        code += "\n" + text + "\n"
    return code, n


_CHAR_XOR = re.compile(
    r"(?i)(?:-join\s*)?\(?\s*(?:\[(?:byte|int|char)\[\]\]\s*)?\(\s*(" + _NUM + r"(?:\s*,\s*" + _NUM + r"){3,})\s*\)\s*"
    r"\|\s*(?:%|ForEach-Object|foreach)\s*\{\s*\[char\]\s*\(\s*(?:\[int\])?\$_\s*-bxor\s*(" + _NUM + r")\s*\)\s*\}\s*\)?"
    r"(?:\s*-join\s*(?:''|\"\"))?"
)


def _t_char_xor(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        k = int(m.group(2), 0)
        try:
            text = "".join(chr((int(x, 0) ^ k) & 0xFFFF) for x in re.split(r"\s*,\s*", m.group(1)))
        except ValueError:
            return m.group(0)
        n += 1
        return _as_lit(text)

    return _CHAR_XOR.sub(repl, code), n


_TRANSFORMS: list[tuple[str, Callable[[str], tuple[str, int]]]] = [
    ("encoded-command", _t_encoded_command),
    ("decompress", _t_decompress),
    ("xor-base64", _t_xor_base64),
    ("xor-char-array", _t_char_xor),
    ("FromBase64String", _t_frombase64),
    ("backtick-strip", _t_strip_backticks),
    ("char-code", _t_charcode),
    ("concat-strings", _t_concat),
    ("format-operator", _t_format),
    ("unwrap-iex", _t_unwrap_iex),
]


def deobfuscate(cmd: str, *, max_passes: int = _MAX_PASSES,
                max_bytes: int = _MAX_BYTES) -> dict[str, Any]:
    original = cmd or ""
    cur = original
    methods: list[str] = []
    cap = max(max_bytes, len(original) + 1)
    for _ in range(max_passes):
        if len(cur) > cap:
            break
        before = cur
        for name, fn in _TRANSFORMS:
            try:
                new, cnt = fn(cur)
            except Exception:  # noqa: BLE001
                continue
            if cnt and new != cur:
                cur = new
                if name not in methods:
                    methods.append(name)
        if cur == before:
            break
    return {"changed": cur.strip() != original.strip(), "code": cur, "methods": methods}
