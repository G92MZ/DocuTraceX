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
  Each decrypted stage is put back in place so the next pass keeps peeling;
- ``ConvertTo-SecureString -Key`` (AES) with the key in the script.

``deobfuscate(cmd)`` returns ``{changed, code, methods}``.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import fnmatch
import re
import zlib
from typing import Any, Callable

_MAX_PASSES = 30
_MAX_BYTES = 2_000_000

# PowerShell string literals: '...'' ...' (single, '' escapes) and "...`"..." .
_SQ = r"'(?:[^']|'')*'"
_DQ = r'"(?:`.|[^"`])*"'
_STRLIT = rf"(?:{_SQ}|{_DQ})"


# Stages decoded while deobfuscating (each one becomes a nested child with its
# recipe). Set per deobfuscate() call; transforms append via _stage().
_STAGES: list[dict[str, Any]] | None = None


def _stage(recipe: list[str], text: str, source: str) -> None:
    if _STAGES is not None and len(_STAGES) < 20 and text and len(text.strip()) >= 32:
        _STAGES.append({"recipe": recipe, "text": text, "source": source})


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
        _stage(["base64 (-EncodedCommand)", "utf-16le"], text, m.group(1))
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
        _stage(["base64", m.group(1).lower()], text, _lit_value(m.group(2)))
        return _as_lit(text)

    def repl_bare(m: re.Match) -> str:
        nonlocal n
        text = _b64_to_text(_lit_value(m.group(1)))
        # binary (compressed/encrypted bytes) stays as base64: a later stage
        # (decompress / XOR) or the analyst handles it, not latin-1 garbage
        if text is None or not _looks_text(text):
            return m.group(0)
        n += 1
        _stage(["base64"], text, _lit_value(m.group(1)))
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


_CHARCODE = re.compile(r"(?i)\[char\]\s*(?:\[(?:int|byte|int16|int32)\]\s*)?(?:(0x[0-9a-fA-F]+|\d{1,7})|\(\s*(0x[0-9a-fA-F]+|\d{1,7})\s*\))")


def _t_charcode(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        try:
            ch = chr(_int(m.group(1) or m.group(2)) & 0x10FFFF)
        except ValueError:
            return m.group(0)
        n += 1
        return _as_lit(ch)

    return _sub_outside(_CHARCODE, repl, code), n


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
    r"(?i)(?:(?<![\w'\"$-])(?:Invoke-Expression|iex)(?![\w'\"-])|^\s*&)\s*"
    r"(?:\(\s*(" + _STRLIT + r")\s*\)|(" + _STRLIT + r")(?=\s*(?:$|[;\n|})])))\s*;?"
)


def _t_unwrap_iex(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return "\n" + _lit_value(m.group(1) or m.group(2)) + "\n"

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
        _stage(["base64", m.group(1).lower()], text, _lit_value(m.group(2)))
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
        _stage(["base64", sm.group(1).lower()], text, _lit_value(am.group(2)))
        code = code.replace(am.group(0), f"{am.group(1)} = <# {sm.group(1)}-decompressed #> " + _as_lit(text), 1)
        code += "\n" + text + "\n"
    return code, n


_NUM = r"(?:0x[0-9a-fA-F]+|\d+)"
_VAR = r"\$[\w:]+"
_B64_ASSIGN = re.compile(r"(?i)(" + _VAR + r")\s*=\s*" + _B64_LIT)
_BXOR = re.compile(r"(?i)-bxor\s*(" + _NUM + r"|" + _VAR + r"(?:\s*\[[^\]]{1,60}\])?)")
_STR_ASSIGN = r"(?i)\{v}\s*=\s*(" + _STRLIT + r")"


def _int(x: str) -> int:
    """PowerShell integer literal: 0x.. hex, else decimal (leading zeros allowed)."""
    x = x.strip()
    return int(x, 16) if x[:2].lower() == "0x" else int(x, 10)


def _key_bytes(code: str, key: str) -> bytes | None:
    if re.fullmatch(_NUM, key):
        return bytes([_int(key) & 0xFF])
    var = key.split("[", 1)[0].strip()
    m = re.search(r"(?i)" + re.escape(var) + r"\s*=\s*(" + _STRLIT + r")", code)
    if m:
        return _lit_value(m.group(1)).encode("latin-1", "replace") or None
    m = re.search(r"(?i)" + re.escape(var) + r"\s*=\s*(" + _NUM + r")\b", code)
    if m:
        return bytes([_int(m.group(1)) & 0xFF])
    m = re.search(r"(?i)" + re.escape(var) + r"\s*=\s*(?:\[byte\[\]\]\s*)?\(?\s*(" + _NUM +
                  r"(?:\s*,\s*" + _NUM + r")+)\s*\)?", code)
    if m:
        return bytes(_int(x) & 0xFF for x in re.split(r"\s*,\s*", m.group(1)))
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
        kdesc = f"0x{key[0]:02x}" if len(key) == 1 else repr(key.decode("latin-1"))
        _stage(["base64", f"xor({kdesc})"], text, _lit_value(am.group(2)))
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
        k = _int(m.group(2))
        try:
            text = "".join(chr((_int(x) ^ k) & 0xFFFF) for x in re.split(r"\s*,\s*", m.group(1)))
        except ValueError:
            return m.group(0)
        n += 1
        return _as_lit(text)

    return _CHAR_XOR.sub(repl, code), n


_VAR_ARRAY = r"(?i)\${v}\s*=\s*(?:\[(?:byte|int|char)\[\]\]\s*)?@?\(\s*((?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+)){3,})\s*\)"
_VAR_NUM = r"(?i)\${v}\s*=\s*(0x[0-9a-f]+|\d+)\b"
_VAR_XOR = re.compile(
    r"(?i)-join\s*\(?\s*\$(\w+)\s*\|\s*(?:%|ForEach-Object|foreach)\s*\{\s*\[char\]\s*\(\s*(?:\[int\])?\s*\$_\s*"
    r"-bxor\s*(?:\$(\w+)|(0x[0-9a-f]+|\d+))\s*\)\s*\}\s*\)?")


def _t_var_xor(code: str) -> tuple[str, int]:
    """``-join($arr | %{[char]([int]$_ -bxor $key)})`` with ``$arr = @(n,…)`` and
    ``$key = n`` defined elsewhere in the script -> the decoded string."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        am = re.search(_VAR_ARRAY.replace("{v}", re.escape(m.group(1))), code)
        if not am:
            return m.group(0)
        if m.group(3):
            k = _int(m.group(3))
        else:
            km = re.search(_VAR_NUM.replace("{v}", re.escape(m.group(2))), code)
            if not km:
                return m.group(0)
            k = _int(km.group(1))
        try:
            text = "".join(chr((_int(x) ^ k) & 0xFFFF) for x in re.split(r"\s*,\s*", am.group(1)))
        except ValueError:
            return m.group(0)
        n += 1
        return _as_lit(text)

    return _VAR_XOR.sub(repl, code), n


# A helper scriptblock that turns a hex string into text, e.g.
#   $h2s = { param($h) … [Convert]::ToInt32($h.Substring($i,2),16) … }
_HEX_HELPER = re.compile(r"(?is)\$(\w+)\s*=\s*\{\s*param\s*\(\s*\$\w+\s*\)[^\n]{0,400}?"
                         r"ToInt32\s*\(\s*\$\w+\.Substring\s*\([^)]*,\s*2\s*\)\s*,\s*16\s*\)")


def _t_hex_helper(code: str) -> tuple[str, int]:
    """``& $helper '4865…'`` where ``$helper`` is a hex-to-text scriptblock."""
    n = 0
    for hm in _HEX_HELPER.finditer(code):
        call = re.compile(r"(?i)&\s*\$" + re.escape(hm.group(1)) + r"\s+(" + _STRLIT + r")")

        def repl(m: re.Match) -> str:
            nonlocal n
            h = re.sub(r"\s+", "", _lit_value(m.group(1)))
            if len(h) % 2 or not re.fullmatch(r"[0-9A-Fa-f]*", h):
                return m.group(0)
            try:
                text = bytes.fromhex(h).decode("latin-1")
            except ValueError:
                return m.group(0)
            n += 1
            return _as_lit(text)

        code = call.sub(repl, code)
    return code, n


# ConvertTo-SecureString -Key: .NET's exported SecureString is the header
# 76492d1116743f0423413b16050a5345 + base64(UTF-16LE "2|<base64 IV>|<hex AES-CBC
# ciphertext>"), the plaintext UTF-16LE. With the key in the script, decryptable.
_SS_HEADER = "76492d1116743f0423413b16050a5345"
_SS = re.compile(
    r"(?is)(?:(" + _STRLIT + r"|\$[\w:]+)\s*\|\s*)?ConvertTo-SecureString\s+"
    r"(?:-String\s+)?(" + _STRLIT + r"|\$[\w:]+)?\s*-Key\s+"
    r"(\(\s*\d+\s*\.\.\s*\d+\s*\)|@?\(\s*(?:\[byte\[\]\]\s*)?[\d,\s x0-9a-fA-F]+\)|\$[\w:]+|\(\s*\[byte\[\]\]\s*\(\s*[\d,\s]+\)\s*\))")


def _ss_key(code: str, expr: str) -> bytes | None:
    expr = expr.strip()
    m = re.fullmatch(r"\(\s*(\d+)\s*\.\.\s*(\d+)\s*\)", expr)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        rng = range(a, b + 1) if a <= b else range(a, b - 1, -1)
        return bytes(x & 0xFF for x in rng)
    nums = re.findall(r"0x[0-9a-fA-F]+|\d+", expr)
    if not expr.startswith("$") and nums:
        return bytes(_int(x) & 0xFF for x in nums)
    if expr.startswith("$"):
        return _key_bytes(code, expr)
    return None


def _ss_value(code: str, ref: str) -> str | None:
    if not ref:
        return None
    if ref.startswith("$"):
        m = re.search(r"(?i)" + re.escape(ref) + r"\s*=\s*(" + _STRLIT + r")", code)
        return _lit_value(m.group(1)) if m else None
    return _lit_value(ref)


def securestring_decrypt(blob: str, key: bytes) -> str | None:
    blob = re.sub(r"\s+", "", blob or "")
    if not blob.lower().startswith(_SS_HEADER) or len(key) not in (16, 24, 32):
        return None
    try:
        inner = base64.b64decode(blob[len(_SS_HEADER):] + "===").decode("utf-16-le")
        _v, iv_b64, hexct = inner.split("|")[:3]
        iv, ct = base64.b64decode(iv_b64), bytes.fromhex(hexct)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
    except Exception:  # noqa: BLE001
        return None
    n = pt[-1] if pt else 0
    if 1 <= n <= 16 and pt.endswith(bytes([n]) * n):
        pt = pt[:-n]
    try:
        return pt.decode("utf-16-le")
    except UnicodeDecodeError:
        return None


def _t_securestring(code: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        key = _ss_key(code, m.group(3))
        val = _ss_value(code, m.group(2) or m.group(1) or "")
        if not key or not val:
            return m.group(0)
        text = securestring_decrypt(val, key)
        if text is None:
            return m.group(0)
        n += 1
        _stage(["securestring", f"aes-{len(key) * 8}-cbc"], text, val)
        return f"<# SecureString decrypted (AES key {key[:8].hex()}…) #> " + _as_lit(text)

    return _SS.sub(repl, code), n


def _lit_spans(code: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in re.finditer(_STRLIT, code)]


def _sub_outside(rx: re.Pattern, repl: Callable[[re.Match], str], code: str) -> str:
    """``rx.sub`` that leaves matches starting *inside* a string literal alone —
    a layer still quoted is data until a later pass unwraps it."""
    if not rx.search(code):
        return code
    spans = _lit_spans(code)
    starts = [a for a, _ in spans]
    out, last = [], 0
    for m in rx.finditer(code):
        i = bisect.bisect_right(starts, m.start()) - 1
        if i >= 0 and spans[i][0] < m.start() < spans[i][1]:
            continue
        r = repl(m)
        out += [code[last:m.start()], r]
        last = m.end()
    out.append(code[last:])
    return "".join(out)

# --- Invoke-Obfuscation ------------------------------------------------------
# Daniel Bohannon's Invoke-Obfuscation (and its imitators) hide the launcher
# behind tricks that only make sense at run time: "iex" sliced out of
# environment variables, reversed strings, -replace/.Replace chains, numbers in
# octal/binary/hex split and re-joined, wildcard command lookup and aliases.
# Each one is resolved statically into a plain literal / command name, so the
# generic literal transforms (concat, iex unwrap…) finish the job.

# Values Invoke-Obfuscation slices characters from (a stock Windows host).
_AUTO_VARS = {
    "env:comspec": r"C:\WINDOWS\system32\cmd.exe",
    "pshome": r"C:\Windows\System32\WindowsPowerShell\v1.0",
    "shellid": "Microsoft.PowerShell",
    "env:public": r"C:\Users\Public",
    "verbosepreference": "SilentlyContinue",
    "verbosepreference.tostring()": "SilentlyContinue",
    "env:windir": r"C:\WINDOWS",
    "env:systemroot": r"C:\WINDOWS",
    "env:programdata": r"C:\ProgramData",
    "env:allusersprofile": r"C:\ProgramData",
}
_AUTO = r"\$\{?(" + "|".join(re.escape(k).replace(r"\.tostring\(\)", r"\.tostring\(\s*\)")
                              for k in sorted(_AUTO_VARS, key=len, reverse=True)) + r")\}?"
_IDX = r"-?\d{1,3}"
_SLICE = re.compile(r"(?i)(\(\s*)?" + _AUTO + r"(\s*\))?\s*\[\s*(" + _IDX + r"(?:\s*,\s*" + _IDX + r")*)\s*\]")


def _t_env_slice(code: str) -> tuple[str, int]:
    """``$env:ComSpec[4,15,25]-join''`` / ``$PSHome[4]+$PSHome[30]+'x'`` → 'iex'."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        opn, var, cls, idx = m.groups()
        key = re.sub(r"\s+", "", var.lower())
        val = _AUTO_VARS.get(key)
        if val is None:
            return m.group(0)
        try:
            out = "".join(val[int(i)] for i in idx.split(","))
        except (IndexError, ValueError):
            return m.group(0)
        n += 1
        if bool(opn) == bool(cls):
            return _as_lit(out)
        return (opn or "") + _as_lit(out) + (cls or "")

    return _sub_outside(_SLICE, repl, code), n


_REV_IDX = r"\[\s*-\s*1\s*\.\.\s*-\s*\(?\s*(?:\d+|(?:" + _STRLIT + r"|\$\w+)\s*\.\s*Length)\s*\)?\s*\]"
_REVERSE = (
    re.compile(r"(?i)-join\s*\(\s*(" + _STRLIT + r")\s*" + _REV_IDX + r"\s*\)"),
    re.compile(r"(?i)-join\s*(" + _STRLIT + r")\s*" + _REV_IDX),
    re.compile(r"(?i)\(\s*(" + _STRLIT + r")\s*" + _REV_IDX + r"\s*-join\s*(?:''|\"\")\s*\)"),
    re.compile(r"(?i)-join\s*\[regex\]::Matches\(\s*(" + _STRLIT + r")\s*,\s*['\"]\.['\"]\s*,\s*"
               r"['\"]RightToLeft['\"]\s*\)"),
)


def _t_reverse(code: str) -> tuple[str, int]:
    """``-join ('xei'[-1..-3])`` and ``-join [regex]::Matches('xei','.','RightToLeft')``."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return _as_lit(_lit_value(m.group(1))[::-1])

    for rx in _REVERSE:
        code = _sub_outside(rx, repl, code)
    return code, n


def _ps_repl(rep: str) -> Callable[[re.Match], str]:
    """PowerShell -replace substitution ($1, ${name}, $$) as a re callback."""
    def f(m: re.Match) -> str:
        def g(mm: re.Match) -> str:
            tok = mm.group(1)
            if tok == "$":
                return "$"
            tok = tok.strip("{}")
            try:
                return m.group(int(tok) if tok.isdigit() else tok) or ""
            except (IndexError, re.error, KeyError):
                return mm.group(0)
        return re.sub(r"\$(\$|\d+|\{\w+\})", g, rep)
    return f


_REPLACE_OP = re.compile(r"(?i)(" + _STRLIT + r")\s*-([ci]?)replace\s*(" + _STRLIT + r")"
                         r"\s*,\s*(" + _STRLIT + r")")
_REPLACE_M = re.compile(r"(?i)(" + _STRLIT + r")\s*\.Replace\(\s*(" + _STRLIT + r")\s*,\s*(" + _STRLIT + r")\s*\)")


def _t_replace(code: str) -> tuple[str, int]:
    """``'..X..' -replace 'X','y'`` (regex, case-insensitive unless -creplace)
    and ``('..X..').Replace('X','y')`` (literal)."""
    n = 0

    def op(m: re.Match) -> str:
        nonlocal n
        flags = 0 if m.group(2).lower() == "c" else re.IGNORECASE
        try:
            out = re.sub(_lit_value(m.group(3)), _ps_repl(_lit_value(m.group(4))),
                         _lit_value(m.group(1)), flags=flags)
        except re.error:
            return m.group(0)
        n += 1
        return _as_lit(out)

    def meth(m: re.Match) -> str:
        nonlocal n
        old = _lit_value(m.group(2))
        if not old:
            return m.group(0)
        n += 1
        return _as_lit(_lit_value(m.group(1)).replace(old, _lit_value(m.group(3))))

    code = _sub_outside(_REPLACE_OP, op, code)
    code = _sub_outside(_REPLACE_M, meth, code)
    return code, n


_TOINT = re.compile(r"(?i)\[convert\]::ToInt(?:16|32|64)\(\s*(" + _STRLIT + r"|\$_|\d+)\s*,\s*(\d+)\s*\)")
_NUMLIST = r"(?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+)){2,}"
_CHAR_ARRAY = re.compile(r"(?i)\[char\[\]\]\s*@?\(\s*(" + _NUMLIST + r")\s*\)")
_SPLIT_SRC = (r"(?:(" + _STRLIT + r")\s*\.Split\(\s*(" + _STRLIT + r")\s*\)"
              r"|\(\s*(" + _STRLIT + r")\s*-c?split\s*(" + _STRLIT + r")\s*\)"
              r"|@?\(\s*(" + _NUMLIST + r")\s*\))")
_EACH = (r"\s*\|\s*(?:%|ForEach-Object|ForEach|foreach)\s*\{\s*\(?\s*\[char\]\s*(?:\[(?:int|byte|int16|int32)\]\s*)?\(?\s*"
         r"(?:\[convert\]::ToInt(?:16|32|64)\(\s*\$_\s*,\s*(\d+)\s*\)|\$_\s*(?:-bxor\s*(" + _NUM + r"))?|"
         r"\(\s*\$_\s*-bxor\s*(" + _NUM + r")\s*\))\s*\)?\s*\)?\s*\}")
_SPLIT_EACH = re.compile(r"(?i)" + _SPLIT_SRC + _EACH)


def _t_numeric_chars(code: str) -> tuple[str, int]:
    """Character codes in any base, split and mapped back to chars:
    ``'110~151'.Split('~') | % {[char]([convert]::ToInt16($_,8))}``,
    ``-split`` variants, ``@(72,101,…) | % {[char]($_ -bxor 7)}``,
    ``[char[]](72,101,…)`` and a lone ``[convert]::ToInt16('101',8)``."""
    n = 0

    def each(m: re.Match) -> str:
        nonlocal n
        src, sep, src2, rx, nums, base, k1, k2 = m.groups()
        try:
            if nums:
                toks = [t.strip() for t in nums.split(",")]
            elif src is not None:
                seps = _lit_value(sep)
                toks = re.split("[" + re.escape(seps) + "]", _lit_value(src)) if seps else [_lit_value(src)]
            else:
                toks = re.split(_lit_value(rx), _lit_value(src2))
            toks = [t.strip() for t in toks if t.strip()]
            b = int(base) if base else 0
            key = _int(k1 or k2) if (k1 or k2) else 0
            out = "".join(chr((int(t, b) if b else _int(t)) ^ key) for t in toks)
        except (ValueError, re.error, OverflowError):
            return m.group(0)
        n += 1
        return _as_lit(out)

    def arr(m: re.Match) -> str:
        nonlocal n
        try:
            out = "".join(chr(_int(t.strip())) for t in m.group(1).split(","))
        except (ValueError, OverflowError):
            return m.group(0)
        n += 1
        return _as_lit(out)

    def toint(m: re.Match) -> str:
        nonlocal n
        v = m.group(1)
        if v == "$_":
            return m.group(0)
        try:
            num = int(_lit_value(v) if v[:1] in "'\"" else v, int(m.group(2)))
        except ValueError:
            return m.group(0)
        n += 1
        return str(num)

    code = _sub_outside(_SPLIT_EACH, each, code)
    code = _sub_outside(_CHAR_ARRAY, arr, code)
    code = _sub_outside(_TOINT, toint, code)
    return code, n


_JOIN_BIN = re.compile(r"(?i)(" + _STRLIT + r")\s*-join\s*(?:" + _STRLIT + r")")
_JOIN_UN = re.compile(r"(?i)-join\s*(" + _STRLIT + r")(?!\s*[\[.])")
_JOIN_FN = re.compile(r"(?i)\[string\]::join\(\s*" + _STRLIT + r"\s*,\s*(" + _STRLIT + r")\s*\)")
_UNARY_PREV = re.compile(r"(?:^|[(=,;|&{\n])\s*$")


def _t_join_lit(code: str) -> tuple[str, int]:
    """Joining a single string is a no-op: ``-join 'abc'`` / ``'abc' -join ''``."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return m.group(1)

    code = _sub_outside(_JOIN_BIN, repl, code)
    code = _sub_outside(_JOIN_FN, repl, code)
    src = code

    def un(m: re.Match) -> str:
        nonlocal n
        if not _UNARY_PREV.search(src[max(0, m.start() - 40):m.start()]):
            return m.group(0)
        n += 1
        return m.group(1)

    return _sub_outside(_JOIN_UN, un, code), n


_PAREN_LIT = re.compile(r"\(\s*(" + _STRLIT + r")\s*\)")
_PAREN_OK_PREV = re.compile(r"(?i)(?:^|[&.(,=+|;{\n]|-\w+|\biex|Invoke-Expression)\s*$")


def _t_paren_lit(code: str) -> tuple[str, int]:
    """``('abc')`` → ``'abc'`` where the parentheses are only grouping."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        if not _PAREN_OK_PREV.search(code[max(0, m.start() - 40):m.start()]):
            return m.group(0)
        n += 1
        return m.group(1)

    return _sub_outside(_PAREN_LIT, repl, code), n


# Common cmdlets a wildcard (gcm *ke-e*) or GetCmdlet() lookup resolves to.
_CMDLETS = ("Invoke-Expression", "New-Object", "Invoke-WebRequest", "Invoke-RestMethod",
            "Start-Process", "Invoke-Command", "Add-Type", "Set-Variable", "Get-Variable",
            "Start-BitsTransfer", "Invoke-Item", "Set-ItemProperty", "New-ItemProperty",
            "Start-Sleep", "Out-Null", "Out-String", "Get-Process", "Stop-Process",
            "Set-Content", "Get-Content", "Remove-Item", "Copy-Item", "Register-ScheduledTask",
            "New-ScheduledTaskAction", "Write-Host", "Get-WmiObject", "Invoke-WmiMethod",
            "Get-CimInstance", "Invoke-CimMethod", "Set-MpPreference", "Add-MpPreference",
            "ConvertTo-SecureString", "ConvertFrom-SecureString")
_GCM = re.compile(r"(?i)(?:(?<![\w'\"\])])[&.]\s*)?\(\s*(?:gcm|Get-Command)\s+\(?\s*(" + _STRLIT + r"|[\w*?\-\[\]]+)\s*\)?\s*\)")
_GETCMDLET = re.compile(r"(?i)(?:(?<![\w'\"\])])[&.]\s*)?\(?\s*\$ExecutionContext\.InvokeCommand\.(?:GetCmdlet|GetCommand|GetCommandName)"
                        r"\(\s*(" + _STRLIT + r")[^()]*\)\s*\)?")
_CALL_NAME = re.compile(r"(?i)(?:(?<![\w'\"\])\]])|(?<=\())([&.])\s*(" + _STRLIT + r")(?=\s|$|[;)|}])")


def _resolve_cmd(pattern: str) -> str | None:
    hits = [c for c in _CMDLETS if fnmatch.fnmatchcase(c.lower(), pattern.lower())]
    if not hits and pattern.lower() in ("iex",):
        return "Invoke-Expression"
    return hits[0] if len(hits) == 1 else None


def _t_cmd_lookup(code: str) -> tuple[str, int]:
    """``&(gcm *ke-e*)``, ``.(Get-Command I*-*pr*)``,
    ``$ExecutionContext.InvokeCommand.GetCmdlet('Invoke-Expression')`` and
    ``&('iex')`` / ``.('New-Object')`` → the plain command name."""
    n = 0

    def gcm(m: re.Match) -> str:
        nonlocal n
        pat = m.group(1)
        pat = _lit_value(pat) if pat[:1] in "'\"" else pat
        name = _resolve_cmd(pat)
        if not name:
            return m.group(0)
        n += 1
        return name

    def call(m: re.Match) -> str:
        nonlocal n
        name = _lit_value(m.group(2))
        if not re.fullmatch(r"[A-Za-z][\w-]{1,40}", name):
            return m.group(0)
        n += 1
        return name

    code = _sub_outside(_GCM, gcm, code)
    code = _sub_outside(_GETCMDLET, gcm, code)
    code = _sub_outside(_CALL_NAME, call, code)
    return code, n


_ALIAS_DEF = re.compile(r"(?i)\b(?:sal|Set-Alias|nal|New-Alias)\s+(?:-Name\s+)?([\w-]+)\s+(?:-Value\s+)?"
                        r"(" + _STRLIT + r"|[\w-]+)\s*;?")


def _t_alias(code: str) -> tuple[str, int]:
    """``Set-Alias x9 Invoke-Expression; x9 (...)`` → ``Invoke-Expression (...)``."""
    n = 0
    spans = _lit_spans(code)
    for m in list(_ALIAS_DEF.finditer(code)):
        if any(a < m.start() < b for a, b in spans):
            continue
        alias, target = m.group(1), m.group(2)
        target = _lit_value(target) if target[:1] in "'\"" else target
        if not re.fullmatch(r"[A-Za-z][\w-]{1,40}", target) or alias.lower() == target.lower():
            continue
        tail = code[m.end():]
        new_tail = _sub_outside(re.compile(r"(?i)(?<![\w$.-])" + re.escape(alias) + r"(?![\w-])"),
                                lambda _m: target, tail)
        k = int(new_tail != tail)
        if k:
            code = code[:m.start()] + new_tail
            n += k
            break   # offsets changed; next pass picks up the rest
    return code, n


_BRACE_VAR = re.compile(r"\$\{(\w+(?::\w+)?)\}")


def _t_brace_vars(code: str) -> tuple[str, int]:
    """``${env:ComSpec}`` / ``${x}`` → ``$env:ComSpec`` / ``$x``."""
    new = _sub_outside(_BRACE_VAR, lambda m: "$" + m.group(1), code)
    return new, int(new != code)


_SCRIPTBLOCK = re.compile(r"(?i)&?\s*\(?\s*(?:\[scriptblock\]::Create|\$ExecutionContext\.InvokeCommand\.(?:InvokeScript|NewScriptBlock))"
                          r"\(\s*(" + _STRLIT + r")\s*\)\s*\)?(?:\.Invoke\(\s*\))?")
_PIPE_IEX = re.compile(r"(?i)(" + _STRLIT + r")\s*\|\s*(?:iex|Invoke-Expression)\b")


def _t_scriptblock(code: str) -> tuple[str, int]:
    """``[ScriptBlock]::Create('…')``, ``InvokeCommand.InvokeScript('…')`` and
    ``'…' | iex`` → the code itself."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return "\n" + _lit_value(m.group(1)) + "\n"

    code = _sub_outside(_SCRIPTBLOCK, repl, code)
    code = _sub_outside(_PIPE_IEX, repl, code)
    return code, n


_TRANSFORMS: list[tuple[str, Callable[[str], tuple[str, int]]]] = [
    ("encoded-command", _t_encoded_command),
    ("decompress", _t_decompress),
    ("xor-base64", _t_xor_base64),
    ("xor-char-array", _t_char_xor),
    ("xor-var-array", _t_var_xor),
    ("hex-helper", _t_hex_helper),
    ("securestring", _t_securestring),
    ("FromBase64String", _t_frombase64),
    ("backtick-strip", _t_strip_backticks),
    ("brace-vars", _t_brace_vars),
    ("env-var-slice", _t_env_slice),
    ("reverse-string", _t_reverse),
    ("numeric-char-codes", _t_numeric_chars),
    ("replace-chain", _t_replace),
    ("join", _t_join_lit),
    ("paren-literal", _t_paren_lit),
    ("command-lookup", _t_cmd_lookup),
    ("alias", _t_alias),
    ("scriptblock", _t_scriptblock),
    ("char-code", _t_charcode),
    ("concat-strings", _t_concat),
    ("format-operator", _t_format),
    ("unwrap-iex", _t_unwrap_iex),
]


def deobfuscate(cmd: str, *, max_passes: int = _MAX_PASSES,
                max_bytes: int = _MAX_BYTES) -> dict[str, Any]:
    global _STAGES
    original = cmd or ""
    cur = original
    methods: list[str] = []
    stages: list[dict[str, Any]] = []
    _STAGES = stages
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
    _STAGES = None
    # Only stages decoded from data written in THIS script: deeper layers come
    # out again when the stage itself is analysed as a nested child.
    top, seen = [], set()
    for st in stages:
        src = st.pop("source", "")
        if src and src in original and st["text"] not in seen:
            seen.add(st["text"])
            top.append(st)
    return {"changed": cur.strip() != original.strip(), "code": cur, "methods": methods, "stages": top}
