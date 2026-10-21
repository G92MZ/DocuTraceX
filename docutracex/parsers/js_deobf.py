"""Pure-Python JavaScript deobfuscation cascade.

Runs *before* the rest of the JavaScript analysis so the detector, decoder and
sandbox see the real payload instead of its wrapper. Nothing here executes the
script — every transform is a static rewrite — so it is safe to run on the
host Python (no STPyV8 needed) and on nested children.

The cascade, applied in a loop until the code stabilises:

1. multi-pass static decoding — JS string escapes (``\\xNN`` / ``\\uNNNN`` /
   octal), ``unescape`` / ``decodeURIComponent`` percent sequences,
   ``String.fromCharCode``, ``atob`` base64, adjacent-string concatenation,
   string-table (``var a=['..','..']; a[0]``) inlining and single-use string
   variable inlining;
2. unwrapping of the dynamic-exec layer — ``eval`` / ``Function`` /
   ``setTimeout`` / ``document.write`` of a string literal is replaced by the
   literal's value *as code*, so stacked layers unfold pass after pass;
3. known packer schemes — Dean Edwards ``p,a,c,k,e,d`` is fully unpacked here;
   JSFuck / AAEncode / JJEncode are detected and flagged (they are left for the
   STPyV8 sandbox, which hooks ``eval``/``Function`` and unfolds them at run
   time).

``deobfuscate(code)`` returns the best deobfuscated artifact plus the list of
transforms (``layers``) and packer schemes (``schemes``) seen, so the caller
can re-analyse the clean code and surface *how* it was obfuscated.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Callable

_MAX_PASSES = 40
_MAX_BYTES = 4_000_000          # stop expanding past this (zip-bomb-ish packers)
_MAX_LITERAL = 200_000          # a single string literal we will rewrite

# --- low-level string helpers -------------------------------------------------

# A JS string-literal body, written to be *unambiguous*: a backslash can only
# be consumed by ``\\.`` (never by the "any other char" branch), so a failed
# match backtracks linearly instead of exploding exponentially on escape-heavy
# obfuscated strings.
def _lit_pat(q: str = "q") -> str:
    return rf"(?P<{q}>[\"'])(?:\\.|(?!(?P={q}))[^\\])*(?P={q})"


# One JS string literal, single or double quoted, escapes respected.
_STR = re.compile(r"""(?P<q>["'])(?P<body>(?:\\.|(?!(?P=q))[^\\])*)(?P=q)""", re.DOTALL)

_JS_ESC = re.compile(
    r"\\(?:x([0-9a-fA-F]{2})"          # \xNN
    r"|u\{([0-9a-fA-F]{1,6})\}"        # \u{NNNN}
    r"|u([0-9a-fA-F]{4})"              # \uNNNN
    r"|([0-3]?[0-7]{1,2})"             # octal \NNN (incl. \0)
    r"|(\r\n|[\r\n  ])"      # line continuation
    r"|(.))",                          # any other escaped char
    re.DOTALL,
)

_ESC_MAP = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def _unescape_js(body: str) -> str:
    """Value of a JS string-literal body (without the surrounding quotes)."""

    def sub(m: re.Match) -> str:
        hx, ub, u4, octd, cont, other = m.groups()
        try:
            if hx is not None:
                return chr(int(hx, 16))
            if ub is not None:
                cp = int(ub, 16)
                return chr(cp) if cp <= 0x10FFFF else ""
            if u4 is not None:
                return chr(int(u4, 16))
            if octd is not None:
                return chr(int(octd, 8) & 0xFF)
        except ValueError:
            return ""
        if cont is not None:
            return ""
        return _ESC_MAP.get(other, other)

    return _JS_ESC.sub(sub, body)


def _as_js_literal(value: str) -> str:
    """A double-quoted JS literal whose value is ``value``. Exact inverse of
    ``_unescape_js`` so an unwrap step recovers the original bytes."""
    out = ['"']
    for ch in value:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20 or o == 0x7F:
            out.append(f"\\x{o:02x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _decode_percent(s: str) -> str:
    s = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)
    return s


def _lit_value(lit: str) -> str:
    """Value of a full string literal token (quotes included)."""
    return _unescape_js(lit[1:-1])


# --- individual transforms ----------------------------------------------------
# Each returns (new_code, number_of_rewrites). A 0 count means "did nothing".


def _t_decode_escapes(code: str) -> tuple[str, int]:
    """Resolve \\xNN / \\uNNNN / octal escapes inside every string literal."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        body = m.group("body")
        if len(body) > _MAX_LITERAL or "\\" not in body:
            return m.group(0)
        new = _as_js_literal(_unescape_js(body))
        if new != m.group(0):
            n += 1
        return new

    return _STR.sub(repl, code), n


def _t_unescape_calls(code: str) -> tuple[str, int]:
    """``unescape('..')`` / ``decodeURIComponent('..')`` -> decoded literal."""
    n = 0
    rx = re.compile(
        r"\b(?:unescape|decodeURIComponent)\s*\(\s*"
        r"(?P<str>(?P<q>[\"'])(?:\\.|(?!(?P=q))[^\\])*(?P=q))\s*\)",
        re.DOTALL,
    )

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        return _as_js_literal(_decode_percent(_lit_value(m.group("str"))))

    return rx.sub(repl, code), n


def _t_fromcharcode(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(
        r"String\.fromCharCode\s*\(\s*"
        r"((?:0x[0-9a-fA-F]+|\d{1,7})(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d{1,7}))*)\s*\)"
    )

    def repl(m: re.Match) -> str:
        nonlocal n
        try:
            chars = [chr(int(x.strip(), 0) & 0x10FFFF) for x in m.group(1).split(",")]
        except ValueError:
            return m.group(0)
        n += 1
        return _as_js_literal("".join(chars))

    return rx.sub(repl, code), n


def _t_atob(code: str) -> tuple[str, int]:
    n = 0
    rx = re.compile(r"\batob\s*\(\s*(?P<str>(?P<q>[\"'])(?:\\.|(?!(?P=q))[^\\])*(?P=q))\s*\)")

    def repl(m: re.Match) -> str:
        nonlocal n
        raw = _lit_value(m.group("str"))
        try:
            dec = base64.b64decode(raw + "===").decode("latin-1")
        except Exception:  # noqa: BLE001
            return m.group(0)
        n += 1
        return _as_js_literal(dec)

    return rx.sub(repl, code), n


def _t_concat_strings(code: str) -> tuple[str, int]:
    """Collapse ``'a' + 'b'`` into ``'ab'`` (string splitting is very common)."""
    n = 0
    rx = re.compile(
        r"(?P<a>(?P<qa>[\"'])(?:\\.|(?!(?P=qa))[^\\])*(?P=qa))\s*\+\s*"
        r"(?P<b>(?P<qb>[\"'])(?:\\.|(?!(?P=qb))[^\\])*(?P=qb))",
        re.DOTALL,
    )
    # Repeat locally so a+b+c+d collapses fully in one transform call.
    while True:
        def repl(m: re.Match) -> str:
            nonlocal n
            n += 1
            return _as_js_literal(_lit_value(m.group("a")) + _lit_value(m.group("b")))

        new = rx.sub(repl, code)
        if new == code:
            break
        code = new
    return code, n


_EXEC = re.compile(
    r"(?:\bwindow\.|\bself\.|\bglobalThis\.|\bthis\.)?"
    r"(?:eval|execScript)\s*\(\s*(?P<str>(?P<q>[\"'])(?:\\.|(?!(?P=q))[^\\])*(?P=q))\s*\)\s*;?"
)
_FUNC = re.compile(
    r"\(?\s*(?:new\s+)?Function\s*\(\s*(?P<str>(?P<q>[\"'])(?:\\.|(?!(?P=q))[^\\])*(?P=q))\s*\)\s*\)?\s*\(\s*\)\s*;?"
)
_TIMER = re.compile(
    r"\b(?:setTimeout|setInterval)\s*\(\s*(?P<str>(?P<q>[\"'])(?:\\.|(?!(?P=q))[^\\])*(?P=q))\s*(?:,[^);]*)?\)\s*;?"
)
_DOCWRITE = re.compile(
    r"document\s*\.\s*write(?:ln)?\s*\(\s*(?P<str>(?P<q>[\"'])(?:\\.|(?!(?P=q))[^\\])*(?P=q))\s*\)\s*;?"
)


def _t_unwrap_exec(code: str) -> tuple[str, int]:
    """Replace ``eval('code')`` / ``Function('code')()`` / ``setTimeout('code')``
    / ``document.write('code')`` with the string value as code — unfolding one
    obfuscation layer. Only a *single string literal* argument is unwrapped
    (concatenation is collapsed first by ``_t_concat_strings``)."""
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        inner = _lit_value(m.group("str"))
        return "\n" + inner + "\n"

    for rx in (_EXEC, _FUNC, _TIMER, _DOCWRITE):
        code = rx.sub(repl, code)
    return code, n


_ARR_DECL = re.compile(
    r"\b(?:var|let|const)\s+(?P<name>_0x[0-9a-fA-F]+|[A-Za-z_$][\w$]*)\s*=\s*\[(?P<body>[^\[\]]*)\]\s*;"
)


def _t_inline_string_array(code: str) -> tuple[str, int]:
    """``var a = ['x','y']; ... a[0] ... a[1]`` -> inline the literals.

    De-indirects the string tables that obfuscator.io-style packers build, so
    URLs / commands become visible to the detector and the IOC scan."""
    n = 0
    for m in list(_ARR_DECL.finditer(code)):
        name, body = m.group("name"), m.group("body")
        items = [im.group(0) for im in _STR.finditer(body)]
        # Only when the array is purely string literals (commas + whitespace).
        stripped = _STR.sub("", body)
        if not items or re.search(r"[^\s,]", stripped):
            continue
        values = [_lit_value(it) for it in items]
        idx_rx = re.compile(r"\b" + re.escape(name) + r"\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]")

        def repl(im: re.Match) -> str:
            nonlocal n
            i = int(im.group(1), 0)
            if 0 <= i < len(values):
                n += 1
                return _as_js_literal(values[i])
            return im.group(0)

        code = idx_rx.sub(repl, code)
    return code, n


_VAR_DECL = re.compile(
    r"\b(?:var|let|const)\s+(?P<name>_0x[0-9a-fA-F]+|[A-Za-z_$][\w$]{0,60})\s*=\s*"
    r"(?P<str>(?P<q>[\"'])(?:\\.|(?!(?P=q))[^\\])*(?P=q))\s*;"
)


def _t_inline_exec_var(code: str) -> tuple[str, int]:
    """``var a = '..payload..'; eval(a)`` -> ``eval('..payload..')``.

    Only inlines a variable that is a plain string literal and is actually fed
    to a dynamic-exec / decoder sink, to keep the rewrite safe."""
    n = 0
    sinks = ("eval", "Function", "unescape", "decodeURIComponent", "setTimeout", "setInterval", "atob")
    for m in list(_VAR_DECL.finditer(code)):
        name, lit = m.group("name"), m.group("str")
        used_in_sink = re.search(
            r"\b(?:" + "|".join(sinks) + r")\s*\(\s*" + re.escape(name) + r"\s*[),]", code
        )
        if not used_in_sink:
            continue
        # Replace the bare identifier where it is the sole argument of a sink.
        def repl(im: re.Match) -> str:
            nonlocal n
            n += 1
            return im.group(1) + lit + im.group(2)

        pat = re.compile(
            r"(\b(?:" + "|".join(sinks) + r")\s*\(\s*)" + re.escape(name) + r"(\s*[),])"
        )
        code = pat.sub(repl, code)
    return code, n


# --- Dean Edwards packer ------------------------------------------------------

_PACKER = re.compile(
    r"\beval\(\s*function\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)\s*\{.*?\}\s*\((?P<args>.*)\)\s*\)\s*;?",
    re.DOTALL,
)

_DIGITS36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def _encode_token(c: int, base: int) -> str:
    """Reproduce the packer's token for index ``c`` at the given radix."""
    if base <= 36:
        if c == 0:
            return "0"
        out = ""
        while c > 0:
            out = _DIGITS36[c % base] + out
            c //= base
        return out
    # High-radix encoder used by the packer for base > 36.
    first = "" if c < base else _encode_token(c // base, base)
    r = c % base
    return first + (chr(r + 29) if r > 35 else _DIGITS36[r])


def _read_literal(s: str) -> tuple[str, str] | None:
    """Read a leading JS string literal; return (literal, rest)."""
    m = re.match(r"""(["'])(?:\\.|(?!\1)[^\\])*\1""", s, re.DOTALL)
    if not m:
        return None
    return m.group(0), s[m.end():]


def _unpack_dean_edwards(code: str) -> tuple[str, int]:
    n = 0
    while True:
        m = _PACKER.search(code)
        if not m:
            break
        unpacked = _dean_edwards_args(m.group("args"))
        if unpacked is None:
            break
        code = code[: m.start()] + "\n" + unpacked + "\n" + code[m.end():]
        n += 1
        if n > 8 or len(code) > _MAX_BYTES:
            break
    return code, n


def _dean_edwards_args(args: str) -> str | None:
    args = args.strip()
    read = _read_literal(args)
    if not read:
        return None
    payload_lit, rest = read
    mm = re.match(r"\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*", rest)
    if not mm:
        return None
    base, count = int(mm.group(1)), int(mm.group(2))
    rest = rest[mm.end():]
    keywords: list[str] = []
    if rest[:1] in ("'", '"'):
        read2 = _read_literal(rest)
        if not read2:
            return None
        keywords = _lit_value(read2[0]).split("|")
    elif rest[:1] == "[":
        end = rest.find("]")
        if end < 0:
            return None
        keywords = [_lit_value(it.group(0)) for it in _STR.finditer(rest[1:end])]
    else:
        return None
    if count <= 0 or count > 200_000:
        return None
    payload = _lit_value(payload_lit)
    mapping = {}
    for c in range(count):
        tok = _encode_token(c, base)
        kw = keywords[c] if c < len(keywords) else ""
        if kw:
            mapping[tok] = kw
    return re.sub(r"\b\w+\b", lambda t: mapping.get(t.group(0), t.group(0)), payload)


# --- scheme detection (decode delegated to the sandbox) -----------------------

def detect_schemes(code: str) -> list[str]:
    found: list[str] = []
    sample = code[:200_000]
    if _PACKER.search(sample):
        found.append("dean-edwards-packer")
    if re.search(r"[ﾟ・´｀ωДﾉ╰┻]{2,}", sample) and "ﾟ" in sample:
        found.append("aaencode")
    if re.search(r"\$\s*=\s*~\s*\[\s*\]\s*;\s*\$\s*=\s*\{\s*___\s*:", sample) or \
       re.search(r"\$\$\$\$|_\$\$|\$\$_", sample) and sample.count("$") > 80:
        found.append("jjencode")
    stripped = re.sub(r"\s+", "", sample)
    if len(stripped) > 60 and re.fullmatch(r"[\[\]()!+]+", stripped):
        found.append("jsfuck")
    return found


# --- driver -------------------------------------------------------------------

_TRANSFORMS: list[tuple[str, Callable[[str], tuple[str, int]]]] = [
    ("string-array-inline", _t_inline_string_array),
    ("exec-var-inline", _t_inline_exec_var),
    ("concat-strings", _t_concat_strings),
    ("decode-escapes", _t_decode_escapes),
    ("unescape/percent", _t_unescape_calls),
    ("fromCharCode", _t_fromcharcode),
    ("atob/base64", _t_atob),
    ("unwrap-eval/Function/write", _t_unwrap_exec),
]


def deobfuscate(code: str, *, max_passes: int = _MAX_PASSES,
                max_bytes: int = _MAX_BYTES) -> dict[str, Any]:
    """Best-effort static deobfuscation.

    Returns ``{changed, code, layers, methods, schemes}`` where ``code`` is the
    best deobfuscated artifact (equal to the input when nothing fired),
    ``layers`` is the ordered list of ``{method, count}`` applied, ``methods``
    the unique method names, and ``schemes`` any recognised packer family.
    """
    original = code or ""
    cur = original
    layers: list[dict[str, Any]] = []
    methods: list[str] = []
    schemes = detect_schemes(cur)
    # A large input is still processed; the cap only stops runaway *growth*.
    cap = max(max_bytes, len(original) + 1)

    def record(method: str, count: int) -> None:
        if count:
            layers.append({"method": method, "count": count})
            if method not in methods:
                methods.append(method)

    for _ in range(max_passes):
        if len(cur) > cap:
            break
        before = cur
        new, cnt = _unpack_dean_edwards(cur)
        if cnt:
            cur = new
            record("packer:dean-edwards", cnt)
        for name, fn in _TRANSFORMS:
            if len(cur) > cap:
                break
            try:
                new, cnt = fn(cur)
            except Exception:  # noqa: BLE001  (never let a rewrite break analysis)
                continue
            if cnt and new != cur:
                cur = new
                record(name, cnt)
        if cur == before:
            break

    changed = cur.strip() != original.strip()
    return {"changed": changed, "code": cur, "layers": layers,
            "methods": methods, "schemes": schemes}
