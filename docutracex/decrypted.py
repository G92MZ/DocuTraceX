"""Decrypted payloads become nested children.

When an analyzer *resolves* a hidden stage — the JS sandbox logs what a custom
XOR routine returned or flags a dropped payload, a script carries a base64 blob
that is really a PE/ZIP/PDF — that stage is not just shown: it is written to
``extracted/stages/`` with an extension guessed from its content and handed
to the nested scanner, which routes it to the right analyzer (JavaScript,
PowerShell, VBScript, batch, Python, PE, Office, PDF, archive…). The nested
scanner does the same on every child, so a stage that decrypts the next one is
followed until the final behaviour (bounded by the nested depth limit).

Beyond resolved stages, **every encoded literal** in the recovered code (the
original and the deobfuscated source, read whole from the code dumps) is
decoded and re-analysed too: base64 and hex blobs, gzip/zlib inside them. What
comes out is a nested child whatever it is — a file (by magic), a script or
plain text (IOCs), or an opaque binary blob (encrypted/compressed data: hashes,
entropy, YARA) — unless it is already inlined in the code that was analysed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import zlib
from pathlib import Path
from typing import Any

DIRNAME = "stages"   # not "decrypted": that is where unlock puts decrypted originals
MAX_PAYLOADS = 32
PER_SCRIPT = 10        # encoded literals decoded per script
MIN_BLOB = 256        # an opaque binary blob smaller than this is not worth a child
MIN_TEXT = 24
MAX_BYTES = 8 * 1024 * 1024

_B64 = re.compile(r"""["']([A-Za-z0-9+/\r\n]{200,}={0,2})["']""")
# any quoted base64 / hex literal worth decoding (shorter, but strict alphabet)
_B64_LIT = re.compile(r"""(?:["']|-e(?:nc|ncodedcommand)?\s+)(={0,2}[A-Za-z0-9+/]{100,}={0,2})(?:["']|\s|$)""")
_HEX_LIT = re.compile(r"""["'](?:0x)?((?:[0-9A-Fa-f]{2}){48,})["']""")   # AutoIt binary strings: "0x4D5A…"
# PowerShell here-strings (@'…'@ / @"…"@) holding hex split over lines: a payload
# when long, key material when short (``$k = @'<32 hex bytes>'@`` + a -bxor loop)
_HERE = re.compile(r"""@(['"])[ \t]*\r?\n(.*?)\r?\n\1@""", re.S)


def _here_hex(code: str) -> list[bytes]:
    out = []
    for m in _HERE.finditer(code or ""):
        body = re.sub(r"\s+", "", m.group(2))
        if len(body) >= 8 and len(body) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", body):
            out.append(bytes.fromhex(body))
    return out
_MAGIC = ((b"MZ", ".exe"), (b"PK\x03\x04", ".zip"), (b"%PDF", ".pdf"),
          (b"\xd0\xcf\x11\xe0", ".doc"), (b"{\\rt", ".rtf"), (b"\x4c\x00\x00\x00", ".lnk"))

# Content sniffing for decrypted *text* (first hit wins).
_LANG = (
    (".ps1", re.compile(r"(?im)^\s*(?:powershell|pwsh)(?:\.exe)?\b|\b(?:iex|invoke-expression|new-object\s+net\.webclient|"
                        r"downloadstring|start-process|set-executionpolicy|start-sleep|write-(?:host|output|warning|error))\b|"
                        r"\[(?:system\.)?convert\]::frombase64string\b|\[cmdletbinding\(|"
                        r"\[(?:system\.)?reflection\.assembly\]::load|\s-bxor\s|\$env:\w+")),
    (".hta", re.compile(r"(?i)<\s*hta:application|<\s*script[^>]+(?:vbscript|jscript)")),
    (".html", re.compile(r"(?i)<\s*(?:html|script|body|iframe)\b")),
    (".xml", re.compile(r"(?s)^\s*<(?:\?xml|[A-Za-z][\w:.-]*)[^<>]*>.*</[A-Za-z][\w:.-]*>\s*$")),
    (".ini", re.compile(r"(?m)\A\s*\[[\w .:-]{1,60}\]\s*$(?:\r?\n(?:\s*[;#].*|\s*[\w.-]+\s*=.*|\s*))+\Z")),
    (".vbs", re.compile(r"(?im)^\s*dim\s+\w+|^\s*set\s+\w+\s*=\s*(?:createobject|getobject|new\b|nothing\b|\w+\.)|\bcreateobject\s*\(|^\s*(?:sub|function)\s+\w+\s*\(.*\)\s*$|\bend\s+(?:sub|function)\b")),
    (".js", re.compile(r"\bnew\s+ActiveXObject\s*\(|\bWScript\.\w+\s*\(|\bfunction\s*\w*\s*\([^)]*\)\s*\{|\bvar\s+\w+\s*=|=>|\beval\s*\(")),
    (".bat", re.compile(r"(?im)^\s*@?echo\s+off|^\s*set\s+\w+=|\bcmd(?:\.exe)?\s+/[ck]\b|%\w+%|^\s*(?:start|call)\s+")),
    (".py", re.compile(r"(?m)^\s*(?:import\s+\w+|from\s+\w+\s+import\s+|def\s+\w+\(.*\):)")),
)


def sniff_ext(text: str) -> str:
    for ext, rx in _LANG:
        if rx.search(text):
            return ext
    return ".txt"


def _ole_kind(raw: bytes) -> str:
    """An OLE/CFB blob: .msi when it holds Windows Installer's tables, else .doc."""
    import tempfile
    try:
        from .parsers.msi import is_msi_file
        with tempfile.TemporaryDirectory(prefix="dtx_ole_") as t:
            p = Path(t) / "blob.cfb"
            p.write_bytes(raw)
            return ".msi" if is_msi_file(p) else ".doc"
    except Exception:  # noqa: BLE001
        return ".doc"


def _magic_ext(raw: bytes) -> str | None:
    for magic, ext in _MAGIC:
        if raw.startswith(magic):
            return _ole_kind(raw) if ext == ".doc" else ext
    return None


def _text_of(raw: bytes) -> str | None:
    """Readable text (UTF-16LE or 8-bit) from decoded bytes, else None."""
    if len(raw) > 3 and raw[1:9:2] == b"\0" * len(raw[1:9:2]):
        encs = ("utf-16-le", "utf-8", "latin-1")
    else:
        encs = ("utf-8", "latin-1")
    for enc in encs:
        try:
            t = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        ok = sum(1 for c in t if (" " <= c <= "~") or c in "\r\n\t")
        if t and ok >= len(t) * 0.85:
            return t
    return None


def _inflate(raw: bytes) -> bytes | None:
    """gzip / zlib / raw-deflate content -> its decompressed bytes (bounded)."""
    for wbits in ((31,) if raw[:2] == b"\x1f\x8b" else (15, -15) if raw[:1] == b"\x78" else ()):
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(raw, MAX_BYTES)
            if out:
                return out
        except zlib.error:
            continue
    return None


_NUM = r"(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})"
_ARR = re.compile(r"(?:@\(|\[|\(|Array\()\s*(" + _NUM + r"(?:\s*,\s*" + _NUM + r"){0,63})\s*[\])]")
_STR = re.compile(r"""["']([^"'\r\n]{4,64})["']""")


def harvest_keys(code: str) -> dict[str, list[bytes]]:
    """Candidate key material written in a script: byte arrays (1–64 bytes)
    and short string literals. Used to try to decrypt opaque blobs."""
    arrays: list[bytes] = []
    for m in _ARR.finditer(code or ""):
        try:
            vals = [int(x, 16) if x.lower().startswith("0x") else int(x, 10)
                    for x in re.split(r"\s*,\s*", m.group(1))]
        except ValueError:
            continue
        if all(0 <= v <= 255 for v in vals) and 1 <= len(vals) <= 64:
            b = bytes(vals)
            if b not in arrays:
                arrays.append(b)
    strings: list[bytes] = []
    for m in _STR.finditer(code or ""):
        t = m.group(1)
        if len(set(t)) < 3 or " " in t.strip() and len(t) > 40:
            continue
        for b in (t.encode("latin-1", "replace"), t.encode("utf-16-le")):
            if b not in strings:
                strings.append(b)
    for b in _here_hex(code):
        if 2 <= len(b) <= 64 and b not in arrays:
            arrays.append(b)
    return {"arrays": arrays[:40], "strings": strings[:60]}


def _strong_magic(raw: bytes) -> bool:
    """A file signature that random bytes practically never produce (2-byte
    magics like MZ alone would, ~1/65536 per key tried)."""
    if raw[:2] == b"MZ":
        if b"This program" in raw[:512]:
            return True
        if len(raw) >= 0x40:
            off = int.from_bytes(raw[0x3C:0x40], "little")
            return 0 < off < len(raw) - 4 and raw[off:off + 4] == b"PE\0\0"
        return False
    return (raw[:4] in (b"PK\x03\x04", b"\xd0\xcf\x11\xe0") or raw[:5] == b"%PDF-" or raw[:5] == b"{\\rtf"
            or raw[:3] == b"\x1f\x8b\x08" or raw[:20] == b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46")


def _good(raw: bytes) -> bool:
    """Does a decryption attempt look right? A strong file signature, or text."""
    if not raw:
        return False
    if _strong_magic(raw):
        return True
    t = _text_of(raw[:4096])
    return t is not None and len(t.strip()) >= MIN_TEXT


def _b64_of_file(text: bytes) -> bool:
    """Base64 text whose first bytes decode to a file signature (a PE, a zip…)."""
    head = re.sub(rb"\s+", b"", text[:2048])
    if len(head) < 64 or not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", head[:1024]):
        return False
    try:
        raw = base64.b64decode(head[:1024 - 1024 % 4])
    except (binascii.Error, ValueError):
        return False
    return _strong_magic(raw) or _magic_ext(raw) is not None or raw[:3] == b"\x1f\x8b\x08"


def _xor(data: bytes, key: bytes) -> bytes:
    if len(key) == 1:
        k = key[0]
        return bytes(b ^ k for b in data)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _unpad(b: bytes) -> bytes | None:
    n = b[-1] if b else 0
    if 1 <= n <= 16 and b.endswith(bytes([n]) * n):
        return b[:-n]
    return None


def try_keys(raw: bytes, keys: dict[str, list[bytes]] | None) -> tuple[bytes, list[str]] | None:
    """Try to decrypt an opaque blob with single-byte XOR and the key material
    the script itself defines (repeating XOR, AES-CBC/ECB). Returns
    (plaintext, recipe steps) for the first attempt that looks right."""
    head = raw[:256]
    # 1) single-byte XOR (very common for embedded PEs): a file signature wins at once;
    # mere text is only a fallback (base64 XOR-ed with a printable byte stays printable)
    text_byte = None
    for k in range(1, 256):
        h = _xor(head, bytes([k]))
        if _strong_magic(h):
            return _xor(raw, bytes([k])), [f"xor(0x{k:02x})"]
        if text_byte is None and _good(h) and _good(_xor(raw[:4096], bytes([k]))):
            text_byte = k
    keys = keys or {}
    material = list(keys.get("arrays") or []) + list(keys.get("strings") or [])
    # 2) repeating-key XOR with the script's arrays / strings. XOR of base64 text with
    # any printable key is printable too, so a wrong key can look like "text": rank
    # the keys — a file signature, then base64 that decodes to one, then text.
    best: tuple[int, bytes] | None = None
    for key in material:
        if len(key) < 2:
            continue
        out = _xor(raw[:4096], key)
        score = 0
        if _strong_magic(out):
            score = 3
        elif _b64_of_file(out):
            score = 2
        elif _good(out[:256]):
            score = 1
        if score and (best is None or score > best[0]):
            best = (score, key)
            if score == 3:
                break
    if best and (best[0] >= 2 or text_byte is None):
        key = best[1]
        return _xor(raw, key), [f"xor(key {key[:16].hex()}{'…' if len(key) > 16 else ''})"]
    if text_byte is not None:
        return _xor(raw, bytes([text_byte])), [f"xor(0x{text_byte:02x})"]
    if best:
        key = best[1]
        return _xor(raw, key), [f"xor(key {key[:16].hex()}{'…' if len(key) > 16 else ''})"]
    # 3) AES with the script's 16/24/32-byte keys, IVs = its 16-byte arrays or the blob's first block
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:  # noqa: BLE001
        return None
    aes_keys = [k for k in material if len(k) in (16, 24, 32)]
    ivs = [k for k in material if len(k) == 16]
    if len(raw) < 32 or len(raw) % 16:
        aes_keys = aes_keys if len(raw) % 16 == 0 or len(raw) > 16 else []
    for key in aes_keys[:20]:
        trials = [("cbc", iv, raw) for iv in ivs[:12]] + [("cbc-ivprefix", raw[:16], raw[16:]), ("ecb", None, raw)]
        for mode, iv, body in trials:
            if len(body) < 16 or len(body) % 16:
                continue
            try:
                c = Cipher(algorithms.AES(key), modes.CBC(iv) if iv is not None else modes.ECB())
                first = c.decryptor().update(body[:512])
                if not _accept(first):
                    continue
                full = c.decryptor().update(body)
            except Exception:  # noqa: BLE001
                continue
            plain = _unpad(full) or full
            if _accept(plain):
                step = f"aes-{len(key) * 8}-{mode.split('-')[0]}(key {key[:8].hex()}…" + (f", iv {iv[:4].hex()}…)" if iv is not None else ")")
                return plain, [step]
    return _blind_ciphers(raw, keys)


# --- T16: blind trials with what the script carries ------------------------------------------------
BLIND_BUDGET = 600            # cipher trials per blob (each on its first 512 bytes)


def _accept(raw: bytes) -> bool:
    """A decryption that looks right: a file, text, or compressed data that inflates."""
    if _good(raw):
        return True
    if raw[:3] == b"\x1f\x8b\x08" or raw[:2] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e"):
        try:
            d = zlib.decompressobj(31 if raw[:2] == b"\x1f\x8b" else 15)
            out = d.decompress(raw, 512)
        except zlib.error:
            return False
        return bool(out) and (_good(out) or _strong_magic(out) or out[:2] == b"MZ")
    return False


def _blind_keys(keys: dict[str, list[bytes]]) -> list[tuple[bytes, str]]:
    """The script's key material and what loaders derive from it (MD5 / SHA-1 / SHA-256 of a password)."""
    out: list[tuple[bytes, str]] = []
    seen: set[bytes] = set()

    def add(k: bytes, label: str) -> None:
        if k and k not in seen:
            seen.add(k)
            out.append((k, label))
    for a in keys.get("arrays") or []:
        add(a, f"key {a[:8].hex()}{'…' if len(a) > 8 else ''}")
    strs = [s for s in keys.get("strings") or [] if b"\x00" not in s][:30]
    for s in strs:
        shown = s[:32].decode("latin-1") + ("…" if len(s) > 32 else "")
        add(s, f"key '{shown}'")
        add(hashlib.md5(s).digest(), f"key md5('{shown}')")  # noqa: S324  (what loaders derive)
        add(hashlib.sha256(s).digest(), f"key sha256('{shown}')")
        add(hashlib.sha1(s).digest()[:16], f"key sha1('{shown}')[:16]")  # noqa: S324
    return out


def _blind_ciphers(raw: bytes, keys: dict[str, list[bytes]] | None) -> tuple[bytes, list[str]] | None:
    """RC4, AES and 3DES with the script's keys and their hashes (IV: zero, the blob's first block,
    the script's arrays); a trial counts when its first bytes are a file, text or compressed data."""
    if not keys or len(raw) < 32:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:                       # older cryptography
            TripleDES = algorithms.TripleDES  # noqa: N806
        from .resolve.transforms import rc4 as _rc4
    except Exception:  # noqa: BLE001
        return None
    cands = _blind_keys(keys)
    ivs16 = [(b"\x00" * 16, "iv zero")] + [(k, f"iv {k[:4].hex()}…") for k in keys.get("arrays") or [] if len(k) == 16][:4]
    ivs8 = [(b"\x00" * 8, "iv zero")] + [(k, f"iv {k.hex()}") for k in keys.get("arrays") or [] if len(k) == 8][:4]
    budget = BLIND_BUDGET
    head = raw[:512]

    def done(plain: bytes, step: str) -> tuple[bytes, list[str]] | None:
        plain = _unpad(plain) or plain
        return (plain, [step]) if _accept(plain) else None
    # RC4: any key length 5–256
    for k, label in cands:
        if budget <= 0:
            return None
        if not 5 <= len(k) <= 256:
            continue
        budget -= 1
        try:
            if not _accept(_rc4(head, k)):
                continue
            got = done(_rc4(raw, k), f"rc4({label})")
        except Exception:  # noqa: BLE001
            continue
        if got:
            return got
    # AES (16 / 24 / 32-byte keys) and 3DES (16 / 24): ECB, CBC with each IV, CBC with the IV in front
    for k, label in cands:
        if budget <= 0:
            return None
        if len(k) in (16, 24, 32):
            algos = [("aes", algorithms.AES, 16, ivs16)]
        else:
            algos = []
        if len(k) in (16, 24):
            algos.append(("3des", TripleDES, 8, ivs8))
        for name, algo, block, ivs in algos:
            trials = [("ecb", None, raw, "")] + [("cbc", iv, raw, lab) for iv, lab in ivs] + \
                     [("cbc", raw[:block], raw[block:], "iv in front")]
            for mode, iv, body, ivlab in trials:
                if budget <= 0:
                    return None
                if len(body) < block or len(body) % block:
                    continue
                budget -= 1
                try:
                    c = Cipher(algo(k), modes.ECB() if iv is None else modes.CBC(iv))
                    if not _accept(c.decryptor().update(body[:512])):
                        continue
                    bits = f"-{len(k) * 8}" if name == "aes" else ""
                    got = done(c.decryptor().update(body) , f"{name}{bits}-{mode}({label}{', ' + ivlab if ivlab else ''})")
                except Exception:  # noqa: BLE001
                    continue
                if got:
                    return got
    return None


def classify(raw: bytes, how: str, origin: str, depth: int = 0,
             keys: dict[str, list[bytes]] | None = None,
             recipe: list[str] | None = None) -> dict[str, Any] | None:
    """A decoded byte string as a payload: file by magic, (inflated) content,
    text, an opaque blob decrypted with the script's own keys, or an opaque
    blob; None when it is too small to be worth a child. ``recipe`` records the
    transformations that led here (shown on the nested child)."""
    recipe = list(recipe or [])
    if not raw or len(raw) > MAX_BYTES:
        return None
    ext = _magic_ext(raw)
    if ext:
        return {"how": how, "ext": ext, "data": raw, "origin": f"{origin} → {ext[1:].upper()}",
                "recipe": recipe + [ext[1:]]}
    inner = _inflate(raw) if depth < 3 else None
    if inner:
        step = "gzip" if raw[:2] == b"\x1f\x8b" else "zlib"
        return classify(inner, how + "-inflated", f"{origin} → decompressed", depth + 1, keys, recipe + [step])
    text = _text_of(raw)
    if text is not None:
        if len(text.strip()) < MIN_TEXT:
            return None
        if depth < 3 and _b64_of_file(raw):     # a decrypted layer that is base64 of a file
            try:
                dec = base64.b64decode(re.sub(rb"\s+", b"", raw) + b"===")
            except (binascii.Error, ValueError):
                dec = b""
            if dec:
                res = classify(dec, how + "-base64", f"{origin} → base64", depth + 1, keys, recipe + ["base64"])
                if res:
                    return res
        return {"how": how, "text": text, "origin": f"{origin} → text", "recipe": recipe + ["text"]}
    # key trials from 32 bytes (a small encrypted config is still worth it);
    # data full of NUL bytes is not ciphertext (UTF-16 text, structures)
    if depth < 3 and len(raw) >= 32 and raw.count(0) <= len(raw) * 0.1:
        got = try_keys(raw, keys)
        if got:
            plain, steps = got
            res = classify(plain, how + "-decrypted", f"{origin} → decrypted with {steps[0]}", depth + 1,
                           keys, recipe + steps)
            if res:
                return res
    if len(raw) < MIN_BLOB:
        return None
    return {"how": how + "-blob", "ext": ".bin", "data": raw,
            "origin": f"{origin} → opaque binary ({len(raw)} bytes, likely encrypted/compressed)",
            "recipe": recipe + ["opaque"]}


def _read(root: Path | None, rel: Any) -> str:
    if root and rel:
        try:
            return (root / str(rel)).read_text("utf-8", "replace")
        except OSError:
            return ""
    return ""


def _sources(sc: dict[str, Any], root: Path | None) -> tuple[str, str]:
    """(code as analysed, original code): the analysed code is the
    DEOBFUSCATED version when there is one, else the original — read from the
    code dumps when available (stored previews are cut at 60 KB)."""
    orig = _read(root, sc.get("code_file")) or sc.get("_full_code") or sc.get("original_code") or ""
    if sc.get("code_is_deobfuscated"):
        # a stored preview cut short is no source: a literal running past the cut would be
        # decoded half (a PE cut at 400,000 characters carves into "ghost" PEs)
        deob = (_read(root, sc.get("code_file_deob")) or sc.get("_full_deob")
                or ("" if sc.get("code_truncated") else sc.get("code")) or "")
        return deob or orig, orig
    return orig or sc.get("code") or "", ""


def _full_source(sc: dict[str, Any], root: Path | None) -> str:
    """The script's whole code as it was analysed: the DEOBFUSCATED version
    when there is one (a literal the deobfuscator already decoded or decrypted
    is gone from it, so it is not decoded twice), else the original — read
    from the code dumps when available (stored previews are cut at 60 KB)."""
    if sc.get("code_is_deobfuscated"):
        deob = _read(root, sc.get("code_file_deob")) or sc.get("_full_deob") or ""
        if deob:
            return deob
    return (_read(root, sc.get("code_file")) or sc.get("_full_code")
            or ("" if sc.get("code_truncated") else sc.get("code")) or "")


def _already_in(text: str, analysed: str) -> bool:
    """Decoded text already present in the analysed code — judged by its first
    lines, since the analysed copy may have been decoded further in place."""
    lines = [ln.strip() for ln in text.replace("\r", "").splitlines() if ln.strip()][:6]
    if not lines:
        return True
    return sum(1 for ln in lines if ln in analysed) * 2 >= len(lines)


# Shellcode written as numbers — the "payload generator" formats of Cobalt
# Strike / Metasploit / msfvenom: C / Python ``"\\xfc\\xe8…"``, C# / PowerShell
# ``0xfc,0xe8,…``, VBA ``Array(-4,-24,…)`` (signed, with ``_`` continuations).
_ESC_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_HEX_LIST = re.compile(r"(?:0x[0-9A-Fa-f]{1,2}\s*,\s*(?:_?\s*\r?\n\s*)?){31,}0x[0-9A-Fa-f]{1,2}")
_DEC_LIST = re.compile(r"(?:-?\d{1,3}\s*,\s*(?:_\s*\r?\n\s*)?){63,}-?\d{1,3}")
_ESC_GLUE = 24          # quotes / concatenation between two "\x.." runs of one array


def _pe_after_stub(raw: bytes) -> int:
    """Offset of a PE that a short shellcode stub precedes (sRDI / Donut-style: ``jmp`` or ``call``
    over a few bytes, then MZ), or 0."""
    if len(raw) < 0x200 or raw[:2] == b"MZ" or raw[0] not in (0xE9, 0xE8, 0xEB, 0x4D, 0x90, 0x55, 0x56, 0x48):
        return 0
    i = raw.find(b"MZ", 1, 0x100)
    while 0 < i < 0x100:
        off = int.from_bytes(raw[i + 0x3C:i + 0x40], "little")
        if 0x40 <= off < 0x400 and raw[i + off:i + off + 4] == b"PE\0\0":
            return i
        i = raw.find(b"MZ", i + 1, 0x100)
    return 0


MAX_CARVED_PES = 8
PADDING_MIN = 64 * 1024     # bytes after a PE's last section that count as padding (T1027.001)


def pe_extent(raw: bytes, at: int = 0) -> int:
    """Size on disk of the PE starting at ``at`` (headers, sections, Authenticode
    blob), from its headers alone; 0 when the headers do not hold together."""
    try:
        e = at + int.from_bytes(raw[at + 0x3C:at + 0x40], "little")
        if raw[e:e + 4] != b"PE\0\0":
            return 0
        nsec = int.from_bytes(raw[e + 6:e + 8], "little")
        optsz = int.from_bytes(raw[e + 20:e + 22], "little")
        if not 0 < nsec <= 96 or optsz > 0x400:
            return 0
        opt, sec = e + 24, e + 24 + optsz
        end = sec + 40 * nsec - at
        for i in range(nsec):
            h = sec + 40 * i
            size = int.from_bytes(raw[h + 16:h + 20], "little")
            ptr = int.from_bytes(raw[h + 20:h + 24], "little")
            if size and ptr:
                end = max(end, ptr + size)
        magic = int.from_bytes(raw[opt:opt + 2], "little")
        dd = opt + (96 if magic == 0x10B else 112 if magic == 0x20B else 0)
        if dd > opt and dd + 40 <= sec:                      # entry 4: the certificate table (file offset)
            cptr = int.from_bytes(raw[dd + 32:dd + 36], "little")
            csz = int.from_bytes(raw[dd + 36:dd + 40], "little")
            if cptr and csz and cptr + csz <= len(raw) - at + 0x1000:
                end = max(end, cptr + csz)
        avail = len(raw) - at
        if end > avail and end - avail <= max(0x10000, end // 20):
            end = avail                                      # a few KB short: kept, cut where the bytes end
        return end if 0 < end <= avail else 0
    except (IndexError, ValueError):
        return 0


def _pe_layout(raw: bytes, at: int = 0) -> dict[str, Any] | None:
    """Headers of the PE at ``at``: sections, SizeOfHeaders / SizeOfImage, import RVA."""
    import struct
    try:
        e = at + struct.unpack_from("<I", raw, at + 0x3C)[0]
        nsec, = struct.unpack_from("<H", raw, e + 6)
        optsz, = struct.unpack_from("<H", raw, e + 20)
        opt = e + 24
        magic, = struct.unpack_from("<H", raw, opt)
        dd = opt + (96 if magic == 0x10B else 112)
        secs = [struct.unpack_from("<IIII", raw, e + 24 + optsz + 40 * i + 8)    # VirtualSize, VA, SizeOfRawData, Ptr
                for i in range(min(nsec, 96))]
        return {"secs": secs, "headers": struct.unpack_from("<I", raw, opt + 60)[0],
                "image": struct.unpack_from("<I", raw, opt + 56)[0],
                "imports": struct.unpack_from("<I", raw, dd + 8)[0] if dd + 12 <= opt + optsz else 0}
    except struct.error:
        return None


def _dll_name_at(raw: bytes, at: int, lay: dict[str, Any], mapped: bool) -> bool:
    """The first import descriptor's DLL name reads as one, with RVAs taken as file
    offsets (``mapped``) or converted through the section table."""
    import struct

    def off(rva: int) -> int | None:
        if mapped:
            return at + rva
        for vsz, va, rsz, ptr in lay["secs"]:
            if va <= rva < va + max(vsz, rsz):
                return at + rva - va + ptr
        return None
    try:
        o = off(lay["imports"])
        if o is None:
            return False
        o2 = off(struct.unpack_from("<I", raw, o + 12)[0])
        if o2 is None:
            return False
        name = raw[o2:o2 + 64].split(b"\0", 1)[0]
        return bool(re.fullmatch(rb"[A-Za-z0-9_.\-]{1,60}\.(?:dll|DLL|drv|sys|exe)", name))
    except struct.error:
        return False


def is_mapped_pe(raw: bytes, at: int = 0) -> bool:
    """A PE stored as it lies in memory (each section at its RVA, as a loader mapped it
    or a dump left it), not as a file: its imports only make sense with RVAs as offsets."""
    lay = _pe_layout(raw, at)
    if not lay or not lay["imports"] or not lay["secs"]:
        return False
    if any(va != ptr for _v, va, _r, ptr in lay["secs"] if ptr):
        return _dll_name_at(raw, at, lay, True) and not _dll_name_at(raw, at, lay, False)
    return False


def unmap_pe(raw: bytes, at: int = 0) -> bytes:
    """The file form of a PE kept in memory layout: headers, then each section copied
    from its RVA to its PointerToRawData (what pefile, LIEF and debloat expect)."""
    lay = _pe_layout(raw, at)
    if not lay:
        return raw[at:]
    end = max((ptr + rsz for _v, _va, rsz, ptr in lay["secs"]), default=0)
    out = bytearray(max(end, lay["headers"]))
    out[:lay["headers"]] = raw[at:at + lay["headers"]]
    for _vsz, va, rsz, ptr in lay["secs"]:
        if rsz and ptr:
            chunk = raw[at + va:at + va + rsz]
            out[ptr:ptr + len(chunk)] = chunk
    return bytes(out)


def _valid_mz(raw: bytes, i: int) -> bool:
    off = int.from_bytes(raw[i + 0x3C:i + 0x40], "little")
    return 0x40 <= off < 0x400 and raw[i + off:i + off + 4] == b"PE\0\0"


def carve_pes(raw: bytes, start: int = 0, inner: bool = False) -> list[tuple[int, int]]:
    """(offset, size) of the PEs lying one after another in ``raw`` from ``start``
    (a loader DLL and the program it maps, behind a shellcode stub). MZ headers
    inside a PE already carved (its resources, overlay) are not separate PEs —
    unless ``inner``: a reflective loader packed as shellcode often carries the
    program inside its own sections, and that program is the payload."""
    out: list[tuple[int, int]] = []
    i = start
    while len(out) < MAX_CARVED_PES:
        i = raw.find(b"MZ", i)
        if i < 0:
            break
        if not _valid_mz(raw, i):
            i += 2
            continue
        size = pe_extent(raw, i)
        out.append((i, size))
        i += 0x40 if inner else max(size, 0x40)
    return out


def _padding(tail: bytes) -> str:
    """What fills the bytes after a PE: zeros, one repeated pattern, or text."""
    sample = tail[:1 << 20]
    if not sample.strip(b"\0"):
        return "zeros"
    if len(set(sample[i:i + 16] for i in range(0, min(len(sample), 1 << 16), 16))) <= 4:
        return "a repeated pattern"
    printable = sum(1 for b in sample[:65536] if 32 <= b < 127 or b in (9, 10, 13))
    return "text (word lists, CSS, script)" if printable >= min(len(sample), 65536) * 0.9 else "junk bytes"


def payload_children(raw: bytes, how: str, origin: str, keys: dict[str, list[bytes]] | None = None,
                     recipe: list[str] | None = None) -> list[dict[str, Any]]:
    """``payload_child``, but every PE behind a shellcode stub (or one after another
    in the bytes) becomes its own child, cut to its real size: the padding behind it
    (word lists, CSS, zeros) is left out and named in the recipe."""
    pe_at = _pe_after_stub(raw)
    if not pe_at and not (raw[:2] == b"MZ" and _valid_mz(raw, 0)):
        p = payload_child(raw, how, origin, keys=keys, recipe=recipe)
        return [p] if p else []
    pes = carve_pes(raw, pe_at, inner=bool(pe_at))
    out = []
    for k, (at, size) in enumerate(pes):
        # the next PE that starts after this one ends (an inner PE does not cut its host)
        nxt = next((a for a, _s in pes[k + 1:] if a >= at + size), len(raw)) if size else \
            (pes[k + 1][0] if k + 1 < len(pes) else len(raw))
        end = at + size if size else nxt
        steps = list(recipe or []) + (["shellcode stub"] if pe_at else []) + [f"PE at +0x{at:x}"]
        note = ""
        pad = nxt - end
        if size and pad >= PADDING_MIN:
            kind = _padding(raw[end:nxt])
            steps.append(f"padding stripped ({pad} bytes of {kind})")
            note = f", {pad} bytes of padding ({kind}) after it left out"
        what = (f"shellcode stub + PE {k + 1}/{len(pes)}" if pe_at else f"PE {k + 1}/{len(pes)}") if len(pes) > 1 \
            else ("shellcode stub + PE" if pe_at else "PE")
        data = raw[at:end]
        if is_mapped_pe(raw, at):
            # kept as it lies in memory (a loader's mapped copy): back to its file form, from
            # SizeOfImage bytes, so its imports, resources and padding read as in any PE
            lay = _pe_layout(raw, at) or {}
            data = unmap_pe(raw[:at + max(lay.get("image") or 0, end - at)], at)
            steps.append("unmapped (memory layout → file)")
            note += ", stored in memory layout: rebuilt as a file"
        out.append({"how": how, "ext": _pe_ext(data), "data": data, "recipe": steps,
                    "origin": f"{origin} → {what} at offset 0x{at:x} ({len(data)} bytes{note})"})
    if not out:
        p = payload_child(raw, how, origin, keys=keys, recipe=recipe)
        return [p] if p else []
    return out


def _pe_ext(pe: bytes) -> str:
    try:
        e = int.from_bytes(pe[0x3C:0x40], "little")
        return ".dll" if int.from_bytes(pe[e + 22:e + 24], "little") & 0x2000 else ".exe"
    except (IndexError, ValueError):
        return ".exe"


def payload_child(raw: bytes, how: str, origin: str, keys: dict[str, list[bytes]] | None = None,
                  recipe: list[str] | None = None) -> dict[str, Any] | None:
    """``classify``, except that shellcode stays the exact bytes (never text)."""
    from .parsers.ps_deobf import _is_binary_payload
    pe_at = _pe_after_stub(raw)
    if pe_at:               # a reflective-loader stub (jmp over a few bytes) in front of a whole PE
        return {"how": how, "ext": ".exe", "data": raw[pe_at:],
                "recipe": list(recipe or []) + ["shellcode stub", f"PE at +0x{pe_at:x}"],
                "origin": f"{origin} → shellcode stub + PE at offset 0x{pe_at:x} ({len(raw) - pe_at} bytes)"}
    if _is_binary_payload(raw) and not _magic_ext(raw):
        return {"how": how, "ext": ".bin", "data": raw, "recipe": list(recipe or []) + ["shellcode"],
                "origin": f"{origin} → shellcode ({len(raw)} bytes)"}
    return classify(raw, how, origin, keys=keys, recipe=recipe)


def byte_arrays(code: str, binary_only: bool = False) -> list[tuple[str, bytes]]:
    """Byte strings written as numbers in source code. ``binary_only``: keep
    only what is a payload (shellcode / PE) — for code where number lists are
    common (VBA, JS char codes are decoded elsewhere)."""
    from .parsers.ps_deobf import _is_binary_payload
    out: list[tuple[str, bytes]] = []
    runs = list(_ESC_RUN.finditer(code))
    i = 0
    while i < len(runs):                       # "\xfc\xe8" "\x89…" glued across lines / concatenation
        start, end, j = runs[i].start(), runs[i].end(), i
        while j + 1 < len(runs) and runs[j + 1].start() - end <= _ESC_GLUE \
                and not re.search(r"[;{}]", code[end:runs[j + 1].start()]):
            j += 1
            end = runs[j].end()
        blob = bytes(int(h, 16) for h in re.findall(r"\\x([0-9A-Fa-f]{2})", code[start:end]))
        if len(blob) >= 32:
            out.append(("escaped bytes", blob))
        i = j + 1
    for m in _HEX_LIST.finditer(code):
        out.append(("hex array", bytes(int(h, 16) for h in re.findall(r"0x([0-9A-Fa-f]{1,2})", m.group(0)))))
    for m in _DEC_LIST.finditer(code):
        vals = [int(v) for v in re.findall(r"-?\d+", m.group(0))]
        if all(-128 <= v <= 255 for v in vals):
            out.append(("number array", bytes(v & 0xFF for v in vals)))
    if binary_only:
        out = [(k, b) for k, b in out if _is_binary_payload(b) or _magic_ext(b)]
    else:   # decimal lists are everywhere (tables, char codes): only as payloads
        out = [(k, b) for k, b in out if k != "number array" or _is_binary_payload(b) or _magic_ext(b)]
    return out


def python_bytes_literals(code: str, min_size: int = 512) -> list[bytes]:
    """Bytes literals of Python source as Python reads them (largest first); [] when
    the text does not parse as Python."""
    import ast
    if "b'" not in code and 'b"' not in code and "B'" not in code and 'B"' not in code:
        return []
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    found = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
             and isinstance(n.value, bytes) and len(n.value) >= min_size}
    return sorted(found, key=len, reverse=True)[:8]


def _decode_literals(code: str) -> list[tuple[str, bytes]]:
    found: list[tuple[str, bytes]] = byte_arrays(code)
    for m in _B64_LIT.finditer(code):
        lit = m.group(1)
        if len(set(lit)) < 16:                 # "AAAA…", padding runs: not data
            continue
        if lit.lower().startswith("76492d1116743f0423413b16050a5345"):
            continue                           # an exported SecureString (PowerShell decrypts it)
        try:
            dec = base64.b64decode(lit + "=" * (-len(lit) % 4)) if not lit.startswith("=") else b""
        except (binascii.Error, ValueError):
            dec = b""
        if not dec or not (_magic_ext(dec) or _inflate(dec) or _text_of(dec[:2048]) is not None):
            # written backwards (``'…=='[::-1]``, ``StrReverse``): read the other way
            try:
                back = base64.b64decode(lit[::-1].lstrip("=") + "=" * (-len(lit.lstrip("=")) % 4))
            except (binascii.Error, ValueError):
                back = b""
            if back and (_magic_ext(back) or _inflate(back) or _text_of(back[:2048]) is not None):
                found.append(("reversed base64", back))
                continue
        if dec:
            found.append(("base64", dec))
    for m in _HEX_LIT.finditer(code):
        try:
            found.append(("hex", bytes.fromhex(m.group(1))))
        except ValueError:
            continue
    found += [("hex here-string", b) for b in _here_hex(code) if len(b) >= 48]
    return found


def _scripty(text: str) -> bool:
    return len(text) >= MIN_TEXT and sniff_ext(text) != ".txt"


# Script extensions: a short file written with one of them is still code
# ("start x.exe" in a .bat) and is kept whatever its size.
_CODE_EXTS = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".py", ".sct", ".wsc"}


def worth_text_child(text: str, ext: str | None = None) -> bool:
    """A decoded / dropped TEXT stage deserves a nested child unless it is a
    few bytes of non-code (a marker file, "ok", a counter): those only clutter
    the tree. Code — by its extension or by its content — is always kept, and
    binary drops are judged by ``classify`` (magic / size) instead."""
    t = (text or "").strip()
    if not t:
        return False
    if len(t) >= MIN_TEXT or (ext or "").lower() in _CODE_EXTS:
        return True
    return sniff_ext(t) != ".txt"


def _same_text(a: str, b: str) -> bool:
    """The same stage seen twice (the JS sandbox runs the deobfuscated copy: quotes, escapes and
    line ends may differ)."""
    if abs(len(a) - len(b)) > max(16, len(a) // 50):
        return False
    norm = re.compile(r"[\s'\"`\\]+")
    return norm.sub("", a) == norm.sub("", b)


def payloads_from(mods: dict[str, Any], root: Path | None = None) -> list[dict[str, Any]]:
    """Resolved stages found in a set of module results.

    Each is ``{"how": short label, "origin": where it came from, "text"|"data"}``.
    """
    out: list[dict[str, Any]] = []

    js = mods.get("javascript") or {}
    for sc in js.get("scripts") or []:
        if not isinstance(sc, dict) or sc.get("from_nested"):
            continue
        loc = sc.get("location") or sc.get("origin") or "javascript"
        for e in (sc.get("sandbox") or {}).get("log") or []:
            arg = (e.get("args") or [""])[0] if isinstance(e, dict) else ""
            if e.get("kind") == "xor" and _scripty(arg):
                out.append({"how": f"js-xor-{e.get('name')}", "origin": f"JavaScript {loc}: XOR {e.get('name')}()",
                            "text": arg, "recipe": ["js sandbox", f"{e.get('name')}() (XOR)", "text"]})
            elif e.get("kind") == "fromcharcode" and len(arg) >= 80 and _scripty(arg):
                out.append({"how": "js-fromcharcode", "origin": f"JavaScript {loc}: String.fromCharCode", "text": arg})
        # files the script wrote (FileSystemObject / ADODB.Stream), with the
        # extension of the path it gave them
        for e in (sc.get("sandbox") or {}).get("log") or []:
            if isinstance(e, dict) and e.get("kind") == "drop_b64" and (e.get("args") or [""])[0]:
                # a binary file the script wrote (e.g. a PE decoded via MSXML bin.base64)
                name = str(e.get("name") or "")
                try:
                    data = base64.b64decode(e["args"][0])
                except (binascii.Error, ValueError):
                    continue
                p = classify(data, "js-drop", f"JavaScript {loc}: wrote {name}",
                             recipe=["js sandbox", f"wrote {name.rsplit(chr(92), 1)[-1]}"])
                if p:
                    if "data" in p and p.get("ext") == ".bin":
                        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name.rsplit("\\", 1)[-1] else ""
                        p["ext"] = ext if 1 < len(ext) <= 6 else ".bin"
                    out.append(p)
        for e in (sc.get("sandbox") or {}).get("log") or []:
            if isinstance(e, dict) and e.get("kind") == "drop" and (e.get("args") or [""])[0].strip():
                name = str(e.get("name") or "")
                ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name.rsplit("\\", 1)[-1] else ""
                if not worth_text_child(e["args"][0], ext):
                    continue                      # a marker / counter file, not a stage
                out.append({"how": "js-drop", "origin": f"JavaScript {loc}: wrote {name}",
                            "text": e["args"][0], "ext": ext if 1 < len(ext) <= 6 else None,
                            "recipe": ["js sandbox", f"wrote {name.rsplit(chr(92), 1)[-1]}"]})
        for t in sc.get("techniques") or []:
            if t.get("payload") and _scripty(t["payload"]):
                out.append({"how": "js-payload", "origin": f"JavaScript {loc}: {t.get('name')}", "text": t["payload"]})

    # Stages the language deobfuscators decoded in place (XOR/deflate/base64
    # layers, Execute'd strings, exec chains): each one is ALSO a nested child
    # with its recipe, analysed again on its own (its deeper layers come out
    # there, one level down).
    carved_raw: list[bytes] = []          # binary stages carved whole (shellcode, PE)
    for key, ext in (("powershell", ".ps1"), ("vbscript", ".vbs"), ("python", ".py"), ("batch", ".bat"),
                     ("javascript", ".js"), ("script", "")):
        for sc in (mods.get(key) or {}).get("scripts") or []:
            if not isinstance(sc, dict) or sc.get("from_nested"):
                continue
            loc = sc.get("location") or key
            for st in (sc.get("decoded_stages") or [])[:PER_SCRIPT]:
                text, recipe = st.get("text") or "", list(st.get("recipe") or [])
                if st.get("data_b64"):                       # a binary stage (shellcode, PE)
                    try:
                        raw = base64.b64decode(st["data_b64"])
                    except (ValueError, TypeError):
                        continue
                    carved_raw.append(raw)
                    out += payload_children(raw, f"{key}-stage", f"{key} {loc}: {' → '.join(recipe)}",
                                            recipe=recipe)
                    continue
                sext = st.get("ext", ext)           # "": by its content (decoded text that is not code)
                same = next((o for o in out if o.get("text") is not None and _same_text(o["text"], text)), None)
                if same is not None:
                    # the JS sandbox saw it run too: one child, with the static recipe (how it was built)
                    if not (recipe and str(recipe[0]).startswith("sandbox (")):
                        same["recipe"] = recipe
                    if sext and not same.get("ext"):
                        same["ext"] = sext
                    continue
                if worth_text_child(text, sext if len(text.strip()) >= 8 else None):
                    out.append({"how": f"{key}-stage", "origin": f"{key} {loc}: {' → '.join(recipe)}",
                                "text": text, "ext": sext or None, "recipe": recipe})

    # VBA macros carry shellcode as Array(-4, -24, …) / hex strings (Office
    # payloads of Cobalt Strike / Metasploit): each one becomes a binary child
    for mkey in ("oletools", "ole"):
        olevba = (((mods.get(mkey) or {}).get("tools") or {}).get("olevba") or {})
        code = olevba.get("_full_code") or "\n".join(m.get("code") or "" for m in olevba.get("modules") or [])
        for kind, raw in byte_arrays(code, binary_only=True)[:PER_SCRIPT] if code else []:
            out += payload_children(raw, f"vba-{kind}", f"VBA macro: {kind}", recipe=["vba", kind])

    # Every encoded literal in the recovered code (base64 / hex, gzip/zlib in
    # them) is decoded and becomes a child, whatever comes out — unless the
    # deobfuscator already inlined it in the code that was analysed.
    langs = ("javascript", "powershell", "vbscript", "batch", "python", "script")
    scripts = [(key, sc, *_sources(sc, root)) for key in langs
               for sc in (mods.get(key) or {}).get("scripts") or []
               # scripts surfaced from nested children are handled by that child
               if isinstance(sc, dict) and not sc.get("from_nested")]
    # what was analysed in ANY language here (e.g. the PowerShell tab already
    # decoded the -enc a VBScript launches): decoded text found in it is skipped
    analysed = "\n".join(src for _k, _sc, src, _o in scripts).replace("\r", "")
    for key, sc, src, orig in scripts:
        loc = sc.get("location") or key
        keys = harvest_keys(src + "\n" + orig)
        n = 0
        seen_lits: set[bytes] = set()
        # literals still encoded in the analysed code: every outcome is a child;
        # literals the deobfuscator already resolved (only in the original):
        # only when they turn out to be a FILE (e.g. HTML smuggling's PE),
        # since their text/decryption is already in the analysed code
        for resolved, code in ((False, src), (True, orig)):
            lits = _decode_literals(code)
            if key == "python":
                # whole bytes literals first (b'MZ\x90…text…' mixes escapes and plain
                # characters); the \x runs cut out of them are not payloads of their own
                whole = [("bytes literal", b) for b in python_bytes_literals(code)]
                lits = whole + [(k, b) for k, b in lits
                                if not (whole and k == "escaped bytes") and not any(b in w for _k, w in whole)]
            for kind, raw in lits:
                if n >= PER_SCRIPT or raw in seen_lits:
                    continue
                if carved_raw and (kind == "escaped bytes" and key == "python"
                                   or len(raw) < (1 << 20) and any(raw in big for big in carved_raw)):
                    continue                   # pieces of a payload already carved whole

                seen_lits.add(raw)
                for p in payload_children(raw, f"{key}-{kind}", f"{key} {loc}: {kind} literal",
                                          keys=keys, recipe=[kind]):
                    if resolved and not (p.get("ext") and p["ext"] != ".bin"):
                        continue
                    if "text" in p and _already_in(p["text"], analysed):
                        continue           # already decoded in place and analysed
                    out.append(p)
                    n += 1

    # Unique by content.
    seen: set[str] = set()
    uniq = []
    for p in out:
        blob = p["data"] if "data" in p else p["text"].strip().encode("utf-8", "replace")
        h = hashlib.sha256(blob).hexdigest()
        if h not in seen:
            seen.add(h)
            p["sha256"] = h
            uniq.append(p)
    return uniq[:MAX_PAYLOADS]


_B64_FILE = re.compile(rb"[A-Za-z0-9+/\r\n]{64,}={0,2}\s*")
_B64_MAGIC = {b"MZ": ".exe", b"MSAP": ".bin", b"PK\x03\x04": ".zip", b"7z\xbc\xaf": ".7z", b"\x1f\x8b": ".gz"}


def _b64_file(raw: bytes) -> tuple[bytes, str] | None:
    """(decoded, extension) when ``raw`` is nothing but the base64 of a binary file of a known type."""
    import base64
    import binascii
    s = raw.strip()
    if len(s) < 64 or not _B64_FILE.fullmatch(s):
        return None
    try:
        out = base64.b64decode(re.sub(rb"\s+", b"", s), validate=True)
    except (binascii.Error, ValueError):
        return None
    return next(((out, ext) for m, ext in _B64_MAGIC.items() if out.startswith(m)), None)


def write(payloads: list[dict[str, Any]], dest: Path,
          skip_sha: set[str] | None = None) -> list[dict[str, Any]]:
    """Write payloads under ``dest`` as nested items ``{path, filename, origin}``."""
    items: list[dict[str, Any]] = []
    skip_sha = skip_sha or set()
    for p in payloads:
        if p["sha256"] in skip_sha:
            continue
        if "data" in p:
            raw, ext = p["data"], p.get("ext") or ".bin"
        else:
            raw, ext = p["text"].encode("utf-8", "replace"), (p.get("ext") or sniff_ext(p["text"]))
        dec = _b64_file(raw)
        if dec is not None:     # a stage written as base64 text (certutil -decode on the victim): the file
            raw, ext = dec
            p = {**p, "recipe": list(p.get("recipe") or []) + ["base64 (the text it writes)"]}
        slug = re.sub(r"[^A-Za-z0-9_-]+", "_", p["how"])[:40].strip("_") or "stage"
        name = f"decrypted_{slug}_{p['sha256'][:8]}{ext}"
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / name).write_bytes(raw)
        except OSError:
            continue
        items.append({"path": str(dest / name), "filename": name, "origin": p["origin"],
                      "recipe": p.get("recipe") or []})
    return items


def is_decrypted(path: Path) -> bool:
    return DIRNAME in path.parts
