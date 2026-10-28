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
_B64_LIT = re.compile(r"""(?:["']|-e(?:nc|ncodedcommand)?\s+)([A-Za-z0-9+/]{100,}={0,2})(?:["']|\s|$)""")
_HEX_LIT = re.compile(r"""["']((?:[0-9A-Fa-f]{2}){48,})["']""")
_MAGIC = ((b"MZ", ".exe"), (b"PK\x03\x04", ".zip"), (b"%PDF", ".pdf"),
          (b"\xd0\xcf\x11\xe0", ".doc"), (b"{\\rt", ".rtf"), (b"\x4c\x00\x00\x00", ".lnk"))

# Content sniffing for decrypted *text* (first hit wins).
_LANG = (
    (".ps1", re.compile(r"(?im)^\s*(?:powershell|pwsh)(?:\.exe)?\b|\b(?:iex|invoke-expression|new-object\s+net\.webclient|"
                        r"downloadstring|start-process|set-executionpolicy|\[convert\]::frombase64string)\b|\$env:\w+")),
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


def _magic_ext(raw: bytes) -> str | None:
    for magic, ext in _MAGIC:
        if raw.startswith(magic):
            return ext
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


def classify(raw: bytes, how: str, origin: str, depth: int = 0) -> dict[str, Any] | None:
    """A decoded byte string as a payload: file by magic, (inflated) content,
    text, or an opaque blob; None when it is too small to be worth a child."""
    if not raw or len(raw) > MAX_BYTES:
        return None
    ext = _magic_ext(raw)
    if ext:
        return {"how": how, "ext": ext, "data": raw, "origin": f"{origin} → {ext[1:].upper()}"}
    inner = _inflate(raw) if depth < 2 else None
    if inner:
        return classify(inner, how + "-inflated", f"{origin} → decompressed", depth + 1)
    text = _text_of(raw)
    if text is not None:
        if len(text.strip()) < MIN_TEXT:
            return None
        return {"how": how, "text": text, "origin": f"{origin} → text"}
    if len(raw) < MIN_BLOB:
        return None
    return {"how": how + "-blob", "ext": ".bin", "data": raw,
            "origin": f"{origin} → opaque binary ({len(raw)} bytes, likely encrypted/compressed)"}


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
        deob = _read(root, sc.get("code_file_deob")) or sc.get("_full_deob") or sc.get("code") or ""
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
    return (_read(root, sc.get("code_file")) or sc.get("_full_code") or sc.get("code") or "")


def _already_in(text: str, analysed: str) -> bool:
    """Decoded text already present in the analysed code — judged by its first
    lines, since the analysed copy may have been decoded further in place."""
    lines = [ln.strip() for ln in text.replace("\r", "").splitlines() if ln.strip()][:6]
    if not lines:
        return True
    return sum(1 for ln in lines if ln in analysed) * 2 >= len(lines)


def _decode_literals(code: str) -> list[tuple[str, bytes]]:
    found: list[tuple[str, bytes]] = []
    for m in _B64_LIT.finditer(code):
        lit = m.group(1)
        if len(set(lit)) < 16:                 # "AAAA…", padding runs: not data
            continue
        try:
            found.append(("base64", base64.b64decode(lit + "=" * (-len(lit) % 4))))
        except (binascii.Error, ValueError):
            continue
    for m in _HEX_LIT.finditer(code):
        try:
            found.append(("hex", bytes.fromhex(m.group(1))))
        except ValueError:
            continue
    return found


def _scripty(text: str) -> bool:
    return len(text) >= MIN_TEXT and sniff_ext(text) != ".txt"


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
                            "text": arg})
            elif e.get("kind") == "fromcharcode" and len(arg) >= 80 and _scripty(arg):
                out.append({"how": "js-fromcharcode", "origin": f"JavaScript {loc}: String.fromCharCode", "text": arg})
        # files the script wrote (FileSystemObject / ADODB.Stream), with the
        # extension of the path it gave them
        for e in (sc.get("sandbox") or {}).get("log") or []:
            if isinstance(e, dict) and e.get("kind") == "drop" and (e.get("args") or [""])[0].strip():
                name = str(e.get("name") or "")
                ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name.rsplit("\\", 1)[-1] else ""
                out.append({"how": "js-drop", "origin": f"JavaScript {loc}: wrote {name}",
                            "text": e["args"][0], "ext": ext if 1 < len(ext) <= 6 else None})
        for t in sc.get("techniques") or []:
            if t.get("payload") and _scripty(t["payload"]):
                out.append({"how": "js-payload", "origin": f"JavaScript {loc}: {t.get('name')}", "text": t["payload"]})

    # Every encoded literal in the recovered code (base64 / hex, gzip/zlib in
    # them) is decoded and becomes a child, whatever comes out — unless the
    # deobfuscator already inlined it in the code that was analysed.
    langs = ("javascript", "powershell", "vbscript", "batch", "python")
    scripts = [(key, sc, *_sources(sc, root)) for key in langs
               for sc in (mods.get(key) or {}).get("scripts") or []
               # scripts surfaced from nested children are handled by that child
               if isinstance(sc, dict) and not sc.get("from_nested")]
    # what was analysed in ANY language here (e.g. the PowerShell tab already
    # decoded the -enc a VBScript launches): decoded text found in it is skipped
    analysed = "\n".join(src for _k, _sc, src, _o in scripts).replace("\r", "")
    for key, sc, src, orig in scripts:
        loc = sc.get("location") or key
        n = 0
        seen_lits: set[bytes] = set()
        # literals still encoded in the analysed code: every outcome is a child;
        # literals the deobfuscator already resolved (only in the original):
        # only when they turn out to be a FILE (e.g. HTML smuggling's PE),
        # since their text/decryption is already in the analysed code
        for resolved, code in ((False, src), (True, orig)):
            for kind, raw in _decode_literals(code):
                if n >= PER_SCRIPT or raw in seen_lits:
                    continue
                seen_lits.add(raw)
                p = classify(raw, f"{key}-{kind}", f"{key} {loc}: {kind} literal")
                if not p:
                    continue
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
        slug = re.sub(r"[^A-Za-z0-9_-]+", "_", p["how"])[:40].strip("_") or "stage"
        name = f"decrypted_{slug}_{p['sha256'][:8]}{ext}"
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / name).write_bytes(raw)
        except OSError:
            continue
        items.append({"path": str(dest / name), "filename": name, "origin": p["origin"]})
    return items


def is_decrypted(path: Path) -> bool:
    return DIRNAME in path.parts
