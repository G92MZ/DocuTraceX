"""Decrypted payloads become nested children.

When an analyzer *resolves* a hidden stage — the JS sandbox logs what a custom
XOR routine returned or flags a dropped payload, a script carries a base64 blob
that is really a PE/ZIP/PDF — that stage is not just shown: it is written to
``extracted/decrypted/`` with an extension guessed from its content and handed
to the nested scanner, which routes it to the right analyzer (JavaScript,
PowerShell, VBScript, batch, Python, PE, Office, PDF, archive…). The nested
scanner does the same on every child, so a stage that decrypts the next one is
followed until the final behaviour (bounded by the nested depth limit).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path
from typing import Any

DIRNAME = "decrypted"
MAX_PAYLOADS = 12
MIN_TEXT = 24
MAX_BYTES = 8 * 1024 * 1024

_B64 = re.compile(r"""["']([A-Za-z0-9+/\r\n]{200,}={0,2})["']""")
_MAGIC = ((b"MZ", ".exe"), (b"PK\x03\x04", ".zip"), (b"%PDF", ".pdf"),
          (b"\xd0\xcf\x11\xe0", ".doc"), (b"{\\rt", ".rtf"), (b"\x4c\x00\x00\x00", ".lnk"))

# Content sniffing for decrypted *text* (first hit wins).
_LANG = (
    (".ps1", re.compile(r"(?im)^\s*(?:powershell|pwsh)(?:\.exe)?\b|\b(?:iex|invoke-expression|new-object\s+net\.webclient|"
                        r"downloadstring|start-process|set-executionpolicy|\[convert\]::frombase64string)\b|\$env:\w+")),
    (".hta", re.compile(r"(?i)<\s*hta:application|<\s*script[^>]+(?:vbscript|jscript)")),
    (".html", re.compile(r"(?i)<\s*(?:html|script|body|iframe)\b")),
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


def _scripty(text: str) -> bool:
    return len(text) >= MIN_TEXT and sniff_ext(text) != ".txt"


def payloads_from(mods: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolved stages found in a set of module results.

    Each is ``{"how": short label, "origin": where it came from, "text"|"data"}``.
    """
    out: list[dict[str, Any]] = []

    js = mods.get("javascript") or {}
    for sc in js.get("scripts") or []:
        if not isinstance(sc, dict):
            continue
        loc = sc.get("location") or sc.get("origin") or "javascript"
        for e in (sc.get("sandbox") or {}).get("log") or []:
            arg = (e.get("args") or [""])[0] if isinstance(e, dict) else ""
            if e.get("kind") == "xor" and _scripty(arg):
                out.append({"how": f"js-xor-{e.get('name')}", "origin": f"JavaScript {loc}: XOR {e.get('name')}()",
                            "text": arg})
            elif e.get("kind") == "fromcharcode" and len(arg) >= 80 and _scripty(arg):
                out.append({"how": "js-fromcharcode", "origin": f"JavaScript {loc}: String.fromCharCode", "text": arg})
        for t in sc.get("techniques") or []:
            if t.get("payload") and _scripty(t["payload"]):
                out.append({"how": "js-payload", "origin": f"JavaScript {loc}: {t.get('name')}", "text": t["payload"]})

    # Base64 blobs in any recovered code that are really files (PE, ZIP, PDF…).
    for key in ("javascript", "powershell", "vbscript", "batch", "python"):
        for sc in (mods.get(key) or {}).get("scripts") or []:
            if not isinstance(sc, dict):
                continue
            code = sc.get("_full_deob") or sc.get("code") or ""
            for m in list(_B64.finditer(code))[:6]:
                try:
                    raw = base64.b64decode(re.sub(r"\s+", "", m.group(1)) + "===")
                except (binascii.Error, ValueError):
                    continue
                ext = _magic_ext(raw)
                if ext and len(raw) <= MAX_BYTES:
                    out.append({"how": f"{key}-base64", "ext": ext, "data": raw,
                                "origin": f"{key} {sc.get('location') or ''}: base64 blob → {ext[1:].upper()}"})

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
            raw, ext = p["text"].encode("utf-8", "replace"), sniff_ext(p["text"])
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
