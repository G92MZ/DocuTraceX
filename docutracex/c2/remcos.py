"""Remcos RAT configuration.

The builder stores the settings in an RCDATA resource named ``SETTINGS``:
``[key length][RC4 key][RC4(config)]``. The decrypted config is a list of
fields separated by ``|\\x1e\\x1e\\x1f|`` (older builds: ``|``); the first is
the C2 list — ``host:port:tls`` entries separated by ``\\x1e`` — the second the
campaign (botnet) name, and the mutex looks like ``Rmc-XXXXXX``.
"""

from __future__ import annotations

import re
from typing import Any

SEPS = (b"|\x1e\x1e\x1f|", b"|")
_MUTEX = re.compile(r"Rmc-[A-Z0-9]{6}")
_HOSTPORT = re.compile(r"^([A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\]):(\d{1,5})(?::(\d))?$")


def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def _rcdata(data: bytes) -> list[tuple[str, bytes]]:
    """(name, bytes) of every RCDATA resource of a PE (named ones first)."""
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception:  # noqa: BLE001
        return []
    out = []
    for t in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or []:
        if t.id != 10:                                   # RT_RCDATA
            continue
        for n in getattr(t, "directory", None) and t.directory.entries or []:
            name = str(n.name) if n.name is not None else str(n.id)
            for lang in getattr(n, "directory", None) and n.directory.entries or []:
                e = lang.data.struct
                try:
                    out.append((name, pe.get_data(e.OffsetToData, e.Size)))
                except Exception:  # noqa: BLE001, S112  (a broken entry is just skipped)
                    continue
    out.sort(key=lambda x: x[0].upper() != "SETTINGS")
    return out


def prefilter(data: bytes) -> bool:
    return data[:2] == b"MZ" and (b"S\x00E\x00T\x00T\x00I\x00N\x00G\x00S" in data or b"Remcos" in data
                                  or b"remcos" in data or b"Rmc-" in data)


def _parse(plain: bytes) -> dict[str, Any] | None:
    sep = next((s for s in SEPS if s in plain), None)
    if sep is None:
        return None
    raw = plain.split(sep)
    fields = [f.decode("latin-1", "replace").strip("\x00") for f in raw]
    entries = [e for e in fields[0].replace("\x1e", "|").split("|") if e]
    c2 = []
    for e in entries:
        m = _HOSTPORT.match(e.strip())
        if m:
            c2.append((m.group(1), m.group(2), m.group(3) == "1"))
    if not c2:
        return None
    mutex = next((m.group(0) for f in fields for m in [_MUTEX.search(f)] if m), "")
    summary: dict[str, Any] = {
        "C2": [f"{h}:{p}" + (" (TLS)" if tls else "") for h, p, tls in c2],
        "Campaign": fields[1] if len(fields) > 1 else "",
        "Mutex": mutex,
    }
    printable = {f"field {i}": f for i, f in enumerate(fields)
                 if f and all(31 < ord(c) < 127 or c in "\x1e" for c in f) and len(f) <= 200}
    return {"summary": {k: v for k, v in summary.items() if v}, "c2": [h for h, _, _ in c2],
            "fields": printable}


def extract(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ":
        return None
    for name, blob in _rcdata(data):
        if len(blob) < 8:
            continue
        klen = blob[0]
        if not 1 <= klen < len(blob) - 4:
            continue
        res = _parse(rc4(blob[1:1 + klen], blob[1 + klen:]))
        if res:
            return {"family": "Remcos", "kind": "RAT",
                    "method": f"RCDATA '{name}' resource, RC4 (key {klen} bytes)", "confidence": "high",
                    **res}
    return None
