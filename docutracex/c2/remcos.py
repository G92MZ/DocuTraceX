"""Remcos RAT configuration.

The builder stores the settings in an RCDATA resource named ``SETTINGS``:
``[key length][RC4 key][RC4(config)]``. The decrypted config is a list of
fields separated by ``|\\x1e\\x1e\\x1f|`` (older builds: ``|``); the first is
the C2 list — ``host:port:tls`` entries separated by ``\\x1e`` — the second the
campaign (botnet) name, and the mutex looks like ``Rmc-XXXXXX``. Remcos 3.x / 4.x builds have a fixed
field order, read by position through the common family layer (install,
persistence, keylogger, screenshots…); older builds keep the generic reading.
When nothing decrypts, the family's traces are reported as indicators.
"""

from __future__ import annotations

import re
from typing import Any

from . import familyspec

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


# Field positions of the decrypted SETTINGS (Remcos 3.x / 4.x, as public parsers
# read them). Only the positions agreed by those parsers are named; the rest
# stay "field N". Older builds have fewer fields and keep the generic reading.
POSITIONS = {
    "0": "c2", "1": "group", "2": "interval", "3": "install", "4": "run_hkcu", "5": "run_hklm",
    "6": "run_policies", "7": "winlogon_shell", "8": "winlogon_userinit", "9": "install_folder",
    "10": "install_name", "11": "startup_name", "12": "install_hidden", "13": "injection", "14": "mutex",
    "15": "keylog_mode", "16": "keylog_folder", "17": "keylog_file", "18": "keylog_encrypted", "19": "log_hidden",
    "20": "screenshots", "21": "screenshot_interval", "25": "screenshot_folder", "26": "screenshot_file",
}
MIN_POSITIONAL = 21
_PERSIST = (("run_hkcu", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{name}"),
            ("run_hklm", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{name}"),
            ("run_policies", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\{name}"),
            ("winlogon_shell", "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell (appended)"),
            ("winlogon_userinit", "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit (appended)"))
_VERSION = re.compile(rb"Remcos v(\d+(?:\.\d+)+(?: [A-Za-z]+)?)")

SPEC = familyspec.Spec(
    family="Remcos",
    fields={k: v for k, v in POSITIONS.items() if v not in ("c2",)},
    options={"interval": ("seconds", "reconnects every {v} s"),
             "injection": ("flag", "injects itself into another process"),
             "screenshots": ("flag", "takes screenshots")},
    defaults={"group": {"RemoteHost": "builder default botnet name"},
              "install_name": {"remcos.exe": "builder default install name"},
              "startup_name": {"remcos": "builder default startup name"}},
    default_prefixes=(),
    traces=((b"Breaking-Security.Net", "vendor string Breaking-Security.Net"), (b"Remcos", "Remcos strings"),
            (b"S\x00E\x00T\x00T\x00I\x00N\x00G\x00S", "resource SETTINGS"), (b"Rmc-", "Rmc- mutex prefix"),
            (b"licence", "licence string")),
    min_traces=3)


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
    pairs = [f"{h}:{p}" + (" (TLS)" if tls else "") for h, p, tls in c2]
    printable = {f"field {i}": f for i, f in enumerate(fields)
                 if f and all(31 < ord(c) < 127 or c in "\x1e" for c in f) and len(f) <= 200}
    if len(fields) < MIN_POSITIONAL:                      # an older layout: the generic reading
        mutex = next((m.group(0) for f in fields for m in [_MUTEX.search(f)] if m), "")
        summary: dict[str, Any] = {"C2": pairs, "Campaign": fields[1] if len(fields) > 1 else "", "Mutex": mutex}
        return {"summary": {k: v for k, v in summary.items() if v}, "c2": [h for h, _, _ in c2],
                "fields": printable, "layout": "older (fields not named)"}
    named = {str(i): f for i, f in enumerate(fields) if str(i) in POSITIONS}
    summary, _hosts = familyspec.interpret(SPEC, named)
    g = familyspec.roles(SPEC, named)
    out: dict[str, Any] = {"C2": pairs}
    if summary.get("Group"):
        out["Campaign"] = summary.pop("Group")
    out.update(summary)
    # install: the folder is a path or a code of the builder's folder list (not mapped: it changed between versions)
    if familyspec._on(g.get("install", "")):
        folder = g.get("install_folder", "")
        name = g.get("install_name", "")
        if folder and ("%" in folder or "\\" in folder):
            out["Install path"] = f"{folder}\\{name}" if name else folder
        else:
            out["Install path"] = f"{name} (folder: builder option {folder or '?'})"
        if familyspec._on(g.get("install_hidden", "")):
            out["Install path"] += " (hidden file)"
    pers = [t.format(name=g.get("startup_name") or "?") for role, t in _PERSIST if familyspec._on(g.get(role, ""))]
    if pers:
        out["Persistence"] = pers
    mode = g.get("keylog_mode", "").strip()
    if mode and mode != "0":                              # 1 unlimited, 2 limited (by window title)
        path = "\\".join(x for x in (g.get("keylog_folder"), g.get("keylog_file")) if x)
        out["Keylogger"] = ("on" + (" (only some windows)" if mode == "2" else "")
                            + (f", log {path}" if path else "")
                            + (" (encrypted)" if familyspec._on(g.get("keylog_encrypted", "")) else "")
                            + (" (hidden)" if familyspec._on(g.get("log_hidden", "")) else ""))
    if familyspec._on(g.get("screenshots", "")) and (g.get("screenshot_folder") or g.get("screenshot_file")):
        out["Screenshots to"] = "\\".join(x for x in (g.get("screenshot_folder"), g.get("screenshot_file")) if x)
        if g.get("screenshot_interval", "").isdigit() and int(g["screenshot_interval"]) > 0:
            out["Screenshots to"] += f" (every {int(g['screenshot_interval'])} min)"
    labels = {v: k for k, v in POSITIONS.items()}
    named_fields = {f"{r} (field {labels[r]})": g[r] for r in g if r in labels and len(g[r]) <= 200}
    other = {k: v for k, v in printable.items() if k.split()[1] not in POSITIONS}
    return {"summary": {k: v for k, v in out.items() if v not in ("", [], None)}, "c2": [h for h, _, _ in c2],
            "fields": {**named_fields, **other}, "layout": f"Remcos 3.x / 4.x ({len(fields)} fields)"}


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
            layout = res.pop("layout")
            v = _VERSION.search(data)
            if v:
                res["summary"] = {"Version": v.group(1).decode(), **res["summary"]}
            return {"family": "Remcos", "kind": "RAT",
                    "method": f"RCDATA '{name}' resource, RC4 (key {klen} bytes) — {layout}", "confidence": "high",
                    **res}
    return familyspec.traces(SPEC, data)
