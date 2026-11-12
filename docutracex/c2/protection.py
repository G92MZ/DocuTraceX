"""Protectors and virtualizers that keep an implant's configuration out of static reach.

When no configuration is found in an object, the C2 tab says *why* if the object
is protected: a .NET virtualizer (KoiVM, ConfuserEx's VM), a native protector
(Themida / WinLicense, VMProtect, Enigma…) or an obfuscator that encrypts the
strings. The code that would decrypt the settings runs inside the protector's
VM or after its unpacking stub, so reading it needs the program to run — out of
scope for a static tool. Seen in the real-sample validation on AsyncRAT and
RedLine (KoiVM) and XWorm (Themida).

Markers are the protectors' own names and section names; Detect It Easy's
"protector" verdicts (when DIE ran on the object) are added.
"""

from __future__ import annotations

from typing import Any

# name → (kind, byte markers); a marker must be the protector's own (not generic code)
MARKERS: dict[str, tuple[str, tuple[bytes, ...]]] = {
    "KoiVM": ("virtualizer", (b"KoiVM", b"#Koi\x00")),
    "ConfuserEx": ("obfuscator", (b"ConfusedByAttribute",)),
    ".NET Reactor": ("protector", (b"Eziriz", b"E\x00z\x00i\x00r\x00i\x00z\x00")),
    "Eazfuscator.NET": ("obfuscator", (b"Eazfuscator",)),
    "SmartAssembly": ("obfuscator", (b"SmartAssembly.Attributes", b"PoweredByAttribute")),
    "Babel Obfuscator": ("obfuscator", (b"BabelObfuscatorAttribute",)),
    "Agile.NET": ("protector", (b"AgileDotNetRT",)),
    "DNGuard HVM": ("virtualizer", (b"HVMRuntm", b"DNGuard")),
    "Themida / WinLicense": ("protector", (b".themida", b".winlice")),
    "VMProtect": ("virtualizer", (b".vmp0\x00", b".vmp1\x00")),
    "Enigma Protector": ("protector", (b".enigma1", b".enigma2")),
    "Obsidium": ("protector", (b"Obsidium",)),
}
# Themida 3 renames its sections to spaces / random words but keeps the taggant section
_THEMIDA3 = b".taggant"

SAYS = {"virtualizer": "its code runs inside a virtual machine of the protector",
        "protector": "its code is encrypted and only unpacked when it runs",
        "obfuscator": "its strings and settings are encrypted by the obfuscator's own routines"}


def detect(data: bytes, die_detects: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    """[{name, kind, evidence}] — the protectors found in one object."""
    out: list[dict[str, str]] = []
    head = data[:64 * 1024 * 1024]
    for name, (kind, marks) in MARKERS.items():
        # as an identifier (#Strings, sections) or as a .NET user string (UTF-16)
        hit = next((m for m in marks if m in head or (m[:1] != b"." and m.rstrip(b"\x00").decode("latin-1")
                                                        .encode("utf-16-le") in head)), None)
        if hit:
            out.append({"name": name, "kind": kind,
                        "evidence": f"marker {hit.decode('latin-1').strip(chr(0)).replace(chr(0), '')!r}"})
    if _THEMIDA3 in head[:4096] and not any(p["name"].startswith("Themida") for p in out):
        out.append({"name": "Themida / WinLicense", "kind": "protector",
                    "evidence": "section .taggant (Themida 3.x renames the others)"})
    for d in die_detects or []:
        if str(d.get("type", "")).lower() not in ("protector", "virtualizer", "cryptor"):
            continue
        name = str(d.get("name") or "").strip()
        if name and not any(name.lower() in p["name"].lower() or p["name"].lower() in name.lower() for p in out):
            out.append({"name": name, "kind": "protector", "evidence": f"Detect It Easy: {d.get('string') or name}"})
    return out


def note(found: list[dict[str, str]]) -> str:
    names = ", ".join(p["name"] for p in found)
    why = SAYS.get(found[0]["kind"], SAYS["protector"]) if found else ""
    return (f"protected with {names}: {why}, so the configuration cannot be read statically — "
            "only the family's traces, if any. Unpacking it needs the program to run (a sandbox).")
