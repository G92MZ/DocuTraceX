"""Where static analysis stops: the objects whose configuration needs a dynamic analysis.

DocuTraceX follows a sample as far as it can without running it. Two endings leave the C2 out of
reach, and the C2 tab says so plainly instead of staying silent:

* **payload** — the final payload of a known family was reached (its family rules or traces match), but
  its configuration is encrypted with a scheme no extractor here reads (Formbook / XLoader, newer
  builds of a stealer…). This *is* the payload: run it in a sandbox to get the C2.
* **probable payload** — the last executable a chain leads to (decrypted, unpacked, hidden…), with no
  configuration of a known family and nothing below it, in a case where no configuration was read:
  probably the payload of a family no extractor knows. Said with less weight than the other two.
* **loader** — a loader whose payload is still encrypted inside it (a Go loader with a large encrypted
  data section, a native loader with encrypted resources, an encrypted section) and that did not
  yield a payload here: the payload only exists once it runs.

Each entry says what to do in the sandbox and what to watch for (decoy domains, dead drops, anti-VM
checks). Nothing is run here.
"""

from __future__ import annotations

import math
import re
from typing import Any

MIN_BLOB = 64 * 1024
LOADER_ENTROPY = 7.5
_INSTALLERS = (b"Nullsoft", b"Inno Setup", b"InstallShield", b"7-Zip SFX", b"WinRAR SFX", b"Squirrel")
# a blob that is a known compressed format is content (an image, an archive), not an encrypted payload
_MEDIA = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"PK\x03\x04", b"7z\xbc\xaf", b"MSCF", b"RIFF", b"BM", b"\x00\x00\x01\x00",
          b"%PDF", b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"OggS", b"ID3", b"fLaC", b"wOFF", b"\x00\x01\x00\x00", b"OTTO",
          b"<?xml", b"MZ")
_ANTI_VM = (b"vmmemctl", b"vm3dmp", b"vmtoolsd", b"VBoxGuest", b"VBoxService", b"vboxdisp", b"VBOX__", b"qemu-ga",
            b"SbieDll", b"cuckoomon", b"wine_get_unix_file_name")

TODO = ("Run it in an isolated sandbox (network simulated or captured: FakeNet-NG / INetSim, Wireshark).",
        "Watch DNS, HTTP(S), SMTP / FTP and Telegram traffic for the C2.",
        "Or dump the unpacked process (pe-sieve / hollows_hunter, or a sandbox that dumps payloads such as a "
        "self-hosted CAPE) and upload the dump here: its configuration is then read statically.")

FAMILY_TIPS = {
    "formbook": "Formbook / XLoader contacts its real C2 among many decoy domains: the traffic alone does not "
                "say which one is real; a configuration extractor run on a memory dump does.",
    "xloader": "Formbook / XLoader contacts its real C2 among many decoy domains: the traffic alone does not "
               "say which one is real; a configuration extractor run on a memory dump does.",
    "vidar": "Vidar reads its C2 from a dead drop (a Telegram channel or a Steam profile): let that request "
             "out, or open the dead drop, to see the C2.",
    "lumma": "Lumma tries its C2 list in order and falls back to a Steam / Telegram dead drop.",
    "stealc": "StealC v2 posts straight to its C2 (often an IP): the first request shows it.",
    "agenttesla": "AgentTesla exfiltrates by SMTP, FTP or Telegram: the session shows the server and, over plain "
                  "SMTP / FTP, the account it logs in with.",
}


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c if v)


def _sample(b: bytes, cap: int = 1 << 20) -> bytes:
    if len(b) <= cap:
        return b
    step = len(b) // 16
    return b"".join(b[i:i + cap // 16] for i in range(0, len(b), step))[:cap]


def anti_vm(data: bytes) -> list[str]:
    """Names of virtual-machine / sandbox artefacts the object looks for (in clear, ASCII or UTF-16)."""
    out = []
    for m in _ANTI_VM:
        if m in data or m.decode().encode("utf-16-le") in data:
            out.append(m.decode())
    return out


def encrypted_blobs(data: bytes) -> list[dict[str, Any]]:
    """Large encrypted-looking blobs a PE carries: sections and resources of ≥ 64 KB, entropy ≥ 7.5."""
    if data[:2] != b"MZ" or any(m in data[:4 << 20] for m in _INSTALLERS):
        return []
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                                               pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]])
    except Exception:  # noqa: BLE001
        return []
    out: list[dict[str, Any]] = []
    try:
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress:      # .NET: the CIL analysis covers it
            return []
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:                 # Authenticode-signed: too often legitimate
            return []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            if name == ".rsrc":
                continue
            raw = s.get_data()
            if len(raw) >= MIN_BLOB:
                e = _entropy(_sample(raw))
                if e >= LOADER_ENTROPY:
                    out.append({"where": f"section {name}", "size": len(raw), "entropy": round(e, 2)})
        for t in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None).entries if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else []:
            for n in getattr(t, "directory", None).entries if hasattr(t, "directory") else []:
                for leaf in getattr(n, "directory", None).entries if hasattr(n, "directory") else []:
                    size = leaf.data.struct.Size
                    if size < MIN_BLOB:
                        continue
                    if t.id in (2, 3, 14) or (t.id is not None and t.id not in (10,) and not t.name):
                        continue                    # bitmaps / icons / standard types: content, not a payload
                    raw = pe.get_data(leaf.data.struct.OffsetToData, size)
                    if raw.startswith(_MEDIA):
                        continue
                    e = _entropy(_sample(raw))
                    if e >= LOADER_ENTROPY:
                        tname = str(t.name) if t.name else str(t.id)
                        nname = str(n.name) if n.name else str(n.id)
                        out.append({"where": f"resource {tname}/{nname}", "size": size, "entropy": round(e, 2)})
    finally:
        pe.close()
    return out[:6]


def _is_go(data: bytes) -> bool:
    return b"Go build ID" in data[:1 << 16] or b"runtime.gopanic" in data or b"\xff Go buildinf:" in data


def assess_loader(label: str, data: bytes) -> dict[str, Any] | None:
    """A loader whose payload is still encrypted inside it, or None."""
    blobs = encrypted_blobs(data)
    if not blobs:
        return None
    go = _is_go(data)
    kind = "Go loader" if go else "native loader"
    biggest = max(blobs, key=lambda b: b["size"])
    why = (f"{kind}: its payload is still encrypted inside it ({biggest['where']}, {biggest['size'] // 1024} KB, "
           f"entropy {biggest['entropy']}) and is only decrypted when it runs — static analysis stops here.")
    return {"object": label, "role": "loader", "family": "", "why": why, "blobs": blobs,
            "anti_vm": anti_vm(data), "todo": list(TODO), "tips": []}


def assess_payload(label: str, family: str, data: bytes) -> dict[str, Any]:
    key = re.sub(r"[^a-z]", "", family.lower())
    tips = [t for k, t in FAMILY_TIPS.items() if k in key]
    why = (f"final payload of {family} reached, but its configuration is encrypted with a scheme no extractor "
           "here reads: this is the payload — get the C2 from a dynamic analysis.")
    return {"object": label, "role": "payload", "family": family, "why": why, "blobs": [],
            "anti_vm": anti_vm(data), "todo": list(TODO), "tips": tips}


# runtimes a chain drops to run a script: the script is the payload, not the runtime
INTERPRETERS = {b"LuaJIT ": "LuaJIT", b"Copyright (C) 2005-2016 Mike Pall": "LuaJIT", b"AutoIt v3": "AutoIt",
                b"AU3!EA06": "AutoIt", b"python3": "Python", b"Py_Initialize": "Python", b"node.exe": "Node.js",
                b"AutoHotkey": "AutoHotkey", b"PHP_VERSION": "PHP", b"tcl_platform": "Tcl"}


def interpreter(data: bytes) -> str:
    head = data[:8 << 20]
    return next((name for mark, name in INTERPRETERS.items() if mark in head), "")


def assess_leaf(label: str, data: bytes, chain: str = "") -> dict[str, Any]:
    """The last executable obtained from the sample, no configuration read and nothing below it: probably
    the final payload, of a family no extractor here knows (or a build whose configuration is hidden)."""
    net = b"BSJB" in data[:1 << 22]
    runtime = interpreter(data)
    if runtime:
        why = (f"the chain ends in a {runtime} interpreter" + (f" ({chain})" if chain else "")
               + f": the payload is the script it runs, not the {runtime} runtime — the script is in Nested "
               "(it may be obfuscated). If it is malicious, its C2 comes from a dynamic analysis.")
        return {"object": label, "role": "probable_payload", "family": "", "why": why, "blobs": [],
                "anti_vm": [], "todo": list(TODO), "tips": [], "runtime": runtime}
    why = ("probably the final payload: the last executable this chain leads to"
           + (f" ({chain})" if chain else "") + ", with no configuration of a known family in it and nothing "
           "else inside it. " + ("A .NET program: its strings and the CIL emulation are in the .NET tab. "
                                 if net else "") + "If it is malicious, its C2 comes from a dynamic analysis.")
    return {"object": label, "role": "probable_payload", "family": "", "why": why, "blobs": [],
            "anti_vm": anti_vm(data), "todo": list(TODO), "tips": []}


def finding(entry: dict[str, Any]) -> dict[str, Any]:
    if entry["role"] == "payload":
        detail = f"{entry['family']} payload reached — configuration needs a dynamic analysis"
    elif entry["role"] == "probable_payload":
        detail = "Probable final payload without a readable configuration — check it with a dynamic analysis"
    else:
        detail = "Loader with an encrypted payload — the payload needs a dynamic analysis"
    ev = entry["why"] + (" Anti-VM checks: " + ", ".join(entry["anti_vm"]) + "." if entry["anti_vm"] else "")
    ev += (" " + " ".join(entry["tips"])) if entry["tips"] else ""
    return {"tool": "c2", "rule": "c2:dynamic_analysis",
            "severity": "low" if entry["role"] == "probable_payload" else "medium", "detail": detail,
            "location": entry["object"], "evidence": ev[:1500]}
