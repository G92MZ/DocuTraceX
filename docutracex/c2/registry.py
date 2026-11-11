"""Extractor Registry (C2 roadmap 3.2 / 6.1): what each C2 extractor is, what it
needs and what it tries to recover. Every extractor runs on every object and
says what happened (6.2):

* ``extracted`` — a configuration was recovered;
* ``partial`` — some of it;
* ``indicators`` — traces of the family, no configuration;
* ``not_found`` — the object is in its scope, nothing of the family in it;
* ``not_applicable`` — the object is not in its scope (its quick test said no);
* ``unsupported_format`` — in scope but in a form it cannot read;
* ``error`` — the extractor failed (the others still ran).
"""

from __future__ import annotations

from typing import Any

STATUSES = ("extracted", "partial", "indicators", "not_found", "not_applicable", "unsupported_format", "error")

# id → descriptor. ``version`` is the extractor's own version (bumped when what
# it recovers changes), stored with each result and each normalized field.
EXTRACTORS: dict[str, dict[str, Any]] = {
    "cobalt": {
        "name": "Cobalt Strike", "families": ["Cobalt Strike"], "version": "2.0",
        "formats": ["PE / DLL beacon", "raw shellcode", "stager", "memory dump", "decoded PowerShell / HTA stages"],
        "engines": ["1768.py (Didier Stevens)", "dissect.cobaltstrike (Fox-IT)", "shellcode reader", "reflective DLL carving"],
        "dependencies": ["tools/didier/1768.py", "dissect.cobaltstrike (Python)"],
        "fields": ["C2", "URIs", "User-Agent", "sleep / jitter", "watermark", "version", "DNS channel",
                   "process injection", "evasion", "guardrails", "pipe", "RSA public key", "malleable profile"],
        "output": "configuration (beacon / stager) or indicators",
        "limits": "a beacon only decrypted in memory by a custom loader needs that layer decoded first (or a memory dump)",
    },
    "remcos": {
        "name": "Remcos", "families": ["Remcos"], "version": "1.0", "formats": ["PE"],
        "engines": ["PE resources", "RC4"], "dependencies": ["pefile"],
        "fields": ["C2 (host:port:TLS)", "campaign", "mutex", "install"], "output": "configuration",
        "limits": "",
    },
    "dotnet": {
        "name": "AsyncRAT / DcRAT / QuasarRAT", "families": ["AsyncRAT", "DcRAT", "QuasarRAT"], "version": "1.0",
        "formats": [".NET assembly"], "engines": [".NET metadata", "AES + HMAC (PBKDF2)"],
        "dependencies": ["dnfile", "pycryptodome"],
        "fields": ["hosts", "ports", "version", "mutex", "group", "certificate", "install"], "output": "configuration",
        "limits": "",
    },
    "metasploit": {
        "name": "Metasploit / Meterpreter", "families": ["Metasploit / Meterpreter"], "version": "1.0",
        "formats": ["shellcode", "PE with shellcode"], "engines": ["block_api shapes"], "dependencies": [],
        "fields": ["LHOST", "LPORT", "transport", "URI"], "output": "stager configuration", "limits": "",
    },
    "dotnet_more": {
        "name": "njRAT / XWorm / NanoCore / RedLine / Snake / DarkGate…", "version": "1.0",
        "families": ["njRAT", "XWorm", "NanoCore", "RedLine / META", "Snake Keylogger", "Raccoon Stealer v2",
                     "Warzone / AveMaria", "DarkGate"],
        "formats": [".NET assembly", "PE"], "engines": [".NET strings", "AES / DES / RC4", "custom base64"],
        "dependencies": ["dnfile", "pycryptodome"], "fields": ["C2", "campaign", "mutex", "install", "exfiltration"],
        "output": "configuration", "limits": "NanoCore: identification only",
    },
    "go": {
        "name": "Go implants", "families": ["Sliver", "Merlin", "Mythic (Go agent)", "Go implant"], "version": "1.0",
        "formats": ["Go PE / ELF / Mach-O"],
        "engines": ["own Go parser (BuildInfo, pclntab)", "Go module: code strings per function, go:embed, crypto, Garble"],
        "dependencies": ["the Go module's results when it ran (optional)"],
        "fields": ["C2 (with provenance)", "framework", "Go version", "module", "network functions", "crypto"],
        "output": "configuration, or indicators (framework without endpoints)",
        "limits": "a bare literal is never taken as the C2 on its own; endpoints built at run time are not seen",
    },
    "stealers": {
        "name": "AgentTesla-style stealers", "families": ["AgentTesla"], "version": "1.0",
        "formats": [".NET assembly", "PE", "memory dump"], "engines": ["strings"], "dependencies": [],
        "fields": ["SMTP / FTP / Telegram exfiltration", "accounts"], "output": "exfiltration channel",
        "limits": "builds that encrypt their strings need the .NET string decryption or a memory dump",
    },
}


def status_of(found: list[dict[str, Any]], applicable: bool, error: str = "") -> str:
    if error:
        return "error"
    if not applicable:
        return "not_applicable"
    if not found:
        return "not_found"
    kinds = {c.get("kind") for c in found}
    if kinds == {"indicators"}:
        return "indicators"
    if any(str(c.get("status") or "").startswith("partial") for c in found):
        return "partial"
    return "extracted"


def descriptors() -> list[dict[str, Any]]:
    return [{"id": k, **v} for k, v in EXTRACTORS.items()]
