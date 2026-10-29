"""Metasploit (Meterpreter / shell) stagers in raw shellcode.

Recognised by Stephen Fewer's ``block_api`` prologue (the PEB walk + ROR13 API
hashing every Metasploit payload — and Cobalt Strike's stagers — start with).
The connect-back target is read from fixed shapes:

* x86 reverse_tcp: ``push <ip>`` ``push 0x0002 <port>`` (sockaddr_in on the stack)
* x64 reverse_tcp: ``mov r12/r14, <port><0x0002><ip>``
* reverse_http(s): the port pushed before ``InternetConnectA``'s hash and the
  host / URI as NUL-terminated strings in the payload.
"""

from __future__ import annotations

import re
import socket
import struct
from typing import Any

BLOCK_API = {
    "x86": (b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30",
            b"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30",
            b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"),
    "x64": (b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52",
            b"\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52",
            b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52"),
}
H_WININET = b"\x68\x6e\x65\x74\x00\x68\x77\x69\x6e\x69"     # push "net\0"; push "wini"
H_INTERNETCONNECT = b"\x68\x57\x89\x9f\xc6"                  # push 0xC69F8957
H_WINHTTP = b"\x68\x77\x69\x6e\x68"                           # push "winh"
_SOCK_X86 = re.compile(rb"\x68(.{4})\x68\x02\x00(.{2})", re.DOTALL)
_SOCK_X64 = re.compile(rb"\x49[\xbc\xbe]\x02\x00(.{2})(.{4})", re.DOTALL)
_HOST = re.compile(rb"(?<![\x21-\x7e])((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}|\d{1,3}(?:\.\d{1,3}){3})\x00")
_URI = re.compile(rb"\x00(/[A-Za-z0-9_\-./?=&%]{3,200})\x00")


def _arch(data: bytes) -> tuple[str, int] | None:
    best = None
    for arch, sigs in BLOCK_API.items():
        for s in sigs:
            i = data.find(s)
            if i >= 0 and (best is None or i < best[1]):
                best = (arch, i)
    return best


def prefilter(data: bytes) -> bool:
    return _arch(data) is not None


def _ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


def extract(data: bytes) -> dict[str, Any] | None:
    found = _arch(data)
    if not found:
        return None
    arch, at = found
    sc = data[at:at + 0x4000]
    summary: dict[str, Any] = {"Architecture": arch}
    c2: list[str] = []
    transport = ""
    m = (_SOCK_X64.search(sc) if arch == "x64" else None) or _SOCK_X86.search(sc)
    if m and not (H_WININET in sc or H_WINHTTP in sc):
        if m.re is _SOCK_X64:
            port, ip = struct.unpack(">H", m.group(1))[0], _ip(m.group(2))
        else:
            ip, port = _ip(m.group(1)), struct.unpack(">H", m.group(2))[0]
        transport = "reverse_tcp"
        c2.append(f"{ip}:{port}")
    elif H_WININET in sc or H_WINHTTP in sc:
        transport = "reverse_http(s)"
        port = None
        j = sc.find(H_INTERNETCONNECT)
        if j >= 5 and sc[j - 5] == 0x68:
            port = struct.unpack("<I", sc[j - 4:j])[0]
        hosts = [h.decode() for h in _HOST.findall(sc) if not h.lower().startswith((b"wininet", b"winhttp"))]
        uris = [u.decode() for u in _URI.findall(sc)]
        if port in (443, 8443):
            transport = "reverse_https"
        for h in hosts[-2:]:
            c2.append(f"{h}:{port}" if port else h)
        if uris:
            summary["URI"] = uris[0]
    if not c2:
        return {"family": "Metasploit-style stager", "kind": "stager", "method": "block_api signature",
                "confidence": "low", "summary": {**summary, "Note": "block_api shellcode found; "
                                                 "no connect-back target in a known shape"},
                "c2": [], "fields": {"block_api offset": hex(at)}}
    summary["Transport"] = transport
    summary["C2"] = c2
    return {"family": "Metasploit / Meterpreter", "kind": "stager",
            "method": f"block_api ({arch}) + {transport} shape", "confidence": "high",
            "summary": summary, "c2": [c.rsplit(":", 1)[0] for c in c2],
            "fields": {"block_api offset": hex(at), "architecture": arch, "transport": transport,
                       "connect-back": ", ".join(c2)},
            "note": "Cobalt Strike stagers share this prologue; a Cobalt Strike match on the "
                    "same object is the better name."}
