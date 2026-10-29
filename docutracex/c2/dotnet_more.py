"""More .NET implants: njRAT, XWorm, AgentTesla-style stealers, NanoCore.

All read the #US (user strings) heap of the assembly — see ``dotnet_rats``.

* **njRAT / Bladabindi** keeps its settings in clear: host, port, campaign
  name (base64), version, install name / folder, mutex-like registry value and
  the ``|'|'|`` splitter.
* **XWorm** encrypts each setting with AES-256-ECB; the key is
  ``MD5(mutex)[:15] + MD5(mutex) + 0x00`` and the mutex is a plain string of
  the same class. Every plain string is tried as the mutex.
* **AgentTesla-style stealers**: the exfiltration channel (SMTP server and
  accounts, FTP URL, Telegram-style bot token / chat) next to the browser /
  mail-client credential paths they read. Builds that encrypt their strings
  hide this from a static read — then only a memory dump shows it.
* **NanoCore**: recognised by its client/plugin type names; its settings are
  stored encrypted in a resource and are not decrypted (identification only).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .dotnet_rats import _b64, _classify, _is_host, prefilter, user_strings

_NJ_SPLIT = "|'|'|"
_NJ_MARKERS = ("SEE_MASK_NOZONECHECKS", "netsh firewall add allowedprogram", "cmd.exe /c ping 0 -n 2 & del")
_XW_MARKERS = (b"XWorm", b"X\x00W\x00o\x00r\x00m", b"<Xwormmm>", b"<\x00X\x00w\x00o\x00r\x00m\x00m\x00m\x00>")
_NANO_MARKERS = (b"NanoCore Client", b"NanoCore.ClientPlugin", b"IClientNetworkHost", b"NanoCore.ClientPluginHost")
_STEALER_PATHS = ("\\Google\\Chrome\\User Data", "logins.json", "\\Mozilla\\Firefox", "Thunderbird",
                  "\\Opera Software", "Login Data", "\\Microsoft\\Edge\\User Data", "FileZilla",
                  "\\Outlook\\", "encryptedPassword", "\\Yandex\\YandexBrowser")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$")
_BOT = re.compile(r"/bot(\d{6,12}:[A-Za-z0-9_-]{30,50})")
_TOKEN = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,50}$")
_FTP = re.compile(r"^ftp://\S+$", re.IGNORECASE)


def _printable(s: str) -> bool:
    return bool(s) and all(c.isprintable() for c in s)


# --- njRAT -----------------------------------------------------------------------
def njrat(data: bytes, strings: list[str]) -> dict[str, Any] | None:
    if _NJ_SPLIT not in strings and sum(m in s for s in strings for m in _NJ_MARKERS) < 2:
        return None
    summary: dict[str, Any] = {}
    host_i = next((i for i, s in enumerate(strings) if _is_host(s) and not s.lower().startswith("www.")), None)
    if host_i is None:
        return None
    host = strings[host_i]
    port = next((s for s in strings[host_i + 1:host_i + 4] if s.isdigit() and 0 < int(s) < 65536), None) \
        or next((s for s in strings if s.isdigit() and 0 < int(s) < 65536 and len(s) >= 2), None)
    summary["C2"] = [f"{host}:{port}" if port else host]
    for s in strings:
        b = _b64(s) if len(s) >= 4 else None
        if b and 3 <= len(b) <= 64 and all(32 <= c < 127 for c in b) and "Campaign" not in summary:
            summary["Campaign"] = b.decode()
        elif re.match(r"^(0\.\d[\w.]*|im\d{3,})$", s) and "Version" not in summary:
            summary["Version"] = s
        elif re.match(r"^[0-9a-f]{32}$", s) and "Mutex / registry key" not in summary:
            summary["Mutex / registry key"] = s
        elif s.lower().endswith(".exe") and "Install name" not in summary and "\\" not in s:
            summary["Install name"] = s
        elif s in ("TEMP", "AppData", "UserProfile", "WinDir", "ProgramFiles") and "Install folder" not in summary:
            summary["Install folder"] = s
    if _NJ_SPLIT in strings:
        summary["Splitter"] = _NJ_SPLIT
    return {"family": "njRAT", "kind": "RAT", "method": "plain .NET settings strings", "confidence": "high",
            "summary": summary, "c2": [host],
            "fields": {f"string {i}": s for i, s in enumerate(strings) if _printable(s) and len(s) <= 200}}


# --- XWorm -----------------------------------------------------------------------
def _xw_key(mutex: str) -> bytes:
    h = hashlib.md5(mutex.encode("utf-8")).digest()
    return h[:15] + h + b"\x00"


def _aes_ecb(key: bytes, ct: bytes) -> str | None:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        pt = d.update(ct) + d.finalize()
    except Exception:  # noqa: BLE001
        return None
    pad = pt[-1] if pt else 0
    if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    try:
        s = pt[:-pad].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if _printable(s) else None


def xworm(data: bytes, strings: list[str]) -> dict[str, Any] | None:
    enc = [(s, b) for s in strings for b in [_b64(s)] if b and len(b) % 16 == 0]
    if not enc:
        return None
    for mutex in [s for s in strings if 6 <= len(s) <= 64 and re.match(r"^[A-Za-z0-9_\-<>]+$", s)][:60]:
        key = _xw_key(mutex)
        values = [v for _, b in enc for v in [_aes_ecb(key, b)] if v is not None]
        if len(values) < 2:
            continue
        cls = _classify(values)
        summary = cls["summary"]
        hosts = cls["hosts"]
        for v in values:
            if _TOKEN.match(v):
                summary["Telegram-style bot token"] = v
            elif v.startswith("<") and v.endswith(">") and len(v) <= 32:
                summary["Splitter"] = v
            elif v.lower().endswith(".exe") and "USB name" not in summary:
                summary["USB name"] = v
        summary["Mutex"] = mutex
        if not hosts:
            continue
        family = "XWorm" if any(m in data for m in _XW_MARKERS) or "Splitter" in summary else "XWorm-like RAT"
        return {"family": family, "kind": "RAT", "method": "AES-256-ECB, key MD5(mutex)", "confidence": "high",
                "summary": summary, "c2": hosts,
                "fields": {**{f"value {i + 1}": v for i, v in enumerate(values)}, "mutex (key)": mutex}}
    return None


# --- AgentTesla-style stealers -------------------------------------------------------
def agenttesla(data: bytes, strings: list[str]) -> dict[str, Any] | None:
    paths = {p for p in _STEALER_PATHS for s in strings if p.lower() in s.lower()}
    if len(paths) < 2:
        return None
    summary: dict[str, Any] = {}
    hosts: list[str] = []
    emails = [s for s in strings if _EMAIL.match(s)]
    smtp = [s for s in strings if _is_host(s) and re.match(r"^(smtp|mail|webmail|mx)\d*\.", s, re.IGNORECASE)]
    ports = [s for s in strings if s in ("25", "465", "587", "2525", "21", "990")]
    if smtp:
        summary["SMTP server"] = [f"{h}:{ports[0]}" if ports else h for h in smtp]
        hosts += smtp
    if emails:
        summary["Accounts"] = emails
    for s in strings:
        m = _BOT.search(s)
        if m:
            summary["Telegram-style bot token"] = m.group(1)
            host = re.sub(r"^https?://", "", s).split("/", 1)[0]
            if _is_host(host):
                hosts.append(host)
            summary.setdefault("Exfil URL", s)
        elif _FTP.match(s):
            summary["FTP"] = s
            host = re.sub(r"^ftp://([^@/]*@)?", "", s, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
            if _is_host(host):
                hosts.append(host)
    chat = next((s for s in strings if re.match(r"^-?\d{7,14}$", s)), None)
    if chat and "Telegram-style bot token" in summary:
        summary["Chat id"] = chat
    if not hosts and "Accounts" not in summary:
        return None
    summary["Credential sources"] = sorted(paths)
    named = b"AgentTesla" in data or b"A\x00g\x00e\x00n\x00t\x00T\x00e\x00s\x00l\x00a" in data
    return {"family": "AgentTesla" if named else "AgentTesla-like stealer", "kind": "stealer",
            "method": "plain .NET strings: exfiltration channel + credential paths",
            "confidence": "high" if named else "medium", "summary": summary,
            "c2": list(dict.fromkeys(hosts)),
            "fields": {f"string {i}": s for i, s in enumerate(strings)
                       if _printable(s) and len(s) <= 200 and (s in emails or s in smtp or "/bot" in s
                                                              or _FTP.match(s) or s == chat or s in ports)}}


# --- NanoCore (identification) ----------------------------------------------------------
def nanocore(data: bytes) -> dict[str, Any] | None:
    hits = [m.decode("latin-1") for m in _NANO_MARKERS if m in data]
    if len(hits) < 1:
        return None
    return {"family": "NanoCore", "kind": "RAT", "method": "type names: " + ", ".join(hits), "confidence": "medium",
            "summary": {"Note": "NanoCore identified; its settings are stored encrypted in a resource and are "
                                "not decrypted — analyse a memory dump of the process for the C2."},
            "c2": [], "fields": {}}


def extract_all(data: bytes) -> list[dict[str, Any]]:
    if not prefilter(data):
        return []
    strings = user_strings(data)
    out = []
    for fn in (njrat, xworm, agenttesla):
        r = fn(data, strings) if strings else None
        if r:
            out.append(r)
    if not out:
        r = nanocore(data)
        if r:
            out.append(r)
    return out

