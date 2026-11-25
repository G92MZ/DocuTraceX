"""DarkCloud (Visual Basic 6 stealer): its configuration, read statically.

DarkCloud is a VB6 native-code stealer sold by its author as a builder. The builder writes the
settings into the stub's string constants — VB6 keeps each one as a BSTR in the code section: a
DWORD byte length, the UTF-16 text and two NUL bytes — in a fixed order:

    @StrFtpUser @StrFtpPass @StrFtpServer @StrReceiver @StrSmtpUser @StrSmtpPass @StrServer
    @intSmtpPort @cboolSSL @GateUrl   <Telegram bot token> <Telegram chat id>

A channel the buyer did not set keeps its placeholder name (``@StrSmtpUser`` …): that channel is
off. Seen in builds with the strings in clear ("Agent: DARKCLOUD V5.0").

Other builds encrypt their strings with **RC4, one key per string**: a hex ciphertext next to an
alphabetic key in the same pool (Unit 42, 2025). Every hex constant is tried with the keys around
it, and what turns into text replaces it before the configuration is read.

Besides the channels it reads what the build steals (browsers, cards, mail, FTP clients,
keystrokes, clipboard, screenshots, contacts), the version, the ID it sends with its uploads, the
install path and the VB project path the author compiled it from. Nothing is run.
"""

from __future__ import annotations

import re
import struct
from typing import Any

FAMILY = "DarkCloud"
_MAX = 64 * 1024 * 1024

# the builder's placeholders, in the order of the string pool
FIELDS = (("@StrFtpUser", "FTP user"), ("@StrFtpPass", "FTP password"), ("@StrFtpServer", "FTP server"),
          ("@StrReceiver", "Mail recipient"), ("@StrSmtpUser", "SMTP user"), ("@StrSmtpPass", "SMTP password"),
          ("@StrServer", "SMTP server"), ("@intSmtpPort", "SMTP port"), ("@cboolSSL", "SMTP SSL"),
          ("@GateUrl", "Panel (gate) URL"))
_PLACEHOLDER = re.compile(r"^@(?:Str|int|cbool)[A-Z]\w{2,30}$|^@GateUrl$")
_TOKEN = re.compile(r"^\d{8,11}:AA[\w-]{30,40}$")
_CHAT = re.compile(r"^-?\d{6,15}$")
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2}){2,2048}$")
_KEY = re.compile(r"^[A-Za-z]{8,128}$")
_VERSION = re.compile(r"DARKCLOUD\s*V?(\d+(?:\.\d+)*)", re.IGNORECASE)
_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$")
_HOST = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,24}$", re.IGNORECASE)
_BENIGN_URL = ("schemas.microsoft.com", "api.telegram.org", "showip.net", "mediacollege.com", "www.w3.org",
               "schemas.openxmlformats.org")

# what the build reads, by the paths / queries in its strings
_STEALS = (
    ("browser passwords (Chromium)", ("Login Data", "origin_url, username_value, password_value")),
    ("browser passwords (Firefox family)", ("logins.json", "moz_logins", "signons.sqlite")),
    ("credit cards", ("credit_cards", "card_number_encrypted")),
    ("Outlook accounts", ("9375CFF0413111d3B88A00104B2A6676",)),
    ("Foxmail", ("Foxmail",)),
    ("Thunderbird / eM Client / MailMaster contacts", ("Contacts_Thunderbird_", "eM Client", "MailMaster")),
    ("FileZilla", ("sitemanager.xml", "recentservers.xml")),
    ("WinSCP", ("Martin Prikryl\\WinSCP",)),
    ("CoreFTP", ("COREFTP",)),
    ("Pidgin", ("Pidgin", "accounts.xml")),
    ("keystrokes", ("\\KeyData_",)),
    ("clipboard", ("[CLIPBOARD]",)),
    ("screenshots", ("Screenshot",)),
    ("machine details (WMI)", ("Win32_Processor", "Win32_ComputerSystem")),
)


def bstrs(data: bytes) -> list[str]:
    """The VB6 string constants, in file order: a DWORD byte length, then that many bytes of
    UTF-16 text, then a NUL character."""
    out: list[str] = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){2,}\x00\x00", data[:_MAX]):
        start = m.start()
        if start < 4:
            continue
        n = struct.unpack_from("<I", data, start - 4)[0]
        if n % 2 or n < 2 or start + n != m.end() - 2:
            continue
        out.append(data[start:start + n].decode("utf-16-le"))
    return out


def _rc4(key: bytes, data: bytes) -> bytes:
    from ..resolve.transforms import rc4
    return rc4(data, key)


def decrypt_pool(strings: list[str]) -> tuple[list[str], int]:
    """Hex constants decrypted with RC4 and an alphabetic key next to them (± 3 places); the keys
    that opened one are taken out, so the pool keeps the order of the plain constants."""
    out: list[str | None] = list(strings)
    used: set[int] = set()
    n = 0
    for i, s in enumerate(strings):
        if not _HEX.match(s) or len(s) < 4:
            continue
        ct = bytes.fromhex(s)
        for j in sorted(range(max(0, i - 3), min(len(strings), i + 4)), key=lambda j: (abs(j - i), -j)):
            k = strings[j]
            if j == i or not _KEY.match(k):
                continue
            pt = _rc4(k.encode(), ct)
            try:
                txt = pt.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if txt and all(31 < ord(c) < 127 or c in "\r\n\t" for c in txt):
                out[i] = txt
                used.add(j)
                n += 1
                break
    return [s for j, s in enumerate(out) if j not in used and s is not None], n


def _host_of(v: str) -> str:
    v = re.sub(r"^[a-z]+://", "", v.strip(), flags=re.IGNORECASE)
    return v.split("@")[-1].split("/")[0].split(":")[0]


def _config(pool: list[str]) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """(set fields, channels switched off, telegram [token, chat])."""
    start = next((i for i, s in enumerate(pool) if s == FIELDS[0][0]), None)
    tok_i = next((i for i, s in enumerate(pool) if _TOKEN.match(s)), None)
    if start is None and tok_i is not None:
        start = tok_i - len(FIELDS)
    values: dict[str, str] = {}
    unset: dict[str, str] = {}
    tg: list[str] = []
    if start is not None and start >= 0:
        block = pool[start:start + len(FIELDS) + 2]
        for (ph, name), v in zip(FIELDS, block):
            if v == ph or _PLACEHOLDER.match(v):
                unset[name] = v
            elif v:
                values[name] = v
        rest = block[len(FIELDS):]
        if rest and _TOKEN.match(rest[0]):
            tg = [rest[0]] + ([rest[1]] if len(rest) > 1 and _CHAT.match(rest[1]) else [])
    if not tg and tok_i is not None:
        nxt = pool[tok_i + 1] if tok_i + 1 < len(pool) else ""
        tg = [pool[tok_i]] + ([nxt] if _CHAT.match(nxt) else [])
    # a block whose slots do not have the shapes of the fields is not the configuration
    port = values.get("SMTP port")
    if port and not port.isdigit():
        values = {}
    return values, unset, tg


def _vbp(data: bytes) -> str:
    """The VB project the stub was compiled from (``*\\A<path>.vbp``, kept in the VB header)."""
    m = re.search(rb"\*\x00\\\x00A\x00((?:[\x20-\x7e]\x00){4,260}?)\.\x00v\x00b\x00p\x00", data[:_MAX], re.IGNORECASE)
    if m:
        return m.group(1).decode("utf-16-le") + ".vbp"
    m = re.search(rb"\*\\A([\x20-\x7e]{4,260}?\.vbp)", data[:_MAX], re.IGNORECASE)
    return m.group(1).decode("latin-1") if m else ""


def extract(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ" or b"MSVBVM60" not in data[:_MAX]:
        return None
    raw = bstrs(data)
    pool, n_dec = decrypt_pool(raw)
    has_ph = any(s in (FIELDS[0][0], "@GateUrl", "@StrReceiver") for s in pool)
    version = next((m.group(1) for s in pool for m in [_VERSION.search(s)] if m), "")
    if not (version or has_ph):
        return None
    values, unset, tg = _config(pool)
    summary: dict[str, Any] = {}
    c2: list[str] = []
    if version:
        summary["Version"] = f"DarkCloud {version}"
    if tg:
        summary["Telegram bot token"] = tg[0]
        if len(tg) > 1:
            summary["Telegram chat id"] = tg[1]
        c2.append("api.telegram.org")
    smtp = values.get("SMTP server")
    if smtp:
        port = values.get("SMTP port", "")
        summary["SMTP server"] = f"{smtp}:{port}" if port else smtp
        if values.get("SMTP SSL"):
            summary["SMTP SSL"] = values["SMTP SSL"]
        c2.append(_host_of(smtp))
    for k in ("SMTP user", "SMTP password", "Mail recipient"):
        if values.get(k):
            summary[k] = values[k]
    ftp = values.get("FTP server")
    if ftp:
        summary["FTP server"] = ftp
        c2.append(_host_of(ftp))
        for k in ("FTP user", "FTP password"):
            if values.get(k):
                summary[k] = values[k]
    gate = values.get("Panel (gate) URL")
    urls = [s for s in pool if re.match(r"^https?://[^\s/]+", s) and not any(b in s for b in _BENIGN_URL)]
    if gate:
        summary["Panel (gate) URL"] = gate
        c2.append(_host_of(gate))
    elif urls:
        summary["URLs"] = urls[:10]
        c2 += [_host_of(u) for u in urls[:10]]
    channels = [c for c, on in (("Telegram", bool(tg)), ("SMTP", bool(smtp)), ("FTP", bool(ftp)),
                                ("panel", bool(gate))) if on]
    summary["Exfiltration"] = ", ".join(channels) or "none set in this build"
    if unset:
        off = sorted({re.sub(r" (user|password|server|recipient|port|SSL|\(gate\) URL)$", "", k) for k in unset})
        summary["Channels not set (placeholders left by the builder)"] = ", ".join(off)
    guid = next((s for s in pool if _GUID.match(s)), "")
    if guid:
        summary["Build / victim ID (sent with the uploads)"] = guid
    install = [s for s in pool if re.search(r"\\Templates\\[^\\]+\.exe$|\\[^\\]+\.exe$", s)
               and "\\Microsoft\\Windows\\" in s]
    if install:
        summary["Install path"] = install[0]
    if any("CurrentVersion\\RunOnce" in s for s in pool):
        summary["Persistence"] = "HKCU …\\CurrentVersion\\RunOnce"
    vbp = next((s for s in pool if s.lower().endswith(".vbp")), "") or _vbp(data)
    if vbp:
        summary["VB project path (author's machine)"] = re.sub(r"^.{0,3}\*\\A", "", vbp)
    joined = "\n".join(pool)
    steals = [what for what, marks in _STEALS if any(m in joined for m in marks)]
    if steals:
        summary["Steals"] = steals
    if n_dec:
        summary["Strings decrypted (RC4, key per string)"] = n_dec
    found = bool(tg or smtp or ftp or gate)
    fields = {**{name: v for name, v in values.items()}, **({"Telegram bot token": tg[0]} if tg else {}),
              **({"Telegram chat id": tg[1]} if len(tg) > 1 else {})}
    return {"family": FAMILY, "kind": "stealer" if found else "indicators",
            "method": "VB6 string constants (BSTR pool)" + (" · RC4 per-string keys" if n_dec else "")
                      + (" · builder placeholders" if unset else ""),
            "confidence": "high" if (version and found) else ("medium" if found or version else "low"),
            "summary": summary, "c2": list(dict.fromkeys(h for h in c2 if h)), "fields": fields,
            **({"indicators": [f"DarkCloud {version}" if version else "DarkCloud builder placeholders"]}
               if not found else {}),
            **({"note": "the exfiltration goes to Telegram itself: report / block the bot, not the domain"}
               if tg and not (smtp or ftp or gate) else {})}
