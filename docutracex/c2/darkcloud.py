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

A build in another order is read by the shape of its values (an account, the value after it, an
``smtp.`` host, a port, True / False, an ``ftp://`` server, a URL); a build with neither a version
string nor placeholders is recognised by its structure (VB6, Telegram / CDO upload, keystrokes or
clipboard and three more kinds of stolen data).

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


_SHAPES: dict[str, Any] = {
    "FTP user": lambda v: bool(re.fullmatch(r"[\w.@+-]{2,64}", v)),
    "FTP password": lambda v: 1 <= len(v) <= 128,
    "FTP server": lambda v: bool(re.match(r"^(?:ftps?://)?[\w.-]+\.[a-z]{2,24}(?::\d+)?(?:/.*)?$|^\d{1,3}(?:\.\d{1,3}){3}",
                                         v, re.IGNORECASE)),
    "Mail recipient": lambda v: bool(_EMAIL.match(v)),
    "SMTP user": lambda v: bool(_EMAIL.match(v)) or bool(re.fullmatch(r"[\w.+-]{2,64}", v)),
    "SMTP password": lambda v: 1 <= len(v) <= 128,
    "SMTP server": lambda v: bool(_HOST.match(v)) or bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", v)),
    "SMTP port": lambda v: v.isdigit() and 0 < int(v) < 65536,
    "SMTP SSL": lambda v: v.lower() in ("true", "false", "1", "0"),
    "Panel (gate) URL": lambda v: bool(re.match(r"^https?://", v, re.IGNORECASE)),
}


def _positional(pool: list[str], start: int) -> tuple[dict[str, str], dict[str, str], int]:
    """The block read in the builder's order: (values, placeholders, slots that do not fit)."""
    values: dict[str, str] = {}
    unset: dict[str, str] = {}
    bad = 0
    for (ph, name), v in zip(FIELDS, pool[start:start + len(FIELDS)]):
        if v == ph or _PLACEHOLDER.match(v):
            unset[name] = v
        elif v:
            if _SHAPES[name](v):
                values[name] = v
            else:
                bad += 1
    return values, unset, bad


def _by_shape(pool: list[str], around: int) -> dict[str, str]:
    """When the order is not the known one: the values near the anchor, named by their shape. An
    account and the value right after it (its password) are kept together."""
    lo, hi = max(0, around - 25), min(len(pool), around + 26)
    win = pool[lo:hi]
    out: dict[str, str] = {}
    mails = [i for i, v in enumerate(win) if _EMAIL.match(v)]
    for k, i in enumerate(mails[:2]):
        out["SMTP user" if k == 0 else "Mail recipient"] = win[i]
        nxt = win[i + 1] if i + 1 < len(win) else ""
        if k == 0 and nxt and not (_EMAIL.match(nxt) or _HOST.match(nxt) or nxt.isdigit() or _TOKEN.match(nxt)
                                   or _PLACEHOLDER.match(nxt) or nxt.lower() in ("true", "false")):
            out["SMTP password"] = nxt
    for v in win:
        if "FTP server" not in out and re.match(r"^ftps?://|^ftp\.", v, re.IGNORECASE):
            out["FTP server"] = v
        elif "SMTP server" not in out and re.match(r"^(?:smtp|mail|smtpout|mx)\d*\.", v, re.IGNORECASE) and _HOST.match(v):
            out["SMTP server"] = v
        elif "SMTP port" not in out and v in ("25", "465", "587", "2525", "26"):
            out["SMTP port"] = v
        elif "SMTP SSL" not in out and v in ("True", "False"):
            out["SMTP SSL"] = v
        elif "Panel (gate) URL" not in out and re.match(r"^https?://", v, re.IGNORECASE) and not any(
                b in v for b in _BENIGN_URL):
            out["Panel (gate) URL"] = v
    return out


def _config(pool: list[str]) -> tuple[dict[str, str], dict[str, str], list[str], str]:
    """(set fields, channels switched off, telegram [token, chat], how it was read)."""
    start = next((i for i, s in enumerate(pool) if s == FIELDS[0][0]), None)
    tok_i = next((i for i, s in enumerate(pool) if _TOKEN.match(s)), None)
    if start is None:
        # a placeholder further down the block tells where it starts
        for k, (ph, _n) in enumerate(FIELDS):
            j = next((i for i, s in enumerate(pool) if s == ph), None)
            if j is not None:
                start = j - k
                break
    if start is None and tok_i is not None:
        start = tok_i - len(FIELDS)
    values: dict[str, str] = {}
    unset: dict[str, str] = {}
    tg: list[str] = []
    how = "builder order"
    if start is not None and start >= 0:
        values, unset, bad = _positional(pool, start)
        rest = pool[start + len(FIELDS):start + len(FIELDS) + 2]
        if rest and _TOKEN.match(rest[0]):
            tg = [rest[0]] + ([rest[1]] if len(rest) > 1 and _CHAT.match(rest[1]) else [])
        if bad:
            values, how = {}, ""
    if not tg and tok_i is not None:
        nxt = pool[tok_i + 1] if tok_i + 1 < len(pool) else ""
        prv = pool[tok_i - 1] if tok_i > 0 else ""
        tg = [pool[tok_i]] + ([nxt] if _CHAT.match(nxt) else [prv] if _CHAT.match(prv) else [])
    if not values:
        anchor = tok_i if tok_i is not None else start if start is not None else next(
            (i for i, s in enumerate(pool) if _EMAIL.match(s)), None)
        if anchor is not None:
            shaped = {k: v for k, v in _by_shape(pool, anchor).items() if k not in unset}
            if shaped:
                values, how = shaped, "by the shape of the values (not in the known builder order)"
    return values, unset, tg, how or "builder order"


def identify(data: bytes, pool: list[str]) -> tuple[str, str]:
    """(version, how it was recognised) or ("", "") — DarkCloud by its version string, its builder
    placeholders, or, when a build has neither, by its structure: a VB6 stub that uploads to
    Telegram (sendDocument) or mails through CDO and reads at least four kinds of stolen data,
    keystrokes or clipboard among them."""
    version = next((m.group(1) for s in pool for m in [_VERSION.search(s)] if m), "")
    if version:
        return version, "version string"
    if any(_PLACEHOLDER.match(s) and s in {p for p, _ in FIELDS} for s in pool):
        return "", "builder placeholders"
    joined = "\n".join(pool)
    exfil = ("sendDocument" in joined and "api.telegram.org" in joined) or "cdo/configuration/smtpserver" in joined
    steals = [w for w, marks in _STEALS if any(m in joined for m in marks)]
    spy = any(w in steals for w in ("keystrokes", "clipboard"))
    if exfil and spy and len(steals) >= 4:
        return "", "structure (VB6 stealer: Telegram / CDO upload, keystrokes / clipboard, browser and mail data)"
    return "", ""


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
    version, known_by = identify(data, pool)
    if not known_by:
        return None
    values, unset, tg, how = _config(pool)
    summary: dict[str, Any] = {}
    c2: list[str] = []
    if version:
        summary["Version"] = f"DarkCloud {version}"
    summary["Recognised by"] = known_by
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
    if found and how != "builder order":
        summary["Configuration read"] = how
    fields = {**{name: v for name, v in values.items()}, **({"Telegram bot token": tg[0]} if tg else {}),
              **({"Telegram chat id": tg[1]} if len(tg) > 1 else {})}
    return {"family": FAMILY, "kind": "stealer" if found else "indicators",
            "method": "VB6 string constants (BSTR pool)" + (" · RC4 per-string keys" if n_dec else "")
                      + (" · builder placeholders" if unset else "")
                      + (" · values named by their shape" if found and how != "builder order" else ""),
            "confidence": ("high" if (version or unset) and found and how == "builder order"
                           else "medium" if found or version else "low"),
            "summary": summary, "c2": list(dict.fromkeys(h for h in c2 if h)), "fields": fields,
            **({"indicators": [f"DarkCloud {version}" if version else f"DarkCloud ({known_by})"]}
               if not found else {}),
            **({"note": "the exfiltration goes to Telegram itself: report / block the bot, not the domain"}
               if tg and not (smtp or ftp or gate) else {})}
