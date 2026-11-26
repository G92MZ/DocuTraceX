"""Stealers and RATs common in invoice-phishing chains.

* **RedLine / META** (.NET): ``IP`` (C2, ``host:port``, several joined by
  ``|``) and ``ID`` (build tag) are ``base64( xor( base64(value), key ) )``
  with the XOR key a plain string of the same class; with dnfile + dncil the
  settings class names them (IP, ID, Message, Key), read through the common
  family layer. Traces when nothing decrypts.
* **Snake Keylogger / 404** (.NET): strings DES-ECB encrypted with
  ``MD5(key string)[:8]``, base64; exfiltration over SMTP / FTP / Telegram,
  read into the common family card (server, port, sender / receiver, the
  password by position, bot token / chat). Traces when nothing decrypts.
* **Raccoon Stealer v2** (native): strings ``base64( RC4(key, value) )`` with
  the RC4 key a plain string in the binary; the C2 is an ``http(s)://`` URL
  (all of them), with the request fields, a 32-hex config ID when present and
  the user agent; the rest of the configuration comes from the C2. Traces when
  nothing decrypts.
* **Warzone / AveMaria** (native): ``.bss`` section = ``[key length DWORD]
  [RC4 key][RC4(config)]``; config = ``[host length DWORD][host UTF-16][port]``
  then the builder options (shown raw: their layout changes between
  versions); the version from ``warzoneNNN``; traces when nothing decrypts.
* **DarkGate**: settings base64-encoded with a *custom alphabet* (a 64-char
  permutation of the standard one stored in the binary / script).

Every one tries each candidate key it finds and only reports values that
decrypt into something meaningful (a C2 endpoint, an account), so a wrong key
gives nothing rather than noise.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from typing import Any

from . import familyspec
from .dotnet_more import _BOT, _EMAIL, _FTP, _TOKEN
from .dotnet_rats import _b64, _is_host, settings_fields, user_strings
from .remcos import rc4

_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_HOSTPORT = re.compile(r"^((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
_URL = re.compile(r"^https?://([A-Za-z0-9.\-]+)(?::(\d{1,5}))?(/\S*)?$")
_ASCII = re.compile(rb"[\x20-\x7e]{6,512}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){6,512}")


def _printable(s: str) -> bool:
    return bool(s) and all(c.isprintable() for c in s)


def native_strings(data: bytes, limit: int = 4000) -> list[str]:
    out = [m.group(0).decode("ascii") for m in _ASCII.finditer(data)]
    out += [m.group(0).decode("utf-16-le") for m in _WIDE.finditer(data)]
    return list(dict.fromkeys(out))[:limit]


def _hostport(v: str) -> tuple[str, str] | None:
    m = _HOSTPORT.match(v.strip())
    if m and _is_host(m.group(1)) and 0 < int(m.group(2)) < 65536:
        return m.group(1), m.group(2)
    return None


def _url_host(v: str) -> str | None:
    m = _URL.match(v.strip())
    return m.group(1) if m and _is_host(m.group(1)) else None


# --- RedLine / META --------------------------------------------------------------------
def _redline_dec(value: str, key: str) -> str | None:
    raw = _b64(value)
    if not raw:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    x = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s))
    inner = _b64(x) if len(x) >= 4 else None
    if not inner:
        return None
    try:
        out = inner.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return out if _printable(out) else None


REDLINE = familyspec.Spec(
    family="RedLine Stealer",
    fields={"ip": "hosts", "id": "group", "message": "message", "key": "xor_key", "version": "version"},
    options={"message": ("value", 'shows a fake error message: "{v}"')},
    traces=((b"RedLine", "RedLine strings"), (b"R\x00e\x00d\x00L\x00i\x00n\x00e", "RedLine strings"),
            (b"StringDecrypt", "class StringDecrypt"), (b"ScanningArgs", "type ScanningArgs"),
            (b"ScanResult", "type ScanResult"), (b"net.tcp://", "WCF net.tcp channel"),
            (b"n\x00e\x00t\x00.\x00t\x00c\x00p\x00:\x00/\x00/", "WCF net.tcp channel"),
            (b"Login Data", "browser credential theft"), (b"wallet", "crypto-wallet theft")),
    min_traces=3)


def _redline_named(data: bytes, decrypted: dict[str, str]) -> tuple[dict[str, str], str]:
    names, cls_name = settings_fields(data)
    named: dict[str, str] = {}
    for lit, fields in names.items():
        for f in fields:
            named.setdefault(f, decrypted.get(lit, lit))
    return (named, cls_name) if familyspec.known(REDLINE, named) else ({}, "")


def redline(data: bytes, strings: list[str]) -> dict[str, Any] | None:
    enc = [s for s in strings if _b64(s)]
    if not enc:
        return redline_traces(data)
    cand = [s for s in strings if 3 <= len(s) <= 64 and _printable(s)]
    # a key of letters only can look like base64 ("Pedestal"): try those last, never skip them
    keys = ([s for s in cand if s not in enc] + [s for s in cand if s in enc])[:80]
    for key in keys:
        decrypted = {s: v for s in enc for v in [_redline_dec(s, key)] if v}
        values = list(decrypted.values())
        c2 = [hp for v in values for part in v.split("|") for hp in [_hostport(part)] if hp]
        if not c2:
            continue
        named = b"RedLine" in data or b"R\x00e\x00d\x00L\x00i\x00n\x00e" in data
        meta = (b"META" in data or b"M\x00E\x00T\x00A" in data) and not named
        fam = "RedLine Stealer" if named or not meta else "META Stealer"
        fields_named, cls_name = _redline_named(data, decrypted)
        if fields_named:
            summary, _ = familyspec.interpret(REDLINE, {k: v for k, v in fields_named.items()
                                                       if k.lower() != "key"})
            if "Group" in summary:
                summary["Build ID"] = summary.pop("Group")
            summary["XOR key"] = key
            fields = {**fields_named, "Settings class": cls_name}
            how = f"base64 + XOR(key) + base64 — settings named from {cls_name or 'the settings class'}"
        else:
            summary = {"C2": [f"{h}:{p}" for h, p in c2]}
            build = next((v for v in values if not any(_hostport(p) for p in v.split("|"))), "")
            if build:
                summary["Build ID"] = build
            summary["XOR key"] = key
            fields = {f"value {i + 1}": v for i, v in enumerate(values)}
            how = "base64 + XOR(key) + base64 (.NET strings)"
        summary["Note"] = ("the C2 is a WCF (net.tcp) panel: the stealer asks it what to collect, so the targets "
                           "are not in the file")
        return {"family": fam, "kind": "stealer", "method": how, "confidence": "high", "summary": summary,
                "c2": list(dict.fromkeys(h for h, _ in c2)),
                "fields": fields if fields_named else {**fields, "key": key}}
    return redline_traces(data)


def redline_traces(data: bytes) -> dict[str, Any] | None:
    r = familyspec.traces(REDLINE, data)
    if r and not any("RedLine" in i for i in r["indicators"]) and b"META" in data:
        r = familyspec.traces(REDLINE, data, "META Stealer")
    return r


# --- Snake Keylogger -------------------------------------------------------------------
def _des_ecb(key8: bytes, ct: bytes) -> str | None:
    try:
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:  # older cryptography
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        d = Cipher(TripleDES(key8 * 3), modes.ECB()).decryptor()
        pt = d.update(ct) + d.finalize()
    except Exception:  # noqa: BLE001
        return None
    pad = pt[-1] if pt else 0
    if not 1 <= pad <= 8 or pt[-pad:] != bytes([pad]) * pad:
        return None
    try:
        s = pt[:-pad].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if _printable(s) else None


_SNAKE_ROLES = ("smtp_server", "smtp_port", "smtp_user", "smtp_password", "smtp_to", "ftp_server", "ftp_user",
                "ftp_password", "telegram_token", "telegram_chat")
SNAKE = familyspec.Spec(
    family="Snake Keylogger", fields={r: r for r in _SNAKE_ROLES},
    traces=((b"S\x00n\x00a\x00k\x00e\x00 \x00K\x00e\x00y\x00l\x00o\x00g\x00g\x00e\x00r", "Snake Keylogger banner"),
            (b"Snake Keylogger", "Snake Keylogger banner"), (b"KeyLoggerEventArgs", "type KeyLoggerEventArgs"),
            (b"DESCryptoServiceProvider", "DES string decryption"), (b"MD5CryptoServiceProvider", "MD5 key derivation"),
            (b"SmtpClient", "SMTP exfiltration"), (b"encryptedPassword", "browser credential theft"),
            (b"Login Data", "browser credential theft")),
    min_traces=4)
_PORTS = ("25", "465", "587", "2525", "21", "990")
_CHAT = re.compile(r"^-?\d{7,14}$")


def _snake_roles(values: list[str]) -> dict[str, str]:
    """Decrypted values (in the order the settings class sets them) → exfiltration roles.

    The builder keeps sender, password, SMTP server, receiver, port together; the
    password is the value right after the sender that is nothing else (by position)."""
    def other(v: str) -> bool:
        return not (_EMAIL.match(v) or _is_host(v) or v in _PORTS or _TOKEN.match(v) or _CHAT.match(v)
                    or _FTP.match(v) or _BOT.search(v) or "snake" in v.lower() or "---" in v or len(v) > 64)
    g: dict[str, str] = {}
    emails = [v for v in values if _EMAIL.match(v)]
    if emails:
        g["smtp_user"] = emails[0]
        g["smtp_to"] = emails[1] if len(emails) > 1 else emails[0]
        i = values.index(emails[0])
        if i + 1 < len(values) and other(values[i + 1]):
            g["smtp_password"] = values[i + 1]
    for v in values:
        if _is_host(v) and re.match(r"^(smtp|mail|webmail|mx)\d*\.", v, re.IGNORECASE):
            g.setdefault("smtp_server", v)
        elif v in _PORTS and v not in ("21", "990"):
            g.setdefault("smtp_port", v)
        elif _TOKEN.match(v):
            g.setdefault("telegram_token", v)
        elif _BOT.search(v):
            g.setdefault("telegram_token", _BOT.search(v).group(1))
        elif _CHAT.match(v):
            g.setdefault("telegram_chat", v)
        elif _FTP.match(v):
            g.setdefault("ftp_server", v)
            j = values.index(v)
            rest = [x for x in values[j + 1:j + 3] if other(x)]
            if rest:
                g.setdefault("ftp_user", rest[0])
            if len(rest) > 1:
                g.setdefault("ftp_password", rest[1])
    if "smtp_user" in g and "smtp_server" not in g:
        # a hosting server's name (not smtp. / mail.): the host the builder keeps beside the sender's account
        hosts = [v for v in values if _is_host(v) and not _EMAIL.match(v) and not _FTP.match(v)]
        if hosts:
            g["smtp_server"] = hosts[0]
    return g


def snake(data: bytes, strings: list[str]) -> dict[str, Any] | None:
    enc = [(s, b) for s in strings for b in [_b64(s)] if b and len(b) % 8 == 0]
    if len(enc) < 2:
        return snake_traces(data)
    cand = [s for s in strings if 8 <= len(s) <= 128 and _printable(s)]
    # the key string is usually not base64, but a key of letters only can be: try those last
    keys = ([s for s in cand if not _b64(s)] + [s for s in cand if _b64(s)])[:80]
    for key in keys:
        k8 = hashlib.md5(key.encode("utf-8")).digest()[:8]
        values = [v for _, b in enc for v in [_des_ecb(k8, b)] if v]
        if len(values) < 2:
            continue
        g = _snake_roles(values)
        if not any(r in g for r in ("smtp_server", "smtp_user", "telegram_token", "ftp_server")):
            continue
        summary, hosts = familyspec.interpret(SNAKE, g)
        channels = [c for c, r in (("SMTP", "smtp_user"), ("FTP", "ftp_server"), ("Telegram", "telegram_token"))
                    if g.get(r)]
        banner = next((v for v in values if "snake" in v.lower() and not _TOKEN.match(v) and not _BOT.search(v)), "")
        summary = {"Channel": channels, **summary}
        if banner:
            summary["Banner"] = banner.strip("- ")
        if g.get("smtp_password"):
            summary["Note"] = "the SMTP password is taken by its position after the sender account"
        named = bool(banner) or b"Snake" in data
        labels = {r: familyspec.EXFIL[r][0] for r in g}
        return {"family": "Snake Keylogger" if named else "Snake-like keylogger", "kind": "stealer",
                "method": f"DES-ECB, key MD5(string)[:8] (.NET strings) — {len(values)} values decrypted",
                "confidence": "high" if named else "medium", "summary": summary,
                "c2": hosts,
                "fields": {**{f"value {i + 1}": v for i, v in enumerate(values)},
                           **{f"{labels[r]} (role)": v for r, v in g.items()}, "key string": key}}
    return snake_traces(data)


def snake_traces(data: bytes) -> dict[str, Any] | None:
    return familyspec.traces(SNAKE, data)


# --- Raccoon Stealer v2 ------------------------------------------------------------------
def _ksa(key: bytes) -> list[int]:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def _rc4_prefix(ksa: list[int], data: bytes, n: int) -> bytes:
    s = ksa[:]
    i = j = 0
    out = bytearray()
    for c in data[:n]:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

RACCOON = familyspec.Spec(
    family="Raccoon Stealer v2", fields={},
    traces=((b"nss3.dll", "nss3.dll (Firefox credential decryption)"), (b"sqlite3.dll", "sqlite3.dll (browser databases)"),
            (b"mozglue.dll", "mozglue.dll"), (b"softokn3.dll", "softokn3.dll"), (b"freebl3.dll", "freebl3.dll"),
            (b"wallet.dat", "wallet.dat (crypto wallets)"), (b"\\Local State", "browser Local State key"),
            (b"machineId=", "machineId= request field"), (b"configId=", "configId= request field")),
    min_traces=4)
_HEX32 = re.compile(r"^[0-9a-f]{32}$")


# --- StealC / Vidar (same string protection as Raccoon v2: base64 + RC4, key in the binary) ---------
_STEALC_GATE = re.compile(r"^/[0-9a-f]{16}\.php$")
_DEAD_DROP = re.compile(r"^https?://(?:t\.me/[A-Za-z0-9_]{3,64}|telegram\.me/[A-Za-z0-9_]{3,64}|"
                        r"steamcommunity\.com/(?:profiles/\d{10,20}|id/[A-Za-z0-9_-]{2,64}))/?$")


def _stealc_vidar(key: str, values: list[str], urls: list[str], strings: list[str],
                  data: bytes) -> dict[str, Any] | None:
    """StealC: the C2 host and its gate (/<16 hex>.php) among the decrypted strings.
    Vidar: the C2 is fetched from a dead drop (a Telegram channel or a Steam profile whose
    name holds it) — the profile URLs are among the decrypted strings."""
    gates = [v for v in values if _STEALC_GATE.match(v)]
    drops = [v for v in values if _DEAD_DROP.match(v)]
    hosts = [u for u in urls if not _DEAD_DROP.match(u)]
    browser = [what for needle, what in RACCOON.traces[:7] if needle in data]
    if gates and hosts:
        c2 = [u.rstrip("/") + gates[0] for u in hosts]
        summary: dict[str, Any] = {"C2": c2, "Gate": gates[0], "RC4 key": key}
        if browser:
            summary["Traces"] = browser
        summary["Note"] = ("StealC asks the gate for its configuration (what to steal, the DLLs to download) when it "
                           "checks in: it is not in the file")
        return {"family": "StealC", "kind": "stealer", "method": "base64 + RC4 with a key string from the binary",
                "confidence": "high", "summary": summary,
                "c2": list(dict.fromkeys(h for u in hosts for h in [_url_host(u)] if h)),
                "fields": {f"value {i + 1}": v for i, v in enumerate(values[:60])}}
    if drops:
        summary = {"Dead drop": drops, "RC4 key": key}
        if hosts:
            summary["Other URLs"] = hosts
        if browser:
            summary["Traces"] = browser
        summary["Note"] = ("Vidar reads its C2 from the dead drop (the Telegram channel's description or the Steam "
                           "profile's name): open it with a network check to see the current C2")
        return {"family": "Vidar", "kind": "stealer", "method": "base64 + RC4 with a key string from the binary",
                "confidence": "medium" if browser else "low", "summary": summary,
                "c2": list(dict.fromkeys(h for u in hosts for h in [_url_host(u)] if h)),
                "dead_drop": drops,
                "fields": {f"value {i + 1}": v for i, v in enumerate(values[:60])}}
    return None


# Vidar builds that keep their strings in clear: the dead drops next to the build's own markers
_VIDAR_MARKS = (b"information.txt", b"Work Dir: In memory", b"build_id", b"file_data", b"passwords.txt",
                b"Soft: WinSCP", b"Soft: FileZilla", b"\\Autofill\\", b"\\CC\\", b"[Hardware]", b"[Processes]")
_VIDAR_UA = re.compile(r"^Mozilla/5\.0 \(Windows NT [^)]+\) AppleWebKit/[\d.]+ \(KHTML, like Gecko\) .{10,120}$")


def vidar_plain(data: bytes) -> dict[str, Any] | None:
    """Vidar with its strings in clear (unpacked builds): its dead drops — a Telegram channel and a Steam
    profile whose name / description holds the C2 — beside at least three of the build's own markers
    (``information.txt``, ``Work Dir: In memory``, ``build_id``, ``file_data``, ``Soft: WinSCP``…). The
    32-hex profile / build key and the user agent it sends are kept too."""
    if data[:2] != b"MZ":
        return None
    marks = [m.decode() for m in _VIDAR_MARKS if m in data]
    if len(marks) < 3:
        return None
    strings = native_strings(data)
    drops = list(dict.fromkeys(s.rstrip("/") for s in strings if _DEAD_DROP.match(s)))
    if not drops:
        return None
    idx = {s: i for i, s in enumerate(strings)}
    near = {j for d in drops for i in [idx.get(d, idx.get(d + "/", -99))] for j in range(i - 3, i + 4)}
    keys = [strings[j] for j in sorted(near) if 0 <= j < len(strings) and re.fullmatch(r"[0-9a-f]{32}", strings[j])]
    ua = next((s for s in strings if _VIDAR_UA.match(s)), "")
    summary: dict[str, Any] = {"Dead drop": drops}
    if keys:
        summary["Profile / build key"] = keys[0]
    if ua:
        summary["User agent"] = ua
    summary["Markers"] = marks
    summary["Note"] = ("Vidar reads its C2 from the dead drop (the Telegram channel's description or the Steam "
                       "profile's name): open it with a network check to see the current C2")
    return {"family": "Vidar", "kind": "stealer", "method": "strings in clear: dead drops + the build's markers",
            "confidence": "high" if len(marks) >= 4 else "medium", "summary": summary,
            "c2": [], "dead_drop": drops,
            "fields": {**{f"dead drop {i + 1}": d for i, d in enumerate(drops)},
                       **({"key": keys[0]} if keys else {}), **({"user agent": ua} if ua else {})}}


_STEALC2_KEYS = ("opcode", "access_token", "self_delete", "take_screenshot", "steal_steam", "steal_discord",
                  "steal_outlook", "loader_id", "upload_file", "parse_cookies", "use_v20")


def _stealc_v2(key: str, values: list[str], urls: list[str]) -> dict[str, Any] | None:
    """StealC v2 (2025): the same base64 + RC4 strings, but a JSON protocol instead of the ``.php`` gate —
    its request / task keys (``opcode``, ``access_token``, ``steal_steam``, ``loader_id``…) among them."""
    keys = [v for v in values if v in _STEALC2_KEYS]
    if len(keys) < 4:
        return None
    build = next((v for v in values if re.fullmatch(r"[A-Za-z0-9]{14,32}", v) and v != key
                  and any(c.isdigit() for c in v) and any(c.isupper() for c in v)), "")
    tasks = [v for v in values if v.startswith(("steal_", "take_", "self_delete", "loader", "run_as_admin"))]
    summary: dict[str, Any] = {"C2": list(dict.fromkeys(urls)), "RC4 key": key}
    if build:
        summary["Build ID (probably)"] = build
    if tasks:
        summary["Tasks it accepts"] = tasks
    summary["Protocol"] = "JSON (StealC v2): " + ", ".join(keys[:8])
    summary["Note"] = ("the C2 sends what to steal (browsers, wallets, plugins, files) and what to load next when the "
                       "stealer checks in: it is not in the file")
    return {"family": "StealC", "kind": "stealer", "method": "base64 + RC4 with a key string from the binary (v2)",
            "confidence": "high", "summary": summary,
            "c2": list(dict.fromkeys(h for u in urls for h in [_url_host(u)] if h)),
            "fields": {f"value {i + 1}": v for i, v in enumerate(values[:60])}}


def _decimal_ip(url: str) -> str:
    """``http://3405803823:80/`` (an IPv4 written as one number) → the dotted address beside it."""
    m = re.match(r"^(https?://)(\d{8,10})((?::\d+)?(?:/.*)?)$", url)
    if not m or int(m.group(2)) > 0xFFFFFFFF:
        return url
    n = int(m.group(2))
    return f"{m.group(1)}{n >> 24}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}{m.group(3)}"


# strings every build of these stealers encrypts: known plaintext to recover a fixed RC4 keystream
_KNOWN = (b"kernel32.dll", b"advapi32.dll", b"GetProcAddress", b"LoadLibraryA", b"ExitProcess", b"ntdll.dll",
          b"user32.dll", b"crypt32.dll", b"shell32.dll", b"wininet.dll", b"sqlite3.dll", b"nss3.dll")
_LONG = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
         b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
         b"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
         b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
         b"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
         b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/")


def _keystream(enc: list[tuple[str, bytes]]) -> bytes | None:
    """RC4 with one key gives one keystream for every string: when the key itself is not a readable string
    of the binary, guess a string the stealer always carries (``kernel32.dll``…), keep the keystream that
    turns most of the others into text, and lengthen it with a longer one (the base64 alphabet…)."""
    blobs = [b for _, b in enc]
    best: tuple[int, bytes] = (0, b"")
    for c in blobs[:300]:
        for guess in _KNOWN:
            if len(c) != len(guess):
                continue
            ks = bytes(x ^ y for x, y in zip(c, guess))
            ok = sum(1 for d in blobs if len(d) >= 4 and all(32 <= (d[i] ^ ks[i]) < 127 for i in range(min(len(d), len(ks)))))
            if ok > best[0]:
                best = (ok, ks)
    if best[0] < max(10, len(blobs) // 4):
        return None
    ks = best[1]
    for _ in range(3):
        grown = False
        for c in blobs:
            if len(c) <= len(ks):
                continue
            head = bytes(x ^ y for x, y in zip(c, ks))
            for long in _LONG:
                if len(long) == len(c) and long.startswith(head):
                    ks = bytes(x ^ y for x, y in zip(c, long))
                    grown = True
                    break
        if not grown:
            break
    return ks


def _values_with(enc: list[tuple[str, bytes]], dec: Any) -> list[str]:
    values = []
    for _, b in enc:
        pt = dec(b)
        if pt is None:
            continue
        try:
            v = pt.decode("ascii")
        except UnicodeDecodeError:
            continue
        if _printable(v):
            values.append(v)
    return values


def raccoon(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ":
        return None
    strings = [s for s in native_strings(data) if len(s) <= 256]
    enc = [(s, b) for s in strings for b in [_b64(s)] if b and 4 <= len(b) <= 512][:600]
    if not enc:
        return raccoon_traces(data)
    # the key is a plain string of the binary — often alphanumeric, so it may also look like base64
    keys = sorted((s for s in strings if 6 <= len(s) <= 64), key=lambda k: bool(_b64(k)))[:4000]
    for key in keys:
        kb = key.encode("latin-1")
        ksa = _ksa(kb)
        if not any(_rc4_prefix(ksa, b, 4) in (b"http", b"HTTP") for _, b in enc):
            continue                                    # cheap probe: no URL with this key
        got = _from_values(key, f"key '{key}'", _values_with(enc, lambda b, kb=kb: rc4(kb, b)), strings, data)
        if got:
            return got
    ks = _keystream(enc)
    if ks:
        got = _from_values("", "keystream recovered from known strings (the key is not stored as text)",
                           _values_with(enc, lambda b: bytes(x ^ y for x, y in zip(b, ks)) if len(b) <= len(ks) else None),
                           strings, data)
        if got:
            got["method"] = "base64 + RC4 (fixed keystream recovered from strings every build carries)"
            return got
    return raccoon_traces(data)


def _from_values(key: str, key_label: str, values: list[str], strings: list[str], data: bytes) -> dict[str, Any] | None:
    values = [_decimal_ip(v) for v in values]
    urls = [v for v in values if _url_host(v)]
    if not urls:
        return None
    markers = [v for v in values if v.startswith(("machineId=", "configId=", "&configId="))]
    other = _stealc_vidar(key or key_label, values, urls, strings, data)
    if other and not markers:
        return other
    v2 = _stealc_v2(key or key_label, values, urls)
    if v2 and not markers:
        return v2
    fam = "Raccoon Stealer v2" if markers else "RC4-encrypted C2 (Raccoon-like)"
    summary: dict[str, Any] = {"C2": list(dict.fromkeys(urls)), "RC4 key": key or key_label}
    build = [s for s in strings if _HEX32.match(s)]
    if build and markers:
        summary["Config ID (probably)"] = build[0]
    if markers:
        summary["Request fields"] = markers
    ua = next((v for v in values if v.startswith("Mozilla/") or v.lower().startswith("user-agent")), "")
    if ua:
        summary["User agent"] = ua
    hits = list(dict.fromkeys(what for needle, what in RACCOON.traces if needle in data))
    if hits:
        summary["Traces"] = hits
    summary["Note"] = ("the C2 sends the real configuration when the stealer checks in (what to steal, the DLLs "
                       "to download, file grabbers): it is not in the file")
    return {"family": fam, "kind": "stealer", "method": "base64 + RC4 with a key string from the binary",
            "confidence": "high" if markers else "medium", "summary": summary,
            "c2": list(dict.fromkeys(h for u in urls for h in [_url_host(u)] if h)),
            "fields": {f"value {i + 1}": v for i, v in enumerate(values[:60])}}


def raccoon_traces(data: bytes) -> dict[str, Any] | None:
    """Indicators only — and only with Raccoon's own request fields: the browser DLLs alone are shared by
    many stealers (Vidar, StealC…) and would name the wrong family."""
    if b"machineId=" not in data and b"configId=" not in data:
        return None
    return familyspec.traces(RACCOON, data)


# --- Warzone / AveMaria --------------------------------------------------------------------
def _bss(data: bytes) -> bytes | None:
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
    except Exception:  # noqa: BLE001
        return None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".bss":
            return s.get_data()
    return None


WARZONE = familyspec.Spec(
    family="Warzone / AveMaria", fields={},
    traces=((b"Ave_Maria", "Ave_Maria string"), (b"A\x00v\x00e\x00_\x00M\x00a\x00r\x00i\x00a", "Ave_Maria string"),
            (b"warzone", "warzone version string"), (b"w\x00a\x00r\x00z\x00o\x00n\x00e", "warzone version string"),
            (b"Elevation:Administrator!new:", "UAC bypass moniker"),
            (b"E\x00l\x00e\x00v\x00a\x00t\x00i\x00o\x00n\x00:\x00A\x00d\x00m\x00i\x00n", "UAC bypass moniker"),
            (b"_rptls", "registry key _rptls"), (b"_\x00r\x00p\x00t\x00l\x00s", "registry key _rptls"),
            (b"rdpwrap", "hidden RDP (rdpwrap)"), (b"r\x00d\x00p\x00w\x00r\x00a\x00p", "hidden RDP (rdpwrap)")),
    min_traces=3)
_WZ_VERSION = re.compile(rb"w(?:\x00)?a(?:\x00)?r(?:\x00)?z(?:\x00)?o(?:\x00)?n(?:\x00)?e(?:\x00)?((?:\d(?:\x00)?){2,4})")


def warzone(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ":
        return None
    res = _warzone_config(data) if b".bss" in data[:0x400] else None
    if res is None:
        return familyspec.traces(WARZONE, data)
    m = _WZ_VERSION.search(data)
    if m:
        digits = m.group(1).replace(b"\x00", b"").decode()
        res["summary"] = {"Version": f"{digits[0]}.{digits[1:]}", **res["summary"]}
    hits = [what for needle, what in WARZONE.traces if needle in data]
    if hits:
        res["summary"]["Traces"] = list(dict.fromkeys(hits))
    return res


def _warzone_config(data: bytes) -> dict[str, Any] | None:
    blob = _bss(data)
    if not blob or len(blob) < 16:
        return None
    klen = struct.unpack_from("<I", blob, 0)[0]
    if not 4 <= klen <= 256 or 4 + klen + 8 > len(blob):
        return None
    cfg = rc4(blob[4:4 + klen], blob[4 + klen:4 + klen + 2048])
    hlen = struct.unpack_from("<I", cfg, 0)[0]
    if not 2 <= hlen <= 512 or hlen % 2 or 4 + hlen + 2 > len(cfg):
        return None
    try:
        host = cfg[4:4 + hlen].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    port = struct.unpack_from("<H", cfg, 4 + hlen)[0]
    if not _is_host(host) or not port:
        return None
    rest = cfg[4 + hlen + 2:4 + hlen + 2 + 256]
    gap = re.search(rb"\x00{16,}", rest)             # the options end where the zero padding starts
    rest = (rest[:gap.start()] if gap else rest[:64]).rstrip(b"\x00")
    return {"family": "Warzone / AveMaria", "kind": "RAT", "method": f".bss: RC4 (key {klen} bytes)",
            "confidence": "high",
            "summary": {"C2": [f"{host}:{port}"], "RC4 key": blob[4:4 + klen].hex(),
                        "Note": "the bytes after the port hold the builder options (install, startup, "
                                "offline keylogger, hidden RDP…); their layout changes between versions, "
                                "so they are shown raw"},
            "c2": [host],
            "fields": {"host": host, "port": str(port), "key": blob[4:4 + klen].hex(),
                       **({"options (raw)": rest.hex()} if rest else {})}}


# --- DarkGate --------------------------------------------------------------------------------
_ALPHA = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{64,65}(?![A-Za-z0-9+/=])")


def _custom_b64(s: str, alphabet: str) -> bytes | None:
    table = str.maketrans(alphabet[:64], _STD)
    try:
        return base64.b64decode(s.translate(table) + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def darkgate(data: bytes) -> dict[str, Any] | None:
    alphabets = []
    for m in _ALPHA.finditer(data):
        a = m.group(0).decode()[:64]
        if len(set(a)) == 64 and set(a) <= set(_STD) and a != _STD:
            alphabets.append(a)
    if not alphabets:
        return None
    strings = [s for s in native_strings(data) if 8 <= len(s) <= 2048 and re.match(r"^[A-Za-z0-9+/=]+$", s)]
    for alpha in alphabets[:4]:
        values = []
        for s in strings:
            if s.startswith(alpha[:20]):
                continue
            b = _custom_b64(s, alpha)
            if not b:
                continue
            try:
                v = b.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if _printable(v.replace("\r", "").replace("\n", "")):
                values.append(v)
        urls, hosts = [], []
        for v in values:
            for part in re.split(r"[\r\n|,]+", v):
                part = part.strip()
                if "=" in part and part.split("=", 1)[0].isdigit():
                    part = part.split("=", 1)[1]
                h = _url_host(part)
                if h:
                    urls.append(part)
                    hosts.append(h)
        if not urls:
            continue
        return {"family": "DarkGate", "kind": "loader", "method": "base64 with a custom alphabet",
                "confidence": "medium", "summary": {"C2": list(dict.fromkeys(urls)), "Alphabet": alpha},
                "c2": list(dict.fromkeys(hosts)),
                "fields": {f"value {i + 1}": v[:300] for i, v in enumerate(values[:40])}}
    return None


# --- Discord-webhook exfiltration (token grabbers, small stealers) ------------------------
_WEBHOOK = re.compile(rb"https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d{15,21}/[A-Za-z0-9_-]{60,70}")
_GRABBER = ((b"leveldb", "Discord / browser LevelDB"), (b"Login Data", "browser passwords"),
            (b"Local State", "browser master key"), (b"Cookies", "browser cookies"), (b"wallet", "wallets"),
            (b"Discord Tokens", "Discord tokens"), (b"[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}", "Discord token regex"),
            (b"mfa\\.[\\w-]{84}", "Discord MFA token regex"))
_STEALER_NAME = re.compile(r"\b([A-Z][A-Za-z0-9]{2,24}(?:Stealer|Grabber|Logger))\b")


def discord_webhook(data: bytes) -> dict[str, Any] | None:
    """A Discord webhook written in the binary (ASCII or UTF-16): where a token
    grabber / small stealer posts what it took. The webhook URL is the
    indicator (and what to report to Discord to have it removed)."""
    hooks: list[str] = []
    for blob in (data, data.replace(b"\x00", b"")):
        hooks += [m.group(0).decode("ascii") for m in _WEBHOOK.finditer(blob)]
    hooks = list(dict.fromkeys(hooks))
    if not hooks:
        return None
    flat = data.replace(b"\x00", b"")
    traits = list(dict.fromkeys(label for needle, label in _GRABBER if needle in flat))
    name = next((m.group(1) for st in native_strings(data) for m in [_STEALER_NAME.search(st)] if m), "")
    family = name or ("Discord-webhook stealer" if traits else "Discord webhook")
    summary: dict[str, Any] = {"Channel": ["Discord webhook"], "Webhook": hooks}
    if traits:
        summary["Steals"] = traits[:8]
    return {"family": family, "kind": "stealer" if traits else "indicators",
            "method": "Discord webhook URL in the strings" + (f" + {len(traits)} grabber trait(s)" if traits else ""),
            "confidence": "high" if traits else "medium", "summary": summary, "c2": hooks,
            "fields": {**{f"webhook {i + 1}": h for i, h in enumerate(hooks)},
                       **({"name in the binary": name} if name else {})},
            "note": "the exfiltration channel is Discord itself: block / report the webhook URL, not the domain"}


def extract_all(data: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if data[:2] == b"MZ" and b"BSJB" in data:
        strings = user_strings(data)
        found = [r for fn in (redline, snake) for r in [fn(data, strings) if strings else None] if r]
        # a decrypted configuration wins over another family's traces
        best = next((r for r in found if r.get("kind") != "indicators"), found[0] if found else None)
        if best:
            out.append(best)
    else:
        found = [r for fn in (warzone, raccoon, vidar_plain) for r in [fn(data)] if r]
        best = next((r for r in found if r.get("kind") != "indicators"), found[0] if found else None)
        if best:
            out.append(best)
    if not out:
        r = darkgate(data)
        if r:
            out.append(r)
    if not out or all(r.get("kind") == "indicators" for r in out):
        r = discord_webhook(data)
        if r:
            out.append(r)
    return out
