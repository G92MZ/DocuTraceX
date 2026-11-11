"""Embedded resources of a binary, found statically (Go phase 6).

* ``go:embed`` file systems: ``embed.FS`` points at a ``[]file`` whose entries
  are ``{name string; data string; hash [16]byte}``; the slice header and the
  entries are found in the data sections and every file is recovered.
* Certificates and keys: PEM blocks and DER X.509 certificates (parsed when
  ``cryptography`` is available).
* Compressed data: gzip / zlib / xz / zstd / bzip2 streams that really
  decompress.
* Scripts and templates held as string literals (not in an embed.FS):
  PowerShell, batch, shell, VBScript, JScript, Python, AppleScript and Go
  ``text/template`` / ``html/template`` text in the read-only data, carved so
  the nested analysis runs the script engines on them.
* Go dependencies: modules declared in BuildInfo versus the packages that
  actually have functions in pclntab, notable third-party modules and the
  standard-library packages that say what the binary can do.

Nothing is executed; every item keeps its file offset (Hex tab) and source.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
import zlib
from typing import Any

MAX_EMBED_FILES = 500
MAX_EMBED_BYTES = 32 * 1024 * 1024
MAX_ITEMS = 200
_NAME_OK = re.compile(rb"^[\w.\-/ @+~=,()\[\]]+$")
_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----[\r\n]+([A-Za-z0-9+/=\r\n]{16,65536}?)-----END \1-----")


def _read(data: bytes, binf, va: int, n: int) -> bytes | None:
    off = binf.va_to_off(va)
    if off is None or n < 0 or off + n > len(data):
        return None
    return data[off:off + n]


def go_embed(data: bytes, binf) -> list[dict[str, Any]]:
    """Files of every embed.FS: [{fs_va, files: [{name, size, offset, sha256, data}]}]."""
    ps = 8 if binf.bits == 64 else 4
    en = ">" if binf.big_endian else "<"
    ent = 4 * ps + 16
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    secs = [s for s in binf.sections if s.size and s.offset and s.name not in (".text", "__text", ".gopclntab")]
    for s in secs:
        blob = data[s.offset:s.offset + s.size]
        for i in range(0, len(blob) - 3 * ps, ps):
            ptr, ln, cap = struct.unpack_from(en + ("QQQ" if ps == 8 else "III"), blob, i)
            if not (0 < ln <= MAX_EMBED_FILES and ln == cap) or ptr in seen:
                continue
            arr = _read(data, binf, ptr, ln * ent)
            if not arr:
                continue
            files = []
            for k in range(ln):
                nptr, nlen, dptr, dlen = struct.unpack_from(en + ("QQQQ" if ps == 8 else "IIII"), arr, k * ent)
                if not (0 < nlen <= 512):
                    break
                name = _read(data, binf, nptr, nlen)
                if not name or not _NAME_OK.match(name):
                    break
                body = _read(data, binf, dptr, dlen) if dlen else b""
                if body is None or dlen > MAX_EMBED_BYTES:
                    break
                h = arr[k * ent + 4 * ps:k * ent + 4 * ps + 16]
                files.append({"name": name.decode("utf-8", "replace"), "size": dlen, "dir": name.endswith(b"/"),
                              "kind": _embed_kind(name.decode("utf-8", "replace"), body or b""),
                              "offset": binf.va_to_off(dptr) if dlen else None, "hash": h.hex(),
                              "sha256": hashlib.sha256(body).hexdigest() if dlen else "", "data": body})
            names = [f["name"] for f in files]
            # embed sorts its entries (directory first, then name): a strong check against chance matches
            if len(files) != ln or not any(not f["dir"] for f in files) or names != _embed_order(names):
                continue
            seen.add(ptr)
            out.append({"fs_va": ptr, "slice_offset": s.offset + i, "files": files})
    return out


_SCRIPT_EXT = (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".sh", ".py", ".hta", ".wsf", ".lua")
_TEMPLATE_EXT = (".tmpl", ".tpl", ".gohtml", ".html", ".htm", ".txt.tmpl")


def _embed_kind(name: str, body: bytes) -> str:
    low = name.lower()
    if body[:2] == b"MZ" or body[:4] == b"\x7fELF":
        return "executable"
    if low.endswith(_SCRIPT_EXT) or body[:2] == b"#!":
        return "script"
    if low.endswith(_TEMPLATE_EXT) or b"{{" in body[:4096]:
        return "template"
    if low.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".xml")):
        return "configuration"
    if low.endswith((".pem", ".crt", ".key", ".der", ".p12", ".pfx")):
        return "certificate / key"
    return "data"


def _embed_order(names: list[str]) -> list[str]:
    def key(n: str) -> tuple[str, str]:
        t = n.rstrip("/")
        d, _, b = t.rpartition("/")
        return d, b
    return sorted(names, key=key)


def certificates_and_keys(data: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in _PEM.finditer(data):
        kind = m.group(1).decode()
        item = {"type": "pem", "label": kind, "offset": m.start(), "size": m.end() - m.start(),
                "private": "PRIVATE" in kind}
        if "CERTIFICATE" in kind:
            try:
                item.update(_x509(base64.b64decode(re.sub(rb"\s", b"", m.group(2)))))
            except (ValueError, TypeError):
                pass
        out.append(item)
        if len(out) >= MAX_ITEMS:
            return out
    # DER certificates: SEQUENCE(len) { SEQUENCE(len) tbsCertificate ... }
    for m in re.finditer(rb"\x30\x82(..)\x30\x82", data, re.DOTALL):
        n = struct.unpack(">H", m.group(1))[0] + 4
        if n < 300 or m.start() + n > len(data) or any(abs(x["offset"] - m.start()) < 8 for x in out):
            continue
        info = _x509(data[m.start():m.start() + n])
        if info.get("subject"):
            out.append({"type": "der", "label": "X.509 certificate", "offset": m.start(), "size": n,
                        "private": False, **info})
        if len(out) >= MAX_ITEMS:
            break
    return out


def _x509(der: bytes) -> dict[str, Any]:
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001  (not a certificate, or no cryptography)
        return {}
    try:
        nb, na = c.not_valid_before_utc, c.not_valid_after_utc
    except AttributeError:                                      # older cryptography
        nb, na = c.not_valid_before, c.not_valid_after
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "serial": format(c.serial_number, "x"), "not_before": nb.isoformat(), "not_after": na.isoformat(),
            "self_signed": c.subject == c.issuer, "sha256": hashlib.sha256(der).hexdigest()}


_COMP = [(b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"\x28\xb5\x2f\xfd", "zstd"), (b"BZh", "bzip2"),
         (b"\x78\x9c", "zlib"), (b"\x78\xda", "zlib"), (b"\x78\x01", "zlib")]


def compressed(data: bytes, skip: list[tuple[int, int]] | None = None) -> list[dict[str, Any]]:
    """Compressed streams that decompress to at least 64 bytes (first 4 MB of output)."""
    import bz2
    import lzma
    out: list[dict[str, Any]] = []
    skip = skip or []
    for magic, kind in _COMP:
        start = 0
        tries = 0
        while len(out) < MAX_ITEMS and tries < 20000:
            tries += 1
            i = data.find(magic, start)
            if i < 0:
                break
            start = i + 1
            if any(a <= i < b for a, b in skip):
                continue
            chunk = data[i:i + 8 * 1024 * 1024]
            try:
                if kind == "gzip":
                    d = zlib.decompressobj(31)
                    raw = d.decompress(chunk, 4 << 20)
                    used = len(chunk) - len(d.unused_data)
                elif kind == "zlib":
                    d = zlib.decompressobj()
                    raw = d.decompress(chunk, 4 << 20)
                    used = len(chunk) - len(d.unused_data)
                    if not d.eof:
                        continue
                elif kind == "xz":
                    d = lzma.LZMADecompressor()
                    raw = d.decompress(chunk, 4 << 20)
                    used = len(chunk) - len(d.unused_data)
                elif kind == "bzip2":
                    if not re.match(rb"BZh[1-9]1AY&SY", chunk):
                        continue
                    d = bz2.BZ2Decompressor()
                    raw = d.decompress(chunk, 4 << 20)
                    used = len(chunk) - len(d.unused_data)
                else:
                    continue                                        # zstd: reported only when zstandard exists
            except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError):
                continue
            if len(raw) < 64:
                continue
            out.append({"type": kind, "offset": i, "size": used, "decompressed_size": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(), "head": raw[:16].hex(), "data": raw})
            start = i + max(used, 1)
    return out


MAX_SCRIPTS = 50
MIN_SCRIPT = 120
_RUN = re.compile(rb"[\t\n\r\x20-\x7e]{%d,}" % MIN_SCRIPT)
# language → (extension, markers); a run is that language when ≥ 2 distinct markers match
SCRIPT_MARKERS: dict[str, tuple[str, list[re.Pattern[str]]]] = {k: (ext, [re.compile(m, re.I | re.M) for m in ms]) for k, (ext, ms) in {
    "PowerShell": (".ps1", [r"\$env:\w+", r"\bInvoke-(?:Expression|WebRequest|RestMethod|Command)\b", r"\bNew-Object\s",
                           r"-(?:EncodedCommand|ExecutionPolicy)\b", r"\[System\.[\w.]+\]", r"\bSet-ItemProperty\b",
                           r"\bStart-Process\b", r"\bIEX\b", r"\bAdd-Type\b", r"\bGet-(?:WmiObject|CimInstance|Process)\b",
                           r"\$PSScriptRoot\b"]),
    "Batch": (".bat", [r"^\s*@echo off\b", r"%~dp0", r"\bset /a\b", r"\bgoto :?\w+", r"\breg add\b",
                       r"\bschtasks\s+/create\b", r"%errorlevel%", r"\bstart \"\"", r"\btimeout /t\b"]),
    "Shell": (".sh", [r"^#!/(?:usr/)?bin/(?:env )?(?:ba|z|da)?sh\b", r"\bchmod \+x\b", r"\|\s*(?:ba)?sh\b", r"2>/dev/null",
                      r"\bcrontab\b", r"\bnohup\b", r"\bsystemctl (?:enable|start)\b", r"\bexport [A-Z_]{2,}=",
                      r"\b(?:curl|wget) (?:-\w+ )*https?://"]),
    "VBScript": (".vbs", [r"\bCreateObject\(", r"\bWScript\.(?:Shell|CreateObject|Sleep)\b", r"^\s*Dim\s+\w+",
                          r"\bEnd (?:Sub|Function)\b", r"\bOn Error Resume Next\b", r"\bSet \w+ = "]),
    "JScript / JavaScript": (".js", [r"\bnew ActiveXObject\(", r"\bWScript\.(?:Shell|CreateObject)\b",
                                     r"\bfunction\s*\w*\s*\([^)]*\)\s*\{", r"\bvar\s+\w+\s*=", r"\beval\(",
                                     r"\bString\.fromCharCode\("]),
    "Python": (".py", [r"^import (?:os|sys|subprocess|socket|base64)\b", r"^from \w+ import ", r"^def \w+\(",
                       r"\bsubprocess\.(?:Popen|run|call)\(", r"if __name__ == ['\"]__main__['\"]"]),
    "AppleScript": (".applescript", [r"\btell application\b", r"\bdo shell script\b", r"\bend tell\b",
                                     r"\bdisplay dialog\b"]),
    "Go template": (".tmpl", [r"\{\{-?\s*\.\w+", r"\{\{-?\s*range\b", r"\{\{-?\s*if\b", r"\{\{-?\s*end\s*-?\}\}",
                              r"\{\{-?\s*(?:define|template|with|block)\b"]),
}.items()}


def script_literals(data: bytes, binf) -> list[dict[str, Any]]:
    """Scripts and templates held as string literals in the read-only data.

    Go keeps literals back to back without separators, so a text run can carry
    neighbours: the run is kept whole (capped) and named by the language whose
    markers it matches (≥ 2 distinct ones). [{language, ext, offset, size,
    markers, preview, data}]"""
    secs = [x for x in binf.sections if x.offset and x.size and
            (x.name in (".rdata", ".rodata", "__rodata", "__const", "__cstring") or "rodata" in x.name)]
    regions = [(x.offset, min(len(data), x.offset + x.size)) for x in secs] or [(0, len(data))]
    out: list[dict[str, Any]] = []
    for a, b in regions:
        for m in _RUN.finditer(data, a, b):
            raw = m.group(0)[:256 * 1024]
            text = raw.decode("ascii", "replace")
            best, hits = "", []
            for lang, (_ext, pats) in SCRIPT_MARKERS.items():
                got = [p.pattern for p in pats if p.search(text)]
                if len(got) >= 2 and len(got) > len(hits):
                    best, hits = lang, got
            if not best:
                continue
            out.append({"language": best, "ext": SCRIPT_MARKERS[best][0], "offset": m.start(), "size": len(raw),
                        "markers": len(hits), "preview": text.strip()[:240], "data": raw})
            if len(out) >= MAX_SCRIPTS:
                return out
    return out


# Standard-library packages that say what a Go binary can do (functions present in pclntab).
STD_NOTABLE: list[tuple[str, str]] = [
    ("os/exec", "runs commands"), ("syscall", "raw system calls"), ("plugin", "loads Go plugins at run time"),
    ("runtime/cgo", "C code linked in (cgo)"), ("debug/pe", "parses PE files (loader / injector?)"),
    ("debug/elf", "parses ELF files (loader?)"), ("net/http", "HTTP client / server"), ("net/smtp", "sends mail (exfiltration?)"),
    ("net/rpc", "RPC channel"), ("net/mail", "builds / parses mail"), ("crypto/tls", "TLS"), ("crypto/aes", "AES"),
    ("crypto/cipher", "block cipher modes (GCM, CTR, CBC…)"), ("crypto/rc4", "RC4"), ("crypto/des", "DES / 3DES"),
    ("crypto/rsa", "RSA"), ("crypto/ecdh", "key exchange (ECDH)"), ("crypto/x509", "certificates"),
    ("compress/gzip", "gzip"), ("compress/zlib", "zlib"), ("compress/flate", "DEFLATE"), ("archive/zip", "ZIP archives"),
    ("encoding/base64", "Base64"), ("encoding/hex", "hex encoding"), ("text/template", "text templates"),
    ("html/template", "HTML templates (phishing pages / panels?)"), ("image/png", "PNG (screenshots / steganography?)"),
    ("image/jpeg", "JPEG (screenshots?)"), ("os/user", "user enumeration"), ("os/signal", "signal handling"),
    ("net", "raw sockets / DNS"),
]


NOTABLE_MODULES: list[tuple[str, str]] = [
    ("github.com/gorilla/websocket", "WebSocket channel"), ("nhooyr.io/websocket", "WebSocket channel"),
    ("github.com/miekg/dns", "DNS client / server (DNS C2?)"), ("github.com/hashicorp/yamux", "connection multiplexing"),
    ("github.com/armon/go-socks5", "SOCKS5 proxy"), ("golang.org/x/net/proxy", "proxy client"),
    ("github.com/libp2p/", "peer-to-peer networking"), ("golang.org/x/crypto/ssh", "SSH client / server"),
    ("github.com/gliderlabs/ssh", "SSH server"), ("github.com/kbinani/screenshot", "screen capture"),
    ("github.com/atotto/clipboard", "clipboard access"), ("golang.design/x/clipboard", "clipboard access"),
    ("github.com/shirou/gopsutil", "process / system enumeration"), ("github.com/StackExchange/wmi", "WMI queries"),
    ("github.com/yusufpapurcu/wmi", "WMI queries"), ("github.com/go-ole/go-ole", "COM / WMI automation"),
    ("github.com/kardianos/service", "runs as a service (persistence)"), ("github.com/mattn/go-sqlite3", "SQLite (browser data?)"),
    ("modernc.org/sqlite", "SQLite (browser data?)"), ("golang.org/x/sys/windows/registry", "Windows registry"),
    ("github.com/Binject/", "binary injection / shellcode tooling"), ("github.com/C-Sto/BananaPhone", "direct syscalls"),
    ("github.com/Ne0nd0g/", "Merlin C2 framework"), ("github.com/bishopfox/sliver", "Sliver C2 framework"),
    ("github.com/MythicAgents/", "Mythic agent"), ("github.com/BurntSushi/xgb", "X11 access"),
    ("github.com/go-vgo/robotgo", "keyboard / mouse / screen automation"), ("github.com/moutend/go-hook", "keyboard / mouse hooks"),
    ("golang.org/x/crypto", "extra cryptography"), ("filippo.io/age", "file encryption (age)"),
    ("github.com/tidwall/gjson", "JSON parsing (config?)"), ("github.com/go-resty/resty", "HTTP client"),
    ("github.com/valyala/fasthttp", "HTTP client / server"), ("github.com/elazarl/goproxy", "HTTP proxy"),
    ("golang.org/x/sys/windows", "Windows API (syscalls)"), ("github.com/lxn/win", "Windows API"),
    ("github.com/Microsoft/go-winio", "named pipes / Windows I/O"), ("github.com/mitchellh/go-ps", "process listing"),
    ("github.com/fsnotify/fsnotify", "file system watching"), ("github.com/robfig/cron", "scheduled jobs"),
    ("github.com/go-telegram-bot-api/", "Telegram bot (C2 / exfiltration?)"), ("gopkg.in/telebot", "Telegram bot (C2 / exfiltration?)"),
    ("github.com/bwmarrin/discordgo", "Discord bot (C2 / exfiltration?)"), ("github.com/slack-go/slack", "Slack API (C2 / exfiltration?)"),
    ("github.com/aws/aws-sdk-go", "AWS SDK (cloud exfiltration?)"), ("cloud.google.com/go/storage", "cloud storage"),
    ("github.com/jlaffaye/ftp", "FTP client (exfiltration?)"), ("github.com/pkg/sftp", "SFTP (exfiltration?)"),
    ("github.com/emersion/go-smtp", "SMTP (exfiltration?)"), ("github.com/xtaci/kcp-go", "KCP / UDP tunnelling"),
    ("github.com/fatedier/frp", "frp reverse proxy (tunnelling)"), ("github.com/jpillora/chisel", "chisel tunnel"),
    ("github.com/cretz/bine", "Tor"), ("github.com/ipsn/go-libtor", "Tor"),
    ("github.com/vmihailenco/msgpack", "MessagePack (C2 protocol?)"), ("google.golang.org/grpc", "gRPC (C2 channel?)"),
    ("github.com/quic-go/quic-go", "QUIC transport"), ("github.com/lucas-clemente/quic-go", "QUIC transport"),
    ("github.com/pion/webrtc", "WebRTC channel"), ("github.com/alexmullins/zip", "password-protected ZIP"),
    ("github.com/yeka/zip", "password-protected ZIP"), ("github.com/vova616/screenshot", "screen capture"),
    ("github.com/gordonklaus/portaudio", "microphone / audio"), ("github.com/blackjack/webcam", "webcam"),
    ("github.com/google/gopacket", "packet capture / crafting"), ("github.com/denisbrodbeck/machineid", "machine ID (fingerprinting)"),
    ("github.com/zalando/go-keyring", "OS keyring (credentials)"), ("github.com/danieljoos/wincred", "Windows Credential Manager"),
    ("github.com/billgraziano/dpapi", "DPAPI (browser secrets)"), ("github.com/awgh/rawreader", "raw memory reading"),
]


def notable(module_paths: list[str]) -> list[dict[str, str]]:
    out = []
    for m in module_paths:
        for pre, label in NOTABLE_MODULES:
            if m == pre.rstrip("/") or m.startswith(pre):
                out.append({"module": m, "why": label})
                break
    return out


def go_package(name: str) -> str:
    """'github.com/a/b/pkg.(*T).M' → 'github.com/a/b/pkg'."""
    n = name.split("[", 1)[0]
    i = n.rfind("/")
    return n[:i + 1] + n[i + 1:].split(".", 1)[0]


def go_dependencies(buildinfo: dict[str, Any] | None, function_names: list[str]) -> dict[str, Any]:
    """BuildInfo modules versus the packages with code in pclntab."""
    bi = buildinfo or {}
    deps = [d.get("path", "") for d in bi.get("deps") or [] if d.get("path")]
    main = bi.get("path") or ""
    pkgs: dict[str, int] = {}
    for n in function_names:
        base = go_package(n)
        if base and "." in base.split("/")[0]:              # std packages have no dot in their first element
            pkgs[base] = pkgs.get(base, 0) + 1

    def owner(pkg: str) -> str:
        best = ""
        for m in [main, *deps]:
            if m and (pkg == m or pkg.startswith(m + "/")) and len(m) > len(best):
                best = m
        return best
    used: dict[str, int] = {}
    undeclared: dict[str, int] = {}
    for p, c in pkgs.items():
        o = owner(p)
        if o:
            used[o] = used.get(o, 0) + c
        elif p != "main" and "." in p.split("/")[0]:
            undeclared[p] = c
    std: dict[str, int] = {}
    for n in function_names:
        base = go_package(n)
        if base and "." not in base.split("/")[0]:
            std[base] = std.get(base, 0) + 1
    std_notable = [{"package": p, "functions": std[p], "why": why} for p, why in STD_NOTABLE if std.get(p)]
    return {"declared": len(deps), "notable": notable(sorted(set(deps) | set(undeclared))), "std_notable": std_notable,
            "with_code": sorted(m for m in deps if m in used),
            "without_code": sorted(m for m in deps if m not in used),
            "undeclared": sorted(undeclared.items(), key=lambda x: -x[1])[:100],
            "functions_per_module": dict(sorted(used.items(), key=lambda x: -x[1]))}


def scan(data: bytes, binf, mode: str) -> dict[str, Any]:
    """Every resource kind for one binary (the raw bytes stay under ``data``
    keys for the caller to write out, never into JSON)."""
    res: dict[str, Any] = {"embed": [], "certificates": [], "compressed": [], "scripts": []}
    if mode == "go":
        try:
            res["embed"] = go_embed(data, binf)
        except (struct.error, ValueError):
            pass
    res["certificates"] = certificates_and_keys(data)
    skip = [(f["offset"], f["offset"] + f["size"]) for fs in res["embed"] for f in fs["files"] if f["offset"] is not None]
    # compressed DWARF (.debug_* / .zdebug_* / __DWARF) is debug information, not a payload
    skip += [(x.offset, x.offset + x.size) for x in binf.sections
             if x.offset and x.name.startswith((".debug", ".zdebug", "__debug", "__zdebug"))]
    res["compressed"] = compressed(data, skip)
    try:
        res["scripts"] = [x for x in script_literals(data, binf)
                          if not any(a <= x["offset"] < b for a, b in skip)]
    except (re.error, ValueError):
        pass
    return res
