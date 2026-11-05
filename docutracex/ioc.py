"""Common IOC extractor.

Scans textual/structured parser results after parsing. Extracts IPv4/IPv6,
URLs, domains, hash-like strings, emails, file paths, registry keys, named
pipes, MAC addresses, and sensitive Windows commands / PowerShell cmdlets. 
Keeps provenance and deduplicates by (type, value). No network access and 
no execution of extracted content.

Registry-key validation checks Windows root aliases and key-path structure;
it does NOT prove that a key exists on a particular Windows system.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from pathlib import Path
from urllib.parse import urlparse

from . import tlds

# --- Patterns ---------------------------------------------------------------

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]}]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"(?<![\w:.])(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}(?![\w:])",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])",
    re.IGNORECASE,
)
_HASH_RE = re.compile(
    r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{128}|[A-Fa-f0-9]{96}|"
    r"[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])"
)
_EMAIL_RE = re.compile(
    r"(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+",
    re.IGNORECASE,
)

# Named pipes are checked before generic Windows paths.
_PIPE_RE = re.compile(
    r"(?i)(?<![\w])(?:\\\\\.\\pipe\\|\\\\\?\\pipe\\|"
    r"\\\\[^\\\s]+\\pipe\\)[^\s\"'<>|,;]+"
)

# Registry root aliases. A subkey is required; a bare root is not reported.
_REG_ROOTS = (
    r"(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|"
    r"HKEY_CLASSES_ROOT|HKU|HKEY_USERS|HKCC|HKEY_CURRENT_CONFIG)"
)
_REGISTRY_RE = re.compile(
    rf"(?i)(?<![A-Z0-9_]){_REG_ROOTS}\\[^\s\"'<>|,;]+"
)

# Drive-letter paths, environment-variable paths and UNC paths.
# Directory components may contain spaces ("Start Menu", "Program Files") as
# long as another "\\" follows; the last component stops at whitespace (an
# unquoted path cannot say where a spaced file name ends). A path inside
# double quotes is taken whole, spaces included.
_DIR = r"(?:[^\\\s\"'<>|?*:](?:[^\\\"'<>|?*:\r\n\t]{0,80}[^\\\s\"'<>|?*:])?\\)"
_LAST = r"[^\s\"'<>|?*]+"
_FILEPATH_RE = re.compile(
    r"(?i)(?:"
    r"(?<=\")(?:[A-Z]:\\|%[A-Z0-9_()]+%\\|\\\\)[^\"\r\n<>|?*]+(?=\")|"
    r"(?<![\w])(?:"
    rf"[A-Z]:\\{_DIR}*{_LAST}|"
    rf"%[A-Z0-9_()]+%\\{_DIR}*{_LAST}|"
    r"\\\\[^\\\s]+\\[^\\\s]+(?:\\[^\s\"'<>|?*]+)*"
    r"))"
)

_MAC_RE = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|"
    r"[0-9a-f]{2}(?:-[0-9a-f]{2}){5})(?![0-9a-f])"
)

# --- Sensitive Windows Binaries, LOLBins & PowerShell Cmdlets List ----------
_SENSITIVE_COMMANDS = [
    # Red, Conectividad y Herramientas de Descarga / Transferencia
    "netsh", "ipconfig", "route", "nbtstat", "arp", "nslookup", "tracert",
    "ping", "netstat", "pathping", "bitsadmin", "ftp", "tftp", "finger",
    "netbtugc", "klist", "nltest", "dnscmd", "rpcping", "cmstp", "telephon",
    "curl", "wget", "nc", "ncat", "certutil", "certreq",

    # Administración del Sistema, Servicios, Procesos y Seguridad
    "schtasks", "sc", "taskkill", "tasklist", "wevtutil", "wmic", "powershell",
    "pwsh", "cmd", "cscript", "wscript", "mshta", "rundll32", "reg", "regsvr32",
    "gpupdate", "gpresult", "bcdedit", "vssadmin", "wbadmin", "fsutil", "cipher",
    "takeown", "icacls", "cacls", "attrib", "systeminfo", "whoami", "hostname",
    "query", "quser", "qwinsta", "logoff", "shutdown", "reboot", "powercfg",
    "fltmc", "driverquery", "lodctr", "unlodctr", "auditpol", "dism", "pnputil",
    "wbemtest", "tzutil", "logman", "reagentc",

    # Comandos Net (Gestión de Usuarios, Grupos, Recursos)
    "net", "net1",

    # LOLBins, Compiladores y Bypass de AppLocker/WDAC
    "at", "psexec", "winrm", "wsl", "bash", "installutil", "msbuild", "csc",
    "vbc", "regasm", "regsvcs", "bginfo", "msiexec", "control", "explorer", "hh",
    "infdefaultinstall", "forfiles", "diskpart", "format", "subst", "runas",
    "expand", "makecab", "extrac32", "esentutl", "findstr", "where", "dxdiag",
    "msinfo32", "type", "pocalc", "aspnet_regiis", "dfsvc", "mavinject",
    "appvlp", "tracker", "PresentationHost", "Microsoft.Workflow.Compiler",
    "ieexec", "msconfig", "cleanmgr", "verifier", "mmc", "msdt", "diantz",
    "register-cimprovider", "wslconfig", "tar", "utilman", "sethc",

    # PowerShell Cmdlets Comunes y Peligrosos (Verbos de Acción PowerShell)
    "Invoke-WebRequest", "Invoke-RestMethod", "Invoke-Expression", "IEX",
    "Start-Process", "New-Object", "Add-MpPreference", "Set-MpPreference",
    "Remove-MpPreference", "Disable-NetAdapterBinding", "Enable-NetAdapterBinding",
    "Set-NetIPAddress", "Get-Process", "Stop-Process", "Get-Service", "Set-Service",
    "Restart-Service", "Get-CimInstance", "Get-WmiObject", "Get-ItemProperty",
    "Set-ItemProperty", "New-ItemProperty", "Get-ChildItem", "Remove-Item",
    "Copy-Item", "Move-Item", "Register-ScheduledTask", "Unregister-ScheduledTask",
    "New-ScheduledTask", "Set-ExecutionPolicy", "Import-Module", "Export-Clixml",
    "Out-File", "Add-Content", "Set-Content", "Read-Host", "Write-Host"
]

# Expresión regular robusta para binarios tradicionales y cmdlets de PowerShell
_ARG = r"(?:/[a-z0-9_/?:.\\*%-]+|-[a-z0-9_/?:.\\*%-]+|\"[^\"\r\n]+\"|'[^'\r\n]+'|[a-z0-9_\\.:*?%$/=@~#+,-]+)"
# Arguments are separated by spaces/tabs only: a command never runs onto the
# next line.
_COMMAND_RE = re.compile(
    rf"(?i)\b(?P<cmd>{'|'.join(_SENSITIVE_COMMANDS)})(?P<exe>\.exe)?\b[ \t]+"
    rf"(?P<args>{_ARG}(?:[ \t]+{_ARG})*)",
    re.IGNORECASE
)
# Commands that are also everyday words ("at IANA", "type of", "where to"):
# only reported in command position (line start, after & | ; ( or a quote,
# after cmd /c), written as name.exe, or with a switch as first argument.
_AMBIGUOUS_COMMANDS = {
    "at", "type", "where", "format", "control", "expand", "tracker", "explorer",
    "tar", "bash", "hh", "subst", "verifier", "date", "time", "set", "start",
    "copy", "move", "find", "echo", "net", "sc", "print", "help", "more", "sort",
}
# .NET helpers every decoder uses: not an indicator by themselves.
_BENIGN_NEW_OBJECT = re.compile(
    r"(?i)(?:-TypeName\s+)?(?:System\.)?(?:IO\.(?:MemoryStream|StreamReader|StreamWriter|BinaryReader|"
    r"Compression\.\w+)|Text\.\w+|Collections\.[\w.`\[\]]+|Byte\[\]|Random|"
    r"Security\.Cryptography\.(?:AesManaged|AesCryptoServiceProvider|RijndaelManaged|SHA256Managed))\b")
_TECH_ARG = re.compile(r"[\\/.%:\d\"']")   # a path, file, time, variable or quoted arg
_CMD_POSITION = re.compile(r"(?i)(?:^|[&|;(`\"']|\bcmd(?:\.exe)?\s+/[ck]|\bcall)\s*$")

_FILE_TLDS = {
    "xml", "rels", "bin", "png", "jpeg", "jpg", "gif", "emf", "wmf",
    "bmp", "tiff", "docx", "docm", "dotx", "dotm", "xlsx", "xlsm",
    "xltx", "xltm", "xlam", "xlsb", "pptx", "pptm", "potx", "potm",
    "ppsx", "ppsm", "ppam", "sldx", "sldm", "doc", "dot", "xls",
    "xlt", "xla", "ppt", "pot", "pdf", "eml", "emlx", "msg", "rtf",
    "txt", "json", "html", "htm", "css", "js", "exe", "dll", "zip",
    "jar", "mgc",
}

_CONTEXT = 64

# TLDs come from the official IANA list (see tlds.py).

_NAMESPACE_HOSTS = {
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "www.w3.org",
    "w3.org",
    "purl.org",
    "ns.adobe.com",
    "schemas.xmlsoap.org",
}

_VERSION_BEFORE = re.compile(r"(?i)(?:version|ver|v)\s*[=:]?\s*[\"']?$")
_CODE_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "gov", "edu",
    "mil", "int", "xyz", "top", "online", "site", "club", "app",
    "dev", "example", "test", "onion", "ru", "cn",
}
_CODE_LOCATION = re.compile(
    r"code|vba|sandbox|decoded|pcode|formula|xlm|macro|script",
    re.IGNORECASE,
)


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(
        p.isdigit() and 0 <= int(p) <= 255 for p in parts
    )


def _valid_ipv6(value: str) -> str | None:
    """A real IPv6 address: not the unspecified ``::`` or loopback ``::1``, and
    with at least three written groups (``1::``, ``a:b::`` are code / string
    fragments, not addresses)."""
    try:
        addr = ipaddress.IPv6Address(value)
    except ValueError:
        return None
    if addr.is_unspecified or addr.is_loopback:
        return None
    if sum(1 for g in value.split(":") if g) < 3:
        return None
    return addr.compressed


# "name.member = value" / "name.member(" right after a dotted name: code, not a host.
_CODE_MEMBER_AFTER = re.compile(r"\s*(?:=(?!=)|\()")
# A tool's own report of what it carved ("MD5 = '…'", "sha256: …") inside its
# output — the app computes the hashes it needs; these are not sample content.
_TOOL_OUTPUT_LOC = re.compile(r"(?:^|[/› ])tools/[^/]+/output$")
_DIGEST_LABEL = re.compile(r"(?i)\b(?:md5|sha-?1|sha-?256|sha-?512|hash)\s*[:=]\s*['\"]?$")


_HEX_BLOB = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64,}[ \t]*\r?\n\s*){2,}[A-Fa-f0-9]{16,}")
_HEX_DATA = re.compile(r"(?i)0000|ffff|504b0304|3c3f786d6c")


def _random_hex(value: str) -> bool:
    """A digest is random-looking: no long runs of one nibble (``00000000``,
    ``ffffffff`` — padding in a hex dump) and enough distinct hex digits."""
    v = value.lower()
    return not re.search(r"(.)\1{7,}", v) and len(set(v)) >= min(10, len(v) // 4)


def _clean_url(url: str) -> str:
    url = re.sub(r"\[[A-Za-z_]*$", "", url)       # fwlink…[VSDNETURLMSG: an MSI property after it
    return url.rstrip(".,;:)]}'\"")


def _domain_of(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
        return host.lower() if host else None
    except ValueError:
        return None


def _is_gateway(domain: str) -> bool:
    return (
        domain in (
            "urldefense.com",
            "urldefense.proofpoint.com",
            "linkprotect.cudasvc.com",
        )
        or domain.endswith(
            ("safelinks.protection.outlook.com", ".mimecast.com")
        )
    )


def _known_tld(domain: str, strict: bool = False) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    if not tlds.is_known(tld):
        return False
    if strict:
        # code (VBA/JS/...) is full of obj.member pairs: only common TLDs, or a
        # ccTLD with at least two labels before it
        return tld in _CODE_TLDS or tld.startswith("xn--") or (
            len(tld) == 2 and len(domain.split(".")) >= 3
        )
    return True


# Certificate infrastructure (CRL / OCSP / CA certs / CPS of the public CAs):
# every signed binary carries them, they are not indicators.
_CA_HOST = re.compile(
    r"(?:^|\.)(?:digicert|sectigo|ssl|globalsign|usertrust|comodoca|comodo|verisign|symantec|symcb|symcd"
    r"|entrust|godaddy|letsencrypt|lencr|amazontrust|thawte|geotrust|certum|identrust|quovadisglobal"
    r"|starfieldtech|rapidssl)\.(?:com|net|org|pl)$")
_MS_PKI = re.compile(r"(?i)^https?://(?:www|crl|ocsp|pki)\.microsoft\.com/(?:pki|pkiops)/")
# Hosts quoted by open-source license / credit text bundled with runtimes
# (CPython's LICENSE, bzip2, Apache / OSI notices).
_REFERENCE_HOSTS = {
    "beopen.com", "www.beopen.com", "pythonlabs.com", "www.pythonlabs.com", "cwi.nl", "www.cwi.nl",
    "cnri.reston.va.us", "www.cnri.reston.va.us", "hdl.handle.net", "opensource.org", "www.opensource.org",
    "apache.org", "www.apache.org", "xkcd.com", "crl.microsoft.com",
    "myapplication.app",                       # Visual Studio's default manifest identity
}
_REFERENCE_EMAILS = {"jseward@acm.org", "jseward@bzip.org", "nadeem.vawda@gmail.com", "jloup@gzip.org",
                     "madler@alumni.caltech.edu"}


def _is_reference_host(domain: str) -> bool:
    return domain in _REFERENCE_HOSTS or bool(_CA_HOST.search(domain))


# "obj.member" that is code, not a host: an identifier everybody uses as the
# object (this.top, self.af, builtins.id, thread.local) or a TLD that in
# practice is a property name / reserved (.name, .invalid, .local, .windows).
_CODE_OBJECTS = {"this", "self", "builtins", "collections", "thread", "os", "sys", "window", "document",
                 "math", "proto", "prototype", "props", "prop", "options", "config", "params", "data"}
_MEMBER_TLDS = {"invalid", "local", "localhost", "name", "windows", "abc", "data", "style", "properties",
                "property", "target", "events", "observer", "py"}
# Minified JS / code bundles: count of code tokens per text
_CODE_TOKENS = re.compile(r"\bfunction\b|=>|\bthis\.|\bvar |\breturn\b|\};|\)\{")


def _code_like(text: str) -> bool:
    n = len(_CODE_TOKENS.findall(text[:200000]))
    return n >= 10 and n * 400 >= min(len(text), 200000)


# Code namespaces that look like hosts (java.io, javax.crypto, android.os…).
_CODE_NAMESPACES = ("java.", "javax.", "android.", "androidx.", "kotlin.", "jdk.", "sun.")


# Shared objects: libc.so, libapp.so, libssl.so.3 — .so is also a ccTLD (Somalia),
# so only lib*.so names are treated as files; notion.so stays a domain.
_SHARED_LIB = re.compile(r"(?i)^lib[\w+-]*\.so$")


def _looks_like_filename(domain: str) -> bool:
    return (domain.rsplit(".", 1)[-1].lower() in _FILE_TLDS or domain.lower().startswith(_CODE_NAMESPACES)
            or bool(_SHARED_LIB.match(domain)))


# URLs of the analysis tools themselves (banners, help text, tracebacks): never
# IOCs. Matched by *project*, never by generic host: an unrelated github.com,
# python.org or nodejs.org URL is still reported.
_TOOL_REPOS = {  # owner or owner/repo on GitHub (github.com, raw/codeload/api)
    "decalage2", "borntyping/python-colorlog", "didierstevens",
    "jesparza/peepdf", "erocarrera/pefile", "mandiant/flare-floss",
    "mandiant/capa", "mandiant/capa-rules", "virustotal/yara",
    "virustotal/yara-python", "dissectmalware/xlmmacrodeobfuscator",
    "nolze/msoffcrypto-tool", "teammsgextractor/msg-extractor",
    "py-pdf/pypdf", "j4k0xb/webcrack", "connorshride/box-ps", "zrax/pycdc",
    "leibnitz27/cfr", "fboldewin/reconstructer.org", "miurahr/py7zr",
    "danifus/pyzipper", "clalancette/pycdlib", "astral-sh/python-build-standalone",
    "g92mz/docutracex",
}
_TOOL_HOSTS = (  # hosts that belong to a tool (subdomains included)
    "decalage.info", "didierstevens.com", "reconstructer.org", "benf.org",
    "eternal-todo.com", "virustotal.github.io", "webcrack.netlify.app",
    "oletools.readthedocs.io", "yara.readthedocs.io", "pypdf.readthedocs.io",
    "msoffcrypto-tool.readthedocs.io", "pefile.readthedocs.io",
)
_TOOL_PYPI = {
    "oletools", "olefile", "colorlog", "vipermonkey", "pefile", "pdfid", "peepdf",
    "peepdf-3", "pypdf", "msoffcrypto-tool", "xlmmacrodeobfuscator",
    "extract-msg", "yara-python", "py7zr", "pyzipper", "pycdlib", "flare-floss",
    "flare-capa",
}
_GH_HOSTS = ("github.com", "www.github.com", "raw.githubusercontent.com",
             "codeload.github.com", "objects.githubusercontent.com")


def _is_tool_url(url: str) -> bool:
    try:
        u = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    parts = [p for p in u.path.lower().split("/") if p]
    if host == "api.github.com" and parts[:1] == ["repos"]:
        host, parts = "github.com", parts[1:]
    if host in _GH_HOSTS and parts:
        return parts[0] in _TOOL_REPOS or "/".join(parts[:2]) in _TOOL_REPOS
    if host in ("pypi.org", "pypi.python.org") and len(parts) >= 2 \
            and parts[0] in ("project", "pypi", "simple"):
        return parts[1] in _TOOL_PYPI
    return any(host == h or host.endswith("." + h) for h in _TOOL_HOSTS)


# The app's own install path (tool output, tracebacks) is never an IOC.
_INSTALL_DIR = str(Path(__file__).resolve().parents[1]).lower().rstrip("\\/")


# Paths the JS sandbox's WSH emulation invents (the script's own location):
# artefacts of the emulation, never indicators of the sample.
_EMULATOR_PATHS = {"c:\\users\\user\\downloads\\invoice.js"}


def _is_self_path(value: str) -> bool:
    low = value.lower().replace("/", "\\")
    if low in _EMULATOR_PATHS:
        return True
    inst = _INSTALL_DIR.replace("/", "\\")
    return "docutracex" in low or (len(inst) > 3 and low.startswith(inst))


def _plausible_component(part: str) -> bool:
    """Reject components that are binary noise rather than real names: control
    chars, escaped bytes (\\xNN), or mostly non-ASCII / non-alphanumeric."""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in part):
        return False
    non_ascii = sum(1 for ch in part if ord(ch) > 127)
    if non_ascii * 2 > len(part):
        return False
    if part.startswith("%") and part.endswith("%"):
        return True
    good = sum(1 for ch in part if ch.isalnum() or ch in " ._-$()~[]{}#@&+,'!")
    return good * 10 >= len(part) * 8


def _valid_filepath(value: str) -> bool:
    """Validate a Windows path candidate without restricting scan sources.

    Reject malformed components, including colons inside ordinary filename
    components. This filters FLOSS fragments such as O:\\e:k while preserving
    valid paths such as O:\\file.exe and O:\\klgsdfj___.exe.

    NTFS alternate data streams are intentionally not treated as ordinary
    file paths by this IOC type.
    """
    value = value.strip().rstrip(".,;:)]}")

    if not value or any(ch in value for ch in '<>"|?*'):
        return False
    # escaped byte runs (\x4d\x5a...) are binary noise, not a path
    if re.search(r"(?i)(\\x[0-9a-f]{2}){2}", value):
        return False
    # RTF control syntax ({\fldrslt, }}{\*\...) is markup, not a path; a GUID
    # folder (\{3F2504E0-...}\) never has "{\", "}{" or "}}"
    if re.search(r"\{\\|\}\{|\}\}|\\\*\\", value):
        return False

    # Absolute drive path, e.g. C:\\Windows\\cmd.exe
    if re.match(r"(?i)^[a-z]:\\", value):
        components = value[3:].split("\\")

    # UNC path, e.g. \\\\server\\share\\file.exe
    elif value.startswith("\\\\"):
        parts = value[2:].split("\\")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return False
        # the host is a name, an IP or a WebDAV host@SSL@port — not "d}}{"
        if not re.fullmatch(r"[A-Za-z0-9._$-]+(?:@[A-Za-z0-9]+)*|\?|\.|\[[0-9A-Fa-f:.]+\]", parts[0]):
            return False
        components = parts

    # Environment-variable path, e.g. %TEMP%\\payload.exe
    elif re.match(r"(?i)^%[a-z0-9_()]+%\\", value):
        components = value.split("\\")[1:]

    else:
        return False

    if not components or any(not part for part in components):
        return False

    for part in components:
        # A colon inside a filename/directory component is invalid
        if ":" in part or not _plausible_component(part):
            return False

        # Windows conventional file/directory components cannot end in a space or dot
        if part.endswith((" ", ".")):
            return False

    return True


class _Collector:
    def __init__(self) -> None:
        self.iocs: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        self,
        ioc_type: str,
        value: str,
        module: str,
        location: str,
        context: str,
    ) -> None:
        key = (ioc_type, value)
        entry = self.iocs.get(key)
        occurrence = {
            "module": module,
            "location": location,
            "context": context,
        }

        if entry is None:
            self.iocs[key] = {
                "type": ioc_type,
                "value": value,
                "occurrences": [occurrence],
            }
        else:
            entry["occurrences"].append(occurrence)

    def result(self) -> dict[str, Any]:
        iocs = sorted(
            self.iocs.values(),
            key=lambda item: (item["type"], item["value"]),
        )
        counts: dict[str, int] = {}

        for item in iocs:
            item["count"] = len(item["occurrences"])
            counts[item["type"]] = counts.get(item["type"], 0) + 1

        counts["total"] = len(iocs)
        return {"iocs": iocs, "counts": counts}


def _ctx(text: str, start: int, end: int) -> str:
    a = max(0, start - _CONTEXT)
    b = min(len(text), end + _CONTEXT)
    return text[a:b].replace("\n", " ").strip()


def _scan_text(
    text: str,
    module: str,
    location: str,
    col: _Collector,
) -> None:
    if not text:
        return

    # Scan de Comandos Sensibles, LOLBins y Cmdlets de PowerShell
    for match in _COMMAND_RE.finditer(text):
        if match.group("cmd").lower() in _AMBIGUOUS_COMMANDS and not (
            match.group("exe")
            or match.group("args")[:1] in "/-"
            or (_CMD_POSITION.search(text[max(0, match.start() - 40):match.start()].rsplit("\n", 1)[-1])
                and _TECH_ARG.search(match.group("args").split()[0]))
        ):
            continue
        args = match.group("args").split()
        # code, not a command line: an assignment / comparison (cmd = name,
        # nc += prev, cmd in topics), a printf format (type %.100s, at %p)
        if (re.fullmatch(r"(?:[=!<>+*/%&|^-]=?|==|in|is|and|or|not)", args[0])
                or re.match(r"%[-+ #0]*\d*(?:\.\d+)?[a-z]", args[0])
                or args[0].startswith("//")
                or (match.group("cmd").lower() in _AMBIGUOUS_COMMANDS and not match.group("exe")
                    and re.fullmatch(r"([\"'])[a-z]+\1", args[0], re.I) and len(args) == 1)):
            continue
        # prose, not a command line ("PowerShell deobfuscated before analysis")
        if len(args) >= 2 and all(re.fullmatch(r"[a-z]{3,}", w) for w in args[:4]):
            continue
        # named in a sentence with a single plain word after it ("May run
        # PowerShell commands", "uses cmd prompts"): a description, not a run
        if (len(args) == 1 and re.fullmatch(r"[a-z]{4,}", args[0]) and not match.group("exe")
                and re.search(r"[A-Za-z]{2,} $", text[max(0, match.start() - 20):match.start()])):
            continue
        if match.group("cmd").lower() == "new-object" and _BENIGN_NEW_OBJECT.match(match.group("args")):
            continue
        cmd_val = match.group(0).strip(".,;:)]}")
        if cmd_val.count('"') % 2:      # drop a dangling quote, keep balanced ones
            cmd_val = cmd_val.strip('"')
        if cmd_val.count("'") % 2:
            cmd_val = cmd_val.strip("'")
        if len(cmd_val) > 3:
            col.add(
                "command", cmd_val, module, location,
                _ctx(text, match.start(), match.end()),
            )

    url_spans: list[tuple[int, int]] = []

    for match in _URL_RE.finditer(text):
        url = _clean_url(match.group(0))
        url_spans.append((match.start(), match.start() + len(url)))
        domain = _domain_of(url)

        if domain in _NAMESPACE_HOSTS or _is_tool_url(url) or (
                domain and _is_reference_host(domain)) or _MS_PKI.match(url):
            continue

        tld = (domain or "").rsplit(".", 1)[-1]
        if (
            domain
            and "." in domain
            and ":" not in domain
            and not _valid_ipv4(domain)
            and not tlds.is_known(tld)
        ):
            continue

        col.add(
            "url", url, module, location,
            _ctx(text, match.start(), match.end()),
        )

        if (
            domain
            and "." in domain
            and not _looks_like_filename(domain)
            and not _valid_ipv4(domain)
            and ":" not in domain
            and not _is_gateway(domain)
        ):
            col.add(
                "domain", domain, module, location,
                _ctx(text, match.start(), match.end()),
            )

    for match in _IPV4_RE.finditer(text):
        value = match.group(0)
        if not _valid_ipv4(value):
            continue

        before = text[max(0, match.start() - 14):match.start()]
        if value.endswith(".0") or _VERSION_BEFORE.search(before) or re.search(r"\d\.$", before) or (
            text[match.end():match.end() + 1] == "."
            and text[match.end() + 1:match.end() + 2].isdigit()
        ):
            continue

        col.add(
            "ipv4", value, module, location,
            _ctx(text, match.start(), match.end()),
        )

    for match in _IPV6_RE.finditer(text):
        address = _valid_ipv6(match.group(0))
        if address:
            col.add(
                "ipv6", address, module, location,
                _ctx(text, match.start(), match.end()),
            )

    tool_output = bool(_TOOL_OUTPUT_LOC.search(location or ""))
    floss = "floss" in (location or "")
    # hex-encoded data split in lines (a hash list has no 0000 / PK runs)
    blobs = [(m.start(), m.end()) for m in _HEX_BLOB.finditer(text) if _HEX_DATA.search(m.group(0))]
    for match in _HASH_RE.finditer(text):
        if not _random_hex(match.group(0)):
            continue
        # a line of a hex blob (hex dump / hex-encoded data split in lines), or
        # the head of a WIN_CERTIFICATE (dwLength, revision 0x200, PKCS#7)
        if (floss                                    # GUIDs / constants of the binary, not hashes of anything
                or any(a <= match.start() < b for a, b in blobs)
                or re.match(r"(?i)[0-9a-f]{8}000202003082", match.group(0))):
            continue
        if tool_output and _DIGEST_LABEL.search(text[max(0, match.start() - 24):match.start()]):
            continue
        col.add(
            "hash_like", match.group(0).lower(), module, location,
            _ctx(text, match.start(), match.end()),
        )

    for match in _EMAIL_RE.finditer(text):
        email = match.group(0).rstrip(".,;:")
        if email.lower() in _REFERENCE_EMAILS:
            continue
        if (len(email) <= 254 and len(email.split("@", 1)[0]) <= 64
                and tlds.is_known(email.rsplit(".", 1)[-1])):
            col.add(
                "email", email.lower(), module, location,
                _ctx(text, match.start(), match.start() + len(email)),
            )

    # Registry paths first so they are not also emitted as generic file paths.
    registry_spans: list[tuple[int, int]] = []

    for match in _REGISTRY_RE.finditer(text):
        value = match.group(0).rstrip(".,;:)]}")
        _, _, subkey = value.partition("\\")
        if not subkey or not any(subkey.split("\\")):
            continue

        registry_spans.append(
            (match.start(), match.start() + len(value))
        )
        col.add(
            "registry_key", value, module, location,
            _ctx(text, match.start(), match.start() + len(value)),
        )

    pipe_spans: list[tuple[int, int]] = []

    for match in _PIPE_RE.finditer(text):
        value = match.group(0).rstrip(".,;:)]}")
        if "\\pipe\\" not in value.lower() or not value.rsplit("\\", 1)[-1]:
            continue

        pipe_spans.append((match.start(), match.start() + len(value)))
        col.add(
            "named_pipe", value, module, location,
            _ctx(text, match.start(), match.start() + len(value)),
        )

    for match in _FILEPATH_RE.finditer(text):
        value = match.group(0).rstrip(".,;:)]}")
        start = match.start()
        end = start + len(value)

        if any(
            a <= start < b
            for a, b in registry_spans + pipe_spans
        ):
            continue

        # Validate the candidate only; source collection remains unchanged.
        if (
            value.endswith("\\")
            or len(value) < 4
            or not _valid_filepath(value)
            or _is_self_path(value)
            or re.match(r"(?i)[a-z]:\\a\\(?:\d+|_work)\\", value)   # Azure / GitHub build agent (D:\a\1\s\…)
        ):
            continue

        col.add(
            "filepath", value, module, location,
            _ctx(text, start, end),
        )

    for match in _MAC_RE.finditer(text):
        value = match.group(0).lower().replace("-", ":")
        octets = value.split(":")
        if len(octets) == 6 and any(int(octet, 16) for octet in octets):
            col.add(
                "mac_address", value, module, location,
                _ctx(text, match.start(), match.end()),
            )

    code_text = _code_like(text)
    for match in _DOMAIN_RE.finditer(text):
        if any(a <= match.start() < b for a, b in url_spans):
            continue

        domain = match.group(1).lower()
        strict = (
            bool(_CODE_LOCATION.search(location or ""))
            or module in ("javascript", "vipermonkey")
        )

        if (
            _looks_like_filename(domain)
            or not _known_tld(domain, strict)
            or domain in _NAMESPACE_HOSTS
            or (domain.endswith(".so") and re.match(r"\.\d", text[match.end():match.end() + 2]))  # libfoo.so.1
            or _CODE_MEMBER_AFTER.match(text, match.end())              # a.download = …, obj.show(…)
            or _is_reference_host(domain)
            or (len(labels := domain.split(".")) == 2 and labels[1] in _MEMBER_TLDS)
            or labels[0] in _CODE_OBJECTS
            or re.match(r"\d?(?:system|microsoft|mscorlib)$", labels[0])     # .NET namespaces (System.Net…)
            or (floss and all(len(x) <= 2 for x in labels[:-1]))             # c.sc.ki: FLOSS junk
            or text[match.start() - 1:match.start()] == "]"            # [MsiProperty].NET
            # bundled code: a bare host is only one written as a string literal
            or (code_text and text[match.start() - 1:match.start()] not in ("\"", "'", "`", "/", "@"))
        ):
            continue

        col.add(
            "domain", domain, module, location,
            _ctx(text, match.start(), match.end()),
        )


def extract(sources: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract IOCs from a list of {module, location, text} sources."""
    collector = _Collector()

    for source in sources:
        _scan_text(
            source.get("text") or "",
            source.get("module", ""),
            source.get("location", ""),
            collector,
        )

    return collector.result()


# Keys containing hashes/identifiers computed by the app itself, not sample content.
_SKIP_KEYS = {
    "sha1", "sha256", "sha384", "sha512", "md5", "imphash", "ssdeep",
    "tlsh", "pehash", "crc32", "digest", "checksum", "fingerprint",
    "entropy", "code_file",
}


# Text the app writes about the sample (finding titles, where it was found,
# its own storage paths), not content of the sample: never mined.
_APP_TEXT_KEYS = {
    "detail", "location", "origin", "label", "note",
    "stored_path", "code_file", "code_file_deob", "view_id", "decrypted_from",
}
# Tool run bookkeeping: the command line the app ran, its errors and paths.
_TOOL_META = re.compile(r"(?:^|/)tools/[^/]+/(?:command|error|stderr|cwd|returncode|timeout)$")


def _skip_key(key: Any) -> bool:
    name = str(key).lower()
    return (name.startswith("_") or name in _SKIP_KEYS or name in _APP_TEXT_KEYS or "hash" in name
            or any(h in name for h in ("sha1", "sha256", "sha512", "md5")))


def _walk(
    node: Any,
    module: str,
    location: str,
    sources: list[dict[str, Any]],
) -> None:
    """Collect every non-empty string under node, tagged with its key path."""
    if isinstance(node, str):
        if node.strip():
            sources.append({
                "module": module,
                "location": location or module,
                "text": node,
            })

    elif isinstance(node, dict):
        for key, value in node.items():
            if _skip_key(key):
                continue

            sublocation = f"{location}/{key}" if location else str(key)
            if _TOOL_META.search(sublocation) or (
                    module in _MODULE_SKIP_PATHS and _MODULE_SKIP_PATHS[module].search(sublocation)):
                continue
            _walk(value, module, sublocation, sources)

    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            sublocation = (
                f"{location}[{index}]" if location else f"[{index}]"
            )
            _walk(value, module, sublocation, sources)


def _email_sources(
    email: dict[str, Any],
    sources: list[dict[str, Any]],
) -> None:
    """Scan email body/link content, not headers or attachment names."""

    def add(location: str, text: Any) -> None:
        if isinstance(text, str) and text.strip():
            sources.append({
                "module": "email",
                "location": location,
                "text": text,
            })

    add("body", email.get("body_sample"))
    add("body_html", email.get("html_text_sample"))

    for link in email.get("html_links", []) or []:
        add("body_html_link", link)


# Modules whose output is never mined for IOCs. YARA results echo the matched
# bytes, rule metadata (author URLs, references) and hex context, which are
# already covered by the parsers that read the file itself.
# netcheck: our own network enrichment (RDAP abuse contacts, DNS, the pages we
# visited) describes infrastructure, it is not content of the sample. file /
# unlock / findings / iocs: metadata and derived views the app computes.
_SKIP_MODULES = {"yara", "ml", "golang", "code", "dotnet", "netcheck", "file", "unlock", "findings", "iocs", "summary"}
# Per-module paths that hold names/metadata, not content (archive member
# names like "visor.py" or "notas.one" are not domains).
_MODULE_SKIP_PATHS = {
    "archive": re.compile(r"entries\[\d+\]/(?:name|stored_path|path)$"),
    # Binary analysis: the file's own name, the libraries / DLLs / sections it
    # declares (libc.so, KERNEL32.dll, .text), and capa's capability / ATT&CK /
    # MBC names ("query or enumerate registry key", "Query Registry") describe
    # the binary, they are not indicators. Strings, PDB paths, version info and
    # signatures are still mined.
    "msi": re.compile(
        r"items\[\d+\]/(?:file|kind|machine|subsystem|imports_dll(?:\[\d+\])?|capa(?:[/\[].*)?"
        r"|lief/(?:libraries|imports|delay_imports|export_name|exports|sections|format|resource_types|linker"
        r"|mitigations|dll_characteristics|overlay/head)(?:[/\[].*)?"
        # certificate bookkeeping (serials, thumbprints, CA issuer / policy OIDs)
        r"|(?:signature|lief/authenticode|lief/signatures)/.*(?:serial_number|serial|thumbprint"
        r"|certificate_policies(?:\[\d+\])?|issuer)|lief/authenticode/status_message"
        r"|extraction/entries\[\d+\]/(?:name|path|stored_path))$"),
    # the C2 extractors' own bookkeeping (step names, which tool ran)
    "c2": re.compile(r"^(?:timings(?:[/\[].*)?|registry(?:[/\[].*)?|extractor_status(?:/.*)?|runs(?:\[\d+\])?"
                     r"|run_id|interpretations(?:[/\[].*)?"
                     r"|configs\[\d+\]/(?:tools/[^/]+/tool|indicators(?:\[\d+\])?"
                     r"|summary/Indicators(?:\[\d+\])?|public_key|sections/[^/]+/Note|note|status"
                     r"|run_id|raw_ref|extractor|extractor_version|related(?:[/\[].*)?"
                     r"|normalized\[\d+\]/(?:name|type|status|extractor|extractor_version|run_id|raw_ref"
                     r"|evidence|confidence)))$"),
    # emldump's dump of a non-text MIME part (an RTF / Office / binary
    # attachment) is markup and hex, not prose: the attachment itself is
    # analysed as a nested child, which is where its IOCs come from.
    "mailrules": re.compile(r"tools/emldump part \d+ \((?!text/)[^)]*\)/output$"),
    # olevba's description of each indicator ("May run PowerShell commands")
    "oletools": re.compile(r"tools/olevba/analysis\[\d+\]/description$"),
}


def sources_from_modules(
    modules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build scan sources from parser results, preserving email/nested carve-outs."""
    sources: list[dict[str, Any]] = []

    for name, data in modules.items():
        if name in ("golang", "code", "dotnet") and isinstance(data, dict):
            # only the strings the analysed code uses (and FLOSS / certificates),
            # never the Go metadata (module paths such as github.com/... are not IOCs)
            for obj in data.get("objects") or []:
                for item in obj.get("ioc_sources") or []:
                    if isinstance(item, dict) and isinstance(item.get("text"), str) and item["text"].strip():
                        sources.append({"module": name, "location": item.get("location", ""), "text": item["text"]})
            continue
        if name in _SKIP_MODULES or not isinstance(data, (dict, list)):
            continue

        if name == "email":
            if isinstance(data, dict):
                _email_sources(data, sources)

        elif name == "nested":
            if isinstance(data, dict):
                _walk(data.get("findings"), "nested", "", sources)

                for item in data.get("ioc_sources") or []:
                    if (
                        isinstance(item, dict)
                        and item.get("module") not in _SKIP_MODULES
                        and isinstance(item.get("text"), str)
                        and item["text"].strip()
                    ):
                        sources.append({
                            "module": item.get("module", "nested"),
                            "location": item.get("location", ""),
                            "text": item["text"],
                        })
            else:
                _walk(data, "nested", "", sources)

        else:
            _walk(data, name, "", sources)

    return sources
