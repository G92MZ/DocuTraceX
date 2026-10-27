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
_FILEPATH_RE = re.compile(
    r"(?i)(?<![\w])(?:"
    r"[A-Z]:\\(?:[^\s\"'<>|?*]+\\)*[^\s\"'<>|?*]+|"
    r"%[A-Z0-9_()]+%\\(?:[^\s\"'<>|?*]+\\)*[^\s\"'<>|?*]+|"
    r"\\\\[^\\\s]+\\[^\\\s]+(?:\\[^\s\"'<>|?*]+)*"
    r")"
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
_COMMAND_RE = re.compile(
    rf"(?i)\b(?:{'|'.join(_SENSITIVE_COMMANDS)})(?:\.exe)?\b\s+"
    r"(?:/[a-z0-9_/?:.\\*%-]+|-[a-z0-9_/?:.\\*%-]+|\"[^\"]+\"|'[^']+'|[a-z0-9_\\.:*?%$-]+)"
    r"(?:\s+(?:/[a-z0-9_/?:.\\*%-]+|-[a-z0-9_/?:.\\*%-]+|\"[^\"]+\"|'[^']+'|[a-z0-9_\\.:*?%$-]+))*",
    re.IGNORECASE
)

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

_GENERIC_TLDS = set("""
com net org info biz edu gov mil int arpa name pro aero coop museum mobi
asia tel travel jobs cat xyz top online site club app dev cloud store shop
live life world today tech space website fun icu vip work link click download
zip mov win bid loan date racing review stream trade party science cricket
faith accountant men gdn kim ooo rest host press email news blog page one
digital network center company solutions services agency group media studio
support systems software services finance financial bank money pay cash
credit capital fund academy education school college university global
international ltd llc inc gmbh microsoft google apple amazon office windows
live azure aws example test invalid localhost local onion
""".split())

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
    try:
        return ipaddress.IPv6Address(value).compressed
    except ValueError:
        return None


def _clean_url(url: str) -> str:
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
    if tld.startswith("xn--"):
        return True
    if strict:
        return tld in _CODE_TLDS or (
            len(tld) == 2 and len(domain.split(".")) >= 3
        )
    return len(tld) == 2 or tld in _GENERIC_TLDS


def _looks_like_filename(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1].lower() in _FILE_TLDS


# URLs of the analysis tools themselves (banners, help text, tracebacks): never IOCs.
_TOOL_URL_PREFIXES = (
    "github.com/decalage2/", "github.com/borntyping/", "decalage.info/",
    "www.decalage.info/", "github.com/decalage2", "pypi.org/project/oletools",
    "pypi.org/project/colorlog", "pypi.org/project/vipermonkey",
)


def _is_tool_url(url: str) -> bool:
    low = re.sub(r"(?i)^[a-z]+://", "", url).lower()
    return low.startswith(_TOOL_URL_PREFIXES) or any(
        x in low for x in ("/oletools", "/vipermonkey", "/colorlog"))


# The app's own install path (tool output, tracebacks) is never an IOC.
_INSTALL_DIR = str(Path(__file__).resolve().parents[1]).lower().rstrip("\\/")


def _is_self_path(value: str) -> bool:
    low = value.lower().replace("/", "\\")
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

    # Absolute drive path, e.g. C:\\Windows\\cmd.exe
    if re.match(r"(?i)^[a-z]:\\", value):
        components = value[3:].split("\\")

    # UNC path, e.g. \\\\server\\share\\file.exe
    elif value.startswith("\\\\"):
        parts = value[2:].split("\\")
        if len(parts) < 2 or not parts[0] or not parts[1]:
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
        cmd_val = match.group(0).strip(".,;:)]}\"'")
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

        if domain in _NAMESPACE_HOSTS or _is_tool_url(url):
            continue

        tld = (domain or "").rsplit(".", 1)[-1]
        if (
            domain
            and "." in domain
            and ":" not in domain
            and not _valid_ipv4(domain)
            and not (tld.isalpha() or tld.lower().startswith("xn--"))
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
        if _VERSION_BEFORE.search(before) or (
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

    for match in _HASH_RE.finditer(text):
        col.add(
            "hash_like", match.group(0).lower(), module, location,
            _ctx(text, match.start(), match.end()),
        )

    for match in _EMAIL_RE.finditer(text):
        email = match.group(0).rstrip(".,;:")
        if len(email) <= 254 and len(email.split("@", 1)[0]) <= 64:
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


def _skip_key(key: Any) -> bool:
    name = str(key).lower()
    return name.startswith("_") or name in _SKIP_KEYS or "hash" in name


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


def sources_from_modules(
    modules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build scan sources from parser results, preserving email/nested carve-outs."""
    sources: list[dict[str, Any]] = []

    for name, data in modules.items():
        if not isinstance(data, (dict, list)):
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
