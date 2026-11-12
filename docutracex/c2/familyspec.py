"""The common layer of the C2 families: what every RAT / stealer configuration
holds, read the same way whatever the family.

A family is described by a :class:`Spec` — which of its settings is the C2,
the mutex, the install path, the persistence, an option or an exfiltration
channel; the builder's default values; the traces left when nothing decrypts.
Only *finding and decrypting* the configuration stays specific to each
extractor. :func:`interpret` then turns the named settings into the card every
family shares (C2, version, group, mutex, install path, persistence, options in
plain words, exfiltration, the pinned certificate, builder defaults), and
:func:`traces` gives the "indicators only" result when the settings cannot be
read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

ON = ("true", "1", "yes", "on")
# Environment.SpecialFolder names (what .NET builders store) → the folder they mean
SPECIAL = {"applicationdata": "%AppData%", "localapplicationdata": "%LocalAppData%",
           "commonapplicationdata": "%ProgramData%", "programfiles": "%ProgramFiles%",
           "programfilesx86": "%ProgramFiles(x86)%", "userprofile": "%UserProfile%", "windows": "%WinDir%",
           "system": "%WinDir%\\System32", "startup": "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "mydocuments": "%UserProfile%\\Documents", "desktop": "%UserProfile%\\Desktop", "temp": "%Temp%"}

RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
# exfiltration roles: (label, sensitive)
EXFIL = {"smtp_server": ("SMTP server", False), "smtp_port": ("SMTP port", False), "smtp_user": ("SMTP user", True),
         "smtp_password": ("SMTP password", True), "smtp_to": ("Mail to", False), "smtp_from": ("Mail from", False),
         "ftp_server": ("FTP server", False), "ftp_user": ("FTP user", True), "ftp_password": ("FTP password", True),
         "telegram_token": ("Telegram bot token", True), "telegram_chat": ("Telegram chat ID", False),
         "discord_webhook": ("Discord webhook", True)}


@dataclass
class Spec:
    """One family's settings, by role.

    ``fields`` maps a setting's name (lower case; for configurations read by
    position, the position as a string) to its role: ``hosts``, ``ports``,
    ``dead_drop``, ``version``, ``group``, ``mutex``, ``install``,
    ``install_folder``, ``install_subdir``, ``install_name``, ``install_hidden``,
    ``startup``, ``startup_name``, ``certificate``, an option (see ``options``) or
    an exfiltration role (:data:`EXFIL`).
    """
    family: str
    fields: dict[str, str]
    # role → (kind, text): kind "flag" (shown when on), "seconds" / "ms" (with {v} seconds), "value" ({v})
    options: dict[str, tuple[str, str]] = field(default_factory=dict)
    # persistence: "install_name" (the install file's stem names it) or "startup_name" (a setting names it)
    persistence: str = ""
    persistence_text: tuple[str, str] = ('scheduled task "{name}" at logon (when run as admin)',
                                         RUN_KEY + "\\{name} (otherwise)")
    install_default_folder: str = "%AppData%"
    # role → {value: note}; prefixes: (role, prefix, note)
    defaults: dict[str, dict[str, str]] = field(default_factory=dict)
    default_prefixes: tuple[tuple[str, str, str], ...] = ()
    traces: tuple[tuple[bytes, str], ...] = ()
    min_traces: int = 3


def roles(spec: Spec, named: dict[str, str]) -> dict[str, str]:
    """Named settings → {role: value} (first setting of each role wins)."""
    out: dict[str, str] = {}
    for k, v in named.items():
        r = spec.fields.get(str(k).lower())
        if r and r not in out and v is not None:
            out[r] = str(v)
    return out


def known(spec: Spec, named: dict[str, str]) -> bool:
    """Whether the names say something (an obfuscator may have renamed every field)."""
    return any(str(k).lower() in spec.fields for k in named)


def _on(v: str) -> bool:
    return str(v).strip().lower() in ON


def _folder(v: str, default: str) -> str:
    v = (v or "").strip() or default
    if not v.startswith("%") and "\\" not in v:
        v = SPECIAL.get(v.lower(), f"<{v}>")
    return v


def interpret(spec: Spec, named: dict[str, str], certificate: Any = None) -> tuple[dict[str, Any], list[str]]:
    """Named settings → (card summary, C2 hosts).

    ``certificate``: a callable reading a pinned certificate (base64) into card fields."""
    g = roles(spec, named)
    summary: dict[str, Any] = {}
    hosts: list[str] = []
    pairs: list[str] = []
    ports = [p.strip() for p in re.split(r"[;,|]", g.get("ports", "")) if p.strip().isdigit()]
    for h in (x.strip() for x in re.split(r"[;,|]", g.get("hosts", "")) if x.strip() and x.strip().lower() != "null"):
        if ":" in h and h.rsplit(":", 1)[1].isdigit():            # host:port in the hosts setting
            pairs.append(h)
            hosts.append(h.rsplit(":", 1)[0])
        else:
            hosts.append(h)
            pairs += [f"{h}:{p}" for p in ports] or [h]
    if pairs:
        summary["C2"] = list(dict.fromkeys(pairs))
    paste = g.get("dead_drop", "")
    if paste and paste.lower() != "null":
        summary["Dead drop (Pastebin)"] = paste
        summary["Note"] = ("the C2 host:port is downloaded from this paste when the client starts: "
                           "the paste is the lead, its content can change")
        host = re.sub(r"^[a-z]+://", "", paste).split("/", 1)[0]
        if host:
            hosts.append(host)
    for role, label in (("version", "Version"), ("group", "Group"), ("mutex", "Mutex")):
        if g.get(role):
            summary[label] = g[role]
    # install
    if "install" in g:
        if _on(g["install"]):
            parts = [_folder(g.get("install_folder", ""), spec.install_default_folder),
                     g.get("install_subdir", ""), g.get("install_name", "")]
            summary["Install path"] = "\\".join(p for p in parts if p) + (
                " (hidden file)" if _on(g.get("install_hidden", "")) else "")
        else:
            summary["Install"] = "no (runs from where it is)"
    # persistence
    name = ""
    if spec.persistence == "install_name" and _on(g.get("install", "")):
        name = g.get("install_name", "").rsplit(".", 1)[0] if g.get("install_name") else ""
    elif spec.persistence == "startup_name" and _on(g.get("startup", "")):
        name = g.get("startup_name", "")
    if name:
        summary["Persistence"] = [t.format(name=name) for t in spec.persistence_text]
    # options in plain words
    opts = []
    for role, (kind, text) in spec.options.items():
        v = g.get(role, "")
        if kind == "flag" and _on(v):
            extra = ""
            if role == "keylogger" and g.get("log_dir"):
                extra = f', logs in the folder "{g["log_dir"]}"' + (" (hidden)" if _on(g.get("log_hidden", "")) else "")
            opts.append(text + extra)
        elif kind == "seconds" and v.isdigit() and int(v) > 0:
            opts.append(text.format(v=int(v)))
        elif kind == "ms" and v.isdigit():
            opts.append(text.format(v=int(v) // 1000))
        elif kind == "value" and v and v.lower() not in ("null", "false", "0"):
            opts.append(text.format(v=v))
    if opts:
        summary["Options"] = opts
    # exfiltration (stealers): the channel, credentials marked sensitive
    ex = [f"{EXFIL[r][0]}: {g[r]}" for r in EXFIL if g.get(r) and g[r].lower() != "null"]
    if ex:
        summary["Exfiltration"] = ex
        if any(EXFIL[r][1] for r in EXFIL if g.get(r) and g[r].lower() != "null"):
            summary["Sensitive"] = ("the exfiltration credentials are the operator's: handle them as evidence, "
                                    "do not log in with them")
        for r in ("smtp_server", "ftp_server"):
            if g.get(r) and g[r].lower() != "null":
                hosts.append(re.sub(r"^[a-z]+://", "", g[r]).split("/", 1)[0].split(":", 1)[0])
    # the pinned certificate
    cert = certificate(g["certificate"]) if certificate and g.get("certificate") else {}
    summary.update(cert)
    # builder defaults
    checks = [(r, summary.get(lbl, "")) for r, lbl in (("mutex", "Mutex"), ("group", "Group"))]
    checks += [("certificate_cn", cert.get("Certificate CN", "")), ("startup_name", g.get("startup_name", "")),
               ("install_name", g.get("install_name", ""))]
    defaults = [f"{v} — {spec.defaults[r][v]}" for r, v in checks if v and v in spec.defaults.get(r, {})]
    for r, prefix, note in spec.default_prefixes:
        v = summary.get({"mutex": "Mutex", "group": "Group"}.get(r, r), "") or g.get(r, "")
        if v.startswith(prefix):
            defaults.append(f"{v} — {note}")
    if defaults:
        summary["Builder defaults"] = defaults
    return {k: v for k, v in summary.items() if v not in ("", [], None)}, list(dict.fromkeys(h for h in hosts if h))


def traces(spec: Spec, data: bytes, family: str | None = None) -> dict[str, Any] | None:
    """Indicators only: at least ``min_traces`` distinct traces of the family, no configuration."""
    hits = list(dict.fromkeys(what for needle, what in spec.traces if needle in data))
    if len(hits) < spec.min_traces:
        return None
    fam = family or spec.family
    return {"family": fam, "kind": "indicators", "method": "static indicators", "confidence": "low",
            "status": "indicators only", "c2": [], "fields": {}, "indicators": hits,
            "summary": {"Indicators": hits,
                        "Configuration": "not decrypted (another salt or a modified builder)"},
            "note": f"{fam} traces without a readable configuration: no C2 recovered."}
