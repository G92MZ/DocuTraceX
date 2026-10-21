"""Windows shortcuts: ``.lnk`` (binary Shell Link) and ``.url`` / ``.website``
(INI internet shortcuts).

Shortcuts are a very common initial-access lure: a ``.lnk`` whose target is a
LOLBin (``powershell``/``cmd``/``mshta``…) with a hidden window and obfuscated
arguments, or a ``.url`` whose ``URL=`` points to a remote payload (WebDAV/SMB)
or whose ``IconFile=`` sits on a UNC path to steal NTLM hashes.

We parse the structure (LnkParse3 for ``.lnk``, an INI read for ``.url``),
surface the target/arguments/metadata (including the ``.lnk`` tracker block —
the creating host's machine id, useful for attribution) and, crucially, run the
**command line through the scripting engine**: the PowerShell/batch it launches
is deobfuscated and matched against the shared behaviour catalogue, exactly like
a standalone script. Nothing is executed.
"""

from __future__ import annotations

import configparser
import re
from pathlib import Path
from typing import Any

from . import script_rules

_LNK_EXT = {".lnk"}
_URL_EXT = {".url", ".website"}

_LOLBIN = re.compile(
    r"(?i)\b(?:powershell|pwsh|cmd|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|"
    r"msiexec|installutil|regasm|regsvcs|forfiles|wmic|curl|wget|conhost)\b(?:\.exe)?")
_DOC_ICON = re.compile(r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\b")
_DOUBLE_EXT = re.compile(r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|csv)\.(?:lnk|url|website)$")


def _name_findings(rel: str, loc: str) -> list[dict[str, Any]]:
    if _DOUBLE_EXT.search(rel):
        return [_finding("shortcut_double_extension", "high",
                         "double extension disguises the shortcut as a document",
                         loc, rel, "T1036.007")]
    return []


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "", attack: str = "") -> dict:
    return {"tool": "shortcut", "rule": rule, "severity": severity,
            "detail": detail + (f" · {attack}" if attack else ""),
            "location": location, "evidence": evidence[:2000]}


def _guess_lang(cmd: str) -> str:
    low = cmd.lower()
    if "powershell" in low or "pwsh" in low:
        return script_rules.PS
    if "cscript" in low or "wscript" in low or ".vbs" in low:
        return script_rules.VBS
    return script_rules.BAT


def _scan_command(command: str, loc: str) -> list[dict[str, Any]]:
    """Deobfuscate the shortcut's command and run the shared behaviour rules."""
    out: list[dict[str, Any]] = []
    if not command.strip():
        return out
    lang = _guess_lang(command)
    deob = command
    try:
        if lang == script_rules.PS:
            from . import ps_deobf
            r = ps_deobf.deobfuscate(command)
            deob = r["code"] if r.get("changed") else command
        elif lang == script_rules.BAT:
            from . import bat_deobf
            r = bat_deobf.deobfuscate(command)
            deob = r["code"] if r.get("changed") else command
    except Exception:  # noqa: BLE001
        pass
    for h in script_rules.scan(deob, lang):
        out.append(_finding(h["rule"], h["severity"], h["label"].rsplit(" · ", 1)[0],
                            loc, h.get("line", "")[:300], h.get("attack", "")))
    return out


def analyze_lnk(path: Path, rel: str) -> dict[str, Any]:
    loc = f"file:{rel}"
    item: dict[str, Any] = {"kind": "lnk", "file": rel, "findings": []}
    try:
        import LnkParse3
        with open(path, "rb") as fh:
            d = LnkParse3.lnk_file(fh).get_json()
    except Exception as exc:  # noqa: BLE001
        item["error"] = f"could not parse .lnk: {exc}"
        return item

    data = d.get("data") or {}
    link = d.get("link_info") or {}
    hdr = d.get("header") or {}
    extra = d.get("extra") or {}
    env = extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK") or {}
    tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}

    args = str(data.get("command_line_arguments") or "")
    target = str(link.get("local_base_path") or "") or str(env.get("target_unicode") or env.get("target_ansi") or "")
    command = (target + " " + args).strip()
    icon = str(data.get("icon_location") or "")
    show = str(hdr.get("windowstyle") or hdr.get("show_command") or "")
    try:
        size = int(hdr.get("file_size") or 0)
    except (TypeError, ValueError):
        size = 0

    item.update(target=target, arguments=args, command=command[:4000],
                working_directory=str(data.get("working_directory") or ""),
                icon_location=icon, show_command=show, file_size=size,
                description=str(data.get("description") or ""),
                machine_id=str(tracker.get("machine_identifier") or ""))
    item["_full_code"] = command

    f = item["findings"]
    f.extend(_name_findings(rel, loc))
    if _LOLBIN.search(command):
        f.append(_finding("lnk_lolbin_target", "high", "shortcut target is a LOLBin / shell",
                          loc, command[:400], "T1204.002"))
    if re.search(r"(?i)hidden|minimized", show) or re.search(r"(?i)-w(?:indowstyle)?\s+hidden|-nop\b", args):
        f.append(_finding("lnk_hidden_window", "medium", "runs with a hidden/minimized window",
                          loc, (show or args)[:200], "T1564.003"))
    if _DOC_ICON.search(icon) and (_LOLBIN.search(command) or args):
        f.append(_finding("lnk_icon_spoof", "high", "icon disguises the shortcut as a document",
                          loc, icon, "T1036.008"))
    if size > 20000:
        f.append(_finding("lnk_appended_payload", "high",
                          f"unusually large shortcut ({size} bytes) — may carry an appended payload",
                          loc, str(size), "T1027.009"))
    f.extend(_scan_command(command, loc))
    return item


def analyze_url(path: Path, rel: str) -> dict[str, Any]:
    loc = f"file:{rel}"
    item: dict[str, Any] = {"kind": "url", "file": rel, "findings": []}
    try:
        text = path.read_bytes()[:200_000].decode("utf-8", "replace")
    except OSError as exc:
        item["error"] = str(exc)
        return item

    url = icon = workdir = ""
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        cp.read_string(text)
        for sect in cp.sections():
            for k, v in cp.items(sect):
                lk = k.lower()
                url = v if lk == "url" and not url else url
                icon = v if lk == "iconfile" and not icon else icon
                workdir = v if lk == "workingdirectory" and not workdir else workdir
    except configparser.Error:
        pass
    if not url:
        m = re.search(r"(?im)^\s*URL\s*=\s*(.+)$", text)
        url = m.group(1).strip() if m else ""
    if not icon:
        m = re.search(r"(?im)^\s*IconFile\s*=\s*(.+)$", text)
        icon = m.group(1).strip() if m else ""

    item.update(url=url, icon_file=icon, working_directory=workdir)
    f = item["findings"]
    f.extend(_name_findings(rel, loc))
    if url.startswith("\\\\") or re.match(r"(?i)^file:", url):
        f.append(_finding("url_remote_file_target", "high",
                          "internet shortcut points to a remote file (WebDAV/SMB)", loc, url, "T1105"))
    if re.match(r"(?i)^(?:search-ms|ms-[a-z]+|ldap|its|mhtml|res|vbscript|javascript):", url):
        f.append(_finding("url_protocol_handler", "high",
                          "uses a protocol handler often abused for execution", loc, url, "T1218"))
    if icon.startswith("\\\\") or re.match(r"(?i)^file:////", icon):
        f.append(_finding("url_unc_icon_ntlm", "high",
                          "IconFile on a UNC path — forces SMB auth (NTLM hash theft)", loc, icon, "T1187"))
    if re.search(r"(?i)\.(?:exe|scr|dll|hta|ps1|bat|cmd|jse?|vbe?|msi|lnk)(?:\?|$)", url):
        f.append(_finding("url_executable_target", "high",
                          "points to an executable/script payload", loc, url, "T1204.001"))
    return item


def analyze(original: Path, extracted_dir: Path | None = None,
            modules: dict[str, Any] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "shortcut", "status": "ok", "items": [], "findings": []}
    ext = original.suffix.lower()
    if ext in _LNK_EXT:
        item = analyze_lnk(original, original.name)
    elif ext in _URL_EXT:
        item = analyze_url(original, original.name)
    else:
        return res
    res["items"].append(item)
    res["findings"].extend(item.get("findings", []))
    res["counts"] = {"findings": len(res["findings"]), "items": len(res["items"])}
    if res["findings"]:
        res["status"] = "ok_with_findings"
    return res
