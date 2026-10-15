"""DocuTraceX's own detection rules for Office documents (OOXML and legacy OLE).

Static, offline checks for the techniques maldocs actually use, complementing
the third-party tools:

- Remote content pulled in on open: attached remote templates (template
  injection), external OLE objects / frames / sub-documents, MSHTML ``mhtml:``
  targets (CVE-2021-40444), ``ms-msdt:`` (Follina, CVE-2022-30190), protocol
  handlers (``search-ms:``, ``ms-word:``...), UNC / ``file://`` targets (NTLM
  hash leaks) and remote images.
- Fields that load remote resources (INCLUDEPICTURE / INCLUDETEXT / LINK / ...).
- Embedded objects: Equation Editor (CVE-2017-11882 / CVE-2018-0802), OLE
  Package objects carrying scripts/executables, OLE2Link URL monikers
  (CVE-2017-0199), ActiveX controls (by CLSID).
- Excel 4.0 macro sheets, Auto_Open-style names, dangerous XLM functions.
- PowerPoint actions that launch programs (on click / on mouse-over).
- Payload hiding places: document variables and custom properties.
- Attribution: author, last editor, company, template, local paths and Word
  revision ids (rsid).

Nothing is executed and nothing is fetched.
"""

from __future__ import annotations

import io
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

try:
    from defusedxml.ElementTree import fromstring as _xml
except Exception:  # noqa: BLE001
    from xml.etree.ElementTree import fromstring as _xml  # type: ignore

_REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_XL = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"

EQUATION_CLSIDS = {"0002ce02-0000-0000-c000-000000000046", "0002ce03-0000-0000-c000-000000000046"}
URL_MONIKER_CLSID = bytes.fromhex("e0c9ea79f9bace118c8200aa004ba90b")   # 79EAC9E0-BAF9-11CE-8C82-00AA004BA90B
FILE_MONIKER_CLSID = bytes.fromhex("0303000000000000c000000000000046")  # 00000303-0000-0000-C000-000000000046

# ActiveX CLSIDs seen in exploits/abuse -> (name, severity).
ACTIVEX: dict[str, tuple[str, str]] = {
    "bdd1f04b-858b-11d1-b16a-00c0f0283628": ("MSCOMCTL ListView (CVE-2012-0158)", "high"),
    "c74190b6-8589-11d1-b16a-00c0f0283628": ("MSCOMCTL TreeView (CVE-2012-0158)", "high"),
    "996bf5e0-8044-4650-adeb-0b013914e99c": ("MSCOMCTL ListView 2", "high"),
    "8856f961-340a-11d0-a96b-00c04fd705a2": ("Shell.Explorer (embedded browser)", "high"),
    "04a1e553-fe36-4fde-865e-344194e69424": ("InkPicture (used to auto-run macros)", "high"),
    "ec2b2f4a-a45f-4e1a-a50c-c0e9f8c0f8b5": ("Windows Media Player (abused)", "medium"),
    "6bf52a52-394a-11d3-b153-00c04f79faa6": ("Windows Media Player", "medium"),
    "d27cdb6e-ae6d-11cf-96b8-444553540000": ("Shockwave Flash", "high"),
    "8bd21d40-ec42-11ce-9e0d-00aa006002f3": ("Forms.ComboBox", "low"),
    "8bd21d10-ec42-11ce-9e0d-00aa006002f3": ("Forms.TextBox", "low"),
    "d7053240-ce69-11cd-a777-00dd01143c57": ("Forms.CommandButton", "low"),
    "4c599241-6926-101b-9992-00000b65c6f9": ("Forms.Image", "low"),
}

RISKY_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".wsh", ".hta", ".jar", ".ps1", ".lnk", ".dll", ".cpl", ".msi", ".reg", ".url", ".chm",
    ".iso", ".img", ".vhd", ".vhdx", ".sct", ".inf", ".xll", ".html", ".htm", ".svg",
}

XLM_DANGEROUS = ("EXEC", "CALL", "REGISTER", "URLDOWNLOADTOFILE", "RUN", "FORMULA.FILL",
                 "FOPEN", "FWRITE", "FWRITELN", "SHELL", "CREATEOBJECT", "WINEXEC")
_AUTO_NAMES = ("auto_open", "auto_close", "auto_activate", "auto_deactivate")
_LOCAL_PATH = re.compile(r"(?:[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\<>\"|*?\r\n]{1,64}"
                         r"(?:\\[^\\<>\"|*?\r\n]{1,128}){0,6})|(?:/Users/[^/<>\"\r\n]{1,64}(?:/[^/<>\"\r\n]{1,128}){0,6})")
_FIELD_RESOURCE = re.compile(r"^\s*(INCLUDEPICTURE|INCLUDETEXT|LINK|IMPORT|HYPERLINK|DDEAUTO|DDE)\b\s*"
                             r"(?:\\\w\s+)*\"?([^\"\s]+)", re.IGNORECASE)


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "officerules", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


def _remote_kind(target: str) -> tuple[str, str, str] | None:
    """Classify an external target. Returns (rule, severity, label) or None."""
    t = target.strip().lower()
    if "ms-msdt:" in t:
        return "follina_msdt", "high", "ms-msdt: handler (Follina, CVE-2022-30190)"
    if t.startswith("mhtml:") or "!x-usc:" in t:
        return "mshtml_mhtml", "high", "MSHTML mhtml:/x-usc: target (CVE-2021-40444)"
    if t.startswith(("search-ms:", "search:", "ms-search:")):
        return "search_ms_handler", "high", "search-ms: protocol handler"
    if t.startswith(("ms-officecmd:", "ms-word:", "ms-excel:", "ms-powerpoint:", "ms-access:")):
        return "office_protocol_handler", "medium", "Office protocol handler"
    if t.startswith("file:") or t.startswith("\\\\") or t.startswith("//"):
        return "unc_file_target", "high", "UNC / file:// target (NTLM hash leak / remote load)"
    return None


# --- OOXML -------------------------------------------------------------------------

def _ooxml_rels(zf: zipfile.ZipFile) -> list[dict[str, str]]:
    out = []
    for name in zf.namelist():
        if not name.endswith(".rels"):
            continue
        try:
            root = _xml(zf.read(name))
        except Exception:  # noqa: BLE001
            continue
        for el in root:
            if el.tag == f"{_REL_NS}Relationship":
                out.append({"rels_file": name, "type": (el.get("Type") or "").rsplit("/", 1)[-1],
                            "target": el.get("Target") or "", "mode": el.get("TargetMode") or "Internal"})
    return out


def _rules_relationships(rels: list[dict[str, str]], res: dict[str, Any]) -> None:
    for r in rels:
        if r["mode"] != "External":
            continue
        t, typ, loc = r["target"], r["type"], r["rels_file"]
        kind = _remote_kind(t)
        if kind:
            res["findings"].append(_finding(kind[0], kind[1], f"{kind[2]} in a '{typ}' relationship",
                                            loc, t))
        if typ == "attachedTemplate":
            res["findings"].append(_finding(
                "remote_template", "high",
                "Remote template loaded when the document opens (template injection)", loc, t))
        elif typ == "oleObject":
            extra = " — HTML target (CVE-2021-40444 pattern)" if re.search(r"\.html?\b|mhtml:", t, re.I) else ""
            res["findings"].append(_finding("external_ole_object", "high",
                                            f"OLE object loaded from an external location{extra}", loc, t))
        elif typ in ("subDocument", "frame"):
            res["findings"].append(_finding("remote_subdocument", "high",
                                            f"External {typ} loaded into the document", loc, t))
        elif typ == "image" and t.lower().startswith(("http:", "https:")):
            res["findings"].append(_finding("remote_image", "medium",
                                            "Remote image fetched on open (tracking / beacon)", loc, t))


def _rules_word_fields(zf: zipfile.ZipFile, res: dict[str, Any]) -> None:
    parts = [n for n in zf.namelist() if re.match(r"word/(document|header\d*|footer\d*)\.xml$", n)]
    for name in parts:
        try:
            root = _xml(zf.read(name))
        except Exception:  # noqa: BLE001
            continue
        instrs = [i.text for i in root.iter(f"{_W}instrText") if i.text]
        instrs += [f.get(f"{_W}instr") for f in root.iter(f"{_W}fldSimple") if f.get(f"{_W}instr")]
        for instr in instrs:
            m = _FIELD_RESOURCE.match(instr)
            if not m:
                continue
            field, target = m.group(1).upper(), m.group(2)
            low = target.lower()
            if field in ("INCLUDEPICTURE", "INCLUDETEXT", "LINK", "IMPORT") and \
                    (low.startswith(("http:", "https:", "ftp:", "file:", "\\\\")) or "://" in low):
                sev = "high" if field in ("INCLUDETEXT", "LINK") or low.startswith(("\\\\", "file:")) else "medium"
                res["findings"].append(_finding("remote_field_resource", sev,
                                                f"{field} field loads a remote resource", name, instr.strip()))
            kind = _remote_kind(target)
            if kind:
                res["findings"].append(_finding(kind[0], kind[1], f"{kind[2]} in a {field} field",
                                                name, instr.strip()))
        # Document variables: a classic hiding place for macro payloads.
    settings = zf.namelist() and "word/settings.xml" in zf.namelist()
    if settings:
        try:
            root = _xml(zf.read("word/settings.xml"))
            dvars = [(v.get(f"{_W}name") or "", v.get(f"{_W}val") or "")
                     for v in root.iter(f"{_W}docVar")]
            if dvars:
                big = [n for n, v in dvars if len(v) > 200]
                sev = "high" if big else "medium"
                res["findings"].append(_finding(
                    "document_variables", sev,
                    f"{len(dvars)} document variable(s) (macros often read payloads from them)"
                    + (f"; large: {', '.join(big[:5])}" if big else ""),
                    "word/settings.xml",
                    "\n".join(f"{n} = {v[:160]}" for n, v in dvars[:10])))
            res["attribution"]["rsid_count"] = sum(1 for _ in root.iter(f"{_W}rsid"))
        except Exception:  # noqa: BLE001
            pass


def _rules_activex(zf: zipfile.ZipFile, res: dict[str, Any]) -> None:
    for name in zf.namelist():
        if not re.search(r"/activeX/activeX\d+\.xml$", name):
            continue
        try:
            text = zf.read(name).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        m = re.search(r"classid=\"\{([0-9A-Fa-f-]{36})\}\"", text)
        if not m:
            continue
        clsid = m.group(1).lower()
        label, sev = ACTIVEX.get(clsid, ("unknown control", "medium"))
        res["findings"].append(_finding("activex_control", sev, f"ActiveX control: {label}",
                                        name, f"CLSID {{{clsid.upper()}}}"))


def _rules_embedded_ole(data: bytes, location: str, res: dict[str, Any]) -> None:
    """Equation Editor, Package (Ole10Native) and OLE2Link in one OLE blob."""
    try:
        import olefile
        if not olefile.isOleFile(data):
            return
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return
    try:
        clsids = {str(ole.root.clsid or "").lower()}
        for entry in ole.listdir(streams=False, storages=True):
            try:
                clsids.add(str(ole.getclsid(entry) or "").lower())
            except Exception:  # noqa: BLE001
                pass
        names = {"/".join(e).lower() for e in ole.listdir()}
        if clsids & EQUATION_CLSIDS or any("equation native" in n for n in names):
            res["findings"].append(_finding(
                "equation_editor", "high",
                "Equation Editor object (CVE-2017-11882 / CVE-2018-0802 exploit vector)",
                location, "CLSID {0002CE02-0000-0000-C000-000000000046} / 'Equation Native' stream"))
        for entry in ole.listdir():
            leaf = entry[-1]
            if leaf == "\x01Ole10Native":
                pkg = parse_ole10native(ole.openstream(entry).read())
                if pkg:
                    ext = Path(pkg["filename"]).suffix.lower()
                    sev = "high" if ext in RISKY_EXT else "medium"
                    res["findings"].append(_finding(
                        "package_object", sev,
                        f"OLE Package object carrying '{pkg['filename']}' ({pkg['size']} bytes)",
                        location, f"source path: {pkg['source_path']}\ntemp path: {pkg['temp_path']}"))
            elif leaf == "\x01Ole":
                url = ole2link_target(ole.openstream(entry).read())
                if url:
                    res["findings"].append(_finding(
                        "ole2link", "high",
                        "OLE2Link to a remote/linked object (CVE-2017-0199 pattern)", location, url))
    finally:
        ole.close()


def parse_ole10native(data: bytes) -> dict[str, Any] | None:
    """Parse an OLE Package (\\x01Ole10Native) header: file name, paths, size."""
    try:
        pos = 4 + 2                                    # total size + flags
        def cstr() -> str:
            nonlocal pos
            end = data.index(b"\x00", pos)
            s = data[pos:end].decode("latin-1", "replace")
            pos = end + 1
            return s
        filename = cstr()
        source = cstr()
        pos += 4                                       # unknown (0x00030000)
        tlen = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        temp = data[pos:pos + tlen].rstrip(b"\x00").decode("latin-1", "replace")
        pos += tlen
        size = struct.unpack_from("<I", data, pos)[0]
        return {"filename": filename, "source_path": source, "temp_path": temp, "size": size}
    except (ValueError, struct.error):
        return None


def ole2link_target(data: bytes) -> str | None:
    """Extract the URL/path of an OLE2Link (\\x01Ole stream with a moniker)."""
    idx = data.find(URL_MONIKER_CLSID)
    if idx >= 0:
        try:
            size = struct.unpack_from("<I", data, idx + 16)[0]
            raw = data[idx + 20: idx + 20 + size]
            return raw.decode("utf-16-le", "replace").split("\x00", 1)[0] or None
        except struct.error:
            return None
    idx = data.find(FILE_MONIKER_CLSID)
    if idx >= 0:
        try:
            alen = struct.unpack_from("<I", data, idx + 18)[0]
            return data[idx + 22: idx + 22 + alen].rstrip(b"\x00").decode("latin-1", "replace") or None
        except struct.error:
            return None
    return None


def _rules_excel(zf: zipfile.ZipFile, res: dict[str, Any]) -> None:
    names = zf.namelist()
    macrosheets = [n for n in names if re.match(r"xl/macrosheets/.*\.xml$", n)]
    if macrosheets:
        res["findings"].append(_finding("xlm_macrosheet", "high",
                                        f"{len(macrosheets)} Excel 4.0 (XLM) macro sheet(s)",
                                        macrosheets[0], ", ".join(macrosheets[:10])))
    wb = "xl/workbook.xml"
    if wb in names:
        try:
            root = _xml(zf.read(wb))
            for dn in root.iter(f"{_XL}definedName"):
                nm = (dn.get("name") or "").lower().replace("_xlnm.", "")
                if nm.startswith(_AUTO_NAMES):
                    res["findings"].append(_finding(
                        "xlm_auto_open", "high",
                        f"Auto-run name '{dn.get('name')}' (runs an XLM macro on open/close)",
                        wb, f"{dn.get('name')} -> {dn.text or ''}"))
        except Exception:  # noqa: BLE001
            pass
    for ms in macrosheets:
        try:
            root = _xml(zf.read(ms))
        except Exception:  # noqa: BLE001
            continue
        hits: list[str] = []
        for f in root.iter(f"{_XL}f"):
            txt = (f.text or "").upper()
            if any(re.search(rf"\b{re.escape(k)}\s*\(", txt) for k in XLM_DANGEROUS):
                hits.append(f.text or "")
        if hits:
            res["findings"].append(_finding("xlm_dangerous_function", "high",
                                            f"{len(hits)} XLM formula(s) with dangerous functions "
                                            "(EXEC/CALL/REGISTER/URLDownloadToFile/...)",
                                            ms, "\n".join("=" + h for h in hits[:10])))


def _rules_powerpoint(zf: zipfile.ZipFile, res: dict[str, Any]) -> None:
    for name in zf.namelist():
        if not re.match(r"ppt/slides/slide\d+\.xml$", name):
            continue
        text = zf.read(name).decode("utf-8", "replace")
        for m in re.finditer(r"<a:(hlinkClick|hlinkMouseOver)\b[^>]*action=\"(ppaction://program[^\"]*)\"", text):
            trigger = "mouse-over" if m.group(1) == "hlinkMouseOver" else "click"
            res["findings"].append(_finding("ppt_program_action", "high",
                                            f"Slide action launches a program on {trigger}",
                                            name, m.group(0)[:300]))


def _rules_addins_custom(zf: zipfile.ZipFile, res: dict[str, Any]) -> None:
    names = zf.namelist()
    addins = [n for n in names if re.search(r"/webextensions/webextension\d*\.xml$", n)]
    for n in addins:
        text = zf.read(n).decode("utf-8", "replace")
        refs = re.findall(r"<we:reference\b[^>]*>", text)
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        res["findings"].append(_finding("office_addin", "medium",
                                        "Office web add-in (loads JavaScript from a web location)",
                                        n, "\n".join(refs[:3] + urls[:5])))
    if "docProps/custom.xml" in names:
        try:
            root = _xml(zf.read("docProps/custom.xml"))
            props = []
            for p in root:
                val = "".join(p.itertext())
                props.append((p.get("name") or "", val))
            big = [(n, v) for n, v in props if len(v) > 200 or re.fullmatch(r"[A-Za-z0-9+/=]{80,}", v or "")]
            if big:
                res["findings"].append(_finding(
                    "custom_property_payload", "medium",
                    f"{len(big)} custom document propert(y/ies) with long/encoded values "
                    "(payload hiding place)", "docProps/custom.xml",
                    "\n".join(f"{n} = {v[:160]}" for n, v in big[:5])))
            res["attribution"]["custom_properties"] = {n: v[:200] for n, v in props[:30]}
        except Exception:  # noqa: BLE001
            pass


def _attribution_ooxml(zf: zipfile.ZipFile, res: dict[str, Any]) -> None:
    att = res["attribution"]
    for part, fields in (("docProps/core.xml", ("creator", "lastModifiedBy", "created", "modified",
                                                "revision", "title")),
                         ("docProps/app.xml", ("Company", "Template", "Application", "AppVersion",
                                               "TotalTime", "Manager"))):
        if part not in zf.namelist():
            continue
        text = zf.read(part).decode("utf-8", "replace")
        for f in fields:
            m = re.search(rf"<(?:\w+:)?{f}\b[^>]*>([^<]*)</", text)
            if m and m.group(1).strip():
                att[f[0].lower() + f[1:]] = m.group(1).strip()
    paths: set[str] = set()
    for name in zf.namelist():
        if name.endswith((".xml", ".rels")):
            try:
                text = zf.read(name).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                continue
            for m in _LOCAL_PATH.finditer(text):
                paths.add(m.group(0)[:200])
    if paths:
        att["local_paths"] = sorted(paths)[:20]
        res["findings"].append(_finding("author_local_path", "low",
                                        f"{len(paths)} local path(s) of the author's machine",
                                        "docProps/xml parts", "\n".join(sorted(paths)[:10])))
    tpl = att.get("template", "")
    if tpl and tpl.lower() not in ("normal", "normal.dotm", "normal.dot") and \
            re.search(r"https?://|\\\\", tpl):
        res["findings"].append(_finding("remote_template_name", "high",
                                        "app.xml Template points to a remote location",
                                        "docProps/app.xml", tpl))


def analyze_ooxml(path: Path) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "officerules", "status": "ok", "findings": [], "attribution": {}}
    if not zipfile.is_zipfile(path):
        return res
    with zipfile.ZipFile(path) as zf:
        rels = _ooxml_rels(zf)
        _rules_relationships(rels, res)
        _rules_word_fields(zf, res)
        _rules_activex(zf, res)
        _rules_excel(zf, res)
        _rules_powerpoint(zf, res)
        _rules_addins_custom(zf, res)
        _attribution_ooxml(zf, res)
        for name in zf.namelist():
            if re.search(r"/embeddings/.*\.bin$", name, re.I):
                _rules_embedded_ole(zf.read(name), name, res)
    return _finalize(res)


# --- Legacy OLE ---------------------------------------------------------------------

def analyze_ole(path: Path) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "officerules", "status": "ok", "findings": [], "attribution": {}}
    try:
        import olefile
        if not olefile.isOleFile(str(path)):
            return res
        data = path.read_bytes()
    except Exception:  # noqa: BLE001
        return res
    # The whole file and every embedded storage (ObjectPool/_*) share the checks.
    _rules_embedded_ole(data, "document", res)
    try:
        ole = olefile.OleFileIO(str(path))
        try:
            md = ole.get_metadata()
            for attr in ("author", "last_saved_by", "company", "template", "title",
                         "creating_application", "create_time", "last_saved_time"):
                v = getattr(md, attr, None)
                if v:
                    res["attribution"][attr] = v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v)
            tpl = res["attribution"].get("template", "")
            if re.search(r"https?://|\\\\", tpl):
                res["findings"].append(_finding("remote_template_name", "high",
                                                "Document template points to a remote location",
                                                "SummaryInformation", tpl))
            # Strings of the main streams: local paths and protocol handlers.
            blob = b""
            for s in ("WordDocument", "1Table", "0Table", "Workbook", "Book"):
                if ole.exists(s):
                    blob += ole.openstream(s).read(4 * 1024 * 1024)
            text = blob.decode("latin-1", "replace") + blob.decode("utf-16-le", "replace")
            paths = sorted({m.group(0)[:200] for m in _LOCAL_PATH.finditer(text)})[:20]
            if paths:
                res["attribution"]["local_paths"] = paths
                res["findings"].append(_finding("author_local_path", "low",
                                                f"{len(paths)} local path(s) of the author's machine",
                                                "document streams", "\n".join(paths[:10])))
            for m in re.finditer(r"ms-msdt:[^\s\"'\x00]{0,200}", text, re.I):
                res["findings"].append(_finding("follina_msdt", "high",
                                                "ms-msdt: handler (Follina, CVE-2022-30190)",
                                                "document streams", m.group(0)))
                break
        finally:
            ole.close()
    except Exception:  # noqa: BLE001
        pass
    return _finalize(res)


def _finalize(res: dict[str, Any]) -> dict[str, Any]:
    # Same rule + location + evidence only once.
    seen: set[tuple[str, str, str]] = set()
    uniq = []
    for f in res["findings"]:
        key = (f["rule"], f["location"], f["evidence"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    res["findings"] = uniq
    res["counts"] = {"findings": len(uniq)}
    if uniq:
        res["status"] = "ok_with_findings"
    return res
