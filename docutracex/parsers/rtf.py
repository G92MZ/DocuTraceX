"""RTF analysis: structure, objects, fields, attribution and visible text.

RTF is a favourite maldoc carrier: Word opens it from any extension (a ``.doc``
that is really RTF is common), the parser is extremely tolerant (``{\\rt``
is enough as a header, junk inside hex data is skipped, anything after the last
brace is ignored) and it can embed OLE objects that Word loads with no prompt
(Equation Editor, OLE2Link with ``\\objupdate``, ActiveX...).

This module never renders or executes anything. It runs:

- an own tokenizer (bounded) for the structure (groups, depth, destinations,
  ``\\bin``, data after the end, header), the ``\\info`` group, generator,
  rsid table, document variables / user properties, ``\\*\\template``, fields
  (``\\fldinst``) and the visible text (for the IOC phase);
- oletools ``rtfobj`` (Python API) for the ``\\objdata`` objects, which follows
  Word's own quirks; objects are extracted to ``extracted/rtfobj`` so the
  recursive scan analyses them with their own tools;
- Didier Stevens' ``rtfdump.py`` (groups list and object overview) and
  OfficeMalScanner's ``RTFScan.exe`` when provisioned (raw output);

and turns the results into findings (Equation Editor, OLE2Link, Package,
ActiveX/MSCOMCTL, remote template/fields, font table overflow, pFragments,
deep nesting, ``\\objdata`` obfuscation, data after the end...).
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

from .. import quiet, toolrun
from ..config import settings
from ..logging_config import get_logger

log = get_logger(__name__)

_MAX_BYTES = 60 * 1024 * 1024
_TEXT_BOUND = 200000
_OUTPUT_BOUND = 60000
_MAX_OBJECTS = 50

# Destinations whose content is not visible document text.
_HIDDEN_DEST = {
    "fonttbl", "colortbl", "stylesheet", "info", "pict", "objdata", "objclass", "objname",
    "themedata", "colorschememapping", "datastore", "latentstyles", "listtable",
    "listoverridetable", "rsidtbl", "generator", "xmlnstbl", "mmathpr", "fldinst", "template",
    "sp", "sn", "sv", "filetbl", "revtbl", "pgdsctbl", "panose", "falt", "bkmkstart", "bkmkend",
    "nonshppict", "docvar", "userprops", "oleclsid", "defchp", "defpap", "listpicture",
    "wgrffmtfilter", "pnseclvl", "operator", "author", "title", "subject", "company", "manager",
    "doccomm", "keywords", "category", "comment", "hlinkbase", "creatim", "revtim", "printim",
    "buptim", "propname", "staticval", "objalias", "objsect", "ftnsep", "ftnsepc", "aftnsep",
    "aftnsepc", "protusertbl", "xform", "shpinst",
}
_INFO_FIELDS = ("title", "subject", "author", "operator", "company", "manager", "doccomm",
                "keywords", "category", "comment", "hlinkbase")
_TIME_DEST = ("creatim", "revtim", "printim", "buptim")
_OBJ_WORDS = ("objemb", "objlink", "objautlink", "objsub", "objpub", "objicemb", "objhtml", "objocx",
              "objupdate", "objsetsize", "objw", "objh")

_TOKEN = re.compile(rb"\\([a-zA-Z]{1,32})(-?\d{1,10})? ?|\\'([0-9a-fA-F]{2})|\\(.)|([{}])|([^\\{}]+)",
                    re.DOTALL)
_HEX_JUNK = re.compile(rb"[^0-9a-fA-F\s]")

_EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf",
             ".wsh", ".hta", ".jar", ".ps1", ".lnk", ".dll", ".cpl", ".msi", ".reg", ".url", ".chm",
             ".sct", ".inf", ".xll"}


def is_rtf(head: bytes) -> bool:
    """Word accepts ``{\\rt`` (followed by anything) as an RTF header."""
    return head.lstrip(b"\xef\xbb\xbf")[:4] == b"{\\rt"


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "rtf", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": (evidence or "")[:2000]}


# --- tokenizer --------------------------------------------------------------------------

def parse_structure(data: bytes) -> dict[str, Any]:
    """Walk the RTF once: structure, info, fields, text, object control words."""
    st: dict[str, Any] = {
        "size": len(data), "groups": 0, "max_depth": 0, "control_words": 0, "bin_count": 0,
        "bin_bytes": 0, "bin_in_objdata": 0, "font_count": 0, "font_max_index": -1,
        "destinations": {}, "end_offset": None, "trailing_bytes": 0, "unbalanced": False,
        "objdata_junk": 0, "objdata_groups": 0, "objdata_cwords": 0, "pfragments": [],
    }
    info: dict[str, str] = {}
    times: dict[str, str] = {}
    fields: list[dict[str, str]] = []
    objects: list[dict[str, Any]] = []
    docvars: list[list[str]] = []
    userprops: list[list[str]] = []
    rsids: list[int] = []
    oleclsids: list[str] = []
    template = ""
    generator = ""
    text_parts: list[str] = []
    text_len = 0

    # Frame: [dest, skip_text, buffer list or None, object index or None, field index or None]
    stack: list[list] = [[None, False, None, None, None]]
    just_opened = False
    star = False
    pos = 0
    n = len(data)
    depth = 0
    uc = 1
    skip_chars = 0
    time_parts: dict[str, int] = {}
    shape_name = None

    def dest_buf() -> list | None:
        return stack[-1][2]

    while pos < n:
        m = _TOKEN.match(data, pos)
        if not m:
            pos += 1
            continue
        pos = m.end()
        word, param, hexch, sym, brace, text = m.groups()
        frame = stack[-1]
        if brace == b"{":
            depth += 1
            st["groups"] += 1
            st["max_depth"] = max(st["max_depth"], depth)
            if frame[0] == "objdata":
                st["objdata_groups"] += 1
            if frame[0] == "docvar" and frame[2] is not None:
                frame[2].append("\x1f")  # {\*\docvar {name}{value}}: separate the sub-groups
            stack.append([frame[0], frame[1], frame[2], frame[3], frame[4]])
            just_opened, star = True, False
            continue
        if brace == b"}":
            if len(stack) > 1:
                done = stack.pop()
                dest, buf = done[0], done[2]
                if buf is not None and buf is not stack[-1][2]:
                    value = "".join(buf).strip()
                    if dest in _INFO_FIELDS:
                        info[dest] = value[:2000]
                    elif dest in _TIME_DEST:
                        t = time_parts
                        if t:
                            times[dest] = (f"{t.get('yr', 0):04d}-{t.get('mo', 0):02d}-{t.get('dy', 0):02d} "
                                           f"{t.get('hr', 0):02d}:{t.get('min', 0):02d}")
                    elif dest == "fldinst" and done[4] is not None:
                        fields[done[4]]["instr"] = (fields[done[4]].get("instr", "") + " " + value).strip()[:4000]
                    elif dest == "fldrslt" and done[4] is not None:
                        fields[done[4]]["result"] = (fields[done[4]].get("result", "") + value)[:1000]
                    elif dest == "objclass" and done[3] is not None:
                        objects[done[3]]["class"] = value[:200]
                    elif dest == "template":
                        template = value[:2000]
                    elif dest == "generator":
                        generator = value.rstrip(";")[:300]
                    elif dest == "sn":
                        shape_name = value
                    elif dest == "sv" and shape_name:
                        if shape_name.lower() == "pfragments":
                            st["pfragments"].append(value[:300])
                        shape_name = None
                    elif dest == "oleclsid":
                        oleclsids.append(value.strip("{}")[:80])
                    elif dest == "docvar":
                        parts = [x for x in value.split("\x1f") if x.strip()]
                        if parts:
                            docvars.append([parts[0][:200], "".join(parts[1:])[:4000]])
                    elif dest in ("propname", "staticval"):
                        if dest == "propname":
                            userprops.append([value[:200], ""])
                        elif userprops:
                            userprops[-1][1] = value[:2000]
                    if dest in _TIME_DEST:
                        time_parts = {}
            depth -= 1
            if depth == 0 and st["end_offset"] is None:
                st["end_offset"] = pos
                break  # Word ignores everything after the document group
            if depth < 0:
                st["unbalanced"] = True
                depth = 0
            just_opened, star = False, False
            continue
        if word is not None:
            st["control_words"] += 1
            w = word.decode("ascii").lower()
            p = int(param) if param is not None else None
            if frame[0] == "objdata":
                st["objdata_cwords"] += 1
            if w == "bin" and p and p > 0:
                st["bin_count"] += 1
                st["bin_bytes"] += p
                if frame[0] == "objdata":
                    st["bin_in_objdata"] += 1
                pos += p
                just_opened = False
                continue
            if w == "uc" and p is not None:
                uc = max(0, p)
            if w == "u" and p is not None and not frame[1]:
                ch = chr(p + 65536 if p < 0 else p) if -32768 <= p <= 65535 else "?"
                _emit(frame, ch, text_parts, ch)
                text_len += 1
                skip_chars = uc
                just_opened = False
                continue
            is_dest = just_opened and (star or w in _HIDDEN_DEST or w in ("fldrslt", "field", "object",
                                                                          "result", "shp", "header",
                                                                          "footer"))
            if just_opened and star:
                is_dest = True
            if is_dest:
                st["destinations"][w] = st["destinations"].get(w, 0) + 1
                frame[0] = w
                frame[1] = frame[1] or w in _HIDDEN_DEST or star
                if w in _INFO_FIELDS or w in _TIME_DEST or w in ("fldinst", "fldrslt", "objclass",
                                                                  "template", "generator", "sn", "sv",
                                                                  "oleclsid", "docvar", "propname",
                                                                  "staticval"):
                    frame[2] = []
                if w == "field":
                    fields.append({"instr": "", "result": ""})
                    frame[4] = len(fields) - 1
                if w == "object":
                    objects.append({"offset": m.start(), "flags": [], "class": ""})
                    frame[3] = len(objects) - 1
                if w == "result":
                    frame[1] = False
                if w == "fldrslt":
                    frame[1] = False
                    frame[2] = []
            if frame[0] == "fonttbl" and w == "f" and p is not None:
                st["font_count"] += 1
                st["font_max_index"] = max(st["font_max_index"], p)
            if frame[0] == "rsidtbl" and w == "rsid" and p is not None and len(rsids) < 5000:
                rsids.append(p)
            if frame[0] in _TIME_DEST and w in ("yr", "mo", "dy", "hr", "min") and p is not None:
                time_parts[w] = p
            if frame[3] is not None and w in _OBJ_WORDS and frame[0] == "object":
                objects[frame[3]]["flags"].append(w if p is None else f"{w}{p}")
            if not frame[1] and w in ("par", "line", "sect", "page", "row") and text_len < _TEXT_BOUND:
                _emit(frame, "\n", text_parts, "\n")
                text_len += 1
            elif not frame[1] and w in ("tab", "cell") and text_len < _TEXT_BOUND:
                _emit(frame, "\t", text_parts, "\t")
            just_opened = False
            continue
        if sym is not None:
            if sym == b"*":
                star = True
                continue
            if sym in (b"\\", b"{", b"}"):
                if skip_chars:
                    skip_chars -= 1
                else:
                    _emit(frame, sym.decode(), text_parts, sym.decode())
            elif sym in (b"\n", b"\r") and not frame[1]:
                _emit(frame, "\n", text_parts, "\n")
            elif sym == b"~":
                _emit(frame, " ", text_parts, " ")
            just_opened = False
            continue
        if hexch is not None:
            if skip_chars:
                skip_chars -= 1
            else:
                ch = bytes([int(hexch, 16)]).decode("cp1252", "replace")
                _emit(frame, ch, text_parts, ch)
                text_len += 1
            just_opened = False
            continue
        if text is not None:
            if frame[0] == "objdata":
                st["objdata_junk"] += len(_HEX_JUNK.findall(text))
                continue
            raw = text.replace(b"\r", b"").replace(b"\n", b"")
            if skip_chars and raw:
                cut = min(skip_chars, len(raw))
                raw, skip_chars = raw[cut:], skip_chars - cut
            if raw:
                s = raw.decode("cp1252", "replace")
                _emit(frame, s, text_parts, s)
                text_len += len(s)
            if raw.strip():
                just_opened = False
    if depth > 0:
        st["unbalanced"] = True
    if st["end_offset"] is not None:
        tail = data[st["end_offset"]:]
        st["trailing_bytes"] = len(tail.strip(b" \t\r\n\x00"))
    text_out = "".join(text_parts)
    text_out = re.sub(r"[ \t]+\n", "\n", text_out)
    text_out = re.sub(r"\n{3,}", "\n\n", text_out).strip()
    return {"structure": st, "info": info, "times": times, "fields": fields, "objects": objects,
            "docvars": docvars, "userprops": userprops, "rsids": rsids, "oleclsids": oleclsids,
            "template": template, "generator": generator, "text": text_out[:_TEXT_BOUND]}


def _emit(frame: list, s: str, text_parts: list[str], visible: str) -> None:
    """Text goes to the open destination buffer (if any) and, when visible, to the body."""
    if frame[2] is not None:
        frame[2].append(s)
    if not frame[1]:
        text_parts.append(visible)


# --- rtfobj ------------------------------------------------------------------------------

def _rtfobj_objects(data: bytes, extracted_dir: Path | None) -> list[dict[str, Any]]:
    from oletools import rtfobj

    parser = rtfobj.RtfObjParser(data)
    parser.parse()
    out_dir = (extracted_dir / "rtfobj") if extracted_dir else None
    objs: list[dict[str, Any]] = []
    for i, o in enumerate(parser.objects[:_MAX_OBJECTS], 1):
        cls = (o.class_name or b"").rstrip(b"\x00").decode("latin-1", "replace") if o.is_ole else ""
        rec: dict[str, Any] = {
            "index": i, "offset": o.start, "is_ole": bool(o.is_ole), "class_name": cls,
            "format_id": o.format_id, "raw_size": len(o.rawdata or b""),
            "ole_size": o.oledata_size, "clsid": o.clsid, "clsid_desc": o.clsid_desc,
            "is_package": bool(o.is_package),
        }
        if o.is_package:
            rec.update(filename=o.filename, source_path=o.src_path, temp_path=o.temp_path,
                       payload_size=len(o.olepkgdata or b""))
        blob, name = None, None
        if o.is_package and o.olepkgdata is not None:
            blob = o.olepkgdata
            name = Path(str(o.filename or "package.bin").replace("\\", "/")).name or "package.bin"
        elif o.is_ole and o.oledata:
            blob, name = o.oledata, f"{re.sub(r'[^A-Za-z0-9._-]', '_', cls or 'object')}.bin"
        elif o.rawdata:
            blob, name = o.rawdata, "raw.bin"
        if blob:
            rec["sha256"] = hashlib.sha256(blob).hexdigest()
            rec["_blob"] = blob
            if out_dir:
                out_dir.mkdir(parents=True, exist_ok=True)
                dest = out_dir / f"obj{i:02d}_{re.sub(r'[^A-Za-z0-9._-]', '_', name)[:80]}"
                dest.write_bytes(blob)
                rec["stored_path"] = dest.relative_to(extracted_dir.parent).as_posix()
        objs.append(rec)
    return objs


# --- external tools ----------------------------------------------------------------------

def _rtfdump(path: Path) -> dict[str, Any]:
    from .didier import available_scripts
    script = available_scripts().get("rtfdump")
    if not script:
        return {"available": False, "error": "rtfdump.py not provisioned (tools/didier/)"}
    out: dict[str, Any] = {"available": True}
    for key, args in (("groups", []), ("objects", ["-O"])):
        out[key] = toolrun.run(quiet.python_tool_cmd(str(script), [*args, str(path)], script=True),
                               " ".join(["rtfdump.py", *args, path.name]), timeout=120,
                               extra_env=toolrun.with_package_path(), bound=_OUTPUT_BOUND)
    return out


def _rtfobj_cli(path: Path) -> dict[str, Any]:
    return toolrun.run(quiet.python_tool_cmd("oletools.rtfobj", [str(path)]), f"rtfobj {path.name}",
                       timeout=120, extra_env=toolrun.with_package_path(), bound=_OUTPUT_BOUND)


def _rtfscan(path: Path, workdir: Path | None) -> dict[str, Any] | None:
    exe = settings.tools_dir / "officemalscanner" / "RTFScan.exe"
    if not exe.is_file():
        return None
    try:
        proc = subprocess.run([str(exe), str(path), "scan"], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180,
                              cwd=str(workdir) if workdir else None)
        return {"command": f"RTFScan.exe {path.name} scan", "returncode": proc.returncode,
                "output": (proc.stdout or "")[:_OUTPUT_BOUND]}
    except Exception as exc:  # noqa: BLE001
        return {"command": f"RTFScan.exe {path.name} scan", "error": str(exc)}


# --- rules -------------------------------------------------------------------------------

_FIELD = re.compile(r"^\s*(INCLUDEPICTURE|INCLUDETEXT|LINK|IMPORT|HYPERLINK|DDEAUTO|DDE)\b\s*"
                    r"(?:\\\w\s+)*\"?([^\"\s]+)", re.IGNORECASE)
_REMOTE = re.compile(r"^(?:https?:|ftp:|file:|\\\\|//)|://", re.IGNORECASE)


def _rules(res: dict[str, Any], declared_ext: str) -> None:
    from . import office_rules as orules

    f = res["findings"]
    st = res["structure"]
    ext = (declared_ext or "").lower()
    if ext and ext != ".rtf":
        sev = "high" if ext in (".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".wps") else "medium"
        f.append(_finding("rtf_disguised_extension", sev,
                          f"RTF document with a '{ext}' extension (Word opens it as RTF; common evasion)",
                          "header", res["header"]))
    if not res["header"].startswith("{\\rtf1"):
        f.append(_finding("rtf_malformed_header", "medium",
                          "Non-standard RTF header (Word accepts '{\\rt'; used to evade signatures)",
                          "header", res["header"]))
    if st["trailing_bytes"]:
        f.append(_finding("data_after_rtf_end", "medium",
                          f"{st['trailing_bytes']} bytes after the closing brace (ignored by Word; hidden data)",
                          f"offset 0x{st['end_offset']:X}"))
    if st["unbalanced"]:
        f.append(_finding("unbalanced_braces", "low",
                          "Unbalanced braces (Word tolerates it; typical of hand-crafted / obfuscated RTF)",
                          "structure"))
    if st["max_depth"] > 50:
        f.append(_finding("deep_nesting", "medium",
                          f"Group nesting depth {st['max_depth']} (stack exhaustion / parser confusion trick)",
                          "structure"))
    if st["font_count"] > 32000 or st["font_max_index"] > 32000:
        f.append(_finding("font_table_overflow", "high",
                          f"Font table with {st['font_count']} fonts (max index {st['font_max_index']}): "
                          "CVE-2023-21716 heap corruption shape", "fonttbl"))
    for v in st["pfragments"]:
        f.append(_finding("pfragments_shape", "high",
                          "Shape property pFragments (CVE-2010-3333 stack overflow vector)", "shape", v))
    junk = st["objdata_junk"] + st["objdata_groups"] + st["objdata_cwords"] + st["bin_in_objdata"]
    if junk:
        f.append(_finding("objdata_obfuscated", "medium",
                          "Obfuscated \\objdata: non-hex characters, control words, groups or \\bin inside the "
                          "hex data (Word skips them; breaks naive parsers)", "objdata",
                          f"junk chars {st['objdata_junk']}, groups {st['objdata_groups']}, control words "
                          f"{st['objdata_cwords']}, \\bin {st['bin_in_objdata']}"))
    elif st["bin_count"]:
        f.append(_finding("bin_data", "low", f"{st['bin_count']} \\bin block(s), {st['bin_bytes']} bytes of raw "
                          "binary data", "structure"))

    tpl = res.get("template") or ""
    if tpl:
        kind = orules._remote_kind(tpl)
        if _REMOTE.search(tpl) or kind:
            f.append(_finding("remote_template", "high", "Attached template loaded from a remote location "
                              "(template injection)", "\\*\\template", tpl))
        if kind:
            f.append(_finding(kind[0], kind[1], f"{kind[2]} in the attached template", "\\*\\template", tpl))

    for i, fld in enumerate(res["fields"], 1):
        instr = fld.get("instr", "")
        m = _FIELD.match(instr)
        if not m:
            continue
        name, target = m.group(1).upper(), m.group(2)
        loc = f"field#{i}"
        if name in ("DDE", "DDEAUTO"):
            f.append(_finding("dde_field", "high", f"{name} field (runs a command through DDE)", loc, instr))
            continue
        if name in ("INCLUDEPICTURE", "INCLUDETEXT", "LINK", "IMPORT") and _REMOTE.search(target):
            sev = "high" if name in ("INCLUDETEXT", "LINK") or target.startswith(("\\\\", "file:")) else "medium"
            f.append(_finding("remote_field_resource", sev, f"{name} field loads a remote resource", loc, instr))
        kind = orules._remote_kind(target)
        if kind:
            f.append(_finding(kind[0], kind[1], f"{kind[2]} in a {name} field", loc, instr))

    for o in res["objects"]:
        loc = f"object#{o['index']} @0x{(o['offset'] or 0):X}"
        group = _group_for(o, res["object_groups"]) or {}
        flags = group.get("flags", [])
        cls = (o.get("class_name") or group.get("class") or "")
        low = cls.lower()
        clsid = (o.get("clsid") or "").lower()
        desc = o.get("clsid_desc") or ""
        ev = f"class {cls or '?'}; CLSID {o.get('clsid') or '-'} {desc}; flags {' '.join(flags) or '-'}"
        blob = o.get("_blob") or b""
        sub: dict[str, Any] = {"findings": []}
        if blob and not o.get("is_package"):
            orules._rules_embedded_ole(blob, loc, sub)
        rules = {x["rule"] for x in sub["findings"]}
        for x in sub["findings"]:
            x["tool"] = "rtf"
            f.append(x)
        if "equation_editor" not in rules and (low.startswith("equation") or clsid in orules.EQUATION_CLSIDS):
            f.append(_finding("equation_editor", "high",
                              "Equation Editor object (CVE-2017-11882 / CVE-2018-0802 exploit vector)", loc, ev))
        if "ole2link" not in rules and (low == "ole2link" or clsid.startswith("00000300-")):
            f.append(_finding("ole2link", "high", "OLE2Link object (CVE-2017-0199 pattern)", loc, ev))
        if "objupdate" in flags:
            sev = "high" if (low == "ole2link" or "objautlink" in flags or "objlink" in flags) else "medium"
            f.append(_finding("objupdate_autoload", sev,
                              "\\objupdate forces the object to load/refresh when the document opens "
                              "(no user interaction)", loc, ev))
        if o.get("is_package") and "package_object" not in rules:
            fn = o.get("filename") or ""
            sev = "high" if Path(fn).suffix.lower() in _EXEC_EXT else "medium"
            f.append(_finding("package_object", sev, f"OLE Package object carrying '{fn}' "
                              f"({o.get('payload_size', 0)} bytes)", loc,
                              f"source path: {o.get('source_path')}\ntemp path: {o.get('temp_path')}"))
        if "objocx" in flags or "mscomctl" in low or low.startswith("forms."):
            name, sev = orules.ACTIVEX.get(clsid, ("ActiveX control", "medium"))
            if "mscomctl" in low:
                name, sev = "MSCOMCTL control (CVE-2012-0158)", "high"
            f.append(_finding("activex_control", sev, f"{name} embedded in the RTF", loc, ev))
        elif "CVE" in desc and not rules & {"equation_editor", "ole2link"} \
                and not (low.startswith("equation") or low == "ole2link"):
            f.append(_finding("known_exploit_clsid", "high", f"Object CLSID linked to known exploits: {desc}",
                              loc, ev))
    for c in res.get("oleclsids") or []:
        name, sev = orules.ACTIVEX.get(c.lower(), ("ActiveX control", "medium"))
        f.append(_finding("activex_control", sev, f"{name} (\\oleclsid) in a shape", "shape", c))

    big_vars = [v for v in res["docvars"] if len(v[1]) > 200]
    if res["docvars"]:
        f.append(_finding("document_variables", "high" if big_vars else "medium",
                          f"{len(res['docvars'])} document variable(s) (macros often read payloads from them)",
                          "\\*\\docvar", "\n".join(f"{n} = {v[:160]}" for n, v in res["docvars"][:10])))
    big_props = [p for p in res["userprops"] if len(p[1]) > 200]
    if big_props:
        f.append(_finding("custom_property_payload", "medium",
                          f"{len(big_props)} large user property value(s) (possible payload storage)",
                          "\\*\\userprops", "\n".join(f"{n} = {v[:160]}" for n, v in big_props[:5])))
    att = res["attribution"]
    for k in ("author", "operator"):
        v = att.get(k, "")
        if re.search(r"[A-Za-z]:\\Users\\", v):
            f.append(_finding("author_local_path", "low", f"Local path in the {k} field", "\\info", v))


def _group_for(obj: dict[str, Any], groups: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The \\object group that contains an rtfobj object (closest start before it)."""
    best = None
    for g in groups:
        if g["offset"] <= (obj.get("offset") or 0) and (best is None or g["offset"] > best["offset"]):
            best = g
    return best


# --- entry point -------------------------------------------------------------------------

def analyze(path: Path, declared_ext: str = ".rtf", extracted_dir: Path | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "rtf", "available": True, "status": "ok", "findings": [], "tools": {},
                           "error": None}
    try:
        data = path.read_bytes()[:_MAX_BYTES]
    except OSError as exc:
        res.update(status="error", error=str(exc))
        return res
    res["header"] = data.lstrip(b"\xef\xbb\xbf")[:24].decode("latin-1", "replace").split("\\", 3)[:3]
    res["header"] = "\\".join(res["header"])[:20]
    parsed = parse_structure(data)
    st = parsed["structure"]
    res["structure"] = {k: v for k, v in st.items() if k != "destinations"}
    res["destinations"] = dict(sorted(st["destinations"].items(), key=lambda kv: -kv[1])[:40])
    res["object_groups"] = parsed["objects"]
    res["fields"] = [fl for fl in parsed["fields"] if fl.get("instr")]
    res["template"] = parsed["template"]
    res["docvars"] = parsed["docvars"]
    res["userprops"] = parsed["userprops"]
    res["oleclsids"] = parsed["oleclsids"]
    res["text"] = parsed["text"]
    rs = parsed["rsids"]
    res["attribution"] = {**parsed["info"], **parsed["times"],
                          **({"generator": parsed["generator"]} if parsed["generator"] else {}),
                          **({"template": parsed["template"]} if parsed["template"] else {}),
                          **({"rsid_count": len(rs), "rsids": [f"{r:08X}" for r in rs[:40]]} if rs else {}),
                          **({"user_properties": {n: v[:200] for n, v in parsed["userprops"][:30]}}
                             if parsed["userprops"] else {})}
    try:
        res["objects"] = _rtfobj_objects(data, extracted_dir)
    except Exception as exc:  # noqa: BLE001
        res["objects"] = []
        res["tools"]["rtfobj_error"] = str(exc)
    res["tools"]["rtfobj"] = _rtfobj_cli(path)
    res["tools"]["rtfdump"] = _rtfdump(path)
    scan = _rtfscan(path, (extracted_dir / "officemalscanner") if extracted_dir else None)
    if scan is not None:
        res["tools"]["rtfscan"] = scan
        if re.search(r"Malicious Index\s*=\s*([1-9]\d*)", scan.get("output") or "", re.I):
            res["findings"].append(_finding("rtfscan_malicious_index", "medium",
                                            "RTFScan reports a non-zero Malicious Index", "RTFScan",
                                            (scan.get("output") or "")[-600:]))
    _rules(res, declared_ext)
    for o in res["objects"]:
        o.pop("_blob", None)
    seen: set[tuple[str, str, str]] = set()
    uniq = []
    for fd in res["findings"]:
        key = (fd["rule"], fd["location"], fd["evidence"])
        if key not in seen:
            seen.add(key)
            uniq.append(fd)
    res["findings"] = uniq
    res["counts"] = {"findings": len(uniq), "objects": len(res["objects"]), "fields": len(res["fields"])}
    if uniq:
        res["status"] = "ok_with_findings"
    return res
