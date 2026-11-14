"""Origin fingerprints: values the machine or the kit that built a file leaves in it.

They are shown with each file's own analysis (``fingerprints`` in its module
result: name, value, what it tells) and are never correlated across files or
cases. Read from the structure only, nothing runs:

- **Word (OOXML)**: the document GUID (``w15:docId`` / ``w14:docId``) and the
  revision-save IDs (``rsidRoot``, ``rsid``) of ``word/settings.xml``;
- **Excel (OOXML)**: the build that last saved it (``fileVersion``) and the
  document GUID of ``xr:revisionPtr``;
- **legacy Office (OLE)**: the property-set code page and the root CLSID;
- **VBA** (OLE or ``vbaProject.bin``): the project GUID (``PROJECT`` ``ID=``),
  the platform it was compiled on (``PROJECTSYSKIND``: 32 / 64-bit Windows,
  Mac), its locale (``PROJECTLCID``), code page and VBA version, and the
  version of the compiled p-code cache (``_VBA_PROJECT``);
- **PDF**: the trailer ``/ID`` pair and the XMP ``DocumentID`` / ``InstanceID`` /
  ``OriginalDocumentID`` / derived-from IDs, history and creator tool;
- **LNK**: the MAC address and the time inside the tracker's UUIDv1 object IDs,
  whether that MAC belongs to a hypervisor, and the volume serial / label.
"""

from __future__ import annotations

import io
import re
import struct
import uuid
import zipfile
from datetime import datetime, timedelta
from typing import Any

MAX_RSIDS = 40

# Hypervisor OUIs (IEEE assignments of the virtual NIC vendors): a fact about the address,
# not a baseline — a file made on a VM is a lab / builder clue.
_VM_OUI = {"000569": "VMware", "000C29": "VMware", "001C14": "VMware", "005056": "VMware",
           "080027": "VirtualBox", "0A0027": "VirtualBox", "00155D": "Hyper-V", "525400": "QEMU / KVM",
           "00163E": "Xen", "001C42": "Parallels", "0003FF": "Virtual PC"}
_SYSKIND = {0: "16-bit Windows", 1: "32-bit Windows", 2: "Macintosh", 3: "64-bit Windows"}
_LCID = {0x0409: "en-US", 0x0809: "en-GB", 0x0C0A: "es-ES", 0x040A: "es-ES (traditional)", 0x080A: "es-MX",
         0x040C: "fr-FR", 0x0407: "de-DE", 0x0410: "it-IT", 0x0416: "pt-BR", 0x0816: "pt-PT", 0x0419: "ru-RU",
         0x0422: "uk-UA", 0x0804: "zh-CN", 0x0404: "zh-TW", 0x0411: "ja-JP", 0x0412: "ko-KR", 0x041F: "tr-TR",
         0x0415: "pl-PL", 0x0413: "nl-NL", 0x0429: "fa-IR", 0x0401: "ar-SA", 0x0418: "ro-RO", 0x0405: "cs-CZ"}


def fp(name: str, value: Any, meaning: str) -> dict[str, str]:
    return {"name": name, "value": str(value), "meaning": meaning}


def _lcid(v: int) -> str:
    return f"0x{v:04X}" + (f" ({_LCID[v]})" if v in _LCID else "")


# --- VBA ---------------------------------------------------------------------------------

def _dir_records(raw: bytes) -> dict[str, Any]:
    """PROJECTSYSKIND / LCID / CODEPAGE / VERSION of a decompressed VBA ``dir`` stream."""
    out: dict[str, Any] = {}
    i = 0
    while i + 6 <= len(raw):
        rid, size = struct.unpack_from("<HI", raw, i)
        i += 6
        if rid == 0x0009:                     # PROJECTVERSION: Reserved=4, then major (4) + minor (2)
            if i + 6 <= len(raw):
                out["version"] = f"{struct.unpack_from('<I', raw, i)[0]}.{struct.unpack_from('<H', raw, i + 4)[0]}"
            i += 6
            continue
        if size > len(raw) - i:
            break
        val = raw[i:i + size]
        if rid == 0x0001 and size == 4:
            out["syskind"] = struct.unpack("<I", val)[0]
        elif rid == 0x0002 and size == 4:
            out["lcid"] = struct.unpack("<I", val)[0]
        elif rid == 0x0003 and size == 2:
            out["codepage"] = struct.unpack("<H", val)[0]
        elif rid == 0x0004:
            out["name"] = val.decode("latin-1", "replace")
        elif rid == 0x000F:                   # PROJECTMODULES: the project information ends here
            break
        i += size
    return out


def vba(ole: Any) -> list[dict[str, str]]:
    """Fingerprints of every VBA project in an open ``olefile.OleFileIO``."""
    from oletools.olevba import decompress_stream
    out: list[dict[str, str]] = []
    roots = sorted({"/".join(e[:-1]) for e in ole.listdir() if e and e[-1].upper() == "_VBA_PROJECT"
                    and len(e) >= 2 and e[-2].upper() == "VBA"})
    for vroot in roots[:4]:
        base = vroot.rsplit("/", 1)[0] if "/" in vroot else ""
        where = f" ({base})" if base else ""
        try:
            head = ole.openstream(f"{vroot}/_VBA_PROJECT").read(8)
            if len(head) >= 4 and head[:2] == b"\xcc\x61":
                ver = struct.unpack_from("<H", head, 2)[0]
                out.append(fp("VBA p-code cache version" + where, f"0x{ver:04X}",
                              "0xFFFF: no compiled p-code cache — written by a tool, not saved by Office "
                              "(macro builders / generators)" if ver == 0xFFFF else
                              "version of the compiled p-code: set by the Office build that last compiled the "
                              "macros (a mismatch with the document's application hints at a builder)"))
        except Exception:  # noqa: BLE001
            pass
        try:
            recs = _dir_records(decompress_stream(bytearray(ole.openstream(f"{vroot}/dir").read())))
        except Exception:  # noqa: BLE001
            recs = {}
        if "syskind" in recs:
            out.append(fp("VBA compiled on" + where, _SYSKIND.get(recs["syskind"], recs["syskind"]),
                          "platform of the Office that compiled the project (PROJECTSYSKIND)"))
        if "lcid" in recs:
            out.append(fp("VBA project locale" + where, _lcid(recs["lcid"]),
                          "language of the machine that created the project (PROJECTLCID)"))
        if "codepage" in recs:
            out.append(fp("VBA code page" + where, recs["codepage"], "code page the module sources were saved in"))
        if "version" in recs:
            out.append(fp("VBA project version" + where, recs["version"], "PROJECTVERSION"))
        proj = f"{base}/PROJECT" if base else "PROJECT"
        try:
            text = ole.openstream(proj).read(64 * 1024).decode("latin-1", "replace")
            m = re.search(r'(?im)^ID="(\{[0-9A-F-]{36}\})"', text)
            if m:
                out.append(fp("VBA project GUID" + where, m.group(1),
                              "ID of the VBA project: kept when the document is copied or re-saved"))
        except Exception:  # noqa: BLE001
            pass
    return out


def vba_bytes(data: bytes) -> list[dict[str, str]]:
    try:
        import olefile
        if not olefile.isOleFile(data):
            return []
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return []
    try:
        return vba(ole)
    finally:
        ole.close()


# --- Office ------------------------------------------------------------------------------

def ooxml(zf: zipfile.ZipFile) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    names = set(zf.namelist())
    if "word/settings.xml" in names:
        s = zf.read("word/settings.xml").decode("utf-8", "replace")
        for tag, label in (("w15:docId", "Word document GUID (w15)"), ("w14:docId", "Word document ID (w14)")):
            m = re.search(rf'<{tag}\b[^>]*\b{tag.split(":")[0]}:val="([^"]+)"', s)
            if m:
                out.append(fp(label, m.group(1), "assigned when the document is first created and kept "
                                                  "through copies and edits: the same value = the same original"))
        root = re.search(r'<w:rsidRoot\b[^>]*w:val="([0-9A-Fa-f]{8})"', s)
        if root:
            out.append(fp("Word rsidRoot", root.group(1).upper(),
                          "revision-save ID of the session that created the document"))
        rsids = re.findall(r'<w:rsid\b[^>]*w:val="([0-9A-Fa-f]{8})"', s)
        if rsids:
            shown = " ".join(r.upper() for r in rsids[:MAX_RSIDS])
            out.append(fp(f"Word rsids ({len(rsids)})", shown + (" …" if len(rsids) > MAX_RSIDS else ""),
                          "one ID per editing session: documents sharing them come from the same base "
                          "(the first ones are the template's)"))
    if "xl/workbook.xml" in names:
        s = zf.read("xl/workbook.xml").decode("utf-8", "replace")
        m = re.search(r"<fileVersion\b([^>]*)/?>", s)
        if m:
            attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
            if attrs:
                out.append(fp("Excel file version", " · ".join(f"{k}={v}" for k, v in attrs.items()),
                              "application and build that last saved the workbook (rupBuild)"))
        m = re.search(r'<xr:revisionPtr\b[^>]*documentId="([^"]+)"', s)
        if m:
            out.append(fp("Excel document GUID", m.group(1), "kept through copies and edits of the workbook"))
    for n in sorted(names):
        if n.lower().endswith("vbaproject.bin"):
            try:
                out += vba_bytes(zf.read(n))
            except Exception:  # noqa: BLE001
                pass
    return out


def ole_doc(ole: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    try:
        cp = ole.get_metadata().codepage
        if cp:
            out.append(fp("Property code page", cp, "code page of the machine that wrote the summary properties"))
    except Exception:  # noqa: BLE001
        pass
    try:
        clsid = ole.root.clsid
        if clsid and clsid.strip("0-"):
            out.append(fp("Root CLSID", clsid, "class of the document (Word / Excel / PowerPoint / package…)"))
    except Exception:  # noqa: BLE001
        pass
    try:
        out += vba(ole)
    except Exception:  # noqa: BLE001
        pass
    return out


# --- PDF ---------------------------------------------------------------------------------

_XMP_FIELDS = (("xmpMM:DocumentID", "XMP DocumentID", "the document's ID: kept when it is re-saved or exported "
                                                     "again"),
               ("xmpMM:OriginalDocumentID", "XMP OriginalDocumentID", "ID of the first document this one comes from"),
               ("xmpMM:InstanceID", "XMP InstanceID", "ID of this saved version"),
               ("xmp:CreatorTool", "XMP CreatorTool", "application that created the content"),
               ("pdf:Producer", "XMP Producer", "library or driver that wrote the PDF"))


def _xmp_values(xmp: str, tag: str) -> list[str]:
    vals = re.findall(rf"<{tag}>\s*([^<]+?)\s*</{tag}>", xmp)
    vals += re.findall(rf'\b{tag}="([^"]+)"', xmp)
    return list(dict.fromkeys(v.strip() for v in vals if v.strip()))


def _compressed_xmp(data: bytes) -> bytes:
    """The XMP packet of a /Metadata stream written with /FlateDecode."""
    import zlib
    for m in re.finditer(rb"<<(?:(?!>>).){0,400}?/Type\s*/Metadata(?:(?!>>).){0,400}?>>\s*stream\r?\n", data, re.S):
        if b"FlateDecode" not in m.group(0):
            continue
        end = data.find(b"endstream", m.end())
        try:
            x = zlib.decompressobj().decompress(data[m.end():end if end > 0 else m.end() + 2_000_000], 4_000_000)
        except zlib.error:
            continue
        got = re.search(rb"<x:xmpmeta\b.*?</x:xmpmeta>", x, re.S)
        if got:
            return got.group(0)
    return b""


def pdf(data: bytes) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    ids = re.findall(rb"/ID\s*\[\s*<([0-9A-Fa-f]{16,64})>\s*<([0-9A-Fa-f]{16,64})>\s*\]", data)
    if ids:
        first, last = ids[-1]
        out.append(fp("PDF file ID (trailer /ID)", f"{first.decode().upper()} · {last.decode().upper()}",
                      "first value: set when the PDF was created; second: changes with each update — "
                      "equal values mean it was never modified"))
    m = re.search(rb"<x:xmpmeta\b.*?</x:xmpmeta>", data, re.S)
    raw = m.group(0) if m else _compressed_xmp(data)
    if raw:
        xmp = raw.decode("utf-8", "replace")
        for tag, label, meaning in _XMP_FIELDS:
            vals = _xmp_values(xmp, tag)
            if vals:
                out.append(fp(label, " · ".join(vals[:5]), meaning))
        derived = _xmp_values(xmp, "stRef:documentID") + _xmp_values(xmp, "stRef:instanceID")
        if derived:
            out.append(fp("XMP derived from", " · ".join(dict.fromkeys(derived))[:600],
                          "IDs of the document this one was derived from (exported / saved as)"))
        hist = _xmp_values(xmp, "stEvt:instanceID")
        if hist:
            out.append(fp(f"XMP history ({len(hist)} saves)", " · ".join(hist[:10]),
                          "an ID per save recorded in the history"))
        agents = _xmp_values(xmp, "stEvt:softwareAgent")
        if agents:
            out.append(fp("XMP history software", " · ".join(agents[:10]), "applications that saved it, in order"))
    return out


# --- LNK ---------------------------------------------------------------------------------

def mac_of(droid: str) -> tuple[str, str, str] | None:
    """(MAC, vendor-if-VM, time) of a UUIDv1 object ID; None for other versions."""
    try:
        u = uuid.UUID(droid)
    except (ValueError, TypeError, AttributeError):
        return None
    if u.version != 1:
        return None
    node = f"{u.node:012X}"
    mac = ":".join(node[i:i + 2] for i in range(0, 12, 2))
    when = ""
    try:
        t = datetime(1582, 10, 15) + timedelta(microseconds=u.time // 10)
        when = t.isoformat(sep=" ", timespec="seconds") if 1990 <= t.year <= 2100 else ""
    except OverflowError:
        pass
    return mac, _VM_OUI.get(node[:6], ""), when


def lnk(tracker: dict[str, Any], link_info: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for key, label in (("droid_file_identifier", "tracker object ID"),
                       ("birth_droid_file_identifier", "tracker birth object ID")):
        got = mac_of(str(tracker.get(key) or ""))
        if not got or got[0] in seen:
            continue
        seen.add(got[0])
        mac, vm, when = got
        out.append(fp(f"MAC address ({label})", mac + (f" — {vm} virtual NIC" if vm else ""),
                      "network card of the machine where the target was tracked"
                      + ("; a hypervisor's address: the shortcut was made on a virtual machine" if vm else "")))
        if when:
            out.append(fp(f"Object ID time ({label})", when + " UTC",
                          "when the machine created the tracking ID of the target"))
    b, c = tracker.get("birth_droid_file_identifier"), tracker.get("droid_file_identifier")
    if b and c and b != c:
        out.append(fp("Tracker IDs differ", "birth ≠ current", "the target was moved or copied after it was first tracked"))
    loc = (link_info or {}).get("location_info") or link_info or {}
    for k, label in (("drive_serial_number", "Volume serial"), ("volume_label", "Volume label"),
                     ("drive_type", "Drive type")):
        v = loc.get(k)
        if v not in (None, "", 0):
            out.append(fp(label, v, "volume of the machine where the target lived"))
    return out


# --- PE ----------------------------------------------------------------------------------

def pe(lf: dict[str, Any]) -> list[dict[str, str]]:
    """The build-environment values LIEF already reads, gathered with the others."""
    out: list[dict[str, str]] = []
    for p in lf.get("pdb") or []:
        if p.get("path"):
            out.append(fp("PDB path", p["path"], "build folder of the project (user / project names)"))
        if p.get("guid"):
            out.append(fp("PDB GUID · age", f"{p['guid']} · {p.get('age', '')}",
                          "ID of that build's debug file: identical in every copy of the same build"))
    rh = lf.get("rich_header") or {}
    if rh.get("key"):
        out.append(fp("Rich header key", rh["key"], "checksum of the linked objects and tools: same toolchain "
                                                    "and object set"))
    if rh.get("md5"):
        out.append(fp("Rich header MD5", rh["md5"], "hash of the decoded Rich header (toolchain fingerprint)"))
    if lf.get("imphash"):
        out.append(fp("Imphash", lf["imphash"], "hash of the imported functions"))
    for sig in lf.get("signatures") or []:
        for c in (sig.get("certificates") or [])[:1]:
            out.append(fp("Signer certificate", f"{c.get('subject', '')} · serial {c.get('serial', '')}",
                          "who signed it (a stolen or leaked certificate is reused across families)"))
    return out
