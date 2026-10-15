"""Builders for realistic (benign) Office test documents.

Each builder writes a structurally real file — OPC packages for OOXML, compound
files for legacy Office — carrying the techniques DocuTraceX detects: VBA
projects (real MS-OVBA, readable by olevba/ViperMonkey), remote templates,
remote fields, ActiveX controls, Equation Editor objects, OLE Package objects,
OLE2Link monikers, document variables, custom properties, web add-ins, Excel 4.0
macro sheets... All payloads are inert documentation examples (example.* hosts,
RFC 5737 IPs); nothing here is executable malware.
"""

from __future__ import annotations

import io
import struct
import zipfile

from cfb import build_cfb
from ovba import Module, vba_project_bin, vba_storage

R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PR = "http://schemas.openxmlformats.org/package/2006/relationships"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

EQUATION_CLSID = bytes.fromhex("02ce020000000000c000000000000046")
URL_MONIKER = bytes.fromhex("e0c9ea79f9bace118c8200aa004ba90b")


# --- OLE objects ---------------------------------------------------------------------

def ole10native(filename: str, payload: bytes, source_path: str | None = None) -> bytes:
    """An OLE Package (\\x01Ole10Native stream), as created by Insert > Object > Package."""
    src = (source_path or f"C:\\Users\\jmartin\\Desktop\\{filename}").encode("latin-1")
    tmp = f"C:\\Users\\jmartin\\AppData\\Local\\Temp\\{filename}".encode("latin-1")
    body = (struct.pack("<H", 2) + filename.encode("latin-1") + b"\x00" + src + b"\x00"
            + struct.pack("<I", 0x00030000) + struct.pack("<I", len(tmp) + 1) + tmp + b"\x00"
            + struct.pack("<I", len(payload)) + payload)
    return struct.pack("<I", len(body)) + body


def package_object(filename: str, payload: bytes) -> bytes:
    """oleObject*.bin holding a Package (what Office stores under embeddings/)."""
    comp_obj = (struct.pack("<IIIi", 0xFFFE0001, 0x00000A03, 0xFFFFFFFF, 0) + b"\x00" * 16
                + struct.pack("<I", 8) + b"Package\x00" + struct.pack("<I", 0) + struct.pack("<I", 0))
    return build_cfb({"\x01Ole10Native": ole10native(filename, payload), "\x01CompObj": comp_obj},
                     root_clsid=bytes.fromhex("0c00030000000000c000000000000046"))


def equation_object() -> bytes:
    """An Equation Editor 3.0 object (MTEF header + a FONT record, inert)."""
    native = struct.pack("<HIHIIII", 0x1C, 0x00020000, 0, 0, 0, 0, 0) + \
        b"\x03\x01\x01\x03\x0a\x0a\x01\x08Courier New\x00" + b"\x00" * 64
    return build_cfb({"Equation Native": native, "\x01Ole": b"\x01\x00\x00\x02" + b"\x00" * 16},
                     root_clsid=EQUATION_CLSID)


def ole2link_object(url: str) -> bytes:
    """An OLE2Link: \\x01Ole stream with a URL moniker (CVE-2017-0199 shape)."""
    u = url.encode("utf-16-le") + b"\x00\x00"
    moniker = URL_MONIKER + struct.pack("<I", len(u)) + u
    ole = (struct.pack("<IIII", 0x02000001, 0x00000001, 0, 0) + struct.pack("<I", 0)
           + struct.pack("<I", 0) + struct.pack("<I", len(moniker)) + moniker + b"\x00" * 16)
    return build_cfb({"\x01Ole": ole, "\x03LinkInfo": b"\x00" * 16},
                     root_clsid=bytes.fromhex("0003000000000000c000000000000046"))


# --- OOXML ---------------------------------------------------------------------------

class Opc:
    """Tiny OPC package builder: parts + relationships + content types."""

    def __init__(self) -> None:
        self.parts: dict[str, bytes] = {}
        self.rels: dict[str, list[tuple[str, str, str, bool]]] = {}
        self.defaults = {"rels": "application/vnd.openxmlformats-package.relationships+xml",
                         "xml": "application/xml", "bin": "application/vnd.ms-office.vbaProject",
                         "png": "image/png", "jpeg": "image/jpeg", "emf": "image/x-emf"}
        self.overrides: dict[str, str] = {}

    def part(self, name: str, data: bytes | str, ct: str | None = None) -> None:
        self.parts[name] = data.encode("utf-8") if isinstance(data, str) else data
        if ct:
            self.overrides["/" + name] = ct

    def rel(self, source: str, rid: str, rtype: str, target: str, external: bool = False) -> None:
        self.rels.setdefault(source, []).append((rid, rtype, target, external))

    def build(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            ct = [XML_DECL + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">']
            ct += [f'<Default Extension="{e}" ContentType="{t}"/>' for e, t in self.defaults.items()]
            ct += [f'<Override PartName="{p}" ContentType="{t}"/>' for p, t in self.overrides.items()]
            z.writestr("[Content_Types].xml", "".join(ct) + "</Types>")
            for source, rels in self.rels.items():
                d, f = (source.rsplit("/", 1) if "/" in source else ("", source))
                rels_name = (f"{d}/_rels/{f}.rels" if d else f"_rels/{f}.rels") if source else "_rels/.rels"
                body = [XML_DECL + f'<Relationships xmlns="{PR}">']
                for rid, rtype, target, ext in rels:
                    mode = ' TargetMode="External"' if ext else ""
                    tgt = target.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
                    body.append(f'<Relationship Id="{rid}" Type="{rtype}" Target="{tgt}"{mode}/>')
                z.writestr(rels_name, "".join(body) + "</Relationships>")
            for name, data in self.parts.items():
                z.writestr(name, data)
        return buf.getvalue()


def core_xml(title: str, creator: str, last_by: str, created: str, modified: str,
             revision: int = 3, keywords: str = "") -> str:
    return (XML_DECL + '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:title>{title}</dc:title><dc:subject></dc:subject><dc:creator>{creator}</dc:creator>"
            f"<cp:keywords>{keywords}</cp:keywords><cp:lastModifiedBy>{last_by}</cp:lastModifiedBy>"
            f"<cp:revision>{revision}</cp:revision>"
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified></cp:coreProperties>')


def app_xml(application: str, company: str, template: str = "Normal.dotm", pages: int = 1,
            total_time: int = 7) -> str:
    return (XML_DECL + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
            f"<Template>{template}</Template><TotalTime>{total_time}</TotalTime><Pages>{pages}</Pages>"
            f"<Application>{application}</Application><DocSecurity>0</DocSecurity>"
            f"<Company>{company}</Company><AppVersion>16.0000</AppVersion></Properties>")


def custom_xml(props: dict[str, str]) -> str:
    items = "".join(
        f'<property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="{i + 2}" name="{k}">'
        f"<vt:lpwstr>{v}</vt:lpwstr></property>" for i, (k, v) in enumerate(props.items()))
    return (XML_DECL + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" '
            f'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">{items}</Properties>')


def w_paragraphs(paragraphs: list[str], fields: list[str] | None = None, rsid: str = "00A1B2C3") -> str:
    body = []
    for p in paragraphs:
        body.append(f'<w:p w:rsidR="{rsid}"><w:r><w:t xml:space="preserve">{p}</w:t></w:r></w:p>')
    for instr in fields or []:
        body.append('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
                    f'<w:r><w:instrText xml:space="preserve"> {instr} </w:instrText></w:r>'
                    '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>Loading…</w:t></w:r>'
                    '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
    return (XML_DECL + f'<w:document xmlns:w="{W}" xmlns:r="{R}"><w:body>{"".join(body)}'
            '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/></w:sectPr></w:body></w:document>')


def w_settings(doc_vars: dict[str, str] | None = None, rsids: list[str] | None = None,
               template_rid: str | None = None) -> str:
    dv = ""
    if doc_vars:
        dv = "<w:docVars>" + "".join(f'<w:docVar w:name="{k}" w:val="{v}"/>' for k, v in doc_vars.items()) + "</w:docVars>"
    rs = ""
    if rsids:
        rs = f'<w:rsids><w:rsidRoot w:val="{rsids[0]}"/>' + "".join(f'<w:rsid w:val="{r}"/>' for r in rsids) + "</w:rsids>"
    tpl = f'<w:attachedTemplate r:id="{template_rid}"/>' if template_rid else ""
    return (XML_DECL + f'<w:settings xmlns:w="{W}" xmlns:r="{R}">{tpl}<w:defaultTabStop w:val="708"/>'
            f"{dv}{rs}</w:settings>")


ACTIVEX_XML = (XML_DECL + '<ax:ocx ax:classid="{{{clsid}}}" ax:persistence="persistStorage" r:id="rId1" '
               'xmlns:ax="http://schemas.microsoft.com/office/2006/activeX" xmlns:r="' + R + '"/>')

WEBEXT_XML = (XML_DECL + '<we:webextension xmlns:we="http://schemas.microsoft.com/office/webextensions/webextension/2010/11" '
              'id="{{7C3A2E8B-0A2C-4F1E-9A7D-3B2E6C1D9F00}}"><we:reference id="wa104380862" version="1.0.0.0" '
              'store="{store}" storeType="Uploaded"/><we:alternateReferences/><we:properties/>'
              '<we:bindings/><we:snapshot/></we:webextension>')


def docm(paragraphs: list[str], modules: list[Module] | None = None, *, fields: list[str] | None = None,
         remote_template: str | None = None, doc_vars: dict[str, str] | None = None,
         custom: dict[str, str] | None = None, activex_clsid: str | None = None,
         embeddings: dict[str, bytes] | None = None, ole_links: list[str] | None = None,
         addin_store: str | None = None, core: str | None = None, app: str | None = None,
         rsids: list[str] | None = None, macro: bool = True) -> bytes:
    """A Word document (.docm/.docx) carrying the requested techniques."""
    o = Opc()
    main_ct = ("application/vnd.ms-word.document.macroEnabled.main+xml" if macro
               else "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
    o.part("word/document.xml", w_paragraphs(paragraphs, fields), main_ct)
    o.rel("", "rId1", f"{R}/officeDocument", "word/document.xml")
    o.part("docProps/core.xml", core or core_xml("Document", "user", "user", "2026-10-01T09:00:00Z",
                                                  "2026-10-02T09:00:00Z"),
           "application/vnd.openxmlformats-package.core-properties+xml")
    o.rel("", "rId2", f"{PR.replace('relationships', 'relationships/metadata/core-properties')}", "docProps/core.xml")
    o.part("docProps/app.xml", app or app_xml("Microsoft Office Word", "Contoso"),
           "application/vnd.openxmlformats-officedocument.extended-properties+xml")
    o.rel("", "rId3", f"{R}/extended-properties", "docProps/app.xml")
    if custom:
        o.part("docProps/custom.xml", custom_xml(custom),
               "application/vnd.openxmlformats-officedocument.custom-properties+xml")
        o.rel("", "rId4", f"{R}/custom-properties", "docProps/custom.xml")
    o.part("word/settings.xml", w_settings(doc_vars, rsids, "rIdTpl" if remote_template else None),
           "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml")
    o.rel("word/document.xml", "rId10", f"{R}/settings", "settings.xml")
    if remote_template:
        o.rel("word/settings.xml", "rIdTpl", f"{R}/attachedTemplate", remote_template, external=True)
    if modules and macro:
        o.part("word/vbaProject.bin", vba_project_bin(modules))
        o.rel("word/document.xml", "rId11", "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
              "vbaProject.bin")
    if activex_clsid:
        o.part("word/activeX/activeX1.xml", ACTIVEX_XML.format(clsid=activex_clsid),
               "application/vnd.ms-office.activeX+xml")
        o.part("word/activeX/activeX1.bin", build_cfb({"contents": b"\x00" * 64}))
        o.rel("word/document.xml", "rId12", f"{R}/control", "activeX/activeX1.xml")
    for i, (name, blob) in enumerate((embeddings or {}).items()):
        o.part(f"word/embeddings/{name}", blob, "application/vnd.openxmlformats-officedocument.oleObject")
        o.rel("word/document.xml", f"rId2{i}", f"{R}/oleObject", f"embeddings/{name}")
    for i, url in enumerate(ole_links or []):
        o.rel("word/document.xml", f"rId3{i}", f"{R}/oleObject", url, external=True)
    if addin_store:
        o.part("word/webextensions/webextension1.xml", WEBEXT_XML.format(store=addin_store),
               "application/vnd.ms-office.webextension+xml")
        o.rel("", "rId5", "http://schemas.microsoft.com/office/2011/relationships/webextensiontaskpanes",
              "word/webextensions/webextension1.xml")
    return o.build()


def doc_legacy(text: str, modules: list[Module] | None = None, *, objects: dict[str, bytes] | None = None,
               summary: bytes | None = None) -> bytes:
    """A legacy .doc compound file: WordDocument/1Table, optional Macros/ VBA
    storage and ObjectPool objects (each object a nested compound file tree)."""
    import olefile  # noqa: F401  (only to fail early if missing in tests)

    word = b"\xec\xa5\xc1\x00" + b"\x00" * 508 + text.encode("utf-16-le")
    tree: dict = {"WordDocument": word, "1Table": b"\x00" * 1024}
    if summary:
        tree["\x05SummaryInformation"] = summary
    if modules:
        tree["Macros"] = vba_storage(modules)
    if objects:
        pool: dict = {}
        for name, blob in objects.items():
            pool[name] = _cfb_tree(blob)
        tree["ObjectPool"] = pool
    return build_cfb(tree)


def _cfb_tree(blob: bytes) -> dict:
    """Read a compound file back into a nested dict (to nest it in another one)."""
    import olefile

    ole = olefile.OleFileIO(io.BytesIO(blob))
    try:
        tree: dict = {}
        for entry in ole.listdir(streams=True, storages=False):
            node = tree
            for part in entry[:-1]:
                node = node.setdefault(part, {})
            node[entry[-1]] = ole.openstream(entry).read()
        return tree
    finally:
        ole.close()


def summary_information(author: str, last_saved_by: str, template: str = "Normal.dotm",
                        title: str = "", app: str = "Microsoft Office Word") -> bytes:
    """A minimal \\x05SummaryInformation property set (strings only)."""
    props = [(0x02, title), (0x04, author), (0x07, template), (0x08, last_saved_by), (0x12, app)]
    entries = b""
    data = b""
    base = 8 + 8 * len(props)
    offsets = []
    for pid, val in props:
        raw = val.encode("cp1252") + b"\x00"
        raw += b"\x00" * ((-len(raw)) % 4)
        offsets.append((pid, base + len(data)))
        data += struct.pack("<II", 0x1E, len(val) + 1) + raw
    for pid, off in offsets:
        entries += struct.pack("<II", pid, off)
    section = struct.pack("<II", base + len(data), len(props)) + entries + data
    fmtid = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
    # header (28 bytes): byte order, version, OS version, CLSID, section count
    header = struct.pack("<HH", 0xFFFE, 0) + struct.pack("<I", 0x00020006) + b"\x00" * 16 + struct.pack("<I", 1)
    return header + fmtid + struct.pack("<I", len(header) + 20) + section


def retype(package: bytes, old_ct: str, new_ct: str) -> bytes:
    """Change the main part's content type (e.g. .docx -> .dotx template)."""
    src = zipfile.ZipFile(io.BytesIO(package))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for it in src.infolist():
            data = src.read(it.filename)
            if it.filename == "[Content_Types].xml":
                data = data.replace(old_ct.encode(), new_ct.encode())
            out.writestr(it.filename, data)
    return buf.getvalue()


# --- Excel ------------------------------------------------------------------------

X = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
XLSX_CT = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
XLSM_CT = "application/vnd.ms-excel.sheet.macroEnabled.main+xml"


def _cell(ref: str, value) -> str:
    if isinstance(value, (int, float)):
        return f'<c r="{ref}"><v>{value}</v></c>'
    if isinstance(value, str) and value.startswith("="):
        return f'<c r="{ref}"><f>{_esc(value[1:])}</f><v>0</v></c>'
    return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{_esc(str(value))}</t></is></c>'


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _sheet_xml(rows: list[list], root: str = "worksheet", ns_extra: str = "") -> str:
    out = []
    for r, row in enumerate(rows, 1):
        cells = "".join(_cell(f"{chr(65 + c)}{r}", v) for c, v in enumerate(row) if v is not None)
        out.append(f'<row r="{r}">{cells}</row>')
    return (XML_DECL + f'<{root} xmlns="{X}" xmlns:r="{R}"{ns_extra}><sheetData>{"".join(out)}</sheetData></{root}>')


def xlsx(sheets: list[tuple[str, str, list[list]]], *, main_ct: str = XLSX_CT,
         macro_sheets: list[tuple[str, str, list[list]]] | None = None,
         defined_names: dict[str, str] | None = None, modules: list[Module] | None = None,
         core: str | None = None, app: str | None = None, custom: dict[str, str] | None = None) -> bytes:
    """An Excel workbook. ``sheets``/``macro_sheets``: (name, state, rows); a row
    value starting with ``=`` is a formula. ``modules``: VBA (ThisWorkbook...)."""
    o = Opc()
    o.rel("", "rId1", f"{R}/officeDocument", "xl/workbook.xml")
    entries, wb_rels = [], []
    n = 0
    for name, state, rows in sheets:
        n += 1
        o.part(f"xl/worksheets/sheet{n}.xml", _sheet_xml(rows),
               "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml")
        o.rel("xl/workbook.xml", f"rId{n}", f"{R}/worksheet", f"worksheets/sheet{n}.xml")
        st = f' state="{state}"' if state != "visible" else ""
        entries.append(f'<sheet name="{_esc(name)}" sheetId="{n}"{st} r:id="rId{n}"/>')
    for i, (name, state, rows) in enumerate(macro_sheets or [], 1):
        n += 1
        o.part(f"xl/macrosheets/sheet{i}.xml",
               _sheet_xml(rows, "xm:macrosheet", ' xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"'),
               "application/vnd.ms-excel.macrosheet+xml")
        o.rel("xl/workbook.xml", f"rId{n}", "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet",
              f"macrosheets/sheet{i}.xml")
        st = f' state="{state}"' if state != "visible" else ""
        entries.append(f'<sheet name="{_esc(name)}" sheetId="{n}"{st} r:id="rId{n}"/>')
    names = ""
    if defined_names:
        names = "<definedNames>" + "".join(f'<definedName name="{k}" hidden="1">{_esc(v)}</definedName>'
                                           for k, v in defined_names.items()) + "</definedNames>"
    o.part("xl/workbook.xml", XML_DECL + f'<workbook xmlns="{X}" xmlns:r="{R}"><workbookPr codeName="ThisWorkbook"/>'
           f'<bookViews><workbookView activeTab="0"/></bookViews><sheets>{"".join(entries)}</sheets>{names}</workbook>',
           main_ct)
    if modules:
        o.part("xl/vbaProject.bin", vba_project_bin(modules))
        o.rel("xl/workbook.xml", "rIdVba", "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
              "vbaProject.bin")
    _doc_props(o, core, app or app_xml("Microsoft Excel", "Contoso"), custom)
    return o.build()


def _doc_props(o: Opc, core: str | None, app: str, custom: dict[str, str] | None) -> None:
    o.part("docProps/core.xml", core or core_xml("Document", "user", "user", "2026-10-01T09:00:00Z",
                                                  "2026-10-02T09:00:00Z"),
           "application/vnd.openxmlformats-package.core-properties+xml")
    o.rel("", "rId2", f"{PR.replace('relationships', 'relationships/metadata/core-properties')}", "docProps/core.xml")
    o.part("docProps/app.xml", app, "application/vnd.openxmlformats-officedocument.extended-properties+xml")
    o.rel("", "rId3", f"{R}/extended-properties", "docProps/app.xml")
    if custom:
        o.part("docProps/custom.xml", custom_xml(custom),
               "application/vnd.openxmlformats-officedocument.custom-properties+xml")
        o.rel("", "rId4", f"{R}/custom-properties", "docProps/custom.xml")


# --- PowerPoint -------------------------------------------------------------------

P = "http://schemas.openxmlformats.org/presentationml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
PPTX_CT = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"


def pptx(slides: list[dict], *, main_ct: str = PPTX_CT, modules: list[Module] | None = None,
         core: str | None = None, app: str | None = None, custom: dict[str, str] | None = None) -> bytes:
    """A presentation. Each slide: {"title", "lines", optional "link" (url, text),
    optional "mouseover_program" (command run by ppaction://program on mouse-over)}."""
    o = Opc()
    o.rel("", "rId1", f"{R}/officeDocument", "ppt/presentation.xml")
    ids = []
    for i, s in enumerate(slides, 1):
        rid_base = f"ppt/slides/slide{i}.xml"
        paras = [f'<a:p><a:r><a:rPr lang="es-ES" sz="3200" b="1"/><a:t>{_esc(s.get("title", ""))}</a:t></a:r></a:p>']
        paras += [f'<a:p><a:r><a:rPr lang="es-ES"/><a:t>{_esc(t)}</a:t></a:r></a:p>' for t in s.get("lines", [])]
        if s.get("link"):
            url, text = s["link"]
            o.rel(rid_base, "rIdL1", f"{R}/hyperlink", url, external=True)
            paras.append(f'<a:p><a:r><a:rPr lang="es-ES"><a:hlinkClick r:id="rIdL1"/></a:rPr>'
                         f'<a:t>{_esc(text)}</a:t></a:r></a:p>')
        if s.get("mouseover_program"):
            o.rel(rid_base, "rIdP1", f"{R}/hyperlink", s["mouseover_program"], external=True)
            paras.append('<a:p><a:r><a:rPr lang="es-ES"><a:hlinkMouseOver r:id="rIdP1" '
                         'action="ppaction://program"/></a:rPr><a:t>Cargando contenido…</a:t></a:r></a:p>')
        sp = (f'<p:sp><p:nvSpPr><p:cNvPr id="2" name="Contenido"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr/>'
              f'<p:txBody><a:bodyPr/><a:lstStyle/>{"".join(paras)}</p:txBody></p:sp>')
        o.part(rid_base, XML_DECL + f'<p:sld xmlns:p="{P}" xmlns:a="{A}" xmlns:r="{R}"><p:cSld><p:spTree>'
               f'<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>{sp}'
               '</p:spTree></p:cSld></p:sld>', "application/vnd.openxmlformats-officedocument.presentationml.slide+xml")
        o.rel("ppt/presentation.xml", f"rId{i + 10}", f"{R}/slide", f"slides/slide{i}.xml")
        ids.append(f'<p:sldId id="{255 + i}" r:id="rId{i + 10}"/>')
    o.part("ppt/presentation.xml", XML_DECL + f'<p:presentation xmlns:p="{P}" xmlns:a="{A}" xmlns:r="{R}">'
           f'<p:sldIdLst>{"".join(ids)}</p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/>'
           '<p:notesSz cx="6858000" cy="9144000"/></p:presentation>', main_ct)
    if modules:
        o.part("ppt/vbaProject.bin", vba_project_bin(modules))
        o.rel("ppt/presentation.xml", "rIdVba", "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
              "vbaProject.bin")
    _doc_props(o, core, app or app_xml("Microsoft Office PowerPoint", "Contoso"), custom)
    return o.build()
