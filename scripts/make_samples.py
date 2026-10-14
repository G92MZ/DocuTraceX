#!/usr/bin/env python3
"""Generate benign sample files, one per in-scope type, under ``samples/``.

The OOXML samples (Word/Excel/PowerPoint) carry realistic *benign* content that
exercises the parsers and produces findings and IOCs:
- document metadata (docProps)
- reconstructable text with benign IOCs (RFC 5737 TEST-NET IPs, example.* URLs)
- macro-enabled variants include a VBA project and (Word) a DDEAUTO field
- template variants include an external relationship
- Excel includes a hidden sheet and a WEBSERVICE formula

The legacy OLE/CFB files, XLSB, PDF, EML/EMLX/MSG remain minimal valid files of
their type (their parsers come later). Everything is benign — the "malicious"
strings are documentation examples, not real payloads.

Run:  python scripts/make_samples.py
"""

from __future__ import annotations

import struct
import zipfile
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# Benign documentation IOCs (RFC 5737 / RFC 2606 / example.*).
URL_A = "http://malware.example.com/payload.bin"
URL_FEED = "http://feeds.example.net/data"
IP_A = "203.0.113.10"
EXT_TEMPLATE = "http://templates.example.org/corp.dotm"

REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKGREL = "http://schemas.openxmlformats.org/package/2006/relationships"

MACRO_EXTS = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm",
              ".ppsm", ".ppam", ".sldm"}
TEMPLATE_EXTS = {".dotx", ".dotm", ".xltx", ".xltm", ".potx", ".potm"}

# ext -> (family, main_part, main_content_type)
OOXML_MAIN: dict[str, tuple[str, str, str]] = {
    ".docx": ("word", "word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
    ".docm": ("word", "word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml"),
    ".dotx": ("word", "word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml"),
    ".dotm": ("word", "word/document.xml", "application/vnd.ms-word.template.macroEnabledTemplate.main+xml"),
    ".xlsx": ("excel", "xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
    ".xlsm": ("excel", "xl/workbook.xml", "application/vnd.ms-excel.sheet.macroEnabled.main+xml"),
    ".xltx": ("excel", "xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml"),
    ".xltm": ("excel", "xl/workbook.xml", "application/vnd.ms-excel.template.macroEnabled.main+xml"),
    ".xlam": ("excel", "xl/workbook.xml", "application/vnd.ms-excel.addin.macroEnabled.main+xml"),
    ".pptx": ("powerpoint", "ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
    ".pptm": ("powerpoint", "ppt/presentation.xml", "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"),
    ".potx": ("powerpoint", "ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml"),
    ".potm": ("powerpoint", "ppt/presentation.xml", "application/vnd.ms-powerpoint.template.macroEnabled.main+xml"),
    ".ppsx": ("powerpoint", "ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml"),
    ".ppsm": ("powerpoint", "ppt/presentation.xml", "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml"),
    ".ppam": ("powerpoint", "ppt/presentation.xml", "application/vnd.ms-powerpoint.addin.macroEnabled.main+xml"),
    ".sldx": ("powerpoint", "ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.slide.main+xml"),
    ".sldm": ("powerpoint", "ppt/presentation.xml", "application/vnd.ms-powerpoint.slide.macroEnabled.main+xml"),
    ".xlsb": ("xlsb", "xl/workbook.bin", "application/vnd.ms-excel.sheet.binary.macroEnabled.main"),
}

OLE_EXTS = [".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot", ".msg"]

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
X_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"

CORE_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
    ' xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"'
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    '<dc:title>DocuTraceX benign sample</dc:title>'
    '<dc:creator>gmzpt</dc:creator>'
    '<cp:lastModifiedBy>analyst</cp:lastModifiedBy>'
    '<dcterms:created xsi:type="dcterms:W3CDTF">2026-10-14T00:00:00Z</dcterms:created>'
    '<dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-14T00:00:00Z</dcterms:modified>'
    "</cp:coreProperties>"
)


def _app_xml(app_name: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        f"<Application>{app_name}</Application><Company>DocuTraceX Test</Company>"
        "<AppVersion>16.0000</AppVersion></Properties>"
    )


def _content_types(family: str, main_part: str, main_ct: str) -> str:
    extra = ""
    if family == "excel":
        extra = ('<Override PartName="/xl/worksheets/sheet1.xml" '
                 'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    elif family == "powerpoint":
        extra = ('<Override PartName="/ppt/slides/slide1.xml" '
                 'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
        f'<Override PartName="/{main_part}" ContentType="{main_ct}"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        f"{extra}"
        "</Types>"
    )


def _root_rels(main_part: str, external_template: bool) -> str:
    rels = [
        f'<Relationship Id="rId1" Type="{REL}/officeDocument" Target="{main_part}"/>',
        f'<Relationship Id="rId2" Type="{REL}/metadata/core-properties" Target="docProps/core.xml"/>',
        f'<Relationship Id="rId3" Type="{REL}/extended-properties" Target="docProps/app.xml"/>',
    ]
    if external_template:
        rels.append(
            f'<Relationship Id="rId9" Type="{REL}/attachedTemplate" '
            f'Target="{EXT_TEMPLATE}" TargetMode="External"/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{PKGREL}">{"".join(rels)}</Relationships>'
    )


def _word_doc(macro: bool) -> str:
    body = [
        f'<w:p><w:r><w:t>Confidential quarterly report. See {URL_A} and host {IP_A} for details.</w:t></w:r></w:p>'
    ]
    if macro:
        body.append(
            '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:instrText> DDEAUTO c:\\\\Windows\\\\System32\\\\cmd.exe "/k calc.exe" </w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
        )
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{W_NS}"><w:body>{"".join(body)}</w:body></w:document>'
    )


def _xl_workbook() -> str:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{X_NS}"><sheets>'
        '<sheet name="Summary" sheetId="1"/>'
        '<sheet name="Hidden" sheetId="2" state="veryHidden"/>'
        "</sheets></workbook>"
    )


def _xl_sheet() -> str:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<worksheet xmlns="{X_NS}"><sheetData>'
        f'<row r="1"><c r="A1"><f>WEBSERVICE("{URL_FEED}")</f><v>0</v></c></row>'
        "</sheetData></worksheet>"
    )


def _ppt_presentation() -> str:
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<p:presentation xmlns:p="{P_NS}"/>')


def _ppt_slide() -> str:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<p:sld xmlns:p="{P_NS}" xmlns:a="{A_NS}"><p:cSld><p:spTree><p:sp><p:txBody>'
        f'<a:p><a:r><a:t>Project kickoff. Visit {URL_A} ({IP_A}).</a:t></a:r></a:p>'
        "</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
    )


APP_NAME = {"word": "Microsoft Office Word", "excel": "Microsoft Excel",
            "powerpoint": "Microsoft Office PowerPoint", "xlsb": "Microsoft Excel"}

_DOCM_CT = "application/vnd.ms-word.document.macroEnabled.main+xml"


def _docm_bytes() -> bytes:
    """A macro-enabled Word doc (DDEAUTO + vbaProject.bin), built in memory.

    Used as an email attachment so the third-party tools (olevba, msodde) have
    something real to pull out of the message.
    """
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types("word", "word/document.xml", _DOCM_CT))
        z.writestr("_rels/.rels", _root_rels("word/document.xml", False))
        z.writestr("docProps/core.xml", CORE_XML)
        z.writestr("docProps/app.xml", _app_xml(APP_NAME["word"]))
        z.writestr("word/document.xml", _word_doc(macro=True))
        z.writestr("word/vbaProject.bin", b"\x00VBA placeholder (benign sample)")
    return buf.getvalue()


def make_ooxml(path: Path, ext: str) -> None:
    family, main_part, main_ct = OOXML_MAIN[ext]
    macro = ext in MACRO_EXTS
    external = ext in TEMPLATE_EXTS
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types(family, main_part, main_ct))
        z.writestr("_rels/.rels", _root_rels(main_part, external))
        z.writestr("docProps/core.xml", CORE_XML)
        z.writestr("docProps/app.xml", _app_xml(APP_NAME[family]))
        if family == "word":
            z.writestr(main_part, _word_doc(macro))
        elif family == "excel":
            z.writestr(main_part, _xl_workbook())
            z.writestr("xl/worksheets/sheet1.xml", _xl_sheet())
        elif family == "powerpoint":
            z.writestr(main_part, _ppt_presentation())
            z.writestr("ppt/slides/slide1.xml", _ppt_slide())
        else:  # xlsb — minimal binary workbook part
            z.writestr(main_part, b"\x00\x00\x00\x00 placeholder xlsb workbook part")
        if macro:
            vba_dir = {"word": "word", "excel": "xl", "powerpoint": "ppt"}[family]
            z.writestr(f"{vba_dir}/vbaProject.bin", b"\x00VBA placeholder (benign sample)")


def make_cfb(path: Path) -> None:
    """Write a minimal valid OLE/CFB (compound file) with only a Root Entry."""
    SECTOR = 512
    FREESECT = 0xFFFFFFFF
    ENDOFCHAIN = 0xFFFFFFFE
    FATSECT = 0xFFFFFFFD

    header = bytearray(SECTOR)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 0x18, 0x003E)
    struct.pack_into("<H", header, 0x1A, 0x0003)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)
    struct.pack_into("<H", header, 0x1E, 0x0009)
    struct.pack_into("<H", header, 0x20, 0x0006)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, 1)
    struct.pack_into("<I", header, 0x38, 0x00001000)
    struct.pack_into("<I", header, 0x3C, ENDOFCHAIN)
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)
    struct.pack_into("<I", header, 0x4C, 0)
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + i * 4, FREESECT)

    fat = bytearray(SECTOR)
    struct.pack_into("<I", fat, 0, FATSECT)
    struct.pack_into("<I", fat, 4, ENDOFCHAIN)
    for i in range(2, SECTOR // 4):
        struct.pack_into("<I", fat, i * 4, FREESECT)

    directory = bytearray(SECTOR)
    name = "Root Entry".encode("utf-16-le")
    directory[0:len(name)] = name
    struct.pack_into("<H", directory, 0x40, len(name) + 2)
    directory[0x42] = 0x05
    directory[0x43] = 0x01
    struct.pack_into("<I", directory, 0x44, FREESECT)
    struct.pack_into("<I", directory, 0x48, FREESECT)
    struct.pack_into("<I", directory, 0x4C, FREESECT)
    struct.pack_into("<I", directory, 0x74, ENDOFCHAIN)
    struct.pack_into("<Q", directory, 0x78, 0)
    for e in range(1, 4):
        base = e * 128
        struct.pack_into("<I", directory, base + 0x44, FREESECT)
        struct.pack_into("<I", directory, base + 0x48, FREESECT)
        struct.pack_into("<I", directory, base + 0x4C, FREESECT)

    path.write_bytes(bytes(header) + bytes(fat) + bytes(directory))


def make_pdf(path: Path) -> None:
    """A deliberately suspicious (benign) PDF: auto-run JavaScript, a Launch
    action, a /URI, and a real embedded file (the macro .docm) so the recursive
    scan has something to pull out."""
    embedded = _docm_bytes()
    objs: list[bytes] = [
        # 1: Catalog — auto-runs JS on open, holds the embedded-files name tree.
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R "
        b"/AA << /WC 6 0 R >> /Names << /EmbeddedFiles 7 0 R >> >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/AA << /O 6 0 R >> >>\nendobj\n",
        # 4: a URI action pointing at an external host.
        b"4 0 obj\n<< /Type /Action /S /URI /URI (http://evil.example/pdf) >>\nendobj\n",
        # 5: JavaScript action (OpenAction target).
        b"5 0 obj\n<< /Type /Action /S /JavaScript /JS "
        b"(app.alert\\('owned'\\); this.exportDataObject\\({cName:'report.docm'}\\);) >>\nendobj\n",
        # 6: Launch action (spawn a program).
        b"6 0 obj\n<< /Type /Action /S /Launch /Win << /F (cmd.exe) /P (/c calc.exe) >> "
        b"/Next 4 0 R >>\nendobj\n",
        # 7: EmbeddedFiles name tree -> 8 (filespec).
        b"7 0 obj\n<< /Names [ (report.docm) 8 0 R ] >>\nendobj\n",
        # 8: Filespec -> 9 (embedded file stream).
        b"8 0 obj\n<< /Type /Filespec /F (report.docm) /EF << /F 9 0 R >> >>\nendobj\n",
        # 9: the embedded file stream.
        b"9 0 obj\n<< /Type /EmbeddedFile /Length " + str(len(embedded)).encode()
        + b" >>\nstream\n" + embedded + b"\nendstream\nendobj\n",
    ]
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj in objs:
        offsets.append(len(out))
        out += obj
    xref_pos = len(out)
    n = len(objs) + 1
    out += f"xref\n0 {n}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n".encode()
    out += f"{xref_pos}\n".encode() + b"%%EOF\n"
    path.write_bytes(out)


def _build_eml() -> bytes:
    msg = EmailMessage()
    # Spoofy headers: display-name domain and Return-Path differ from From;
    # a two-hop Received chain with a suspicious origin; failing auth.
    msg["Received"] = ("from mx.corp.example (mx.corp.example [198.51.100.2]) "
                       "by inbox.corp.example with ESMTP id def; "
                       "Wed, 14 Oct 2026 20:00:05 +0000")
    msg["Received"] = ("from evil.example (unknown [203.0.113.9]) "
                       "by mx.corp.example with ESMTP id abc; "
                       "Wed, 14 Oct 2026 20:00:00 +0000")
    msg["From"] = '"IT Support <support@corp.example>" <attacker@evil.example>'
    msg["To"] = "Bob <bob@corp.example>"
    msg["Reply-To"] = "billing@evil.example"
    msg["Return-Path"] = "<bounce@evil.example>"
    msg["Subject"] = "DocuTraceX sample — please review invoice"
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = "<sample-0001@evil.example>"
    msg["Authentication-Results"] = "mx.corp.example; spf=fail; dkim=none; dmarc=fail"
    msg["X-Mailer"] = "SuspiciousMailer 1.0"
    msg.set_content(f"Benign-looking body. Reference: {URL_A} and {IP_A}.\n")
    msg.add_alternative(
        f'<html><body><p>Click <a href="http://evil.example/pay">'
        f'https://corp.example/invoice</a> to review.</p></body></html>',
        subtype="html")
    msg.add_attachment(b"MZ fake payload (benign sample)",
                       maintype="application", subtype="octet-stream",
                       filename="invoice.pdf.exe")
    # A real macro-enabled Office attachment so third-party tools find macros/DDE.
    msg.add_attachment(_docm_bytes(), maintype="application",
                       subtype="vnd.ms-word.document.macroEnabled.12",
                       filename="report.docm")
    return msg.as_bytes()


def make_eml(path: Path) -> None:
    path.write_bytes(_build_eml())


def make_msg(path: Path) -> None:
    """Enriched Outlook .msg fixture (MAPI over OLE), mirroring the .eml."""
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    from mkmsg import write_msg

    headers = (
        "Received: from mx.corp.example (mx.corp.example [198.51.100.2]) "
        "by inbox.corp.example with ESMTP id def; Wed, 14 Oct 2026 20:00:05 +0000\n"
        "Received: from evil.example (unknown [203.0.113.9]) "
        "by mx.corp.example with ESMTP id abc; Wed, 14 Oct 2026 20:00:00 +0000\n"
        'From: "IT Support <support@corp.example>" <attacker@evil.example>\n'
        "To: Bob <bob@corp.example>\n"
        "Reply-To: billing@evil.example\n"
        "Return-Path: <bounce@evil.example>\n"
        "Subject: DocuTraceX sample — please review invoice\n"
        "Authentication-Results: mx.corp.example; spf=fail; dkim=none; dmarc=fail\n"
        "X-Mailer: SuspiciousMailer 1.0\n"
    )
    write_msg(path, headers, "DocuTraceX sample — please review invoice",
              f"Benign-looking body. Reference: {URL_A} and {IP_A}.",
              "attacker@evil.example",
              [("invoice.pdf.exe", b"MZ fake payload (benign sample)"),
               ("report.docm", _docm_bytes())])


def make_emlx(path: Path) -> None:
    message = _build_eml()
    plist = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        b'<plist version="1.0"><dict><key>flags</key><integer>0</integer></dict></plist>\n'
    )
    path.write_bytes(f"{len(message)}\n".encode() + message + plist)


def main() -> None:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    made = []
    for ext in OOXML_MAIN:
        p = SAMPLES / f"sample{ext}"
        make_ooxml(p, ext)
        made.append(p.name)
    for ext in OLE_EXTS:
        if ext == ".msg":
            continue  # real MAPI fixture, not a bare CFB
        p = SAMPLES / f"sample{ext}"
        make_cfb(p)
        made.append(p.name)
    make_pdf(SAMPLES / "sample.pdf"); made.append("sample.pdf")
    make_eml(SAMPLES / "sample.eml"); made.append("sample.eml")
    make_emlx(SAMPLES / "sample.emlx"); made.append("sample.emlx")
    make_msg(SAMPLES / "sample.msg"); made.append("sample.msg")

    print(f"Generated {len(made)} samples in {SAMPLES}:")
    for name in sorted(made):
        print(f"  {name}")


if __name__ == "__main__":
    main()
