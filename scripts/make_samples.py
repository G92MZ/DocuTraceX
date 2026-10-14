#!/usr/bin/env python3
"""Generate benign sample files, one per in-scope type, under ``samples/``.

These are *minimal, structurally valid* files of each type, for exercising
identification and the parsers. They are benign and carry no findings yet
(findings-bearing samples come later, on request).

What each one is:
- OOXML/OPC packages (.docx family, .xlsx family, .pptx family, .xlsb): minimal
  Open Packaging Convention ZIP packages with the correct content type for the
  declared extension.
- Legacy Office (.doc/.xls/.ppt and variants) and .msg: minimal valid OLE/CFB
  compound files (container-valid; not full Office documents).
- .pdf: a minimal valid PDF.
- .eml: a valid RFC 822 message. .emlx: an Apple Mail wrapper around one.

Run:  python scripts/make_samples.py
"""

from __future__ import annotations

import struct
import zipfile
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

REL_OFFICE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
X_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"

WORD_BODY = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document xmlns:w="{W_NS}"><w:body/></w:document>'
XL_BODY = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<workbook xmlns="{X_NS}"><sheets/></workbook>'
PP_BODY = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<p:presentation xmlns:p="{P_NS}"/>'

# extension -> (main part path, content type, main part bytes)
OOXML: dict[str, tuple[str, str, bytes]] = {
    # Word
    ".docx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml", WORD_BODY.encode()),
    ".docm": ("word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml", WORD_BODY.encode()),
    ".dotx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml", WORD_BODY.encode()),
    ".dotm": ("word/document.xml", "application/vnd.ms-word.template.macroEnabledTemplate.main+xml", WORD_BODY.encode()),
    # Excel
    ".xlsx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", XL_BODY.encode()),
    ".xlsm": ("xl/workbook.xml", "application/vnd.ms-excel.sheet.macroEnabled.main+xml", XL_BODY.encode()),
    ".xltx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml", XL_BODY.encode()),
    ".xltm": ("xl/workbook.xml", "application/vnd.ms-excel.template.macroEnabled.main+xml", XL_BODY.encode()),
    ".xlam": ("xl/workbook.xml", "application/vnd.ms-excel.addin.macroEnabled.main+xml", XL_BODY.encode()),
    # PowerPoint
    ".pptx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml", PP_BODY.encode()),
    ".pptm": ("ppt/presentation.xml", "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml", PP_BODY.encode()),
    ".potx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml", PP_BODY.encode()),
    ".potm": ("ppt/presentation.xml", "application/vnd.ms-powerpoint.template.macroEnabled.main+xml", PP_BODY.encode()),
    ".ppsx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml", PP_BODY.encode()),
    ".ppsm": ("ppt/presentation.xml", "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml", PP_BODY.encode()),
    ".ppam": ("ppt/presentation.xml", "application/vnd.ms-powerpoint.addin.macroEnabled.main+xml", PP_BODY.encode()),
    ".sldx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.slide.main+xml", PP_BODY.encode()),
    ".sldm": ("ppt/presentation.xml", "application/vnd.ms-powerpoint.slide.macroEnabled.main+xml", PP_BODY.encode()),
    # Excel binary (OPC package with a binary workbook part)
    ".xlsb": ("xl/workbook.bin", "application/vnd.ms-excel.sheet.binary.macroEnabled.main", b"\x00\x00\x00\x00 placeholder xlsb workbook part"),
}

# Legacy OLE/CFB formats (same minimal compound file, different extension).
OLE_EXTS = [".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot", ".msg"]


def make_opc(path: Path, main_part: str, content_type: str, body: bytes) -> None:
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="bin" ContentType="application/vnd.ms-excel.sheet.binary.macroEnabled.main"/>'
        f'<Override PartName="/{main_part}" ContentType="{content_type}"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="{REL_OFFICE}" Target="{main_part}"/>'
        "</Relationships>"
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr(main_part, body)


def make_cfb(path: Path) -> None:
    """Write a minimal valid OLE/CFB (compound file) with only a Root Entry."""
    SECTOR = 512
    FREESECT = 0xFFFFFFFF
    ENDOFCHAIN = 0xFFFFFFFE
    FATSECT = 0xFFFFFFFD

    header = bytearray(SECTOR)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # signature
    # CLSID (16) zeros already
    struct.pack_into("<H", header, 0x18, 0x003E)  # minor version
    struct.pack_into("<H", header, 0x1A, 0x0003)  # major version (v3, 512B)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)  # byte order LE
    struct.pack_into("<H", header, 0x1E, 0x0009)  # sector shift 2^9
    struct.pack_into("<H", header, 0x20, 0x0006)  # mini sector shift 2^6
    struct.pack_into("<I", header, 0x28, 0)        # num dir sectors (0 for v3)
    struct.pack_into("<I", header, 0x2C, 1)        # num FAT sectors
    struct.pack_into("<I", header, 0x30, 1)        # first dir sector = #1
    struct.pack_into("<I", header, 0x34, 0)        # transaction sig
    struct.pack_into("<I", header, 0x38, 0x00001000)  # mini stream cutoff
    struct.pack_into("<I", header, 0x3C, ENDOFCHAIN)  # first mini FAT sector
    struct.pack_into("<I", header, 0x40, 0)        # num mini FAT sectors
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)  # first DIFAT sector
    struct.pack_into("<I", header, 0x48, 0)        # num DIFAT sectors
    # DIFAT array (109 entries): first points to FAT sector #0, rest FREESECT
    struct.pack_into("<I", header, 0x4C, 0)
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + i * 4, FREESECT)

    # FAT sector (#0): entry0=FATSECT, entry1=ENDOFCHAIN (dir chain), rest FREE
    fat = bytearray(SECTOR)
    struct.pack_into("<I", fat, 0, FATSECT)
    struct.pack_into("<I", fat, 4, ENDOFCHAIN)
    for i in range(2, SECTOR // 4):
        struct.pack_into("<I", fat, i * 4, FREESECT)

    # Directory sector (#1): 4 entries of 128 bytes
    directory = bytearray(SECTOR)
    name = "Root Entry".encode("utf-16-le")
    directory[0:len(name)] = name
    struct.pack_into("<H", directory, 0x40, len(name) + 2)  # name length incl null
    directory[0x42] = 0x05  # object type: root storage
    directory[0x43] = 0x01  # color: black
    struct.pack_into("<I", directory, 0x44, FREESECT)  # left sibling
    struct.pack_into("<I", directory, 0x48, FREESECT)  # right sibling
    struct.pack_into("<I", directory, 0x4C, FREESECT)  # child
    struct.pack_into("<I", directory, 0x74, ENDOFCHAIN)  # starting sector (mini)
    struct.pack_into("<Q", directory, 0x78, 0)  # stream size
    # Unused entries 1..3: mark siblings/child as NOSTREAM
    for e in range(1, 4):
        base = e * 128
        struct.pack_into("<I", directory, base + 0x44, FREESECT)
        struct.pack_into("<I", directory, base + 0x48, FREESECT)
        struct.pack_into("<I", directory, base + 0x4C, FREESECT)

    path.write_bytes(bytes(header) + bytes(fat) + bytes(directory))


def make_pdf(path: Path) -> None:
    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
    ]
    out = bytearray(b"%PDF-1.7\n")
    offsets = [0]
    for obj in objs:
        offsets.append(len(out))
        out += obj
    xref_pos = len(out)
    out += b"xref\n0 4\n0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n"
    out += f"{xref_pos}\n".encode() + b"%%EOF\n"
    path.write_bytes(out)


def _build_eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = "Alice <alice@example.com>"
    msg["To"] = "Bob <bob@example.org>"
    msg["Subject"] = "DocuTraceX benign sample"
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = "<sample-0001@example.com>"
    msg.set_content("Benign plain-text body for testing.\n")
    return msg.as_bytes()


def make_eml(path: Path) -> None:
    path.write_bytes(_build_eml())


def make_emlx(path: Path) -> None:
    message = _build_eml()
    plist = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        b'<plist version="1.0"><dict><key>flags</key><integer>0</integer></dict></plist>\n'
    )
    # emlx: byte count of the message, newline, message, then the plist.
    path.write_bytes(f"{len(message)}\n".encode() + message + plist)


def main() -> None:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    made = []
    for ext, (main_part, ct, body) in OOXML.items():
        p = SAMPLES / f"sample{ext}"
        make_opc(p, main_part, ct, body)
        made.append(p.name)
    for ext in OLE_EXTS:
        p = SAMPLES / f"sample{ext}"
        make_cfb(p)
        made.append(p.name)
    make_pdf(SAMPLES / "sample.pdf"); made.append("sample.pdf")
    make_eml(SAMPLES / "sample.eml"); made.append("sample.eml")
    make_emlx(SAMPLES / "sample.emlx"); made.append("sample.emlx")

    print(f"Generated {len(made)} samples in {SAMPLES}:")
    for name in sorted(made):
        print(f"  {name}")


if __name__ == "__main__":
    main()
