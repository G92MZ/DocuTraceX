"""Builder for realistic (benign) RTF test documents.

Writes real RTF — info group, generator, font/colour tables, rsid table,
paragraphs, fields and ``\\object`` groups whose ``\\objdata`` holds genuine
OLE 1.0 objects (Equation Editor, OLE2Link, Package...) — carrying the
techniques DocuTraceX detects. Payloads are inert documentation examples
(example.* hosts, RFC 5737 IPs).
"""

from __future__ import annotations

import binascii
import struct

import officekit as ok


def ole1(class_name: str, native: bytes, format_id: int = 2) -> bytes:
    """An OLE 1.0 object (what ``\\objdata`` carries): header, class, native data."""
    cls = class_name.encode("latin-1") + b"\x00"
    return (struct.pack("<II", 0x00000501, format_id) + struct.pack("<I", len(cls)) + cls
            + struct.pack("<II", 0, 0) + struct.pack("<I", len(native)) + native)


def hexdata(data: bytes, width: int = 128, junk: str = "") -> str:
    """Hex text in lines, optionally interleaving ``junk`` (obfuscation trick)."""
    h = binascii.hexlify(data).decode()
    lines = [h[i:i + width] for i in range(0, len(h), width)]
    return ("\n" + junk).join(lines) if junk else "\n".join(lines)


def rtf_escape(text: str) -> str:
    out = []
    for ch in text:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ord(ch) > 127:
            out.append(f"\\u{ord(ch) if ord(ch) < 32768 else ord(ch) - 65536}?")
        elif ch == "\n":
            out.append("\\par\n")
        else:
            out.append(ch)
    return "".join(out)


def obj_group(class_name: str, ole1_bytes: bytes, *, kind: str = "objemb", update: bool = False,
              junk: str = "", width: int = 2500, height: int = 800) -> str:
    upd = "\\objupdate" if update else ""
    return (f"{{\\object\\{kind}{upd}\\objw{width}\\objh{height}{{\\*\\objclass {class_name}}}"
            f"{{\\*\\objdata\n{hexdata(ole1_bytes, junk=junk)}\n}}"
            f"{{\\result {{\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\insrsid1080131 }}}}}}")


def equation(junk: str = "") -> str:
    return obj_group("Equation.3", ole1("Equation.3", ok.equation_object()), junk=junk)


def ole2link(url: str) -> str:
    return obj_group("Word.Document.8", ole1("OLE2Link", ok.ole2link_object(url)),
                     kind="objautlink", update=True)


def package(filename: str, payload: bytes) -> str:
    native = ok.ole10native(filename, payload)[4:]  # OLE1 native data: no size prefix
    return obj_group("Package", ole1("Package", native))


def field(instr: str, result: str) -> str:
    return (f"{{\\field{{\\*\\fldinst {{\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\insrsid1080131 {rtf_escape(instr)}}}}}"
            f"{{\\fldrslt {{\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\insrsid1080131 {rtf_escape(result)}}}}}}}")


def pfragments_shape() -> str:
    """A drawing shape with a pFragments property (CVE-2010-3333 shape, inert value)."""
    return ("{\\shp{\\*\\shpinst\\shpleft0\\shptop0\\shpright100\\shpbottom100"
            "{\\sp{\\sn pFragments}{\\sv 2;6;11111111aabbccdd}}}}")


def build_rtf(paragraphs: list[str], *, title: str = "", author: str = "", operator: str = "",
              company: str = "", created: tuple[int, int, int, int, int] = (2026, 10, 9, 8, 41),
              revised: tuple[int, int, int, int, int] = (2026, 10, 13, 17, 2),
              generator: str = "Microsoft Word 11.0.0000", template: str | None = None,
              body_extra: list[str] | None = None, rsids: list[int] | None = None,
              fonts: int | None = None, nesting: int = 0, header: str = "{\\rtf1",
              trailer: bytes = b"") -> bytes:
    """A Word-like RTF document carrying the requested techniques."""
    def tim(tag, t):
        return f"{{\\{tag}\\yr{t[0]}\\mo{t[1]}\\dy{t[2]}\\hr{t[3]}\\min{t[4]}}}"

    font_names = ["Times New Roman", "Arial", "Calibri", "Cambria Math"]
    if fonts:
        ftbl = "".join(f"{{\\f{i}\\fswiss\\fcharset0 F{i};}}" for i in range(fonts))
    else:
        ftbl = "".join(f"{{\\f{i}\\froman\\fcharset0\\fprq2 {n};}}" for i, n in enumerate(font_names))
    rs = rsids or [1080131, 7347290, 12152466]
    parts = [
        header + "\\adeflang1025\\ansi\\ansicpg1252\\uc1\\adeff0\\deff0\\stshfdbch0\\stshfloch0\\deflang3082",
        "{\\fonttbl" + ftbl + "}",
        "{\\colortbl;\\red0\\green0\\blue0;\\red31\\green73\\blue125;}",
        "{\\*\\defchp \\fs22\\loch\\af31506}",
        "{\\stylesheet{\\ql \\li0\\ri0\\sa160\\sl259\\slmult1 \\f31506\\fs22 \\snext0 Normal;}}",
    ]
    if template:
        parts.append("{\\*\\template " + rtf_escape(template) + "}")
    parts.append("{\\*\\rsidtbl " + "".join(f"\\rsid{r}" for r in rs) + "}")
    parts.append("{\\*\\generator " + rtf_escape(generator) + ";}")
    info = "{\\info"
    for tag, val in (("title", title), ("author", author), ("operator", operator), ("company", company)):
        if val:
            info += f"{{\\{tag} {rtf_escape(val)}}}"
    info += tim("creatim", created) + tim("revtim", revised) + "{\\version2}{\\edmins4}{\\nofpages1}}"
    parts.append(info)
    parts.append("\\paperw11906\\paperh16838\\margl1701\\margr1701\\margt1417\\margb1417")
    parts.append("\\pard\\plain \\ltrpar\\ql \\li0\\ri0\\sa160\\sl259\\slmult1 \\f31506\\fs22\\insrsid"
                 f"{rs[0]}")
    for p in paragraphs:
        parts.append("{\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\insrsid" + str(rs[-1]) + " " + rtf_escape(p) + "\\par }")
    parts += body_extra or []
    if nesting:
        parts.append("{" * nesting + "x" + "}" * nesting)
    body = "\n".join(parts) + "\n}"
    return body.encode("latin-1") + trailer
