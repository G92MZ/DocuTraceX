# Samples

Realistic, **benign** sample files — one per supported type — to try every
DocuTraceX module. Upload any of them and open the case in **Components**.

They all tell one fictitious story: an **invoice-fraud campaign** that
impersonates a supplier, *Suministros Iberia S.L.*, against the finance team of
*Grupo Ejemplo* ("factura 2026-0187 pendiente de pago — hemos cambiado nuestra
cuenta bancaria"). Each file is a structurally real document of its type and
carries the techniques real maldocs use.

> **Nothing here is malware.** Every host is a reserved `*.example` domain
> (RFC 2606), every address a TEST-NET IP (RFC 5737), and the "payloads" are
> inert placeholders (`MZ` + a text line, `MsgBox` scripts). The macros and
> scripts reference those inert values only.

## Getting the files

The samples are stored **compressed and encrypted** in `samples/samples.zip`
with the customary password **`infected`**, so antivirus engines, mail gateways
and Git hosting scanners do not flag or quarantine them (they would: the files
carry real exploit *structures*, even if every payload is inert).

```bash
python scripts/make_samples.py --extract   # unpack into samples/ (git-ignored)
python scripts/make_samples.py             # regenerate samples/samples.zip
```

Or open the archive with 7-Zip, WinRAR or Windows Explorer (password `infected`).
The test suite unpacks it on its own.

## Campaign indicators (all inert)

| Indicator | Role |
|---|---|
| `cdn-update.example.net` — `http://cdn-update.example.net/files/upd.bin` | payload download |
| `198.51.100.23` — `http://198.51.100.23/plantillas/Normal.dotm`, `/a.ps1` | remote template, PowerShell stage 2 |
| `203.0.113.47` | sending VPS, OLE2Link target, form collector |
| `login.rnicrosoft-online.example` | look-alike Microsoft 365 login (phishing page) |
| `suministros-iberia.example.com` | the impersonated supplier |
| `pagos.suministros@mail-box.example.org` | Reply-To used to divert the payment |

## What each file contains

| File | What you should see |
|---|---|
| `sample.docm` | *Factura 2026-0187*. VBA downloader (`AutoOpen`/`Document_Open`, `URLDownloadToFileA` declare, hex-decoded URL, `WScript.Shell.Run`), Base64 PowerShell stored in a **document variable**, a **DDEAUTO** field, custom properties, rsids. ViperMonkey emulates the download and the commands. |
| `sample.docx` | Commercial proposal with **remote template injection** (`attachedTemplate` → `198.51.100.23`) and an `INCLUDEPICTURE` tracking image. No macros. |
| `sample.dotx` / `sample.dotm` | Corporate template with a tracking image / a **global template** with `AutoExec` persistence (copies itself to Word STARTUP) and `AutoNew`, plus a remote template. |
| `sample.xlsx` | Invoice sheet with `WEBSERVICE` / `FILTERXML` formulas and a **hidden** sheet holding the "new IBAN". |
| `sample.xlsm` `.xltm` `.xlam` | Same, plus a **very-hidden Excel 4.0 macro sheet** with `Auto_Open` → `CALL(urlmon, URLDownloadToFileA)` + `EXEC(rundll32 …)`, and VBA `Workbook_Open` (XMLHTTP + ADODB.Stream + Shell). |
| `sample.xltx` | Template version of the invoice workbook (no macros). |
| `sample.xlsb` | oletools' benign Excel 4.0 test file (`ALERT` + `HALT` in an XLM macro sheet with `Auto_Open`); see *Third-party* below. |
| `sample.pptx` `.potx` `.sldx` | "New supplier payment procedure" slides with a link to the look-alike login page. |
| `sample.ppsx` | Slideshow with the **mouse-over `ppaction://program`** trick (PowerShell download on hover). |
| `sample.pptm` `.potm` `.ppsm` `.ppam` `.sldm` | Same slides plus VBA `Auto_Open` launching `mshta` through WMI (`Win32_Process.Create`). |
| `sample.doc` | Legacy Word binary: the VBA downloader, SummaryInformation, and an **Equation Editor** object in the ObjectPool (CVE-2017-11882 shape). |
| `sample.dot` | Legacy template with `AutoExec`/`AutoNew` and an **OLE Package** carrying `Factura.pdf.vbs` (extracted and scanned recursively). |
| `sample.xls` `.xlt` `.xla` | BIFF8 workbook with a **very-hidden Excel 4.0 macro sheet** and VBA `Workbook_Open`. |
| `sample.ppt` `.pot` | Legacy PowerPoint with data **appended after the compound file**. |
| `sample.rtf` | RTF invoice: **Equation Editor** object with junk inside `\objdata`, **OLE2Link** + `\objupdate` (CVE-2017-0199) to `203.0.113.47`, an **OLE Package** (`Factura.pdf.vbs`), remote `\*\template`, `INCLUDEPICTURE` and a hyperlink field. |
| `sample.pdf` | Invoice lure "protected by Microsoft 365": **OpenAction JavaScript** obfuscated with `eval(unescape(...))` that exports and opens the embedded `report.docm` and launches the phishing URL (the V8 sandbox unfolds it), a **Launch** action, a link and a **QR code** to the look-alike login, a credential **form submitting** to `203.0.113.47`, and the macro document **embedded**. |
| `sample.eml` | The phishing email: SPF/DKIM/DMARC fail, two `Received` hops from `203.0.113.47`, PHPMailer, Reply-To diversion, a **DKIM signature broken by a later edit** of the amount (1.250,00 → 7.250,00), a **Safe Links + Proofpoint** wrapped link to the look-alike domain, hidden text and a tracking pixel. Attachments: `report.docm`, `pedido.doc` (**the RTF disguised as .doc**), `Factura_2026-0187.pdf.exe` (double extension), `Factura.html` (**HTML smuggling**: `atob` → Blob → download, then redirect) and `escanear.png` (**QR code**). All attachments are analysed recursively. |
| `sample.emlx` | The same message in Apple Mail's `.emlx` wrapper. |
| `sample.msg` | The same message as an Outlook `.msg` (MAPI streams, HTML body, the same attachments). |
| `encrypted/sample_encrypted.eml` | Gateway evasion: `Factura_2026-0187.zip` (**WinZip AES**) holding a **password-protected** `.xlsm`, with *"La contraseña del archivo es: Fact2026"* in the body. DocuTraceX finds the password, opens the ZIP and the workbook, and analyses the macros inside (Nested tab). |
| `encrypted/sample_velvet.xlsm` | The macro workbook encrypted with Excel's built-in **`VelvetSweatshop`** password (opens without a prompt, scanners see only ciphertext): decrypted automatically, flagged high, and the decrypted copy analysed. |

## Lab: test the network checks safely

`lab/phish_lab.eml` (inside the archive) is the same campaign with its link and an attached login form pointing to a **local phishing-kit simulator**:

```bash
python scripts/phish_lab.py      # serves http://127.0.0.1:8808 (Ctrl+C to stop)
```

Open the email in DocuTraceX and press **Check** on the `127.0.0.1` URL in the IOCs tab. The simulator behaves like a real kit: a bot filter (no browser headers → 404), a redirect, a Microsoft 365 look-alike login prefilled with the address from the link, an obfuscated script that "exfiltrates" to a `*.example` URL, a different page for iPhones (cloaking), and — after **Send fake credentials** — an MFA page linking to a `.docm` download. The simulator's console prints the fake identity it receives.

## Third-party

| File | Source | License |
|---|---|---|
| `sample.xlsb` | [oletools](https://github.com/decalage2/oletools) `tests/test-data/excel4-macros/excel4_sample_macro.xlsb` (benign: `ALERT` + `HALT`) | BSD-2-Clause, © Philippe Lagadec |

Everything else is generated by `scripts/make_samples.py` with the builders in
`scripts/` (`officekit`, `ovba`, `cfb`, `rtfkit`, `pdfkit`, `mailkit`, `mkmsg`).
