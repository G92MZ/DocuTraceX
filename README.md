<div align="center">

# 📄🔎 DocuTraceX

**Static forensic analysis of malicious documents, emails, scripts and droppers — without opening them.**

Drop in a suspicious `.docm`, `.xlsm`, `.rtf`, `.pdf`, `.eml`/`.msg`, a `.js`/`.vbs`/`.ps1`/`.hta`,
a `.lnk`, an `.iso`/`.zip`, a OneNote, a `.jar`, an `.msi` or an `.exe`, open the browser, and
investigate: the real file type vs. what it claims to be, macros (decompiled **and emulated**),
DDE, remote templates and exploit objects, hidden Excel 4.0 sheets, scripts **deobfuscated and
run in sandboxes**, the **obfuscation techniques** they use, XOR/compressed stages **decrypted and
followed to the final behaviour**, email spoofing, broken DKIM and look-alike domains, packed PEs
unpacked, payloads **pulled apart recursively**, IOCs you can **check on the Internet through your
proxy**, your own **YARA** rules, triage marks, a one-click report — and an **AI assistant / MCP
server** that can read the case for you. **Nothing in the sample is ever executed.**

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-local-009688)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Offline](https://img.shields.io/badge/offline-unless%20you%20ask-success)

</div>

---

## 🚀 Quickstart

```bash
python install.py             # once: sets everything up
python run.py                 # from then on — open http://127.0.0.1:8000
```

```bash
python run.py --port 8001     # run next to WinHound/Longanizer on another port
```

> Prefer pip? `pip install -r requirements.txt` installs the web service, and
> `python run.py` heals the portable toolchain on start. `install.py --web-only`
> does the former without the portable; `install.py --force` reprovisions it.

## 🔄 Updating

<!-- rev: gmzpt -->

`python run.py` **checks for a new version on every start**: if there is one it
asks `Update X.Y.Z -> A.B.C? [y/N]`, and on `y` it updates and re-provisions the
toolchain (`install.py`) before launching, so new tools are installed
automatically. Skip the check with `python run.py --no-update`.

You can also update on demand without git — the updater checks GitHub and updates
the app in place, **keeping your cases, rules, settings and tools**:

```bash
python update.py            # check for a new version and update (asks first)
python update.py --check    # only check, change nothing
python update.py --yes      # update without asking
```

(Cloned with git? `git pull` works too.)

## 🧪 Samples

`samples/samples.zip` (password **`infected`**, so antivirus engines leave it
alone — open it with 7-Zip/Windows, or run `python scripts/make_samples.py --extract`)
holds realistic, **benign** samples for every supported type and engine, all telling the
same story: an invoice-fraud campaign impersonating a supplier — a `.docm` with a VBA
downloader + DDEAUTO, an `.xlsm` with a very-hidden Excel 4.0 macro sheet, an RTF disguised
as `.doc` with Equation Editor / OLE2Link objects, a PDF with obfuscated JavaScript, a QR code
and an embedded macro document, the phishing `.eml`/`.msg` that carries them (broken DKIM,
wrapped look-alike link, HTML smuggling…), plus droppers in every script language
(obfuscator.io JS, a JS stacking the classic **obfuscation techniques**, a **JS → VBS →
PowerShell → XOR → Deflate** chain, a PowerShell XOR stager), shortcuts (`.lnk`/`.url`), an
`.msi`, a `.jar`/`.war`, a OneNote lure, `.iso`/`.cab`/`.tar.gz` containers, a packed PE, a
PyInstaller `.exe` and a file full of **IOC noise** the extractor must ignore. Every indicator is
inert (`*.example`, RFC 5737 IPs, `MZ`+text stubs). See [`samples/README.md`](samples/README.md).

## 🧭 How you use it

1. **📥 Upload** — drop one or more files (and a **password**, if they are encrypted and you know it). Each original is copied, hashed and never modified; the analyses are **queued** and run in the background (one at a time by default; raise it right under the upload box, up to 8, or with `DOCUTRACEX_MAX_CONCURRENCY`). The **Tasks** tab shows every task — running ones step by step, live, with a ticking timer; finished ones with how long each step took, even after a restart.
2. **🔬 Identify** — libmagic + structural recognizers decide the *real* family and flag extension/type **discrepancies** (that `.doc` that is really RTF, that `.pdf` that is an OLE container).
3. **🧩 Inspect** — **Components**: a sub-tab per analysis — Findings (with the exact **evidence** and a ↗ pivot to where it lives), IOCs (grouped by type, filterable), VBA, JavaScript (with the **confirmed obfuscation techniques**), PowerShell/VBScript/batch/Python, PDF tools, email Authentication/Headers/Body/Attachments, RTF Objects/Structure, PE, the recursive **Nested** tree (decrypted stages included), every tool's raw output…
4. **🌐 Check** — press **Check** on a URL, domain or IP in the IOCs tab: DocuTraceX visits it as a real browser through your proxy (see [Network checks](#-network-checks-and-opsec)).
5. **🧷 Hunt** — load your **YARA** rules (upload or a server path); they run **automatically on every analysed object** (the file, everything extracted, nested children, decoded stages). Hits wait in the YARA tab until you mark them — a marked hit becomes a finding (True positives reach the report) — and **export the matches to CSV** (rule, metadata, matched bytes and the hex context with the hit marked).
6. **🤖 Ask** — in the **AI** tab, ask questions about the case to your LiteLLM / provider API or a local model, or connect Claude Desktop / Claude Code through **MCP**.
7. **🏷️ Triage** — mark each finding **TP / FP / Suspicious / Informational** with a comment (or add free-text notes); marks survive re-analysis.
8. **📝 Report** — a self-contained HTML report of the **confirmed (True positive)** findings, ready to print to PDF or attach to a ticket.

## ✨ What's inside

| | |
|---|---|
| 🔍 **Type truth** | libmagic + structural recognizers (OPC/OOXML, EMLX, CFB, RTF) → family and extension/type **discrepancy** |
| 📝 **Office (OOXML)** | Word/Excel/PowerPoint: metadata and attribution, VBA, DDE & field codes, `WEBSERVICE`/`FILTERXML`, **hidden/very-hidden sheets** (and an **unhidden copy** as evidence), external links, `.xlsb` (pyxlsb2) |
| 🗂️ **Office (OLE/BIFF)** | legacy `.doc`/`.xls`/`.ppt`: CFB structure, SummaryInformation, VBA, ObjectPool objects, **Excel 4.0 (XLM)** macros in hidden BIFF sheets |
| 🐒 **VBA** | olevba, mraptor, **p-code** disassembly and decompilation (pcodedmp · pcode2code — VBA stomping), oledump VBA plugins, hidden modules and locked projects, risky `Declare`s, and **ViperMonkey emulation** on a second portable interpreter (PyPy 2.7), isolated and time-limited: what the macro would download, write and run |
| 🧩 **Own Office rules** | remote templates (template injection), Follina/MSHTML/search-ms handlers, UNC targets, Equation Editor, OLE2Link, OLE Package, ActiveX/MSCOMCTL, XLM macro sheets + `Auto_Open`, PowerPoint program actions, add-ins, payloads in document variables / custom properties |
| 📄 **PDF** | raw-token scan (`/OpenAction`, `/JS`, `/Launch`, `/EmbeddedFile`, `/XFA`, `/URI`, hex-obfuscated names…), every object browsable, peepdf (versions, CVEs), targeted pdf-parser, pdfid -e, **digital signatures** (modified after signing?), incremental updates that add active content, **QR codes** on rendered pages, lure layouts, external form submits, data after `%%EOF` |
| 📃 **RTF** | recognised by content (a `.doc` that is really RTF too): `\objdata` objects via rtfobj (Equation Editor, OLE2Link + `\objupdate`, Package, ActiveX) extracted and scanned recursively, remote `\*\template` and fields, font-table overflow (CVE-2023-21716), pFragments (CVE-2010-3333), deep nesting, `\objdata` obfuscation, data after the end, `\info`/generator/rsid attribution, rtfdump · RTFScan |
| ✉️ **Email** | `.eml`/`.emlx`/`.msg`: the **`Received` hop chain** with Δt and anomalies, SPF/DKIM/DMARC, **offline DKIM body hash** (edited after signing?), From/Return-Path/Reply-To & display-name **spoofing**, **look-alike / homoglyph domains**, links rewritten by gateways decoded (Proofpoint, Safe Links, Barracuda, Mimecast, Trend Micro…), HTML phishing patterns (credential forms, **HTML smuggling**, tracking pixels), QR codes in images, attachments hashed, typed and analysed |
| 🔗 **Shortcuts** | `.lnk` (LnkParse3: target, arguments, hidden window, icon, the tracker block's machine id) and `.url`/`.website` (remote `URL=`, UNC `IconFile=` for NTLM theft); the launched command goes through the scripting engine |
| 📓 **OneNote** | `.one`/`.onepkg`: the embedded files behind "double-click to view" lures carved from the MS-ONESTORE structure and analysed recursively |
| ☕ **Java** | `.jar`/`.war`/`.ear`/`.class`/`.jsp`: manifest (Main-Class, Java agents), constant-pool strings and calls matched against Java behaviour rules (`Runtime.exec`, reflection/`defineClass`, JNDI/Log4Shell, deserialization), JSP webshell patterns, `web.xml`, signing, serialized objects; **CFR** decompiles interesting classes when a JVM is present |
| 📦 **MSI** | Windows Installer database: `CustomAction` (scripts, EXE/DLL, commands) and when it fires, `Binary` streams, `Property`/`CustomActionData`, embedded CABs; commands through the scripting engine |
| 🧱 **PE** | `.exe`/`.dll`/`.sys`…: **static triage** with pefile — header and timestamp anomalies, section entropy and W+X, suspicious imports grouped by behaviour, embedded PEs and overlays, TLS callbacks, Authenticode, version-info masquerading; **packer detection and static unpacking** (UPX, AutoIt, Inno Setup, NSIS/SFX, Nuitka, Enigma Virtual Box) with the unpacked files analysed as children; **FLOSS** strings mined for IOCs and **capa** capabilities as ATT&CK findings (optional) |
| 🐍 **Python** | `.py`/`.pyc` and **PyInstaller** executables (CArchive + PYZ unpacked): `.pyc` decompiled with **pycdc** when provisioned, else disassembled or string-mined; Python behaviour rules |
| 💿 **Containers** | `.zip`/`.7z` (password-protected too), `.tar`/`.gz`/`.bz2`/`.xz`, **CAB** and **ISO/IMG/UDF** images (a classic Mark-of-the-Web bypass carrying a LNK + payload), extracted with limits against archive bombs |
| 🟨 **JavaScript** | collected from PDFs, email HTML, HTML/HTA/SVG/WSF/JS/JSE attachments and JScript inside VBA; **deobfuscated first** (multi-pass decode, `eval`/`Function` unfolding, Dean Edwards / JSFuck / AAEncode / JJEncode, **webcrack** for obfuscator.io), then an isolated **STPyV8 sandbox** with recording stubs (WScript, ActiveX, FileSystemObject, browser, Acrobat) logs what the script would do. **Confirmed obfuscation techniques**, each with concrete evidence and marked *static* or *resolved in the sandbox*: arithmetic literals, massive `\xNN` blocks (variable + lines), custom **XOR** decryptors, IIFEs fed encoded strings, `fromCharCode` with arithmetic, encrypted array + hard-coded key + decryptor, fake library headers, **anti-sandbox timing** (`WScript.Sleep`, clock deltas), the strings `fromCharCode` builds, what the XOR routines return and the **dropped payload** |
| 🧪 **Scripting engine** | PowerShell, VBScript, batch/cmd, Python and JavaScript get their own tabs: each is **deobfuscated before analysis** (PowerShell `-enc`/`FromBase64String`/char codes/format/concat/`iex` layers **plus `-bxor` XOR loops (numeric, string or byte-array key), XOR'ed number arrays and `DeflateStream`/`GZipStream` stages**; VBScript `.vbe`/`Chr`/`StrReverse`/`Replace`; batch caret/`set` indirection; JS cascade + webcrack) and the clean code is matched against a shared **behaviour catalogue** — execution, download, LOLBins, persistence, AMSI/defence evasion, anti-sandbox, injection/shellcode, discovery, credential access, file-drop/HTML-smuggling, C2 — every hit a finding with its MITRE **ATT&CK** technique, the full source dumped to `extracted/code/`. Commands launched by VBScript/batch are followed into PowerShell. Emulation: JS (STPyV8), VBA (ViperMonkey) and **PowerShell** (**box-ps** on portable PowerShell Core) |
| 🧰 **Real tools** | oletools (olevba · oleid · mraptor · msodde · oleobj · rtfobj), pcodedmp · pcode2code, msoffcrypto-tool, XLMMacroDeobfuscator, pyxlsb2, peepdf · pyHanko · pdfium + zxing-cpp, dkimpy, OfficeMalScanner/RTFScan, Didier Stevens Suite (oledump + plugins, zipdump, pdfid, pdf-parser, emldump, rtfdump, decode-vbe), LnkParse3, pefile, **FLOSS** · **capa**, **webcrack** (JS deobfuscation, portable Node), **box-ps** (PowerShell sandbox, portable PowerShell Core), **pycdc**, **CFR**, and the unpackers (UPX, AutoIt-Ripper, innoextract, 7-Zip, nuitka-extractor, evbunpack, Detect It Easy) — each tool's raw output kept next to its findings |
| 🔐 **Encrypted files** | password-protected Office (OOXML agile/standard, legacy RC4/CryptoAPI), PDF (RC4/AES, owner-only too) and **ZIP (ZipCrypto/AES) / 7z** archives are **unlocked and the decrypted copy is analysed** in full — with your password (at upload, or *Unlock & re-analyse* later), a password the **email gives in its body** (detected in English, Spanish, Italian, French, German, Portuguese, Dutch, Polish, Turkish, Russian, Chinese… "la contraseña es…", "Kennwort lautet…"), the empty PDF password, Excel's `VelvetSweatshop` or the usual `infected`; when the email disguises it, **Try every word of the email** tests every word of the text body, the subject, the attachment names and the sender's/recipients' addresses, names and domains (no time limit); the original keeps the encryption findings |
| 🪆 **Recursion** | attachments, ZIP/7z/tar/CAB/ISO entries, embedded OLE objects, RTF objects, PDF-embedded files, OneNote embedded files, MSI binaries, unpacked PE contents, PyInstaller modules and files served by checked URLs are analysed **in turn** with their family's tools — the DDE inside a `.docm` inside a `.pdf` surfaces with its full path. **Decrypted and decoded stages too**: what a script decrypts (XOR results, dropped payloads) and **every encoded literal in the recovered code** (base64 / hex, gzip/zlib inside them) becomes a 🔓 **nested child** — a file by its magic, a script, plain text mined for IOCs, or an opaque blob with its entropy (encrypted data) — analysed by whatever fits it — JS → VBS → PowerShell → final download, followed to the end. Scripts analysed inside nested children (a dropped `.ps1`, a `.js` in a ZIP…) also appear in the case's **JavaScript / PowerShell / VBScript / batch / Python tabs** with their full analysis and their nested path. Every nested child with its own analysis (PE, PDF, Office, RTF, email, shortcut, MSI, Java, OneNote, archive…) can be **opened like a case** — *Open analysis ↗* in the Nested tree shows its own tabs, at any depth — and first-level children also get a **direct tab** in the case (`PE · payload.exe`, `RTF · pedido.doc`…). Up to **12 levels**, capped at 300 nodes per case against archive bombs |
| 🧷 **IOC extractor** | URLs, domains, IPv4/IPv6, emails, file paths (spaces and quoted paths included), registry keys, named pipes, commands/LOLBins, MAC addresses and hash-like strings across every parser's output, with provenance (email IOCs come from the content, not the headers). TLDs validated against the **official IANA list** (downloaded at install, refreshable in Settings); noise filtered out: the tools' own URLs, the app's install path, binary garbage that looks like a path, everyday words that look like commands, and YARA results. The IOCs tab groups them **by type** with a type filter, value search, counts, collapsible sections and *Check all* |
| 🌐 **Network checks** | on demand, through your proxy: **URLs** visited as a real browser (Edge on Windows *and* Safari on iPhone → cloaking) with the victim's address swapped for a fake identity — redirects, TLS certificate, forms, impersonated brand, page scripts in the V8 sandbox, screenshot with JavaScript off, safe preview, served files analysed, and *Send fake credentials* to see the kit's next stage; **domains**: DNS, RDAP age/registrar, Certificate Transparency and a visit to the domain's website (same views, screenshot and forms as a URL); **IPs**: ASN/ISP/country offline, RDAP owner and abuse contact, reverse DNS, Tor exit |
| 🛡️ **YARA** | your rules by upload (`.yar`/`.yara`/`.zip`/`.tar.gz`) or **server path**, compiled on demand with streaming progress and **run automatically on every analysed object** (original, extracted, nested children, decoded/decrypted stages, recovered code); matches with the rule source, the matched bytes in context and the file path. **A hit is not a finding until you mark it** in the YARA tab: once marked it joins Findings, and True positives reach the report — and **Export CSV** (RFC 4180, UTF-8 for Excel): one row per matched string with rule, namespace, tags, every `meta` field, offset, bytes and the hex context with the hit in `[ ]` |
| 🤖 **AI & MCP** | **AI (API)**: any OpenAI-compatible endpoint (your company's LiteLLM, a provider's API); **AI (local)**: Ollama / LM Studio / llama.cpp on your machine; **MCP**: a stdio server for Claude Desktop / Claude Code — all three use the same **read-only** tools over the case |
| 🏷️ **Marks** | per-finding TP/FP/Suspicious/Informational + comment, manual marks on any IOC/header/attachment/JavaScript hit, sandbox event or decoded string, and free-text notes, kept separate from the evidence and **preserved across re-analysis** (stable finding IDs) |
| 🧵 **Tasks** | the analysis queue (configurable concurrency) with a **live sub-step log** — the step running now with its timer, every finished tool with its status, duration and findings — and **every finished task kept across restarts** with its timings; plus isolated **re-run** of a single module |
| 📊 **Report** | one self-contained HTML report of the confirmed findings, with evidence, IOCs and the nested tree |
| ⚙️ **Settings** | the app-wide proxy for network checks (HTTP/HTTPS/SOCKS4/SOCKS5, tested from the UI), or a free public proxy picked and rotated automatically; the IANA TLD list used to validate IOC domains (status + *Refresh now*) |
| 🩺 **Diagnostics** | app vs. tool interpreters, every dependency, external tool, IP database, Chromium and the proxy checked in one place |

## 📦 Supported formats

| Family | Extensions |
|---|---|
| **Word** | `.doc` `.dot` `.docx` `.docm` `.dotx` `.dotm` |
| **Excel** | `.xls` `.xlt` `.xla` `.xlsx` `.xlsm` `.xltx` `.xltm` `.xlam` `.xlsb` |
| **PowerPoint** | `.ppt` `.pot` `.pptx` `.pptm` `.potx` `.potm` `.ppsx` `.ppsm` `.ppam` `.sldx` `.sldm` |
| **RTF** | `.rtf` (and any extension whose content is RTF) |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.emlx` `.msg` |
| **Archives / containers** | `.zip` `.7z` (password-protected too) · `.tar` `.gz` `.tgz` `.bz2` `.tbz2` `.xz` `.txz` · `.cab` · `.iso` `.img` `.udf` |
| **Scripting files** | `.js` `.jse` `.mjs` `.vbs` `.vbe` `.wsf` `.wsc` `.sct` `.hta` `.html` `.htm` `.svg` `.mht` `.mhtml` `.ps1` `.psm1` `.psd1` `.bat` `.cmd` `.py` `.pyw` `.pyc` `.pyo` — their own engine: **deobfuscated first**, then scanned for malicious **behaviour** with MITRE **ATT&CK** ids |
| **Shortcuts** | `.lnk` `.url` `.website` |
| **OneNote** | `.one` `.onepkg` |
| **Java** | `.jar` `.war` `.ear` `.class` `.jsp` `.jspx` `.jspf` |
| **Windows binaries** | `.msi` · `.exe` `.dll` `.scr` `.sys` `.ocx` `.cpl` `.com` (PyInstaller executables unpacked) |
| **Any other file** | images, data… — no specific parser, but still a full case: basic record (type, size, hashes), **YARA**, marks, notes and the report |

Scripts found **inside** other files (a `.js` in a PDF, VBScript in an `.hta`, PowerShell behind a macro, a `.bat` in a ZIP, the command of a `.lnk`…) go through the same scripting engine, at the top level and inside the nested tree — and so do the stages those scripts **decrypt**.

<!-- rev: MH22fELbKP -->

## 🌐 Network checks and OPSEC

Checking an indicator means contacting the attacker's infrastructure, so DocuTraceX is careful about it:

- **Nothing goes out unless you press Check.** Configure a proxy (HTTP, HTTPS, SOCKS4 or SOCKS5 — Tor works) in **Settings**, or press **Connect to free proxy** to pick a working one from the [ProxyScrape free list](https://proxyscrape.com/free-proxy-list) (downloaded at startup; random candidates tested in parallel; **Rotate** for another one; a dead one is replaced automatically before the next check); without one you are asked once and, if you accept the risk, checks leave from your own IP. The installer and the updater never use it.
- **Looks like a victim's click.** Requests carry the full header set of a current browser (Edge on Windows and Safari on iPhone, with the webmail `Referer` for links from emails), so bot filters and cloaking kits serve the real page — and the two views are compared to detect cloaking.
- **Never the real victim.** The victim's address in the link (plain, URL-encoded or Base64; query, path or fragment) and usernames are replaced by a random fake identity on mail.com / gmx.com / email.com / post.com / consultant.com / usa.com.
- **Free proxies are untrusted:** through them an invalid TLS certificate is never accepted (so a proxy can't inject content into the evidence), a proxy is only accepted if a strictly verified HTTPS request through it works, and every check says it went through a free proxy. Kits often block public proxy IPs — if a page looks clean, rotate and re-check.
- **Nothing runs.** No JavaScript runs and no images, CSS or scripts are downloaded; page scripts go through the V8 sandbox, the screenshot is rendered from the downloaded HTML with every request blocked, and the preview is sandboxed with a CSP that forbids any load. The optional *live screenshot* (with images/CSS, still no JavaScript) is the only exception, through the proxy.
- **Forms only on request.** *Send fake credentials* posts the fake identity through a form (hidden fields and cookies kept) to show the kit's next stage — only when you press it.
- **Domains** get DNS (your resolver), RDAP and crt.sh (through the proxy) and, when the name resolves, a visit to their website exactly like a URL check (HTTPS, then HTTP). **IPs** are never contacted: owner and ASN come from RDAP and a local database, plus the Tor list.
- **Patient with slow sites:** each request waits up to 60 s (90 s for a whole redirect chain), and live screenshots up to 60 s for the page to load.
- **Practise safely:** `python scripts/phish_lab.py` starts a local phishing-kit simulator (bot filter, redirect, M365 look-alike login, exfiltration script, iPhone cloaking, MFA stage, `.docm` download); then open `lab/phish_lab.eml` from the samples archive and press **Check**.

IP data: *IP Geolocation by [DB-IP](https://db-ip.com)* (CC BY 4.0) and [iptoasn.com](https://iptoasn.com) (public domain), downloaded at install time.

<!-- k: bhd1Sl5iFX -->

## 🤖 AI and MCP

The **AI** tab has three options, all built on the same **read-only** tools over
the cases — `list_cases`, `case_summary`, `get_findings` (with your marks),
`get_iocs`, `get_module` (any tool's raw result), `get_network_checks` and
`search_case`. None can modify a case or touch the network.

- **AI (API)** — ask in natural language ("is this phishing? what would the macro do?") and the model answers with real data from the case, calling the tools. Any **OpenAI-compatible endpoint** works: your company's **LiteLLM** proxy (with user / extra headers) or a provider's API.
- **AI (local)** — the same against an AI app on your machine (**Ollama** `http://localhost:11434/v1`, **LM Studio** `http://localhost:1234/v1`, llama.cpp…), so the case data never leaves it. Use a model with function calling.
- **MCP** — a stdio MCP server for **Claude Desktop**, **Claude Code** or any MCP client. The tab shows the exact configuration for your installation, ready to copy:

```json
{
  "mcpServers": {
    "docutracex": {
      "command": "<DocuTraceX>/tools/python/python.exe",
      "args": ["-m", "docutracex.mcp_server"],
      "env": { "PYTHONPATH": "<DocuTraceX>", "DOCUTRACEX_CASES_DIR": "<DocuTraceX>/cases" }
    }
  }
}
```

```bash
claude mcp add docutracex -e PYTHONPATH=<DocuTraceX> -e DOCUTRACEX_CASES_DIR=<DocuTraceX>/cases -- <python> -m docutracex.mcp_server
```

Nothing is sent on its own: the AI endpoint is only called when you ask, and its
key is kept in your browser (localStorage), not on the server.

## 📝 Notes

- **Nothing runs for real.** No macro, formula, PDF action, link, media or attachment is ever executed by Office, a browser or the OS. The only exceptions are *emulation*: ViperMonkey (a VBA interpreter written in Python) and the STPyV8 sandbox (a bare V8 with no file system, network or processes, only recording stubs) — both in a separate process with a time limit.
- **Offline unless you ask.** Analysis never touches the network. Network access happens only for the one-time provisioning, the **network checks you launch**, and the **AI endpoint you configure** when you ask it something.
- **Your data lives in** `cases/` (per-case evidence, results, marks, task history, report), `yara/` (your rules), `config/` (settings such as the proxy and concurrency) and `tools/` (the portable runtime, the IP databases and the IANA TLD list) — all git-ignored and preserved across updates.
- **Two interpreters by design:** `install.py` puts only the web service on **your** Python (`fastapi`/`uvicorn`/`jinja2`/`python-multipart` — nothing native or heavy), so your machine's Python is **never a constraint**, and provisions a **portable** Python under `tools/` for the whole analysis toolchain (oletools, YARA, STPyV8, Playwright, pikepdf, the Didier Stevens scripts, OfficeMalScanner, Chromium…), plus PyPy 2.7 just for ViperMonkey, a portable **Node** for webcrack (JS deobfuscation) and portable **PowerShell Core** for box-ps (PowerShell sandbox) — see `scripts/setup_portable_python.py`. A messy tool dependency never touches your environment.
- **Time limits:** every analysis limit (tool runs, the JS/PowerShell sandboxes, ViperMonkey, FLOSS/capa, unpackers, YARA, the whole case) is multiplied by `DOCUTRACEX_TIMEOUT_FACTOR` (default **5**) — a slow tool is better than a lost analysis. In the JavaScript step, webcrack only runs on obfuscator.io/bundled code and up to 3 scripts are analysed at once; the Tasks tab shows the progress inside the step (`script 7/23`).
- **Decrypted stages** (what scripts decrypt) are written to `extracted/stages/` and analysed as nested children; they are never executed either — JavaScript stages only run in the STPyV8 sandbox.
- **Optional tools:** FLOSS, capa, pycdc, CFR (needs a JVM), webcrack and box-ps are provisioned by `scripts/setup_portable_python.py` when possible and skipped cleanly when absent. The PE unpackers (UPX, innoextract, 7-Zip, nuitka-extractor, Detect It Easy) are picked up from `tools/<tool>/` or the `DOCUTRACEX_UPX` / `DOCUTRACEX_INNOEXTRACT` / `DOCUTRACEX_7Z` / `DOCUTRACEX_NUITKA_EXTRACTOR` / `DOCUTRACEX_DIEC` variables; FLOSS/capa can point at existing binaries with `DOCUTRACEX_FLOSS` / `DOCUTRACEX_CAPA` (e.g. FLARE-VM's).
- **Encrypted files:** nothing is brute-forced — only your password, the ones the carrying email gives, the empty PDF password and the well-known defaults are tried (plus every word of the email, only when you press the button). The decrypted copy goes to `extracted/decrypted/` (archives to `extracted/archive/`, with limits on entries and size against archive bombs); the password you type is kept in the case folder (`password.json`), never in `case.json`.
- **Licences:** DocuTraceX is Apache-2.0 and ships no GPL code. GPL/LGPL tools (pcodedmp, peepdf-3, py7zr, **box-ps** and **pycdc** — GPL-3.0, UPX, 7-Zip) are installed into the portable at provisioning time or picked up from `tools/`, and invoked as separate processes, never shipped in this repository. PowerShell Core, Node and webcrack are MIT. webcrack pulls `isolated-vm`, which builds from source, so it needs Node build tools on the host; if the build fails, webcrack stays disabled and the pure-Python JS cascade is the fallback. `python run.py` provisions webcrack and box-ps on start when they are missing, but only **once** — a failed attempt is skipped on later starts (so a missing build toolchain never slows every launch); re-run `scripts/setup_portable_python.py` to retry.

## 🧭 Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full design notes and the task breakdown.

## 📜 License

Licensed under the **Apache License 2.0** — free to use, modify and distribute
(including commercially); just keep the copyright and `NOTICE`, and state your
changes. See [`LICENSE`](LICENSE).

© 2026 Gregorio Moreno (**gmzpt**)
