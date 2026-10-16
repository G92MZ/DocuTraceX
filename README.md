<div align="center">

# 📄🔎 DocuTraceX

**Static forensic analysis of Office, PDF, RTF and email files — without opening them.**

Drop in a suspicious `.docm`, `.xlsm`, `.doc`, `.rtf`, `.pdf`, `.eml` or `.msg`,
open the browser, and investigate: the real file type vs. what it claims to be,
macros (decompiled **and emulated**), DDE, remote templates and exploit objects,
hidden Excel 4.0 sheets, PDF JavaScript run in a **sandbox**, email spoofing,
broken DKIM and look-alike domains, payloads **pulled apart recursively**, IOCs
you can **check on the Internet through your proxy**, your own **YARA** rules,
triage marks, a one-click report — and an **AI assistant / MCP server** that can
read the case for you. **Nothing in the sample is ever executed.**

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-local-009688)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Offline](https://img.shields.io/badge/offline-unless%20you%20ask-success)

</div>

---

## 🚀 Quickstart

```bash
pip install -e .
python run.py                 # open http://127.0.0.1:8000
```

```bash
python run.py --port 8001     # run next to WinHound/Longanizer on another port
```

The web app runs on **your** Python; the analysis tools run on a **portable**
Python under `tools/`, provisioned automatically on first launch together with
everything else the tools need (PyPy 2.7 for ViperMonkey, the Didier Stevens
scripts, OfficeMalScanner, the IP database and Chromium for screenshots — see
`scripts/setup_portable_python.py`). On Windows, point it at your FLARE-VM and it
just works.

> 🧪 **Try it now:** `samples/samples.zip` (password **`infected`**, so antivirus
> engines leave it alone — open it with 7-Zip/Windows, or run
> `python scripts/make_samples.py --extract`) holds one realistic, **benign** sample per
> supported type, all telling the same story — an invoice-fraud campaign that
> impersonates a supplier: a `.docm` with a VBA downloader + DDEAUTO, an `.xlsm`
> with a very-hidden Excel 4.0 macro sheet, an RTF disguised as `.doc` with
> Equation Editor / OLE2Link objects, a PDF with obfuscated JavaScript, a QR code
> and an embedded macro document, and the phishing `.eml`/`.msg` that carries
> them (broken DKIM, wrapped look-alike link, HTML smuggling…). Every indicator
> is inert (`*.example`, RFC 5737 IPs). See [`samples/README.md`](samples/README.md).

## 🧭 How you use it

1. **📥 Upload** — drop a file. The original is copied, hashed and never modified; the analysis is **queued** (one per instance) and runs in the background.
2. **🔬 Identify** — libmagic + structural recognizers decide the *real* family and flag extension/type **discrepancies** (that `.doc` that is really RTF, that `.pdf` that is an OLE container).
3. **🧩 Inspect** — **Components**: a sub-tab per analysis — Findings (with the exact **evidence** and a ↗ pivot to where it lives), IOCs, VBA, JavaScript, PDF tools, email Authentication/Headers/Body/Attachments, RTF Objects/Structure, the recursive **Nested** tree, every tool's raw output…
4. **🌐 Check** — press **Check** on a URL, domain or IP in the IOCs tab: DocuTraceX visits it as a real browser through your proxy (see [Network checks](#-network-checks-and-opsec)).
5. **🧷 Hunt** — load your **YARA** rules (upload or a server path) and match them over the file and everything extracted from it.
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
| 🟨 **JavaScript** | collected from PDFs, email HTML, HTML/HTA/SVG/WSF/JS/JSE attachments and JScript inside VBA; static patterns, string decoding and an isolated **STPyV8 sandbox** with recording stubs (WScript, ActiveX, browser, Acrobat) that unfolds `eval`/`Function` layers and logs what the script would do |
| 🧰 **Real tools** | oletools (olevba · oleid · mraptor · msodde · oleobj · rtfobj), pcodedmp · pcode2code, msoffcrypto-tool, XLMMacroDeobfuscator, pyxlsb2, peepdf · pyHanko · pdfium + zxing-cpp, dkimpy, OfficeMalScanner/RTFScan, Didier Stevens Suite (oledump + plugins, zipdump, pdfid, pdf-parser, emldump, rtfdump, decode-vbe) — each tool's raw output kept next to its findings |
| 🪆 **Recursion** | attachments, embedded OLE objects, RTF objects, PDF-embedded files and files served by checked URLs are analysed **in turn** with their family's tools — the DDE inside a `.docm` inside a `.pdf` surfaces with its full path |
| 🧷 **IOC extractor** | URLs, domains, IPv4/IPv6 and hash-like strings across every parser's output, with provenance (email IOCs come from the content, not the headers) |
| 🌐 **Network checks** | on demand, through your proxy: **URLs** visited as a real browser (Edge on Windows *and* Safari on iPhone → cloaking) with the victim's address swapped for a fake identity — redirects, TLS certificate, forms, impersonated brand, page scripts in the V8 sandbox, screenshot with JavaScript off, safe preview, served files analysed, and *Send fake credentials* to see the kit's next stage; **domains**: DNS, RDAP age/registrar, Certificate Transparency; **IPs**: ASN/ISP/country offline, RDAP owner and abuse contact, reverse DNS, Tor exit |
| 🛡️ **YARA** | your rules by upload (`.yar`/`.yara`/`.zip`/`.tar.gz`) or **server path**, compiled on demand with streaming progress; matches with the rule source, the matched bytes in context and the file path — every hit a finding you mark |
| 🤖 **AI & MCP** | **AI (API)**: any OpenAI-compatible endpoint (your company's LiteLLM, a provider's API); **AI (local)**: Ollama / LM Studio / llama.cpp on your machine; **MCP**: a stdio server for Claude Desktop / Claude Code — all three use the same **read-only** tools over the case |
| 🏷️ **Marks** | per-finding TP/FP/Suspicious/Informational + comment, manual marks on any IOC/header/attachment/JavaScript hit, sandbox event or decoded string, and free-text notes, kept separate from the evidence and **preserved across re-analysis** (stable finding IDs) |
| 🧵 **Tasks** | a sequential queue with per-file **sub-step log** — every tool that ran, its status, timing and findings — plus isolated **re-run** of a single module |
| 📊 **Report** | one self-contained HTML report of the confirmed findings, with evidence, IOCs and the nested tree |
| ⚙️ **Settings** | the app-wide proxy for network checks (HTTP/HTTPS/SOCKS5, tested from the UI) |
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

Scripts and web pages found inside them (`.js` `.jse` `.vbs` `.hta` `.wsf` `.html` `.svg`…) are extracted and analysed too.

## 🌐 Network checks and OPSEC

Checking an indicator means contacting the attacker's infrastructure, so DocuTraceX is careful about it:

- **Nothing goes out unless you press Check.** Configure a proxy (HTTP, HTTPS or SOCKS5 — Tor works) in **Settings**; without one you are asked once and, if you accept the risk, checks leave from your own IP. The installer and the updater never use it.
- **Looks like a victim's click.** Requests carry the full header set of a current browser (Edge on Windows and Safari on iPhone, with the webmail `Referer` for links from emails), so bot filters and cloaking kits serve the real page — and the two views are compared to detect cloaking.
- **Never the real victim.** The victim's address in the link (plain, URL-encoded or Base64; query, path or fragment) and usernames are replaced by a random fake identity on mail.com / gmx.com / email.com / post.com / consultant.com / usa.com.
- **Nothing runs.** No JavaScript runs and no images, CSS or scripts are downloaded; page scripts go through the V8 sandbox, the screenshot is rendered from the downloaded HTML with every request blocked, and the preview is sandboxed with a CSP that forbids any load. The optional *live screenshot* (with images/CSS, still no JavaScript) is the only exception, through the proxy.
- **Forms only on request.** *Send fake credentials* posts the fake identity through a form (hidden fields and cookies kept) to show the kit's next stage — only when you press it.
- **Domains and IPs without touching the attacker:** DNS through your resolver; RDAP, crt.sh and the Tor list through the proxy; ASN/ISP/country from a local database.
- **Practise safely:** `python scripts/phish_lab.py` starts a local phishing-kit simulator (bot filter, redirect, M365 look-alike login, exfiltration script, iPhone cloaking, MFA stage, `.docm` download); then open `lab/phish_lab.eml` from the samples archive and press **Check**.

IP data: *IP Geolocation by [DB-IP](https://db-ip.com)* (CC BY 4.0) and [iptoasn.com](https://iptoasn.com) (public domain), downloaded at install time.

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
- **Your data lives in** `cases/` (per-case evidence, results, marks, report), `yara/` (your rules), `config/` (settings such as the proxy) and `tools/` (the portable runtime) — all git-ignored and preserved across updates.
- **Two interpreters by design:** the web app on your Python, the analysis tools on the portable one (plus PyPy 2.7 just for ViperMonkey), so a messy tool dependency never touches your environment.
- **Licences:** DocuTraceX is Apache-2.0 and ships no GPL code. GPL tools (pcodedmp, peepdf-3) are installed into the portable at provisioning time and run as separate processes.

## 🔄 Updating

Grab the latest version without git — the updater checks GitHub and updates the
app in place, **keeping your cases, rules, settings and tools**:

```bash
python update.py            # check for a new version and update (asks first)
python update.py --check    # only check, change nothing
python update.py --yes      # update without asking
```

(Cloned with git? `git pull` works too.)

## 🧭 Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full design notes and the task breakdown.

## 📜 License

Licensed under the **Apache License 2.0** — free to use, modify and distribute
(including commercially); just keep the copyright and `NOTICE`, and state your
changes. See [`LICENSE`](LICENSE).

© 2026 Gregorio Moreno (**gmzpt**)
