<div align="center">

# 📄🔎 DocuTraceX

**Static forensic analysis of malicious documents, emails, scripts and droppers — without opening them.**

Drop in a suspicious `.docm`, `.xlsm`, `.rtf`, `.pdf`, `.eml`/`.msg`, a `.js`/`.vbs`/`.ps1`/`.hta`,
a `.lnk`, an `.iso`/`.zip`, a OneNote, a `.jar`, an `.msi` or an `.exe`, open the browser, and
investigate: what the file really is, macros, DDE, remote templates and exploit objects, scripts
**deobfuscated and followed to their final behaviour**, email spoofing and look-alike domains,
packed binaries unpacked, payloads **pulled apart recursively**, IOCs you can **check on the
Internet through your proxy**, your own **YARA** rules, a machine-learning second opinion, triage
marks, a one-click report — and an **AI assistant / MCP server** that can read the case for you.
**Nothing in the sample is ever executed.**

![Python](https://img.shields.io/badge/Python-3.10+%20(64--bit)-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-local-009688)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Offline](https://img.shields.io/badge/offline-unless%20you%20ask-success)

</div>

---

## 🚀 Quickstart

**Requirements on your machine (the host):** Python **3.10 or newer, 64-bit** (tested on 3.10–3.14)
with `pip`, on Windows, Linux or macOS, and Internet access the first time (a 32-bit Python may ask
for the C++ Build Tools to compile dependencies). Only the web service is
installed on it — `fastapi`, `uvicorn`, `jinja2` and `python-multipart` — so its version does not
limit the analysis: every analysis library runs on a separate **portable Python 3.13** that
`install.py` downloads into `tools/` (nothing to install by hand). x86-64 or ARM64.
No compiler, Build Tools or Java needed: the one component that has to be compiled uses a toolchain
fetched for the purpose, and a portable Java runtime is downloaded when there is none.

```bash
python install.py             # once: sets everything up
python run.py                 # from then on — open http://127.0.0.1:8000
```

```bash
python run.py --port 8001     # run next to another local app on a different port
```

> Prefer pip? `pip install -r requirements.txt` installs the web service, and
> `python run.py` heals the portable toolchain on start. `install.py --web-only`
> does the former without the portable; `install.py --force` reprovisions it.

## 🔄 Updating

<!-- rev: gmzpt -->

`python run.py` **checks for a new version on every start**: if there is one it
asks `Update X.Y.Z -> A.B.C? [y/N]`, and on `y` it updates and re-provisions the
toolchain before launching. Skip the check with `python run.py --no-update`.

You can also update on demand without git, **keeping your cases, rules, settings and tools**:

```bash
python update.py            # check for a new version and update (asks first)
python update.py --check    # only check, change nothing
python update.py --yes      # update without asking
```

(Cloned with git? `git pull` works too.)

## 🧪 Samples

`samples/samples.zip` (password **`infected`**, so antivirus engines leave it alone — open it
with 7-Zip/Windows, or run `python scripts/make_samples.py --extract`) holds realistic, **benign**
samples for every supported type, all telling the same story: an invoice-fraud campaign
impersonating a supplier — malicious Office documents, PDFs, RTFs and the phishing emails that
carry them, droppers in every script language, shortcuts, installers, Java, OneNote, containers,
binaries and a set of files for the Machine Learning tab. Every indicator is inert (`*.example`,
RFC 5737 IPs, harmless stubs). See [`samples/README.md`](samples/README.md).

## 🧭 How you use it

1. **📥 Upload** — drop one or more files (and a **password**, if they are encrypted and you know it). Each original is copied, hashed and never modified; analyses are **queued** and run in the background, and the **Tasks** tab shows each one live, step by step.
2. **🔬 Identify** — the *real* file type is recognised from its content, and a mismatch with the extension is flagged (that `.doc` that is really RTF).
3. **🧩 Inspect** — **Components** has a tab per analysis: findings with their evidence (grouped by source, by file or as a list), IOCs grouped by type, the code found and deobfuscated, email headers and authentication, the recursive tree of everything inside the file, and each analysis's raw output.
4. **🌐 Check** — press **Check** on a URL, domain or IP: DocuTraceX visits it like a real victim would, through your proxy (see [Network checks](#-network-checks-and-opsec)).
5. **🧷 Hunt** — load your **YARA** rules; they run on every object of the case, and you can export the matches to CSV.
6. **🤖 Ask** — ask questions about the case to your AI provider or a local model, or connect an MCP client.
7. **🏷️ Triage** — mark each finding **TP / FP / Suspicious / Informational** with a comment; marks survive re-analysis.
8. **📝 Report** — a self-contained HTML report of the **confirmed** findings, ready to print to PDF or attach to a ticket.

## ✨ What's inside

| | |
|---|---|
| 🔍 **Type truth** | the real family of every file, recognised by its content, and extension/type **discrepancies** |
| 📝 **Office** | Word, Excel and PowerPoint, modern and legacy: metadata and author attribution, **macros** (extracted, decompiled — including stomped macros — and **emulated** to see what they would download, write and run), DDE and field codes, **hidden and very-hidden sheets**, **Excel 4.0 macros**, remote templates, exploit objects (Equation Editor, OLE links, Follina-style handlers…), embedded objects and suspicious add-ins |
| 📄 **PDF** | active content (JavaScript, launch actions, embedded files, forms that submit elsewhere), every object browsable, known exploit patterns, **digital signatures** and changes made after signing, **QR codes**, lure layouts and data hidden after the end |
| 📃 **RTF** | recognised whatever its extension: embedded objects extracted and analysed, exploit patterns, remote templates and fields, obfuscation and attribution data |
| ✉️ **Email** | `.eml`/`.emlx`/`.msg`: the delivery path with its anomalies, SPF/DKIM/DMARC and whether the body was **edited after signing**, sender **spoofing**, **look-alike domains**, links rewritten by security gateways decoded, HTML phishing (credential forms, **HTML smuggling**, tracking pixels), QR codes and every attachment analysed |
| 🔗 **Shortcuts** | `.lnk` and `.url`/`.website`: what they launch, hidden windows, remote targets and NTLM-theft tricks; the launched command goes through the scripting engine |
| 📓 **OneNote** | the files hidden behind "double-click to view" lures, extracted and analysed |
| ☕ **Java** | `.jar`/`.war`/`.ear`/`.class`/`.jsp`: entry points, dangerous behaviour (command execution, reflection, JNDI/Log4Shell, deserialization), **webshells** and signing; classes decompiled |
| 📦 **MSI** | custom actions (scripts, binaries, commands) and when they fire, embedded binaries and cabinets |
| 🧱 **Binaries** | Windows PE, ELF and Mach-O: **static triage** (anomalies, suspicious imports by behaviour, entropy, signatures, masquerading), **padding removed** so oversized binaries can be analysed, **packers detected and unpacked**, obfuscated strings recovered, capabilities mapped to **MITRE ATT&CK**, build artefacts such as PDB paths. Every unpacked or recovered binary is analysed as a child |
| 🐍 **Python** | scripts, `.pyc` and **PyInstaller** executables unpacked and decompiled when possible |
| 💿 **Containers** | ZIP/7z (password-protected too), tar/gz/bz2/xz, CAB and **ISO/IMG** images, extracted safely with limits against archive bombs |
| 🧪 **Scripting engine** | JavaScript, PowerShell, VBScript, batch and Python are **deobfuscated before analysis** — encodings, XOR and compression layers, string tricks and well-known obfuscators (obfuscator.io, JSFuck, Invoke-Obfuscation, DOSfuscation, PyArmor…) — then matched against a **behaviour catalogue** (execution, download, persistence, defence evasion, injection, credential access, C2…) with their **MITRE ATT&CK** techniques. JavaScript, VBScript and PowerShell also run in **isolated sandboxes** that record what they would do, the **obfuscation techniques** found are listed with their evidence, and the payloads they drop are recovered |
| 🔐 **Encrypted files** | password-protected Office, PDF and ZIP/7z are **unlocked and analysed** — with your password, a password the **carrying email gives** (many languages), or the usual defaults; nothing is brute-forced |
| 🪆 **Recursion** | everything inside a file — attachments, archive entries, embedded objects, unpacked binaries, **stages that scripts decrypt or decode** — is analysed **in turn** with its family's tools, many levels deep, each with the **recipe** that produced it. Any child can be **opened like a case** with its own tabs |
| 📡 **C2 / Beacons** | implant configurations pulled out of every object of the case — Cobalt Strike, Metasploit stagers and common RATs (Remcos, AsyncRAT, DcRAT, Quasar) — **statically**: C2 endpoints, URIs, user agent, mutexes, watermark… Its own tab; each configuration is a finding, its values land in the IOCs, and the ones you mark go into the report. Exportable to CSV |
| 🤖 **Machine Learning** | the **EMBER2024** static classifiers (Apache-2.0) score every PE, .NET, PDF, ELF and APK object against a threshold calibrated at a **1% false-positive rate**, with family / behaviour hints — each family explained (what kind of malware it is, generic AV names flagged, a warning when the model can't decide) — and **why**: the features that pushed the score, each said in plain words with the evidence from the file and a jump to it in the Hex tab. Its own tab next to YARA; a complementary indicator, **not a verdict**: results become findings only once you mark them. In the report and exportable to CSV |
| 🔢 **Hex** | a hex viewer for every file of the case, opened from any **Hex** button at the right offset: search (hex with wildcards, text, regex), entropy strip with a colour legend, file structures coloured, an inspector for the selected bytes, copy-as, **decode the selection** and **extract it as a new child** of the case |
| 🧷 **IOCs** | URLs, domains, IPs, emails, file paths, registry keys, named pipes, commands and hashes from the content of every analysis, with provenance — **filtered for noise**, so what you see comes from the sample, not from the tools. Grouped by type, searchable, with *Check all* |
| 🌐 **Network checks** | on demand, through your proxy: **URLs** visited like a real victim (desktop and mobile, to catch cloaking) with a fake identity — redirects, certificate, forms, impersonated brand, screenshot, safe preview, served files analysed, and fake credentials to see the next stage; **domains**: DNS, registration age, certificates and their website; **IPs**: owner, ASN, country, reverse DNS, Tor |
| 🛡️ **YARA** | your rules by upload or **server path**, run on **every object of the case**; a hit is not a finding until you mark it. Matches export to CSV |
| 🤖 **AI & MCP** | ask about the case through any OpenAI-compatible endpoint (your company's LiteLLM, a provider), a local model (Ollama, LM Studio…) or an MCP client (Claude Desktop, Claude Code) — always **read-only** |
| 🏷️ **Marks** | TP/FP/Suspicious/Informational + comment on any finding, manual marks on any IOC or item, free-text notes — **preserved across re-analysis** |
| 🧵 **Tasks** | the analysis queue with configurable concurrency, a **live log** of each step, history kept across restarts, and re-run of a single module |
| 📊 **Report** | one self-contained HTML report: confirmed findings with evidence, IOCs, the nested tree and the Machine Learning results |
| ⚙️ **Settings** | the proxy for network checks (or a free public proxy picked and rotated automatically) and the reference data the app keeps up to date |
| 🩺 **Diagnostics** | every dependency, tool, database and the proxy checked in one place — with a **Retry** button to reinstall whatever is missing |

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
| **Scripting files** | `.js` `.jse` `.mjs` `.vbs` `.vbe` `.wsf` `.wsc` `.sct` `.hta` `.html` `.htm` `.svg` `.mht` `.mhtml` `.ps1` `.psm1` `.psd1` `.bat` `.cmd` `.py` `.pyw` `.pyc` `.pyo` |
| **Shortcuts** | `.lnk` `.url` `.website` |
| **OneNote** | `.one` `.onepkg` |
| **Java** | `.jar` `.war` `.ear` `.class` `.jsp` `.jspx` `.jspf` |
| **Binaries** | `.msi` · `.exe` `.dll` `.scr` `.sys` `.ocx` `.cpl` `.com` · ELF / Mach-O (by content) |
| **Any other file** | no specific parser, but still a full case: basic record (type, size, hashes), **YARA**, marks, notes and the report |

Scripts found **inside** other files (a `.js` in a PDF, VBScript in an `.hta`, PowerShell behind a macro, a `.bat` in a ZIP, the command of a `.lnk`…) go through the same scripting engine — and so do the stages those scripts **decrypt**.

<!-- rev: MH22fELbKP -->

## 🌐 Network checks and OPSEC

Checking an indicator means contacting the attacker's infrastructure, so DocuTraceX is careful about it:

- **Nothing goes out unless you press Check.** Configure a proxy (HTTP, HTTPS, SOCKS4 or SOCKS5 — Tor works) in **Settings**, or press **Connect to free proxy** to use one from the [ProxyScrape free list](https://proxyscrape.com/free-proxy-list); without one you are asked once and, if you accept the risk, checks leave from your own IP. The installer and the updater never use it.
- **Looks like a victim's click**, so bot filters and cloaking kits serve the real page — and the desktop and mobile views are compared to detect cloaking.
- **Never the real victim.** The victim's address in the link and usernames are replaced by a random fake identity.
- **Free proxies are untrusted:** invalid TLS certificates are never accepted through them, and every check says it went through a free proxy. Kits often block public proxy IPs — if a page looks clean, rotate and re-check.
- **Nothing runs.** The page's scripts never run in a browser and nothing else is downloaded; screenshots and previews are rendered offline. The optional *live screenshot* is the only exception, still through the proxy and without JavaScript.
- **Forms only on request.** *Send fake credentials* posts the fake identity only when you press it.
- **IPs are never contacted:** their owner and network come from public registries and a local database.
- **Practise safely:** `python scripts/phish_lab.py` starts a local phishing-kit simulator; then open `lab/phish_lab.eml` from the samples archive and press **Check**.

IP data: *IP Geolocation by [DB-IP](https://db-ip.com)* (CC BY 4.0) and [iptoasn.com](https://iptoasn.com) (public domain), downloaded at install time. Domain TLDs are validated against the official [IANA list](https://data.iana.org/TLD/tlds-alpha-by-domain.txt).

<!-- k: bhd1Sl5iFX -->

## 🤖 AI and MCP

The **AI** tab has three options, all built on the same **read-only** tools over the cases
(case summary, findings with your marks, IOCs, any analysis result, network checks, search).
None can modify a case or touch the network.

- **AI (API)** — ask in natural language ("is this phishing? what would the macro do?") and the model answers with real data from the case. Any **OpenAI-compatible endpoint** works: your company's **LiteLLM** proxy or a provider's API.
- **AI (local)** — the same against an AI app on your machine (**Ollama**, **LM Studio**…), so the case data never leaves it. Use a model with function calling.
- **MCP** — an MCP server for **Claude Desktop**, **Claude Code** or any MCP client. The tab shows the exact configuration for your installation, ready to copy:

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
key is kept in your browser, not on the server.

## 📝 Notes

- **Nothing runs for real.** No macro, formula, PDF action, link, media or attachment is ever executed by Office, a browser or the OS. Emulation and sandboxes are isolated, in separate processes, with time limits.
- **Offline unless you ask.** Analysis never touches the network. Network access happens only for the one-time provisioning, the **network checks you launch**, and the **AI endpoint you configure** when you ask it something.
- **Your data lives in** `cases/` (evidence, results, marks, task history, reports), `yara/` (your rules), `config/` (settings) and `tools/` (the portable toolchain and reference data) — all git-ignored and preserved across updates.
- **Your Python is never a constraint:** `install.py` puts only a light web service on your Python and provisions a separate **portable** toolchain under `tools/` for the analysis, so no tool dependency ever touches your environment.
- **Slow machine?** Every analysis time limit is multiplied by `DOCUTRACEX_TIMEOUT_FACTOR` (default **5**): a slow tool is better than a lost analysis. Concurrency is set under the upload box or with `DOCUTRACEX_MAX_CONCURRENCY`.
- **Optional components** are provisioned when possible and skipped cleanly when absent; Diagnostics shows what is available. Tools, licences and configuration variables: [`docs/TOOLS.md`](docs/TOOLS.md).
- **Licences:** DocuTraceX is Apache-2.0 and ships no third-party GPL code. Some optional tools are GPL/LGPL: they are installed at provisioning time (or picked up from `tools/`) and run as separate processes, never distributed in this repository.

## 🧭 Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full design notes and the task breakdown.

## 📜 License

Licensed under the **Apache License 2.0** — free to use, modify and distribute
(including commercially); just keep the copyright and `NOTICE`, and state your
changes. See [`LICENSE`](LICENSE).

© 2026 Gregorio Moreno (**gmzpt**)
