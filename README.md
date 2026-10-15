<div align="center">

# 📄🔎 DocuTraceX

**Static forensic analysis for Microsoft Office, PDF and email — without opening the file.**

Drop in a suspicious `.docx`, `.xlsm`, `.doc`, `.xls`, `.pdf`, `.eml` or `.msg`,
open the browser, and investigate: the real file type vs. what it claims to be,
macros and DDE, hidden/very-hidden Excel sheets, PDF JavaScript and launch
actions, email spoofing and the `Received` chain, embedded payloads **pulled
apart recursively**, IOCs, your own **YARA** rules, triage marks and a one-click
report. **Nothing in the sample is ever executed.**

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-local-009688)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Offline](https://img.shields.io/badge/runs-100%25%20offline-success)

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

> 🧪 **Try it now:** benign booby-trapped samples ship in `samples/` — a `.docm`
> with DDEAUTO, an `.xlsm` with a very-hidden sheet + `WEBSERVICE`, a `.pdf` that
> auto-runs JavaScript and carries an embedded macro doc, and `.eml`/`.msg`
> phishing with a `report.docm` attachment. Upload one and look around.

The web app runs on **your** Python; the analysis tools run on a **portable**
Python under `tools/`, provisioned automatically on first launch (see
`scripts/setup_portable_python.py`). On Windows, point it at your FLARE-VM and
it just works.

## 🧭 How you use it

1. **📥 Upload** — drop a file. The original is copied, hashed and never modified; the analysis is **queued** (one per instance) and runs in the background.
2. **🔬 Identify** — libmagic + structural recognizers decide the *real* family and flag extension/type **discrepancies** (that `.pdf` that is really an OLE container).
3. **🧩 Inspect** — the **Components** view: a tab per analysis — Findings (with the exact **evidence** that triggered each one and a ↗ pivot to where it lives), IOCs, the semantic content, external-tool output, the recursive **Nested** tree, and more.
4. **🧷 Hunt** — load your **YARA** rules (upload or a server path) and match them over the file and everything extracted from it.
5. **🏷️ Triage** — mark each finding **TP / FP / Suspicious / Informational** with a comment; marks survive re-analysis.
6. **📝 Report** — a self-contained HTML report of the **confirmed (True positive)** findings, ready to print to PDF or attach to a ticket.

## ✨ What's inside

| | |
|---|---|
| 🔍 **Type truth** | libmagic + structural recognizers (OPC/OOXML, EMLX, CFB, RTF) → family and extension/type **discrepancy** |
| 📝 **Office (OOXML)** | Word/Excel/PowerPoint: metadata, VBA, DDE & field codes, `WEBSERVICE`/`FILTERXML`, **hidden/very-hidden sheets** (and an **unhidden copy** as evidence), external links |
| 🗂️ **Office (OLE/BIFF)** | legacy `.doc`/`.xls`/`.ppt`: CFB structure, SummaryInformation, VBA, and **Excel 4.0 (XLM)** macros in hidden BIFF sheets |
| 📄 **PDF** | robust raw-token scan (`/OpenAction`, `/JS`, `/Launch`, `/EmbeddedFile`, `/XFA`, `/URI`, hex-obfuscated names…), **extracted JavaScript**, every object browsable, embedded-file extraction, text & URIs |
| 📃 **RTF** | recognised by content (a `.doc` that is really RTF too): `\objdata` objects via rtfobj (Equation Editor, OLE2Link + `\objupdate`, Package, ActiveX/MSCOMCTL) extracted and scanned recursively, remote `\*\template` and fields, font-table overflow, pFragments, deep nesting, `\objdata` obfuscation, data after the end, `\info`/generator/rsid attribution, rtfdump · RTFScan |
| ✉️ **Email** | `.eml`/`.emlx`/`.msg`: the **`Received` hop chain** with Δt, SPF/DKIM/DMARC, From/Return-Path/Reply-To & display-name **spoofing**, attachments hashed & typed |
| 🧰 **Real tools** | oletools (olevba · oleid · mraptor · msodde · oleobj · rtfobj), pcodedmp · pcode2code, msoffcrypto-tool, XLMMacroDeobfuscator, pyxlsb2, peepdf · pyHanko · pdfium + zxing-cpp (QR), dkimpy, OfficeMalScanner/RTFScan, Didier Stevens Suite (oledump + plugins/zipdump/pdfid/pdf-parser/emldump/rtfdump/decode-vbe) — each tool's raw output kept next to its findings |
| 🐒 **VBA emulation** | ViperMonkey on a second portable interpreter (PyPy 2.7), isolated and time-limited: what the macro would download, write and run |
| 🟨 **JavaScript** | collected from PDFs, email HTML, HTML/HTA/SVG/WSF/JS/JSE attachments and JScript inside VBA; static patterns, string decoding and an isolated **STPyV8 sandbox** with recording stubs that unfolds `eval`/`Function` layers |
| 🧩 **Own rules** | remote templates, Follina/MSHTML handlers, Equation Editor, OLE2Link, Package, ActiveX, XLM macro sheets, hidden VBA modules / locked projects, PDF revisions and signatures, look-alike domains, gateway-wrapped links, DKIM body hash, HTML smuggling… |
| 🪆 **Recursion** | attachments, embedded OLE objects and PDF-embedded files are analyzed **in turn** with their family's tools — the DDE inside a `.docm` inside a `.pdf` surfaces with its full path |
| 🛡️ **YARA** | your rules by upload (`.yar`/`.yara`/`.zip`/`.tar.gz`) or **server path**, compiled with streaming progress; matches shown as cards — **opt-in**: a rule becomes a finding only when you tick it |
| 🧷 **IOC extractor** | URLs, domains, IPv4/IPv6 and hash-like strings across every parser's output, with provenance |
| 🏷️ **Marks** | per-finding TP/FP/Suspicious/Informational + comment, kept separate from the evidence and **preserved across re-analysis** (stable finding IDs) |
| 🧵 **Tasks** | a sequential queue with per-file **sub-step log** — every tool that ran, its status, timing and findings — plus isolated **re-run** of a single module |
| 📊 **Report** | one self-contained HTML report of the confirmed findings, with evidence, IOCs and the nested tree |
| 🩺 **Diagnostics** | app vs. tool interpreter, every dependency and external tool checked in one place |

## 📦 Supported formats

| Family | Extensions |
|---|---|
| **Word** | `.doc` `.dot` `.docx` `.docm` `.dotx` `.dotm` |
| **Excel** | `.xls` `.xlt` `.xla` `.xlsx` `.xlsm` `.xltx` `.xltm` `.xlam` `.xlsb` |
| **PowerPoint** | `.ppt` `.pot` `.pptx` `.pptm` `.potx` `.potm` `.ppsx` `.ppsm` `.ppam` `.sldx` `.sldm` |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.emlx` `.msg` |
| **RTF** | `.rtf` (and any extension whose content is RTF) |

## 📝 Notes

- **Nothing runs for real.** No macro, formula, PDF action, link, media or attachment is ever executed by Office, a browser or the OS. The only exceptions are *emulation*: ViperMonkey (a VBA interpreter written in Python) and the STPyV8 sandbox (a bare V8 with no file system, network or processes, only recording stubs) — both in a separate process with a time limit.
- **Runs offline.** The only network access is the one-time provisioning of the portable Python and external tools (from PyPI and GitHub) on first launch.
- **Your data lives in** `cases/` (per-case evidence, results, marks, report), `yara/` (your rules) and `tools/` (the portable runtime) — all git-ignored and preserved across updates.
- **Two interpreters by design:** the web app on your Python, the analysis tools on the portable one, so a messy tool dependency never touches your environment.

## 🔄 Updating

Grab the latest version without git — the updater checks GitHub and updates the
app in place, **keeping your cases, rules and tools** (`cases/`, `yara/`, `tools/`):

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
