# Tools, licences and configuration

DocuTraceX stands on the shoulders of many open-source projects. They are
installed into the portable toolchain under `tools/` by
`scripts/setup_portable_python.py` (or picked up from `tools/<tool>/`), never
into your own Python, and each one's raw output is kept next to its findings.
The **Diagnostics** tab shows which ones are available.

## Credits

| Area | Projects |
|---|---|
| Type identification | libmagic |
| Office / VBA | oletools (olevba, oleid, mraptor, msodde, oleobj, rtfobj), pcodedmp, pcode2code, ViperMonkey (on PyPy 2.7), msoffcrypto-tool, XLMMacroDeobfuscator, pyxlsb2, OfficeMalScanner / RTFScan |
| PDF | pikepdf, peepdf-3, pyHanko, pdfium, zxing-cpp |
| Email | extract-msg, dkimpy |
| Didier Stevens Suite | oledump (+ plugins), zipdump, pdfid, pdf-parser, emldump, rtfdump, decode-vbe |
| Shortcuts | LnkParse3 |
| Binaries | pefile, LIEF, debloat, FLOSS, capa, UPX, AutoIt-Ripper, innoextract, 7-Zip, nuitka-extractor, evbunpack, Detect It Easy |
| Python / Java | pycdc, CFR |
| Scripts | STPyV8 (JavaScript sandbox), webcrack (on a portable Node), box-ps (on portable PowerShell Core) |
| Containers | py7zr, pyzipper, pycdlib |
| Machine Learning | LightGBM, the EMBER2024 models and feature extractor (Apache-2.0) |
| Rules | YARA (yara-python) |
| Network checks | Playwright + Chromium, DB-IP (CC BY 4.0), iptoasn.com, the IANA TLD list, ProxyScrape |
| Web / AI | FastAPI, Uvicorn, Jinja2, the MCP Python SDK |

## Licences

DocuTraceX is Apache-2.0 and ships no GPL code. GPL/LGPL tools (pcodedmp,
peepdf-3, py7zr, box-ps and pycdc — GPL-3.0 —, UPX, 7-Zip) are installed into
the portable at provisioning time or picked up from `tools/`, and invoked as
separate processes, never shipped in this repository. PowerShell Core, Node and
webcrack are MIT. webcrack pulls `isolated-vm`, which builds from source, so it
needs Node build tools on the host; if the build fails, webcrack stays disabled
and the pure-Python JavaScript cascade is the fallback. `python run.py`
provisions webcrack and box-ps on start when they are missing, but only once —
re-run `scripts/setup_portable_python.py` to retry.

## Optional components

FLOSS, capa, pycdc, CFR (needs a JVM), webcrack, box-ps, the PE unpackers and
the Machine Learning family model (459 MB, `DOCUTRACEX_EMBER_FAMILY=1` at
install or the button in the Machine Learning tab) are optional: provisioned
when possible, skipped cleanly when absent.

## Configuration variables

| Variable | What it sets |
|---|---|
| `DOCUTRACEX_HOST`, `DOCUTRACEX_PORT` | where the web service listens (default `127.0.0.1:8000`) |
| `DOCUTRACEX_CASES_DIR`, `DOCUTRACEX_YARA_DIR`, `DOCUTRACEX_CONFIG_DIR` | where cases, YARA rules and settings live |
| `DOCUTRACEX_MAX_CONCURRENCY` | analyses run at once (1–8) |
| `DOCUTRACEX_TIMEOUT_FACTOR` | multiplier for every analysis time limit (default 5) |
| `DOCUTRACEX_LOG_LEVEL` | log level (default `INFO`) |
| `DOCUTRACEX_SKIP_SETUP` | `1` skips the start-up provisioning checks |
| `DOCUTRACEX_PYTHON`, `DOCUTRACEX_PYPY`, `DOCUTRACEX_NODE`, `DOCUTRACEX_PWSH`, `DOCUTRACEX_JAVA`, `DOCUTRACEX_CHROMIUM` | explicit interpreters / runtimes |
| `DOCUTRACEX_FLOSS`, `DOCUTRACEX_CAPA`, `DOCUTRACEX_PYCDC`, `DOCUTRACEX_CFR`, `DOCUTRACEX_WEBCRACK`, `DOCUTRACEX_BOXPS` | existing binaries / installs of those tools |
| `DOCUTRACEX_UPX`, `DOCUTRACEX_INNOEXTRACT`, `DOCUTRACEX_7Z`, `DOCUTRACEX_NUITKA_EXTRACTOR`, `DOCUTRACEX_DIEC` | the PE unpackers |
| `DOCUTRACEX_FLOSS_TIMEOUT`, `DOCUTRACEX_CAPA_TIMEOUT`, `DOCUTRACEX_UNPACK_TIMEOUT` | per-tool time limits (before the factor) |
| `DOCUTRACEX_CA_BUNDLE` | extra CA bundle for network checks behind a TLS-inspecting proxy |
| `DOCUTRACEX_EMBER_FAMILY` | `1` downloads the optional ML family model at install |
