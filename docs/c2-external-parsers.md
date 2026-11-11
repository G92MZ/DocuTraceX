# C2 extractors — dependency policy and third-party parsers

## Dependency policy (decided)

Every C2 extractor dependency is **optional, with a warning** (`docutracex/c2/registry.py` → `REQUIRES`).

- **Missing required dependency.** Only that extractor is switched off. Its status is `missing_dependency`, and the reason appears in the C2 tab → *Extractors* and in the run's warnings.
- **Missing optional dependency.** The extractor still works, with less. Its run is marked `degraded`; for example, Cobalt Strike without `1768.py` or `dissect.cobaltstrike` falls back to the built-in parser.
- **Always.** The case, the other extractors and the app keep running.
- **Diagnostics → C2 extractors** lists what is missing and how to get it.

| Extractor | Required | Optional |
|---|---|---|
| Cobalt Strike | — | `dissect.cobaltstrike`, `1768.py` (built-in fallback) |
| Remcos | `pefile` | — |
| AsyncRAT / DcRAT / QuasarRAT | `pefile`, `cryptography` | `rat-king-parser` (second engine) |
| Metasploit / Meterpreter | — | — |
| njRAT / XWorm / NanoCore / RedLine / Snake / DarkGate… | `cryptography` | — |
| AgentTesla-style stealers | — | `pefile`, `cryptography` |
| Go implants | — | the Go module's results |
| RMM / remote-access tools | — | the LOLRMM catalogue (downloaded; built-in list without it) |

## Licence review of third-party parser collections

Reviewed on 2026-11-11 against each project's current default branch and the PyPI metadata of its dependencies.

The project rule: only permissive code goes into the repo. GPL tools are downloaded at provisioning, run in a separate process and are never committed.

### CAPE-parsers (CAPESandbox/CAPE-parsers)

- **Licence:** the repository is **MIT**, but it is **mixed**. 16 parsers carry their own **GPL-3.0** header:
  - AxolotLoader, Azorult, BitPaymer, BlackDropper, DoppelPaymer, DridexLoader, IcedID, IcedIDLoader, Latrodectus, NitroBunnyDownloader, Oyster, PlugX, SquirrelWaffle, WarzoneRAT, Zloader (core);
  - Carbanak (community);
  - the files in `deprecated/`.
- **Bundled code:** a copy of `malduck`, which is **GPL-3.0** on PyPI.
- **Dependencies:** `maco` (MIT), `rat-king-parser` (MIT), `pefile`, `pycryptodomex`, `yara-python`, `yara-x`, `dnfile`, `dncil`, `capstone`, and `unicorn` (GPL-2.0).
- **Fit:** most parsers expect what the CAPE sandbox produces (unpacked payloads, process dumps), not the files a static case holds.
- **Decision:** do not vendor it as a whole.
  - The MIT parsers may be **adapted one by one, with attribution** in `NOTICE`, when a family is worked on (for example DarkGate, Formbook, QakBot, Rhadamanthys, SmokeLoader, PikaBot, BumbleBee, BruteRatel, HijackLoader, GuLoader, Remcos, RedLine).
  - The GPL ones may only run **as a separate process** from a package installed at provisioning.

### RATDecoders (kevthehermit/RATDecoders)

- **Licence:** **MIT**.
- **State:** **unmaintained** (last commit 2021).
- **Dependencies:** `pycrypto` (abandoned, does not build on current Python), `androguard`, `javaobj-py3`, `pbkdf2`.
- **Decision:** do not integrate. Its .NET RAT coverage is better served by `rat-king-parser`.

### DC3-MWCP (dod-cyber-crime-center/DC3-MWCP)

- **Licence:** **MIT**. It is a US Government work and also MIT-licensed for third-party code.
- **What it is:** a parser **framework** with few parsers of its own.
- **Dependencies:** heavy (`pandas`, `lief`, `malstruct`, `dynaconf`, pytest plugins…).
- **Decision:** do not add it as a dependency. Our contract (`c2/normalize.py`) already covers its report model. Its field names can inform `normalize` when useful.

### rat-king-parser (jeFF0Falltrades) — integrated

- **Licence:** **MIT**. Actively maintained.
- **Coverage:** AsyncRAT, DcRAT, QuasarRAT, VenomRAT and other .NET RATs.
- **Dependencies:** `dnfile`, `pycryptodomex`, `yara-python`.
- **Integrated** as the **optional second engine** of the .NET RAT extractor (`docutracex/c2/ratking.py`), in the same way `dissect.cobaltstrike` sits next to `1768.py`: a child process with a timeout, one sub-tab per engine, hosts compared (*agree / partial / differ*). `DOCUTRACEX_RATKING=0` disables it. It needs the real `.cctor` of the settings class, so the inert samples only show its *nothing found* view; validating it is part of the real-sample phase.

### LOLRMM (magicsword-io) — integrated as a feed

- **Licence:** **Apache-2.0** (data and code).
- **What it is:** the community catalogue of RMM and remote-access tools (~360): names, PE metadata, installation paths, network domains, code-signing signers.
- **Integration:** `docutracex/lolrmm.py` downloads `rmm_tools.json` (lolrmm.io, falling back to its GitHub copy) into `tools/lolrmm/` on install and every 7 days in the background; Settings → C2 has *Refresh now*. Only the catalogue is downloaded: nothing about a sample is sent. The C2 `rmm` extractor matches its file names, descriptions, signers and domains as whole strings of the file; generic installer names, cloud domains and shared signers are dropped, and a vendor's domain alone never names a product. Without the file the built-in list (~20 products, with the instance parsers) is used.
- **Also in the IOCs and the text** (`docutracex/rmmintel.py`): domain / URL / file-path IOCs of a product get an *RMM: <product>* badge (context only, never raised), and a product's *name* in the text of a document, email or script is a finding `rmm:mention` — *info* alone, *low* next to install / run / ID / password words, *medium* next to its installer — one per product, skipped when the C2 extractor already found it bound to an instance. Names that are ordinary words (Level, Remote PC, Remotely…) and names shorter than 6 characters without a second word are never matched.
