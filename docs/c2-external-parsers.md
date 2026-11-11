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
| AsyncRAT / DcRAT / QuasarRAT | `pefile`, `cryptography` | — |
| Metasploit / Meterpreter | — | — |
| njRAT / XWorm / NanoCore / RedLine / Snake / DarkGate… | `cryptography` | — |
| AgentTesla-style stealers | — | `pefile`, `cryptography` |
| Go implants | — | the Go module's results |

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

### rat-king-parser (jeFF0Falltrades) — candidate

- **Licence:** **MIT**. Actively maintained.
- **Coverage:** AsyncRAT, DcRAT, QuasarRAT, VenomRAT and other .NET RATs.
- **Dependencies:** `dnfile`, `pycryptodomex`, `yara-python`.
- **Recommendation:** add it as an **optional second engine** for the .NET RAT extractor, in the same way `dissect.cobaltstrike` sits next to `1768.py`. This would be a separate task, validated with real samples.
