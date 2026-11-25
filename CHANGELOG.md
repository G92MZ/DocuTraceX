# Changelog

What changed in each version of DocuTraceX, newest first. After an update, the app shows
the entries between the version you had and the new one.

## 1.253.0 — 2026-11-25 (#333)

**JavaScript, VBScript and batch evaluated statically to what they drop**

- JScript / page scripts, VBScript and `.bat` droppers are followed without running them: `eval` / `Execute` layers, `this['ev'+'al']`, `Chr` / `StrReverse` / `%var:~n,1%` tricks, MSXML `bin.base64`, `ADODB.Stream`, CryptoJS, pako, `certutil -decode` of the script itself, XOR loops.
- Files they would write (an `.exe`, a `.vbs`, a `.ps1`) go to **Nested** with their recipe; the commands they chain are followed (`powershell -enc`, `echo … | powershell -`, `mshta`, `wscript x.vbs`, `certutil`, `bitsadmin`).
- Each script card shows its Resolution; downloads and calls that depend on the victim's machine (registry, environment) are reported with why.

## 1.252.0 — 2026-11-25 (#332)

**Python scripts evaluated statically to the binary they hide**

- Python droppers are followed without running them: exec layers, `getattr(__builtins__, 'ex'+'ec')`, base64 / zlib / lzma / marshal, AES and Fernet, XOR loops, down to what they run or load with `ctypes`.
- Hidden binaries go to **Nested** with their recipe; the Resolution tab shows Python scripts too.
- Downloads (`urllib`, `requests`) are reported, and calls that depend on the victim's machine are flagged with why.

## 1.251.0 — 2026-11-25 (#331)

**Resolution tab: how each hidden stage was reached**

- New **Resolution** tab: every script evaluated statically, with what it runs, loads or writes, each stage's recipe step by step (`here-string $P → base64 → aes-256-cbc(key $K, iv $V) → gzip`), its downloads, the calls that could not be resolved and the full trace.
- Each script card (PowerShell…) shows its own Resolution block; computed command names say how they were written (`Invoke-Expression (called as & ("Inv"+"oke-Ex"+"pression"))`).
- The Markdown report has a **Resolution** section with the same.

## 1.250.0 — 2026-11-25 (#330)

**PowerShell resolved statically, to the binaries it hides**

- PowerShell scripts are now **evaluated statically** (never run): variables, here-strings, the script's own functions, loops and .NET calls (base64, AES, GZip, MemoryStream, Assembly.Load…) are followed to what the script runs, loads or writes — each stage in Nested with its recipe, a second layer's binaries under it.
- Commands with computed names are resolved (`"Inv"+"oke-Expression"`, `$env:ComSpec[4,15,25]`, `gcm I*e-E*n`, aliases, backticks…).
- New findings: **downloads** (URL, method and what the script would do with it — to fetch it yourself) and **dynamic calls not resolved** (they depend on the victim's machine, with why), plus reflective loaders, watch loops and multi-layer loaders with integrity checks.

## 1.249.0 — 2026-11-25 (#329)

**Scripts in a .txt read by the right engine**

- A script with an extension that says nothing (`.txt`, `.dat`, none) is now recognised **by its content** — PowerShell, JavaScript, VBScript, batch, Python, Perl, PHP, Ruby, Lua, Tcl, shell, AutoIt, AutoHotkey — also inside archives and other files, and only that language's engine reads it: no VBScript or batch findings on PowerShell code.
- Scripts up to 64 MB are analysed whole (was 2 MB), and stages are named after the engine that found them.
- Fixed: a word inside a base64 blob ("vbox") no longer raises VM-detection findings, and a long Python preview no longer carves "ghost" PEs out of a cut array.

## 1.248.0 — 2026-11-25 (#328)

**Markdown report: the whole analysis, every tool's output in full**

- The Markdown export now has every tool's **complete** output (also of each nested child), with command, exit code and stderr: an agent can point at what a tool showed and no rule caught.
- New sections: **Email** (every header verbatim, bodies whole, also of attached messages), **FLOSS** (decoded, stack and tight strings, plus the static ones worth reading), **Complete content** (document, PDF and RTF text, every PDF object, a page's text), **Code files**, and the C2 extractors' raw output.
- **Download with every output (.zip)**: the report plus each complete output as its own file, FLOSS's every string included.
- Nothing capped any more in the results either: every capa capability, PE import / export, .NET string and type, script of a file, attachment and header of an email.

## 1.247.0 — 2026-11-25 (#327)

**Nested: every child analysed in depth, however many and however deep**

- No more *listed · not analysed in depth*: every file inside a case is analysed — an installer with hundreds of files, a PE's resources, ten or fifteen archives one inside another.
- Archives are bounded by size only (500 MB in all, 100 MB per file), not by how many files they hold.
- A file that contains itself is shown once and not opened again.
- For a slow machine, the old caps can still be set (`DOCUTRACEX_NESTED_MAX_CHILDREN`, `DOCUTRACEX_NESTED_MAX_NODES`, `DOCUTRACEX_ARCHIVE_MAX_ENTRIES`).

## 1.246.1 — 2026-11-25 (#326)

**Nested: every file opens, in the tree too**

- Every file in **Nested** now has **Open analysis ↗**, even one with nothing to show but the file itself (listed only, plain text, an opaque blob): its **File** tab gives type, size, hash, folder and Hex.
- The tree's details panel (and the Findings "By file" view) now have **📁 Folder**, **↓** and **Hex**, as the list does; folded groups (*listed only*, *clean files*) open each member too.

## 1.246.0 — 2026-11-21 (#325)

**ELF: capa and their strings**

- ELF binaries now get **capa** too (capabilities with ATT&CK), as Windows binaries do — in the background when they are large. An ELF that does not say which OS it is for is analysed as Linux.
- ELF and Mach-O binaries get a **Strings** tab, and their IOCs come from those strings even when the code analysis is not available (before, a Linux binary could end up with no IOCs at all).

## 1.245.0 — 2026-11-20 (#324)

**Rust on Linux too**

- Rust ELF binaries (Linux ransomware, bots…) get the same **Rust** tab: compiler, crates and what they are for, build machine user and project.
- A new finding flags crates for **encryption plus walking the file system**, the shape of a locker, on Windows and Linux alike.

## 1.244.0 — 2026-11-20 (#323)

**Rust binaries: compiler, crates and the build machine**

- A new **Rust** tab in the Binary view: the compiler version, every crate with its version and what it says the binary does (HTTP client, encryption, string obfuscation, reconnaissance, screen or keyboard capture…), git dependencies, and the project's own source paths.
- The **user of the build machine** and the **project name** come out of those paths — useful to relate samples built on the same machine.
- Findings for a Rust binary, for risky crates (obfuscation, capture, injection, browser data, chat C2) and for HTTP + encryption together.

## 1.243.0 — 2026-11-20 (#322)

**Rust binaries: their strings split apart again, and used**

- Rust keeps its strings back to back with no separator. FLOSS splits them apart, but that part needs a module that cannot be installed on Windows; DocuTraceX now ships the same algorithm in Python, so it works again.
- The split strings now reach the Binary tab, Code and IOCs (before, they were left out even with the old floss.exe), and the blob they form is no longer mined — a C2 URL comes out whole, not run into the next string.
- The FLOSS tab says when the binary is Rust (and its compiler version).

## 1.242.3 — 2026-11-20 (#321)

**Fix: tool bookkeeping no longer shows up as IOCs**

- The C2 tab's family-YARA rule sources (the CAPE and ditekSHen GitHub URLs) are no longer listed as IOCs.
- A PDF's trailer `/ID` and the PDF's own MD5 / SHA-1 / SHA-256 reported by peepdf are no longer hash IOCs; nor are the hashes of any file found inside the case (a PDF in a ZIP in the email). Real hashes and URLs in the same documents are still extracted.

## 1.242.2 — 2026-11-20 (#320)

**Fix: FLOSS on Windows no longer fails at the very end**

- On Windows, FLOSS could finish its work and then fail while cleaning up a temporary copy of the binary (still open), losing all its strings. The cleanup can no longer fail a finished run; leftovers are removed later.
- If the fast FLOSS run fails anyway, the complete analysis now takes its place in the Binary tab instead of only adding to it.

## 1.242.1 — 2026-11-20 (#319)

**Tasks: a queued background job says so in its step too**

- A FLOSS / capa job waiting for its turn now shows *queued* in its step as well (not *running*), with *waiting — …* and the time it has been waiting.

## 1.242.0 — 2026-11-20 (#318)

**Large binaries: FLOSS and capa results in minutes, completed in the background**

- On a large binary, FLOSS and capa first run on a **fast analysis** (about 10× faster: 3 minutes instead of 34 on a 6 MB 64-bit binary), so their strings and capabilities arrive much sooner.
- The **complete analysis** then runs in the background (Tasks) and **adds** whatever the fast one missed — strings and capabilities are merged, nothing is replaced. The Binary tab says which results you are looking at.
- `DOCUTRACEX_VIVISECT_FAST=0` turns it off (complete analysis only).

## 1.241.0 — 2026-11-20 (#317)

**FLOSS keeps what it found when it runs out of time, and shows its progress**

- If FLOSS hits its time limit, the strings it had already found (static, stack, decoded so far) are kept: they reach the Binary tab, Code → Strings, IOCs and Findings, marked **PARTIAL**. Before, a timeout lost everything. A partial run is not cached, so a re-analysis runs FLOSS again.
- Tasks and Deep FLOSS show what FLOSS and capa are doing: the phase and how many functions are done (e.g. *stack strings 1200/4800*, *matching rules*).

## 1.240.0 — 2026-11-20 (#316)

**FLOSS and capa as Python libraries: one analysis per binary, shared**

- FLOSS and capa no longer run as the standalone floss.exe / capa.exe: they are installed as Mandiant's Python libraries (same versions, same results) in the app's Python, and the old executables are removed.
- The analysis of a binary they both start with is saved and reused: capa after FLOSS, FLOSS tight, Deep FLOSS and re-analyses of the same binary load it instead of analysing it again — much faster on large binaries.
- After updating, the next start installs them (or press **Retry** for FLOSS / capa in the status page).

## 1.239.4 — 2026-11-20 (#315)

**Fix: FLOSS and capa no longer exhaust the RAM**

- FLOSS and capa use a lot of memory on large binaries. Their background runs (and Deep FLOSS) now go **one at a time**: the others show as *queued* in Tasks and start on their own; they can be cancelled while waiting.
- `DOCUTRACEX_HEAVY_JOBS` sets how many run at once (default 1).

## 1.239.3 — 2026-11-20 (#314)

**Fix: the app no longer stops answering on Windows after a dropped connection**

- On Windows, a browser or another computer dropping its connection at the wrong moment (`WinError 64`) could make the app stop answering until restarted. It now uses a different Windows network loop that doesn't have this problem.

## 1.239.2 — 2026-11-20 (#313)

**Tasks filter by state; background jobs cut by a restart show as interrupted**

- If the app restarts (an update, closing it) while FLOSS or capa runs in the background, the case no longer shows them as *running* forever: they show as *interrupted*, with a hint to re-run the analysis.
- Tasks: filter by state (queued, running, completed, failed…). Pick one or several; *All* shows everything, and your choice is remembered.

## 1.239.1 — 2026-11-19 (#312)

**Fix: background FLOSS and capa actually finish**

- With the portable Python (the usual install), the background FLOSS / capa of a large binary were lost when the analysis ended: they never finished and did not show in Tasks. They now run in the app itself, so they show in Tasks and their results reach the case.
- The same applies to the FLOSS tight strings on the code analysis' priority functions.
- In the Cases list, a finished case whose FLOSS or capa is still running shows *+ N in background* next to *completed*.

## 1.239.0 — 2026-11-19 (#311)

**capa of a large binary also runs in the background**

- On a large binary capa no longer holds the case: it runs as a background task (Tasks, with its time and Cancel) next to FLOSS.
- When it ends its capabilities and ATT&CK techniques are added to the Binary tab and to Findings; a cached result still runs inline.
- When it ends, Code → Capabilities is compared with capa again (capa column, *Only in capa*), and code findings that capa already covers are removed, so the same technique doesn't show up twice.

## 1.238.3 — 2026-11-19 (#310)

**Fix: background FLOSS starts before capa, not after**

- On a large binary the background FLOSS task was only started once capa had finished; it now starts first, so both run at the same time.

## 1.238.2 — 2026-11-19 (#309)

**Fix: evbunpack installs again (it left PyPI)**

- evbunpack (Enigma Virtual Box unpacker) is no longer on PyPI, so a fresh install reported it missing. The installer now falls back to its pinned source on GitHub (0.2.6); Diagnostics → Retry installs it.

## 1.238.1 — 2026-11-19 (#308)

**Tasks: "completed + N in background"**

- An analysis whose case still has background work (FLOSS of a large binary) shows *completed* plus a "+ 1 in background" badge and which task it is; the background job says which analysis started it, and the header counts them.
- The PE triage's per-tool rows say "5 tool(s)", not "5 object(s)".

## 1.238.0 — 2026-11-19 (#307)

**Code step: what it is doing, live; FLOSS tight on priority functions in the background**

- While native code is analysed, the task says the phase and its time: "code · a.exe · Rizin analysis · 4m 10s", "decompiling 40/120", "FLOSS tight strings on 120 priority function(s)".
- On the case's own large binary (> 2 MB), FLOSS tight strings on the priority functions run as a background task too: the case does not wait; they reach Code → Strings and the IOCs when it ends.

## 1.237.0 — 2026-11-19 (#306)

**FLOSS of a large binary in the background: the case does not wait for it**

- Above 2 MB, the case's own binary gets FLOSS as a background task: the analysis finishes with everything else and C2, YARA or ML can run meanwhile.
- The task shows in Tasks with how long it has been running and Cancel; the Binary tab says FLOSS is still running.
- When it ends, its strings are added to the Binary tab and to Code → Strings, and the IOCs and findings are recomputed — no re-analysis, marks kept.

## 1.236.2 — 2026-11-19 (#305)

**Tasks: which of FLOSS and capa is still running**

- While a binary's FLOSS and capa run, the task says which one has finished and which is still going: "capa running · 23m 42s (FLOSS done in 8m 10s)".

## 1.236.1 — 2026-11-19 (#304)

**Deep FLOSS: what it recovers reaches the IOCs at once**

- The strings Deep FLOSS recovers (tight strings) are added to the case's IOCs and findings when it ends, with the function they come from — no re-analysis needed.

## 1.236.0 — 2026-11-19 (#303)

**FLOSS without tight strings by default; Deep FLOSS with no time limit**

- The automatic FLOSS run skips *tight strings* on every file (they emulate every tight loop: minutes to hours on large binaries); decoded, stack and static strings stay, and the code analysis still runs tight strings on its priority functions.
- **Deep FLOSS…** in the Code view runs them on every function in the background with **no time limit**; it shows how long it has been running and can be cancelled.
- The Binary tab's FLOSS pane says when tight strings were skipped and where to run them.

## 1.235.0 — 2026-11-19 (#302)

**Tasks: what the PE triage is doing, tool by tool**

- While a binary is triaged, the task shows the tool running now and, for FLOSS and capa, for how long ("FLOSS + capa running · 3m 05s").
- Afterwards the step lists each tool as a sub-step with its time and status: LIEF, debloat, packer detection / unpacking, FLOSS, capa (timeout, cached, skipped and why).

## 1.234.0 — 2026-11-19 (#301)

**MCP: everything, never cut — and C2, YARA and raw-record tools**

- Over MCP no answer is clipped or capped any more: long ones come in pages (`offset` / `next_offset`); `get_module` gives any module's whole raw JSON in slices.
- New tools: `get_c2` (every configuration with all its fields, YARA names, provenance, marks, extractor status), `get_c2_raw` (each extractor's raw output per object), `get_yara` (hits, matched strings, rule source, marks), `list_yara_rules` and `list_modules`.
- The nested tree over MCP lists every node (path and depth), however deep.

## 1.233.0 — 2026-11-19 (#300)

**C2: the malware family named by CAPE and ditekSHen YARA rules; clear YARA rules from Settings**

- The C2 analysis runs the CAPE and ditekSHen family rules on every object (downloaded and refreshed weekly; *Refresh now* in the C2 view). A family no extractor reads (Formbook, GuLoader, Latrodectus…) is named; one an extractor reads gets the rule names as corroboration.
- Settings → YARA rules → **Clear…**: drop the compiled rules, or everything (uploads, registered folders, enabled marks — nothing on disk is deleted).

## 1.232.2 — 2026-11-19 (#299)

**A binary named like a script: its recovered code one click away**

- A compiled AutoIt blob called `.au3` (or any binary named like source code): the **File** tab now says so and what was carved out of it, with offset and size.
- The script recovered from it gets a direct tab (*AutoIt · script.au3*) with its decompiled code, decrypted strings and findings — before, it was only reachable three levels down in Nested.
- A re-analysis drops results an older version left behind (an `.au3` once painted as AutoIt code), so the export and the AI tools show only the current ones.

## 1.232.1 — 2026-11-19 (#298)

**Fix: the hidden-payload sweep no longer gives up on short trailing data**

- A stream shorter than a file signature (seen after an Inno Setup part) made the whole sweep stop with "index out of range", so files hidden in the case's other images and resources were not looked for. It is now skipped.

## 1.232.0 — 2026-11-19 (#297)

**DLL side-loading with the HijackLibs catalogue, kept up to date**

- The list of side-loadable DLLs is now [HijackLibs](https://hijacklibs.net) (~600 Windows and vendor DLLs), downloaded and refreshed weekly in the background; offline, the built-in list of ~100 names is used.
- Findings say where the DLL is expected and whether the program next to it is a *known host*; vendor DLLs (`libcurl.dll` next to its updater) are caught when the pair does not hold together.
- Runtimes apps ship next to themselves (`vcruntime140.dll`…) stay quiet unless the signatures do not match.
- The "What's new" panel shows *italics* properly.

## 1.231.0 — 2026-11-19 (#296)

**Check for updates now from the header**

- The version in the header is always clickable: "up to date · last checked HH:MM" and a **Check now** button that asks GitHub at once (it works even with the automatic check off).
- If a newer version turns up, the chip lights up and its changes and the **Update** button show straight away.

## 1.230.0 — 2026-11-19 (#295)

**DLL side-loading: a signed program next to a DLL with a system library's name**

- Archives and disk images: `version.dll`, `winhttp.dll`, `dbghelp.dll`… next to a program that imports it is *dll_sideloading* — high when the program is signed and the DLL is not, the DLL has another signer, or it is a proxy forwarding its exports to the real library.
- Installers: the same pair installed in one folder is *msi_dll_sideloading* (high when the installer runs the program).
- A Microsoft-signed redistributable copy (dbghelp, d3d…) stays low. Samples: ZIP, ISO and MSI.

## 1.229.0 — 2026-11-19 (#294)

**New version highlighted, one-click update, and what's new after updating**

- The version in the header lights up when a newer one is on GitHub; its changes can be read before updating.
- **Update** (admin) stops DocuTraceX, runs `run.py --update` (update without asking, re-provision) and starts it again; the page reloads by itself.
- After an update, the first page shows what changed since the version you had (this file).

## 1.228.0 — 2026-11-19 (#292)

**AutoIt: decrypt the strings obfuscated scripts hide behind their own decoders**

- A small AutoIt evaluator runs the script's own decoder functions on their constant arguments and puts the strings back in the code. It is limited to pure string and number work and never reaches the system.
- New rules on the decrypted code: process injection (hollowing), AMSI / ETW patching, ntdll unhooking, checks for security products.
- The AutoIt tab shows the decrypted code; its URLs and IPs become IOCs.

## 1.227.0 — 2026-11-19 (#293)

**Content before extension: binaries named like scripts are read as binaries**

- A file named like a script (.au3, .py, .pl, .ps1…) must be text to be read as code. Otherwise: disguised_binary, no script engine, and the binary path.
- Pieces embedded anywhere are carved as children: compiled AutoIt with junk in front, PEs, ZIP / 7z / CAB / OLE / PDF.
- AutoIt-Ripper now ships with DocuTraceX, so compiled AutoIt is always decompiled.

## 1.226.0 — 2026-11-19 (#291)

**AutoHotkey: compiled EXEs, scripts without extension, DllCall side-loading**

- the side-loading shape seen in the wild: a renamed AutoHotkey.exe, a script with no extension, and a DLL loaded with `DllCall("payload\Export")`.
- **unpack.** EXEs compiled with Ahk2Exe are recognised by their RCDATA resource `>AUTOHOTKEY SCRIPT<` / `>AHK WITH ICON<` (family `ahk`).
- **Test fix.** `test_findings_grouped_by_source` waits for the Findings pane's own Nested list. Since the tree view (#289), the Nested panel keeps a hidden list, so the old selector timed out; this test was failing on main.

## 1.225.0 — 2026-11-18 (#290)

**Nested tree: starts at the root, + / − per branch, Maximise, extension filter**

- **Starts at the root.** At first only the analysed file is shown, as its own box with the file count and "high inside". **+** on any box loads its children one level at a time, and **−** hides them.
- **⤢ Maximise**, first in the bar: the tree takes the whole window. **Esc** or **Restore** goes back.
- **Extensions filter.** Every extension in this case is listed with its count, computed once when the tree loads.

## 1.224.0 — 2026-11-18 (#289)

**Nested as a horizontal tree: open/close branches, pan and zoom in a large window**

- **Layout.** Each level is a column. Each edge takes the colour of the worst finding in its branch, so the dangerous chain stands out.
- **Opens itself.** Only the branches that lead to findings start open; **▸** opens or closes any other branch.
- **Large window.** The viewport is 68vh, or full screen. When the browser refuses full screen, a fixed overlay is used instead.

## 1.223.0 — 2026-11-18 (#288)

**Script tab for the generic engine; PEs in memory layout unmapped, resource padding stripped**

- AutoIt, AutoHotkey, Lua, Ruby, Perl, Tcl, shell and PHP scripts get their own code tab, named after the language.
- It works like the other languages: the lines the rules flagged (why, line, code, mark), metrics, the full code and the download link.
- Scripts found inside nested children show up there too.

## 1.222.0 — 2026-11-18 (#287)

**UI: long unbroken values wrap inside their box in every tab**

- monospace spans, links and plain `<pre>`.

## 1.221.0 — 2026-11-18 (#286)

**IOCs: pasted header blocks out of a page's visible text too**

- **`htmlpage`**: header blocks are stripped from the visible text *before* it is joined, whether the block comes line by line, in a `<pre>` or with `<br>`.
- **`ioc.strip_header_blocks`**: the Begin/End block is also recognised when it is flattened into one line. When `End` was cut off, everything up to the end of the text is removed.
- **Sample**: `sample_reported_phish.eml` now also has an HTML part with the block line by line.

## 1.220.0 — 2026-11-18 (#285)

**AutoIt without the EXE: standalone .a3x and scripts uploaded on their own**

- **Standalone `.a3x`** (`parsers/autoit.py`).
- **Renamed interpreters** (`interpreters.py`).

## 1.219.0 — 2026-11-18 (#284)

**Polyglots, portable interpreters, PEs carved out of shellcode**

- Finding `polyglot_html_<ext>`: high when the code decodes, runs or downloads; medium otherwise.
- The code around the page, with the page replaced by a placeholder, becomes a nested child analysed by its language. This happens at top level and in nested.
- Ordinary pages with scripts, Python that templates HTML and plain PHP templates are not reported.

## 1.218.0 — 2026-11-18 (#283)

**MSI: read the tables; embedded interpreter, decoy installer; less noise**

- Every custom action now says what it really runs: the EXE a property points at, its arguments with `[PROPERTY]` / `[#File]` expanded, and the `File` row with the stream it is stored in. All actions are kept in `item["custom_actions"]`.
- **`msi_embedded_interpreter` (high):** an interpreter the package ships, run on a file it also ships. For example: *embedded Python interpreter (pythonw.exe) shipped and run by the installer on 'InstallNotes.html' (stream Asset0)*. The…
- **`msi_decoy_installer` (high):** another MSI installed with msiexec while that payload runs.

## 1.217.0 — 2026-11-18 (#282)

**Registry: remote-access tools installed, portable, run, scheduled**

- **High** when the tool is portable (run from Downloads, Desktop, Temp, AppData, Public…), **renamed** or launched by a scheduled task. Renamed means Amcache keeps the original name, product or publisher of a file that is now called…
- **Medium** when the tool is installed normally.
- This replaces `reg_rmm_service` / `reg_rmm_installed`.

## 1.216.0 — 2026-11-18 (#281)

**RMM: hives skipped everywhere, match in the title; YARA: double context**

- **Bug from #279:** hives and `.reg` files were skipped only in the C2 path (`c2.scan_object`). The RMM step over the case's objects (`rmmintel.scan_objects`) calls `rmm.extract` directly, so hives were still read for product strings…
- **Test:** `test_finding_names_what_matched_and_hives_are_skipped_everywhere` covers the title, the evidence, a hive and a `.reg` file, and `rmmintel.scan_objects` on a hive.
- Hits now carry **six** hexdump lines (96 bytes) of context before and after the match, instead of three. This shows in the view and the CSV.

## 1.215.0 — 2026-11-17 (#280)

**Fix the four tests failing on main**

- The tests stubbed only webcrack and box-ps, so every other optional runtime ran its real installer (downloads, builds).
- One of those helpers calls `sys.exit` when the portable interpreter is missing. `SystemExit` is not an `Exception`, so it escaped `_ensure_optional`.
- Fix in the code: `_ensure_optional` also catches `SystemExit` and marks that runtime. A helper's exit must not stop the app's start.

## 1.214.0 — 2026-11-17 (#279)

**C2 / RMM: say what matched; no RMM from hives or generic signers**

- **Matched**: each indicator, with the text around its first occurrence and its offset. Example: `anydesk.exe — …Descargue [AnyDesk.exe] desde https://… (offset 1018)`. Shown one per line and not mined for IOCs.
- **Generic signers**: LOLRMM lists *Adobe Systems Incorporated* as Pcvisit's signer, so every machine with Acrobat came out as Pcvisit. Publishers that sign far more than remote-access tools (Adobe, Microsoft, Google, Symantec, Comodo,…
- **Hives and `.reg`**: they are not scanned for RMM product strings any more. The Registry rules (`reg_rmm_service`, `reg_rmm_installed`) read those traces and give the key and value.

## 1.213.0 — 2026-11-17 (#278)

**Registry: payloads in values analysed in Nested; fewer false ones**

- A re-run replaces them instead of listing them twice. A hive analysed on its own gets the same origin.
- In the Registry tab's table, each file name is a link that scrolls to its Nested card, opens any collapsed parent and flashes the card. The title now explains this.
- **Amcache** is not carved any more: it holds paths of what ran, never a payload. A shortcut to `Windows PowerShell (x86).lnk` was read as a command.

## 1.212.0 — 2026-11-17 (#277)

**Registry tab: readable entries table**

- The entries of a finding and of a *listed* rule use one table (`entryTable`) with **fixed columns**: Src, Key 36 %, Value 14 %, Data (the rest), Last write.
- The key wraps at its backslashes (`<wbr>`).
- A value over 300 characters scrolls inside its cell (about 7 lines), with its length shown.

## 1.211.0 — 2026-11-17 (#276)

**Email: no IOCs from headers or pasted header blocks**

- **Dropped:** the `X-Forefront-Antispam-Report` CIP / PTR / HELO and `X-Originating-IP` sources, the mail engine's header facts (`ms`, `auth`, `esp`) and the evidence of header rules (`ms_*`, `dkim_*`, `received_*`…). They stay in the…
- **No double counting:** emldump's `text/plain` and `text/html` outputs are not mined again when the body was not truncated.
- **Still mined:** the body, its links, the attachments and the chain's participants (From, Reply-To, To…).

## 1.210.0 — 2026-11-15 (#275)

**Registry: 30 more built-in rules**

- Run on the machine-sized synthetic hives: no new finding.
- `registry/sample_more_rules.reg`, `sample_more_SOFTWARE` (hidden task, AMSI provider deleted), `sample_more_BCD`, `sample_more_SAM`.
- Each trace sits next to the default that must stay quiet.

## 1.209.0 — 2026-11-15 (#274)

**Remove Sigma rules from the registry module**

- `docutracex/registry/sigma.py` and the hook in `registry.analyze`.
- The Settings card *Registry: Sigma rules*, `GET/PUT /api/settings/sigma` and `appsettings.sigma_settings`.
- The *Sigma hunting* section of the Registry tab.

## 1.208.0 — 2026-11-15 (#273)

**Sigma hunting: confirmable selections only, sorted and filterable**

- *Service binary in a suspicious folder*: its `Image` selection, with `Image` ignored, matched the `Start` of every service.
- A SolarMarker-style rule: with `Detail` and `Image` ignored, only a `TargetObject|re` matching any 14–19-letter name was left.
- Event metadata (`EventID`, `Channel`, `Provider_Name`…) is always dropped, option or not.

## 1.207.0 — 2026-11-15 (#272)

**Registry: stop flagging what a clean Windows ships**

## 1.206.0 — 2026-11-15 (#271)

**Registry: Sigma matches as hunting (no findings, no IOCs)**

- `sigma.run` now returns hits only (`hunting: true`): no case findings, no IOC sources.
- Registry tab: a **Sigma hunting** section (level badge, title, count, ATT&CK; opening it shows the rule metadata, the ignored fields and every entry, built on demand).
- IOCs come only from the entries behind the built-in findings.

## 1.205.0 — 2026-11-15 (#270)

**Registry: no cap on finding entries; Sigma rules with fields a hive lacks (1.205.0)**

- The registry rules keep **every entry behind a finding**. Before, each rule query stopped at 500 rows and each finding showed 40 ("40 of 500 shown — the rest in Search / SQL"). Sigma rules had the same caps; both are gone.
- The tab builds a finding's entries only when it is opened, and a listed rule's entries when its box opens. A large machine stays fast to open.
- Checked in a browser: findings open and show their entries, with no JavaScript errors.

## 1.204.0 — 2026-11-15 (#269)

**Registry: hives from a collection zip keep their path; logs paired per folder (1.204.0)**

- every hive showed up as **"NTUSER.DAT"**, so you could not tell which user it was.
- `parse.is_hive()` now also checks the base block's file type: `0` is a hive, `1` / `2` is a transaction log. Logs start with the same `regf` block, so before this they could be taken for hives.
- `analyze._registry_sources()` maps each extracted file back to its entry in the archive. The hive is labelled with that path (`archive › Users/ana/NTUSER.DAT`) and is given the `.LOG1` / `.LOG2` / `.LOG` from the same folder, whatever…

## 1.203.1 — 2026-11-15 (#268)

**Docs: where the registry hives are on a Windows machine (1.203.1)**

- How to collect the hives, which are locked while Windows runs: from an image, with a forensic collector (KAPE, FTK Imager, Velociraptor…), or as an administrator with `reg save`. Each hive should come with its transaction logs (`.LOG1`…
- Notes on `RegBack` (empty by default since Windows 10 1803) and on collecting every user's hives.

## 1.203.0 — 2026-11-14 (#267)

**C2: StealC, Vidar, Lumma, Brute Ratel, Havoc (Demon), Pure family; a card per family (1.203.0)**

- One engine fix: the RC4 key may itself look like base64 (real StealC keys usually do). It was skipped before and is now tried.
- New extractor `modern` (Lumma, Brute Ratel, Havoc, Pure). It runs only when no other extractor read a C2. `stealers` is now 1.2.
- Not included: GuLoader, Formbook / XLoader, Rhadamanthys and Latrodectus. Reading them faithfully needs real samples.

## 1.202.1 — 2026-11-14 (#266)

**Fix two failing tests: stego padding and the phishing lab's sample path (1.202.1)**

- **`test_stego::test_keyed_xor_and_trimmed_size`**: a real bug. The check that rejects a stream because of zero runs ("XOR-ed data with 64 zeros = wrong stream") also counted the image's own trailing padding. A keyed-XOR payload smaller…
- **`test_netcheck::test_url_check_submit_and_download`**: the phishing lab (`scripts/phish_lab.py`) looked for `sample.docm` at the root of `samples.zip`, but samples now sit in their type folder. It now reads `word/sample.docm` and…

## 1.202.0 — 2026-11-14 (#265)

**Settings: YARA rules under Detection rules, page in four groups of cards (1.202.0)**

- **Recompile** with progress, compile errors per file and the compiled rules with a filter.
- A sticky **index** at the top: Network · Your organisation · Email intelligence · Detection rules.
- Text inputs and links are styled consistently (some were white or default blue). On very wide screens the cards sit in two columns.

## 1.201.1 — 2026-11-14 (#264)

**Registry: Sigma rules from a folder set in Settings (1.201.0)**

- **Details** uses Sysmon's spelling: `DWORD (0x00000001)`, `QWORD (0x…-0x…)`, `Binary Data`, `(Empty)`.
- **EventType** is `SetValue` for a value and `CreateKey` for a key. Entries recovered from deleted cells are `DeleteValue` / `DeleteKey`, and they are the only rows `registry_delete` rules look at.
- Modifiers: `contains`, `startswith`, `endswith`, `all`, `re` (RE2), `cased`, `windash`.

## 1.200.0 — 2026-11-14 (#263)

**HTML section: offline preview, structure, phishing rules, victim, QR drawn in HTML (1.200.0)**

- PNG rendered by the network checks' Chromium in its `offline` mode: **JavaScript off, every request blocked**, in its own process. The page never tells its author it was opened; remote images, CSS and fonts show as gaps and are listed…
- **Loaders**: if the page is `document.write(atob(…))`, `unescape`, `String.fromCharCode` or escaped strings, the next layer is **decoded from its literals, never executed** (up to 4 layers). The preview shows the recovered page.
- **QR codes drawn with HTML / CSS / SVG** (table cells, `<div>`s, `<rect>`s, so there is no image to extract) are read from the preview. This completes the QR work from #261.

## 1.199.0 — 2026-11-14 (#262)

**Origin fingerprints per file: Word / Excel / VBA / PDF / LNK / PE (1.199.0)**

## 1.198.0 — 2026-11-14 (#261)

**QR codes in every image: standalone, Office / OneNote media, data: URIs, RTF pictures (1.198.0)**

- **Image case**: a new `qr` result (QR tab) with the codes and their findings.
- **Nested**: every image child is read — Office and OneNote media, images in PE resources, archive members. Icons under 40 px a side are skipped; at most 120 images a case. The tree shows a *QR →* badge.
- **Markup and RTF**: base64 `data:` images in HTML / SVG (and in the email's HTML body) and RTF `\pict` pictures (`pngblip` / `jpegblip`) become image children of their own, so they are read too and can be opened or downloaded.

## 1.197.0 — 2026-11-13 (#260)

**Registry: suspicious Windows commands in any value, two-tier (1.197.0)**

- **`reg_cmd_critical`** (high): one critical indicator is enough — encoded PowerShell, AMSI bypass, reflection, comsvcs MiniDump / ntdsutil / shadow-copy credential theft, `reg save` of SAM, squiblydoo, Follina, Kerberoasting / PtH,…
- **`reg_cmd_combination`**: two or more different medium indicators in the same value — medium, **high** when the value is in an autostart key (Run, services, Winlogon, Active Setup, IFEO…).
- **`reg_cmd_allowlisted`** (info): SCCM, MpCmdRun, Windows Update and management suites clear the value; the generic command rule does not repeat it.

## 1.196.0 — 2026-11-13 (#259)

**Quick analysis: several files at once in YARA, ML and C2 (1.196.0)**

- The **loose file** forms of **YARA, Machine Learning and C2** take several files (*Choose file(s)*): one quick case per file, uploaded one after another and run by the task queue **as many at a time as *Analyze at a time*** (New…
- **Task queue fix**: tasks of the same case now run one at a time, in order. With *also its contents* and several workers, a file's engine run could start while its own full analysis was still writing results (possible before with one…
- Docs: the quick-analysis paragraph in YARA.

## 1.195.4 — 2026-11-13 (#258)

**Markdown export: no limits in any section (1.195.4)**

## 1.195.3 — 2026-11-13 (#257)

**Registry: hives inside archives no longer flood the IOCs (1.195.3)**

## 1.195.2 — 2026-11-13 (#256)

**New analysis: Registry and Memory dumps tiles; README and docs (1.195.2)**

- **New analysis → Supported formats**: a **Registry** tile (REG: `.reg`, NTUSER.DAT, UsrClass.dat, SYSTEM, SOFTWARE, SAM, SECURITY, Amcache.hve, `.LOG1/2`) and the missing **Memory dumps** one (DMP: `.dmp`, `.mdmp`), each with its tooltip.
- **README**: the Registry bullet now covers recovery of deleted entries, the machine context, hiding rules, exports and the size it handles.
- **Docs site**: a Registry card on the home page (the file-type page was already updated with each registry PR); `TOOLS.md` credits regipy, DuckDB and the RECmd batch files.

## 1.195.1 — 2026-11-13 (#255)

**Registry: Recovered sub-tab (1.195.1)**

## 1.195.0 — 2026-11-13 (#254)

**Registry: machine-sized sample, fast hive walker, large-hive fixes (1.195.0)**

- **`fastregf`**: keys and values read with `struct` from the bytes (nk, lf/lh/li/ri, vk, db big data). Same rows as regipy (tested on several hives), ~20× faster; regipy takes over on a structure it does not understand.
- Bulk inserts through CSV (DuckDB `executemany` cost 50 s for the artifacts and catalogue).
- regipy plugins that only re-list keys already in the database are skipped (services, installed programs, classes installer: 48 s).

## 1.194.0 — 2026-11-13 (#253)

**Registry: deleted entries, machine context, anti-forensics, exports (1.194.0)**

- Browse → **Export .reg**: a key and its subtree, as regedit writes it (round-trip tested).
- Timeline → **Export bodyfile / CSV**: the whole timeline streamed in pages (mactime -b / Plaso).
- Both are audited (GET exports are now audited when listed).

## 1.193.1 — 2026-11-13 (#252)

**Registry findings: compact table with marks, entries on demand (1.193.1)**

## 1.193.0 — 2026-11-13 (#251)

**Registry: decoded artifacts (regipy plugins) and the RECmd catalogue (1.193.0)**

- Browse: **★ Bookmarks** select per source, grouped by category.
- New **Artifacts** sub-tab (plugins and catalogue categories per source → table) and **Timeline** (key last-writes + artifact timestamps).
- SQL examples for artifacts, catalogue, timeline and `json_extract`.

## 1.192.2 — 2026-11-13 (#250)

**Registry: read with the DuckDB that wrote the database (1.192.2)**

## 1.192.1 — 2026-11-13 (#249)

**Registry tab: show why it is missing instead of hiding it (1.192.1)**

## 1.192.0 — 2026-11-13 (#248)

**Registry: rules for the less common autostarts and tampering (1.192.0)**

- **Persistence**: Windows `Load` / `Run` (T1547.001), Active Setup `StubPath` with a suspicious command (T1547.014), `BootExecute` / `SetupExecute` beyond `autocheck autochk *` (T1547), AppCertDLLs (T1546.009), print monitors / print…
- **Services**: `ServiceDll` outside System32 / Program Files, names posing as Windows components (T1036.004), image paths in AppData / Desktop / Downloads / ProgramData / a drive root / pointing at a non-executable.
- **Evasion**: PowerShell script block / module logging or transcription off (T1562.002), AMSI off for WSH (T1562.001).

## 1.191.0 — 2026-11-13 (#247)

**Registry module: hives and .reg into a per-case DuckDB database (1.191.0)**

- **Persistent per-case database**: every key and value goes into `results/registry.duckdb` (`sources`, `keys`, `vals`) once; reopening the case reads it without re-parsing. Hives are mounted where Windows mounts them; transaction logs…
- **Rules** (27, SQL over the database, with ATT&CK): Run keys, Winlogon, services, IFEO / SilentProcessExit, AppInit, LSA, netsh helpers, per-user COM servers, logon scripts, Defender off / exclusions, UAC off / handler bypass, WDigest,…
- **Payloads in values** (PE, script, base64, encoded PowerShell) are carved and analysed as nested objects.

## 1.190.0 — 2026-11-13 (#246)

**Email: HTML surface rules and link facts (1.190.0)**

- `link_shortener`: links through a URL shortener.
- `link_deep_subdomain`: a trusted-looking name buried in a long subdomain chain.
- New lexicons: `refund`, `security_alert`, `cta`.

## 1.189.0 — 2026-11-13 (#245)

**Real-sample batch: Cobalt stagers, encoder stubs, loaders, padded installers, hidden Python, UPX ELF (1.189.0)**

- **1768.py 0.0.23**, the version `install.py` downloads, changed its stager report to `Found shellcode:`, `Identification: CS …` and `license-id:`.
- **Cobalt Strike vs Metasploit:**
- **Discord webhooks**: token grabbers' exfiltration channel (the webhook URL is the indicator).

## 1.188.0 — 2026-11-13 (#244)

**Sign-in, users, audit trail and a token for MCP over HTTP (1.188.0)**

- **First start**: the app asks for the **admin** password and shows nothing else until it is set. `run.py` also says so in the console.
- After that, pages redirect to `/login` and API calls answer 401. Static files and `/health` stay open.
- Every change must carry the `X-DTX` header that the page itself adds (CSRF protection), on top of a SameSite=Strict, HttpOnly cookie.

## 1.187.0 — 2026-11-13 (#243)

**docs: run.py update prompt and a Configuration page (1.187.0)**

- **Getting started / README**: every `python run.py` first checks GitHub and asks `Update X -> Y? [y/N]` before starting; it also lists `--no-update`, `--host` / `--port` and `update.py --yes`.
- Two screenshots of Settings filled with **invented** values (`grupoejemplo.example`, Tor on `127.0.0.1:9050`), taken by `scripts/docs_screenshots.py --only configuration`. Nothing is saved.

## 1.186.0 — 2026-11-13 (#242)

**Own domains without a cap; MCP server over HTTP (1.186.0)**

- Settings kept at most 200 domains and 200 brands; the cap is gone, and duplicates are dropped.
- 1,200 own domains × 300 case domains: 16 s → 1.7 s.
- `python -m docutracex.mcp_server --http [--host 0.0.0.0] [--port 8001]` serves streamable HTTP on `/mcp`, on mcp 2.x and 1.x. It replaces a hand-written `run_mcp_http.py`.

## 1.185.0 — 2026-11-12 (#241)

**Documentation site (MkDocs Material on GitHub Pages) and a lighter README (1.185.0)**

- **Screenshots**: `scripts/docs_screenshots.py` analyses the **inert samples** into a throw-away cases folder (lookups off) and serves the app. Engine views run their module first; YARA uses an inert rule. Each tab is taken with headless…
- **Publishing**: `.github/workflows/docs.yml` builds with `--strict` and deploys to GitHub Pages on every push to `main` that touches `docs/` or `mkdocs.yml`.
- **README**: cut to one screen with a link to the site. The hidden marks in the README are kept.

## 1.184.0 — 2026-11-12 (#240)

**Process memory dumps: carve PEs and executable memory from minidumps (1.184.0)**

- The carved files go to the nested tree and to the C2 tab.
- Findings: PEs that no module on disk backs (high, T1620), and private executable memory (medium if RWX).
- Bounded: 120 files, 64 MB per image, 8 GiB scanned.

## 1.183.0 — 2026-11-12 (#239)

**.NET crypters: inline RC4, hex keys, Bitmaps with empty pixels, XOR key recovery (1.183.0)**

- `strdec.decrypt_blob`: RC4 when a method has an inline RC4 shape (256-entry table, `& 255`, `xor`). Key strings that are hex text are also tried decoded.

## 1.182.0 — 2026-11-12 (#238)

**.NET loaders: decrypt the next stage hidden in .resources entries (1.182.0)**

- Many .NET loaders keep the next stage as an AES-encrypted `byte[]` entry of a `.resources` file, with the key string in the class' static constructor, not in the decrypting method. Those entries were extracted but stayed encrypted.
- `strdec.decrypt_blob` now looks for key material in three places, in order: the method, its class (`.cctor` / static fields), then the assembly's strings (max 300, first-block pre-check so it stays fast).
- High-entropy entries inside `.resources` go through it too. The decrypted stage is a nested child (recipe `decrypt: AES-…`), gets the finding `dotnet:resource_decrypted`, and the C2 extractors read it.

## 1.181.0 — 2026-11-12 (#237)

**Cobalt: Artifact Kit payloads XOR-ed with a 4-byte key; packers named (1.181.0)**

- `cobalt.xor4_payloads`: when the parsers find nothing in a PE, every section (up to 4 MB) is searched for the key that turns its bytes into a **block_api prologue** (x86 / x64) or a **reflective-loader head**.
- The card shows *Loader: payload XOR-ed with 4-byte key … at offset … (Artifact Kit layout)* and keeps the indicators.
- Checked on the real set: the Artifact Kit sample now gives its **stager with C2**, with no other hit across the 53 samples. The real beacon is unchanged.

## 1.180.0 — 2026-11-12 (#236)

**Metasploit: windows/exec payloads read with their command (1.180.0)**

- `WinExec`'s ROR13 hash (x86 `push`, x64 `mov r10d`) after block_api now marks a **single-stage exec payload**. The family is *Metasploit payload (exec)*, kind `payload`.
- The **command line** is read: the NUL-terminated string after the call that looks like a command (cmd, net, powershell, reg, schtasks…, or an `.exe` / `.bat` / `.ps1`).
- `net user … /add` is flagged as *adds a local user*.

## 1.179.0 — 2026-11-12 (#235)

**C2: protected objects named, with why there is no configuration (1.179.0)**

- **Detect It Easy's** protector / virtualizer / cryptor verdicts, when DIE ran on the object (read from the PE analysis).

## 1.178.0 — 2026-11-12 (#234)

**Unpack: WinRAR SFX with the archive after its comment (1.178.0)**

- A stub that carries **WinRAR** strings, with a **`Rar!\x1a\x07` header in the first 64 KB of the overlay**, is now a RAR SFX (evidence: *RAR archive inside the overlay of a WinRAR SFX stub*). It is extracted with 7-Zip as before.
- Without the WinRAR stub, the RAR bytes alone do not make an SFX.
- the DcRAT RAR SFX (already detected) unpacks to its loader plus VBE / BAT scripts.

## 1.177.0 — 2026-11-12 (#233)

**Go: identified by its runtime messages when pclntab is hidden (1.177.0)**

- With no readable pclntab, **5+ runtime messages** add `runtime_messages` (35) and the runtime evidence. The Sliver builds now come out **Likely**.
- Trait `garble`, with the reason: *Go runtime present but pclntab hidden and BuildInfo altered: garble or a modified toolchain — function names and config are not readable statically*.
- Binaries with a pclntab are unchanged (Merlin stays Confirmed).

## 1.176.0 — 2026-11-12 (#232)

**njRAT: custom-splitter builds recognised (1.176.0)**

- At least **5 command names plus a splitter** (`|…|`) now identify it, next to the host and port.
- The card shows the splitter and the commands.
- The classic path is unchanged. Command names alone, without a splitter, are not enough.

## 1.175.0 — 2026-11-12 (#231)

**Cobalt: dissect.cobaltstrike false finds discarded (1.175.0)**

- A found config is **discarded** when it has no strong evidence (a real C2 host or URI, POST URI, public key, watermark or known version) **and** fewer than `MIN_SETTINGS` = 10 recognised settings. A real beacon carries ~30–70. The view…
- Host values that are not a host or an IP (control characters) are dropped from kept configs.

## 1.174.0 — 2026-11-12 (#230)

**Chain: quoted senders without a display name; no incomplete-chain warning (1.174.0)**

- a display name equal to the address is dropped.

## 1.173.0 — 2026-11-12 (#229)

**Inno Setup [Code] read; no nested child left unread; installer noise (1.173.0)**

- **Strings** (ANSI and UTF-16 constants) are mined for IOCs: the URLs, hosts, paths and registry keys of a downloader.
- **Calls**: the Inno built-ins (`DownloadTemporaryFile`, `CreateDownloadPage`, `Exec`, `ShellExec`, `RegWriteStringValue`, `ExtractTemporaryFile`, `LoadDLL`…, plus the IDP / ITD download plug-ins) and DLL imports (`dll:urlmon.dll` +…
- The DLL / function names are excluded from the IOCs.

## 1.172.0 — 2026-11-12 (#228)

**ViperMonkey: the real reason when there is no result; 5-minute limit (1.172.0)**

- Otherwise only ViperMonkey's own log lines (`ERROR    …`), stderr first, or a Python traceback's last line count. Then the exit code, then "stopped without a result".

## 1.171.0 — 2026-11-12 (#227)

**ViperMonkey on Windows: /tmp paths to a real temp folder (1.171.0)**

- `export_all_excel_sheets.py`: `/tmp/sheet_…`.
- ViperMonkey now runs through `parsers/_vmonkey_launch.py`. It wraps the file functions ViperMonkey uses (`open`, `io.open`, `os.remove` / `exists` / `isfile` / `makedirs`…, `shutil.rmtree` / `copy`…) and maps **only those names** to the…
- The launcher is Python 2 / 3 compatible (PyPy 2.7). It is copied into the work folder and run from there, so no DocuTraceX module can shadow one of ViperMonkey's imports.

## 1.170.0 — 2026-11-12 (#226)

**XLM without distutils; ViperMonkey failures show their reason (1.170.0)**

- The file is now pre-filled with `{}`, so ViperMonkey finishes.
- When there are no results, the step says why: *no emulation result: no VBA macros found* or *…: \<ViperMonkey's last ERROR line>* (`emulation`: `no_vba` / `no_result`).

## 1.169.0 — 2026-11-12 (#225)

**Tasks: step notes say why a tool did not run (1.169.0)**

- `run()` in `analyze.py` appended its `note` ("not provisioned", the only value every caller passes) to **every** step, not only when the tool was missing. So didier / OfficeMalScanner showed *ok · not provisioned* after running, and a…

## 1.168.0 — 2026-11-12 (#224)

**Inno Setup 6.2+ with innounp; C2 dependency check on the analysis Python (1.168.0)**

- innoextract 1.9 (2020, the last release) reads Inno Setup up to 6.1. Newer installers fail with *"Unexpected setup loader revision: 2 … Setup loader checksum mismatch!"*: a format it does not know, not a corrupt or tampered file.
- `_unpack_inno` now tries innoextract first, then **innounp** (J. Rathlev's branch, 2.71.3: Inno Setup 2.0.7 – 7.1.1) when innoextract is missing or cannot read it. Command: `-x -m -b -y -q -h -o -d<out>`, which is static, never prompts,…
- `install_script.iss` (`[Run]`, `[Code]`) is kept as a recovered script, so the IOC sweep mines it.

## 1.167.0 — 2026-11-12 (#223)

**Tenant lookup: tenant.fyi too, on by default, kept for good (1.167.0)**

- **What it adds**: the tenant's names over time and every domain it has held — **former ones with first / last seen** (`/api/tenants/{id}?status=all`, paged).
- **Merged into the tenant card**: brand / name when AZMap has none, "also named", removed domains with their dates (tooltip), tenant.fyi status and link. If AZMap fails or is off, tenant.fyi alone fills the card.
- **Kept for good**: the raw answer is stored in the case (`mailrules.tenant.tenants[].fyi`), and `tools/mailintel/tenantfyi_cache.json` keeps the last good answer. When the site fails or no longer has the tenant, that answer is returned…

## 1.166.0 — 2026-11-12 (#222)

**C2: Raccoon Stealer v2 in depth (1.166.0)**

- Every C2 URL, the request fields (`machineId=` / `configId=`), the user agent, and a 32-hex **config ID** when present (marked as probable).
- Browser-DLL / wallet traces next to the config.
- Note: the real configuration (what to steal, DLLs to download, grabbers) comes from the C2 at check-in.

## 1.165.0 — 2026-11-12 (#221)

**C2: Warzone / AveMaria version, options and traces (1.165.0)**

- Version from `warzoneNNN` (e.g. 1.60).
- The builder options after the port shown **raw** (up to the zero padding): their layout changes between versions, so they are not named — [muestras reales].
- Family traces (Ave_Maria, UAC-bypass moniker, `_rptls` key, rdpwrap) next to the config, and alone when nothing decrypts.

## 1.164.0 — 2026-11-12 (#220)

**C2: RedLine / META settings by name (1.164.0)**

- **Named settings**: the settings class (`IP`, `ID`, `Message`, `Key`) read from the `.cctor` (dnfile + dncil) and interpreted by `familyspec`: panel host:port list, **build ID**, the **fake error message** shown to the victim, XOR key.
- XOR keys that look like base64 (a plain word such as `Pedestal`) are tried last instead of skipped.
- In the .NET stealer pass, a decrypted configuration wins over another family's traces.

## 1.163.0 — 2026-11-12 (#219)

**C2: Snake Keylogger exfiltration channel (1.163.0)**

- The decrypted strings (DES-ECB, key MD5(string)[:8]) go to **exfiltration roles** read by `familyspec`: SMTP server, port, sender, receiver and the **password by its position** after the sender (said so in a note); FTP URL, user and…
- Credentials are marked **sensitive**; channel list (SMTP / FTP / Telegram) and the banner.
- Key strings that look like base64 are now tried last instead of skipped.

## 1.162.0 — 2026-11-12 (#218)

**C2: XWorm settings by name (1.162.0)**

- **Named settings**: the settings class (`Hosts`, `Port`, `KEY`, `SPL`, `Sleep`, `Groub`, `USBNM`, `InstallDir`, `InstallStr`, `Mutex`, `LoggerPath`, `ChatID`, `Token`…) read from the `.cctor` (ldstr → stsfld, dnfile + dncil) and…
- Without readable names, the values are read by what they look like, as before (now with the version too).
- **Traces only** when nothing decrypts.

## 1.161.0 — 2026-11-12 (#217)

**C2: Remcos settings by field position (1.161.0)**

- **By field position** (Remcos 3.x / 4.x, ≥ 21 fields) through `familyspec`: C2 `host:port` with TLS flag, botnet (campaign), reconnect interval, install folder + name (hidden), persistence (HKCU / HKLM Run, Policies\Explorer\Run,…
- Named fields shown as `role (field N)`; positions not agreed by public parsers stay `field N`.
- **Older layouts** (fewer fields) keep the generic reading (C2, campaign, `Rmc-` mutex).

## 1.160.0 — 2026-11-12 (#216)

**C2: common family layer (1.160.0)**

- `interpret()` builds the card all families share, and `traces()` gives the *indicators only* result.
- **AsyncRAT / DcRAT and QuasarRAT** now go through it. Their output is identical to before, checked against a baseline of every sample. The renamed-fields fallback and the traces are unchanged.
- From here, each new family only needs to find and decrypt its configuration and fill in its `Spec`.

## 1.159.0 — 2026-11-12 (#215)

**.NET RATs: renamed settings fields fall back to reading the values (1.159.0)**

- When an obfuscator renames the settings fields (`\\^B`, `a`…), the names say nothing. #213 then found no hosts and dropped the whole configuration, which is worse than before.
- Unknown names now fall back to reading the values by what they look like, as before #213.
- A configuration that still gives no C2 reports the family's traces instead of nothing.

## 1.158.0 — 2026-11-12 (#214)

**QuasarRAT settings named by their field (1.158.0)**

- **Quasar builder defaults** are flagged: `Office04`, `Client.exe`, `Quasar Client Startup`, the `QSR_MUTEX_` pattern and the `Quasar Server CA` certificate.
- **Sample:** `c2/quasar/sample_quasar.exe` rebuilt with its `Settings` `.cctor`. The family card now reads *AsyncRAT / DcRAT / QuasarRAT*.
- Tests added; C2 suites pass.

## 1.157.0 — 2026-11-12 (#213)

**AsyncRAT / DcRAT in depth, C2 family cards, YARA + RMM in the Markdown export (1.157.0)**

- Settings are **named by their field**: `ldstr → stsfld` in the settings class `.cctor` (dnfile + dncil). Guessing from the values is now only a fallback, so the `Delay` value is no longer read as a port.
- The pinned **server certificate** is decoded: CN, issuer, validity, SHA-1 and serial. The SHA-1 now links clients of the same server across cases.
- **Pastebin dead drop:** the paste host is the IOC, not a C2 contact.

## 1.156.0 — 2026-11-12 (#212)

**PE overlay: the Authenticode signature is not an overlay (1.156.0)**

- **Bug:** pefile and LIEF count the certificate table, which sits after the sections, as overlay. So every signed PE showed a high-entropy overlay: `pe_overlay`, and `lief_overlay_encrypted` (medium) on the PKCS#7 blob itself.
- **Fix:** both now measure only what is around the signature. If nothing is left, there is no overlay.
- **New `pe_data_after_signature` (medium):** bytes appended after the signature, outside what it covers. This can be configuration stamped on a signed installer, or content added to a signed file.

## 1.155.0 — 2026-11-12 (#211)

**Less noise on signed installers: masquerade, severities, IOCs (1.155.0)**

- **Sample:** `windows-pe/sample_signed_bootstrapper.exe` plus tests. PE, IOC, .NET, stego, mail and C2 suites pass.

## 1.154.0 — 2026-11-12 (#210)

**README: new features, phone layout, screenshots (1.154.0)**

- **Screenshots** of the inert `sample.eml` case at the top: desktop overview, findings, and two on a phone (`docs/img/`, ~210 KB in total).
- **Short additions to the feature table:**
- Also: quick analysis of a loose file, `validate_samples.py`, and phone access in the Quickstart.

## 1.153.0 — 2026-11-12 (#209)

**Web UI: phone layout (1.153.0)**

- **Findings** become one card per finding: severity · source · rule, then detail, location and the review controls.
- **Heavy views** (hex, call graph, CFG, code) stay usable by scrolling.
- **Desktop** is unchanged: everything is inside the media query, and the only JS change is an optional class on the findings tables.

## 1.152.0 — 2026-11-12 (#208)

**RMM in IOCs and text: tags + rmm:mention findings (1.152.0)**

- **IOC tags:** domain, URL, file-path and command IOCs of an RMM product (LOLRMM plus the built-in list) get an *RMM: product* badge in the IOCs tab. It is context only: the IOC is not raised or scored.
- **Objects in every IOC extraction:** the original, extracted and nested objects go through the C2 RMM extractor in every IOC extraction (full analysis, module re-runs, quick cases) **without running C2**.
- **Noise control:** names that are ordinary words (Level, Remote PC, Remotely, Absolute…) and short single-word names are never matched. No false positives over `samples.zip`.

## 1.151.0 — 2026-11-12 (#207)

**RMM: product list from LOLRMM, refreshed weekly (1.151.0)**

- **LOLRMM** (magicsword-io, **Apache-2.0**) is the product list of the `rmm` extractor: about 360 RMM and remote-access tools.
- `rmm_tools.json` is downloaded on install and refreshed in the background when older than 7 days. Settings → C2 has *Refresh now*. It is fetched from lolrmm.io, with its GitHub copy as fallback.
- Only the catalogue is downloaded: nothing about a sample is sent.

## 1.150.0 — 2026-11-12 (#206)

**C2: RMM tools in installers + batch validation script (1.150.0)**

- **RMM / remote-access extractor (`rmm`):** names the product from ASCII and UTF-16 strings, also inside MSI and setup installers. It covers ScreenConnect, AnyDesk, TeamViewer, Atera, NetSupport, Splashtop, Remote Utilities, MeshCentral,…
- It also reads the instance the client is bound to: the ScreenConnect relay (`h=`/`p=`, session type), the Atera account, the NetSupport gateway, the MeshCentral server and the Tactical RMM API.
- These are legitimate products. A product with no instance is reported as *indicators* with a low finding; a product bound to an instance gives a medium finding `c2:rmm`.

## 1.149.0 — 2026-11-11 (#205)

**C2: rat-king-parser as second .NET RAT engine (1.149.0)**

- **rat-king-parser** (jeFF0Falltrades, MIT) is now the optional second engine of the AsyncRAT / DcRAT / Quasar extractor. It also covers VenomRAT, Xeno RAT and clones.
- It runs in a child process with a 60 s timeout and only reads files statically.
- Shown as one sub-tab per engine (own decoder / rat-king-parser), with the hosts compared: agree / partial / differ, and medium confidence when they differ.

## 1.148.0 — 2026-11-11 (#204)

**Cobalt Strike: shared watermarks / keys list, profile download (1.148.0)**

- **Shared watermarks and keys** (C2 view): your own list of watermarks and public-key SHA-256 known to be shared (leaked or cracked builds), one per line as `value note`. Listed values show their note on the card and never link cases. No…
- **Download .profile:** downloads the malleable C2 profile that dissect.cobaltstrike rebuilds.
- Already in place before this PR, so not changed: pipes and spawn-to are extracted as IOCs (named_pipe / filepath); the DNS channel, process injection, evasion (sleep mask, syscalls, Beacon Gate, cleanup), guardrails and kill date are…

## 1.147.0 — 2026-11-11 (#203)

**Go phases 2 and 5: source lines, build paths, func-value calls (1.147.0)**

- **Source lines (phase 2):** each function gets its `file:line` from the pclntab `_func` pcfile / pcln tables (Go 1.16+; declaration line on 1.20+). It is shown in Code and works without GoReSym. Checked against a real `go build` (test…
- **Build paths:** without `-trimpath`, the build account and the project directory are shown under Types → Source files, with an info finding `go:build_paths`. With `-trimpath` the UI says so.
- **Func values / closures (phase 5):** an indirect call through a funcval whose `fn` is a known function is resolved. It appears as a closure edge in the call graph and under *resolved targets* in Code. Interface itabs are unchanged.

## 1.146.0 — 2026-11-11 (#202)

**Cobalt Strike: faster with dissect, known watermarks, version guess labelled (1.146.0)**

- dissect.cobaltstrike runs first; if it already has the configuration, 1768.py runs once without the `-x` / `-e` retries (~11 s less per 4.10 sample).
- Known watermarks: `0` = trial / no licence, plus a few widely reported leaked / cracked ones. They get a meaning on the card and are **not** used to link cases. A watermark identifies a licence, never an actor, so no attribution.
- *Version (guess)* now says it is inferred from the configuration, not read from the beacon.

## 1.145.0 — 2026-11-11 (#201)

**Engines / AI sections, coloured duotone icons, quick analysis of a loose file**

- **Engines** groups YARA, Machine Learning, C2 / Beacons and Hex: the raw analysis tools.
- **AI** is a section of its own.
- **Icons:** every tab has its own colour.

## 1.144.0 — 2026-11-11 (#200)

**C2: extractor dependencies optional with a warning; licence review of third-party parsers**

- `registry.REQUIRES` declares each extractor's dependencies (kind, name, required or optional, and what it is for).
- **Missing required dependency:** only that extractor is switched off.
- **Missing optional dependency:** the extractor still runs with less, and its run is marked `degraded`. Example: Cobalt Strike without `1768.py` / `dissect.cobaltstrike` falls back to the built-in parser.

## 1.143.0 — 2026-11-11 (#199)

**Go phase 8: layered payloads, static key derivation, call-graph routes to crypto**

- `crypto.unwrap()`: a decrypted payload wrapped in gzip, zlib, xz, bzip2, zstd or Base64 is unwrapped, up to 3 layers.
- The chain is kept in the method name, for example "AES-GCM (authenticated) … → gzip", together with the size before and after.
- CBC, CTR and RC4 now also accept a plaintext that unwraps to text or to a PE / ELF. Compressed data is not printable before decompression, so before this change it was rejected.

## 1.142.0 — 2026-11-11 (#198)

**Go ↔ C2: Go implants in the C2 contract (framework + endpoints with provenance)**

- the Go version and the main module.
- A bare literal is never taken as a C2 on its own: with no framework and no link to config, decryption or a network call, nothing is reported.
- The extractor runs after the others, only when no configuration was recovered.

## 1.141.0 — 2026-11-11 (#197)

**Go phase 6: scripts / templates in string literals, standard-library and more notable modules**

- `resources.script_literals()` scans the read-only data (`.rdata`, `.rodata`, `__rodata`, `__const`, `__cstring`) for long text runs.
- A run is named by the language whose markers it matches, needing at least 2 distinct ones. Languages: PowerShell, batch, shell, VBScript, JScript, Python, AppleScript and Go `text/template` / `html/template`.
- Go keeps literals back to back, so a run can carry neighbouring strings. The run is kept whole, up to 256 KB, with its file offset.

## 1.140.0 — 2026-11-11 (#196)

**Tenant lookups cached 7 days (Microsoft too); the Verdict tab is not mined for IOCs**

- **Tenant lookups cached 7 days, Microsoft included.** Microsoft's domain → tenant answers (OpenID configuration + `getuserrealm`) are now cached for 7 days, like AZMap's. Failed lookups are retried after 10 minutes. The Settings text is…
- **The Verdict tab is not mined for IOCs.** `mailrules` `verdict/*` holds the raised / lowered signals and their "why". It only summarises signals whose values are already mined where they come from, so it no longer produces IOCs…

## 1.139.0 — 2026-11-11 (#195)

**Listen on all interfaces by default: reachable from other computers**

- **Default host:** `DOCUTRACEX_HOST` now defaults to `0.0.0.0`. It was `127.0.0.1`.
- **Startup log:** lists the addresses to use, `http://127.0.0.1:<port>` for this computer plus the machine's LAN IPs for other computers. The LAN IP is found from the default-route interface; no packet is sent.
- **Local only:** `python run.py --host 127.0.0.1` or `DOCUTRACEX_HOST=127.0.0.1` keeps it on this computer, as before.

## 1.138.0 — 2026-11-11 (#194)

**MCP tab: check mcp in the portable Python the client launches, as Diagnostics does**

- The MCP tab ran `importlib.metadata.version("mcp")` inside the web server's own process.
- The web app runs on the Python that launched it, but the MCP client (Claude Desktop / Code) runs `tools/python`, which is also the interpreter Diagnostics probes.
- When those are two different interpreters, the tab reported `mcp` missing even though it was installed where it is used.

## 1.137.0 — 2026-11-11 (#193)

**Replace case-derived values in tests and samples with invented ones; CLAUDE.md rule**

- **CLAUDE.md rule:** evidence the owner shares must never go into the repo, commits or PRs. Patterns are reproduced with invented values and cases are described generically.

## 1.136.0 — 2026-11-11 (#192)

**Email: Microsoft 365 tenant checks with AZMap + Microsoft's public endpoints (typosquats in throw-away tenants)**

- **AZMap** (tenant ID from `X-MS-Exchange-CrossTenant-Id`) gives the brand and the current domains.
- **Microsoft** (`login.microsoftonline.com`, no account or token) gets the sender's domains: From, Reply-To and Return-Path, never your own, at most 10.
- The email view has a new **"Sender domains → tenant (Microsoft)"** table: domain, tenant, type, brand, and whether it matches the header's tenant.
