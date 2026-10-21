# Scripting detection rules

Behaviour-rule catalogue applied by the scripting engine over the **deobfuscated** code of every scripting language (JavaScript/JScript, PowerShell, VBScript, batch/cmd). Each rule is a finding you can mark, with its MITRE ATT&CK technique and the matching line as evidence. The catalogue lives in `docutracex/parsers/script_rules.py`; this file is a generated reference.

Languages run through their own deobfuscator first: JS cascade (multi-pass decode, `eval`/`Function` unfolding, Dean Edwards/JSFuck/AAEncode/JJEncode), PowerShell layers (`-enc`, `FromBase64String`, backticks, `[char]`, `-f`, IEX), VBScript (`.vbe` decode, `Chr`/`&`/`StrReverse`/`Execute`), batch (caret escaping, `set` indirection, `%VAR:~%`, delayed expansion), Python (`.py`: light `base64`/hex/`exec` decode; `.pyc`: decompiled with pycdc when provisioned, else dotted-call + string reconstruction from the bytecode, else raw string carving). The engine runs at the top level and inside the nested tree; the full source (original + deobfuscated) is dumped to `extracted/code/`.

- **JS**: 25 rules
- **PS**: 24 rules
- **VBScript**: 16 rules
- **Batch**: 9 rules
- **Python**: 19 rules
- **Java**: 16 rules

| Rule | Languages | Severity | ATT&CK | Behaviour |
|---|---|---|---|---|
| `bat_destructive` | Batch | high | T1485 | destructive / inhibits recovery |
| `bat_download` | Batch | high | T1105 | downloads a file |
| `bat_exec` | Batch | high | T1059.003 | command execution (cmd) |
| `bat_lolbin` | Batch | high | T1218 | invokes a LOLBin |
| `bat_persist` | Batch | high | T1547.001 | persistence (Run key / task / startup) |
| `bat_powershell` | Batch | high | T1059.001 | spawns PowerShell |
| `js_activex` | JS | high | T1059.007 | ActiveXObject/GetObject |
| `js_credential_exfil` | JS | high | T1056 | sends a password field |
| `js_dotnet_load` | JS, VBScript | high | T1620 | in-memory .NET load (DotNetToJScript) |
| `js_download` | JS | high | T1105 | network request |
| `js_file_write` | JS | high | T1105 | writes files (ADODB.Stream/FileSystemObject) |
| `js_heap_spray` | JS | high | T1055 | heap-spray / shellcode pattern |
| `js_html_smuggling` | JS | high | T1027.006 | builds a file in the browser (HTML smuggling) |
| `js_lolbin` | JS | high | T1218 | invokes a LOLBin / shell |
| `js_run_key` | JS | high | T1547.001 | Run-key persistence (registry) |
| `js_scheduled_task` | JS, VBScript | high | T1053.005 | creates a scheduled task |
| `js_wmi` | JS, VBScript | high | T1047 | WMI (winmgmts) access |
| `js_wscript_shell` | JS | high | T1059.001 | runs commands (WScript.Shell/ShellExecute/Run) |
| `pdf_js_exploit_api` | JS | high | T1203 | PDF: API used by known Reader exploits |
| `pdf_js_export_launch` | JS | high | T1203 | PDF: extracts and launches an attachment |
| `ps_addtype` | PS | high | T1059.001 | compiles inline code (Add-Type/DllImport) |
| `ps_amsi` | PS | high | T1562.001 | AMSI bypass |
| `ps_bits` | PS | high | T1197 | BITS transfer |
| `ps_cred_access` | PS | high | T1003 | credential access |
| `ps_defender_off` | PS | high | T1562.001 | disables Defender |
| `ps_download` | PS | high | T1105 | downloads / connects out |
| `ps_encoded` | PS | high | T1027 | base64-encoded command |
| `ps_etw_patch` | PS | high | T1562.006 | ETW patching |
| `ps_exec` | PS | high | T1059.001 | process / in-memory execution |
| `ps_iex` | PS | high | T1059.001 | executes a dynamic string (IEX) |
| `ps_keylog` | JS, PS, VBScript | high | T1056.001 | keylogging API |
| `ps_lolbin` | PS | high | T1218 | invokes a LOLBin |
| `ps_reflection_load` | PS | high | T1620 | reflective .NET assembly load |
| `ps_service` | PS | high | T1543.003 | creates a service |
| `ps_shellcode` | PS, VBScript | high | T1055 | memory-injection API |
| `ps_wmi_persist` | PS | high | T1546.003 | WMI event-subscription persistence |
| `vbs_activex` | VBScript | high | T1059.005 | creates/uses a COM object |
| `vbs_download` | VBScript | high | T1105 | network request / stream |
| `vbs_exec` | VBScript | high | T1059.005 | executes a dynamic string |
| `vbs_file` | VBScript | high | T1105 | writes files |
| `vbs_lolbin` | VBScript | high | T1218 | invokes a LOLBin / shell |
| `vbs_run_key` | VBScript | high | T1547.001 | Run-key persistence (registry) |
| `vbs_shell` | VBScript | high | T1059.005 | runs commands (WScript.Shell/Run) |
| `bat_defense_evasion` | Batch | medium | T1562.001 | disables defences / hides |
| `bat_discovery` | Batch | medium | T1082 | host discovery |
| `bat_obfusc` | Batch | medium | T1027 | batch obfuscation primitives |
| `js_atob` | JS | medium | T1140 | base64 decoding (atob) |
| `js_document_write` | JS | medium | T1059.007 | document.write |
| `js_eval` | JS | medium | T1059.007 | eval() of dynamic code |
| `js_fromcharcode` | JS | medium | T1140 | String.fromCharCode |
| `js_function_ctor` | JS | medium | T1059.007 | Function constructor |
| `js_redirect` | JS | medium | T1105 | navigates / redirects |
| `js_sleep` | JS, VBScript | medium | T1497.003 | long sleep (sandbox evasion) |
| `js_unescape` | JS | medium | T1140 | unescape()/percent-decoding |
| `pdf_js_launch_url` | JS | medium | T1204.002 | PDF: opens a URL / submits data |
| `ps_antivm` | PS | medium | T1497.001 | VM / sandbox detection |
| `ps_clear_logs` | PS | medium | T1070.001 | clears event logs |
| `ps_discovery` | PS | medium | T1082 | host / domain discovery |
| `ps_dns` | PS | medium | T1071.004 | DNS query / possible exfil |
| `ps_hidden` | PS | medium | T1564.003 | stealth execution flags |
| `ps_obfusc` | PS | medium | T1027 | obfuscation primitives |
| `ps_persist` | PS | medium | T1547.001 | persistence (registry / scheduled task) |
| `ps_sleep` | PS | medium | T1497.003 | long sleep (sandbox evasion) |
| `vbs_antivm` | VBScript | medium | T1497.001 | VM / sandbox detection |
| `vbs_discovery` | JS, VBScript | medium | T1082 | host discovery |
| `vbs_obfusc` | VBScript | medium | T1027 | obfuscation primitives |

Plus `script_attack_chain` (high, T1059): emitted when a single script combines two or more distinct high-risk behaviour families (e.g. download + execution), and the per-language `*_deobfuscated` finding noting the script was deobfuscated before analysis.

## Emulation / deobfuscation engines

Beyond the static rules above, the scripting engine uses real analysis tools (provisioned on the portables, invoked as separate processes):

- **webcrack** (JavaScript, portable Node): flattens obfuscator.io string-array/rotator and control-flow obfuscation and unpacks bundles, re-emitting readable code *before* the rules, the IOC scan and the STPyV8 sandbox run — so detections see the real payload. Falls back to the pure-Python cascade when not provisioned.
- **box-ps** (PowerShell, portable PowerShell Core): emulates the deobfuscated PowerShell with overridden cmdlets and records behaviour. Its actions become findings — `boxps_network`, `boxps_file`, `boxps_exec`, `boxps_inject`, `boxps_registry`, `boxps_persist` — shown in the PowerShell tab's Sandbox section. This brings PowerShell to parity with JavaScript (STPyV8) and VBA (ViperMonkey).
- **pycdc** (Python, built from source): decompiles `.pyc` back to readable source before the rules run. When it is not provisioned the Python engine still reconstructs dotted calls and strings from the bytecode, so detections keep working — the decompiler only improves readability.
- **CFR** (Java, a jar run with any host JVM): decompiles suspicious `.class` files to readable Java before the rules run; decompilation is budgeted to classes that already look suspicious from the constant pool. Without CFR (or a JVM) the Java engine matches on the constant pool's class/method references and strings, so detections keep working.

## Shortcut and binary families

Two families carry executable intent in structure rather than in a script body; they are parsed for that structure and **their embedded command line is fed to the scripting engine above** (deobfuscated and matched against the full catalogue), so a shortcut or MSI that launches PowerShell lights up the same `ps_*` rules as a standalone script.

**Shortcuts** (`.lnk` via LnkParse3; `.url`/`.website` as INI text), module `shortcut`:

| Rule | Severity | ATT&CK | Behaviour |
|---|---|---|---|
| `shortcut_double_extension` | high | T1036.007 | name disguised as a document (`invoice.pdf.lnk`) |
| `lnk_lolbin_target` | high | T1204.002 | shortcut target is a LOLBin / shell |
| `lnk_hidden_window` | medium | T1564.003 | hidden/minimised window |
| `lnk_icon_spoof` | high | T1036.008 | icon disguises the shortcut as a document |
| `lnk_appended_payload` | high | T1027.009 | unusually large `.lnk` (possible appended payload) |
| `url_remote_file_target` | high | T1105 | `.url` points to a remote file (WebDAV/SMB) |
| `url_protocol_handler` | high | T1218 | abused protocol handler (`search-ms:`, `ms-…:`…) |
| `url_unc_icon_ntlm` | high | T1187 | `IconFile` on a UNC path (forced SMB auth / NTLM theft) |
| `url_executable_target` | high | T1204.001 | points to an executable/script payload |

**Binaries / PE** (`.msi` via olefile; PE images triaged), module `msi`:

| Rule | Severity | ATT&CK | Behaviour |
|---|---|---|---|
| `msi_custom_action` | high | T1218.007 | `CustomAction` table — runs code during install |
| `msi_install_sequence` | medium | — | install-sequence tables schedule custom actions |
| `msi_embedded_binary` | high | T1027.009 | embedded `Binary`/stream payload(s) |
| `msi_embedded_cab` | medium | T1027 | embedded CAB archive(s) |
| `msi_lolbin_string` | high | T1218.007 | installer string references a LOLBin / shell |
| `msi_suspicious_api` | medium | T1059 | download/exec indicators in the installer strings |
| `pe_image` | info | T1204.002 | PE image categorised/triaged (no static unpacking) |
| `pe_not_pe` | medium | T1036 | PE extension without an `MZ` header (masquerade) |

**PyInstaller** (a frozen `.exe` in the binary family), module `pyinstaller`: the CArchive and PYZ are unpacked and each module written back as a `.pyc` for the Python engine (flat **Python** tab) and the nested tree.

| Rule | Severity | ATT&CK | Behaviour |
|---|---|---|---|
| `pyinstaller_bundle` | medium | — | PyInstaller-frozen executable (Python version, bundled runtime, entry count) |
| `pyinstaller_entry_script` | medium | — | entry script(s) recovered and analysed as Python |

## Python rules

Applied by the Python engine to ``.py`` source and to ``.pyc`` recovered by decompilation/disassembly (loose files, and the modules unpacked from a PyInstaller `.exe`). `py_suspicious_imports` (medium) also fires when only raw strings survive and two or more risky modules are referenced; `py_pyc_recovered` (info) records how a `.pyc` was recovered.

| Rule | Severity | ATT&CK | Behaviour |
|---|---|---|---|
| `py_exec` | high | T1059.006 | executes dynamic code (eval/exec/compile) |
| `py_subprocess` | high | T1059.006 | spawns a process (subprocess/os) |
| `py_lolbin` | high | T1218 | invokes a Windows LOLBin / shell |
| `py_download` | high | T1105 | downloads / connects out (urllib/requests/http) |
| `py_persist_registry` | high | T1547.001 | persistence (Run key / registry) |
| `py_persist_os` | high | T1547 | persistence (startup / task / cron) |
| `py_packed_code` | high | T1027 | loads packed/serialised code (marshal/pickle/zlib) |
| `py_inject` | high | T1055 | memory injection via ctypes / WinAPI |
| `py_shellcode` | high | T1055 | embedded shellcode blob (`\x` escapes) |
| `py_credentials` | high | T1555 | credential access (DPAPI / browser stores) |
| `py_disable_defender` | high | T1562.001 | disables AV / Defender |
| `py_shell_true` | medium | T1059 | `shell=True` command execution |
| `py_socket` | medium | T1095 | raw socket (possible C2) |
| `py_b64` | medium | T1140 | base64 / hex decoding |
| `py_dynamic_import` | medium | T1027 | dynamic import / attribute resolution |
| `py_discovery` | medium | T1082 | host / user discovery |
| `py_clr` | medium | T1620 | in-memory .NET load (pythonnet/CLR) |
| `py_antivm` | medium | T1497.001 | VM / sandbox / debugger detection |
| `py_sleep` | medium | T1497.003 | long sleep (sandbox evasion) |

## Java rules

Applied by the Java engine to `.class` files (matched on the constant pool — referenced classes/methods and string literals — and, with **CFR** provisioned, on the decompiled source) and to JSP scriptlet text. `.jar`/`.war`/`.ear` are unpacked and recursed; the module also surfaces `java_main_class`/`java_signed`/`java_web_descriptor` (info), `java_serialized_object` (high, `AC ED 00 05` stream magic) and the MANIFEST/web.xml/signing metadata.

| Rule | Severity | ATT&CK | Behaviour |
|---|---|---|---|
| `java_exec` | high | T1059 | runs OS commands (Runtime/ProcessBuilder) |
| `java_script_engine` | high | T1059.007 | dynamic script eval (ScriptEngine/Nashorn) |
| `java_defineclass` | high | T1620 | in-memory class loading (defineClass/ClassLoader/Unsafe) |
| `java_download` | high | T1105 | network download / connection |
| `java_jndi` | high | T1190 | JNDI lookup (Log4Shell / injection) |
| `java_deserialization` | high | T1190 | Java deserialization gadget |
| `java_agent` | high | T1574 | Java agent (premain / Instrumentation) |
| `java_reflection` | medium | T1620 | reflection (Class.forName / setAccessible) |
| `java_socket` | medium | T1095 | raw socket (possible C2) |
| `java_crypto` | medium | T1027 | crypto (payload decryption) |
| `java_base64` | medium | T1140 | base64 decoding |
| `java_native_load` | medium | T1129 | loads native code (System.load / JNI) |
| `java_disable_security` | medium | T1562 | disables the SecurityManager |
| `java_webshell_input` | medium | T1505.003 | reads attacker input (JSP/servlet) |
| `java_jsp_scriptlet` | medium | T1505.003 | JSP scriptlet / expression |
| `java_file_write` | medium | T1105 | writes files (FileOutputStream/Files) |
