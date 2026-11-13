"""What in a hive / .reg means persistence, defence evasion or credential exposure.

Each rule is a key pattern (regex on the full path, case-insensitive), optionally a value
name and a condition on its data; it runs as one SQL query over the case database.
``suspicious`` (a regex on the data) turns a listing rule into a finding only when the
command looks like malware (script hosts, user-writable folders, encoded commands…).
``dedupe`` rules (the generic ones: what any value holds) run last and leave out the values
another rule already reported.
"""

from __future__ import annotations

from typing import Any

# Commands / paths that legitimate autoruns rarely use.
SUSPICIOUS_CMD = (r"(?i)(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|cmd(\.exe)?\s*/[ck]|certutil|"
                  r"bitsadmin|msiexec\s.*https?://|curl\s|wget\s|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|"
                  r"frombase64string|iex\b|invoke-expression|https?://|\\\\[\w.-]+\\|"
                  r"%(temp|tmp|public)%|\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|"
                  r"\\programdata\\[^\\]+\.(exe|dll|vbs|js|ps1|bat|cmd|hta)|\.(vbs|vbe|js|jse|hta|ps1|bat|cmd|scr|pif)\b)")

# Command lines that are malicious wherever they are stored (a script host with its tell-tale
# switches, a download cradle, AMSI / logging tampering, base64 of these words).
CMD_IN_VALUE = (r"(?i)(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/]{40,}={0,2}|-(w|windowstyle)\s+hid|"
                r"-(ep|executionpolicy)\s+(bypass|unrestricted)|\biex\s*\(|invoke-expression|downloadstring|"
                r"downloaddata|net\.webclient|invoke-webrequest|frombase64string|amsiutils|amsiinitfailed|"
                r"disablescriptblocklogging|cmd(\.exe)?\s+/[ckq]\s.{0,60}(powershell|pwsh|mshta|rundll32|regsvr32|"
                r"bitsadmin|certutil)|cG93ZXJzaGVsbA|SUVYI|SW52b2tlLUV4cHJlc3Npb24|RnJvbUJhc2U2NFN0cmluZw|"
                r"TmV0LldlYkNsaWVudA|RG93bmxvYWRTdHJpbmc|LWVuY29kZWRjb21tYW5k)")
# Script obfuscation (PowerShell / JScript / VBScript / cmd).
OBFUSCATION = (r"(?i)((\[char\]\s*\d{2,3}[^\[]{0,20}){5}|string\.fromcharcode\s*\(\s*\d{2,3}(\s*,\s*\d{2,3}){6}|"
               r"(chrw?\s*\(\s*\d{2,3}\s*\)[^c]{0,12}){5}|(`[a-z]){4}|(\^[a-z]){6}|assembly\]::load|"
               r"gzipstream|deflatestream|executeglobal|getobject\s*\(\s*[\"']script:|"
               r"(\\x[0-9a-f]{2}){8}|(%u[0-9a-f]{4}){4}|(-bxor\s*\d+.{0,40}){2})")
_RANSOM = ("locky|wannacry|wncry|cryptolocker|petya|notpetya|ryuk|conti|egregor|nephilim|blackmatter|lockbit|akira|"
           "powerranges|blackcat|qilin|djvu|phobos|dharma|deimos|makop|avaddon|avdn|ransomexx|hellokitty|abaddon|"
           "elibe|haron|lethal|clop|akiranew|akira_new|ransomhub|blacksuit|exx")
RANSOM_EXT_STRICT = "(" + _RANSOM + ")"
# Words that are ordinary file extensions elsewhere count only as a registered extension.
RANSOM_EXT = "(" + _RANSOM + "|play|hive|abyss|quantum|hydra|epic|matrix|crypt|medusa)"
_STR = ["REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ"]

_CV = r"\\(?:SOFTWARE\\)?(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion"
_NT = r"\\(?:SOFTWARE\\)?(?:WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion"
_CS = r"\\(?:SYSTEM\\)?(?:CurrentControlSet|ControlSet\d{3})"

RULES: list[dict[str, Any]] = [
    # --- persistence ---------------------------------------------------------------------
    {"id": "reg_autorun", "severity": "info", "attack": ["T1547.001"],
     "title": "Autorun entry (Run / RunOnce / RunServices / policies Run)",
     "key": _CV + r"\\(?:Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Policies\\Explorer\\Run)(?:\\\d+)?$",
     "suspicious": SUSPICIOUS_CMD, "suspicious_severity": "high"},
    {"id": "reg_winlogon", "severity": "high", "attack": ["T1547.004"],
     "title": "Winlogon Shell / Userinit / Taskman changed (runs at every logon)",
     "key": _NT + r"\\Winlogon$", "name": r"^(Shell|Userinit|Taskman|AppSetup)$",
     "not_data": r"(?i)^\s*(explorer\.exe|c:\\windows\\system32\\userinit\.exe,?|sihost\.exe)\s*$"},
    {"id": "reg_winlogon_notify", "severity": "high", "attack": ["T1547.004"],
     "title": "Winlogon notification package", "key": _NT + r"\\Winlogon\\Notify\\[^\\]+$"},
    {"id": "reg_ifeo_debugger", "severity": "high", "attack": ["T1546.012"],
     "title": "Image File Execution Options debugger (another program runs instead of / with the target)",
     "key": _NT + r"\\Image File Execution Options\\[^\\]+$", "name": r"^(Debugger|VerifierDlls)$",
     "not_data": r"(?i)^\s*\"?[^\"]*?(vsjitdebugger|windbg|ntsd|cdb)\.exe"},
    {"id": "reg_silent_process_exit", "severity": "high", "attack": ["T1546.012"],
     "title": "SilentProcessExit monitor process (runs when the target exits)",
     "key": _NT + r"\\SilentProcessExit\\[^\\]+$", "name": r"^MonitorProcess$"},
    {"id": "reg_appinit_dlls", "severity": "high", "attack": ["T1546.010"],
     "title": "AppInit_DLLs (a DLL loaded into every GUI process)",
     "key": _NT + r"\\Windows$", "name": r"^AppInit_DLLs$", "data": r"\S"},
    {"id": "reg_com_hijack", "severity": "medium", "attack": ["T1546.015"],
     "title": "COM server registered per user (HKCU wins over HKLM: COM hijacking)",
     "key": r"^HKCU\\Software\\Classes\\(?:WOW6432Node\\)?CLSID\\\{[0-9A-Fa-f-]{36}\}\\(?:InprocServer32|LocalServer32|TreatAs)$"},
    {"id": "reg_service", "severity": "info", "attack": ["T1543.003"],
     "title": "Service image path", "key": _CS + r"\\Services\\[^\\]+$", "name": r"^ImagePath$",
     "suspicious": SUSPICIOUS_CMD[:-1] + r"|\\appdata\\|\\desktop\\|\\downloads\\|\\programdata\\|"
                   r"^\"?[a-z]:\\[^\\]+\.(exe|dll|bat|cmd|ps1)|^\"?[a-z]:\\(tools|scripts|backup|bin|test|dump|cache)\\|"
                   r"\.(txt|log|tmp|dat|bak|png|jpe?g|gif|pdf)\b)", "suspicious_severity": "high"},
    {"id": "reg_service_dll", "severity": "high", "attack": ["T1543.003"],
     "title": "Service DLL outside System32 / Program Files",
     "key": _CS + r"\\Services\\[^\\]+(?:\\Parameters)?$", "name": r"^ServiceDll$",
     "not_data": r"(?i)^\s*\"?((%systemroot%|%windir%|[a-z]:\\windows)\\(system32|syswow64)\\|[a-z]:\\program files( \(x86\))?\\)"},
    {"id": "reg_service_masquerade", "severity": "medium", "attack": ["T1036.004", "T1543.003"],
     "title": "Service named like a Windows component that is not one",
     "key": _CS + r"\\Services\\[^\\]+$", "name": r"^(DisplayName|Description)$",
     "data": r"(?i)\b(windows|microsoft|system)\s?(helper|fix|cleaner|loader|patch|host manager)\b|\bsecurity\s?(fix|helper|patch)\b"},
    {"id": "reg_logon_script", "severity": "high", "attack": ["T1037.001"],
     "title": "Logon script (UserInitMprLogonScript)", "key": r"\\Environment$", "name": r"^UserInitMprLogonScript$"},
    {"id": "reg_screensaver", "severity": "medium", "attack": ["T1546.002"],
     "title": "Screensaver program set", "key": r"\\Control Panel\\Desktop$", "name": r"^SCRNSAVE\.EXE$",
     "not_data": r"(?i)\\system32\\[^\\]+\.scr$"},
    {"id": "reg_startup_folder", "severity": "medium", "attack": ["T1547.001"],
     "title": "Startup folder moved", "key": _CV + r"\\Explorer\\(?:User )?Shell Folders$",
     "name": r"^(Startup|Common Startup)$", "not_data": r"(?i)\\(Start Menu|Menú Inicio)\\Programs\\Startup$|%APPDATA%\\Microsoft\\Windows\\Start Menu"},
    {"id": "reg_office_persistence", "severity": "high", "attack": ["T1137"],
     "title": "Office add-in / test DLL / OPEN macro autoload",
     "key": r"\\Microsoft\\Office(?: test\\Special\\Perf|\\[\d.]+\\(?:Word|Excel|PowerPoint)\\(?:Options|Addins\\[^\\]+))$",
     "name": r"^(OPEN\d*|\(default\)|Manifest|FriendlyName|LoadBehavior)$"},
    {"id": "reg_netsh_helper", "severity": "medium", "attack": ["T1546.007"],
     "title": "Netsh helper DLL outside System32", "key": r"\\Microsoft\\NetSh$",
     "not_data": r"(?i)^[a-z0-9_]+\.dll$"},
    {"id": "reg_lsa_packages", "severity": "high", "attack": ["T1547.002", "T1547.005", "T1556.002"],
     "title": "LSA authentication / security / notification package added", "key": _CS + r"\\Control\\Lsa$",
     "name": r"^(Authentication Packages|Security Packages|Notification Packages)$",
     "not_data": r"(?i)^(msv1_0|scecli|rassfm|kerberos|wdigest|tspkg|pku2u|cloudap|schannel|negoexts|livessp|\"\"|\s|\n)*$"},
    {"id": "reg_windows_load", "severity": "high", "attack": ["T1547.001"],
     "title": "Windows Load / Run value (legacy autostart)", "key": _NT + r"\\Windows$", "name": r"^(Load|Run)$",
     "data": r"\S"},
    {"id": "reg_active_setup", "severity": "info", "attack": ["T1547.014"],
     "title": "Active Setup StubPath", "key": r"\\Microsoft\\Active Setup\\Installed Components\\[^\\]+$",
     "name": r"^StubPath$", "suspicious": SUSPICIOUS_CMD, "suspicious_severity": "high"},
    {"id": "reg_boot_execute", "severity": "high", "attack": ["T1547"],
     "title": "Session Manager BootExecute / SetupExecute changed (runs before Windows starts)",
     "key": _CS + r"\\Control\\Session Manager$",
     "name": r"^(BootExecute|BootExecuteNoPnpSync|SetupExecute|PlatformExecute)$",
     "data": r"\S", "not_data": r"(?is)^\s*(autocheck\s+autochk\s+(/q\s+/v\s+)?\*\s*)+$"},
    {"id": "reg_appcert_dlls", "severity": "high", "attack": ["T1546.009"],
     "title": "AppCertDLLs (loaded into every process that creates processes)",
     "key": _CS + r"\\Control\\Session Manager\\AppCertDlls$"},
    {"id": "reg_print_monitor", "severity": "high", "attack": ["T1547.010", "T1547.012"],
     "title": "Print monitor / print processor DLL with a path (loaded by the spooler as SYSTEM)",
     "key": _CS + r"\\Control\\Print\\(?:Monitors\\[^\\]+|Environments\\[^\\]+\\Print Processors\\[^\\]+)$",
     "name": r"^Driver$", "not_data": r"(?i)^[a-z0-9_.-]+\.dll$"},
    {"id": "reg_cmd_autorun", "severity": "high", "attack": ["T1546"],
     "title": "Command Processor AutoRun (runs with every cmd.exe)", "key": r"\\Microsoft\\Command Processor$",
     "name": r"^AutoRun$", "data": r"\S"},
    {"id": "reg_com_server_path", "severity": "high", "attack": ["T1546.015"],
     "title": "COM server in a user-writable folder or a share",
     "key": r"\\CLSID\\\{[0-9A-Fa-f-]{36}\}\\(?:InprocServer32|LocalServer32)$", "name": r"^\(default\)$",
     "data": r"(?i)(\\users\\|\\programdata\\|\\temp\\|^\s*\"?\\\\[\w.-]+\\|%(appdata|localappdata|temp|tmp|public|programdata|userprofile)%)",
     "not_data": r"(?i)\\appdata\\local\\microsoft\\(onedrive|teams|edge)\\"},
    {"id": "reg_com_script_moniker", "severity": "high", "attack": ["T1546.015", "T1218.010"],
     "title": "COM / TypeLib registration that runs a scriptlet (script: moniker, .sct)",
     "key": r"\\(?:TypeLib|CLSID|Interface)\\\{[0-9A-Fa-f-]{36}\}", "data": r"(?i)(^|[\s\"])script:\s*\S|\.sct\b|scrobj\.dll"},
    {"id": "reg_file_association", "severity": "info", "attack": ["T1546.001"],
     "title": "File association / protocol handler command", "key": r"\\Classes\\[^\\]+\\shell\\[^\\]+\\command$",
     "name": r"^\(default\)$", "suspicious": SUSPICIOUS_CMD, "suspicious_severity": "high", "dedupe": True},
    # --- defence evasion / impairment -----------------------------------------------------
    {"id": "reg_defender_exclusion", "severity": "high", "attack": ["T1562.001"],
     "title": "Microsoft Defender exclusion",
     "key": r"\\(?:Policies\\)?Microsoft\\Windows Defender\\Exclusions\\(?:Paths|Extensions|Processes|IpAddresses|TemporaryPaths)$"},
    {"id": "reg_defender_disabled", "severity": "high", "attack": ["T1562.001"],
     "title": "Microsoft Defender protection turned off",
     "key": r"\\(?:Policies\\)?Microsoft\\Windows Defender(?:\\Real-Time Protection|\\Spynet|\\Features)?$",
     "name": r"^(DisableAntiSpyware|DisableAntiVirus|DisableRealtimeMonitoring|DisableBehaviorMonitoring|"
             r"DisableOnAccessProtection|DisableScanOnRealtimeEnable|DisableIOAVProtection)$", "data": r"^1$"},
    {"id": "reg_uac_disabled", "severity": "high", "attack": ["T1548.002"],
     "title": "UAC turned off or silent elevation", "key": _CV + r"\\Policies\\System$",
     "name": r"^(EnableLUA|ConsentPromptBehaviorAdmin|PromptOnSecureDesktop)$", "data": r"^0$"},
    {"id": "reg_uac_bypass_handler", "severity": "high", "attack": ["T1548.002"],
     "title": "Per-user handler of an auto-elevating program (fodhelper / eventvwr / sdclt UAC bypass)",
     "key": r"^HKCU\\Software\\Classes\\(?:ms-settings|mscfile|exefile|Folder|Launcher\.SystemSettings|AppX[0-9a-z]+)\\shell\\(?:open|runas)\\command$"},
    {"id": "reg_script_logging_disabled", "severity": "high", "attack": ["T1562.002"],
     "title": "PowerShell script block / module logging or transcription turned off",
     "key": r"\\Policies\\Microsoft\\Windows\\PowerShell\\(?:ScriptBlockLogging|ModuleLogging|Transcription)$",
     "name": r"^Enable(ScriptBlockLogging|ScriptBlockInvocationLogging|ModuleLogging|Transcripting)$", "data": r"^0$"},
    {"id": "reg_amsi_disabled", "severity": "high", "attack": ["T1562.001"],
     "title": "AMSI turned off for Windows Script Host", "key": r"\\Microsoft\\Windows Script\\Settings$",
     "name": r"^AmsiEnable$", "data": r"^0$"},
    {"id": "reg_tools_disabled", "severity": "medium", "attack": ["T1112", "T1562"],
     "title": "Task Manager / Registry Editor / command prompt disabled by policy",
     "key": r"\\Policies\\(?:System|Microsoft\\Windows\\System)$",
     "name": r"^(DisableTaskMgr|DisableRegistryTools|DisableCMD)$", "data": r"^[12]$"},
    {"id": "reg_firewall_disabled", "severity": "high", "attack": ["T1562.004"],
     "title": "Windows Firewall turned off",
     "key": r"\\(?:SharedAccess\\Parameters\\FirewallPolicy|Policies\\Microsoft\\WindowsFirewall)\\(?:StandardProfile|PublicProfile|DomainProfile)$",
     "name": r"^EnableFirewall$", "data": r"^0$"},
    {"id": "reg_event_log_disabled", "severity": "high", "attack": ["T1562.002"],
     "title": "Event log / ETW autologger turned off",
     "key": _CS + r"\\(?:Services\\EventLog\\[^\\]+|Control\\WMI\\Autologger\\[^\\]+)$", "name": r"^(Start|Enabled)$",
     "data": r"^0$"},
    {"id": "reg_safeboot_service", "severity": "high", "attack": ["T1562.009"],
     "title": "Service added to Safe Mode boot (ransomware reboot into Safe Mode)",
     "key": _CS + r"\\Control\\SafeBoot\\(?:Minimal|Network)\\[^\\]+$"},
    # --- credentials / remote access ----------------------------------------------------------
    {"id": "reg_wdigest", "severity": "high", "attack": ["T1003.001", "T1112"],
     "title": "WDigest keeps clear-text passwords in memory", "key": _CS + r"\\Control\\SecurityProviders\\WDigest$",
     "name": r"^UseLogonCredential$", "data": r"^1$"},
    {"id": "reg_lsa_protection_off", "severity": "high", "attack": ["T1003.001"],
     "title": "LSA protection / Restricted Admin weakened", "key": _CS + r"\\Control\\Lsa$",
     "name": r"^(RunAsPPL|DisableRestrictedAdmin|DisableRestrictedAdminOutboundCreds|LmCompatibilityLevel)$",
     "data": r"^0$"},
    {"id": "reg_rdp_enabled", "severity": "medium", "attack": ["T1021.001"],
     "title": "Remote Desktop opened (connections allowed / NLA off)",
     "key": _CS + r"\\Control\\Terminal Server(?:\\WinStations\\RDP-Tcp)?$",
     "name": r"^(fDenyTSConnections|UserAuthentication|fSingleSessionPerUser)$", "data": r"^0$"},
    {"id": "reg_proxy", "severity": "medium", "attack": ["T1090"],
     "title": "Proxy / PAC set for the user (traffic through a proxy the attacker controls)",
     "key": _CV + r"\\Internet Settings$", "name": r"^(ProxyServer|AutoConfigURL)$", "data": r"\S"},
    # --- what values hold, wherever they are --------------------------------------------------
    {"id": "reg_command_in_value", "severity": "medium", "attack": ["T1059.001", "T1027"],
     "title": "Malicious-looking command line stored in a value",
     "key": r".", "types": _STR, "data": CMD_IN_VALUE, "dedupe": True},
    {"id": "reg_obfuscated_script", "severity": "medium", "attack": ["T1027"],
     "title": "Obfuscated script code stored in a value", "key": r".", "types": _STR, "data": OBFUSCATION,
     "dedupe": True},
    {"id": "reg_base64_blob", "severity": "low", "attack": ["T1027", "T1112"],
     "title": "Long base64 blob stored in a value (staged payload or configuration)",
     "key": r".", "types": _STR, "data": r"[A-Za-z0-9+/]{160,}={0,2}",
     "not_data": r"(AQAAANCMnd8|-----BEGIN |Security-SPP|SkuPpdConsumed|^[0-9A-Fa-f\s]+$)", "dedupe": True},
    {"id": "reg_long_string", "severity": "low", "attack": ["T1027"],
     "title": "Very long string without spaces stored in a value (embedded payload or configuration)",
     "key": r".", "types": ["REG_SZ", "REG_EXPAND_SZ"], "data": r"[!-~]{600,}",
     "not_data": r"(AQAAANCMnd8|-----BEGIN |[A-Za-z0-9+/]{160,})", "dedupe": True},
    {"id": "reg_wmi_consumer", "severity": "high", "attack": ["T1546.003"],
     "title": "WMI event consumer / binding text in a value",
     "key": r".", "types": _STR,
     "data": r"(?i)(CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding)"},
    {"id": "reg_ransomware_extension", "severity": "high", "attack": ["T1486"],
     "title": "File extension of a known ransomware family registered",
     "key": r"\\(?:Classes|Explorer\\FileExts)\\\." + RANSOM_EXT + r"$"},
    {"id": "reg_ransomware_file", "severity": "high", "attack": ["T1486"],
     "title": "Path to a file with a known ransomware extension",
     "key": r".", "types": _STR, "data": r"(?i)[\\/][^\\/\s]+\." + RANSOM_EXT_STRICT + r"\b"},
    {"id": "reg_root_certificate", "severity": "high", "attack": ["T1553.004"],
     "title": "Certificate added to a trusted root / publisher store (TLS interception, signed malware)",
     "key": r"\\Microsoft\\SystemCertificates\\(?:Root|AuthRoot|TrustedPublisher|CA)\\Certificates\\[0-9A-Fa-f]{40}$",
     "name": r"^Blob$", "source_kinds": ["reg"]},
]

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def sql_for(rule: dict[str, Any]) -> tuple[str, list[Any]]:
    """The query that lists what the rule matches: (src, key, name, data, last_write, op, label)."""
    where = ["regexp_matches(v.\"key\", ?, 'i')"]
    args: list[Any] = [rule["key"]]
    if rule.get("name"):
        where.append("regexp_matches(v.name, ?, 'i')")
        args.append(rule["name"])
    if rule.get("data"):
        where.append("regexp_matches(v.data, ?)")
        args.append(rule["data"])
    if rule.get("not_data"):
        where.append("NOT regexp_matches(v.data, ?)")
        args.append(rule["not_data"])
    if rule.get("types"):
        where.append("v.type IN (" + ",".join("?" for _ in rule["types"]) + ")")
        args += rule["types"]
    if rule.get("source_kinds"):
        where.append("s.kind IN (" + ",".join("?" for _ in rule["source_kinds"]) + ")")
        args += rule["source_kinds"]
    where.append("v.op = ''")
    sql = (f"""SELECT v.src, v."key", v.name, v.data, k.last_write, v.op, s.label, v.type FROM vals v
        JOIN sources s ON s.id = v.src LEFT JOIN keys k ON k.src = v.src AND k.path = v."key"
        WHERE {' AND '.join(where)} ORDER BY v.src, v."key", v.name LIMIT 500""")
    return sql, args


def keys_sql_for(rule: dict[str, Any]) -> tuple[str, list[Any]]:
    """Rules with only a key pattern also match keys that hold no values (an empty TreatAs, a SafeBoot entry)."""
    return ("""SELECT k.src, k.path, NULL, NULL, k.last_write, k.op, s.label, NULL FROM keys k
        JOIN sources s ON s.id = k.src WHERE regexp_matches(k.path, ?, 'i') AND k.op = '' ORDER BY k.src, k.path
        LIMIT 500""", [rule["key"]])
