"""What in a hive / .reg means persistence, defence evasion or credential exposure.

Each rule is a key pattern (regex on the full path, case-insensitive), optionally a value
name and a condition on its data; it runs as one SQL query over the case database.
``suspicious`` (a regex on the data) turns a listing rule into a finding only when the
command looks like malware (script hosts, user-writable folders, encoded commands…).
"""

from __future__ import annotations

from typing import Any

# Commands / paths that legitimate autoruns rarely use.
SUSPICIOUS_CMD = (r"(?i)(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|cmd(\.exe)?\s*/[ck]|certutil|"
                  r"bitsadmin|msiexec\s.*https?://|curl\s|wget\s|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|"
                  r"frombase64string|iex\b|invoke-expression|https?://|\\\\[\w.-]+\\|"
                  r"%(temp|tmp|public)%|\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|"
                  r"\\programdata\\[^\\]+\.(exe|dll|vbs|js|ps1|bat|cmd|hta)|\.(vbs|vbe|js|jse|hta|ps1|bat|cmd|scr|pif)\b)")

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
     "key": _NT + r"\\Image File Execution Options\\[^\\]+$", "name": r"^(Debugger|VerifierDlls)$"},
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
     "suspicious": SUSPICIOUS_CMD, "suspicious_severity": "high"},
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
