"""Suspicious Windows command lines stored in registry values (from gmzpt's
CUSTOM_REG_GENERIC_SUSPICIOUS_WINDOWS_COMMANDS v2, as the module's own rules).

A value can hold a command that never runs from where it is (a task's action, a tool's
configuration, a staged payload) or runs from an autostart key. Every string value is checked:

- **critical** indicators (high signal, almost no false positive) make a finding on their own;
- **medium** ones only count in pairs: two or more different ones in the same value;
- the **allowlist** (SCCM, Defender's MpCmdRun, Windows Update, management suites) clears a value.

Families: PowerShell, cmd.exe, LOLBins, WSH, scheduled tasks, net / sc / reg, credential
dumping, lateral movement, defence evasion, persistence by command, discovery, exfiltration,
tunnelling / C2 and ransomware.
"""

from __future__ import annotations

import re
from typing import Any

# id: (label, ATT&CK, regex) — case-insensitive, searched in the value's text.
CRITICAL: dict[str, tuple[str, str, str]] = {
    "ps_encoded": ("PowerShell with an encoded command", "T1059.001",
                   r"(powershell|pwsh)(\.exe)?\s+.{0,30}(-enc|-encodedcommand)\s+[A-Za-z0-9+/]{20,}={0,2}"),
    "ps_amsi": ("AMSI bypass", "T1562.001",
                r"(amsiInitFailed|AmsiScanBuffer|AmsiUtils|amsi\.dll|System\.Runtime\.InteropServices\.Marshal.*amsi)"),
    "ps_reflect": ("assembly loaded in memory (reflection)", "T1620",
                   r"(\[System\.Reflection\.Assembly\]::Load|\[Reflection\.Assembly\]::LoadFrom|Add-Type\s+-AssemblyName|Assembly\.Load\s*\()"),
    "ps_decompress": ("compressed payload unpacked in memory", "T1027",
                      r"(GzipStream|DeflateStream|MemoryStream.*FromBase64|BinaryFormatter|IO\.Compression)"),
    "ps_bloodhound": ("BloodHound / SharpHound", "T1087.002",
                      r"(Invoke-BloodHound|SharpHound|bloodhound-python|CollectionMethod\s+(All|DCOnly|Session|LoggedOn))"),
    "ps_kerberos": ("Kerberoasting / AS-REP roasting", "T1558.003",
                    r"(Invoke-Kerberoast|Get-DomainSPNTicket|Invoke-ASREPRoast|Get-DomainUser\s+.*-SPN|Request-SPNTicket|\bRubeus\b|Invoke-Rubeus)"),
    "ps_pth": ("pass-the-hash / pass-the-ticket", "T1550.002",
               r"(Invoke-TheHash|Invoke-SMBExec|Invoke-WMIExec|mimikatz.*pth|sekurlsa::pth|kerberos::ptt|kerberos::golden)"),
    "lol_regsvr32": ("regsvr32 scriptlet (squiblydoo)", "T1218.010",
                     r"regsvr32(\.exe)?\s+.{0,80}(/s\s+/n\s+/u\s+/i:|/i:http|\.sct|scrobj\.dll)"),
    "lol_rundll32": ("rundll32 running script or an internal routine (comsvcs MiniDump, url.dll…)", "T1218.011",
                     r"rundll32(\.exe)?\s+.{0,80}(javascript:|shell32\.dll.*ShellExec|url\.dll.*OpenURL|pcwutl\.dll|zipfldr\.dll|"
                     r"advpack\.dll.*LaunchINFSection|ieadvpack\.dll|shdocvw\.dll|dfshim\.dll|comsvcs\.dll.*MiniDump|comsvcs\.dll.*#24)"),
    "lol_mshta": ("mshta running remote or inline script", "T1218.005",
                  r"mshta(\.exe)?\s+.{0,60}(http|vbscript:|javascript:|about:blank|\.hta|\.sct)"),
    "lol_cmstp": ("cmstp with an INF / scriptlet (UAC bypass)", "T1218.003",
                  r"cmstp(\.exe)?\s+.{0,80}(/s|/ns|/au)\s+.{0,80}\.(inf|sct|hta)"),
    "lol_workflow": ("Microsoft.Workflow.Compiler running C#", "T1127",
                     r"Microsoft\.Workflow\.Compiler(\.exe)?\s+.{0,200}\.(xoml|rules)"),
    "lol_mavinject": ("mavinject DLL injection", "T1218.013", r"mavinject(\.exe)?\s+\d{1,8}\s+/injectrunning"),
    "lol_msdt": ("msdt / ms-msdt (Follina)", "T1218", r"msdt(\.exe)?\s+.{0,200}(/id\s+PCWDiagnostic|ms-msdt:|/skip\s+TRUE)|ms-msdt:"),
    "lol_xsl": ("wmic XSL script processing", "T1220", r"wmic(\.exe)?.{0,100}/format:.{0,60}(http|\\\\|\.xsl)"),
    "lol_diskshadow": ("diskshadow running a script / command", "T1006",
                       r"diskshadow(\.exe)?\s+.{0,80}(/s\s+.{0,80}\.(txt|dsh)|exec\s+.{0,200}(cmd|powershell))"),
    "cred_comsvcs": ("LSASS dump through comsvcs.dll", "T1003.001", r"comsvcs(\.dll)?.{0,60}(MiniDump|#24)\s+\d{1,8}"),
    "cred_ntdsutil": ("ntdsutil copying NTDS.dit", "T1003.003", r"ntdsutil(\.exe)?.{0,100}(activate\s+instance\s+ntds|\bifm\b|create\s+full)"),
    "cred_vss_ntds": ("shadow copy of C: (NTDS.dit / SAM theft)", "T1003.003", r"vssadmin(\.exe)?\s+create\s+shadow\s+/for=C:"),
    "cred_tools": ("credential dumping tool", "T1003",
                   r"\b(wce|fgdump|pwdump[0-9]?|gsecdump)(\.exe)?\b|\blsadump\b|\bcachedump\b"),
    "cred_impacket": ("Impacket", "T1003",
                      r"\b(secretsdump|GetNPUsers|GetUserSPNs|smbexec|wmiexec|dcomexec|atexec)(\.py|\.exe)?\b|\bpsexec\.py\b"),
    "cred_shadow_copy": ("reads from a volume shadow copy (NTDS / SAM)", "T1003.003",
                         r"(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy|\\\\\.\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy|"
                         r"HarddiskVolumeShadowCopy\d+\\Windows\\(NTDS|System32\\config))"),
    "reg_sam": ("reg save of SAM / SYSTEM / SECURITY", "T1003.002", r"reg(\.exe)?\s+save\s+HKLM\\(SAM|SYSTEM|SECURITY)\b"),
    "reg_run": ("reg add to an execution key (Run, Winlogon, IFEO…)", "T1547.001",
                r"reg(\.exe)?\s+add.{0,200}(\\Run\b|RunOnce|Winlogon|AppInit|BootExecute|Userinit|SilentProcessExit|Debugger)"),
    "per_wmi_sub": ("WMI event subscription", "T1546.003",
                    r"wmic(\.exe)?\s+.{0,80}/namespace:\\\\root\\subscription.{0,200}(CommandLineEventConsumer|ActiveScriptEventConsumer|__EventFilter|__FilterToConsumerBinding)"),
    "per_ifeo": ("reg add of an IFEO debugger", "T1546.012", r"reg(\.exe)?\s+add.{0,100}Image\s+File\s+Execution\s+Options\\.{0,80}Debugger"),
    "per_spe": ("reg add of a SilentProcessExit monitor", "T1546.012", r"reg(\.exe)?\s+add.{0,100}SilentProcessExit\\.{0,80}(MonitorProcess|ReportingMode)"),
    "per_appcert": ("reg add of an AppCertDLL in a user-writable folder", "T1546.009",
                    r"reg(\.exe)?\s+add.{0,100}AppCertDLLs.{0,100}(C:\\(Temp|Users|ProgramData)|\\\\)"),
    "per_portmon": ("reg add of a port monitor DLL in a user-writable folder", "T1547.010",
                    r"reg(\.exe)?\s+add.{0,100}Print\\Monitors\\.{0,80}Driver.{0,100}(C:\\(Temp|Users|ProgramData)|\\\\)"),
    "ev_patch": ("AMSI / ETW patching", "T1562.001",
                 r"(VirtualProtect.*amsi|WriteProcessMemory.*amsi|NtTraceControl|EtwEventWrite.*patch|Suspend-Thread.*ETW)"),
    "ev_inject": ("process injection APIs", "T1055",
                  r"\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtQueueApcThread|SetThreadContext|RtlCreateUserThread|NtCreateSection|NtMapViewOfSection)\b"),
    "ev_reflective": ("reflective DLL / PE injection", "T1620", r"(ReflectiveDLLInjection|Invoke-ReflectivePEInjection|LoadLibraryR|ReflectiveLoader)"),
    "shadow_delete": ("shadow copies / recovery deleted (ransomware)", "T1490",
                      r"(vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage.{0,60}/maxsize=)|wmic(\.exe)?\s+shadowcopy\s+delete|"
                      r"Win32_ShadowCopy.*Delete\(\)|wbadmin(\.exe)?\s+delete\s+(catalog|backup)|"
                      r"bcdedit(\.exe)?\s+/set\s+.{0,60}(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))"),
    "shadow_backup": ("Windows backups / restore points removed", "T1490",
                      r"(wbadmin(\.exe)?\s+delete\s+(backup|catalog)|Remove-WBBackupSet|Disable-ComputerRestore)"),
    "tun_c2_art": ("Cobalt Strike / Meterpreter artefact (default pipe, beacon DLL)", "T1071",
                   r"(named pipe.*meterpreter|\\\\\.\\pipe\\(msagent_|postex_|status_|MSSE-)|beacon\.(x64|x86)\.dll|cobaltstrike)"),
    "net_admin": ("user added to the Administrators group", "T1098", r"net1?(\.exe)?\s+localgroup\s+(administrators|administradores).{0,60}/add"),
    "net_user": ("local user created / enabled", "T1136.001", r"net1?(\.exe)?\s+user\s+[A-Za-z0-9_$\-]{1,32}\s+.{0,60}(/add|/active:yes)"),
    "schtask_create": ("scheduled task running an interpreter / LOLBin", "T1053.005",
                       r"schtasks(\.exe)?\s+.{0,30}/create.{0,200}/tr\s+.{0,200}(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)"),
    "sc_binpath": ("service whose binPath runs an interpreter or a user-writable folder", "T1543.003",
                   r"sc(\.exe)?\s+.{0,80}binpath=\s*[\"']?.{0,200}(powershell|cmd|mshta|wscript|rundll32|regsvr32|certutil|C:\\(Temp|Users|ProgramData))"),
}

MEDIUM: dict[str, tuple[str, str, str]] = {
    "ps_evasion": ("PowerShell evasion flags", "T1059.001",
                   r"(powershell|pwsh)(\.exe)?\s+.{0,60}(-nop\b|-noprofile|-noninteractive|-nologo|-noexit|-w\s+hid|-windowstyle\s+hid|"
                   r"-ep\s+(bypass|unrestricted)|-executionpolicy\s+(bypass|unrestricted))"),
    "ps_download": ("download cradle", "T1105",
                    r"(New-Object\s+Net\.WebClient|Invoke-WebRequest|\biwr\s|DownloadString\s*\(|DownloadFile\s*\(|DownloadData\s*\(|Start-BitsTransfer)"),
    "ps_mem_exec": ("in-memory execution (IEX, Invoke-Command, scriptblock)", "T1059.001",
                    r"(\bIEX\s*\(|Invoke-Expression\s*\(|Invoke-Command\s*\(|\bicm\s+|&\s*\(\s*\[scriptblock\]|\.invoke\s*\()"),
    "ps_wmi": ("WMI from PowerShell", "T1047", r"(Get-WmiObject|\bgwmi\s|Invoke-WmiMethod|New-Object\s+System\.Management\.)"),
    "ps_creds": ("credential access from PowerShell", "T1003",
                 r"(Get-Credential|ConvertTo-SecureString|NetworkCredential|PSCredential|sekurlsa|kerberos::|mimikatz|Invoke-Mimikatz)"),
    "ps_persist": ("persistence from PowerShell (Run key, scheduled task)", "T1547.001",
                   r"(New-ItemProperty.*\bRun\b|Set-ItemProperty.*\bRun\b|Register-ScheduledTask|New-ScheduledTask|schtasks.*/create)"),
    "ps_remote": ("PowerShell remoting", "T1021.006",
                  r"(Enter-PSSession|New-PSSession|Invoke-Command\s+-ComputerName|Enable-PSRemoting|Set-WSManQuickConfig|winrm\s+quickconfig)"),
    "ps_constrained": ("execution policy / language mode bypass", "T1059.001",
                       r"(Set-ExecutionPolicy|__PSLockdownPolicy|LanguageMode.*FullLanguage|Set-MpPreference\s+-Disable)"),
    "ps_defender": ("Defender tampering from PowerShell", "T1562.001",
                    r"(Set-MpPreference\s+.{0,60}(-Disable[A-Za-z]+\s+\$true|-ExclusionPath|-ExclusionProcess|-ExclusionExtension)|"
                    r"Add-MpPreference\s+.{0,60}-Exclusion|Remove-MpThreat)"),
    "ps_applocker": ("AppLocker policy", "T1562", r"(Get-AppLockerPolicy|Set-AppLockerPolicy|Test-AppLockerPolicy|\[Microsoft\.PowerShell\]::GetConsoleWindow)"),
    "ps_token": ("token / privilege manipulation", "T1134",
                 r"(AdjustTokenPrivileges|OpenProcessToken|DuplicateToken|ImpersonateLoggedOnUser|Invoke-TokenManipulation|Enable-Privilege)"),
    "ps_ad_recon": ("Active Directory reconnaissance", "T1087.002",
                    r"(Get-ADUser|Get-ADGroup|Get-ADComputer|Get-ADDomain|Get-ADForest|Get-ADTrust|Get-ADGroupMember|Invoke-ACLScanner|"
                    r"Find-LocalAdminAccess|Invoke-EnumerateLocalAdmin)"),
    "ps_keylog": ("keylogging / clipboard capture", "T1056.001",
                  r"(GetAsyncKeyState|SetWindowsHookEx|GetClipboard|Get-Clipboard|System\.Windows\.Forms\.Clipboard)"),
    "cmd_lolbin": ("cmd.exe launching a LOLBin / interpreter", "T1059.003",
                   r"cmd(\.exe)?\s+/[cqks].{0,80}(powershell|pwsh|mshta|rundll32|regsvr32|bitsadmin|certutil|wscript|cscript|msiexec|"
                   r"installutil|cmstp|xwizard|pcalua|forfiles|\bbash\b|\bwsl\b)"),
    "cmd_obf": ("cmd.exe caret obfuscation", "T1027.010", r"cmd(\.exe)?\s+/[cq].{0,30}(\^.){4,}"),
    "cmd_seta": ("cmd set /a string rebuilding", "T1027.010", r"cmd(\.exe)?.{0,20}set\s+/a\s+.{0,60}[+\-*/%^]"),
    "cmd_redirect": ("cmd output redirected to a temporary / user folder", "T1074.001",
                     r"cmd(\.exe)?\s+/[cq].{0,200}>\s*(C:\\(Temp|Users|ProgramData|Windows\\Temp)|%TEMP%|%APPDATA%)"),
    "cmd_env_obf": ("environment-variable obfuscation", "T1027", r"(set\s+[A-Za-z_]{1,10}=.{1,20}&&.{0,20}%[A-Za-z_]{1,10}%|%COMSPEC%|%SystemRoot%\\system32\\cmd)"),
    "cmd_delayed": ("delayed expansion (!var!)", "T1027", r"(cmd.{0,20}/v:on|setlocal\s+enabledelayedexpansion)"),
    "lol_certutil": ("certutil download / decode", "T1105", r"certutil(\.exe)?\s+.{0,60}(-urlcache|-decode|-encode|-decodehex|-f\s+http|-split)"),
    "lol_bits": ("bitsadmin transfer", "T1197", r"bitsadmin(\.exe)?\s+.{0,60}(/transfer|/addfile|/setnotifycmdline|/resume|/SetCustomHeaders)"),
    "lol_msiexec": ("msiexec installing from the network", "T1218.007",
                    r"msiexec(\.exe)?\s+.{0,80}(/q.*http|http.*/q|/i\s+http|/package\s+http|/y\s+|/z\s+)"),
    "lol_wmic": ("wmic process creation / shadow deletion", "T1047",
                 r"wmic(\.exe)?\s+.{0,100}(process\s+call\s+create|/node:.{0,60}process|os\s+get\s+/format|shadowcopy\s+delete|/format:.{0,60}(xsl|http))"),
    "lol_forfiles": ("forfiles indirect execution", "T1202", r"forfiles(\.exe)?\s+.{0,100}/c\s+.{0,80}(cmd|powershell|mshta|wscript|rundll32)"),
    "lol_wsl": ("bash / wsl proxy execution", "T1202", r"\b(bash|wsl)(\.exe)?\s+.{0,60}(-c\s+|--exec\s+).{0,100}(curl|wget|\bnc\b|python|perl|ruby|php|\bsh\s)"),
    "lol_uac_bypass": ("auto-elevating binary launching something (UAC bypass)", "T1548.002",
                       r"\b(pcalua|xwizard|eventvwr|fodhelper|sdclt|cmstp|diskcleanup|wsreset|computerdefaults|slui|dccw)(\.exe)?\s+.{0,80}(http|\.exe|\.dll|\.hta|\.sct|/k|/c)"),
    "lol_installutil": ("InstallUtil loading an assembly", "T1218.004", r"InstallUtil(\.exe)?\s+.{0,80}(/logfile=|/LogToConsole=false|/U\s+)"),
    "lol_msdeploy": ("msdeploy sync", "T1218", r"msdeploy(\.exe)?\s+.{0,100}(-verb:sync|-source:package|-dest:auto)"),
    "lol_aspnet": ("aspnet_compiler from a user folder", "T1127", r"aspnet_compiler(\.exe)?\s+.{0,80}(-v\s+/|-p\s+.{0,60}(Temp|AppData|ProgramData))"),
    "lol_appv": ("App-V publishing server proxy", "T1216.002",
                 r"(syncappvpublishingserver|appsyncpublishingserver)(\.exe|\.vbs|\.ps1)?\s+.{0,200}(http|\\\\|powershell|IEX)"),
    "lol_taef": ("TAEF te.exe loading a DLL", "T1218", r"\bte(\.exe)?\s+.{0,100}\.(dll|exe).{0,60}/inproc"),
    "lol_inf": ("infdefaultinstall running an INF", "T1218", r"infdefaultinstall(\.exe)?\s+.{0,200}\.(inf|sct)"),
    "lol_odbcconf": ("odbcconf REGSVR", "T1218.008", r"odbcconf(\.exe)?\s+.{0,80}(/a\s+\{regsvr|/f\s+.{0,60}\.rsp)"),
    "lol_esentutl": ("esentutl copy (locked files / UNC)", "T1105", r"esentutl(\.exe)?\s+.{0,80}(/y\s+.{0,60}(http|\\\\)|/cp|/o\b)"),
    "lol_expand": ("expand from a share / URL", "T1105", r"\bexpand(\.exe)?\s+.{0,80}(\\\\[A-Za-z0-9_.\-]{2,64}\\|http).{0,80}\.(exe|dll|cab)"),
    "lol_extrac32": ("extrac32 staging", "T1105", r"extrac32(\.exe)?\s+.{0,80}(/y\s+|/e\s+|http|\\\\).{0,80}\.(cab|exe|dll)"),
    "lol_findstr": ("findstr reading from a share", "T1105", r"findstr(\.exe)?\s+.{0,60}/v\s+.{0,60}\\\\[A-Za-z0-9_.\-]{2,64}\\"),
    "lol_replace": ("replace.exe copying from a share", "T1105", r"\breplace(\.exe)?\s+\\\\[A-Za-z0-9_.\-]{2,64}\\.{0,200}/a"),
    "lol_hh": ("HTML Help running remote content", "T1218.001", r"\bhh(\.exe)?\s+.{0,80}(http|\.chm|javascript:|mk:@MSITStore)"),
    "lol_mmc": ("mmc loading a snap-in from a share / URL", "T1218.014", r"\bmmc(\.exe)?\s+.{0,80}(/a\s+|\.msc\s+|http|\\\\)"),
    "lol_xbap": ("PresentationHost running an XBAP", "T1218", r"PresentationHost(\.exe)?\s+.{0,80}(http|\.xbap)"),
    "lol_control": ("control.exe loading a CPL / DLL from a user folder or share", "T1218.002",
                    r"\bcontrol(\.exe)?\s+.{0,80}(C:\\(Temp|Users|ProgramData)|\\\\[A-Za-z0-9_.\-]{2,64}\\).{0,80}\.(dll|cpl)"),
    "lol_regasm": ("regasm / regsvcs from a user folder or share", "T1218.009", r"\b(regasm|regsvcs)(\.exe)?\s+.{0,200}(C:\\(Temp|Users|ProgramData)|\\\\).{0,80}\.dll"),
    "lol_tttracer": ("tttracer process dump", "T1003", r"tttracer(\.exe)?\s+.{0,80}(-dumpFull|-attach\s+\d)"),
    "lol_dnscmd": ("dnscmd plug-in DLL", "T1543", r"dnscmd(\.exe)?\s+.{0,80}(/config|/zoneadd|/recordadd|/serverlevelplugindll)"),
    "lol_msconfig": ("msconfig launching tools", "T1218", r"msconfig(\.exe)?\s+.{0,80}(/4\b|/5\b|launch\s+cmd|launch\s+powershell)"),
    "wscript": ("wscript / cscript running a script", "T1059.005",
                r"\b(wscript|cscript)(\.exe)?\s+.{0,80}(/e:vbscript|/e:jscript|//?b\s+|http|\.vbs\b|\.js\b|\.jse\b|\.vbe\b|\.wsf\b)"),
    "schtask_remote": ("scheduled task on a remote computer", "T1053.005", r"schtasks(\.exe)?\s+.{0,80}/s\s+[A-Za-z0-9_.\-]{2,64}\s+.{0,80}/create"),
    "schtask_onlogon": ("scheduled task at logon / start-up", "T1053.005", r"schtasks(\.exe)?\s+.{0,200}/sc\s+(onlogon|onstart|onidle)"),
    "at_exec": ("at.exe job", "T1053.002", r"\bat(\.exe)?\s+(\d{1,2}:\d{2}|\\\\.{2,64})\s+.{0,200}(powershell|cmd|mshta|wscript|rundll32)"),
    "sc_create": ("service created / reconfigured", "T1543.003", r"\bsc(\.exe)?\s+(create|config|failure|sdset)\s+[A-Za-z0-9_\-]{1,60}"),
    "sc_remote": ("service operation on a remote computer", "T1021.002", r"\bsc(\.exe)?\s+\\\\[A-Za-z0-9_.\-]{2,64}\s+(create|config|start|stop|query)"),
    "reg_add": ("reg.exe changing the registry", "T1112", r"\breg(\.exe)?\s+(add|delete|import|export|copy|save|restore|load|unload)\s+"),
    "lat_psexec": ("PsExec / PAExec remote execution", "T1569.002",
                   r"\b(psexec|paexec|remcom)(\.exe)?\s+\\\\[A-Za-z0-9_.\-]{2,64}\s+.{0,200}(cmd|powershell|mshta|/c\s+)"),
    "lat_wmic_remote": ("wmic process on a remote computer", "T1047", r"wmic(\.exe)?\s+/node:[A-Za-z0-9_.\-\"]{2,64}\s+.{0,100}process\s+call\s+create"),
    "lat_winrm": ("WinRM remote shell", "T1021.006", r"(winrm(\.cmd|\.exe)?\s|wsmprovhost|Enter-PSSession|New-PSSession\s+-ComputerName)"),
    "lat_dcom": ("DCOM lateral movement", "T1021.003",
                 r"(MMC20\.Application|ShellWindows|ShellBrowserWindow|Excel\.Application|Outlook\.Application).{0,100}(ExecuteShellCommand|DDEInitiate|Navigate2|ShellExecute)"),
    "lat_smb": ("admin share copy / mapping", "T1021.002", r"(net\s+use\s+\\\\|copy\s+.{0,100}\\\\[A-Za-z0-9_.\-]{2,64}\\(admin|c|ipc)\$)"),
    "lat_rdp": ("RDP forced on", "T1021.001",
                r"(reg\s+add.{0,100}Terminal\s+Server.{0,100}fDenyTSConnections.{0,40}/d\s+0|netsh\s+.{0,60}localport=3389|Set-ItemProperty.{0,100}fDenyTSConnections.{0,40}0)"),
    "lat_ssh": ("SSH / plink tunnel", "T1572", r"\b(plink|ssh)(\.exe)?\s+.{0,100}(-R\s+\d+:|(-N|-T)\s+.{0,80}@|-L\s+\d+:)"),
    "cred_procdump": ("procdump of LSASS / winlogon", "T1003.001", r"procdump(64)?(\.exe)?\s+.{0,80}(-ma|-mm|-mp)\s+.{0,60}(lsass|winlogon)"),
    "cred_dpapi": ("DPAPI credential theft", "T1555.004",
                   r"(dpapi::cred|dpapi::masterkey|dpapi::cache|Invoke-DpapiDecrypt|Get-VaultCredential|vaultcmd(\.exe)?\s+/listcreds)"),
    "ev_logs": ("event logs cleared", "T1070.001",
                r"(wevtutil(\.exe)?\s+(cl|clear-log)\s+(System|Security|Application)|Clear-EventLog\s+-LogName|Remove-EventLog|auditpol(\.exe)?\s+/clear)"),
    "ev_av_disable": ("AV / EDR stopped or killed", "T1562.001",
                      r"(sc(\.exe)?\s+(stop|delete)\s+(WinDefend|MsMpEng|sense|csagent|CarbonBlack|cylance|SentinelOne|CrowdStrike|Symantec|McAfee|Sophos)|"
                      r"taskkill.{0,60}(MsMpEng|\bsense\b|csagent|\bavp\b|mcshield))"),
    "ev_defender_reg": ("Defender disabled with reg add", "T1562.001",
                        r"reg(\.exe)?\s+add.{0,100}(Windows\s+Defender|WinDefend).{0,100}(DisableAntiSpyware|DisableAntiVirus|DisableRealtimeMonitoring).{0,40}/d\s+1"),
    "ev_attrib": ("files hidden with attrib", "T1564.001",
                  r"attrib(\.exe)?\s+.{0,60}(\+h|\+s|\+r).{0,100}(\.exe|\.dll|\.bat|\.ps1|\.vbs|\.js|C:\\(Temp|Users|ProgramData))"),
    "ev_perms": ("permissions taken (icacls / takeown)", "T1222.001",
                 r"(icacls(\.exe)?\s+.{0,80}(/grant|/deny|/remove|/inheritance:r)|takeown(\.exe)?\s+.{0,80}/f\s+.{0,80}(System32|lsass|SAM))"),
    "ev_cipher": ("free space wiped (cipher /w)", "T1070.004", r"cipher(\.exe)?\s+/w:[A-Za-z]:\\"),
    "ev_timestamp": ("timestomping", "T1070.006",
                     r"(Set-ItemProperty\s+.{0,100}-Name\s+(LastWriteTime|CreationTime|LastAccessTime)|\[System\.IO\.File\]::SetLastWriteTime)"),
    "ev_ads": ("alternate data stream", "T1564.004", r"([A-Za-z0-9_\\.\-]{3,200}:[A-Za-z0-9_\-]{2,30}:(\.exe|\.dll|\.ps1|\.vbs)|\btype\s+.{0,100}>\s+.{0,100}:\w+)"),
    "per_com": ("reg add of a COM server in a user folder / share", "T1546.015",
                r"reg(\.exe)?\s+add.{0,100}CLSID\\.{0,80}(InprocServer32|LocalServer32).{0,100}(C:\\(Temp|Users|ProgramData)|\\\\)"),
    "per_dll_hijack": ("DLL copied into System32 / Program Files", "T1574.001",
                       r"\b(copy|xcopy|robocopy)\b.{0,100}(C:\\Windows\\(System32|SysWOW64)|C:\\Program Files).{0,200}\.(dll|ocx)"),
    "per_logon_script": ("reg add of a logon script", "T1037.001", r"reg(\.exe)?\s+add.{0,100}Environment.{0,100}UserInitMprLogonScript"),
    "per_netsh": ("netsh helper DLL added", "T1546.007", r"netsh(\.exe)?\s+add\s+helper\s+.{0,100}\.(dll|ocx)"),
    "net_share": ("share mapped / listed", "T1021.002", r"\bnet1?(\.exe)?\s+(use|view|share)\s+\\\\[A-Za-z0-9_.\-]{2,64}"),
    "net_svc": ("service started / stopped with net", "T1489", r"\bnet1?(\.exe)?\s+(start|stop)\s+[A-Za-z0-9_\- ]{2,40}"),
    "net_fw_off": ("Windows firewall turned off", "T1562.004",
                   r"netsh(\.exe)?\s+.{0,60}(advfirewall\s+set\s+allprofiles\s+state\s+off|firewall\s+set\s+opmode\s+disable)"),
    "disc_sys": ("system discovery", "T1082", r"(\bsysteminfo(\.exe)?\b|ipconfig(\.exe)?\s+/all|\bwhoami(\.exe)?\b|net\s+config\s+workstation)"),
    "disc_net": ("network discovery", "T1016", r"(\barp(\.exe)?\s+-a|netstat(\.exe)?\s+(-an|-ano)|route(\.exe)?\s+print|\bnet\s+view|\bping(\.exe)?\s+-[nt])"),
    "disc_proc": ("process discovery", "T1057", r"(\btasklist(\.exe)?\b|Get-Process|\bqprocess(\.exe)?\b)"),
    "disc_users": ("account discovery", "T1087", r"(\bnet\s+user(\s+/domain)?|query\s+(user|session)|Get-LocalUser|dsquery\s+user|wmic\s+useraccount)"),
    "disc_ad": ("domain / trust discovery", "T1482",
                r"(nltest(\.exe)?\s+(/domain_trusts|/dclist|/trusted_domains)|dsquery\s+(computer|group|user|ou|site)|ldifde\s+-f|csvde\s+-f|\badfind(\.exe)?\b)"),
    "disc_scan": ("network scanning", "T1046", r"(\bnmap(\.exe)?\b|\bmasscan(\.exe)?\b|Test-NetConnection\s+.{0,60}-Port|1\.\.254.*Test-NetConnection|for\s+/l.{0,60}ping)"),
    "disc_shares": ("share discovery", "T1135", r"(net\s+view\s+/all|Invoke-ShareFinder|Find-DomainShare|Get-NetShare)"),
    "disc_gpo": ("group policy discovery", "T1615", r"(Get-GPO\b|Get-GPOReport|gpresult(\.exe)?\s+/[hrzv]|secedit(\.exe)?\s+/export)"),
    "exfil_curl": ("curl / wget upload", "T1048", r"\b(curl|wget)(\.exe)?\s+.{0,80}(-T\s+|-F\s+|-d\s+@|--data-binary\s+@|--upload-file)\s*.{0,200}(http|ftp|smb)"),
    "exfil_ftp": ("scripted FTP", "T1048.003", r"\bftp(\.exe)?\s+.{0,60}(-s:|(-n|-i)\s+)"),
    "exfil_copy": ("robocopy / xcopy to a share", "T1039", r"\b(robocopy|xcopy)(\.exe)?\s+.{0,100}\\\\[A-Za-z0-9_.\-]{2,64}\\"),
    "exfil_compress": ("archive staged for exfiltration", "T1560.001",
                       r"(Compress-Archive\s+.{0,100}-DestinationPath|\btar(\.exe)?\s+.{0,60}(-cf|-czf|--create).{0,100}(\\\\|http|C:\\(Temp|ProgramData)))"),
    "exfil_cloud": ("rclone / MEGA to cloud storage", "T1567.002",
                    r"(rclone(\.exe)?\s+.{0,80}(copy|sync|move).{0,100}(mega:|gdrive:|onedrive:|s3:|dropbox:)|mega-put|megacopy)"),
    "exfil_dns": ("DNS exfiltration / tunnelling", "T1048", r"(nslookup\s+.{0,100}\$|Resolve-DnsName\s+.{0,100}\$|\bdnscat|\biodine\b|dns2tcp)"),
    "tun_portproxy": ("netsh port proxy", "T1090", r"netsh(\.exe)?\s+interface\s+portproxy\s+add\s+v4tov4"),
    "tun_ssh": ("SSH reverse / local tunnel", "T1572", r"\b(plink|ssh)(\.exe)?\s+.{0,100}(-R\s+\d+:|(-N|-T)\s+.{0,80}@|-L\s+\d+:)"),
    "tun_tools": ("tunnelling tool (ngrok, frp, chisel, ligolo)", "T1572",
                  r"(ngrok(\.exe)?\s+(tcp|http|start)|frpc(\.exe)?\s+-c|chisel(\.exe)?\s+(server|client)|ligolo(-ng)?(\.exe)?\s+(agent|proxy))"),
    "tun_socat": ("socat relay / shell", "T1090", r"\bsocat(\.exe)?\s+.{0,100}(TCP:|EXEC:|SYSTEM:)"),
    "tun_nc": ("netcat shell / listener", "T1059", r"\b(nc|ncat|netcat)(\.exe)?\s+.{0,60}(-e\s+|(-l\s+-p|-lvp)\s+\d+|-c\s+(cmd|bash|sh|powershell))"),
    "tun_winrm": ("WinRM opened as a channel", "T1021.006", r"(winrm\s+set\s+winrm/config|Set-WSManInstance\s+.{0,100}Transport|Enable-PSRemoting\s+-Force)"),
    "shadow_encrypt": ("mass encryption", "T1486", r"(cipher(\.exe)?\s+/e\s+/s:|Get-ChildItem.{0,100}\|\s*ForEach.{0,100}Encrypt|\[System\.IO\.File\]::Encrypt\s*\()"),
}

ALLOW = re.compile(r"(?i)(C:\\Windows\\CCM\\|MpCmdRun(\.exe)?|C:\\Windows\\(SoftwareDistribution|WUAgent|winsxs\\)|"
                   r"C:\\Program Files\\(SolarWinds|ManageEngine|Kaseya|ConnectWise|Ansible|Puppet|Chef|SentinelOne\\bin|CrowdStrike\\CSFalcon))")

# Words at least one indicator needs: values without any are skipped (a full SOFTWARE hive has a
# million values; only a few thousand mention a command at all).
PREFILTER = (r"(?i)(powershell|pwsh|cmd|amsi|reflection|assembly|gzip|deflate|compression|binaryformatter|bloodhound|sharphound|"
             r"kerberoast|rubeus|spnticket|asreproast|thehash|smbexec|wmiexec|mimikatz|sekurlsa|kerberos::|regsvr32|rundll32|mshta|"
             r"cmstp|workflow|mavinject|msdt|wmic|diskshadow|comsvcs|ntdsutil|vssadmin|wce|fgdump|pwdump|gsecdump|lsadump|cachedump|"
             r"secretsdump|getnpusers|getuserspns|dcomexec|atexec|psexec|paexec|remcom|globalroot|shadowcopy|reg |reg\.exe|virtualprotect|"
             r"writeprocessmemory|nttracecontrol|etweventwrite|virtualallocex|createremotethread|ntqueueapcthread|setthreadcontext|"
             r"rtlcreateuserthread|ntcreatesection|ntmapviewofsection|reflective|loadlibraryr|wbadmin|bcdedit|disable-computerrestore|"
             r"\\pipe\\|meterpreter|beacon\.|cobaltstrike|net |net1|net\.exe|schtasks|sc |sc\.exe|webclient|invoke-|iwr |download|"
             r"bitstransfer|iex|icm |scriptblock|\.invoke|wmiobject|gwmi|system\.management|credential|securestring|pssession|psremoting|"
             r"wsman|winrm|wsmprovhost|executionpolicy|pslockdown|languagemode|mppreference|applocker|getconsolewindow|token|"
             r"impersonate|enable-privilege|get-ad|aclscanner|localadmin|keystate|windowshook|clipboard|set /a|&&|itemproperty|scheduledtask|%comspec%|system32\\cmd|"
             r"/v:on|delayedexpansion|certutil|bitsadmin|msiexec|forfiles|bash|wsl|pcalua|xwizard|eventvwr|fodhelper|sdclt|diskcleanup|"
             r"wsreset|computerdefaults|slui|dccw|installutil|msdeploy|aspnet_compiler|appvpublishingserver|/inproc|"
             r"infdefaultinstall|odbcconf|esentutl|expand|extrac32|findstr|replace|hh\.exe|hh |mmc|presentationhost|control|regasm|"
             r"regsvcs|tttracer|dnscmd|msconfig|wscript|cscript|at |at\.exe|mmc20|shellwindows|shellbrowserwindow|excel\.application|"
             r"outlook\.application|copy |\$|fdenytsconnections|3389|plink|ssh|procdump|dpapi|vault|wevtutil|eventlog|auditpol|taskkill|"
             r"defender|windefend|attrib|icacls|takeown|cipher|lastwritetime|creationtime|lastaccesstime|setlastwritetime|type\s.{0,100}>|:(\.exe|\.dll|\.ps1|\.vbs)|"
             r"inprocserver32|localserver32|xcopy|robocopy|userinitmprlogonscript|netsh|systeminfo|ipconfig|whoami|arp |netstat|route |"
             r"ping |tasklist|get-process|qprocess|query |get-localuser|dsquery|useraccount|nltest|ldifde|csvde|adfind|nmap|masscan|"
             r"test-netconnection|sharefinder|domainshare|get-netshare|get-gpo|gpresult|secedit|curl|wget|ftp|compress-archive|tar |"
             r"rclone|mega|nslookup|resolve-dnsname|dnscat|iodine|dns2tcp|portproxy|ngrok|frpc|chisel|ligolo|socat|\bnc(\.exe)?\s+-|ncat|"
             r"netcat|encrypt|wbbackupset|named pipe)")

_CRIT = {k: (lab, att, re.compile(rx, re.I | re.S)) for k, (lab, att, rx) in CRITICAL.items()}
_MED = {k: (lab, att, re.compile(rx, re.I | re.S)) for k, (lab, att, rx) in MEDIUM.items()}


def classify(text: str) -> dict[str, Any]:
    """{critical: [ids], medium: [ids], allowed: bool} for one value."""
    if not text:
        return {"critical": [], "medium": [], "allowed": False}
    crit = [k for k, (_l, _a, rx) in _CRIT.items() if rx.search(text)]
    med = [k for k, (_l, _a, rx) in _MED.items() if rx.search(text)]
    return {"critical": crit, "medium": med, "allowed": bool((crit or med) and ALLOW.search(text))}


def describe(ids: list[str]) -> list[str]:
    out = []
    for k in ids:
        lab, att, _rx = (_CRIT.get(k) or _MED.get(k))
        out.append(f"{lab} ({att})")
    return out


def attacks(ids: list[str]) -> list[str]:
    return sorted({(_CRIT.get(k) or _MED.get(k))[1] for k in ids})
