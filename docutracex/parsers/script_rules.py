"""Shared behaviour-rule catalogue for scripting languages.

One catalogue for every scripting engine (JavaScript/JScript, PowerShell,
VBScript, batch/cmd). Each rule maps a malicious *behaviour* to the concrete
syntax its variants use in each language, with a severity and a MITRE ATT&CK
technique. The rules run over the code the parsers have already **deobfuscated**,
so patterns that obfuscation used to hide are now visible.

Every parser calls :func:`scan` with its language code and gets the same hit
shape it used before (``rule``/``severity``/``label``/``line_no``/``line``),
plus an ``attack`` field; the ATT&CK id is also appended to the label so it
reaches the finding detail and the UI. Nothing is executed.

Behaviour families: execution (A), download/ingress (B), LOLBins (C),
persistence (D), defence evasion / AMSI (E), anti-analysis (F), injection /
shellcode (G), discovery (H), credential access (I), file drop / smuggling (J),
C2 / network (K), macro triggers (L), DDE (M).
"""

from __future__ import annotations

import re
from typing import Any

# Language codes.
JS, PS, VBS, BAT, VBA, PY, JAVA = "js", "ps", "vbs", "bat", "vba", "py", "java"

_HITS_PER_RULE = 6

# (rule_id, {langs}, severity, attack, label, regex) — regex matched per line,
# case-insensitive. Existing rule ids are preserved; many variants are added.
_RULES: list[tuple[str, set[str], str, str, str, str]] = [
    # ---- A. Execution of commands / dynamic code ---------------------------
    ("js_eval", {JS}, "medium", "T1059.007", "eval() of dynamic code", r"\beval\s*\("),
    ("js_function_ctor", {JS}, "medium", "T1059.007", "Function constructor",
     r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]"),
    ("js_document_write", {JS}, "medium", "T1059.007", "document.write", r"document\.write(?:ln)?\s*\("),
    ("js_activex", {JS}, "high", "T1059.007", "ActiveXObject/GetObject",
     r"\bnew\s+ActiveXObject\s*\(|\bGetObject\s*\("),
    ("js_wscript_shell", {JS}, "high", "T1059.001", "runs commands (WScript.Shell/ShellExecute/Run)",
     r"WScript\.Shell|Shell\.Application|\.ShellExecute\s*\(|\.Run\s*\(|\.Exec\s*\("),
    ("ps_iex", {PS}, "high", "T1059.001", "executes a dynamic string (IEX)",
     r"Invoke-Expression|\biex\b|\.Invoke\(\)|\bICM\b|Invoke-Command"),
    ("ps_exec", {PS}, "high", "T1059.001", "process / in-memory execution",
     r"Start-Process|Invoke-Item|\bsaps\b|New-Object\s+Net|\[Reflection\.Assembly\]|System\.Reflection"),
    ("vbs_exec", {VBS}, "high", "T1059.005", "executes a dynamic string",
     r"\bExecuteGlobal\b|\bExecute\b|\bEval\b"),
    ("vbs_shell", {VBS}, "high", "T1059.005", "runs commands (WScript.Shell/Run)",
     r"WScript\.Shell|Shell\.Application|\.Run\s*\(|\.Exec\s*\(|\.ShellExecute\s*\("),
    ("vbs_activex", {VBS}, "high", "T1059.005", "creates/uses a COM object",
     r"CreateObject\s*\(|GetObject\s*\("),
    ("bat_exec", {BAT}, "high", "T1059.003", "command execution (cmd)",
     r"\bstart\s+/b|\bcall\s+%|\bcmd(?:\.exe)?\s*/c|&\s*start\b|\bfor\s+/f"),
    ("bat_powershell", {BAT}, "high", "T1059.001", "spawns PowerShell", r"\bpowershell\b|\bpwsh\b"),

    # ---- B. Download / ingress tool transfer -------------------------------
    ("js_download", {JS}, "high", "T1105", "network request",
     r"MSXML2\.(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP|\bfetch\s*\(|XMLHttpRequest"),
    ("ps_download", {PS}, "high", "T1105", "downloads / connects out",
     r"DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Net\.WebClient|System\.Net\.Sockets|System\.Net\.Http"),
    ("ps_bits", {PS}, "high", "T1197", "BITS transfer", r"Start-BitsTransfer|\bbitsadmin\b"),
    ("vbs_download", {VBS}, "high", "T1105", "network request / stream",
     r"MSXML2\.(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP|ADODB\.Stream"),
    ("bat_download", {BAT}, "high", "T1105", "downloads a file",
     r"certutil\s+-urlcache|certutil\s+-f|bitsadmin\s+/transfer|\bcurl\s+|\bwget\s+"),

    # ---- C. LOLBins ---------------------------------------------------------
    ("js_lolbin", {JS}, "high", "T1218", "invokes a LOLBin / shell",
     r"powershell|cmd(?:\.exe)?\s*/c|mshta|regsvr32|rundll32|certutil|bitsadmin|wmic|schtasks|curl\s+-"),
    ("ps_lolbin", {PS}, "high", "T1218", "invokes a LOLBin",
     r"\brundll32\b|\bregsvr32\b|\bmshta\b|\bcertutil\b|\bbitsadmin\b|\bwmic\b|\bschtasks\b|\bmsiexec\b|\binstallutil\b|\bregasm\b|\bregsvcs\b|\bcmstp\b|\bforfiles\b"),
    ("vbs_lolbin", {VBS}, "high", "T1218", "invokes a LOLBin / shell",
     r"powershell|cmd(?:\.exe)?\s*/c|mshta|regsvr32|rundll32|certutil|bitsadmin|wmic|schtasks"),
    ("bat_lolbin", {BAT}, "high", "T1218", "invokes a LOLBin",
     r"\bmshta\b|\bregsvr32\b|\brundll32\b|\bcertutil\b|\bwmic\b|\bbitsadmin\b|\bforfiles\b|\bcscript\b|\bwscript\b|\bmsiexec\b|\binstallutil\b"),

    # ---- D. Persistence -----------------------------------------------------
    ("js_run_key", {JS}, "high", "T1547.001", "Run-key persistence (registry)",
     r"RegWrite|CurrentVersion\\+Run(?:Once)?"),
    ("ps_persist", {PS}, "medium", "T1547.001", "persistence (registry / scheduled task)",
     r"New-ItemProperty|Set-ItemProperty|CurrentVersion\\+Run|Register-ScheduledTask|schtasks\s+/create|"
     r"Schedule\.Service|\.RegisterTask(?:Definition)?\s*\(|<LogonTrigger>|<BootTrigger>"),
    ("ps_wmi_persist", {PS}, "high", "T1546.003", "WMI event-subscription persistence",
     r"__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding|Set-WmiInstance\s+-Class\s+__"),
    ("ps_service", {PS}, "high", "T1543.003", "creates a service",
     r"New-Service\b|\bsc(?:\.exe)?\s+create\b|Win32_Service.*Create"),
    ("vbs_run_key", {VBS}, "high", "T1547.001", "Run-key persistence (registry)",
     r"RegWrite|CurrentVersion\\+Run(?:Once)?"),
    ("bat_persist", {BAT}, "high", "T1547.001", "persistence (Run key / task / startup)",
     r"reg\s+add\s+.*\\Run|schtasks\s+/create|copy\s+.*\\Start ?Menu\\.*Startup|\\Startup\\"),
    ("js_scheduled_task", {JS, VBS}, "high", "T1053.005", "creates a scheduled task",
     r"Schedule\.Service|schtasks\s*/create"),

    # ---- E. Defence evasion / AMSI / obfuscation ---------------------------
    ("ps_hidden", {PS}, "medium", "T1564.003", "stealth execution flags",
     r"-w(?:indowstyle)?\s+hidden|-nop\b|-noni\b|-noprofile\b|-noninteractive\b|-ep\s+bypass|-exec(?:utionpolicy)?\s+bypass"),
    ("ps_encoded", {PS}, "high", "T1027", "base64-encoded command",
     r"-e(?:c|nc|ncod|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|FromBase64String"),
    ("ps_amsi", {PS}, "high", "T1562.001", "AMSI bypass",
     r"amsiUtils|amsiInitFailed|AmsiScanBuffer|amsiContext|System\.Management\.Automation\.AmsiUtils|\[Ref\]\.Assembly.*Amsi"),
    ("ps_etw_patch", {PS}, "high", "T1562.006", "ETW patching",
     r"EtwEventWrite|EtwpCreateEtwThread"),
    ("ps_defender_off", {PS}, "high", "T1562.001", "disables Defender",
     r"Set-MpPreference\s+-Disable|Add-MpPreference\s+-ExclusionPath|DisableRealtimeMonitoring|DisableIOAVProtection|DisableBehaviorMonitoring"),
    ("ps_clear_logs", {PS}, "medium", "T1070.001", "clears event logs",
     r"wevtutil\s+cl|Clear-EventLog|Remove-Item.*\.evtx"),
    ("ps_obfusc", {PS}, "medium", "T1027", "obfuscation primitives",
     r"-join\s|-f\s*['\"]|\[char\]\s*\d+|\[string\]::Join|`[a-z]|\$\{.*\}|\[convert\]::toint"),
    ("vbs_obfusc", {VBS}, "medium", "T1027", "obfuscation primitives",
     r"StrReverse\s*\(|Chr[W]?\s*\(|&\s*H[0-9a-fA-F]{2}"),
    ("js_unescape", {JS}, "medium", "T1140", "unescape()/percent-decoding",
     r"\bunescape\s*\(|\bdecodeURIComponent\s*\(\s*['\"]%"),
    ("js_atob", {JS}, "medium", "T1140", "base64 decoding (atob)", r"\batob\s*\("),
    ("js_fromcharcode", {JS}, "medium", "T1140", "String.fromCharCode", r"String\.fromCharCode\s*\("),
    ("bat_obfusc", {BAT}, "medium", "T1027", "batch obfuscation primitives",
     r"\^[\"%]|%\w+:~\d|![\w]+!|%%\w"),
    ("bat_defense_evasion", {BAT}, "medium", "T1562.001", "disables defences / hides",
     r"\battrib\s+\+h|\btaskkill\s+/|net\s+stop\b|\bsc\s+stop\b|vssadmin\s+delete|Set-MpPreference"),

    # ---- F. Anti-analysis / sandbox evasion --------------------------------
    ("ps_sleep", {PS}, "medium", "T1497.003", "long sleep (sandbox evasion)",
     r"Start-Sleep\s+(?:-Seconds\s+)?\d{3,}|Start-Sleep\s+-m\s+\d{6,}"),
    ("js_sleep", {JS, VBS}, "medium", "T1497.003", "long sleep (sandbox evasion)",
     r"WScript\.Sleep\s*\(\s*\d{4,}|setTimeout\s*\([^,]+,\s*\d{5,}\)"),
    ("ps_antivm", {PS}, "medium", "T1497.001", "VM / sandbox detection",
     r"Win32_ComputerSystem|Win32_BIOS|VMware|VirtualBox|QEMU|\bXen\b|innotek|vbox"),
    ("vbs_antivm", {VBS}, "medium", "T1497.001", "VM / sandbox detection",
     r"Win32_ComputerSystem|Win32_BIOS|VMware|VirtualBox|QEMU"),

    # ---- G. Injection / shellcode ------------------------------------------
    ("js_heap_spray", {JS}, "high", "T1055", "heap-spray / shellcode pattern",
     r"%u0c0c%u0c0c|%u9090|\\u0c0c|nop\s*sled|\.substr\(0,\s*\w+\.length\s*/\s*2\)"),
    ("ps_shellcode", {PS, VBS}, "high", "T1055", "memory-injection API",
     r"VirtualAlloc|VirtualProtect|CreateThread|RtlMoveMemory|WriteProcessMemory|NtAllocateVirtualMemory|CallWindowProc|memset\s*\("),
    ("ps_reflection_load", {PS}, "high", "T1620", "reflective .NET assembly load",
     r"\[Reflection\.Assembly\]::Load|\[System\.Reflection\.Assembly\]::Load|Load\(\[Convert\]::FromBase64String|"
     r"\[AppDomain\]::CurrentDomain\.Load\s*\(|ReturnType\s*-eq\s*\[(?:System\.)?Reflection\.Assembly\]"),
    ("ps_hollow_host", {PS, JS, VBS}, "high", "T1055.012", "targets a .NET host binary for injection (process hollowing)",
     r"Microsoft\.NET\\+Framework(?:64)?\\+[^'\"\s]*\\+(?:MSBuild|RegAsm|RegSvcs|InstallUtil|AppLaunch|aspnet_compiler|"
     r"vbc|jsc|csc|AddInProcess(?:32)?|CasPol)\.exe"),
    ("ps_scriptblock", {PS}, "medium", "T1059.001", "builds and runs code at run time ([scriptblock]::Create)",
     r"\[scriptblock\]::Create\s*\(|\[System\.Management\.Automation\.ScriptBlock\]::Create"),
    ("ps_wmi_exec", {PS}, "high", "T1047", "starts a process through WMI (Win32_Process.Create)",
     r"Win32_Process[^\n]{0,80}\bCreate\b|Invoke-(?:Cim|Wmi)Method[^\n]{0,80}Win32_Process|\[wmiclass\][^\n]{0,40}Win32_Process"),
    ("ps_addtype", {PS}, "high", "T1059.001", "compiles inline code (Add-Type/DllImport)",
     r"Add-Type\s+-(?:TypeDefinition|MemberDefinition)|\bDllImport\b"),
    ("js_dotnet_load", {JS, VBS}, "high", "T1620", "in-memory .NET load (DotNetToJScript)",
     r"DotNetToJScript|mscorlib|System\.Reflection|AppDomain"),

    # ---- H. Discovery -------------------------------------------------------
    ("ps_discovery", {PS}, "medium", "T1082", "host / domain discovery",
     r"\bwhoami\b|\bsysteminfo\b|\bipconfig\b|Get-WmiObject|Get-CimInstance|\[Environment\]::|net\s+(?:user|group|view)\b|\bnltest\b|\barp\s+-a\b"),
    ("vbs_discovery", {VBS, JS}, "medium", "T1082", "host discovery",
     r"Win32_OperatingSystem|Win32_ComputerSystem|\.ComputerName|ExpandEnvironmentStrings"),
    ("js_wmi", {JS, VBS}, "high", "T1047", "WMI (winmgmts) access",
     r"winmgmts:|GetObject\s*\(\s*['\"]winmgmts|Win32_Process"),
    ("bat_discovery", {BAT}, "medium", "T1082", "host discovery",
     r"\bwhoami\b|\bsysteminfo\b|\bipconfig\b|\bnet\s+(?:user|group|view)\b|\btasklist\b|\bnltest\b"),

    # ---- I. Credential access ----------------------------------------------
    ("ps_cred_access", {PS}, "high", "T1003", "credential access",
     r"Invoke-Mimikatz|sekurlsa|\blsass\b|reg\s+save\s+HK\w+\\SAM|Get-Credential|Mimikatz|ntds\.dit|Out-Minidump"),
    ("ps_keylog", {PS, JS, VBS}, "high", "T1056.001", "keylogging API",
     r"GetAsyncKeyState|SetWindowsHookEx|Get-Keystrokes"),
    ("js_credential_exfil", {JS}, "high", "T1056", "sends a password field",
     r"(?:password|passwd|pwd)[^;\n]{0,80}(?:fetch|XMLHttpRequest|\.send\s*\(|ajax|\$\.post)"),

    # ---- J. File drop / HTML smuggling -------------------------------------
    ("js_file_write", {JS}, "high", "T1105", "writes files (ADODB.Stream/FileSystemObject)",
     r"ADODB\.Stream|Scripting\.FileSystemObject|\.SaveToFile\s*\(|\.CreateTextFile\s*\("),
    ("vbs_file", {VBS}, "high", "T1105", "writes files",
     r"Scripting\.FileSystemObject|\.SaveToFile\s*\(|\.CreateTextFile\s*\(|\.WriteLine\b"),
    ("js_html_smuggling", {JS}, "high", "T1027.006", "builds a file in the browser (HTML smuggling)",
     r"new\s+Blob\s*\(|createObjectURL|msSaveOrOpenBlob"),

    # ---- K. C2 / network ----------------------------------------------------
    ("js_redirect", {JS}, "medium", "T1105", "navigates / redirects",
     r"(?:window\.|document\.)?location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\(|window\.open\s*\("),
    ("ps_dns", {PS}, "medium", "T1071.004", "DNS query / possible exfil",
     r"Resolve-DnsName|nslookup\s+\S{20,}"),

    # ---- PDF-embedded JavaScript (Reader) ----------------------------------
    ("pdf_js_export_launch", {JS}, "high", "T1203", "PDF: extracts and launches an attachment",
     r"exportDataObject\s*\([^)]*nLaunch"),
    ("pdf_js_launch_url", {JS}, "medium", "T1204.002", "PDF: opens a URL / submits data",
     r"app\.launchURL|this\.getURL|submitForm"),
    ("pdf_js_exploit_api", {JS}, "high", "T1203", "PDF: API used by known Reader exploits",
     r"util\.printf|getAnnots\s*\(|Collab\.(?:collectEmailInfo|getIcon)|media\.newPlayer|spell\.customDictionaryOpen"),

    # ---- L/M. Destructive / DDE (batch & cross) ----------------------------
    ("bat_destructive", {BAT}, "high", "T1485", "destructive / inhibits recovery",
     r"\bdel\s+/[sfq]|\brd\s+/s|\bformat\s+[a-z]:|vssadmin\s+delete\s+shadows|\bbcdedit\b|wbadmin\s+delete"),

    # ---- Python (.py / .pyc, incl. unpacked PyInstaller) -------------------
    # Matched on deobfuscated / decompiled source and on the dotted-call listing
    # reconstructed from .pyc bytecode; single-token presence is also flagged by
    # the Python engine's import scan when only raw strings survive.
    ("py_exec", {PY}, "high", "T1059.006", "executes dynamic code (eval/exec)",
     r"\b(?:eval|exec|execfile)\s*\(|\bcompile\s*\([^)]*,\s*['\"]?\w*['\"]?\s*,\s*['\"]exec['\"]"),
    ("py_subprocess", {PY}, "high", "T1059.006", "spawns a process (subprocess/os)",
     r"\bsubprocess\.(?:Popen|call|run|check_output|check_call|getoutput)\b|\bos\.(?:system|popen|exec[lv]\w*|spawn\w*)\b|\bpty\.spawn\b"),
    ("py_shell_true", {PY}, "medium", "T1059", "shell=True (shell command execution)",
     r"shell\s*=\s*True"),
    ("py_lolbin", {PY}, "high", "T1218", "invokes a Windows LOLBin / shell",
     r"\b(?:powershell|pwsh|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|msiexec)\b"),
    ("py_download", {PY}, "high", "T1105", "downloads / connects out",
     r"\burllib\.request\b|\burlopen\s*\(|\burlretrieve\s*\(|\brequests\.(?:get|post|request)\b|"
     r"\bhttp\.client\b|\bhttpx\.|\baiohttp\b|\bwget\.download\b"),
    ("py_socket", {PY}, "medium", "T1095", "raw socket (possible C2)",
     r"\bsocket\.socket\s*\(|\bsocket\.(?:AF_INET|SOCK_STREAM|SOCK_DGRAM)\b|\bconnect\s*\(\s*\(\s*['\"]"),
    ("py_persist_registry", {PY}, "high", "T1547.001", "persistence (Run key / registry)",
     r"\bwinreg\.|\b_winreg\b|HKEY_(?:CURRENT_USER|LOCAL_MACHINE)|CurrentVersion\\{1,2}Run"),
    ("py_persist_os", {PY}, "high", "T1547", "persistence (startup / task / cron)",
     r"schtasks|\bcrontab\b|Start Menu\\{1,2}Programs\\{1,2}Startup|LaunchAgents|/etc/rc\.local"),
    ("py_b64", {PY}, "medium", "T1140", "base64 / hex decoding",
     r"\bbase64\.(?:b(?:16|32|64|85)decode|urlsafe_b64decode)\b|\bbinascii\.(?:a2b_\w+|unhexlify)\b|\bcodecs\.decode\s*\("),
    ("py_packed_code", {PY}, "high", "T1027", "loads packed/serialised code (marshal/pickle/zlib)",
     r"\bmarshal\.loads\b|\bpickle\.loads\b|\bzlib\.decompress\b|\blzma\.decompress\b|\btypes\.(?:CodeType|FunctionType)\b"),
    ("py_dynamic_import", {PY}, "medium", "T1027", "dynamic import / attribute resolution",
     r"\b__import__\s*\(|\bimportlib\.import_module\s*\(|\bgetattr\s*\(\s*__import__"),
    ("py_inject", {PY}, "high", "T1055", "memory injection via ctypes/WinAPI",
     r"\bctypes\.(?:windll|cdll|CDLL|WinDLL)\b|VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|"
     r"VirtualProtect|RtlMoveMemory|memmove\s*\(|SetThreadContext"),
    ("py_shellcode", {PY}, "high", "T1055", "embedded shellcode blob (\\x escapes)",
     r"(?:\\x[0-9a-fA-F]{2}){20,}|bytearray\s*\(\s*b?['\"](?:\\x[0-9a-fA-F]{2}){8,}"),
    ("py_discovery", {PY}, "medium", "T1082", "host / user discovery",
     r"\bplatform\.(?:system|node|uname|release)\b|\bsocket\.gethostname\b|\bos\.getlogin\b|\bgetpass\.getuser\b|\bos\.environ\b"),
    ("py_credentials", {PY}, "high", "T1555", "credential access (DPAPI / browser stores)",
     r"\bwin32crypt\b|CryptUnprotectData|\bkeyring\.|Login Data|(?:cookies|logins)\.sqlite|moz_cookies"),
    ("py_clr", {PY}, "medium", "T1620", "in-memory .NET load (pythonnet/CLR)",
     r"\bimport clr\b|\bpythonnet\b|System\.Reflection\.Assembly"),
    ("py_antivm", {PY}, "medium", "T1497.001", "VM / sandbox / debugger detection",
     r"\bvmware\b|\bvirtualbox\b|\bvbox\b|\bqemu\b|IsDebuggerPresent|\bwmic\b|GetSystemFirmwareTable|cpu_count\s*\(\s*\)\s*<"),
    ("py_sleep", {PY}, "medium", "T1497.003", "long sleep (sandbox evasion)",
     r"\btime\.sleep\s*\(\s*(?:[1-9]\d{2,}|\d+\s*\*\s*60)"),
    ("py_disable_defender", {PY}, "high", "T1562.001", "disables AV / Defender",
     r"Set-MpPreference|DisableRealtimeMonitoring|Add-MpPreference\s+-ExclusionPath|defender"),

    # ---- Java (.class constant pool / decompiled source / JSP) -------------
    # Matched on decompiled source (CFR), on the slash-separated class/method
    # refs mined from the .class constant pool, and on JSP scriptlet text.
    ("java_exec", {JAVA}, "high", "T1059", "runs OS commands (Runtime/ProcessBuilder)",
     r"\bRuntime\b[./\s]{0,8}(?:getRuntime[./\s(]{0,6})?[./\s]{0,8}exec\b|getRuntime\s*\(\s*\)\s*\.?\s*exec|"
     r"\bProcessBuilder\b|java[./]lang[./]ProcessImpl"),
    ("java_script_engine", {JAVA}, "high", "T1059.007", "dynamic script eval (ScriptEngine/Nashorn)",
     r"ScriptEngineManager|javax[./]script|getEngineByName|\bNashorn\b"),
    ("java_defineclass", {JAVA}, "high", "T1620", "in-memory class loading (defineClass/ClassLoader)",
     r"\bdefineClass\b|URLClassLoader|\bClassLoader\b|sun[./]misc[./]Unsafe|\bUnsafe\b"),
    ("java_reflection", {JAVA}, "medium", "T1620", "reflection (Class.forName / setAccessible)",
     r"Class\.forName|java[./]lang[./]reflect|\.getDeclaredMethod\b|\.setAccessible\b|\.getMethod\b|invoke\b"),
    ("java_download", {JAVA}, "high", "T1105", "network download / connection",
     r"java[./]net[./](?:URL|HttpURLConnection|URLConnection)|openConnection|openStream|"
     r"java[./]net[./]http[./]HttpClient|getInputStream\s*\("),
    ("java_socket", {JAVA}, "medium", "T1095", "raw socket (possible C2)",
     r"java[./]net[./]Socket|\bServerSocket\b|SocketChannel"),
    ("java_jndi", {JAVA}, "high", "T1190", "JNDI lookup (Log4Shell / injection)",
     r"\$\{jndi:|javax[./]naming|InitialContext|(?:ldap|rmi|dns|iiop)://"),
    ("java_deserialization", {JAVA}, "high", "T1190", "Java deserialization (gadget)",
     r"ObjectInputStream|readObject\b|readUnshared\b|InvokerTransformer|TemplatesImpl|"
     r"CommonsCollections|\bysoserial\b"),
    ("java_crypto", {JAVA}, "medium", "T1027", "crypto (payload decryption)",
     r"javax[./]crypto|\bCipher\b|SecretKeySpec|IvParameterSpec"),
    ("java_base64", {JAVA}, "medium", "T1140", "base64 decoding",
     r"java[./]util[./]Base64|Base64\.(?:get\w*Decoder|decode)|BASE64Decoder"),
    ("java_agent", {JAVA}, "high", "T1574", "Java agent (premain/Instrumentation)",
     r"\bpremain\b|java[./]lang[./]instrument|\bInstrumentation\b|Launcher-Agent-Class"),
    ("java_native_load", {JAVA}, "medium", "T1129", "loads native code (System.load/JNI)",
     r"System\.load(?:Library)?\s*\(|\bRegisterNatives\b"),
    ("java_disable_security", {JAVA}, "medium", "T1562", "disables the SecurityManager",
     r"setSecurityManager\s*\(\s*null|System\.setSecurityManager"),
    ("java_webshell_input", {JAVA}, "medium", "T1505.003", "reads attacker input (JSP/servlet)",
     r"request\.get(?:Parameter|Header|InputStream|Reader|QueryString)\b|getParameterValues"),
    ("java_jsp_scriptlet", {JAVA}, "medium", "T1505.003", "JSP scriptlet / expression",
     r"<%[=@!]?\s|<jsp:|runtime\.exec|pageContext\b"),
    ("java_file_write", {JAVA}, "medium", "T1105", "writes files (FileOutputStream)",
     r"FileOutputStream|java[./]nio[./]file[./]Files\b|\.getBytes\s*\(\s*\)\s*\)|RandomAccessFile"),
]

# Rules that, alone, are too noisy to raise by themselves (still shown as hits).
_NOISE_ALONE = {"js_redirect"}

_COMPILED: dict[str, tuple[set[str], str, str, str, re.Pattern]] = {
    rid: (langs, sev, attack, label, re.compile(rx, re.IGNORECASE))
    for rid, langs, sev, attack, label, rx in _RULES
}


def rules_for(lang: str) -> list[str]:
    """Rule ids that apply to a language (for docs / tests)."""
    return [rid for rid, (langs, *_rest) in _COMPILED.items() if lang in langs]


def scan(code: str, lang: str) -> list[dict[str, Any]]:
    """Behaviour hits in ``code`` for ``lang``.

    Returns the parsers' hit shape: ``rule``/``severity``/``label``/
    ``line_no``/``line`` plus ``attack``; the ATT&CK id is appended to the
    label so it reaches the finding detail and the UI.
    """
    hits: list[dict[str, Any]] = []
    lines = code.splitlines() or [""]
    for rid, (langs, sev, attack, label, rx) in _COMPILED.items():
        if lang not in langs:
            continue
        count = 0
        for no, ln in enumerate(lines, 1):
            if rx.search(ln):
                hits.append({"rule": rid, "severity": sev, "attack": attack,
                             "label": f"{label} · {attack}" if attack else label,
                             "line_no": no, "line": ln.strip()[:300]})
                count += 1
                if count >= _HITS_PER_RULE:
                    break
    return sorted(hits, key=lambda h: (h["line_no"], h["rule"]))


def risk_escalation(hits: list[dict[str, Any]]) -> dict[str, Any] | None:
    """When several distinct high-severity behaviour families co-occur, a script
    is an attack chain, not an isolated oddity. Returns a synthetic high finding
    describing the chain, or None."""
    highs = {h["rule"] for h in hits if h["severity"] == "high"}
    # Group by behaviour family via the rule id's second token.
    families = {r.split("_", 1)[1].split("_")[0] for r in highs}
    key = {"download", "exec", "iex", "shell", "lolbin", "shellcode", "run",
           "wscript", "reflection", "file", "download", "activex", "cred",
           "persist", "wmi", "amsi", "bits", "service", "addtype",
           "subprocess", "inject", "socket", "credentials", "packed",
           "defineclass", "jndi", "deserialization", "webshell", "script"}
    hit_families = families & key
    if len(highs) >= 2 and len(hit_families) >= 2:
        return {"rule": "script_attack_chain", "severity": "high", "attack": "T1059",
                "label": "multiple high-risk behaviours in one script (attack chain)",
                "detail": "chains: " + ", ".join(sorted(highs))}
    return None
