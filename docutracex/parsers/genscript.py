"""Scripts in languages without a dedicated engine: AutoIt, AutoHotkey, Lua, Ruby,
Perl, Tcl, shell, PHP, Node.js-style JavaScript run outside the browser…

They arrive as the code around an HTML polyglot, or next to a portable
interpreter in an archive. The analysis is static and generic: behaviour rules
(a shellcode loader through the language's native-call bridge, downloads,
command execution, dynamic evaluation, decoding) and the script's code handed to
the stage carver (byte arrays, base64 literals → children). Nothing is run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

LANGS = {".au3": "AutoIt", ".ahk": "AutoHotkey", ".lua": "Lua", ".rb": "Ruby", ".rbw": "Ruby",
         ".pl": "Perl", ".pm": "Perl", ".tcl": "Tcl", ".tk": "Tcl", ".sh": "shell", ".bash": "shell",
         ".php": "PHP", ".cjs": "JavaScript (Node.js)", ".r": "R", ".jl": "Julia"}
MAX_BYTES = 96 * 1024 * 1024
_KEEP = 80_000

# native-call bridges of each language (how a script reaches the Windows API)
_BRIDGE = (r"DllCall|DllStructCreate|DllStructSetData|ffi\.(?:C|cdef|load)|ffi-napi|node-ffi|koffi|"
           r"Fiddle|Win32API|Win32::API|DynaLoader|FFI::Platypus|ctypes|ffi::|Rcpp|ccall")
_MEMORY = (r"VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|RtlMoveMemory|RtlCopyMemory|CreateThread|"
           r"CreateRemoteThread|NtAllocateVirtualMemory|WriteProcessMemory|CallWindowProc|EnumWindows|"
           r"EnumSystemLocales|QueueUserAPC|NtCreateThreadEx|HeapCreate")
RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("script_shellcode_loader", "high", "native-call bridge allocating executable memory / starting a thread "
     "(a shellcode loader)", re.compile(rf"(?is)\b(?:{_BRIDGE})\b.{{0,4000}}\b(?:{_MEMORY})\b|\b(?:{_MEMORY})\b.{{0,4000}}\b(?:{_BRIDGE})\b")),
    ("script_download", "medium", "downloads from the network",
     re.compile(r"(?i)\b(?:URLDownloadToFile|InetGet|InetRead|HttpRequest|WinHttp|Net::HTTP|open-uri|LWP::|HTTP::Tiny|"
                r"curl\s|wget\s|Invoke-WebRequest|http\.request|https\.get|fetch\(|socket\.http|file_get_contents\s*\(\s*['\"]https?:|"
                r"http::geturl|download\.file)\b")),
    ("script_exec", "medium", "runs commands or programs",
     re.compile(r"(?i)\b(?:Run(?:Wait)?\s*[,(]|ShellExecute(?:Wait)?\s*\(|system\s*\(|exec\s*[\s(]|popen\s*\(|os\.execute|"
                r"io\.popen|shell_exec|passthru|proc_open|child_process|spawn\s*\(|execSync|IO\.popen|Open3|"
                r"Kernel\.(?:system|exec)|ComObjCreate|ObjCreate\s*\(\s*['\"]WScript\.Shell)")),
    ("script_eval", "medium", "evaluates code built at run time",
     re.compile(r"(?i)\b(?:Execute\s*\(|eval\s*[\s(]|loadstring\s*\(|load\s*\(\s*\w+|instance_eval|class_eval|"
                r"assert\s*\(\s*\$|create_function|new\s+Function\s*\(|vm\.runIn\w+|uplevel|interp\s+eval)")),
    ("script_decode", "low", "decodes base64 / hex / packed data",
     re.compile(r"(?i)\b(?:BinaryToString|_Base64Decode|Base64\.decode64|unpack\s*\(\s*['\"]m|decode_base64|"
                r"base64_decode|gzinflate|gzuncompress|str_rot13|Buffer\.from\s*\([^)]*['\"](?:base64|hex)|"
                r"binary\s+decode\s+base64|mime\.unb64|base64\s+-d)\b")),
    ("script_persistence", "medium", "persistence (Run key, scheduled task, startup folder)",
     re.compile(r"(?i)CurrentVersion\\+Run|schtasks|RegWrite|@StartupDir|\\Startup\\|crontab|systemctl\s+enable")),
]


def _lang(path: Path) -> str | None:
    return LANGS.get(path.suffix.lower())


def analyze(original: Path, extracted_dir: Path | None = None,
            modules: dict[str, Any] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "script", "status": "ok", "scripts": [], "findings": []}
    lang = _lang(original)
    if not lang or not original.is_file():
        return res
    try:
        code = original.read_bytes()[:MAX_BYTES].decode("utf-8", "replace")
    except OSError:
        return res
    hits = []
    for rule, sev, what, rx in RULES:
        m = rx.search(code[:4_000_000])
        if m:
            line = code.count("\n", 0, m.start()) + 1
            hits.append({"rule": rule, "severity": sev, "line": line, "match": m.group(0)[:200]})
            res["findings"].append({"tool": "script", "rule": rule, "severity": sev,
                                    "detail": f"[{original.name}] {lang} script {what}",
                                    "location": f"file:{original.name}:{line}",
                                    "evidence": m.group(0)[:400]})
    if len({h["rule"] for h in hits} & {"script_shellcode_loader", "script_download", "script_exec", "script_eval"}) >= 2:
        res["findings"].append({"tool": "script", "rule": "script_attack_chain", "severity": "high",
                                "detail": f"[{original.name}] {lang} script chains "
                                          + ", ".join(sorted({h['rule'][7:] for h in hits})),
                                "location": f"file:{original.name}", "evidence": ""})
    res["scripts"].append({"id": 1, "kind": lang, "origin": f"file:{original.name}",
                           "location": f"file:{original.name}", "size": len(code),
                           "code": code[:_KEEP], "code_truncated": len(code) > _KEEP,
                           "hits": hits, "_full_code": code})
    return res
