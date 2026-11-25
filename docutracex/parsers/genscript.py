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
    ("script_unhook", "medium", "reads a clean ntdll (KnownDlls / disk) to unhook security products",
     re.compile(r"(?i)\\KnownDlls(?:32)?\\ntdll\.dll|System32\\ntdll\.dll.{0,200}(?:CreateFileMapping|MapViewOfFile)")),
    ("script_av_check", "medium", "looks for security products' processes",
     re.compile(r"(?i)\b(?:avp|avpui|bdagent|bdservicehost|avastui|avastsvc|avgui|msmpeng|mssense|ekrn|egui|"
                r"mbam|mbamservice|sophos\w*|savservice|cylancesvc|csfalconservice|sentinelagent|"
                r"xagt|tmbmsrv|ntrtscan|wrsa|hmpalert)\.exe\b")),
    ("script_persistence", "medium", "persistence (Run key, scheduled task, startup folder)",
     re.compile(r"(?i)CurrentVersion\\+Run|schtasks|RegWrite|@StartupDir|\\Startup\\|crontab|systemctl\s+enable")),
]


# behaviours made of several API names anywhere in the script (each looked up on its own: a
# lookahead over a multi-MB line of hex would backtrack for minutes)
_ALL_OF: list[tuple[str, str, str, list[re.Pattern[str]]]] = [
    ("script_process_injection", "high", "injects into another process (create / open it, write its memory, "
     "start or redirect a thread — process hollowing)",
     [re.compile(r"\b(?:CreateProcess[AW]?|NtCreateUserProcess|OpenProcess|NtOpenProcess)\b"),
      re.compile(r"\b(?:WriteProcessMemory|NtWriteVirtualMemory|NtMapViewOfSection)\b"),
      re.compile(r"\b(?:ResumeThread|NtResumeThread|SetThreadContext|NtSetContextThread|CreateRemoteThread|"
                 r"NtCreateThreadEx|QueueUserAPC|NtQueueApcThread)\b")]),
    ("script_amsi_etw_patch", "high", "patches AMSI / ETW in memory (defence evasion)",
     [re.compile(r"\b(?:VirtualProtect|NtProtectVirtualMemory)\b"),
      re.compile(r"(?i)\b(?:AmsiScanBuffer|amsi\.dll|EtwEventWrite\w*|NtTraceEvent)\b")]),
]


def _all_of(code: str, parts: list[re.Pattern[str]]) -> re.Match[str] | None:
    last = None
    for rx in parts:
        m = rx.search(code)
        if not m:
            return None
        last = m
    return last


def _metrics(code: str) -> dict[str, Any]:
    from .javascript import metrics
    try:
        return metrics(code[:2_000_000])
    except Exception:  # noqa: BLE001
        return {"lines": code.count("\n") + 1}


def _lang(path: Path) -> str | None:
    return LANGS.get(path.suffix.lower())


# AutoHotkey / AutoIt source recognised by its content (a renamed script has no extension)
_AHK_MARK = re.compile(r"(?im)^\s*(?:#NoEnv|#NoTrayIcon|#SingleInstance|#Persistent|#Requires\s+AutoHotkey|"
                       r"#ErrorStdOut|#KeyHistory|#MaxThreads|SetWorkingDir\b|SendMode\b|SetBatchLines\b|"
                       r"DetectHiddenWindows\b|ListLines\b|[A-Za-z_]\w*\s*:=)")
_AU3_MARK = re.compile(r"(?im)^\s*(?:#include\s*<\w+\.au3>|#Region\b|#AutoIt3Wrapper|Func\s+\w+\s*\(|EndFunc\b|"
                       r"(?:Local|Global|Dim)\s+\$\w+|\$\w+\s*=\s*[^=]|Opt\s*\(\s*\"|#NoTrayIcon\b)")
SNIFF_MAX = 4 * 1024 * 1024


def sniff(text: str) -> str | None:
    """The language of a script without a telling extension: AutoHotkey or AutoIt."""
    head = text[:200_000]
    ahk = {m.group(0).strip().split()[0].lower().split(":=")[0] for m in _AHK_MARK.finditer(head)}
    ahk_dir = {x for x in ahk if x.startswith("#") or x in ("setworkingdir", "sendmode", "setbatchlines",
                                                             "detecthiddenwindows", "listlines")}
    au3 = {m.group(0).strip()[:6].lower() for m in _AU3_MARK.finditer(head)}
    if "#requires" in ahk or len(ahk_dir) >= 2 or (ahk_dir and re.search(r"\bDllCall\s*\(|\w+\s*:=", head)):
        return "AutoHotkey"
    if len(au3) >= 3 or re.search(r"(?im)^\s*#include\s*<\w+\.au3>", head):
        return "AutoIt"
    return None


def _text_of(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            raw = fh.read(SNIFF_MAX)
    except OSError:
        return None
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace").lstrip("\ufeff")


# System DLLs: calling into them is ordinary scripting. Anything else named in a DllCall is a
# library the script brought (a side-loaded payload, often with an odd name and extension).
_SYSTEM_DLL = re.compile(r"(?i)^(?:kernel32|user32|ntdll|advapi32|shell32|ole32|oleaut32|ws2_32|wininet|winhttp|"
                         r"msvcrt|gdi32|gdiplus|comctl32|comdlg32|shlwapi|crypt32|psapi|iphlpapi|version|bcrypt|"
                         r"secur32|netapi32|urlmon|winmm|dwmapi|uxtheme|imm32|userenv|wtsapi32|setupapi|dbghelp|"
                         r"mpr|rpcrt4|winspool|wintrust|kernelbase|msimg32|powrprof|ncrypt|dnsapi)(?:\.dll)?$")
_DLLCALL = re.compile(r"(?i)\bDllCall\s*\(\s*([^,)]+)")
_ASSIGN_AHK = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*:=\s*(\"(?:[^\"]|\"\")*\"|'[^']*')\s*$")
_ASSIGN_AHK_LEGACY = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*([^\r\n%]+?)\s*$")
_ASSIGN_AU3 = re.compile(r"(?m)^\s*(?:(?:Local|Global|Dim|Const)\s+)*\$(\w+)\s*=\s*(\"[^\"]*\"|'[^']*')\s*$")


def _resolve(expr: str, env: dict[str, str]) -> str | None:
    """A DllCall's first argument with simple string variables and concatenation
    (``a . "\\b"`` in AutoHotkey, ``$a & "\\b"`` in AutoIt) put back together."""
    out = []
    for tok in re.split(r"\s*(?:\.|&)\s*(?=(?:[\"'$A-Za-z_]))", expr.strip()):
        tok = tok.strip()
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
            out.append(tok[1:-1].replace('""', '"'))
        elif re.fullmatch(r"\$?[A-Za-z_]\w*", tok) and tok.lstrip("$").lower() in env:
            out.append(env[tok.lstrip("$").lower()])
        else:
            return None
    return "".join(out) or None


def dll_calls(code: str) -> list[dict[str, str]]:
    """Libraries (not system DLLs) a script loads with DllCall, and the export it calls."""
    env: dict[str, str] = {}
    for rx in (_ASSIGN_AHK, _ASSIGN_AU3):
        for m in rx.finditer(code[:2_000_000]):
            env[m.group(1).lower()] = m.group(2)[1:-1]
    for m in _ASSIGN_AHK_LEGACY.finditer(code[:2_000_000]):
        env.setdefault(m.group(1).lower(), m.group(2).strip())
    out, seen = [], set()
    for m in _DLLCALL.finditer(code[:4_000_000]):
        target = _resolve(m.group(1), env)
        if not target:
            continue
        lib, _, export = target.replace("/", "\\").rpartition("\\") if "\\" in target or "/" in target else (target, "", "")
        if not export:                       # DllCall("lib.dll", …) in AutoIt: the function is the 2nd argument
            lib, export = target, ""
        base = re.split(r"[\\/]", lib)[-1]
        if not base or _SYSTEM_DLL.match(base):
            continue
        key = (base.lower(), export)
        if key in seen:
            continue
        seen.add(key)
        out.append({"library": lib, "file": base, "export": export,
                    "line_no": code.count("\n", 0, m.start()) + 1, "call": m.group(0)[:200], "resolved": target})
    return out[:20]


def analyze(original: Path, extracted_dir: Path | None = None,
            modules: dict[str, Any] | None = None, lang: str | None = None) -> dict[str, Any]:
    """``lang``: the language when the caller recognised it by the content (a .txt)."""
    res: dict[str, Any] = {"module": "script", "status": "ok", "scripts": [], "findings": []}
    lang = _lang(original) or lang
    if lang and not _lang(original):
        res["sniffed"] = lang
    if not original.is_file():
        return res
    if not lang:
        # no telling extension (a renamed script): recognised by its content
        if original.stat().st_size > SNIFF_MAX:
            return res
        text = _text_of(original)
        lang = sniff(text) if text else None
        if not lang:
            return res
        res["sniffed"] = lang
    try:
        blob = original.read_bytes()[:MAX_BYTES]
    except OSError:
        return res
    from ..contentcheck import is_text
    if not is_text(blob):
        return res                      # binary under a script name: not code (see contentcheck)
    code = blob.decode("utf-8", "replace")
    orig = code
    deob: dict[str, Any] = {}
    if lang == "AutoIt" and "func" in code[:4_000_000].lower():
        # strings hidden behind the script's own decoder functions: decrypted statically
        from . import au3eval
        try:
            deob = au3eval.deobfuscate(code[:au3eval.MAX_SCRIPT])
        except Exception:  # noqa: BLE001  (never fails the analysis)
            deob = {}
        if deob.get("decoded"):
            code = deob["code"]
    hits = []
    for rule, sev, what, rx in RULES + _ALL_OF:
        m = rx.search(code[:4_000_000]) if not isinstance(rx, list) else _all_of(code[:4_000_000], rx)
        if m:
            line = code.count("\n", 0, m.start()) + 1
            a = code.rfind("\n", 0, m.start()) + 1
            b = code.find("\n", m.start())
            hits.append({"rule": rule, "severity": sev, "label": what, "line_no": line,
                         "line": code[a:b if b >= 0 else len(code)][:300], "match": m.group(0)[:200]})
            res["findings"].append({"tool": "script", "rule": rule, "severity": sev,
                                    "detail": f"{lang} script {what}",
                                    "location": f"file:{original.name}:{line}",
                                    "evidence": m.group(0)[:400]})
    for c in dll_calls(code):
        what = (f"loads the library '{c['file']}' and calls its export '{c['export']}'" if c["export"]
                else f"loads the library '{c['file']}'")
        hits.append({"rule": "script_dll_load", "severity": "high", "label": what, "line_no": c["line_no"],
                     "line": c["call"], "match": c["resolved"]})
        res["findings"].append({"tool": "script", "rule": "script_dll_load", "severity": "high",
                                "detail": f"{lang} script {what} (not a system DLL: "
                                          "a payload brought along and run through the interpreter)",
                                "location": f"file:{original.name}:{c['line_no']}",
                                "evidence": f"{c['call']}  →  {c['resolved']}", "attack": "T1129"})
    res["dll_calls"] = dll_calls(code)
    if deob.get("decoded"):
        fns = ", ".join(f"{k} ({v})" for k, v in sorted(deob["functions"].items(), key=lambda x: -x[1])[:6])
        uniq = list(dict.fromkeys(d["value"] for d in deob["decoded"]))
        res["decoded_strings"] = uniq
        res["findings"].append({"tool": "script", "rule": "script_strings_decrypted", "severity": "medium",
                                "detail": f"{lang} script hides its strings behind its own decoder functions: "
                                          f"{len(deob['decoded'])} call(s) decrypted statically ({len(uniq)} "
                                          f"distinct strings) with {fns}",
                                "location": f"file:{original.name}", "evidence": "\n".join(uniq[:200]),
                                "attack": "T1027"})
    if len({h["rule"] for h in hits} & {"script_shellcode_loader", "script_download", "script_exec", "script_eval"}) >= 2:
        res["findings"].append({"tool": "script", "rule": "script_attack_chain", "severity": "high",
                                "detail": f"{lang} script chains "
                                          + ", ".join(sorted({h['rule'][7:] for h in hits})),
                                "location": f"file:{original.name}", "evidence": ""})
    sc = {"id": 1, "kind": lang + (" (by content)" if res.get("sniffed") else ""), "origin": f"file:{original.name}",
          "location": f"file:{original.name}", "size": len(orig),
          "code": code[:_KEEP], "code_truncated": len(code) > _KEEP,
          "hits": hits, "_full_code": orig,
          "metrics": _metrics(code)}
    if deob.get("decoded"):
        sc.update({"code_is_deobfuscated": True, "_full_deob": code, "original_code": orig[:_KEEP],
                   "original_truncated": len(orig) > _KEEP,
                   "deob_methods": [f"{len(deob['decoded'])} string(s) decrypted with the script's decoders "
                                    f"({', '.join(sorted(deob['functions']))[:200]})"]})
    # static resolution: the script's values and operations followed (never run) to what it runs,
    # writes, loads or downloads — the hidden stages go to Nested with their recipe
    resolved = _resolve_script(lang, orig, f"file:{original.name}", code if code != orig else None)
    if resolved:
        ext = _LANG_EXT.get(lang, "")
        for st in resolved["stages"]:
            if "ext" not in st and "text" in st:
                st["ext"] = ext
        sc["decoded_stages"] = resolved["stages"]
        sc["resolution"] = resolved["summary"]
        res["findings"].extend({"tool": "script", **f} for f in resolved["findings"])
    res["scripts"].append(sc)
    return res


_LANG_EXT = {"PHP": ".php", "Perl": ".pl", "Ruby": ".rb", "Lua": ".lua", "AutoHotkey": ".ahk", "shell": ".sh",
             "Tcl": ".tcl", "AutoIt": ".au3"}
_PREFIX = {"PHP": "php", "Perl": "perl", "Ruby": "ruby", "Lua": "lua", "AutoHotkey": "ahk", "shell": "sh",
           "Tcl": "tcl", "AutoIt": "au3"}


def _resolve_script(lang: str, code: str, loc: str, alt: str | None) -> dict[str, Any] | None:
    """The language's static evaluator (``resolve/``), when it has one."""
    from ..resolve import report
    if lang in ("PHP", "Perl", "Ruby", "Lua", "AutoHotkey"):
        from ..resolve import dyn_eval
        fn = dyn_eval.resolver(lang)
    elif lang == "shell":
        from ..resolve import sh_eval
        fn = sh_eval.resolve
    elif lang == "Tcl":
        from ..resolve import tcl_eval
        fn = tcl_eval.resolve
    elif lang == "AutoIt":
        from ..resolve import au3_eval
        fn = au3_eval.resolve
    else:
        return None
    if not code.strip():
        return None
    return report.run(fn, code, loc, _PREFIX[lang], alt)
