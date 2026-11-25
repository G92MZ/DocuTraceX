"""The language of a script by its content — a ``.txt``, a file with no telling extension.

Each language has telltale constructs, weighted by how much they belong to it alone
(``[Convert]::`` and ``-bxor`` are PowerShell; ``$x =`` is PowerShell, Perl and PHP alike). A
language's score is the sum of the weights of the constructs found (each once). Only the
languages that score high enough, near the best one, are returned: a PowerShell loader is
read by the PowerShell engine, not also by the VBScript and batch ones (whose rules would see
PowerShell as theirs). With no clear language, :func:`languages` returns ``[]`` and the caller
may try every engine.
"""

from __future__ import annotations

import re

HEAD = 400_000           # characters looked at (the start says the language; a blob does not)
MIN_SCORE = 6
NEAR = 0.5               # a language within half of the best one's score is kept as well

_F = re.IGNORECASE | re.MULTILINE

_FEATURES: dict[str, list[tuple[int, str]]] = {
    "powershell": [
        (5, r"\[(?:System\.)?(?:Convert|Text\.Encoding|IO\.\w+|Reflection\.\w+|Security\.Cryptography\.\w+|"
            r"Runtime\.InteropServices\.\w+|Net\.\w+|ScriptBlock|Environment|Byte\[\]|char\[\]|string\[\])\]"),
        (4, r"\s-(?:bxor|band|bor|join|split|replace|creplace|ireplace|f|eq|ne|lt|gt|le|ge|like|match|notmatch|contains)\s"),
        (5, r"\b(?:Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|Start-Process|New-Object|Get-Process|"
            r"Start-Sleep|Write-Host|Write-Output|Set-StrictMode|Add-Type|ConvertTo-SecureString|Get-WmiObject|"
            r"Get-CimInstance|Set-ItemProperty|New-ItemProperty|Out-Null|ForEach-Object|Where-Object)\b"),
        (4, r"^\s*function\s+[\w-]+-[\w-]+\s*(?:\{|\()"),
        (4, r"@'\s*$|^'@|@\"\s*$|^\"@"),
        (3, r"\bparam\s*\(\s*(?:\[|\$)"),
        (3, r"\$(?:ErrorActionPreference|env:\w+|PSHome|ShellId|ExecutionContext|PSScriptRoot|null|true|false)\b"),
        (2, r"\$\w+\s*=\s*"),
        (3, r"\b(?:iex|sal|gcm|gci|irm|iwr)\b\s*[\(\$'\"]"),
        (3, r"::(?:FromBase64String|GetString|GetBytes|Load|Create|ReadAllBytes|WriteAllBytes)\s*\("),
    ],
    "javascript": [
        (4, r"\b(?:var|let|const)\s+[\w$]+\s*=[^=]"),
        (4, r"\bfunction\s*[\w$]*\s*\([^)]*\)\s*\{"),
        (5, r"new\s+ActiveXObject\s*\(|WScript\.(?:CreateObject|Shell|Sleep|Echo|ScriptFullName)|GetObject\s*\(\s*['\"]winmgmts"),
        (4, r"String\.fromCharCode|\.charCodeAt\s*\(|\bdocument\.|\bwindow\.|\batob\s*\(|\bJSON\.parse"),
        (3, r"=>\s*[\{\(\w]|\bnew\s+(?:Array|Date|Function|RegExp)\s*\("),
        (2, r";\s*$"),
        (2, r"\beval\s*\(|\.split\(['\"]['\"]\)\.reverse\(\)"),
        (3, r"\bthis\.\w+|\bprototype\b|\bundefined\b"),
    ],
    "vbscript": [
        (5, r"^\s*Dim\s+\w+|^\s*(?:Private|Public)\s+(?:Sub|Function)\b|^\s*End\s+(?:Sub|Function|If|With)\b"),
        (4, r"\bCreateObject\s*\(\s*\"|\bSet\s+\w+\s*=\s*(?:CreateObject|GetObject|New\b)"),
        (4, r"^\s*On\s+Error\s+Resume\s+Next|\bExecute(?:Global)?\s+\w|\bThen\s*$"),
        (3, r"&\s*Chr[WB]?\s*\(|\bChr[WB]?\s*\(\s*\d+\s*\)\s*&|\bStrReverse\s*\(|\bMid\s*\("),
        (2, r"^\s*'|^\s*Rem\s"),
        (3, r"^\s*(?:For\s+\w+\s*=|Next\b|Wend\b|Loop\b)"),
    ],
    "batch": [
        (6, r"^\s*@?echo\s+off\b"),
        (4, r"^\s*set\s+(?:/[ap]\s+)?\"?\w+=|^\s*setlocal\b"),
        (4, r"%~?\w+:~-?\d+(?:,-?\d+)?%|![\w]+!|%~[dpnxf0-9]+"),
        (3, r"^\s*(?:goto|call|rem|exit\s+/b|if\s+(?:not\s+)?(?:exist|errorlevel|defined))\b|^\s*:\w+\s*$|^\s*::"),
        (2, r"%\w+%"),
        (3, r"\b(?:start\s+\"\"|cmd(?:\.exe)?\s+/[ck]|certutil\s+-|bitsadmin\s+/)"),
    ],
    "python": [
        (5, r"^\s*(?:import\s+[\w.]+(?:\s*,\s*[\w.]+)*|from\s+[\w.]+\s+import\s+[\w*(])\s*$"),
        (4, r"^\s*def\s+\w+\s*\([^)]*\)\s*(?:->\s*[\w\[\], .]+)?:\s*$"),
        (4, r"\bexec\s*\(|\b__import__\s*\(|\bmarshal\.loads|\bbase64\.b64decode|\bzlib\.decompress|\bctypes\.\w+"),
        (3, r"^\s*(?:if|elif|for|while|with|try|except[^:]*|else|class\s+\w+[^:]*)\s*.*:\s*$"),
        (3, r"if\s+__name__\s*==\s*['\"]__main__['\"]|\bprint\s*\(|\bself\.\w+"),
        (2, r"\b(?:None|True|False)\b|\blambda\s+\w*\s*:"),
    ],
    "perl": [
        (6, r"^#!.*\bperl\b|^\s*use\s+(?:strict|warnings|[\w:]+::\w+|MIME::Base64|IO::Socket)"),
        (4, r"\bmy\s+[\$@%]\w+|\bour\s+[\$@%]\w+"),
        (4, r"\$\w+\s*=~\s*[smy]?/|\bsub\s+\w+\s*\{|\bdecode_base64\s*\(|\bunpack\s*\(\s*['\"][HCNnVvaA]"),
        (2, r"\bprint\s+\$|\bchomp\s*\(|\bdie\s+"),
    ],
    "php": [
        (8, r"<\?php|<\?=\s"),
        (4, r"\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|openssl_decrypt|preg_replace|"
            r"create_function|file_get_contents|shell_exec|passthru)\s*\("),
        (3, r"\$\w+\s*=\s*[^;]+;\s*$|->\w+\s*\("),
        (2, r"\becho\s+[\$'\"]|\bfunction\s+\w+\s*\(\s*\$"),
    ],
    "ruby": [
        (6, r"^#!.*\bruby\b|^\s*require\s+['\"][\w/]+['\"]\s*$"),
        (4, r"\bBase64\.(?:decode64|strict_decode64)|\bZlib::Inflate|\.each\s+do\s*\||\bputs\s"),
        (3, r"^\s*def\s+\w+[?!]?(?:\(.*\))?\s*$|^\s*end\s*$|\.unpack1?\s*\(\s*['\"]"),
        (2, r"\binstance_eval|\bsystem\s*\(|%x\{|`[^`]+`"),
    ],
    "lua": [
        (5, r"\blocal\s+\w+\s*=|\blocal\s+function\b"),
        (4, r"\bstring\.(?:char|byte|sub|rep|gsub)\s*\(|\bloadstring\s*\(|\bload\s*\(\s*\w|\bos\.execute|\bio\.popen"),
        (3, r"\bfunction\s+[\w.:]+\s*\([^)]*\)\s*$|^\s*end\s*$|~=|\.\.\s*['\"\w]"),
        (2, r"\bthen\s*$|\bnil\b|\belseif\b"),
    ],
    "tcl": [
        (5, r"^\s*proc\s+\w+\s*\{"),
        (4, r"\bset\s+\w+\s+\[|\[(?:expr|binary|string|exec|encoding)\s"),
        (3, r"^\s*(?:puts|package\s+require)\s"),
    ],
    "autoit": [
        (7, r"^\s*EndFunc\b|^\s*#include\s*<\w+\.au3>|^\s*#AutoIt3Wrapper|^\s*#Region\b"),
        (4, r"^\s*(?:Local|Global|Dim)\s+\$\w+|^\s*Func\s+\w+\s*\("),
        (4, r"\b(?:DllCall|DllStructCreate|DllStructSetData|BinaryToString|StringToBinary|ShellExecute|"
            r"FileInstall|InetGet|RegWrite|ProcessExists|StringReverse|Execute)\s*\("),
        (2, r"^\s*(?:EndIf|WEnd|Next|EndSwitch|EndSelect)\b"),
    ],
    "autohotkey": [
        (7, r"^\s*#(?:Requires\s+AutoHotkey|NoEnv|SingleInstance|Persistent|NoTrayIcon)\b"),
        (4, r"^\s*(?:SetWorkingDir|SendMode|SetBatchLines|DetectHiddenWindows|ListLines)\b"),
        (3, r"\b\w+\s*:=|\bDllCall\s*\(\s*\""),
    ],
    "shell": [
        (7, r"^#!\s*/(?:usr/)?bin/(?:env\s+)?(?:ba|z|k|da)?sh\b"),
        (4, r"\|\s*(?:base64\s+(?:-d|--decode)|gunzip|xxd\s+-r|sh|bash)\b|\bchmod\s+\+x\b|\bcurl\s+-[sSkLo]|\bwget\s+-[qO]"),
        (3, r"^\s*(?:if\s+\[|fi\s*$|then\s*$|done\s*$|esac\s*$|export\s+\w+=)"),
        (2, r"\$\(\s*\w|\$\{\w+\}|\beval\s+\""),
    ],
}

_COMPILED = {lang: [(w, re.compile(rx, _F)) for w, rx in feats] for lang, feats in _FEATURES.items()}


def scores(text: str) -> dict[str, int]:
    """Each language's score on ``text`` (only the languages with at least one construct)."""
    head = text[:HEAD]
    # a long encoded blob says nothing about the language: blanked out
    head = re.sub(r"[A-Za-z0-9+/=]{200,}|(?:\d{1,3}\s*,\s*){100,}\d{1,3}", " ", head)
    out = {}
    for lang, feats in _COMPILED.items():
        s = sum(w for w, rx in feats if rx.search(head))
        if s:
            out[lang] = s
    return out


def languages(text: str) -> list[str]:
    """The languages ``text`` is written in, best first; ``[]`` when none stands out."""
    sc = scores(text)
    if not sc:
        return []
    best = max(sc.values())
    if best < MIN_SCORE:
        return []
    return [lang for lang, s in sorted(sc.items(), key=lambda kv: -kv[1]) if s >= max(MIN_SCORE, best * NEAR)]


# genscript's language names for the languages it handles
GENSCRIPT = {"perl": "Perl", "php": "PHP", "ruby": "Ruby", "lua": "Lua", "tcl": "Tcl", "shell": "shell",
             "autoit": "AutoIt", "autohotkey": "AutoHotkey"}
