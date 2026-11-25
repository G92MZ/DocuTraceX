# Scripts

JavaScript / JScript (`.js` `.jse`), VBScript (`.vbs` `.vbe` `.wsf` `.wsc` `.sct`), HTA,
PowerShell (`.ps1` `.psm1`), batch (`.bat` `.cmd`) and Python (`.py` `.pyc`). The same engines
run on a script **wherever it hides**: a loose file, an email attachment, a macro, the command
of a shortcut, a PDF, an archive entry — and on the stages those scripts decode.

## How a script is analysed

0. **Content before extension.** A file named like a script (`.au3`, `.py`, `.pl`, `.ps1`, `.js`, `.vbs`,
   `.bat`…) has to be text to be read as one. UTF-16 with or without BOM, ANSI and encoded
   `.vbe` / `.jse` count as text. Binary content is reported (*disguised_binary*: the extension says
   one thing, the content another) and **not** read as code. Instead it goes down the binary path:
   - it is identified by its content (a PE, a ZIP, an OLE…);
   - the pieces embedded anywhere in it are carved out as children: a compiled AutoIt blob with junk
     in front, PEs cut to their real size, ZIP / 7z / CAB / OLE / PDF.

   In the case view, the **File** tab says the file is named like source but binary and lists what
   was carved (kind, offset, size); the script recovered from it (a decompiled AutoIt script) gets
   a direct tab, *AutoIt · script.au3*, with its code, decrypted strings and findings.

   Compiled AutoIt is always decompiled: AutoIt-Ripper (MIT) ships with DocuTraceX and is used when
   the portable Python does not have its own copy.

1. **Deobfuscate first.** Encodings (Base64, hex, percent, char codes), XOR and compression
   layers, string tricks (concatenation, reversal, `replace`, format operators) and the usual
   obfuscators (obfuscator.io, JSFuck, Invoke-Obfuscation, DOSfuscation, PyArmor…) are peeled,
   layer by layer, with the recipe of each.
2. **Name the techniques.** The obfuscation techniques found are listed with their evidence.
3. **Sandbox.** JavaScript, VBScript and PowerShell also run in **isolated sandboxes** that only
   record what the script would do (downloads, files written, processes, registry) — nothing
   reaches the system or the network.
4. **Behaviour.** The clean code is matched against a behaviour catalogue (execution, download,
   persistence, defence evasion, injection, credential access, C2…) with ATT&CK techniques.
5. **Stages.** Every decoded or decrypted stage becomes a **nested child**, analysed by the
   engine that fits it — a JScript that drops a VBScript that runs PowerShell is followed to
   the end.

## PowerShell resolved statically

PowerShell is not only deobfuscated: it is **evaluated statically**, step by step, without running
it. The evaluator follows variables and here-strings, the script's own functions with their
parameters, loops (a XOR loop over a byte array), conditions, pipelines and the .NET calls
loaders use: `[Convert]::FromBase64String`, `Text.Encoding`, `Aes` / `RijndaelManaged` +
`CreateDecryptor` + `CryptoStream`, `GZipStream` / `DeflateStream`, `MemoryStream`, `SHA256`,
`Reflection.Assembly::Load` + `GetMethod` + `Invoke`, `ConvertTo-SecureString -Key`… What reaches
a call that **runs** code (`Invoke-Expression`, `ScriptBlock::Create`, `-EncodedCommand`),
**loads** bytes (`Assembly.Load`, a PE handed to a loaded assembly's method) or **writes** a file is a
stage in **Nested**, with its recipe (`here-string $P → base64 → aes-256-cbc(key $K, iv $V) → gzip`).
Code it runs is evaluated too, so a second layer's binaries come out under it.

- **Computed command names** are resolved like any value: `& ("Inv"+"oke-Expression")`, `-f`,
  `$env:ComSpec[4,15,25] -join ''`, `$PSHome` / `$ShellId`, backticks and case, `gcm I*e-E*n`,
  `Set-Alias` / `sal`, `$ExecutionContext.InvokeCommand.InvokeScript`, reversed strings, computed
  types and methods (`New-Object ('Net.Web'+'Client')`, `.('Down'+'loadString')`). Conditions that
  always give the same result are worked out; one that cannot be is followed both ways.
- **Downloads** are not fetched: a finding gives the URL (resolved even when built in pieces), the
  method and what the script would do with it (run it, load it, save it to a path and launch it)
  — get it and analyse it as a new case.
- **Dynamic call not resolved**: when a command's name, a type or the data a call gets depends on
  something that only exists on the victim's machine (a file, the registry, the computer or user
  name, the date) or the C2, it cannot be worked out from the script. A finding shows the
  expression, what it depends on and why; the rest of the script is still resolved.
- Bounded: steps, time and loop rounds (a `while ($true)` watch loop runs a few rounds).
- The **Resolution** tab (and a block in each script card) shows it: what the script runs, loads
  or writes, each stage's recipe step by step, the downloads, the calls not resolved and the trace.
  The Markdown report has the same in its Resolution section.

## Python resolved statically

Python is evaluated the same way: the source is parsed (never run) and the evaluator follows
assignments, functions and lambdas, comprehensions, loops (an in-place XOR over a `bytearray`),
conditions and the library calls droppers use: `base64` / `binascii` / `codecs` (rot13, hex),
`zlib` / `gzip` / `lzma` / `bz2`, `marshal`, PyCryptodome (`AES.new(key, AES.MODE_CBC, iv)`,
`unpad`), `cryptography` (Fernet, `Cipher`), `hashlib`, `bytes.fromhex`. What reaches `exec` /
`eval` / `compile`, `ctypes` (a buffer, `RtlMoveMemory`, `VirtualAlloc`), `subprocess` / `os.system`
(a `powershell -enc` becomes a `.ps1` stage) or `open(…, 'wb').write` is a stage in Nested with its
recipe; code it runs is evaluated too.

- **Computed names**: `getattr(__builtins__, 'ex'+'ec')`, `__import__('ba'+'se64')`,
  `getattr(module, name)` with a computed name.
- **Downloads** (`urllib`, `requests`) are reported with what the script does with them; a call
  whose name or data comes from the environment, a file or the network is a **dynamic call not
  resolved**, with why.

## JavaScript resolved statically

JavaScript and JScript are evaluated the same way, next to the V8 sandbox: the script is parsed
(never run) and the evaluator follows variables, closures, the script's functions (`call` /
`apply` / `bind`), arrays and objects, loops, `try` / `catch` and the string and array methods
obfuscators use (obfuscator.io's string array and rotation loop too). What reaches `eval`,
`Function`, `setTimeout("…")` or `document.write` is a stage in Nested with its recipe; bytes
saved with `ADODB.Stream` / `FileSystemObject` / `fs` are a written file with its path; commands
(`WScript.Shell.Run`, WMI `Win32_Process.Create`, `ShellExecute`, `child_process`) are followed
(`powershell -enc` → a `.ps1` stage, `mshta`, `certutil -urlcache`, `cmd /c`).

- **Decoders**: `atob`, `unescape`, `decodeURIComponent`, `String.fromCharCode(.apply)`, MSXML
  `bin.base64` / `bin.hex`, `ADODB.Stream` charset tricks, CryptoJS (AES with a passphrase or a
  key + IV, DES, TripleDES, RC4), pako, Node `Buffer` / `zlib` / `crypto.createDecipheriv`; XOR,
  add and subtract loops are named in the recipe (`xor(key k)`).
- **Computed names**: `this['ev'+'al']`, `window[a+b]`, `[]['constructor']['constructor'](code)`,
  `new Function(…)`.
- A script that **reads its own file** (`WScript.ScriptFullName`) gets its own source; a
  clock / sandbox check that would quit is followed on.
- **Downloads** (`MSXML2.XMLHTTP`, `WinHttpRequest`, `fetch`, `http(s).get`) are reported with
  what the script does with them; a name that comes from the registry or an environment variable
  is a **dynamic call not resolved**, with why.

## VBScript resolved statically

VBScript is tokenised, parsed and walked here (there is no VBScript engine in the loop): `Dim` /
`ReDim` / `Const`, `Set`, the script's `Function` / `Sub` (`ByRef`, the function name as its return
value, `GetRef`), `If` / `Select Case`, `For` / `For Each` / `Do` / `While`, `With`, arrays,
`On Error Resume Next` and the built-ins obfuscators use (`Chr` / `ChrW` / `Asc`, `Mid`,
`StrReverse`, `Replace`, `Split` / `Join`, `Xor` / `Mod` arithmetic). What reaches `Execute` /
`ExecuteGlobal` / `Eval` is a stage, evaluated in turn; the COM objects are the same ones the
JScript evaluator follows (`WScript.Shell`, `ADODB.Stream`, MSXML `bin.base64`, `XMLHTTP`,
`FileSystemObject`, WMI `Win32_Process.Create`), and a `Declare`d memory API fed from an array
(`RtlMoveMemory`) loads those bytes. Loops are named in the recipe (`literal d → reverse → sub(7)`).

## Batch resolved statically

A `.bat` / `.cmd` is walked the way `cmd.exe` reads it: `%var%` when a line is read, `!var!` when
a command runs, `%var:~s,l%` / `%var:a=b%`, `set /a`, carets, `&` / `&&` / `||` / `|`, blocks,
`if` / `for` (`/l`, lists, `/f` over text or a file) / `goto` / `call :label`, and `cmd /c "…"` as
a line of its own. Files go to a virtual folder: `echo … > x.vbs` / `>>`, `type` / `more +N`,
`copy /b a+b c`, `certutil -decode` / `-decodehex` (its own file too: a base64 block after the
code). What it writes is a stage with its recipe (`the script's own file → base64 (certutil
-decode) → writes and runs`); what it launches is followed (`powershell -enc` / `-c`,
`echo … | powershell -`, `mshta`, `certutil -urlcache`, `bitsadmin`, `curl`), and a command read
from the machine (`for /f` over `reg query`) is a dynamic call not resolved.

## PHP, Perl, Ruby, Lua, Tcl, shell, AutoIt and AutoHotkey resolved statically

The languages without an engine of their own are evaluated too (nothing runs):

- **PHP, Perl, Ruby, Lua, AutoHotkey** share one interpreter with a profile per language (strings,
  comments, variables, blocks, operators) and its library: PHP webshells (`eval(gzinflate(base64_decode(…)))`,
  decoder names built at run time like `$f = 'base'.'64_decode'`, `str_rot13`, `strrev`, `assert`,
  `create_function`, `preg_replace('/…/e')`, `openssl_decrypt`, `$_POST` / `$_GET` as what the request
  carries), Perl (`decode_base64`, `pack` / `unpack`, `s///`, `tr///`, backticks, `open` + `print`,
  `IO::Socket::INET`), Ruby (`Base64.decode64`, `Zlib::Inflate`, `pack`, `map { … }.join`,
  `instance_eval`, `File.binwrite`, `Net::HTTP`), Lua (`load` / `loadstring`, `string.char`,
  `:reverse()`, `~` XOR loops, `os.execute`, `io.open`) and AutoHotkey (`UrlDownloadToFile`, `Run`,
  `ComObjCreate("WScript.Shell")`, `FileAppend`, `DllCall` + `NumPut`).
- **Shell (sh / bash)** is read like a shell: quotes, `$var` / `${…}` expansions, `$(…)`, here-documents,
  pipes — `echo … | base64 -d | gunzip | sh`, `printf '\x…'`, `xxd -r -p`, `openssl enc -d`, `rev`,
  `tr`; `curl` / `wget` downloads (saved, made executable, run), `python -c` / `perl -e` stages and
  `/dev/tcp` reverse shells. The commands the other languages run (`system`, `os.execute`,
  backticks, `exec`) go through the same reading.
- **Tcl**: `[…]` / `$var` substitution, `eval` / `uplevel`, `binary decode`, `zlib`, `string reverse`
  / `map`, `format %c`, `exec`, `open` + `puts`, `http::geturl`.
- **AutoIt** runs the script's top level on the same evaluator that decrypts its strings: `Execute`,
  `Run` / `ShellExecute`, `InetGet`, `FileWrite`, `_Crypt_DecryptData` (key from `CryptDeriveKey`),
  and shellcode copied with `DllStructSetData` into `VirtualAlloc` memory and run with
  `CallWindowProc`.

Each stage goes to Nested with its recipe (`base64 → inflate → eval`, `number array d → sub(9) →
eval`, `Binary → decrypt (CryptDeriveKey) → DllStructSetData`); a value read from the machine or the
request (`RegRead`, `$_POST`, `$env(…)`, a file) makes the call a dynamic call not resolved.

## What each language resolves (and where it stops)

| Language | Follows to a stage | Decoders | Stops at |
|---|---|---|---|
| PowerShell | `iex` / `ScriptBlock::Create` / `-enc`, `Assembly.Load`, `WriteAllBytes`, `Start-Process` | base64, AES / 3DES (`CreateDecryptor`), GZip / Deflate, `-bxor` loops, `SecureString -Key`, here-strings | values from the machine (registry, files, `$env:` that is not standard), the network, `Add-Type` C# it does not compile |
| Python | `exec` / `eval` / `compile`, `ctypes` memory, `subprocess`, `open().write` | base64 / b85 / hex, zlib / gzip / lzma / bz2, `marshal`, PyCryptodome / `cryptography` (AES, Fernet…), XOR comprehensions | C extensions, `pickle`, network data, imported modules not in the file |
| JavaScript / JScript | `eval` / `Function` / `setTimeout("…")` / `document.write`, `ADODB.Stream` / FSO / `fs` writes, WSH and WMI commands | `atob`, `unescape`, `fromCharCode`, MSXML `bin.base64`, CryptoJS, pako, Node `zlib` / `crypto`, obfuscator.io | DOM events and timers that need a page, anti-analysis that needs a real engine (the V8 sandbox covers part of it) |
| VBScript | `Execute` / `ExecuteGlobal` / `Eval`, the same COM objects as JScript, `Declare`d memory APIs | `Chr` / `Asc` / `Mid` loops, `StrReverse`, `Replace`, `Split` / `Join`, MSXML `bin.base64` | `GetObject` of live objects, classes with behaviour |
| Batch | `cmd /c`, files written with `echo` / `certutil -decode` / `copy /b` / `more`, `echo … \| powershell -` | `%var:~s,l%`, `%var:a=b%`, `set /a`, `!var!`, `certutil -decode` / `-decodehex` | `for /f` over a command's output, `reg query`, `set /p` (what the user types); lines over 8191 characters (cmd's own limit) |
| PHP / Perl / Ruby / Lua / AutoHotkey | `eval` / `assert` / `create_function` / `preg_replace /e`, `load`, `instance_eval`; commands; written files | base64, gz*, `str_rot13`, `strrev`, `pack` / `unpack`, `openssl_decrypt`, `s///`, `tr`, `string.char`, XOR loops | the web request (`$_POST`, `$_GET`), extensions / gems / rocks not in the file, object-oriented frameworks |
| Shell | `\| sh`, `eval`, `sh -c`, `python -c` / `perl -e`, written files, `curl` / `wget` | `base64 -d`, `gunzip` / `xz` / `bzip2`, `xxd -r`, `openssl enc -d`, `printf`, `rev`, `tr`, `sed s///` | commands whose output only the machine knows (`uname`, `cat /etc/…`) |
| Tcl | `eval` / `uplevel`, `exec`, `open \|…`, `puts` | `binary decode`, `zlib`, `string reverse` / `map`, `format %c` | Tk widgets, packages not in the file |
| AutoIt | `Execute`, `Run` / `ShellExecute`, `InetGet`, `FileWrite`, shellcode in `VirtualAlloc` memory | the script's own decoder functions, `_Crypt_DecryptData`, `BinaryToString`, `StringReverse` | `Exit` at the top, UDFs from `#include`s not in the file |

**Blind trials.** A blob no evaluator reached (the script decrypts it with a module it imports, a
native helper, a function the evaluator stops at) is tried with the script's own key material:
XOR with one byte or with its arrays and strings, RC4, AES and 3DES with its keys as written and
as their MD5 / SHA-1 / SHA-256, IVs zero, in front of the data or from the script. A trial counts
only when it turns into a file, text or compressed data that inflates; the recipe says which key
(`aes-256-cbc(key sha256('…'), iv zero)`). Base64 written backwards is read the other way. Each
blob has a fixed budget of trials.

**Limits.** Every evaluator stops at a budget of steps and seconds, and every value at the output
limit (64 MB): an endless loop, endless recursion, a string that doubles, a huge array or a
decompression bomb ends the evaluation in seconds — the rest of the analysis stands.

## Emulation (sandbox): always, only where static stops, or off

Static evaluation never runs a script. Three **emulators** do run its code, inside a hooked engine
with no network and no real disk: the **V8 sandbox** for JavaScript (plus **box-js** for JScript /
WSH), **box-ps** for PowerShell (when provisioned) and **ViperMonkey** for VBA / VBScript
(when PyPy is provisioned). One setting, next to
*Analyze at a time*, decides when they run:

- **always** — on every script (the default);
- **only when static stops** — only on a script whose static evaluation reached no stage and no
  download (and is obfuscated or has calls not resolved);
- **off (static only)** — never: no script code runs on the machine.

What an emulator saw is shown in the script's **Resolution**, under *Seen in the sandbox*, next to the
static result (and in the Markdown report); the layers box-ps deobfuscates go to **Nested** as a
stage (recipe `sandbox (box-ps) → layers`), like the V8 sandbox's decoded and dropped stages.

### box-js (JScript / WSH)

[box-js](https://github.com/CapacitorSet/box-js) (MIT) emulates the Windows Script Host objects a
JScript dropper uses — `WScript.Shell`, `Scripting.FileSystemObject`, `ADODB.Stream`,
`MSXML2.XMLHTTP`, WMI, the registry — and records the files the script writes, the commands it
runs, the URLs it asks for (never fetched) and the code it evals. It is provisioned like the other
emulators — by the setup and on start, with npm on the portable Node (about 60 MB, no build tools);
*Diagnostics → box-js (Node) → Retry* or `python scripts/setup_portable_python.py --component boxjs`
installs it again.

It follows the same setting, runs on top-level scripts that use WSH objects (a
page's own code is left to V8), and adds to the V8 result: *Seen in the sandbox* lists both, each row
marked with the emulator that saw it; the files it writes and the code it evals go to **Nested** with
the recipe `sandbox (box-js) → writes …` / `→ eval` (a file the static evaluation or V8 already has
stays once, with its recipe); a command it saw run raises a finding.

box-js runs the script's code inside Node's `vm2`, which is no longer maintained and has known
escapes. Like every emulator here, it is best run on an analysis machine; *off* keeps all of them
from running.

### Busy loops

Droppers compute a key in a loop of millions of rounds that only turns numbers, to outlast
emulators. The static evaluation stops such a loop after its share of the budget, marks what it
assigns as unknown and goes on with the rest of the script (what does not depend on it is still
resolved); the loop is listed as a *call not resolved* — "a busy loop against emulators: its result
is left to the sandbox" — and nothing is decoded with a made-up key. A loop that builds a string or
an array (a long decoder) is not cut.

## A script whose extension says nothing

A `.txt`, `.dat`, `.log` or a file with no extension that holds a script — on its own or inside
an archive, an attachment, an installer — is recognised **by its content**: PowerShell,
JavaScript, VBScript, batch, Python, Perl, PHP, Ruby, Lua, Tcl, shell, AutoIt or AutoHotkey, by
the constructs that belong to each (`[Convert]::` and `-bxor` are PowerShell; `Dim` and
`End Sub` VBScript; `@echo off` batch…). Long encoded blobs are left out of the judgement. Only
the engines of that language read it, so no VBScript or batch rule fires on PowerShell code, and
the stages it decodes are named after it (`decrypted_powershell-…`). A text whose language is
not clear goes through every engine, as before. Scripts are read whole up to 64 MB.

## Polyglots: a page that is also a program

An HTML page can be a program at the same time: the page sits where the language ignores it — a
Python triple-quoted string, a PowerShell `<# #>` comment, a `<!-- :` batch / HTA hybrid, a
`/* */` comment (JScript, AutoHotkey), Lua `--[[ ]]`, Ruby `=begin`, Perl `__END__` / POD,
AutoIt `#cs`, Tcl `if 0 { }`, a shell here-document, PHP blocks — and a portable interpreter
(`pythonw.exe notes.html`) runs the code around it. Whatever the file's extension, DocuTraceX
reports **an HTML page that is also a *language* program** (high when the code decodes, runs or
downloads), and the code — with the page replaced by a placeholder — becomes a nested child
analysed by that language's engine: layers peeled, the loader recognised, the payload carved.

AutoIt, AutoHotkey, Lua, Ruby, Perl, Tcl, shell, PHP and similar scripts have no engine of their
own: a **generic** one flags shellcode loaders (`DllCall` / ffi / Fiddle / Win32::API with
`VirtualAlloc`, `CallWindowProc`…), downloads, command execution, dynamic evaluation and
persistence, and hands their byte arrays and encoded literals to the stage carver.

These scripts are analysed the same way when they are **uploaded on their own** (`.au3`, `.ahk`,
`.lua`, `.rb`, `.pl`, `.tcl`, `.sh`, `.php`…). A **compiled AutoIt script** written without the
interpreter (`.a3x`: `AU3!EA05` / `EA06` blob) is recognised by its content whatever its name;
AutoIt-Ripper recovers the script (as it does for compiled AutoIt EXEs) and the generic engine
reads it. Next to it, a renamed `AutoIt3.exe` is still found by the *OriginalFilename* of its
version information (the same goes for the other portable interpreters).

**Obfuscated AutoIt strings are decrypted statically.** Obfuscated AutoIt (DarkGate and other
loaders) hides every string behind the script's own decoder functions: `F("C4B2CAC7…", "key")`. A
small AutoIt evaluator built into DocuTraceX runs those decoders on their constant arguments and
puts the result back in the code (*script_strings_decrypted*). Calls nested inside calls are
resolved too.

- **What the evaluator can do:** only pure string and number work — loops, `StringMid`, `Chr`,
  `BitXOR`, `Dec`… — inside a step budget.
- **What it never does:** nothing outside its own values is reachable. `DllCall` returns zeros,
  file, registry, process and network functions do not exist, and a decoder that needs one is
  simply left as it was.

The rules then read the decrypted code, which brings up process hollowing, AMSI / ETW patching,
ntdll unhooking and checks for security products. The URLs and IPs become IOCs. The AutoIt tab
shows the decrypted code, and the original stays one click away.

**AutoHotkey** is covered the same way:

- `.ahk` scripts, and scripts with **no extension** recognised by their content (`#NoEnv`,
  `#NoTrayIcon`, `:=`…).
- EXEs compiled with **Ahk2Exe**: the script is taken from the `>AUTOHOTKEY SCRIPT<` resource. Old
  `JB01` ones go through AutoIt-Ripper.
- A renamed `AutoHotkey.exe` next to its script, even with no extension.
- `DllCall` is followed through simple variables (`lib := "x.dat"` then `DllCall(lib . "\Export")`).
  A script that loads a library it brought along and calls its export is reported (*script_dll_load*,
  high). The archive's finding names the DLL in the bundle and whether its export table has that
  function: the side-loading shape of AutoHotkey loaders.

**Shellcode with PEs inside.** When a loader's bytes are a short stub (`jmp` over a few bytes)
followed by PEs — a reflective loader DLL and the program it maps — each PE becomes its own
child, **cut to the size its headers give**. What lies after it (zeros, a repeated pattern,
word lists or CSS used to inflate the file past size limits) is left out and named in the
recipe, so only the real program is analysed. A PE kept **in memory layout** (each section at its RVA, the
way a reflective loader maps it — its imports only make sense like that) is rebuilt as a file
first, so the usual engines can read it and padding hidden in its resources is stripped too.

The code of AutoIt, Lua, Ruby, Perl, Tcl, shell or PHP scripts has its own **Script** tab, with
the lines the rules flagged, like the other languages.

## Tabs

??? abstract "JavaScript"

    ![JavaScript tab of sample_obf_techniques.js](../assets/shots/scripts/javascript.webp){ .shot }

??? abstract "PowerShell"

    Also folds the stages a loader decrypts with key material written in the script (XOR,
    AES with `[byte[]]` keys, GZIP / Deflate).

    ![PowerShell tab of sample_crypto_loader.ps1](../assets/shots/scripts/powershell.webp){ .shot }

??? abstract "VBScript"

    ![VBScript tab of sample_xor_loader.vbs](../assets/shots/scripts/vbscript.webp){ .shot }

??? abstract "Batch"

    ![Batch tab of sample_dosfuscation.bat](../assets/shots/scripts/batch.webp){ .shot }

??? abstract "Python"

    Source, `exec` chains of public obfuscators, and byte-compiled `.pyc` (decompiled with pycdc
    when available, otherwise the calls and strings are rebuilt from the bytecode).

    ![Python tab of sample_dropper.pyc](../assets/shots/scripts/python.webp){ .shot }

!!! note "A text file of unknown type"
    goes through every script analyser too, so a dropper saved as `.txt` is not missed.
