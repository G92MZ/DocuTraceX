"""PowerShell, evaluated statically: what a loader computes, without running it.

A small interpreter over :mod:`ps_parse`'s tree. Values are computed from the script's text —
variables, here-strings, functions with parameters, loops, conditions, pipelines and the .NET
calls loaders use (``[Convert]::FromBase64String``, ``Aes`` + ``CryptoStream``, ``GZipStream``,
``MemoryStream``, ``Reflection.Assembly::Load``…) — and what reaches an execute / load / write
call goes to :class:`~docutracex.resolve.sinks.Sinks` with its recipe. Nothing touches the disk,
the network or a process: a download is reported (URL, method, what would be done with it), a
file read or a registry value is an *unknown* value, and every external command is recorded
instead of run.

Commands with computed names are resolved like any value: ``& ("Inv"+"oke-Expression")``,
``.( $env:ComSpec[4,15,25] -join '')``, ``&(gcm I*e-E*n)``, ``Set-Alias``, backticks and case,
``$ExecutionContext.InvokeCommand.InvokeScript``, computed types and methods. One that depends
on the victim's machine is reported as a dynamic call not resolved.

Bounded: steps, time, loop iterations (a ``while ($true)`` watch loop runs a few rounds) and
nesting of the code it evaluates inline.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
import time
from typing import Any, Callable

from . import transforms as T
from .ps_parse import parse
from .sinks import Sinks
from .value import Value

MAX_STEPS = 6_000_000
MAX_SECONDS = 90.0
MAX_LOOP = 2_000_000          # iterations of one loop
MAX_FOREVER = 3               # iterations of a loop whose condition is a constant true
MAX_DEPTH = 12                # code evaluated inline (Invoke-Expression of Invoke-Expression…)
MAX_CALL_DEPTH = 64


# --- values with a recipe --------------------------------------------------------------
class RStr(str):
    recipe: tuple[str, ...] = ()


class RBytes(bytearray):
    """A PowerShell ``byte[]``. ``inplace``: the operation a loop applied to it in place (``xor(0x5a)``)."""
    recipe: tuple[str, ...] = ()
    inplace: str = ""


class PSList(list):
    recipe: tuple[str, ...] = ()


class Unk:
    """A value not computable from the script."""

    def __init__(self, why: str, recipe: tuple[str, ...] = ()) -> None:
        self.why = why
        self.recipe = recipe

    def __repr__(self) -> str:
        return f"<unknown: {self.why}>"


def rec(v: Any) -> tuple[str, ...]:
    return getattr(v, "recipe", ()) or ()


def tag(v: Any, recipe: tuple[str, ...]) -> Any:
    """``v`` carrying ``recipe`` (a copy for immutable types)."""
    if isinstance(v, str):
        v = RStr(v) if type(v) is str else v
    elif isinstance(v, (bytes, bytearray)) and not isinstance(v, RBytes):
        v = RBytes(v)
    elif isinstance(v, list) and not isinstance(v, PSList):
        v = PSList(v)
    try:
        v.recipe = tuple(recipe)[-40:]
    except AttributeError:
        pass
    return v


def step(v: Any, name: str, out: Any) -> Any:
    return tag(out, rec(v) + ((name,) if name else ()))


def label(v: Any, fallback: str = "") -> str:
    """A short name for where a value comes from (``$K``), for a recipe step."""
    for r in rec(v):
        m = re.search(r"(\$[\w:]+)", r)
        if m:
            return m.group(1)
    return fallback


# --- control flow -----------------------------------------------------------------------
class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value: Any) -> None:
        self.value = value
        self.partial: list = []          # the output before the return statement


class _Throw(Exception):
    def __init__(self, value: Any) -> None:
        self.value = value


class _Exit(Exception):
    pass


class Limit(Exception):
    pass


# --- .NET objects -----------------------------------------------------------------------
class TypeRef:
    def __init__(self, name: str) -> None:
        self.name = name
        self.key = norm_type(name)

    def __repr__(self) -> str:
        return f"[{self.name}]"


class Obj:
    """A .NET / COM object of the script, by kind (``kind`` + attributes)."""

    def __init__(self, kind: str, **kw: Any) -> None:
        self.kind = kind
        self.props: dict[str, Any] = {}
        self.__dict__.update(kw)
        self.recipe = kw.get("recipe", ())

    def __repr__(self) -> str:
        return f"<{self.kind}>"


class ScriptBlock:
    def __init__(self, body: list | None, text: str | None = None, recipe: tuple[str, ...] = ()) -> None:
        self.body = body
        self.text = text
        self.recipe = recipe

    def __str__(self) -> str:
        return self.text or ""


class CommandInfo:
    def __init__(self, name: str) -> None:
        self.name = name

    def __str__(self) -> str:
        return self.name


_ACCEL = {
    "convert": "convert", "text.encoding": "text.encoding", "encoding": "text.encoding",
    "string": "string", "str": "string", "int": "int", "int32": "int", "int64": "long", "long": "long",
    "int16": "int", "uint32": "long", "uint16": "int", "byte": "byte", "sbyte": "int", "char": "char", "bool": "bool",
    "boolean": "bool", "double": "double", "float": "double", "single": "double", "decimal": "double",
    "byte[]": "byte[]", "char[]": "char[]", "string[]": "string[]", "object[]": "object[]", "int[]": "int[]",
    "array": "array", "scriptblock": "scriptblock", "management.automation.scriptblock": "scriptblock",
    "type": "type", "regex": "regex", "text.regularexpressions.regex": "regex", "math": "math",
    "reflection.assembly": "assembly", "appdomain": "appdomain", "environment": "environment",
    "io.file": "io.file", "io.memorystream": "io.memorystream", "io.streamreader": "io.streamreader",
    "io.compression.gzipstream": "gzipstream", "io.compression.deflatestream": "deflatestream",
    "io.compression.compressionmode": "enum", "io.compression.zipfile": "zipfile",
    "security.cryptography.aes": "aes", "security.cryptography.aesmanaged": "aes",
    "security.cryptography.aescryptoserviceprovider": "aes", "security.cryptography.rijndaelmanaged": "aes",
    "security.cryptography.aescng": "aes",
    "security.cryptography.des": "des", "security.cryptography.descryptoserviceprovider": "des",
    "security.cryptography.tripledes": "3des", "security.cryptography.tripledescryptoserviceprovider": "3des",
    "security.cryptography.cryptostream": "cryptostream", "security.cryptography.rfc2898derivebytes": "pbkdf2",
    "security.cryptography.passwordderivebytes": "pbkdf2",
    "security.cryptography.sha256": "sha256", "security.cryptography.sha256managed": "sha256",
    "security.cryptography.sha256cryptoserviceprovider": "sha256", "security.cryptography.md5": "md5",
    "security.cryptography.md5cryptoserviceprovider": "md5", "security.cryptography.sha1": "sha1",
    "security.cryptography.sha1managed": "sha1", "security.cryptography.hmacsha256": "hmacsha256",
    "net.webclient": "webclient", "net.http.httpclient": "httpclient", "net.webrequest": "webrequest",
    "net.httpwebrequest": "webrequest", "net.servicepointmanager": "servicepointmanager",
    "runtime.interopservices.marshal": "marshal", "management.automation.pscredential": "pscredential",
    "pscredential": "pscredential", "security.securestring": "securestring",
    "collections.arraylist": "arraylist", "collections.generic.list[byte]": "arraylist",
    "collections.generic.list[object]": "arraylist", "collections.generic.list[string]": "arraylist",
    "linq.enumerable": "linq", "bitconverter": "bitconverter", "text.stringbuilder": "stringbuilder",
    "guid": "guid", "uri": "uri", "datetime": "datetime", "diagnostics.process": "process",
    "diagnostics.processstartinfo": "processstartinfo", "activator": "activator",
    "runtime.interopservices.runtimeenvironment": "runtimeenvironment", "io.path": "io.path",
    "web.httputility": "httputility", "net.webutility": "httputility", "uint8": "byte",
    "pscustomobject": "hashtable", "hashtable": "hashtable", "ordered": "hashtable", "void": "void",
    "security.cryptography.ciphermode": "enum", "security.cryptography.paddingmode": "enum",
    "security.cryptography.cryptostreammode": "enum", "reflection.bindingflags": "enum",
}


def norm_type(name: str) -> str:
    n = re.sub(r"\s+", "", str(name)).replace("`", "").lower()
    n = n[7:] if n.startswith("system.") else n
    return _ACCEL.get(n, n)


# --- the command names a script may compute -------------------------------------------------
CMDLETS = [
    "Invoke-Expression", "Invoke-Command", "Invoke-WebRequest", "Invoke-RestMethod", "Invoke-Item", "New-Object",
    "Start-Process", "Start-Sleep", "Start-Job", "Start-BitsTransfer", "Write-Host", "Write-Output", "Write-Verbose",
    "Write-Debug", "Write-Warning", "Write-Error", "Write-Information", "Out-Null", "Out-String", "Out-File",
    "Get-Process", "Stop-Process", "Get-Command", "Get-Alias", "Set-Alias", "New-Alias", "Get-Variable",
    "Set-Variable", "New-Variable", "Remove-Variable", "Get-Content", "Set-Content", "Add-Content", "Get-Item",
    "Get-ItemProperty", "Set-ItemProperty", "New-ItemProperty", "New-Item", "Remove-Item", "Copy-Item", "Move-Item",
    "Test-Path", "Join-Path", "Split-Path", "Resolve-Path", "ForEach-Object", "Where-Object", "Select-Object",
    "Sort-Object", "Measure-Object", "Group-Object", "Add-Type", "ConvertTo-SecureString", "ConvertFrom-SecureString",
    "ConvertFrom-Json", "ConvertTo-Json", "Set-StrictMode", "Get-WmiObject", "Get-CimInstance", "Invoke-WmiMethod",
    "Register-ScheduledTask", "New-ScheduledTaskAction", "Set-MpPreference", "Add-MpPreference", "Get-Random",
    "Get-Date", "Expand-Archive", "Compress-Archive", "Import-Module", "Get-ChildItem", "Set-Location",
    "Get-Location", "Unblock-File", "Clear-Host", "Read-Host", "Format-List", "Format-Table", "Tee-Object",
    "Get-Member", "Get-Host", "Get-Culture", "Get-ExecutionPolicy", "Set-ExecutionPolicy", "Wait-Job",
    "Receive-Job", "Get-Service", "Start-Service", "Stop-Service", "Restart-Computer", "Stop-Computer",
]
_CMDLET_LOWER = {c.lower(): c for c in CMDLETS}
ALIASES = {
    "iex": "Invoke-Expression", "icm": "Invoke-Command", "iwr": "Invoke-WebRequest", "irm": "Invoke-RestMethod",
    "curl": "Invoke-WebRequest", "wget": "Invoke-WebRequest", "ii": "Invoke-Item", "saps": "Start-Process",
    "start": "Start-Process", "sleep": "Start-Sleep", "echo": "Write-Output", "write": "Write-Output",
    "gps": "Get-Process", "ps": "Get-Process", "kill": "Stop-Process", "spps": "Stop-Process", "gcm": "Get-Command",
    "gal": "Get-Alias", "sal": "Set-Alias", "nal": "New-Alias", "gv": "Get-Variable", "sv": "Set-Variable",
    "set": "Set-Variable", "nv": "New-Variable", "rv": "Remove-Variable", "gc": "Get-Content", "cat": "Get-Content",
    "type": "Get-Content", "sc": "Set-Content", "ac": "Add-Content", "gi": "Get-Item", "gp": "Get-ItemProperty",
    "sp": "Set-ItemProperty", "ni": "New-Item", "ri": "Remove-Item", "rm": "Remove-Item", "del": "Remove-Item",
    "cp": "Copy-Item", "copy": "Copy-Item", "mv": "Move-Item", "move": "Move-Item", "%": "ForEach-Object",
    "foreach": "ForEach-Object", "?": "Where-Object", "where": "Where-Object", "select": "Select-Object",
    "sort": "Sort-Object", "measure": "Measure-Object", "group": "Group-Object", "gwmi": "Get-WmiObject",
    "gcim": "Get-CimInstance", "gci": "Get-ChildItem", "dir": "Get-ChildItem", "ls": "Get-ChildItem",
    "cd": "Set-Location", "sl": "Set-Location", "pwd": "Get-Location", "gl": "Get-Location", "cls": "Clear-Host",
    "fl": "Format-List", "ft": "Format-Table", "tee": "Tee-Object", "gm": "Get-Member", "ipmo": "Import-Module",
    "sajb": "Start-Job", "gsv": "Get-Service", "sasv": "Start-Service", "spsv": "Stop-Service", "rvpa": "Resolve-Path",
}

ENV = {
    "comspec": "C:\\WINDOWS\\system32\\cmd.exe", "windir": "C:\\WINDOWS", "systemroot": "C:\\WINDOWS",
    "systemdrive": "C:", "programfiles": "C:\\Program Files", "programfiles(x86)": "C:\\Program Files (x86)",
    "programdata": "C:\\ProgramData", "public": "C:\\Users\\Public", "allusersprofile": "C:\\ProgramData",
    "commonprogramfiles": "C:\\Program Files\\Common Files", "os": "Windows_NT",
    "processor_architecture": "AMD64", "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL",
    "psmodulepath": "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules",
}
# what only the victim's machine knows: an unknown value (with this reason) when used
ENV_MACHINE = {
    "username": "the victim's user name", "userprofile": "the victim's profile folder", "appdata": "the victim's AppData folder",
    "localappdata": "the victim's AppData folder", "temp": "the victim's TEMP folder", "tmp": "the victim's TEMP folder",
    "computername": "the victim's computer name", "userdomain": "the victim's domain", "homepath": "the victim's home folder",
    "logonserver": "the victim's logon server", "number_of_processors": "the victim's CPU count",
}
AUTOMATIC = {
    "pshome": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0", "shellid": "Microsoft.PowerShell",
    "verbosepreference": "SilentlyContinue", "debugpreference": "SilentlyContinue",
    "erroractionpreference": "Continue", "progresspreference": "Continue", "ofs": " ",
    "warningpreference": "Continue", "informationpreference": "SilentlyContinue", "confirmpreference": "High",
    "maximumhistorycount": 4096, "psculture": "en-US", "psuiculture": "en-US", "pid": 4242,
}


class Interp:
    def __init__(self, sinks: Sinks, source: str = "") -> None:
        self.sinks = sinks
        self.source = source
        self.scopes: list[dict[str, Any]] = [dict(AUTOMATIC)]
        self.scopes[0].update({"true": True, "false": False, "null": None})
        self.functions: dict[str, tuple] = {}
        self.aliases: dict[str, str] = {}
        self.steps = 0
        self.t0 = time.monotonic()
        self.depth = 0
        self.call_depth = 0
        self.errors: list[str] = []
        self.ran_inline: set[str] = set()
        self.assigned: dict[str, str] = {}          # variable -> sha256 of the value when assigned
        self.tracked: dict[str, Any] = {}           # variable -> its last value (any scope)

    # -- running ------------------------------------------------------------------------------
    def run(self, code: str) -> None:
        try:
            body = parse(code)
        except RecursionError:
            self.errors.append("too deeply nested to parse")
            return
        try:
            self.block(body, top=True)
        except (_Exit, Limit):
            pass
        except (_Return, _Break, _Continue):
            pass
        except _Throw as t:
            self.errors.append(f"script stops: {self.text(t.value)[:200]}")
        self.computed_values()

    def computed_values(self) -> None:
        """Values the script computed and left in a variable without running / loading / writing
        them: a PE or archive, or code, decoded by the script (often used by a later step it
        hides, or by a branch not taken here) — a stage as well."""
        from . import langdetect
        seen_ids: set[int] = set()
        for name, v in list(self.scopes[0].items()) + list(self.tracked.items()):   # the script's own names first
            if id(v) in seen_ids:
                continue
            seen_ids.add(id(v))
            ops = [r for r in rec(v) if not r.startswith(("literal", "here-string", "number array"))]
            if not isinstance(v, (RBytes, str, PSList)) or len(v) < 40 or (len(ops) < 2 and not self._changed(name, v)):
                continue            # a literal decoded once: the literal scanner has it already
            if isinstance(v, PSList):
                if not all(isinstance(x, int) for x in v[:64]):
                    continue
                try:
                    v = tag(RBytes(x & 0xFF for x in v), rec(v))
                except TypeError:
                    continue
            raw = bytes(v) if isinstance(v, RBytes) else str(v).encode("utf-8", "replace")
            kind = T.magic(raw)
            if isinstance(v, RBytes) and not kind and T.is_text(raw):
                txt = T.as_text(raw)
                if langdetect.languages(txt):
                    v = tag(txt, rec(v))
                    kind = "script"
            if isinstance(v, str) and not kind:
                if str(v) in (self.source or ""):
                    continue
                if langdetect.languages(str(v)):
                    kind = "script"
                elif _IOCISH.search(str(v)):
                    self.sinks.value_(self.to_value(tag(v, rec(v))), f"value of ${name} (decoded text with IOCs)")
                    continue
                else:
                    continue
            if not kind and isinstance(v, RBytes) and len(v) >= 64 and self._changed(name, v) and not T.is_text(raw):
                kind = "data"                   # bytes the script changed in place (a XOR loop): shellcode, a blob
            if not kind:
                continue
            # an intermediate value of a stage already found (the AES output before its GZip)
            if rec(v) and any(st.recipe[:len(rec(v))] == rec(v) and len(st.recipe) > len(rec(v)) for st in self.sinks.stages):
                continue
            r = rec(v) + (((getattr(v, "inplace", "") or "modified in place"),) if self._changed(name, v) else ())
            val = self.to_value(tag(v, r))
            if kind == "script":
                self.sinks.exec_(val, f"value of ${name} (computed, not run here)")
            else:
                self.sinks.load(val, f"value of ${name} (computed, not run here)")

    def _changed(self, name: str, v: Any) -> bool:
        h = self.assigned.get(name)
        if h is None or not isinstance(v, (RBytes, bytearray)):
            return False
        return h != hashlib.sha256(bytes(v)).hexdigest()

    def tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > MAX_STEPS:
            raise Limit("step limit")
        if not self.steps & 0x3FFF and time.monotonic() - self.t0 > MAX_SECONDS:
            raise Limit("time limit")

    # -- scopes -------------------------------------------------------------------------------
    def get(self, name: str, line: int | None = None) -> Any:
        n = name.lower()
        for p in ("script:", "global:", "local:", "private:", "using:", "variable:"):
            if n.startswith(p):
                n = n[len(p):]
        if n.startswith("env:"):
            e = n[4:]
            for sc in reversed(self.scopes):
                if f"env:{e}" in sc:
                    return sc[f"env:{e}"]
            if e in ENV:
                return tag(ENV[e], (f"$env:{e}",))
            return Unk(ENV_MACHINE.get(e, f"the environment variable {e} of the victim's machine"))
        if n == "executioncontext":
            return Obj("executioncontext")
        if n == "host":
            return Obj("host")
        if n == "psversiontable":
            return {"psversion": "5.1.19041.1", "psedition": "Desktop", "clrversion": "4.0.30319.42000"}
        for sc in reversed(self.scopes):
            if n in sc:
                return sc[n]
        if n in ("_", "psitem", "args", "input", "matches"):
            return None
        return None

    def set(self, name: str, value: Any) -> None:
        n = name.lower()
        scope = self.scopes[-1]
        for p in ("script:", "global:"):
            if n.startswith(p):
                n, scope = n[len(p):], self.scopes[0]
        for p in ("local:", "private:", "variable:"):
            if n.startswith(p):
                n = n[len(p):]
        if n.startswith("env:"):
            self.scopes[0][n] = value
            return
        scope[n] = value

    # -- statements ------------------------------------------------------------------------------
    def block(self, body: list, top: bool = False) -> list:
        out: list = []
        for st in body:
            try:
                self.statement(st, out)
            except _Return as r:
                r.partial = out + r.partial
                raise
            except (_Break, _Continue, _Exit, _Throw, Limit):
                raise
            except RecursionError:
                raise _Throw("recursion")
            except Exception as exc:  # noqa: BLE001  (a statement that fails: the next one still runs)
                self.errors.append(f"line {st[1]}: {type(exc).__name__}: {exc}"[:300])
                if top:
                    continue
                raise _Throw(str(exc)) from exc
        return out

    def emit(self, out: list, v: Any) -> None:
        if v is None:
            return
        if isinstance(v, list) and not isinstance(v, (RBytes,)):
            out.extend(v)
        else:
            out.append(v)

    def statement(self, st: tuple, out: list) -> None:
        self.tick()
        k = st[0]
        line = st[1]
        if k == "expr":
            v = self.eval(st[2], pipe_out=True)
            if st[2][0] in ("command", "pipe") and isinstance(v, _Silent):
                return
            self.emit(out, v.value if isinstance(v, _Silent) else v)
        elif k == "assign":
            self.assign(st[2], st[3], self.rhs(st[4]), line, st[4])
        elif k == "function":
            self.functions[str(st[2]).lower()] = (st[2], st[3], st[4])
        elif k == "param":
            pass
        elif k == "if":
            for cond, body in st[2]:
                c = self.truth(self.eval(cond))
                if c is None:                          # not computable: both ways are followed
                    try:
                        self.emit_all(out, self.block(body))
                    except _Throw:
                        pass
                    continue
                if c:
                    self.emit_all(out, self.block(body))
                    return
            if st[3]:
                self.emit_all(out, self.block(st[3]))
        elif k == "while":
            self.loop(out, st[2], st[3], line)
        elif k == "do":
            body, cond, until = st[2], st[3], st[4]
            n = 0
            while True:
                n += 1
                try:
                    self.emit_all(out, self.block(body))
                except _Break:
                    break
                except _Continue:
                    pass
                c = self.truth(self.eval(cond))
                if c is None or (c if until else not c) or n >= self._loop_cap(cond):
                    break
        elif k == "for":
            if st[2]:
                self.statement(st[2] if st[2][0] in ("assign", "expr") else ("expr", line, st[2]), [])
            n = 0
            cap = self._loop_cap(st[3])
            while True:
                if st[3] is not None:
                    c = self.truth(self.eval(st[3]))
                    if c is None:
                        c = n == 0
                    if not c:
                        break
                n += 1
                if n > cap:
                    break
                try:
                    self.emit_all(out, self.block(st[5]))
                except _Break:
                    break
                except _Continue:
                    pass
                if st[4]:
                    self.statement(st[4] if st[4][0] in ("assign", "expr") else ("expr", line, st[4]), [])
        elif k == "foreach":
            seq = self.eval(st[3])
            n = 0
            for item in self.iterate(seq):
                n += 1
                if n > MAX_LOOP:
                    break
                self.set(st[2], item)
                try:
                    self.emit_all(out, self.block(st[4]))
                except _Break:
                    break
                except _Continue:
                    pass
        elif k == "switch":
            subj = self.eval(st[2])
            for item in self.iterate(subj) if isinstance(subj, list) else [subj]:
                self.set("_", item)
                matched = False
                for key, body in st[3]:
                    if key is None:
                        continue
                    kv = self.eval(key) if key[0] != "sblock" else None
                    hit = (self.truth(self.run_sb(ScriptBlock(key[2]), [item], dollar_=item)) if key[0] == "sblock"
                           else self.text(kv).lower() == self.text(item).lower())
                    if hit:
                        matched = True
                        try:
                            self.emit_all(out, self.block(body))
                        except _Break:
                            return
                if not matched:
                    for key, body in st[3]:
                        if key is None:
                            self.emit_all(out, self.block(body))
        elif k == "try":
            try:
                self.emit_all(out, self.block(st[2]))
            except _Throw as t:
                if st[3]:
                    self.set("_", t.value)
                    try:
                        self.emit_all(out, self.block(st[3][0]))
                    except _Throw:
                        if not st[4]:
                            raise
            finally:
                if st[4]:
                    self.block(st[4])
        elif k == "return":
            raise _Return(self.eval(st[2]) if st[2] is not None else None)
        elif k == "throw":
            raise _Throw(self.eval(st[2]) if st[2] is not None else "ScriptHalted")
        elif k == "exit":
            raise _Exit()
        elif k == "break":
            raise _Break()
        elif k == "continue":
            raise _Continue()
        elif k == "block":
            self.emit_all(out, self.block(st[2]))
        elif k == "unknown":
            self.errors.append(f"line {line}: not parsed ({st[2]})"[:300])

    def emit_all(self, out: list, items: list) -> None:
        out.extend(items)

    def _loop_cap(self, cond: Any) -> int:
        # a loop on a constant true ("watch" loops) runs a few rounds: what it computes is the same
        if cond is None or (cond[0] == "var" and cond[2].lower() == "true") or (cond[0] == "num" and cond[2]):
            return MAX_FOREVER
        return MAX_LOOP

    def loop(self, out: list, cond: Any, body: list, line: int) -> None:
        n = 0
        cap = self._loop_cap(cond)
        while True:
            c = self.truth(self.eval(cond))
            if c is None:
                c = n == 0
            if not c:
                return
            n += 1
            if n > cap:
                return
            try:
                self.emit_all(out, self.block(body))
            except _Break:
                return
            except _Continue:
                continue

    def rhs(self, node: Any) -> Any:
        if node[0] == "stmtexpr":
            out: list = []
            self.statement(node[2], out)
            return out[0] if len(out) == 1 else (PSList(out) if out else None)
        if node[0] == "chainassign":
            v = self.rhs(node[4])
            self.assign(node[2], node[3], v, node[1])
            return v
        v = self.eval(node, pipe_out=True)
        return v.value if isinstance(v, _Silent) else v

    def assign(self, lhs: tuple, op: str, v: Any, line: int, rhs_node: Any = None) -> None:
        cast = None
        while lhs[0] == "cast":
            cast = cast or lhs[2]
            lhs = lhs[3]
        if op != "=":
            cur = self.eval(lhs)
            v = self.binop({"+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%"}[op], cur, v)
        if cast:
            v = self.cast(cast, v)
        if lhs[0] == "var":
            name = lhs[2]
            if isinstance(v, str) and not rec(v) and len(v) >= 8:
                kind = "here-string" if self._is_here(line) else "literal"
                v = tag(v, (f"{kind} ${name}",))
            elif isinstance(v, (str, bytes, bytearray, list)) and rec(v) == ("number array",) and len(v) >= 8:
                v = tag(v, (f"{rec(v)[0]} ${name}",))
            elif isinstance(v, (str, bytes, bytearray)) and rec(v) and len(v) >= 8:
                self.sinks.step(line, f"${name} =", self.to_value(v))
            if isinstance(v, (RBytes, bytearray)) and len(v) <= T.MAX_OUT:
                self.assigned[name.lower()] = hashlib.sha256(bytes(v)).hexdigest()
            if isinstance(v, (RBytes, str, PSList)) and len(v) >= 40:
                self.tracked[name.lower()] = v
            self.set(name, v)
        elif lhs[0] == "index":
            target = self.eval(lhs[2])
            idx = self.eval(lhs[3])
            if isinstance(target, (RBytes, bytearray)):
                target[self.num(idx)] = self.num(v) & 0xFF
                if isinstance(target, RBytes) and not target.inplace:
                    target.inplace = self._inplace_op(lhs, rhs_node) or ""
            elif isinstance(target, list):
                target[self.num(idx)] = v
            elif isinstance(target, dict):
                target[self.key(idx)] = v
        elif lhs[0] == "member":
            target = self.eval(lhs[2])
            name = self.text(self.eval(lhs[3])) if lhs[3][0] != "str" else lhs[3][2]
            self.set_member(target, name, v)

    def _inplace_op(self, lhs: tuple, rhs: Any) -> str | None:
        """``$d[$i] = $d[$i] -bxor $k`` → ``xor($k)`` (the name of an in-place loop's operation)."""
        if not rhs or rhs[0] != "bin" or rhs[2] not in ("bxor", "+", "-"):
            return None
        a, b = rhs[3], rhs[4]
        other = b if a[0] == "index" else a if b[0] == "index" else None
        if other is None:
            return None

        def desc(n: Any) -> str:
            if n[0] == "num":
                return f"0x{n[2] & 0xFFFFFFFF:x}"
            if n[0] == "var":
                v = self.get(n[2])
                if isinstance(v, int):
                    return f"0x{v & 0xFFFFFFFF:x}"
                if isinstance(v, str) and len(v) <= 40:
                    return repr(str(v))
                return f"${n[2]}"
            if n[0] == "index":
                return desc(n[2])
            if n[0] == "paren":
                return desc(n[2])
            return "key"
        op = {"bxor": "xor", "+": "add", "-": "sub"}[rhs[2]]
        return f"{op}({desc(other)})"

    def _is_here(self, line: int) -> bool:
        lines = self.source.splitlines()
        return 0 < line <= len(lines) and "@'" in lines[line - 1] or 0 < line <= len(lines) and '@"' in lines[line - 1]

    # -- expressions ---------------------------------------------------------------------------
    def eval(self, n: Any, pipe_out: bool = False) -> Any:  # noqa: C901
        self.tick()
        k = n[0]
        if k == "str":
            return n[2]
        if k == "num":
            return n[2]
        if k == "xstr":
            return self.expand(n[2])
        if k == "numlist":
            return tag(PSList(n[2]), ("number array",))
        if k == "var":
            return self.get(n[2], n[1])
        if k == "type":
            return TypeRef(n[2])
        if k == "paren":
            v = self.eval(n[2]) if n[2][0] != "stmtexpr" else self.rhs(n[2])
            return v.value if isinstance(v, _Silent) else v
        if k in ("subexpr", "arrayexpr"):
            out = self.block(n[2])
            if k == "arrayexpr":
                return PSList(out)
            return out[0] if len(out) == 1 else (PSList(out) if out else None)
        if k == "array":
            items = [self.eval(x) for x in n[2]]
            if len(items) > 1 and all(isinstance(x, (str,)) for x in items):
                r = next((rec(x) for x in items if rec(x)), ())
                return tag(PSList(items), r)
            return PSList(items)
        if k == "hash":
            d = {}
            for kn, vn in n[2]:
                d[self.key(self.eval(kn))] = self.rhs(vn[2]) if vn[0] == "expr" else self.rhs(vn)
            return d
        if k == "sblock":
            return ScriptBlock(n[2], self._span(n))
        if k == "bin":
            return self.binop(n[2], self.eval(n[3]), self.eval(n[4]), n)
        if k == "neg":
            v = self.eval(n[2])
            return Unk(v.why) if isinstance(v, Unk) else -self.num(v)
        if k == "unary":
            v = self.eval(n[3])
            op = n[2]
            if isinstance(v, Unk):
                return v
            if op == "not":
                t = self.truth(v)
                return None if t is None else not t
            if op == "bnot":
                return ~self.num(v)
            if op == "join":
                return step(v, "", "".join(self.text(x) for x in self.iterate(v)))
            if op == "split":
                return PSList(re.split(r"\s+", self.text(v).strip()))
        if k == "range":
            a, b = self.num(self.eval(n[2])), self.num(self.eval(n[3]))
            if abs(b - a) > MAX_LOOP:
                raise Limit("range too long")
            return PSList(range(a, b + 1) if b >= a else range(a, b - 1, -1))
        if k == "cast":
            return self.cast(n[2], self.eval(n[3]))
        if k == "index":
            return self.index(self.eval(n[2]), self.eval(n[3]))
        if k == "member":
            target = self.eval(n[2])
            name = n[3][2] if n[3][0] == "str" else self.text(self.eval(n[3]))
            if n[4]:
                return self.static_member(target, name, n)
            return self.get_member(target, name)
        if k == "call":
            target = self.eval(n[2])
            name = n[3][2] if n[3][0] == "str" else self.eval(n[3])
            if isinstance(name, Unk):
                self.sinks.unresolved_(self._span(n) or "method call", name.why,
                                       "the method name is computed from something not in the script", n[1])
                return Unk(f"result of a method whose name depends on {name.why}")
            name = self.text(name)
            args = [self.eval(a) for a in n[4]]
            if n[5] or isinstance(target, TypeRef):
                return self.call_static(target, name, args, n)
            return self.call_method(target, name, args, n)
        if k in ("preinc", "postinc"):
            op = n[2]
            ref = n[3]
            cur = self.eval(ref)
            new = self.num(cur) + (1 if op == "++" else -1)
            self.assign(ref, "=", new, n[1])
            return new if k == "preinc" else cur
        if k == "command":
            return self.command(n, None)
        if k == "pipe":
            return self.pipe(n)
        if k == "chain":
            left = self.eval(n[2])
            ok = not isinstance(left, Unk)
            if (n[3] == "&&" and ok) or (n[3] == "||" and not ok):
                return self.eval(n[4])
            return left
        if k == "stmtexpr":
            return self.rhs(n)
        if k == "callsb":
            return self.run_sb(self.eval(n[2]), [self.eval(a) for a in n[3]])
        raise ValueError(f"cannot evaluate {k}")

    def _span(self, n: Any) -> str:
        line = n[1] if isinstance(n, tuple) and len(n) > 1 and isinstance(n[1], int) else 0
        lines = self.source.splitlines()
        return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""

    # -- strings --------------------------------------------------------------------------------
    _XVAR = re.compile(r"`(.)|\$\{([^}]+)\}|\$\(|\$((?:[A-Za-z_]\w*:)?[A-Za-z_\d?^]\w*)")
    _ESC = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b"}

    def expand(self, s: str) -> Any:
        out = []
        pos = 0
        r: tuple[str, ...] = ()
        while True:
            m = self._XVAR.search(s, pos)
            if not m:
                out.append(s[pos:])
                break
            out.append(s[pos:m.start()])
            if m.group(1) is not None:
                out.append(self._ESC.get(m.group(1), m.group(1)))
                pos = m.end()
            elif m.group(0) == "$(":
                depth, j = 1, m.end()
                while j < len(s) and depth:
                    depth += {"(": 1, ")": -1}.get(s[j], 0)
                    j += 1
                inner = s[m.end():j - 1]
                sub = Interp.__new__(Interp)
                v = self._sub_eval(inner)
                if isinstance(v, Unk):
                    return v
                out.append(self.text(v))
                r = r or rec(v)
                pos = j
            else:
                vn = m.group(2) or m.group(3)
                v = self.get(vn)
                if isinstance(v, Unk):
                    if vn.lower().startswith("env:"):              # a path on the victim's machine: %TEMP%\x.exe
                        out.append(f"%{vn[4:].upper()}%")
                        pos = m.end()
                        continue
                    return v
                out.append(self.text(v))
                r = r or rec(v)
                pos = m.end()
        return tag("".join(out), r) if r else "".join(out)

    def _sub_eval(self, code: str) -> Any:
        body = parse(code)
        out = self.block(body)
        return out[0] if len(out) == 1 else (PSList(out) if out else "")

    def text(self, v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        if isinstance(v, bool):
            return "True" if v else "False"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, (RBytes, bytearray, bytes)):
            return " ".join(str(b) for b in v[:200000])
        if isinstance(v, list):
            ofs = self.get("ofs")
            return (ofs if isinstance(ofs, str) else " ").join(self.text(x) for x in v)
        if isinstance(v, TypeRef):
            return v.name
        if isinstance(v, ScriptBlock):
            return v.text or ""
        if isinstance(v, CommandInfo):
            return v.name
        if isinstance(v, Unk):
            return ""
        if isinstance(v, dict):
            return "System.Collections.Hashtable"
        if isinstance(v, Obj):
            if v.kind == "securestring":
                return "System.Security.SecureString"
            return f"System.{v.kind}"
        return str(v)

    def key(self, v: Any) -> str:
        return self.text(v).lower()

    def num(self, v: Any) -> int:
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            return int(round(v))
        if isinstance(v, str):
            t = v.strip()
            if len(t) == 1 and not t.isdigit():
                return ord(t)
            try:
                return int(t, 16) if t.lower().startswith("0x") else int(float(t)) if "." in t else int(t)
            except ValueError as exc:
                raise _Throw(f"cannot convert {t[:40]!r} to a number") from exc
        if v is None:
            return 0
        if isinstance(v, Unk):
            raise _Throw(v.why)
        if isinstance(v, list) and len(v) == 1:
            return self.num(v[0])
        raise _Throw(f"cannot convert {type(v).__name__} to a number")

    def truth(self, v: Any) -> bool | None:
        if isinstance(v, Unk):
            return None
        if isinstance(v, _Silent):
            v = v.value
        if v is None:
            return False
        if isinstance(v, (bool, int, float)):
            return bool(v)
        if isinstance(v, str):
            return len(v) > 0
        if isinstance(v, (list, RBytes, bytearray)):
            if len(v) == 1:
                return self.truth(v[0])
            return len(v) > 0
        return True

    def iterate(self, v: Any) -> list:
        if v is None:
            return []
        if isinstance(v, _Silent):
            v = v.value
        if isinstance(v, (RBytes, bytearray, bytes)):
            return list(v)
        if isinstance(v, list):
            return v
        if isinstance(v, dict):
            return [v]
        return [v]

    # -- operators -------------------------------------------------------------------------------
    def binop(self, op: str, a: Any, b: Any, node: Any = None) -> Any:  # noqa: C901
        if isinstance(a, _Silent):
            a = a.value
        if isinstance(b, _Silent):
            b = b.value
        if isinstance(a, Unk) or isinstance(b, Unk):
            u = a if isinstance(a, Unk) else b
            return Unk(u.why, rec(a) or rec(b))
        if op == "+":
            if isinstance(a, (str, bytes, bytearray, list)) and hasattr(b, "__len__") and len(a) + len(b) > T.MAX_OUT:
                raise Limit("value too large")
            if isinstance(a, str):
                return tag(a + self.text(b), rec(a) or rec(b)) if (rec(a) or rec(b)) else a + self.text(b)
            if isinstance(a, (RBytes, bytearray)):
                return tag(RBytes(a) + bytes(self.as_bytes(b)), rec(a))
            if isinstance(a, list):
                return PSList(list(a) + (list(b) if isinstance(b, list) else [b]))
            if isinstance(a, dict) and isinstance(b, dict):
                return {**a, **b}
            if a is None:
                return b
            if isinstance(b, str):
                return self.num(a) + self.num(b)
            return a + b if isinstance(a, (int, float)) and isinstance(b, (int, float)) else self.num(a) + self.num(b)
        if op == "-":
            return self.arith(a, b, lambda x, y: x - y)
        if op == "*":
            if isinstance(a, str):
                return T.repeat(a, self.num(b))
            if isinstance(a, list):
                if len(a) * max(0, self.num(b)) > T.MAX_OUT:
                    raise Limit("array too large")
                return PSList(list(a) * self.num(b))
            return self.arith(a, b, lambda x, y: x * y)
        if op == "/":
            r = self.arith(a, b, lambda x, y: x / y if y else 0)
            return int(r) if isinstance(r, float) and r.is_integer() else r
        if op == "%":
            return self.arith(a, b, lambda x, y: x % y if y else 0)
        if op in ("band", "bor", "bxor", "shl", "shr"):
            try:
                x, y = self.num(a), self.num(b)
            except _Throw:
                if op == "bor":                     # enum flags ([BindingFlags]::Static -bor …)
                    return RStr(f"{self.text(a)}, {self.text(b)}")
                raise
            return {"band": x & y, "bor": x | y, "bxor": x ^ y, "shl": x << (y & 63), "shr": x >> (y & 63)}[op]
        if op in ("and", "or", "xor"):
            ta, tb = self.truth(a), self.truth(b)
            if ta is None or tb is None:
                return None
            return {"and": ta and tb, "or": ta or tb, "xor": ta != tb}[op]
        if op == "f":
            return self.format(a, b)
        if op == "join":
            sep = self.text(b)
            items = self.iterate(a)
            r = rec(a)
            s = sep.join(self.text(x) for x in items)
            return tag(s, r) if r else s
        if op in ("split", "isplit", "csplit"):
            pat = self.text(b[0] if isinstance(b, list) and b else b)
            flags = 0 if op == "csplit" else re.I
            try:
                parts = re.split(_net_regex(pat), self.text(a), flags=flags)
            except re.error:
                parts = self.text(a).split(pat)
            return tag(PSList(parts), rec(a))
        if op in ("replace", "ireplace", "creplace"):
            pat, repl = (b[0], b[1] if len(b) > 1 else "") if isinstance(b, list) else (b, "")
            flags = 0 if op == "creplace" else re.I
            src = self.text(a)
            try:
                out = re.sub(_net_regex(self.text(pat)), _net_repl(self.text(repl)), src, flags=flags)
            except re.error:
                out = src.replace(self.text(pat), self.text(repl))
            return tag(out, rec(a)) if rec(a) else out
        if op in ("eq", "ieq", "ceq", "ne", "ine", "cne"):
            if isinstance(a, list) and not isinstance(a, RBytes):
                return PSList([x for x in a if self.equal(x, b, op.startswith("c")) == (op.endswith("eq"))])
            r = self.equal(a, b, op.startswith("c"))
            return r if op.endswith("eq") else not r
        if op in ("gt", "ge", "lt", "le", "igt", "ige", "ilt", "ile", "cgt", "cge", "clt", "cle"):
            base = op[-2:]
            x, y = self.cmp_pair(a, b)
            return {"gt": x > y, "ge": x >= y, "lt": x < y, "le": x <= y}[base]
        if op in ("like", "ilike", "clike", "notlike"):
            r = fnmatch.fnmatch(self.text(a).lower(), self.text(b).lower()) if op != "clike" else fnmatch.fnmatchcase(self.text(a), self.text(b))
            return r if op != "notlike" else not r
        if op in ("match", "imatch", "cmatch", "notmatch"):
            try:
                m = re.search(_net_regex(self.text(b)), self.text(a), 0 if op == "cmatch" else re.I)
            except re.error:
                m = None
            if m:
                self.scopes[-1]["matches"] = {str(i): g for i, g in enumerate([m.group(0), *m.groups()])}
            return bool(m) if op != "notmatch" else not m
        if op in ("contains", "icontains", "ccontains", "notcontains"):
            r = any(self.equal(x, b, op == "ccontains") for x in self.iterate(a))
            return r if op != "notcontains" else not r
        if op in ("in", "notin"):
            r = any(self.equal(b2, a, False) for b2 in self.iterate(b))
            return r if op == "in" else not r
        if op in ("is", "isnot"):
            r = self.is_type(a, b)
            return r if op == "is" else not r
        if op == "as":
            try:
                return self.cast(b.name if isinstance(b, TypeRef) else self.text(b), a)
            except Exception:  # noqa: BLE001
                return None
        raise ValueError(f"operator {op}")

    def arith(self, a: Any, b: Any, f: Callable[[Any, Any], Any]) -> Any:
        x = a if isinstance(a, (int, float)) and not isinstance(a, bool) else self.num(a)
        y = b if isinstance(b, (int, float)) and not isinstance(b, bool) else self.num(b)
        return f(x, y)

    def cmp_pair(self, a: Any, b: Any) -> tuple:
        if isinstance(a, (int, float)) or isinstance(b, (int, float)):
            try:
                return self.arith(a, 0, lambda x, y: x), self.arith(b, 0, lambda x, y: x)
            except _Throw:
                pass
        return self.text(a).lower(), self.text(b).lower()

    def equal(self, a: Any, b: Any, case: bool = False) -> bool:
        if isinstance(a, (int, float)) and not isinstance(a, bool):
            try:
                return a == self.num(b)
            except _Throw:
                return False
        if isinstance(a, bool):
            return a == bool(self.truth(b))
        if a is None or b is None:
            return a is None and b is None
        ta, tb = self.text(a), self.text(b)
        return ta == tb if case else ta.lower() == tb.lower()

    def is_type(self, a: Any, b: Any) -> bool:
        t = norm_type(b.name if isinstance(b, TypeRef) else self.text(b))
        return {"string": isinstance(a, str), "int": isinstance(a, int) and not isinstance(a, bool),
                "byte[]": isinstance(a, (RBytes, bytearray)), "array": isinstance(a, list),
                "object[]": isinstance(a, list), "bool": isinstance(a, bool),
                "scriptblock": isinstance(a, ScriptBlock), "hashtable": isinstance(a, dict)}.get(t, False)

    def format(self, fmt: Any, args: Any) -> Any:
        items = self.iterate(args) if isinstance(args, list) and not isinstance(args, RBytes) else [args]
        r = rec(fmt) or next((rec(x) for x in items if rec(x)), ())

        def one(m: re.Match) -> str:
            if m.group(0) in ("{{", "}}"):
                return m.group(0)[0]
            i = int(m.group(1))
            v = items[i] if i < len(items) else ""
            spec = m.group(3) or ""
            width = int(m.group(2)) if m.group(2) else 0
            s = self.text(v)
            if spec:
                c = spec[0].upper()
                try:
                    if c == "X":
                        s = format(self.num(v), ("X" if spec[0] == "X" else "x") + "")
                        s = s.zfill(int(spec[1:])) if spec[1:].isdigit() else s
                    elif c == "D":
                        s = str(self.num(v)).zfill(int(spec[1:]) if spec[1:].isdigit() else 0)
                    elif c == "N" or c == "F":
                        s = f"{float(self.num(v)):.{int(spec[1:]) if spec[1:].isdigit() else 2}f}"
                except (_Throw, ValueError):
                    pass
            if width:
                s = s.rjust(width) if width > 0 else s.ljust(-width)
            return s
        out = re.sub(r"\{\{|\}\}|\{(\d+)(?:,(-?\d+))?(?::([^}]*))?\}", one, self.text(fmt))
        return tag(out, r) if r else out

    # -- indexing and members ---------------------------------------------------------------
    def index(self, target: Any, idx: Any) -> Any:
        if isinstance(target, Unk):
            return target
        if isinstance(idx, Unk):
            return idx
        if isinstance(target, dict):
            if isinstance(idx, list):
                return PSList([target.get(self.key(i)) for i in idx])
            return target.get(self.key(idx))
        if isinstance(target, Obj) and target.kind == "matches":
            return target.groups.get(str(idx))
        seq = target
        if isinstance(seq, (str, list, RBytes, bytearray, bytes)):
            n = len(seq)

            def one(i: Any) -> Any:
                j = self.num(i)
                if j < 0:
                    j += n
                if 0 <= j < n:
                    return seq[j]
                return None
            if isinstance(idx, list) and not isinstance(idx, RBytes):
                vals = [one(i) for i in idx]
                vals = [v for v in vals if v is not None]
                if isinstance(seq, str):
                    return tag(PSList(vals), rec(seq))
                if isinstance(seq, (RBytes, bytearray)):
                    return tag(RBytes(vals), rec(seq))
                return PSList(vals)
            return one(idx)
        if target is None:
            return None
        return None

    def get_member(self, t: Any, name: str) -> Any:
        n = name.lower()
        if isinstance(t, Unk):
            return t
        if isinstance(t, dict):
            if n in ("count", "keys", "values") and n not in t:
                return {"count": len(t), "keys": PSList(t.keys()), "values": PSList(t.values())}[n]
            return t.get(n)
        if isinstance(t, (str, list, RBytes, bytearray, bytes)):
            if n in ("length", "count"):
                return len(t)
            if isinstance(t, list) and not isinstance(t, RBytes):
                vals = [self.get_member(x, name) for x in t]          # member enumeration
                return PSList(vals) if any(v is not None for v in vals) else None
            return None
        if isinstance(t, TypeRef):
            return self.static_member(t, name, None)
        if isinstance(t, ScriptBlock):
            return {"ast": t, "file": None}.get(n)
        if isinstance(t, CommandInfo):
            return {"name": t.name, "commandtype": "Cmdlet", "definition": t.name}.get(n)
        if isinstance(t, Obj):
            return self.obj_member(t, n)
        if isinstance(t, (int, float)) and n in ("length",):
            return 1
        return None

    def set_member(self, t: Any, name: str, v: Any) -> None:
        if isinstance(t, dict):
            t[name.lower()] = v
        elif isinstance(t, Obj):
            t.props[name.lower()] = v

    def static_member(self, t: Any, name: str, node: Any) -> Any:
        n = name.lower()
        if not isinstance(t, TypeRef):
            return self.get_member(t, name)
        k = t.key
        if k == "text.encoding":
            enc = {"utf8": "utf-8", "unicode": "utf-16-le", "ascii": "ascii", "default": "latin-1",
                   "bigendianunicode": "utf-16-be", "utf32": "utf-32-le", "utf7": "utf-7"}.get(n, "utf-8")
            return Obj("encoding", enc=enc)
        if k == "environment":
            return {"newline": "\r\n", "is64bitoperatingsystem": True, "is64bitprocess": True,
                    "osversion": "Microsoft Windows NT 10.0.19045.0", "systemdirectory": "C:\\WINDOWS\\system32",
                    "machinename": Unk("the victim's computer name"), "username": Unk("the victim's user name"),
                    "currentdirectory": Unk("the current folder on the victim's machine"),
                    "processorcount": 4}.get(n)
        if k == "appdomain" and n == "currentdomain":
            return Obj("appdomain")
        if k == "intptr" and n == "size":
            return 8
        if k == "math" and n == "pi":
            return 3.141592653589793
        if k == "string" and n == "empty":
            return ""
        if k == "net.servicepointmanager":
            return None
        if k in ("int", "byte", "long") and n in ("maxvalue", "minvalue"):
            return {"int": (2 ** 31 - 1, -2 ** 31), "byte": (255, 0), "long": (2 ** 63 - 1, -2 ** 63)}[k][0 if n == "maxvalue" else 1]
        # enums and the like: the member's name ([CipherMode]::CBC → "CBC")
        return RStr(name)

    def obj_member(self, o: Obj, n: str) -> Any:  # noqa: C901
        if n in o.props:
            return o.props[n]
        if o.kind == "memorystream":
            return {"length": len(o.data), "position": o.pos, "canread": True, "canwrite": True}.get(n)
        if o.kind == "executioncontext":
            return {"invokecommand": Obj("invokecommand"), "sessionstate": Obj("sessionstate")}.get(n)
        if o.kind == "sessionstate":
            return {"invokecommand": Obj("invokecommand")}.get(n)
        if o.kind == "assembly":
            return {"entrypoint": Obj("method", asm=o, type="", name="EntryPoint"), "fullname": o.props.get("fullname", "assembly")}.get(n)
        if o.kind == "rtype":
            return {"name": o.name, "fullname": o.name}.get(n)
        if o.kind in ("cipher",):
            return o.props.get(n)
        if o.kind == "encoding":
            return {"encodingname": o.enc, "webname": o.enc}.get(n)
        if o.kind == "matches":
            return None
        if o.kind == "pscredential":
            return {"username": o.props.get("user"), "password": o.props.get("password")}.get(n)
        if o.kind == "networkcredential":
            return {"password": o.password, "username": o.user}.get(n)
        if o.kind == "process":
            return None
        return None

    # -- casts --------------------------------------------------------------------------------
    def cast(self, tname: str, v: Any) -> Any:  # noqa: C901
        if isinstance(v, _Silent):
            v = v.value
        if isinstance(v, Unk):
            return v
        t = norm_type(tname)
        r = rec(v)
        if t in ("string",):
            return tag(self.text(v), r) if r else self.text(v)
        if t in ("int", "long"):
            if isinstance(v, str) and len(v) == 1:
                return ord(v)
            return self.num(v)
        if t == "byte":
            return self.num(v) & 0xFF
        if t == "char":
            if isinstance(v, str):
                return v[:1] if len(v) == 1 else (chr(self.num(v)) if v.strip().isdigit() else v[:1])
            return chr(self.num(v) & 0x10FFFF)
        if t == "bool":
            return bool(self.truth(v))
        if t == "double":
            return float(self.num(v)) if not isinstance(v, float) else v
        if t == "byte[]":
            if isinstance(v, (RBytes, bytearray, bytes)):
                return tag(RBytes(v), r)
            if isinstance(v, list):
                return tag(RBytes(self.num(x) & 0xFF for x in v), r)
            if isinstance(v, str):
                raise _Throw("cannot convert a string to byte[]")
            return tag(RBytes([self.num(v) & 0xFF]), r)
        if t == "char[]":
            if isinstance(v, str):
                return tag(PSList(list(v)), r)
            return tag(PSList(chr(self.num(x)) if not isinstance(x, str) else x for x in self.iterate(v)), r)
        if t in ("string[]", "object[]", "array", "int[]"):
            items = self.iterate(v) if not isinstance(v, str) else [v]
            if t == "int[]":
                items = [self.num(x) for x in items]
            if t == "string[]":
                items = [self.text(x) for x in items]
            return tag(PSList(items), r)
        if t == "scriptblock":
            if isinstance(v, ScriptBlock):
                return v
            code = self.text(v)
            return ScriptBlock(None, code, rec(v))
        if t == "type":
            return TypeRef(self.text(v))
        if t == "regex":
            return Obj("regex", pattern=self.text(v))
        if t == "hashtable":
            return v
        if t == "void":
            return _Silent(None)
        if t == "securestring":
            return v
        if t == "uri":
            return self.text(v)
        return v

    # -- helpers ------------------------------------------------------------------------------
    def as_bytes(self, v: Any) -> RBytes:
        if isinstance(v, (RBytes,)):
            return v
        if isinstance(v, (bytes, bytearray)):
            return tag(RBytes(v), rec(v))
        if isinstance(v, list):
            return tag(RBytes(self.num(x) & 0xFF for x in v), rec(v))
        if isinstance(v, str):
            return tag(RBytes(v.encode("utf-8")), rec(v))
        if isinstance(v, Unk):
            raise _Throw(v.why)
        if isinstance(v, int):
            return RBytes([v & 0xFF])
        raise _Throw(f"not bytes: {type(v).__name__}")

    def to_value(self, v: Any) -> Value:
        r = rec(v)
        if isinstance(v, Unk):
            return Value.unknown(v.why, r)
        if isinstance(v, (RBytes, bytearray, bytes)):
            return Value("bytes", bytes(v), r)
        if isinstance(v, ScriptBlock):
            return Value("str", v.text or "", r)
        if isinstance(v, list):
            if v and all(isinstance(x, int) and 0 <= x < 256 for x in v[:64]):
                try:
                    return Value("bytes", bytes(x & 0xFF for x in v), r)
                except TypeError:
                    pass
            return Value("str", self.text(v), r)
        if isinstance(v, str):
            return Value("str", str(v), r)
        return Value.of(v)

    # -- .NET: static calls -------------------------------------------------------------------
    def call_static(self, t: Any, name: str, args: list, node: Any) -> Any:  # noqa: C901
        if not isinstance(t, TypeRef):
            return self.call_method(t, name, args, node)
        k = t.key
        n = name.lower()
        line = node[1] if node else None
        if any(isinstance(a, Unk) for a in args) and not (k == "assembly" and n == "load"):
            u = next(a for a in args if isinstance(a, Unk))
            if k == "scriptblock" or (k == "assembly"):
                self.sinks.unresolved_(self._span(node), u.why, f"the argument of [{t.name}]::{name} is computed "
                                       "from something not in the script", line)
            return Unk(u.why)
        if k == "convert":
            a0 = args[0] if args else ""
            if n == "frombase64string" or n == "frombase64chararray":
                return step(a0, "base64", RBytes(T.b64decode(self.text(a0) if not isinstance(a0, list) else "".join(map(self.text, a0)))))
            if n == "tobase64string":
                return step(a0, "", T.b64encode(bytes(self.as_bytes(a0))))
            if n in ("toint32", "toint16", "toint64", "touint32", "tobyte", "toint", "tosbyte"):
                base = self.num(args[1]) if len(args) > 1 else 10
                s = self.text(a0) if isinstance(a0, str) else a0
                v = int(s, base) if isinstance(s, str) else self.num(s)
                return v & 0xFF if n == "tobyte" else v
            if n == "tochar":
                return chr(self.num(a0))
            if n == "tostring":
                if len(args) > 1:
                    b = self.num(args[1])
                    x = self.num(a0)
                    return format(x, {2: "b", 8: "o", 16: "x"}.get(b, "d"))
                return self.text(a0)
            if n == "fromhexstring":
                return step(a0, "hex", RBytes(T.hexdecode(self.text(a0))))
        if k == "string":
            if n == "join":
                sep = self.text(args[0])
                items = [x for a in args[1:] for x in (self.iterate(a) if isinstance(a, list) else [a])]
                return tag(sep.join(self.text(x) for x in items), rec(args[1]) if len(args) > 1 else ())
            if n == "new":
                a0 = args[0] if args else ""
                if len(args) == 2 and isinstance(args[0], str):
                    return args[0] * self.num(args[1])
                return tag("".join(self.text(x) for x in self.iterate(a0)), rec(a0))
            if n == "concat":
                r = next((rec(a) for a in args if rec(a)), ())
                return tag("".join(self.text(a) for a in (args[0] if len(args) == 1 and isinstance(args[0], list) else args)), r)
            if n == "format":
                return self.format(args[0], PSList(args[1:]) if len(args) > 2 else (args[1] if len(args) > 1 else PSList()))
            if n in ("isnullorempty", "isnullorwhitespace"):
                return not self.text(args[0]).strip() if n.endswith("whitespace") else not self.text(args[0])
        if k == "char" and n in ("convertfromutf32", "tostring"):
            return chr(self.num(args[0]))
        if k in ("byte[]", "char[]", "object[]", "int[]") and n == "new":
            size = self.num(args[0]) if args else 0
            if size > T.MAX_OUT:
                raise Limit("array too large")
            return RBytes(size) if k == "byte[]" else PSList([None] * size)
        if k == "array":
            if n == "reverse" and args and isinstance(args[0], list | bytearray):
                args[0].reverse()
                if isinstance(args[0], (RBytes, bytearray, list)):
                    try:
                        args[0].recipe = rec(args[0]) + ("reverse",)
                    except AttributeError:
                        pass
                return None
            if n == "copy" and len(args) >= 3:
                src, dst = args[0], args[1]
                if len(args) == 3:
                    cnt = self.num(args[2])
                    dst[:cnt] = src[:cnt]
                else:
                    si, di, cnt = self.num(args[1]), self.num(args[3]), self.num(args[4])
                    dst = args[2]
                    dst[di:di + cnt] = src[si:si + cnt]
                    if isinstance(dst, (RBytes,)) and rec(src):
                        dst.recipe = rec(src)
                return None
            if n == "indexof" and len(args) >= 2:
                try:
                    return list(args[0]).index(args[1])
                except ValueError:
                    return -1
            if n == "createinstance" and len(args) >= 2:
                return RBytes(self.num(args[1])) if norm_type(self.text(args[0])) in ("byte",) else PSList([None] * self.num(args[1]))
        if k == "linq" and n == "reverse":
            v = args[0]
            return tag(type(v)(reversed(v)) if isinstance(v, (RBytes, bytearray)) else PSList(reversed(self.iterate(v))), rec(v) + ("reverse",))
        if k == "text.encoding" and n == "getencoding":
            code = args[0]
            enc = {65001: "utf-8", 1200: "utf-16-le", 1201: "utf-16-be", 20127: "ascii", 28591: "latin-1",
                   1252: "cp1252", 437: "cp437", 866: "cp866", 1251: "cp1251"}.get(self.num(code) if not isinstance(code, str) or code.isdigit() else -1,
                                                                                   self.text(code))
            return Obj("encoding", enc=enc)
        if k == "scriptblock" and n == "create":
            sb = ScriptBlock(None, self.text(args[0]), rec(args[0]))
            self.sinks.exec_(self.to_value(tag(sb.text, rec(args[0]))), "ScriptBlock::Create", line)
            return sb
        if k == "assembly" and n in ("load", "loadfile", "loadfrom", "unsafeloadfrom", "reflectiononlyload"):
            a0 = args[0] if args else None
            if n in ("loadfile", "loadfrom", "unsafeloadfrom"):
                self.sinks.step(line, f"Assembly.{name} {self.text(a0)}", self.to_value(a0))
                return Obj("assembly", data=b"", recipe=(), props={"fullname": self.text(a0)})
            if isinstance(a0, Unk):
                self.sinks.load(self.to_value(a0), f"Assembly.{name}", line=line)
                return Obj("assembly", data=b"", recipe=())
            if isinstance(a0, str) and not rec(a0):
                return Obj("assembly", data=b"", recipe=(), props={"fullname": a0})        # by name (System.Drawing)
            data = bytes(self.as_bytes(a0))
            self.sinks.load(self.to_value(tag(RBytes(data), rec(a0))), f"Assembly.{name}", line=line)
            return Obj("assembly", data=data, recipe=rec(a0))
        if k == "appdomain" and n == "currentdomain":
            return Obj("appdomain")
        if k == "io.file":
            path = self.text(args[0]) if args else ""
            if n in ("writeallbytes", "writealltext", "appendalltext", "writealllines"):
                data = args[1] if len(args) > 1 else ""
                self.sinks.write(self.to_value(data if not isinstance(data, list) or isinstance(data, RBytes) else self.as_bytes(data)),
                                 path, f"[IO.File]::{name}", line)
                return None
            if n in ("readallbytes", "readalltext", "readalllines", "openread"):
                return Unk(f"the content of the file {path} on the victim's machine")
            if n == "exists":
                return Unk(f"whether {path} exists on the victim's machine")
            if n in ("delete", "copy", "move", "setattributes"):
                self.sinks.step(line, f"[IO.File]::{name} {path}", Value.of(path))
                return None
        if k == "io.path":
            if n == "combine":
                return "\\".join(self.text(a).rstrip("\\") for a in args)
            if n == "gettemppath":
                return Unk("the victim's TEMP folder")
            if n in ("getfilename", "getextension", "getdirectoryname", "getfilenamewithoutextension"):
                p = self.text(args[0]).replace("/", "\\")
                base = p.rsplit("\\", 1)[-1]
                return {"getfilename": base, "getextension": ("." + base.rsplit(".", 1)[-1]) if "." in base else "",
                        "getdirectoryname": p.rsplit("\\", 1)[0] if "\\" in p else "",
                        "getfilenamewithoutextension": base.rsplit(".", 1)[0]}[n]
            if n == "getrandomfilename":
                return "xk2ow1vm.tmp"
        if k == "environment":
            if n in ("getenvironmentvariable", "expandenvironmentvariables"):
                if n == "expandenvironmentvariables":
                    s = self.text(args[0])

                    def ev(m: re.Match) -> str:
                        v = self.get("env:" + m.group(1))
                        return self.text(v) if not isinstance(v, Unk) else m.group(0)
                    return re.sub(r"%(\w+)%", ev, s)
                return self.get("env:" + self.text(args[0]))
            if n == "getfolderpath":
                return Unk("a special folder of the victim's machine")
            if n == "exit":
                raise _Exit()
        if k == "math":
            nums = [self.num(a) if not isinstance(a, float) else a for a in args]
            f = {"abs": abs, "floor": lambda x: int(x // 1), "ceiling": lambda x: -int(-x // 1), "round": round,
                 "max": max, "min": min, "pow": pow, "sqrt": lambda x: x ** 0.5, "truncate": int}.get(n)
            if f:
                try:
                    return f(*nums)
                except (TypeError, ValueError):
                    return Unk("math")
        if k == "bitconverter":
            if n == "tostring":
                return "-".join(f"{b:02X}" for b in self.as_bytes(args[0]))
            if n in ("toint32", "touint32"):
                b = bytes(self.as_bytes(args[0]))
                i = self.num(args[1]) if len(args) > 1 else 0
                return int.from_bytes(b[i:i + 4], "little", signed=n == "toint32")
            if n == "getbytes":
                return RBytes(self.num(args[0]).to_bytes(4, "little", signed=True))
        if k == "marshal":
            if n in ("securestringtobstr", "securestringtoglobalallocunicode", "securestringtocotaskmemunicode"):
                return args[0]
            if n in ("ptrtostringauto", "ptrtostringbstr", "ptrtostringuni", "ptrtostringansi"):
                v = args[0]
                return v.props.get("plain") if isinstance(v, Obj) and v.kind == "securestring" else v
            if n in ("copy",) and len(args) >= 4:
                src = args[0]
                if isinstance(src, (RBytes, bytearray, list)):
                    self.sinks.load(self.to_value(src), "Marshal.Copy (to unmanaged memory)", line=line)
                return None
            if n == "getdelegateforfunctionpointer":
                self.sinks.step(line, "Marshal.GetDelegateForFunctionPointer: calls native code", Value.of(""))
                return Obj("delegate")
            if n in ("allochglobal", "sizeof", "readint32", "readbyte", "freehglobal", "zerofreebstr"):
                return 0
        if k == "type" and n == "gettype":
            return TypeRef(self.text(args[0]))
        if k == "activator" and n == "createinstance":
            t2 = args[0]
            return self.new_object(t2.name if isinstance(t2, TypeRef) else self.text(t2), args[1:], node)
        if k == "regex":
            if n == "replace" and len(args) >= 3:
                return self.binop("replace", args[0], PSList([args[1], args[2]]))
            if n == "split" and len(args) >= 2:
                return self.binop("csplit", args[0], args[1])
            if n == "unescape":
                return T.unescape(self.text(args[0]))
            if n in ("matches", "match"):
                try:
                    ms = list(re.finditer(_net_regex(self.text(args[1])), self.text(args[0])))
                except re.error:
                    ms = []
                objs = [Obj("match", props={"value": m.group(0), "index": m.start(), "groups": PSList([m.group(0), *m.groups()])}) for m in ms]
                return PSList(objs) if n == "matches" else (objs[0] if objs else Obj("match", props={"value": "", "success": False}))
        if k in ("aes", "des", "3des") and n == "create":
            return self.new_object(t.name, [], node)
        if k in ("sha256", "md5", "sha1") and n == "create":
            return Obj("hash", alg=k)
        if k == "webrequest" and n == "create":
            return Obj("webrequest", url=args[0] if args else "")
        if k == "httputility" and n in ("urldecode", "htmldecode"):
            import html
            import urllib.parse
            s = self.text(args[0])
            return step(args[0], "url-decode" if n == "urldecode" else "html-decode",
                        urllib.parse.unquote_plus(s) if n == "urldecode" else html.unescape(s))
        if k == "zipfile" and n in ("extracttodirectory", "openread"):
            return Unk("an archive on the victim's machine")
        if k == "runtimeenvironment" and n == "getruntimedirectory":
            return "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"
        if k == "guid" and n == "newguid":
            return "6f0c2a8e-3b1d-4e55-9a77-2c4d5e6f7a80"
        if k == "datetime" and n in ("now", "utcnow"):
            return Unk("the date on the victim's machine")
        if n == "new":
            return self.new_object(t.name, args, node)
        if k in ("process",) and n == "start":
            return self.start_process(args, line)
        if k == "enum":
            return RStr(name)
        return Unk(f"[{t.name}]::{name}()")

    # -- .NET: objects -------------------------------------------------------------------------
    def new_object(self, tname: str, args: list, node: Any) -> Any:  # noqa: C901
        k = norm_type(tname)
        line = node[1] if node else None
        if len(args) == 1 and isinstance(args[0], list) and not isinstance(args[0], RBytes) and k in ("io.memorystream",):
            args = list(args[0])                  # New-Object IO.MemoryStream(,$bytes)
        if k == "io.memorystream":
            if args and not isinstance(args[0], (int, float)) and args[0] is not None:
                if isinstance(args[0], Unk):
                    return Obj("memorystream", data=RBytes(), pos=0, recipe=(), unknown=args[0])
                b = self.as_bytes(args[0])
                return Obj("memorystream", data=RBytes(b), pos=0, recipe=rec(args[0]))
            return Obj("memorystream", data=RBytes(), pos=0, recipe=())
        if k in ("gzipstream", "deflatestream"):
            return Obj("compstream", alg="gzip" if k == "gzipstream" else "deflate", inner=args[0] if args else None,
                       mode=self.text(args[1]) if len(args) > 1 else "Decompress", recipe=())
        if k == "io.streamreader":
            return Obj("streamreader", inner=args[0] if args else None, enc=(args[1].enc if len(args) > 1 and isinstance(args[1], Obj) and args[1].kind == "encoding" else "utf-8"))
        if k in ("aes", "des", "3des"):
            return Obj("cipher", alg=k, props={"mode": "CBC", "padding": "PKCS7"})
        if k == "cryptostream":
            return Obj("cryptostream", target=args[0] if args else None, transform=args[1] if len(args) > 1 else None,
                       mode=self.text(args[2]) if len(args) > 2 else "Read", buf=RBytes(), recipe=rec(args[0]) if args else ())
        if k == "pbkdf2":
            return Obj("pbkdf2", pw=args[0] if args else "", salt=args[1] if len(args) > 1 else b"",
                       it=self.num(args[2]) if len(args) > 2 and not isinstance(args[2], str) else 1000)
        if k in ("sha256", "md5", "sha1"):
            return Obj("hash", alg=k)
        if k == "webclient":
            return Obj("webclient")
        if k == "httpclient":
            return Obj("webclient")
        if k in ("text.stringbuilder",):
            return Obj("stringbuilder", parts=[self.text(args[0])] if args else [])
        if k == "arraylist":
            return PSList()
        if k in ("byte[]", "char[]", "object[]", "string[]", "int[]"):
            size = self.num(args[0]) if args else 0
            if not isinstance(size, int) or size > T.MAX_OUT:
                raise Limit("array too large")
            return RBytes(size) if k == "byte[]" else PSList([None] * size)
        if k == "pscredential":
            pw = args[1] if len(args) > 1 else None
            return Obj("pscredential", props={"user": args[0] if args else "", "password": pw})
        if k == "processstartinfo":
            return Obj("processstartinfo", props={"filename": self.text(args[0]) if args else "",
                                                  "arguments": self.text(args[1]) if len(args) > 1 else ""})
        if k == "hashtable":
            return {}
        if k == "string":
            return self.call_static(TypeRef("string"), "new", args, node)
        if k == "uri":
            return self.text(args[0]) if args else ""
        if k == "net.sockets.tcpclient":
            host = self.text(args[0]) if args else ""
            port = self.text(args[1]) if len(args) > 1 else ""
            self.sinks.download(Value.of(f"tcp://{host}:{port}", f"$TcpClient"), "TcpClient", "opens a raw TCP connection (reverse shell / C2)", line)
            return Obj("tcpclient")
        if k.startswith("io.compression.") or k.startswith("security.cryptography."):
            return Obj(k.rsplit(".", 1)[-1])
        if k.startswith("-comobject") or k == "comobject":
            return self.com_object(self.text(args[0]) if args else "")
        return Obj(k)

    def com_object(self, progid: str) -> Obj:
        return Obj("com", progid=progid.lower())

    def stream_read_all(self, s: Any) -> Any:
        """Everything a stream (and the streams it wraps) yields when read."""
        if isinstance(s, Unk):
            return s
        if not isinstance(s, Obj):
            return self.as_bytes(s)
        if s.kind == "memorystream":
            if getattr(s, "unknown", None):
                return s.unknown
            data = s.data[s.pos:]
            s.pos = len(s.data)
            return tag(RBytes(data), s.recipe)
        if s.kind == "compstream":
            inner = self.stream_read_all(s.inner)
            if isinstance(inner, Unk):
                return inner
            raw = bytes(inner)
            out = T.gunzip(raw) if s.alg == "gzip" and raw[:2] == b"\x1f\x8b" else T.inflate(raw)
            return tag(RBytes(out), rec(inner) + (s.alg,))
        if s.kind == "cryptostream":
            inner = self.stream_read_all(s.target)
            if isinstance(inner, Unk):
                return inner
            return self.transform(s.transform, inner)
        if s.kind == "streamreader":
            return self.stream_read_all(s.inner)
        return Unk(f"data read from a {s.kind}")

    def transform(self, tr: Any, data: Any) -> Any:
        if not isinstance(tr, Obj) or tr.kind != "cryptotransform":
            return Unk("a stream transform not known")
        c = tr.cipher
        key = c.props.get("key")
        iv = c.props.get("iv")
        if isinstance(key, Unk) or isinstance(iv, Unk) or key is None:
            return Unk("the key of a cipher computed from something not in the script")
        mode = self.text(c.props.get("mode") or "CBC").lower()
        pad = self.text(c.props.get("padding") or "PKCS7").lower()
        alg = {"aes": "aes", "des": "des", "3des": "3des"}[c.alg]
        kb, ivb = bytes(self.as_bytes(key)), (bytes(self.as_bytes(iv)) if iv is not None else None)
        if tr.encrypt:
            return Unk("data the script encrypts")
        out = T.decrypt(alg, bytes(self.as_bytes(data)), kb, ivb, mode, "pkcs7" if pad.startswith("pkcs") else ("zeros" if pad == "zeros" else "none"))
        name = f"{alg}-{len(kb) * 8}-{mode}" if alg == "aes" else f"{alg}-{mode}"
        k_lab = label(key, f"key {kb[:6].hex()}…")
        iv_lab = label(iv, f"{ivb[:6].hex()}…" if ivb else "")
        return tag(RBytes(out), rec(data) + (f"{name}(key {k_lab}" + (f", iv {iv_lab})" if ivb and mode != "ecb" else ")"),))

    def call_method(self, o: Any, name: str, args: list, node: Any) -> Any:  # noqa: C901
        n = name.lower()
        line = node[1] if node else None
        if isinstance(o, _Silent):
            o = o.value
        if isinstance(o, Unk):
            return Unk(o.why)
        # strings
        if isinstance(o, str):
            r = rec(o)
            s = str(o)
            try:
                if n == "replace":
                    out = s.replace(self.text(args[0]), self.text(args[1])) if self.text(args[0]) else s
                    return tag(out, r) if r else out
                if n == "split":
                    seps = args[0] if args else " "
                    if isinstance(seps, list):
                        parts = re.split("|".join(re.escape(self.text(x)) for x in seps), s)
                    else:
                        sep = self.text(seps)
                        parts = re.split("[" + re.escape(sep) + "]", s) if len(sep) > 1 and not (len(args) > 1) else s.split(sep)
                    if len(args) > 1 and self.text(args[-1]).lower() in ("removeemptyentries", "1"):
                        parts = [p for p in parts if p]
                    return tag(PSList(parts), r)
                if n == "substring":
                    a = self.num(args[0])
                    out = s[a:a + self.num(args[1])] if len(args) > 1 else s[a:]
                    return tag(out, r) if r else out
                if n == "tochararray":
                    return tag(PSList(list(s)), r)
                if n in ("toupper", "toupperinvariant"):
                    return s.upper()
                if n in ("tolower", "tolowerinvariant"):
                    return s.lower()
                if n in ("trim", "trimstart", "trimend"):
                    chars = "".join(self.text(a) for a in args) or None
                    f = {"trim": str.strip, "trimstart": str.lstrip, "trimend": str.rstrip}[n]
                    out = f(s, chars) if chars else f(s)
                    return tag(out, r) if r else out
                if n == "insert":
                    i = self.num(args[0])
                    return s[:i] + self.text(args[1]) + s[i:]
                if n == "remove":
                    i = self.num(args[0])
                    return s[:i] + (s[i + self.num(args[1]):] if len(args) > 1 else "")
                if n == "indexof":
                    return s.find(self.text(args[0]))
                if n == "lastindexof":
                    return s.rfind(self.text(args[0]))
                if n == "contains":
                    return self.text(args[0]) in s
                if n == "startswith":
                    return s.lower().startswith(self.text(args[0]).lower())
                if n == "endswith":
                    return s.lower().endswith(self.text(args[0]).lower())
                if n in ("padleft", "padright"):
                    w = self.num(args[0])
                    ch = self.text(args[1])[:1] if len(args) > 1 else " "
                    return s.rjust(w, ch) if n == "padleft" else s.ljust(w, ch)
                if n in ("tostring", "normalize", "clone"):
                    return o
                if n == "getenumerator":
                    return PSList(list(s))
                if n in ("equals", "compareto"):
                    return s == self.text(args[0]) if n == "equals" else (s > self.text(args[0])) - (s < self.text(args[0]))
                if n == "getbytes":
                    return tag(RBytes(s.encode("utf-8")), r)
                if n == "chars":
                    return s[self.num(args[0])]
            except IndexError:
                return None
        if isinstance(o, (RBytes, bytearray, list)):
            if n in ("clone", "toarray"):
                return tag(type(o)(o) if isinstance(o, (RBytes, bytearray)) else PSList(o), rec(o))
            if n == "add":
                o.append(args[0] if not isinstance(o, (RBytes, bytearray)) else self.num(args[0]) & 0xFF)
                return len(o) - 1
            if n == "addrange":
                o.extend(self.iterate(args[0]))
                return None
            if n == "contains":
                return any(self.equal(x, args[0]) for x in o)
            if n == "indexof":
                try:
                    return list(o).index(args[0])
                except ValueError:
                    return -1
            if n == "reverse":
                o.reverse()
                return None
            if n == "getvalue":
                return o[self.num(args[0])]
            if n == "setvalue":
                o[self.num(args[1])] = args[0]
                return None
            if n in ("foreach", "where"):
                sb = args[0]
                out = []
                for item in self.iterate(o):
                    v = self.run_sb(sb, [], dollar_=item)
                    if n == "foreach":
                        self.emit(out, v)
                    elif self.truth(v):
                        out.append(item)
                return tag(PSList(out), rec(o))
            if n == "tostring":
                return self.text(o)
            if n == "getrange":
                a, c = self.num(args[0]), self.num(args[1])
                return tag(type(o)(o[a:a + c]), rec(o))
        if isinstance(o, dict):
            if n in ("add", "set_item"):
                o[self.key(args[0])] = args[1]
                return None
            if n in ("containskey", "contains"):
                return self.key(args[0]) in o
            if n == "remove":
                o.pop(self.key(args[0]), None)
                return None
            if n == "getenumerator":
                return PSList([{"key": k2, "value": v2, "name": k2} for k2, v2 in o.items()])
        if isinstance(o, ScriptBlock):
            if n in ("invoke", "invokereturnasis", "invokewithcontext"):
                return self.run_sb(o, args, line=line)
            if n == "getnewclosure":
                return o
            if n == "tostring":
                return o.text or ""
        if isinstance(o, CommandInfo):
            if n == "invoke":
                return self.invoke_command(o.name, [("pos", a) for a in args], line, node)
        if isinstance(o, TypeRef):
            return self.call_static(o, name, args, node)
        if isinstance(o, Obj):
            return self.obj_method(o, n, name, args, node, line)
        if o is None:
            return None
        if isinstance(o, (int, float)) and n == "tostring":
            if args:
                spec = self.text(args[0])
                if spec[:1] in ("X", "x"):
                    return format(self.num(o), spec[0]).zfill(int(spec[1:]) if spec[1:].isdigit() else 0)
            return self.text(o)
        return Unk(f"{name}() of {type(o).__name__}")

    def obj_method(self, o: Obj, n: str, name: str, args: list, node: Any, line: int | None) -> Any:  # noqa: C901
        k = o.kind
        if k in ("encoding",):
            if n == "getstring":
                b = args[0]
                if isinstance(b, Unk):
                    return b
                raw = bytes(self.as_bytes(b))
                if len(args) >= 3:
                    i, c = self.num(args[1]), self.num(args[2])
                    raw = raw[i:i + c]
                txt = T.as_text(raw, o.enc)
                return tag(txt, rec(b)) if rec(b) else txt
            if n == "getbytes":
                s = self.text(args[0])
                try:
                    raw = s.encode(o.enc if o.enc != "utf-16-le" else "utf-16-le", "replace")
                except LookupError:
                    raw = s.encode("utf-8")
                return tag(RBytes(raw), rec(args[0]))
        if k == "memorystream":
            if n == "toarray" or n == "getbuffer":
                if getattr(o, "unknown", None):
                    return o.unknown
                return tag(RBytes(o.data), o.recipe)
            if n == "write":
                b = self.as_bytes(args[0])
                off = self.num(args[1]) if len(args) > 1 else 0
                cnt = self.num(args[2]) if len(args) > 2 else len(b) - off
                o.data[o.pos:o.pos + cnt] = b[off:off + cnt]
                o.pos += cnt
                o.recipe = o.recipe or rec(args[0])
                return None
            if n == "writebyte":
                o.data.append(self.num(args[0]) & 0xFF)
                return None
            if n == "read":
                buf = args[0]
                off = self.num(args[1]) if len(args) > 1 else 0
                cnt = self.num(args[2]) if len(args) > 2 else len(buf)
                chunk = o.data[o.pos:o.pos + cnt]
                buf[off:off + len(chunk)] = chunk
                o.pos += len(chunk)
                return len(chunk)
            if n == "seek":
                o.pos = self.num(args[0])
                return o.pos
            if n == "copyto":
                dst = args[0]
                data = self.stream_read_all(o)
                self._stream_write(dst, data)
                return None
            if n in ("dispose", "close", "flush", "setlength"):
                return None
        if k in ("compstream", "cryptostream", "streamreader"):
            if k == "cryptostream" and self.text(o.mode).lower() == "write":
                if n == "write":
                    b = self.as_bytes(args[0])
                    off = self.num(args[1]) if len(args) > 1 else 0
                    cnt = self.num(args[2]) if len(args) > 2 else len(b) - off
                    o.buf += b[off:off + cnt]
                    o.recipe = rec(args[0]) or o.recipe
                    return None
                if n in ("flushfinalblock", "close", "dispose", "flush"):
                    if not getattr(o, "done", False):
                        o.done = True
                        out = self.transform(o.transform, tag(RBytes(o.buf), o.recipe))
                        if isinstance(out, Unk):
                            if isinstance(o.target, Obj) and o.target.kind == "memorystream":
                                o.target.unknown = out
                            return None
                        self._stream_write(o.target, out)
                    return None
            if k == "compstream" and self.text(o.mode).lower() == "compress":
                return None
            if n in ("copyto",):
                data = self.stream_read_all(o)
                self._stream_write(args[0], data)
                return None
            if n in ("readtoend",):
                data = self.stream_read_all(o)
                if isinstance(data, Unk):
                    return data
                enc = getattr(o, "enc", "utf-8")
                return tag(T.as_text(bytes(data), enc), rec(data))
            if n == "read":
                data = self.stream_read_all(o)
                if isinstance(data, Unk):
                    return 0
                buf = args[0]
                off = self.num(args[1]) if len(args) > 1 else 0
                cnt = min(self.num(args[2]) if len(args) > 2 else len(buf), len(data))
                buf[off:off + cnt] = data[:cnt]
                if isinstance(buf, RBytes):
                    buf.recipe = rec(data)
                return cnt
            if n in ("dispose", "close", "flush"):
                return None
            if n == "readline":
                data = self.stream_read_all(o)
                return T.as_text(bytes(data)).splitlines()[0] if not isinstance(data, Unk) and data else None
        if k == "cipher":
            if n in ("createdecryptor", "createencryptor"):
                if args:
                    o.props["key"] = args[0]
                    if len(args) > 1:
                        o.props["iv"] = args[1]
                return Obj("cryptotransform", cipher=o, encrypt=n == "createencryptor")
            if n in ("generatekey", "generateiv"):
                o.props["key" if n == "generatekey" else "iv"] = Unk("a random key generated at run time")
                return None
            if n in ("dispose", "clear"):
                return None
        if k == "cryptotransform":
            if n == "transformfinalblock":
                data = self.as_bytes(args[0])
                off = self.num(args[1]) if len(args) > 1 else 0
                cnt = self.num(args[2]) if len(args) > 2 else len(data) - off
                return self.transform(o, tag(RBytes(data[off:off + cnt]), rec(args[0])))
            if n == "dispose":
                return None
        if k == "hash":
            if n == "computehash":
                d = args[0]
                if isinstance(d, Unk):
                    return d
                return tag(RBytes(T.digest(o.alg, bytes(self.as_bytes(d)))), ())
            if n in ("dispose", "clear"):
                return None
        if k == "pbkdf2" and n == "getbytes":
            pw, salt = o.pw, o.salt
            if isinstance(pw, Unk) or isinstance(salt, Unk):
                return Unk("a key derived from something not in the script")
            out = T.pbkdf2(bytes(self.as_bytes(pw)) if not isinstance(pw, str) else pw.encode(), bytes(self.as_bytes(salt)) if not isinstance(salt, str) else salt.encode(), o.it, self.num(args[0]))
            return tag(RBytes(out), (f"pbkdf2({label(pw, 'password')}, {o.it})",))
        if k == "webclient":
            if n in ("downloadstring", "downloaddata", "downloadfile", "openread", "downloadstringtaskasync",
                     "downloaddatataskasync", "getstringasync", "getbytearrayasync", "uploadstring", "uploaddata",
                     "uploadfile", "uploadvalues"):
                url = args[0] if args else ""
                dest = self.text(args[1]) if n == "downloadfile" and len(args) > 1 else ""
                use = ("saves it to " + dest) if dest else ("returns it to the script" if n not in ("uploadstring", "uploaddata", "uploadfile", "uploadvalues") else "sends data to it (exfiltration)")
                self._download(url, f"WebClient.{name}", use, line, dest)
                return Unk(f"the content downloaded from {self.text(url) if not isinstance(url, Unk) else 'a URL'}", (f"download {self.text(url)}",))
            return None
        if k == "webrequest":
            if n in ("getresponse", "getresponseasync"):
                self._download(o.url, "WebRequest.GetResponse", "returns it to the script", line)
                return Obj("webresponse", url=o.url)
        if k == "webresponse" and n == "getresponsestream":
            return Unk(f"the content downloaded from {self.text(o.url)}", (f"download {self.text(o.url)}",))
        if k == "assembly":
            if n == "gettype":
                return Obj("rtype", asm=o, name=self.text(args[0]) if args else "")
            if n == "gettypes" or n == "getexportedtypes":
                return PSList([Obj("rtype", asm=o, name="(types of the loaded assembly)")])
            if n == "createinstance":
                return Obj("instance", asm=o, name=self.text(args[0]) if args else "")
        if k == "rtype":
            if n in ("getmethod", "getmethods"):
                return Obj("method", asm=o.asm, type=o.name, name=self.text(args[0]) if args else "")
            if n == "invokemember":
                return self._invoke_loaded(o.asm, o.name, self.text(args[0]) if args else "", args[4] if len(args) > 4 else [], line)
        if k == "method":
            if n == "invoke":
                call_args = args[1] if len(args) > 1 else []
                return self._invoke_loaded(o.asm, o.type, o.name, call_args, line)
        if k == "appdomain" and n == "load":
            return self.call_static(TypeRef("Reflection.Assembly"), "Load", args, node)
        if k == "invokecommand":
            if n in ("invokescript", "newscriptblock"):
                code = args[0] if args else ""
                if n == "invokescript":
                    return self.run_code(code, "$ExecutionContext.InvokeCommand.InvokeScript", line)
                return ScriptBlock(None, self.text(code), rec(code))
            if n in ("getcommand", "getcmdlet", "getcommandname"):
                return self.resolve_command_value(args[0] if args else "", node)
            if n == "expandstring":
                return self.expand(self.text(args[0]))
        if k == "stringbuilder":
            if n in ("append", "appendline"):
                o.parts.append(self.text(args[0]) + ("\r\n" if n == "appendline" else ""))
                return o
            if n == "tostring":
                return "".join(o.parts)
        if k == "com":
            return self.com_call(o, n, name, args, line)
        if k == "regex":
            if n == "replace":
                return self.binop("replace", args[0], PSList([o.pattern, args[1] if len(args) > 1 else ""]))
            if n == "split":
                return self.binop("csplit", args[0], o.pattern)
            if n in ("matches", "match", "ismatch"):
                return self.binop("match", args[0], o.pattern) if n == "ismatch" else self.call_static(TypeRef("regex"), name, [args[0], o.pattern], node)
        if k == "pscredential" and n == "getnetworkcredential":
            pw = o.props.get("password")
            plain = pw.props.get("plain") if isinstance(pw, Obj) and pw.kind == "securestring" else pw
            return Obj("networkcredential", password=plain, user=o.props.get("user"))
        if k == "match":
            return None
        if n in ("dispose", "close", "clear", "flush"):
            return None
        return Unk(f"{name}() of a {k}")

    def _stream_write(self, dst: Any, data: Any) -> None:
        if isinstance(dst, Obj) and dst.kind == "memorystream":
            if isinstance(data, Unk):
                dst.unknown = data
                return
            dst.data[dst.pos:dst.pos + len(data)] = data
            dst.pos += len(data)
            dst.recipe = rec(data) or dst.recipe

    def _invoke_loaded(self, asm: Any, tname: str, mname: str, call_args: Any, line: int | None) -> Any:
        """A method of an assembly the script loaded: what it is handed is recorded (a PE passed
        to a loader's "run" method is the payload it injects)."""
        items = self.iterate(call_args) if isinstance(call_args, list) and not isinstance(call_args, RBytes) else [call_args]
        shown = []
        for a in items:
            if isinstance(a, (RBytes, bytearray)) and len(a) >= 64:
                self.sinks.load(self.to_value(a), f"argument of {tname}.{mname} (handed to the loaded assembly)", line=line)
                shown.append(f"{len(a)} bytes")
            elif isinstance(a, str):
                shown.append(repr(str(a))[:120])
            else:
                shown.append(type(a).__name__)
        self.sinks.step(line, f"invokes {tname}.{mname}({', '.join(shown)}) of the loaded assembly", Value.of(""))
        return Unk(f"the result of {tname}.{mname} in the loaded assembly")

    def com_call(self, o: Obj, n: str, name: str, args: list, line: int | None) -> Any:
        pid = o.progid
        if pid in ("wscript.shell",) and n in ("run", "exec"):
            cmd = args[0] if args else ""
            self.sinks.step(line, f"WScript.Shell.{name} {self.text(cmd)[:200]}", self.to_value(cmd))
            self.external(self.text(cmd), line, rec(cmd))
            return 0
        if pid in ("shell.application",) and n == "shellexecute":
            cmd = " ".join(self.text(a) for a in args[:2])
            self.sinks.step(line, f"Shell.Application.ShellExecute {cmd[:200]}", self.to_value(cmd))
            self.external(cmd, line, ())
            return None
        if pid in ("msxml2.xmlhttp", "microsoft.xmlhttp", "msxml2.serverxmlhttp", "winhttp.winhttprequest.5.1"):
            if n == "open" and len(args) >= 2:
                o.props["url"] = args[1]
            if n == "send":
                self._download(o.props.get("url", ""), f"{pid} Send", "returns it to the script", line)
            return None
        if pid in ("adodb.stream",):
            if n == "write":
                o.props["data"] = args[0]
            if n == "savetofile" and args:
                self.sinks.write(self.to_value(o.props.get("data", b"")), self.text(args[0]), "ADODB.Stream.SaveToFile", line)
            return None
        return None

    def _download(self, url: Any, method: str, use: str, line: int | None, dest: str = "") -> None:
        if isinstance(url, Unk):
            self.sinks.download(Value.unknown(url.why), method, use, line, dest)
        else:
            self.sinks.download(Value("str", self.text(url), rec(url)), method, use, line, dest)

    # -- script blocks and inline code -------------------------------------------------------------
    def run_sb(self, sb: Any, args: list, dollar_: Any = None, line: int | None = None) -> Any:
        if isinstance(sb, CommandInfo):
            return self.invoke_command(sb.name, [("pos", a) for a in args], line, None)
        if not isinstance(sb, ScriptBlock):
            if isinstance(sb, str):
                return self.run_code(sb, "&", line)
            return Unk("a script block not known")
        if sb.body is None:
            code = sb.text or ""
            return self.run_code(tag(code, sb.recipe), "ScriptBlock.Invoke", line)
        params = next((st[2] for st in sb.body if st[0] == "param"), None)
        if params:
            self.scopes.append({"_": dollar_, "psitem": dollar_})
            try:
                return self.invoke_body("scriptblock", params, sb.body, [("pos", a) for a in args], dollar_)
            finally:
                self.scopes.pop()
        self.scopes.append({"_": dollar_, "psitem": dollar_, "args": PSList(args)})
        try:
            out = self.block(sb.body)
        except _Return as r:
            out = list(r.partial)
            self.emit(out, r.value)
        finally:
            self.scopes.pop()
        return out[0] if len(out) == 1 else (PSList(out) if out else None)

    def run_code(self, code: Any, sink: str, line: int | None) -> Any:
        """Code handed to Invoke-Expression & co.: reported as a stage, then evaluated here too (so
        the functions it defines and the stages it computes are followed)."""
        if isinstance(code, Unk):
            self.sinks.exec_(Value.unknown(code.why), sink, line)
            return Unk(f"the output of code computed from {code.why}")
        if isinstance(code, ScriptBlock):
            if code.body is not None:
                return self.run_sb(code, [], line=line)
            code = tag(code.text or "", code.recipe)
        text = self.text(code)
        self.sinks.exec_(self.to_value(tag(text, rec(code))), sink, line)
        h = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if self.depth >= MAX_DEPTH or h in self.ran_inline:
            return None
        self.ran_inline.add(h)
        self.depth += 1
        self.sinks.depth = self.depth
        saved = self.source
        try:
            self.source = text
            body = parse(text)
            out = self.block(body, top=True)
        except (_Return, _Break, _Continue):
            out = []
        finally:
            self.source = saved
            self.depth -= 1
            self.sinks.depth = self.depth
        return out[0] if len(out) == 1 else (PSList(out) if out else None)

    # -- commands ------------------------------------------------------------------------------
    def pipe(self, n: tuple) -> Any:
        cur: Any = None
        first = True
        for part in n[2]:
            if first:
                cur = self.eval(part)
                first = False
                continue
            if part[0] == "command":
                cur = self.command(part, cur)
            else:
                cur = self.eval(part)
        return cur

    def resolve_command_value(self, v: Any, node: Any) -> Any:
        if isinstance(v, Unk):
            return v
        if isinstance(v, (CommandInfo, ScriptBlock)):
            return v
        name = self.text(v).strip().strip("'\"").replace("`", "")
        found = self.resolve_name(name)
        return CommandInfo(found) if found else CommandInfo(name)

    def resolve_name(self, name: str) -> str | None:
        """A command name as PowerShell would resolve it: case, aliases, wildcards (Get-Command)."""
        n = name.strip().replace("`", "").lower()
        n = n.rsplit("\\", 1)[-1]
        if n in self.functions:
            return self.functions[n][0]
        if n in self.aliases:
            return self.aliases[n]
        if n in ALIASES:
            return ALIASES[n]
        if n in _CMDLET_LOWER:
            return _CMDLET_LOWER[n]
        if any(c in n for c in "*?["):
            pool = list(self.functions) + list(_CMDLET_LOWER) + list(ALIASES)
            hits = [p for p in pool if fnmatch.fnmatch(p, n)]
            if hits:
                # Get-Command returns the first in its order: cmdlets come before aliases in practice
                best = sorted(hits, key=lambda p: (p not in _CMDLET_LOWER, p))[0]
                return _CMDLET_LOWER.get(best) or ALIASES.get(best) or self.functions.get(best, (best,))[0]
        return None

    def command(self, n: tuple, piped: Any) -> Any:
        line = n[1]
        name_node, arg_nodes, invoke = n[2], n[3], n[4]
        if name_node[0] == "str" and invoke is None:
            target: Any = name_node[2]
        else:
            target = self.eval(name_node)
        args: list = []
        i = 0
        while i < len(arg_nodes):
            a = arg_nodes[i]
            if a[0] == "param":
                val = self.eval(a[3]) if a[3] is not None else _SWITCH
                args.append(("named", a[2], val))
            else:
                args.append(("pos", self.eval(a)))
            i += 1
        if isinstance(target, Unk):
            self.sinks.unresolved_(self._span(n), target.why, "the name of the command it runs is computed from "
                                   "something not in the script", line)
            return Unk(f"the output of a command whose name depends on {target.why}")
        if isinstance(target, ScriptBlock):
            return self.run_sb(target, [v for kind, *rest in args for v in ([rest[-1]] if kind == "pos" else [])],
                               dollar_=piped, line=line)
        if isinstance(target, CommandInfo):
            return self.invoke_command(target.name, args, line, n, piped)
        if isinstance(target, (list,)) and not isinstance(target, RBytes) and target and all(isinstance(x, str) for x in target):
            target = "".join(target)
        if isinstance(target, str):
            return self.invoke_command(target, args, line, n, piped)
        return Unk("a command not known")

    def _args(self, args: list, spec: list[str]) -> tuple[dict[str, Any], list]:
        """Named arguments matched to ``spec`` (prefixes allowed) and the positional ones."""
        named: dict[str, Any] = {}
        pos: list = []
        it = iter(range(len(args)))
        idx = 0
        while idx < len(args):
            a = args[idx]
            if a[0] == "named":
                key = a[1].lower()
                full = next((s for s in spec if s.lower() == key), None) or next((s for s in spec if s.lower().startswith(key)), key)
                val = a[2]
                if val is _SWITCH and idx + 1 < len(args) and args[idx + 1][0] == "pos" and full.lower() not in _SWITCHES:
                    val = args[idx + 1][1]
                    idx += 1
                named[full.lower()] = val
            else:
                pos.append(a[1])
            idx += 1
        del it
        return named, pos

    def invoke_command(self, name: str, args: list, line: int | None, node: Any, piped: Any = None) -> Any:  # noqa: C901
        raw = name
        resolved = self.resolve_name(name)
        # how the name was written, when it is not the command's own name (computed, alias, backticks)
        named_as = ""
        if resolved and node is not None and node[0] == "command":
            if node[4] is not None:                                   # & (…) / . (…)
                named_as = f"{resolved} (called as {node[4]} {_unparse(node[2])[:100]})"
            elif raw.strip().lower() != resolved.lower() and raw.strip().lower() not in ALIASES:
                named_as = f"{resolved} (called as {raw.strip()[:60]})"   # a script's alias, backticks
        low = (resolved or raw).lower()
        base = raw.replace("`", "").strip().lower().rsplit("\\", 1)[-1]
        self.call_depth += 1
        try:
            if self.call_depth > MAX_CALL_DEPTH:
                raise _Throw("call depth")
            if low in self.functions:
                return self.call_function(low, args, piped, line)
            if base in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
                return self.powershell_exe(args, line)
            if base in ("cmd", "cmd.exe"):
                text = " ".join(self.text(a[-1]) for a in args)
                self.sinks.step(line, f"cmd {text[:200]}", Value.of(text))
                self.external("cmd " + text, line, ())
                return None
            named, pos = self._args(args, ["Command", "ScriptBlock", "Uri", "OutFile", "FilePath", "ArgumentList",
                                           "TypeName", "ComObject", "Name", "Value", "Path", "Seconds", "Milliseconds",
                                           "Object", "InputObject", "Process", "MemberName", "Source", "Destination",
                                           "TypeDefinition", "MemberDefinition", "String", "Key", "AsPlainText",
                                           "Force", "ValueOnly", "Scope", "Option", "First", "Last", "Skip", "Index",
                                           "ExpandProperty", "Property", "Encoding", "Method", "Body", "Headers",
                                           "UseBasicParsing", "WindowStyle", "NoNewWindow", "Wait", "PassThru",
                                           "ErrorAction", "Definition", "Language", "ReferencedAssemblies",
                                           "PropertyType", "Verb", "Credential", "Argument", "RunAs32"])
            if low == "invoke-expression":
                code = named.get("command", pos[0] if pos else piped)
                return self.run_code(code, named_as or "Invoke-Expression", line)
            if low == "start-job":
                sb = named.get("scriptblock", pos[0] if pos else None)
                al = named.get("argumentlist", named.get("argument"))
                if isinstance(sb, ScriptBlock):
                    return self.run_sb(sb, list(self.iterate(al)) if isinstance(al, list) and not isinstance(al, RBytes) else ([al] if al is not None else []), line=line)
                return _Silent(None)
            if low == "invoke-command":
                sb = named.get("scriptblock", pos[0] if pos else None)
                return self.run_sb(sb, list(self.iterate(named.get("argumentlist"))), line=line) if isinstance(sb, ScriptBlock) else self.run_code(sb, "Invoke-Command", line)
            if low in ("write-host", "write-output", "write-verbose", "write-debug", "write-warning", "write-error", "write-information"):
                vals = pos or ([named.get("object") or named.get("inputobject")] if named else [])
                if low == "write-output":
                    return PSList(vals) if len(vals) > 1 else (vals[0] if vals else piped)
                if vals:
                    self.sinks.step(line, f"{resolved}: {' '.join(self.text(v) for v in vals)[:200]}", Value.of(""))
                return _Silent(None)
            if low == "out-null":
                return _Silent(None)
            if low == "out-string":
                return self.text(piped)
            if low in ("start-sleep", "set-strictmode", "clear-host", "set-executionpolicy", "import-module",
                       "set-location", "unblock-file", "wait-job", "format-list", "format-table"):
                return _Silent(None)
            if low == "get-process":
                return PSList()              # nothing runs in the analysis: no process is found
            if low in ("get-command", "get-alias"):
                v = named.get("name", pos[0] if pos else "")
                return self.resolve_command_value(v, node)
            if low in ("set-alias", "new-alias"):
                nm = self.text(named.get("name", pos[0] if pos else ""))
                val = named.get("value", pos[1] if len(pos) > 1 else "")
                tgt = self.resolve_name(self.text(val)) or self.text(val)
                self.aliases[nm.lower()] = tgt
                return _Silent(None)
            if low in ("get-variable",):
                nm = named.get("name", pos[0] if pos else "")
                if isinstance(nm, Unk):
                    return nm
                pat = self.text(nm).lower()
                val = self.get(pat) if not any(c in pat for c in "*?") else next(
                    (v for sc in reversed(self.scopes) for k2, v in sc.items() if fnmatch.fnmatch(k2, pat)), None)
                if "valueonly" in named:
                    return val
                return {"name": pat, "value": val}
            if low in ("set-variable", "new-variable"):
                nm = self.text(named.get("name", pos[0] if pos else ""))
                self.set(nm, named.get("value", pos[1] if len(pos) > 1 else piped))
                return _Silent(None)
            if low == "new-object":
                tn = named.get("typename", pos[0] if pos else "")
                if "comobject" in named:
                    return self.com_object(self.text(named["comobject"]))
                if isinstance(tn, Unk):
                    self.sinks.unresolved_(self._span(node), tn.why, "the type it creates is computed from something not in the script", line)
                    return Unk(f"an object whose type depends on {tn.why}")
                al = named.get("argumentlist", pos[1] if len(pos) > 1 else None)
                al_list = list(al) if isinstance(al, list) and not isinstance(al, RBytes) else ([] if al is None else [al])
                tname = self.text(tn)
                m = re.match(r"\s*([\w.\[\]]+)\s*\((.*)\)\s*$", tname)
                if m and not al_list:
                    tname = m.group(1)
                return self.new_object(tname, al_list, node)
            if low in ("invoke-webrequest", "invoke-restmethod", "start-bitstransfer"):
                url = named.get("uri", named.get("source", pos[0] if pos else ""))
                dest = self.text(named.get("outfile", named.get("destination", "")))
                self._download(url, resolved or name, f"saves it to {dest}" if dest else "returns it to the script", line, dest)
                return Unk(f"the content downloaded from {self.text(url) if not isinstance(url, Unk) else 'a URL'}")
            if low == "start-process":
                fp = named.get("filepath", pos[0] if pos else "")
                al = named.get("argumentlist", pos[1] if len(pos) > 1 else "")
                cmd = f"{self.text(fp)} {self.text(al) if not isinstance(al, list) else ' '.join(self.text(x) for x in al)}".strip()
                self.sinks.step(line, f"Start-Process {cmd[:200]}", Value.of(cmd))
                self.external(cmd, line, rec(al) or rec(fp))
                return _Silent(None)
            if low == "add-type":
                code = named.get("typedefinition", named.get("memberdefinition", pos[0] if pos else None))
                if code is not None and not isinstance(code, Unk) and len(self.text(code)) > 30:
                    self.sinks.step(line, "Add-Type: compiles C# code", self.to_value(code))
                    self.sinks._add(__import__("docutracex.resolve.sinks", fromlist=["Stage"]).Stage(
                        "write", "Add-Type (C# source)", self.text(code).encode("utf-8"), rec(code) + ("→ Add-Type (C#)",), "add-type.cs", line))
                return _Silent(None)
            if low in ("convertto-securestring",):
                s = named.get("string", pos[0] if pos else piped)
                key = named.get("key")
                if "asplaintext" in named:
                    return Obj("securestring", props={"plain": s})
                if key is not None and not isinstance(s, Unk) and not isinstance(key, Unk):
                    from ..parsers.ps_deobf import securestring_decrypt
                    plain = securestring_decrypt(self.text(s), bytes(self.as_bytes(key)))
                    if plain is not None:
                        return Obj("securestring", props={"plain": tag(plain, rec(s) + ("securestring(-Key)",))})
                return Obj("securestring", props={"plain": Unk("a SecureString protected for the victim's user (DPAPI)")})
            if low in ("foreach-object",):
                sb = named.get("process", pos[0] if pos else None)
                out: list = []
                if "membername" in named or isinstance(sb, str):
                    mem = self.text(named.get("membername", sb))
                    for item in self.iterate(piped):
                        self.emit(out, self.get_member(item, mem))
                    return PSList(out)
                for item in self.iterate(piped):
                    self.emit(out, self.run_sb(sb, [], dollar_=item))
                return tag(PSList(out), rec(piped)) if rec(piped) else PSList(out)
            if low == "where-object":
                sb = pos[0] if pos else None
                return PSList([x for x in self.iterate(piped) if self.truth(self.run_sb(sb, [], dollar_=x))])
            if low == "select-object":
                items = self.iterate(piped)
                if "first" in named:
                    items = items[:self.num(named["first"])]
                if "last" in named:
                    items = items[-self.num(named["last"]):]
                if "skip" in named:
                    items = items[self.num(named["skip"]):]
                if "index" in named:
                    idx = [self.num(x) for x in self.iterate(named["index"])]
                    items = [items[i] for i in idx if i < len(items)]
                if "expandproperty" in named:
                    items = [self.get_member(x, self.text(named["expandproperty"])) for x in items]
                return PSList(items)
            if low == "sort-object":
                return PSList(sorted(self.iterate(piped), key=lambda x: self.text(x)))
            if low == "measure-object":
                return {"count": len(self.iterate(piped))}
            if low in ("get-content", "get-item", "get-itemproperty", "get-childitem", "read-host", "get-wmiobject", "get-ciminstance"):
                what = self.text(named.get("path", pos[0] if pos else ""))
                why = {"get-content": f"the content of the file {what} on the victim's machine",
                       "get-itemproperty": f"the registry / item value {what} on the victim's machine",
                       "read-host": "what the user types",
                       "get-wmiobject": f"WMI data ({what}) of the victim's machine",
                       "get-ciminstance": f"WMI data ({what}) of the victim's machine"}.get(low, f"{what} on the victim's machine")
                return Unk(why)
            if low in ("set-content", "add-content", "out-file", "new-item", "set-itemproperty", "new-itemproperty"):
                path = self.text(named.get("path", named.get("filepath", pos[0] if pos else "")))
                val = named.get("value", pos[1] if len(pos) > 1 else piped)
                if val is not None and not isinstance(val, Unk):
                    self.sinks.write(self.to_value(val), path, resolved or name, line)
                return _Silent(None)
            if low == "test-path":
                return Unk(f"whether {self.text(named.get('path', pos[0] if pos else ''))} exists on the victim's machine")
            if low == "join-path":
                return "\\".join(self.text(x).rstrip("\\") for x in [named.get("path", pos[0] if pos else ""), named.get("childpath", pos[1] if len(pos) > 1 else "")] if x)
            if low == "split-path":
                p = self.text(named.get("path", pos[0] if pos else ""))
                return p.rsplit("\\", 1)[-1] if "leaf" in named else (p.rsplit("\\", 1)[0] if "\\" in p else "")
            if low == "get-random":
                return 4
            if low == "get-date":
                return Unk("the date on the victim's machine")
            if low in ("register-scheduledtask", "new-scheduledtaskaction", "set-mppreference", "add-mppreference",
                       "stop-process", "remove-item", "copy-item", "move-item", "invoke-item",
                       "expand-archive", "restart-computer", "stop-computer", "start-service", "stop-service"):
                txt = " ".join(self.text(a[-1]) for a in args)
                self.sinks.step(line, f"{resolved}: {txt[:200]}", Value.of(txt))
                return _Silent(None)
            if low in ("convertfrom-json",):
                import json as _json
                try:
                    return _json.loads(self.text(pos[0] if pos else piped))
                except ValueError:
                    return None
            if low == "tee-object":
                return piped
            if low == "get-member":
                return None
            # not a known command: an external program (or a name the script did not define)
            txt = " ".join(self.text(a[-1]) for a in args)
            if not resolved and re.search(r"(?i)\.(exe|com|bat|cmd|vbs|js|hta|msi|dll)$|^(mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|msiexec|schtasks|reg|wmic|curl|wget)$", base):
                self.sinks.step(line, f"runs {raw} {txt[:200]}", Value.of(txt))
                self.external(f"{raw} {txt}", line, ())
                return Unk(f"the output of {raw}")
            return Unk(f"the output of {raw}")
        finally:
            self.call_depth -= 1

    def call_function(self, low: str, args: list, piped: Any, line: int | None) -> Any:
        fname, params, body = self.functions[low]
        return self.invoke_body(fname, params, body, args, piped)

    def invoke_body(self, fname: str, params: list, body: list, args: list, piped: Any) -> Any:
        scope: dict[str, Any] = {}
        spec = [p[0] for p in params]
        named, pos = self._args(args, spec)
        pi = 0
        bound_inputs = []
        for pname, ptype, default in params:
            key = pname.lower()
            if key in named:
                v = named[key]
                v = True if v is _SWITCH else v
            elif pi < len(pos):
                v = pos[pi]
                pi += 1
            elif default is not None:
                v = self.eval(default)
            else:
                v = None
            if ptype and v is not None and not isinstance(v, Unk):
                try:
                    v = self.cast(ptype, v)
                except _Throw:
                    pass
            if isinstance(v, str) and not rec(v) and len(v) >= 16:
                v = tag(v, (f"literal (-{pname})",))
            scope[key] = v
            bound_inputs.append((pname, v))
        scope["args"] = PSList(pos[pi:])
        scope["_"] = piped
        scope["input"] = piped
        self.scopes.append(scope)
        try:
            out = self.block(body)
        except _Return as r:
            out = list(r.partial)
            self.emit(out, r.value)
        finally:
            self.scopes.pop()
        out = [x.value if isinstance(x, _Silent) else x for x in out if not (isinstance(x, _Silent) and x.value is None)]
        result = out[0] if len(out) == 1 else (PSList(out) if out else None)
        if isinstance(result, _Silent):
            result = result.value
        # the function's work as one recipe step when its own operations were not named (a XOR loop)
        if isinstance(result, (str, RBytes, bytearray, list)) and result is not None:
            ins = [(nm, v) for nm, v in bound_inputs if isinstance(v, (str, RBytes, bytearray, list)) and v is not None and len(v) >= 8]
            r = rec(result)
            if ins and (not r or r[-1] != f"{fname}()"):
                main = max(ins, key=lambda x: len(x[1]))
                others = [f"{nm} {label(v, '')}".strip() for nm, v in ins if v is not main[1]]
                stepname = f"{fname}({', '.join(o for o in others if o)})"
                if getattr(result, "inplace", ""):
                    stepname = result.inplace          # what its loop did (xor(0x5a)) says more than its name
                # the steps it named inside (base64, aes…) when they continue its input's recipe
                base = r if r[:len(rec(main[1]))] == rec(main[1]) and len(r) >= len(rec(main[1])) else (rec(main[1]) + r[-3:])
                try:
                    result = tag(result, base + (stepname,))
                except TypeError:
                    pass
        return result

    def powershell_exe(self, args: list, line: int | None) -> Any:
        words = [(a[1] if a[0] == "named" else None, a[-1]) for a in args]
        i = 0
        while i < len(words):
            flag, val = words[i]
            f = (flag or "").lower()
            if f and "encodedcommand".startswith(f) and f.startswith("e"):
                v = val if val is not _SWITCH else (words[i + 1][1] if i + 1 < len(words) else "")
                try:
                    code = T.as_text(T.b64decode(self.text(v)), "utf-16-le")
                except T.TransformError:
                    return None
                return self.run_code(tag(code, rec(v) + ("base64 (-EncodedCommand)", "utf-16")), "powershell -EncodedCommand", line)
            if f and "command".startswith(f) and f.startswith("c"):
                rest = [w[1] for w in words[i + 1:]] if val is _SWITCH else [val] + [w[1] for w in words[i + 1:]]
                code = " ".join(self.text(x) for x in rest if x is not _SWITCH)
                if rest and isinstance(rest[0], ScriptBlock):
                    return self.run_sb(rest[0], [], line=line)
                return self.run_code(code, "powershell -Command", line)
            i += 1
        return None

    def external(self, cmd: str, line: int | None, recipe: tuple[str, ...]) -> None:
        """A command line the script launches: a PowerShell in it is followed (``-enc``)."""
        m = re.search(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b(.*)", cmd)
        if m:
            tail = m.group(1)
            e = re.search(r"(?i)\s-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", tail)
            if e:
                try:
                    code = T.as_text(T.b64decode(e.group(1)), "utf-16-le")
                    self.run_code(tag(code, recipe + ("base64 (-EncodedCommand)", "utf-16")), "powershell -EncodedCommand", line)
                except T.TransformError:
                    pass
                return
            c = re.search(r"(?i)\s-c(?:ommand)?\s+(.+)$", tail)
            if c:
                code = c.group(1).strip().strip('"')
                self.run_code(tag(code, recipe), "powershell -Command", line)


def _unparse(n: Any) -> str:
    """A short readable form of an expression (how a computed command name was written)."""
    if not isinstance(n, tuple) or not n:
        return "…"
    k = n[0]
    try:
        if k == "str":
            return str(n[2]) if re.fullmatch(r"[A-Za-z][\w*?.-]*", str(n[2])) else repr(str(n[2]))
        if k == "xstr":
            return '"' + n[2] + '"'
        if k == "num":
            return str(n[2])
        if k == "var":
            return "$" + n[2]
        if k == "type":
            return f"[{n[2]}]"
        if k == "paren":
            return "(" + _unparse(n[2]) + ")"
        if k == "bin":
            return f"{_unparse(n[3])} {'-' + n[2] if n[2].isalpha() else n[2]} {_unparse(n[4])}"
        if k == "array":
            return ",".join(_unparse(x) for x in n[2])
        if k == "index":
            return f"{_unparse(n[2])}[{_unparse(n[3])}]"
        if k == "range":
            return f"{_unparse(n[2])}..{_unparse(n[3])}"
        if k == "member":
            return f"{_unparse(n[2])}{'::' if n[4] else '.'}{_unparse(n[3]) if n[3][0] != 'str' else n[3][2]}"
        if k == "call":
            return f"{_unparse(n[2])}{'::' if n[5] else '.'}{_unparse(n[3]) if n[3][0] != 'str' else n[3][2]}({', '.join(_unparse(a) for a in n[4])})"
        if k == "cast":
            return f"[{n[2]}]{_unparse(n[3])}"
        if k == "unary":
            return f"-{n[2]} {_unparse(n[3])}"
        if k == "command":
            return " ".join([_unparse(n[2]) if n[2][0] != "str" else n[2][2]]
                            + [(("-" + a[2]) if a[0] == "param" else _unparse(a)) for a in n[3]])
        if k == "subexpr":
            return "$(…)"
    except (IndexError, TypeError):
        pass
    return "…"


_IOCISH = re.compile(r"(?i)\b(?:https?|ftp|tcp)://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|biz|io|ru|cn|top|xyz|example|onion)\b")


class _Silent:
    """A command's result that is not pipeline output (Write-Host, Out-Null)."""

    def __init__(self, value: Any) -> None:
        self.value = value


_SWITCH = object()
_SWITCHES = {"force", "valueonly", "asplaintext", "usebasicparsing", "nonewwindow", "wait", "passthru", "leaf"}


def _net_regex(p: str) -> str:
    """A .NET regular expression as Python's (the usual differences)."""
    p = re.sub(r"\(\?<([A-Za-z]\w*)>", r"(?P<\1>", p)
    p = p.replace("\\k<", "(?P=").replace("(?i)", "")
    return p


def _net_repl(r: str) -> str:
    r = r.replace("\\", "\\\\")
    r = re.sub(r"\$\{(\w+)\}", r"\\g<\1>", r)
    r = re.sub(r"\$(\d+)", r"\\g<\1>", r)
    return r.replace("$$", "$")


def resolve(code: str, location: str = "powershell") -> Sinks:
    """Evaluate a PowerShell script statically; its stages, downloads, unresolved calls and trace."""
    code = code.lstrip("\ufeff")
    s = Sinks("powershell")
    it = Interp(s, code)
    try:
        it.run(code)
    except RecursionError:
        it.errors.append("recursion")
    s.errors = it.errors  # type: ignore[attr-defined]
    s.stats = {"steps": it.steps, "seconds": round(time.monotonic() - it.t0, 2)}  # type: ignore[attr-defined]
    return s
