"""JavaScript deobfuscation sandbox (STPyV8), run as a separate process.

Runs a script inside a bare V8 isolate — no file system, no network, no
processes: the only host objects are *recorders* we provide. It answers "what
does this obfuscated script end up doing?" by:

- hooking ``eval``, ``Function``, ``setTimeout``/``setInterval`` with strings,
  ``String.fromCharCode`` (resolved strings) and the clock (``Date.now``,
  ``getTime``, ``performance.now``: anti-sandbox time-delta checks),
  ``document.write``/``writeln``: each unwrapped layer of code is recorded and
  then executed inside the sandbox, so multi-layer packers unfold;
- stubbing the hosts maldoc scripts expect — Windows Script Host
  (``WScript``, ``ActiveXObject``, ``GetObject``), the browser (``window``,
  ``document``, ``location``, ``navigator``, ``atob``) and Acrobat (``app``,
  ``util``, ``this.exportDataObject``, ``submitForm``...) — with objects that
  only log the calls (``WScript.Shell.Run("powershell ...")``, URLs opened...).

    python -m docutracex.js_sandbox < script.js     -> JSON on stdout

Each recorded event is printed as one JSON line as soon as it happens, so the
caller (which enforces a hard time limit) keeps the log even when it has to
kill a script stuck in an endless loop. ``parse_output`` rebuilds the result.
"""

from __future__ import annotations

import base64
import json
import sys

MAX_LOG = 400
MAX_TEXT = 20000
MAX_DROP = 16 * 1024 * 1024

_log: list[dict] = []
_CLOCK = [0.0]        # ms added by WScript.Sleep (virtual time, see Recorder)


def _js_str(v) -> str:
    """Readable form of a JS value passed to a host stub (objects -> key=value)."""
    try:
        if hasattr(v, "keys") and not isinstance(v, str):
            return "{" + ", ".join(f"{k}: {v[k]}" for k in v.keys()) + "}"
    except Exception:  # noqa: BLE001
        pass
    return str(v)


def _rec(kind: str, name: str, args: list) -> None:
    """Record one event and stream it at once (one JSON line), so the caller
    keeps everything recorded even if it has to kill an endless script.
    Files the script writes ("drop") keep their whole content (up to
    MAX_DROP): they are the next stage, analysed as nested children."""
    if len(_log) < MAX_LOG or kind == "drop":
        cap = MAX_DROP if kind == "drop" else MAX_TEXT
        item = {"kind": kind, "name": name, "args": [_js_str(a)[:cap] for a in args]}
        _log.append(item)
        print(json.dumps({"event": item}), flush=True)


class Recorder:
    """Any attribute is a callable that logs the call and returns a new Recorder."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attr: str):
        if attr.startswith("__"):
            raise AttributeError(attr)
        if attr in ("toString", "valueOf", "toJSON"):
            # string coercion (``fso.GetSpecialFolder(2) + "\\x.vbs"``) must
            # yield a primitive, or V8 throws and the script stops there
            return lambda *a: str(self)
        name = f"{self._name}.{attr}"

        def call(*args):
            _rec("call", name, list(args))
            return Recorder(name + "()")
        return call

    def __str__(self) -> str:  # used when scripts concatenate objects
        return f"[{self._name}]"


# --- Windows Script Host emulation ------------------------------------------
# Realistic enough for droppers to carry on: string properties where scripts
# expect strings (ScriptFullName, expanded %TEMP%…), a FileSystemObject that
# returns the script's OWN source when it reads itself (payloads hidden in the
# dropper) and records every file it writes WITH its content ("drop" events,
# which become nested children), ADODB.Stream, XMLHTTP. Nothing touches disk.

SELF_PATH = "C:\\Users\\user\\Downloads\\invoice.js"   # where the emulated script "lives" (not an IOC)
_SELF = {"path": SELF_PATH, "code": ""}
_ENV = {"temp": "C:\\Users\\user\\AppData\\Local\\Temp", "tmp": "C:\\Users\\user\\AppData\\Local\\Temp",
        "appdata": "C:\\Users\\user\\AppData\\Roaming", "localappdata": "C:\\Users\\user\\AppData\\Local",
        "userprofile": "C:\\Users\\user", "username": "user", "computername": "DESKTOP-7F3K2Q",
        "public": "C:\\Users\\Public", "programdata": "C:\\ProgramData", "windir": "C:\\Windows",
        "systemroot": "C:\\Windows", "systemdrive": "C:", "homedrive": "C:", "homepath": "\\Users\\user",
        "userdomain": "WORKGROUP", "os": "Windows_NT", "processor_architecture": "AMD64",
        "comspec": "C:\\Windows\\System32\\cmd.exe"}
_SPECIAL = {0: "C:\\Windows", 1: "C:\\Windows\\System32", 2: _ENV["temp"]}
_FILES: dict[str, str] = {}          # files written during the run (lower-case path -> text)


def _expand(s) -> str:
    import re as _re
    return _re.sub(r"%([^%]+)%", lambda m: _ENV.get(m.group(1).lower(), m.group(0)), str(s))


def _drop(path, content) -> None:
    path, content = str(path), str(content)
    _FILES[path.lower()] = content
    _rec("drop", path, [content])


def _read(path) -> str:
    p = str(path).lower()
    if p == _SELF["path"].lower() or p.endswith("\\" + _SELF["path"].rsplit("\\", 1)[-1].lower()):
        return _SELF["code"]
    return _FILES.get(p, "")


class _TextStream:
    def __init__(self, path, writing: bool) -> None:
        self._path, self._w, self._buf = str(path), writing, []
        self._data, self._pos = ("" if writing else _read(path)), 0
        self.AtEndOfStream = not self._data
        self.Line = 1

    def Write(self, s):  # noqa: N802
        self._buf.append(str(s))

    def WriteLine(self, s=""):  # noqa: N802
        self._buf.append(str(s) + "\r\n")

    def WriteBlankLines(self, n=1):  # noqa: N802
        self._buf.append("\r\n" * int(n))

    def ReadAll(self):  # noqa: N802
        out, self._pos = self._data[self._pos:], len(self._data)
        self.AtEndOfStream = True
        return out

    def ReadLine(self):  # noqa: N802
        end = self._data.find("\n", self._pos)
        end = len(self._data) if end < 0 else end + 1
        out, self._pos = self._data[self._pos:end].rstrip("\r\n"), end
        self.AtEndOfStream = self._pos >= len(self._data)
        self.Line += 1
        return out

    def Read(self, n):  # noqa: N802
        out = self._data[self._pos:self._pos + int(n)]
        self._pos += len(out)
        self.AtEndOfStream = self._pos >= len(self._data)
        return out

    def Skip(self, n):  # noqa: N802
        self._pos += int(n)

    def SkipLine(self):  # noqa: N802
        self.ReadLine()

    def Close(self):  # noqa: N802
        if self._w and self._buf:
            _drop(self._path, "".join(self._buf))
            self._buf = []


class _File:
    def __init__(self, path) -> None:
        self.Path = str(path)
        self.Name = self.Path.rsplit("\\", 1)[-1]
        self.ParentFolder = self.Path.rsplit("\\", 1)[0] if "\\" in self.Path else ""
        self.Size = len(_read(path))
        self.Attributes = 32
        self.ShortPath = self.Path

    def OpenAsTextStream(self, mode=1, *a):  # noqa: N802
        return _TextStream(self.Path, int(mode) in (2, 8))

    def Delete(self, *a):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.DeleteFile", [self.Path])

    def Copy(self, dest, *a):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.CopyFile", [self.Path, dest])

    def Move(self, dest):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.MoveFile", [self.Path, dest])

    def __str__(self) -> str:
        return self.Path


class _FSO(Recorder):
    def __init__(self) -> None:
        super().__init__("Scripting.FileSystemObject")

    def FileExists(self, p):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.FileExists", [p])
        return str(p).lower() in _FILES or bool(_read(p))

    def FolderExists(self, p):  # noqa: N802
        return True

    def DriveExists(self, p):  # noqa: N802
        return True

    def GetSpecialFolder(self, n):  # noqa: N802
        return _SPECIAL.get(int(n) if str(n).isdigit() else 2, _ENV["temp"])

    def GetTempName(self):  # noqa: N802
        return "rad7A3F1.tmp"

    def BuildPath(self, a, b):  # noqa: N802
        return str(a).rstrip("\\") + "\\" + str(b)

    def GetFileName(self, p):  # noqa: N802
        return str(p).rsplit("\\", 1)[-1]

    def GetBaseName(self, p):  # noqa: N802
        return str(p).rsplit("\\", 1)[-1].rsplit(".", 1)[0]

    def GetExtensionName(self, p):  # noqa: N802
        n = str(p).rsplit("\\", 1)[-1]
        return n.rsplit(".", 1)[-1] if "." in n else ""

    def GetParentFolderName(self, p):  # noqa: N802
        return str(p).rsplit("\\", 1)[0] if "\\" in str(p) else ""

    def GetAbsolutePathName(self, p):  # noqa: N802
        return str(p)

    def GetFile(self, p):  # noqa: N802
        return _File(p)

    def OpenTextFile(self, p, mode=1, create=False, *a):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.OpenTextFile", [p, mode])
        return _TextStream(p, int(mode) in (2, 8))

    def CreateTextFile(self, p, *a):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.CreateTextFile", [p])
        return _TextStream(p, True)

    def CreateFolder(self, p):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.CreateFolder", [p])
        return str(p)

    def CopyFile(self, a, b, *x):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.CopyFile", [a, b])
        if _read(a):
            _drop(b, _read(a))

    def MoveFile(self, a, b):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.MoveFile", [a, b])

    def DeleteFile(self, p, *x):  # noqa: N802
        _rec("call", "Scripting.FileSystemObject.DeleteFile", [p])


class _Shell(Recorder):
    def __init__(self) -> None:
        super().__init__("WScript.Shell")
        self.CurrentDirectory = _SELF["path"].rsplit("\\", 1)[0]

    def ExpandEnvironmentStrings(self, s):  # noqa: N802
        _rec("call", "WScript.Shell.ExpandEnvironmentStrings", [s])
        return _expand(s)

    def SpecialFolders(self, name):  # noqa: N802
        n = str(name).lower()
        return {"desktop": "C:\\Users\\user\\Desktop", "startup":
                "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                "appdata": _ENV["appdata"], "mydocuments": "C:\\Users\\user\\Documents"}.get(n, _ENV["userprofile"])

    def Environment(self, *a):  # noqa: N802
        class _Env:
            def Item(self, k):  # noqa: N802
                return _ENV.get(str(k).lower(), "")
        return _Env()

    def RegRead(self, k):  # noqa: N802
        _rec("call", "WScript.Shell.RegRead", [k])
        return ""


class _Stream(Recorder):
    """ADODB.Stream: text written then saved to a file -> a drop."""
    def __init__(self) -> None:
        super().__init__("ADODB.Stream")
        self.Type, self.Charset, self.Position, self.Size = 1, "", 0, 0
        self._buf: list[str] = []

    def WriteText(self, s, *a):  # noqa: N802
        self._buf.append(str(s))

    def Write(self, s):  # noqa: N802
        self._buf.append(str(s))

    def LoadFromFile(self, p):  # noqa: N802
        self._buf = [_read(p)]

    def ReadText(self, *a):  # noqa: N802
        return "".join(self._buf)

    def Read(self, *a):  # noqa: N802
        return "".join(self._buf)

    def SaveToFile(self, p, *a):  # noqa: N802
        _rec("call", "ADODB.Stream.SaveToFile", [p])
        _drop(p, "".join(self._buf))


class _Quit(Exception):
    """WScript.Quit: ends the script (surfaces as a JS exception, logged)."""


def _create(progid):
    pid = str(progid).strip().lower()
    if pid == "scripting.filesystemobject":
        return _FSO()
    if pid in ("wscript.shell", "wscript.shell.1"):
        return _Shell()
    if pid == "adodb.stream":
        return _Stream()
    return Recorder(str(progid))


class _WScript(Recorder):
    def __init__(self) -> None:
        super().__init__("WScript")
        self.ScriptFullName = _SELF["path"]
        self.ScriptName = _SELF["path"].rsplit("\\", 1)[-1]
        self.Path = "C:\\Windows\\System32"
        self.FullName = "C:\\Windows\\System32\\wscript.exe"
        self.Name = "Windows Script Host"
        self.Version = "5.812"
        self.Interactive = True

    def CreateObject(self, progid, *a):  # noqa: N802
        _rec("activex", "WScript.CreateObject", [progid])
        return _create(progid)

    def GetObject(self, *a):  # noqa: N802
        _rec("activex", "WScript.GetObject", list(a))
        return Recorder("GetObject")

    def Sleep(self, ms=0):  # noqa: N802
        # Anti-sandbox defeat: returns at once but advances the virtual clock
        # that Date/performance read, so before/after-Sleep checks see the time.
        _rec("call", "WScript.Sleep", [ms])
        try:
            _CLOCK[0] += max(0.0, float(ms))
        except (TypeError, ValueError):
            pass

    def Echo(self, *a):  # noqa: N802
        _rec("call", "WScript.Echo", list(a))

    def Quit(self, *a):  # noqa: N802
        _rec("call", "WScript.Quit", list(a))
        raise _Quit("WScript.Quit")


try:
    import STPyV8
    _Base = STPyV8.JSClass
except Exception:  # noqa: BLE001
    STPyV8 = None
    # tag: gmzpt
    _Base = object


class Host(_Base):
    """Global object: explicit stubs only (no catch-all, so builtins keep working)."""

    def __init__(self) -> None:
        super().__init__()
        self.WScript = _WScript()
        self.app = Recorder("app")
        self.util = Recorder("util")
        self.navigator = Recorder("navigator")
        self.console = Recorder("console")
        self.event = Recorder("event")

    def ActiveXObject(self, progid):  # noqa: N802 (JS API name)
        _rec("activex", "new ActiveXObject", [progid])
        return _create(progid)

    def GetObject(self, name, *a):  # noqa: N802
        _rec("activex", "GetObject", [name, *a])
        return Recorder(f"GetObject({name})")

    def __rec(self, kind, name, *args):
        _rec(kind, name, list(args))

    def _dtx_log(self, kind, name, value):
        _rec(str(kind), str(name), [value])

    def _dtx_clock(self):
        return _CLOCK[0]

    def atob(self, s):
        try:
            return base64.b64decode(str(s) + "===").decode("latin-1")
        except Exception:  # noqa: BLE001
            return ""

    def btoa(self, s):
        return base64.b64encode(str(s).encode("latin-1", "replace")).decode()

    # Acrobat document methods reachable through `this` at top level.
    def exportDataObject(self, *a):  # noqa: N802
        _rec("call", "this.exportDataObject", list(a))

    def submitForm(self, *a):  # noqa: N802
        _rec("call", "this.submitForm", list(a))

    def getURL(self, *a):  # noqa: N802
        _rec("url", "this.getURL", list(a))

    def launchURL(self, *a):  # noqa: N802
        _rec("url", "launchURL", list(a))


# Hooks installed in JS before the sample runs.
PRELUDE = r"""
(function(g){
  var _eval = g.eval, _Function = g.Function;
  g.eval = function(c){ _dtx_log('layer', 'eval', String(c)); return _eval(c); };
  g.Function = function(){ var a = Array.prototype.slice.call(arguments);
    _dtx_log('layer', 'Function', String(a[a.length - 1])); return _Function.apply(this, a); };
  g.setTimeout = function(f){ if (typeof f === 'string') { _dtx_log('layer', 'setTimeout', f); _eval(f); }
    else if (typeof f === 'function') { try { f(); } catch (e) {} } return 1; };
  g.setInterval = g.setTimeout;
  var el = function(tag){ var o = {tagName: tag, style: {}, children: [], attrs: {},
      setAttribute: function(k, v){ this.attrs[k] = v; _dtx_log('dom', 'setAttribute', k + '=' + v); },
      appendChild: function(c){ this.children.push(c); return c; },
      addEventListener: function(t){ _dtx_log('dom', 'addEventListener', tag + ':' + t); },
      click: function(){ _dtx_log('dom', 'click', (this.href || '') + ' download=' + (this.download || '')); },
      submit: function(){ _dtx_log('dom', 'form.submit', this.action || ''); } };
    return o; };
  var body = el('body');
  g.document = { body: body, documentElement: el('html'), cookie: '', referrer: '', title: '',
    write: function(s){ _dtx_log('layer', 'document.write', String(s)); },
    writeln: function(s){ _dtx_log('layer', 'document.writeln', String(s)); },
    createElement: function(t){ return el(String(t)); },
    getElementById: function(i){ return el('div'); },
    getElementsByTagName: function(t){ return [el(t)]; },
    querySelector: function(){ return el('div'); }, querySelectorAll: function(){ return []; },
    addEventListener: function(){}, location: null };
  var loc = { _h: '', toString: function(){ return this._h; },
    replace: function(u){ _dtx_log('url', 'location.replace', String(u)); },
    assign: function(u){ _dtx_log('url', 'location.assign', String(u)); } };
  Object.defineProperty(loc, 'href', { get: function(){ return this._h; },
    set: function(u){ this._h = u; _dtx_log('url', 'location.href', String(u)); } });
  g.location = loc; g.document.location = loc;
  g.window = g; g.self = g; g.top = g; g.parent = g;
  g.open = function(u){ _dtx_log('url', 'window.open', String(u)); return null; };
  g.fetch = function(u, o){ _dtx_log('url', 'fetch', String(u)); return { then: function(){ return this; } }; };
  g.XMLHttpRequest = function(){ return { open: function(m, u){ _dtx_log('url', 'XMLHttpRequest.open', m + ' ' + u); },
    send: function(d){ _dtx_log('call', 'XMLHttpRequest.send', String(d || '')); }, setRequestHeader: function(){} }; };
  g.FormData = function(){ return { get: function(){ return ''; }, append: function(){} }; };
  g.Blob = function(parts, opts){ _dtx_log('dom', 'new Blob', (opts && opts.type) || ''); this.size = 0; };
  g.URL = { createObjectURL: function(){ _dtx_log('dom', 'URL.createObjectURL', 'blob'); return 'blob:sandbox'; } };
  g.navigator.msSaveOrOpenBlob = function(b, n){ _dtx_log('dom', 'msSaveOrOpenBlob', String(n)); };
  // Strings built with fromCharCode (only meaningful ones, capped so a
  // char-by-char loop cannot flood the log).
  var _fcc = String.fromCharCode, _nf = 0;
  String.fromCharCode = function(){ var r = _fcc.apply(String, arguments);
    if (r.length >= 4 && _nf < 40) { _nf++; _dtx_log('fromcharcode', 'String.fromCharCode', r); } return r; };
  // Clock reads (anti-sandbox time-delta checks), capped.
  var _nt = 0, _tl = function(n){ if (_nt < 8) { _nt++; _dtx_log('timing', n, ''); } };
  // Virtual time: WScript.Sleep(ms) advances _dtx_clock() instead of waiting.
  var _now = Date.now, _gt = Date.prototype.getTime, _vo = Date.prototype.valueOf;
  var _t0 = _now(), _p0 = _t0;
  Date.now = function(){ _tl('Date.now'); return _now() + _dtx_clock(); };
  Date.prototype.getTime = function(){ _tl('Date.getTime'); return _gt.call(this) + _dtx_clock(); };
  Date.prototype.valueOf = function(){ return _vo.call(this) + _dtx_clock(); };
  g.performance = { now: function(){ _tl('performance.now'); return _now() - _p0 + _dtx_clock(); } };
})(this);
"""


def run(code: str) -> dict:
    out: dict = {"available": STPyV8 is not None, "error": None}
    _SELF["code"] = code
    if STPyV8 is None:
        out["error"] = "STPyV8 not installed"
        return out
    try:
        with STPyV8.JSContext(Host()) as ctx:
            ctx.eval(PRELUDE)
            try:
                ctx.eval(code)
            except Exception as exc:  # noqa: BLE001  (script errors are expected)
                out["error"] = str(exc)[:500] or exc.__class__.__name__
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"sandbox failure: {exc}"[:500]
    return out


def main() -> int:
    code = sys.stdin.buffer.read().decode("utf-8", "replace")
    print(json.dumps({"done": run(code)}), flush=True)
    return 0


def parse_output(text: str, timed_out: bool = False) -> dict:
    """Rebuild {log, error, timed_out, available} from the streamed lines."""
    res: dict = {"log": [], "error": None, "timed_out": timed_out, "available": True}
    for line in (text or "").splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if "event" in obj:
            res["log"].append(obj["event"])
        # rev: gmzpt
        elif "done" in obj:
            res["error"] = obj["done"].get("error")
            res["available"] = obj["done"].get("available", True)
    if timed_out:
        res["error"] = "stopped by the time limit (endless loop / heavy computation); partial log kept"
    return res


if __name__ == "__main__":
    raise SystemExit(main())
