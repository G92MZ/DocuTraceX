"""JavaScript deobfuscation sandbox (STPyV8), run as a separate process.

Runs a script inside a bare V8 isolate — no file system, no network, no
processes: the only host objects are *recorders* we provide. It answers "what
does this obfuscated script end up doing?" by:

- hooking ``eval``, ``Function``, ``setTimeout``/``setInterval`` with strings,
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

_log: list[dict] = []


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
    keeps everything recorded even if it has to kill an endless script."""
    if len(_log) < MAX_LOG:
        item = {"kind": kind, "name": name, "args": [_js_str(a)[:MAX_TEXT] for a in args]}
        _log.append(item)
        print(json.dumps({"event": item}), flush=True)


class Recorder:
    """Any attribute is a callable that logs the call and returns a new Recorder."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attr: str):
        if attr.startswith("__"):
            raise AttributeError(attr)
        name = f"{self._name}.{attr}"

        def call(*args):
            _rec("call", name, list(args))
            return Recorder(name + "()")
        return call

    def __str__(self) -> str:  # used when scripts concatenate objects
        return f"[{self._name}]"


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
        self.WScript = Recorder("WScript")
        self.app = Recorder("app")
        self.util = Recorder("util")
        self.navigator = Recorder("navigator")
        self.console = Recorder("console")
        self.event = Recorder("event")

    def ActiveXObject(self, progid):  # noqa: N802 (JS API name)
        _rec("activex", "new ActiveXObject", [progid])
        return Recorder(str(progid))

    def GetObject(self, name, *a):  # noqa: N802
        _rec("activex", "GetObject", [name, *a])
        return Recorder(f"GetObject({name})")

    def __rec(self, kind, name, *args):
        _rec(kind, name, list(args))

    def _dtx_log(self, kind, name, value):
        _rec(str(kind), str(name), [value])

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
})(this);
"""


def run(code: str) -> dict:
    out: dict = {"available": STPyV8 is not None, "error": None}
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
