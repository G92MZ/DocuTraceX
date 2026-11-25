"""box-js: JScript / WSH emulator on the portable Node.

box-js (MIT, CapacitorSet; provisioned like the other emulators under ``tools/boxjs/`` with the
portable Node under ``tools/node/``) runs a Windows Script Host script with
emulated ActiveX objects — WScript.Shell, Scripting.FileSystemObject,
ADODB.Stream, MSXML2.XMLHTTP, WMI… — and records what it would do: files it
writes, commands it runs, URLs it requests (never fetched: ``--download`` is not
passed), code it evals. It complements the STPyV8 sandbox, whose WSH model is
smaller.

It **runs the sample's code** (inside Node's ``vm2``), so it obeys the
``analysis.sandbox`` setting like every emulator here (``off``: it never runs),
and it runs top-level only on scripts that use WSH objects. ``vm2`` is
unmaintained and has known escapes.

``run`` returns ``{tool, events, stages, error}``: ``events`` for the Resolution
block (*Seen in the sandbox*), ``stages`` (files written, code eval'd) for
Nested with the recipe ``sandbox (box-js) → …``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .. import toolrun
from ..config import settings, tmo

TOOL = "box-js"
_TIMEOUT_S = 20                    # box-js's own --timeout (seconds of emulation)
_MAX_INPUT = 4_000_000
_MAX_STAGE = 8_000_000
_MAX_EVENTS = 60
_SCRIPT_EXT = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".bat", ".cmd", ".py", ".sct"}
_WSH = re.compile(r"ActiveXObject|WScript\b|GetObject\s*\(|Scripting\.FileSystemObject|ADODB\.Stream|"
                  r"MSXML2?\.|WinHttp|Shell\.Application", re.IGNORECASE)
_PATCHES = "/* !!!! Patches from box-js !!!! */"
_BOGUS = re.compile(r"^\s*__bogus_var_name__\s*=\s*\d+;\s*")   # box-js's prefix on eval'd code


def _node() -> Path | None:
    exe = settings.node_executable()
    if exe:
        return exe
    p = shutil.which("node")
    return Path(p) if p else None


def _runner() -> Path | None:
    d = settings.boxjs_dir()
    return d / "node_modules" / "box-js" / "run.js" if d else None


def available() -> bool:
    r = _runner()
    return _node() is not None and r is not None and r.is_file()


def status() -> dict[str, Any]:
    if _node() is None:
        return {"available": False, "detail": "portable Node not provisioned under tools/node/"}
    if not available():
        return {"available": False, "detail": "box-js not installed under tools/boxjs/"}
    return {"available": True, "detail": f"box-js ready on {_node()}"}


def worth(code: str) -> bool:
    """A Windows Script Host script: what box-js emulates (a page's own JS is left to V8)."""
    return bool(code) and bool(_WSH.search(code[:2_000_000]))


def _ext_of(path: str) -> str:
    """The stage's extension when the target names a script (else "": sniffed by its content)."""
    m = re.search(r"(\.[A-Za-z0-9]{1,4})\s*$", path or "")
    ext = m.group(1).lower() if m else ""
    return ext if ext in _SCRIPT_EXT else ""


def _file_shim(bindir: Path) -> None:
    """box-js runs the Unix ``file`` command on every file the script writes; on Windows there is
    none and the write would fail inside the emulation. A stub answers "data"."""
    if sys.platform.startswith("win"):
        (bindir / "file.cmd").write_text("@echo %~1: data\r\n", encoding="ascii")


def raw_of(data: bytes | str) -> bytes:
    """The bytes of a stage (box-js writes strings as "binary", one byte per char)."""
    if isinstance(data, bytes):
        return data
    try:
        return data.encode("latin-1")
    except UnicodeEncodeError:
        return data.encode("utf-8")


def as_stage(recipe: list[str], data: bytes | str, ext: str, seen: set[str]) -> list[dict[str, Any]]:
    """A Nested stage: text when it is text, ``data_b64`` when it is a file (PE, archive…) or binary;
    the same bytes only once."""
    from ..resolve import transforms

    raw = raw_of(data)[:_MAX_STAGE]
    if not raw.strip():
        return []
    sha = hashlib.sha256(raw).hexdigest()
    if sha in seen:
        return []
    seen.add(sha)
    if transforms.magic(raw) is None and transforms.is_text(raw):
        text = data if isinstance(data, str) else transforms.as_text(
            raw, "utf-16-le" if raw[1:2] == b"\x00" else "utf-8")
        return [{"recipe": recipe, "text": text[:_MAX_STAGE], "ext": ext, "sink": TOOL}]
    return [{"recipe": recipe, "data_b64": base64.b64encode(raw).decode(), "ext": ext, "sink": TOOL}]


def parse(results: Path) -> dict[str, Any]:
    """Read box-js's results folder (``IOC.json``, ``urls.json``, its snippet / resource files)."""
    out: dict[str, Any] = {"tool": TOOL, "events": [], "stages": [], "error": None}

    def load(name: str) -> Any:
        try:
            return json.loads((results / name).read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            return None

    by_sha: dict[str, Path] = {}
    for f in results.iterdir() if results.is_dir() else []:
        if f.is_file() and not f.name.endswith(".json") and f.name != "analysis.log":
            try:
                if f.stat().st_size <= _MAX_STAGE:
                    by_sha[hashlib.sha256(f.read_bytes()).hexdigest()] = f
            except OSError:
                pass

    ev, stages, seen = out["events"], out["stages"], set()

    def stage(recipe: list[str], data: bytes | str, ext: str) -> None:
        stages.extend(as_stage(recipe, data, ext, seen))

    def norm(path: Any) -> str:
        return re.sub(r"\\{2,}", r"\\", str(path or ""))

    for ioc in load("IOC.json") or []:
        if not isinstance(ioc, dict):
            continue
        t, v = ioc.get("type") or "", ioc.get("value")
        v = dict(v) if isinstance(v, dict) else {"value": v}
        for k in ("file", "path"):
            if k in v:
                v[k] = norm(v[k])
        if t == "FileWrite":
            ev.append({"kind": "writes", "what": t, "detail": str(v.get("file", ""))[:300],
                       "size": len(str(v.get("contents") or ""))})
            c = v.get("contents")
            if isinstance(c, str) and c.strip():
                stage(["sandbox (box-js)", f"writes {v.get('file', '')}"], c, _ext_of(str(v.get("file", ""))))
        elif t == "NewResource":
            f = by_sha.get(str(v.get("sha256", "")))
            path = str(v.get("path", ""))
            if not any(e["kind"] == "writes" and e["detail"] == path[:300] for e in ev):
                ev.append({"kind": "writes", "what": "resource", "detail": path[:300]})
            if f is not None:
                stage(["sandbox (box-js)", f"writes {path}"], f.read_bytes(), _ext_of(path))
        elif t in ("Run", "CommandExec", "WMI.GetObject.Run", "WMI.GetObject.Create", "WMI.GetObject.ShellExecute",
                   "Task", "Task Arguments"):
            ev.append({"kind": "command", "what": t, "detail": norm(v.get("command") or next(iter(v.values()), ""))[:300]})
        elif t in ("UrlFetch", "XMLHTTP", "WMI.GetObject.send"):
            ev.append({"kind": "network", "what": t, "detail": str(v.get("url") or next(iter(v.values()), ""))[:300]})
        elif t == "DynamicCode":
            ev.append({"kind": "runs code", "what": t, "detail": json.dumps(v)[:300]})
        elif t in ("RegWrite", "RegDelete", "CreateShortcut", "FileCopy", "FileMove", "FileDelete", "FolderCreate",
                   "WMI.GetObject.SaveToFile", "Word.Application", "InternetExplorer.Application"):
            ev.append({"kind": "behaviour", "what": t, "detail": json.dumps(v, ensure_ascii=False)[:300]})

    # one row per URL / command (box-js reports an XMLHTTP open and its fetch apart)
    dedup, rows = set(), []
    for e in ev:
        key = (e["kind"], e["detail"]) if e["kind"] in ("network", "command") else None
        if key is None or key not in dedup:
            rows.append(e)
            if key:
                dedup.add(key)
    ev[:] = rows
    known = {e["detail"] for e in ev if e["kind"] == "network"}
    for u in load("urls.json") or []:
        if isinstance(u, str) and u not in known:
            ev.append({"kind": "network", "what": "URL", "detail": u[:300]})
            known.add(u)

    # code the script eval'd / built a Function from (box-js keeps each as <uuid>.js; the first one
    # is its own rewritten copy of the sample, with its patches in front)
    for f in sorted(results.glob("*.js"), key=lambda p: p.stat().st_mtime if p.exists() else 0):
        try:
            code = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        code = _BOGUS.sub("", code, count=1)
        if code.lstrip().startswith(_PATCHES) or len(code.strip()) < 16:
            continue
        ev.append({"kind": "runs code", "what": "eval", "detail": code[:300], "size": len(code)})
        stage(["sandbox (box-js)", "eval"], code, ".js")

    out["events"] = ev[:_MAX_EVENTS]
    return out


def run(code: str, name: str = "sample.js") -> dict[str, Any]:
    """Emulate ``code`` in box-js and read what it saw. Never raises; ``error`` says why nothing ran."""
    if not available():
        return {"tool": TOOL, "events": [], "stages": [], "error": "box-js not provisioned"}
    node, runner = _node(), _runner()
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(name).name)[:60] or "sample.js"
    if not safe.lower().endswith((".js", ".jse", ".wsf")):
        safe += ".js"
    with tempfile.TemporaryDirectory(prefix="dtx_boxjs_") as td:
        tdp = Path(td)
        src, outdir, bindir = tdp / safe, tdp / "out", tdp / "bin"
        outdir.mkdir()
        bindir.mkdir()
        try:
            src.write_text(code[:_MAX_INPUT], encoding="utf-8")
        except OSError as exc:
            return {"tool": TOOL, "events": [], "stages": [], "error": str(exc)}
        _file_shim(bindir)
        rec = toolrun.run(
            [str(node), str(runner), str(src), f"--output-dir={outdir}", "--no-shell-error", "--no-kill",
             f"--timeout={_TIMEOUT_S}", "--loglevel=warning", "--no-echo"],
            "box-js (WSH emulation)", timeout=tmo(_TIMEOUT_S + 40), cwd=tdp,
            extra_env={"PATH": str(bindir) + os.pathsep + toolrun.env().get("PATH", "")},
        )
        res = next(iter(sorted(outdir.glob("*.results"))), None)
        out = parse(res) if res else {"tool": TOOL, "events": [], "stages": [], "error": None}
    if rec.get("timed_out"):
        out["error"] = "timed out"
    elif not out["events"] and rec.get("returncode") not in (0, None):
        out["error"] = (rec.get("stderr") or rec.get("output") or rec.get("error") or "box-js failed").strip()[-300:]
    return out
