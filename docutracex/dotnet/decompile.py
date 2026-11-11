""".NET decompilation on demand: ILSpy CLI (``ilspycmd``, MIT) on a portable
.NET runtime, with de4dot-cex (GPL-3) as an optional clean-up step first.

Static only. Both tools are separate programs under ``tools/`` (provisioned by
``scripts/setup_portable_python.py --component ilspy`` / ``de4dot``), run in a
separate process with a timeout and a memory limit, and only when the analyst
presses *Decompile*:

- **ILSpy** reads the assembly and prints C#; it never runs it. Only the
  prioritised methods (network, crypto, ``Process.Start``, ``Assembly.Load``,
  registry…) are decompiled: their declaring type is decompiled and the method
  is cut out of it.
- **de4dot** runs only when an obfuscator was detected, and only as
  ``-p un --strtyp none``: the generic deobfuscator (renaming + control-flow
  clean-up). ``--strtyp none`` means it never decrypts strings, so it never
  invokes (``delegate``) or emulates (``emulate``) the sample's methods.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

TIMEOUT = 120                     # seconds per tool run
MEMORY_MB = 1024                  # per tool run
MAX_MODULE = 15                   # prioritised methods per "Decompile module"
MAX_CODE = 60_000                 # characters kept per method
PRIORITY = {"network", "exfiltration", "crypto", "execution", "loader", "persistence", "injection"}
# the only de4dot mode DocuTraceX uses; --preserve-tokens keeps each method's
# MethodDef row, so a renamed method is still found by its row.
DE4DOT_ARGS = ["-p", "un", "--strtyp", "none", "--preserve-tokens"]

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _tools() -> Path:
    from ..config import settings
    return Path(settings.tools_dir)


def dotnet_executable() -> Path | None:
    env = os.environ.get("DOCUTRACEX_DOTNET")
    if env and Path(env).is_file():
        return Path(env)
    for c in (_tools() / "dotnet" / "dotnet.exe", _tools() / "dotnet" / "dotnet"):
        if c.is_file():
            return c
    return None


def ilspy_dll() -> Path | None:
    env = os.environ.get("DOCUTRACEX_ILSPYCMD")
    if env and Path(env).is_file():
        return Path(env)
    base = _tools() / "ilspy"
    found = sorted(base.glob("tools/net*/any/ilspycmd.dll")) if base.is_dir() else []
    return found[-1] if found else None


def de4dot_command() -> list[str] | None:
    env = os.environ.get("DOCUTRACEX_DE4DOT")
    exe = Path(env) if env and Path(env).is_file() else None
    if exe is None:
        base = _tools() / "de4dot"
        found = sorted(base.rglob("de4dot*.exe"), key=lambda p: ("x64" not in p.name, "net4" not in str(p),
                                                                  len(str(p)))) if base.is_dir() else []
        exe = found[0] if found else None
    if exe is None:
        return None
    if sys.platform.startswith("win"):
        return [str(exe)]
    mono = shutil.which("mono")
    return [mono, str(exe)] if mono else None


def ilspy_available() -> bool:
    return dotnet_executable() is not None and ilspy_dll() is not None


def de4dot_available() -> bool:
    return de4dot_command() is not None


def status() -> dict[str, Any]:
    return {"ilspy": ilspy_available(), "de4dot": de4dot_available(),
            "de4dot_mode": " ".join(DE4DOT_ARGS)}


# --- running a tool in its own process ----------------------------------------

def _job_limit(proc: subprocess.Popen, mb: int) -> Any:
    """Windows: put the process in a Job Object with a memory cap (killed with
    the job). Returns the job handle to keep alive, or None."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class _Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class _Io(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rt", "wt", "ot")]

        class _Ext(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", _Basic), ("IoInfo", _Io),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        k32 = ctypes.windll.kernel32
        job = k32.CreateJobObjectW(None, None)
        info = _Ext()
        info.BasicLimitInformation.LimitFlags = 0x100 | 0x2000   # PROCESS_MEMORY | KILL_ON_JOB_CLOSE
        info.ProcessMemoryLimit = mb * 1024 * 1024
        k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
        k32.AssignProcessToJobObject(job, wintypes.HANDLE(proc._handle))  # type: ignore[attr-defined]
        return job
    except Exception:  # noqa: BLE001
        return None


def _run(cmd: list[str], cwd: Path, timeout: int = TIMEOUT) -> tuple[int, str, str]:
    """One tool run: own process, no shell, timeout, memory cap (Job Object on
    Windows; ``DOTNET_GCHeapHardLimit`` for the .NET runtime; RLIMIT_CPU on
    POSIX), no telemetry or update checks."""
    env = dict(os.environ)
    env.update(DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1", DOTNET_gcServer="0",
               DOTNET_GCHeapHardLimit=hex(MEMORY_MB * 1024 * 1024))
    kw: dict[str, Any] = {}
    if not sys.platform.startswith("win"):
        def _limits() -> None:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 5))
        kw["preexec_fn"] = _limits
    else:
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, **kw)
    job = _job_limit(proc, MEMORY_MB)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise TimeoutError(f"{Path(cmd[-1]).name if cmd else 'tool'}: no result after {timeout} s") from None
    finally:
        if job:
            try:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(job)
            except Exception:  # noqa: BLE001
                pass
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


# --- C# slicing ---------------------------------------------------------------

def split_method(owner: str) -> tuple[str, str]:
    """``Ns.Type::Method`` → (``Ns.Type``, ``Method``)."""
    t, _, m = owner.partition("::")
    return t, m


def cut_method(source: str, type_name: str, method: str) -> str | None:
    """The declaration of ``method`` (with its body) in the C# of its type.
    Constructors are looked up by the type's short name. Overloads: all of them."""
    short = type_name.rsplit(".", 1)[-1].rsplit("/", 1)[-1]
    name = short if method in (".ctor", ".cctor") else method
    if not name:
        return None
    pat = re.compile(r"^[ \t]*(?:\[[^\]\n]*\][ \t]*\n[ \t]*)*(?:[\w<>\[\],.? \t]+[ \t])?"
                     + re.escape(name) + r"[ \t]*(?:<[^>\n]*>)?[ \t]*\([^;{}]*\)[^;{}]*\{", re.M)
    pieces: list[str] = []
    for m in pat.finditer(source):
        head = source[m.start():m.end()]
        if method == ".cctor" and "static" not in head or method == ".ctor" and "static " in head:
            continue
        depth, i = 0, m.end() - 1
        while i < len(source):
            ch = source[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            elif ch == '"':                        # skip string literals (braces inside)
                i += 1
                while i < len(source) and source[i] != '"':
                    i += 2 if source[i] == "\\" else 1
            i += 1
        pieces.append(_dedent(source[m.start():i + 1]))
    return "\n\n".join(pieces) if pieces else None


def _dedent(code: str) -> str:
    lines = code.splitlines()
    pad = min((len(x) - len(x.lstrip()) for x in lines if x.strip()), default=0)
    return "\n".join(x[pad:] for x in lines)


# --- the case side --------------------------------------------------------------

def _store(case_root: Path) -> Path:
    d = case_root / "dotnet_decompiled"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load(case_root: Path, sha256: str) -> dict[str, Any]:
    try:
        return json.loads((case_root / "dotnet_decompiled" / f"{sha256}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"methods": {}}


def _save(case_root: Path, sha256: str, data: dict[str, Any]) -> None:
    (_store(case_root) / f"{sha256}.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def priority_methods(obj: dict[str, Any]) -> list[str]:
    """The methods worth decompiling, best first (from the CIL pass)."""
    return list(_priority_rids(obj))


def _priority_rids(obj: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for m in ((obj.get("result") or {}).get("cil") or {}).get("interesting") or []:
        if set(m.get("categories") or []) & PRIORITY or "called by a loader" in (m.get("categories") or []):
            out[m["method"]] = int(m.get("rid") or 0)
    return out


def _renamed(asm: Path) -> dict[int, str]:
    """MethodDef row → ``Type::Method`` in the (de4dot-renamed) assembly."""
    try:
        import dnfile

        from .cil import _owners
        return _owners(dnfile.dnPE(str(asm)).net.mdtables)
    except Exception:  # noqa: BLE001
        return {}


def _lock(sha: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(sha, threading.Lock())


def _cleaned(case_root: Path, target: Path, sha: str, obfuscated: bool, data: dict[str, Any]) -> Path:
    """The assembly ILSpy reads: de4dot's output when an obfuscator was detected
    and de4dot is provisioned (``-p un --strtyp none``), else the original."""
    if not obfuscated:
        return target
    out = _store(case_root) / f"{sha}.de4dot.bin"
    if out.is_file():
        return out
    cmd = de4dot_command()
    if cmd is None:
        data["de4dot"] = "not provisioned (Windows / Mono only): decompiled without the clean-up step"
        return target
    try:
        rc, so, se = _run([*cmd, "-f", str(target), "-o", str(out), *DE4DOT_ARGS], _store(case_root))
    except (OSError, TimeoutError) as exc:
        data["de4dot"] = f"failed ({exc}); decompiled without the clean-up step"
        return target
    if rc != 0 or not out.is_file():
        data["de4dot"] = f"failed (exit {rc}: {(se or so).strip()[-300:]}); decompiled without the clean-up step"
        return target
    data["de4dot"] = f"cleaned with de4dot {' '.join(DE4DOT_ARGS)} (renaming + control flow; strings untouched)"
    return out


def decompile(case_root: Path, target: Path, obj: dict[str, Any], methods: list[str]) -> dict[str, Any]:
    """Decompile ``methods`` (owner names from the CIL pass, which must be
    prioritised ones) of the assembly at ``target``; results are kept in the
    case and returned whole."""
    if not ilspy_available():
        raise RuntimeError("ILSpy CLI not provisioned")
    sha = obj["sha256"]
    allowed = _priority_rids(obj)
    with _lock(sha):
        data = load(case_root, sha)
        data.setdefault("methods", {})
        obfuscated = bool((obj.get("result") or {}).get("obfuscators"))
        asm = _cleaned(case_root, target, sha, obfuscated, data)
        data["source"] = "de4dot output" if asm != target else "original assembly"
        names_now = _renamed(asm) if asm != target else {}
        by_type: dict[str, list[tuple[str, str]]] = {}
        for full in methods:
            if full not in allowed:
                data["methods"][full] = {"status": "skipped", "detail": "not a prioritised method"}
                continue
            t, m = split_method(names_now.get(allowed[full]) or full)
            by_type.setdefault(t, []).append((full, m))
        dotnet, dll = dotnet_executable(), ilspy_dll()
        for t, names in by_type.items():
            try:
                rc, so, se = _run([str(dotnet), str(dll), "--disable-updatecheck", "-t", t, str(asm)],
                                  _store(case_root))
                err = "" if rc == 0 and so.strip() else f"exit {rc}: {(se or so).strip()[-300:]}"
            except (OSError, TimeoutError) as exc:
                so, err = "", str(exc)
            for key, m in names:
                if err:
                    data["methods"][key] = {"status": "error", "detail": err}
                    continue
                code = cut_method(so, t, m)
                renamed = f"{t}::{m}" if f"{t}::{m}" != key else ""
                data["methods"][key] = ({"status": "ok", "code": code[:MAX_CODE], "renamed": renamed} if code else
                                        {"status": "partial", "detail": "method not found in the type's C#; "
                                         "the type is shown", "code": so[:MAX_CODE]})
        data["tool"] = "ILSpy CLI (ilspycmd)"
        _save(case_root, sha, data)
        return data
