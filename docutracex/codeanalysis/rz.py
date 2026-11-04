"""Run Rizin (+ rz-ghidra) headless on a binary with a command script.

Rizin only parses / disassembles / decompiles the file — nothing in it runs.
Each command's output is delimited with ``echo DTXMARK <label>`` so one
process answers many questions. A failing command aborts a Rizin script, so
callers only send commands known to exist. Time and memory are watched: the
process is killed past its limits and what it printed so far is kept.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

MARK = "DTXMARK"


def executable() -> Path | None:
    from ..config import settings
    return settings.rizin_executable()


def _prefix(exe: Path) -> Path:
    """The install prefix: the folder holding lib/rizin/plugins (bin/.. on
    Linux, the exe folder on Windows, somewhere in the .app on macOS)."""
    for c in (exe.parent.parent, exe.parent, *exe.parents):
        if (c / "lib" / "rizin" / "plugins").is_dir():
            return c
    return exe.parent.parent


def sleigh_home(exe: Path) -> Path | None:
    base = _prefix(exe)
    c = base / "lib" / "rizin" / "plugins" / "rz_ghidra_sleigh"
    if c.is_dir():
        return c
    hits = sorted(base.rglob("rz_ghidra_sleigh"))
    return hits[0] if hits else None


def env(exe: Path) -> dict[str, str]:
    e = dict(os.environ)
    pre = _prefix(exe)
    e["RZ_PREFIX"] = str(pre)
    lib = str(pre / "lib")
    if sys.platform.startswith("linux"):
        e["LD_LIBRARY_PATH"] = lib + os.pathsep + e.get("LD_LIBRARY_PATH", "")
    elif sys.platform == "darwin":
        e["DYLD_LIBRARY_PATH"] = lib + os.pathsep + e.get("DYLD_LIBRARY_PATH", "")
    else:
        e["PATH"] = str(exe.parent) + os.pathsep + e.get("PATH", "")
    e.pop("RZ_RCFILE", None)
    e["RZ_NORC"] = "1"
    return e


def header(exe: Path) -> list[str]:
    lines = ["e scr.color=0", "e scr.interactive=false", "e scr.utf8=false"]
    sh = sleigh_home(exe)
    if sh:
        lines.append(f"e ghidra.sleighhome={sh.as_posix()}")
    return lines


def version(exe: Path | None = None) -> str:
    exe = exe or executable()
    if exe is None:
        return ""
    try:
        r = subprocess.run([str(exe), "-v"], capture_output=True, text=True, timeout=30, env=env(exe), check=False,
                           stdin=subprocess.DEVNULL)
        return (r.stdout or "").splitlines()[0].strip() if r.stdout else ""
    except Exception:  # noqa: BLE001
        return ""


def run(binary: Path, commands: list[tuple[str, str]], timeout: float, mem_mb: int,
        prelude: list[str] | None = None) -> dict[str, Any]:
    """Run ``commands`` ([(label, rizin command)]) on ``binary``. Returns
    {outputs: {label: text}, stderr, elapsed_s, killed, returncode}."""
    exe = executable()
    if exe is None:
        return {"outputs": {}, "error": "rizin not provisioned"}
    lines = header(exe) + list(prelude or [])
    for label, cmd in commands:
        lines.append(f"echo {MARK} {label}")
        lines.append(cmd)
    fd, script = tempfile.mkstemp(suffix=".rz", prefix="dtx_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    t0 = time.monotonic()
    killed: list[str] = []
    try:
        # DWARF types confuse rz-ghidra on Go (it gives up silently): read code without them
        proc = subprocess.Popen([str(exe), "-q", "-e", "bin.dbginfo=false", "-i", script, str(binary)],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=env(exe))
    except Exception as exc:  # noqa: BLE001
        with contextlib.suppress(OSError):
            os.unlink(script)
        return {"outputs": {}, "error": f"could not start rizin: {exc}"}

    def watch() -> None:
        try:
            import psutil
            ps = psutil.Process(proc.pid)
        except Exception:  # noqa: BLE001
            ps = None
        while proc.poll() is None:
            if time.monotonic() - t0 > timeout:
                killed.append(f"time limit ({int(timeout)} s)")
                proc.kill()
                return
            if ps is not None:
                try:
                    if ps.memory_info().rss > mem_mb * 1024 * 1024:
                        killed.append(f"memory limit ({mem_mb} MB)")
                        proc.kill()
                        return
                except Exception:  # noqa: BLE001
                    ps = None
            time.sleep(0.25)
    w = threading.Thread(target=watch, daemon=True)
    w.start()
    out_b, err_b = proc.communicate()
    w.join(timeout=2)
    with contextlib.suppress(OSError):
        os.unlink(script)
    out = out_b.decode("utf-8", "replace")
    outputs: dict[str, str] = {}
    cur = None
    buf: list[str] = []
    for line in out.splitlines():
        if line.startswith(MARK + " "):
            if cur is not None:
                outputs[cur] = "\n".join(buf)
            cur, buf = line[len(MARK) + 1:].strip(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        outputs[cur] = "\n".join(buf)
    err = err_b.decode("utf-8", "replace")
    err = "\n".join(x for x in err.splitlines() if "Cannot create flag" not in x)
    return {"outputs": outputs, "stderr": err[-4000:], "elapsed_s": round(time.monotonic() - t0, 2),
            "killed": killed[0] if killed else None, "returncode": proc.returncode}


def as_json(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text.strip())
    except ValueError:
        return None


@contextlib.contextmanager
def exclusive(lock_path: Path, wait_s: float = 3600):
    """One code analysis at a time across all analysis processes."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+b")  # noqa: SIM115
    t0 = time.monotonic()
    try:
        while True:
            try:
                if sys.platform.startswith("win"):
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() - t0 > wait_s:
                    raise TimeoutError("another code analysis is still running") from None
                time.sleep(1)
        yield
    finally:
        try:
            if sys.platform.startswith("win"):
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        fh.close()


def run_groups(binary: Path, groups: list[tuple[str, list[tuple[str, str]]]], timeout: float, mem_mb: int,
               prelude: list[str] | None = None, deadline: float | None = None) -> dict[str, Any]:
    """Run command groups ([(key, [(label, cmd)])]) resiliently: a command that
    fails aborts a Rizin script, so the group whose output stops is recorded as
    failed and the run resumes with the next group. Returns {outputs, failed,
    killed, elapsed_s, runs}."""
    outputs: dict[str, str] = {}
    failed: list[str] = []
    todo = list(groups)
    t0 = time.monotonic()
    runs = 0
    killed = None
    while todo:
        if deadline is not None and time.monotonic() > deadline:
            break
        cmds = [c for _k, cs in todo for c in cs] + [("__end__", "echo end")]
        r = run(binary, cmds, timeout=timeout, mem_mb=mem_mb, prelude=prelude)
        runs += 1
        out = r.get("outputs") or {}
        outputs.update({k: v for k, v in out.items() if k != "__end__"})
        if r.get("error") or r.get("killed"):
            killed = r.get("error") or r.get("killed")
            break
        if "__end__" in out:
            break
        # find the first group not fully answered: it failed; resume after it
        idx = next((i for i, (_k, cs) in enumerate(todo) if any(lbl not in out for lbl, _c in cs)), None)
        if idx is None:
            break
        failed.append(todo[idx][0])
        todo = todo[idx + 1:]
    return {"outputs": outputs, "failed": failed, "killed": killed, "runs": runs,
            "elapsed_s": round(time.monotonic() - t0, 2)}
