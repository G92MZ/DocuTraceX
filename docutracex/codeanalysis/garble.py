"""Garble ``-literals`` string recovery (Go phase 7).

Garble replaces every string literal with a small closure that rebuilds it at
run time and hands the bytes to ``runtime.slicebytetostring``. Candidates are
program functions that call it and nothing but runtime helpers. Each one is
emulated — only that routine, on a simulated CPU, in a separate process, no OS
or APIs (see ``garble_emu``) — and stopped at ``slicebytetostring``: its
arguments are the decoded string. Results are marked "reconstructed by
emulation". x86-64 only (the patterns of Go's register ABI).
"""

from __future__ import annotations

import importlib.util
import json
import string
import subprocess
import sys
from pathlib import Path
from typing import Any

MAX_JOBS = 300
MAX_FN_SIZE = 8192
TIMEOUT = 120
SBTS = ("runtime.slicebytetostring",)
_PRINT = set(string.printable.encode())


def available() -> bool:
    return importlib.util.find_spec("unicorn") is not None


def candidates(full: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for f in full.get("functions") or []:
        cn = f.get("callee_names") or []
        if not any(n in SBTS for n in cn) or (f.get("size") or 0) > MAX_FN_SIZE:
            continue
        others = [n for n in cn if not n.startswith("runtime.")]
        if others:
            continue                                        # a real function, not a literal-decoding closure
        out.append(f)
    return out[:MAX_JOBS]


def recover(full: dict[str, Any], data: bytes, binf, names: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    res: dict[str, Any] = {"status": "ok", "strings": [], "candidates": 0, "failed": []}
    if mode != "go":
        return {"status": "skipped", "detail": "Go binaries only", "strings": []}
    if (binf.arch or "").lower() not in ("amd64", "x86_64", "x86-64", "x64"):
        return {"status": "skipped", "detail": f"x86-64 only (this is {binf.arch or 'unknown'})", "strings": []}
    cands = candidates(full)
    res["candidates"] = len(cands)
    if not cands:
        return res
    if not available():
        res.update(status="unavailable", detail="the Unicorn emulator is not installed in the portable Python "
                                                "(Diagnostics → Retry tool-deps)")
        return res
    sbts = [n["start"] for n in names if n["name"] in SBTS]
    if not sbts:
        return {"status": "skipped", "detail": "runtime.slicebytetostring not in the function table", "strings": []}
    secs = [[s.va, data[s.offset:s.offset + s.size].hex()] for s in binf.sections if s.va and s.offset and s.size]
    job = {"sections": secs, "jobs": [{"entry": f["addr"]} for f in cands], "sbts": sbts,
           "functions": [n["start"] for n in names], "max_insn": 200000}
    script = Path(__file__).with_name("garble_emu.py")
    try:
        p = subprocess.run([sys.executable, "-I", str(script)], input=json.dumps(job), capture_output=True,
                           text=True, timeout=TIMEOUT, check=False)
        out = json.loads(p.stdout or "[]")
    except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
        res.update(status="failed", detail=f"emulator: {exc}"[:300])
        return res
    by = {f["addr"]: f for f in cands}
    for r in out:
        f = by.get(r["entry"])
        if f is None:
            continue
        if "value" not in r:
            res["failed"].append({"function": f["name"], "detail": r.get("error", "")})
            continue
        raw = bytes.fromhex(r["value"])
        text = raw.decode("utf-8", "replace")
        res["strings"].append({"function": f["name"], "addr": f["addr"], "value": text[:2000], "size": len(raw),
                               "printable": all(b in _PRINT for b in raw),
                               "status": "reconstructed", "method": "emulation (Garble literal)"})
    res["failed"] = res["failed"][:100]
    return res
