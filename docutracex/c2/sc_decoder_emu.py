"""Bounded emulation of a shellcode DECODER stub (shikata_ga_nai and the like).

Run as a separate process (``python -I sc_decoder_emu.py < job.json``): Unicorn
(GPL-2) is never imported by DocuTraceX itself. Only the decoder loop runs, on a
simulated CPU: the shellcode is copied into an empty address space with a fake
stack. There is no operating system, no API, no file, no network: the first
read of the PEB (``fs:[0x30]`` / ``gs:[0x60]``), any ``int`` / ``syscall`` /
``sysenter``, a jump outside the buffer or the instruction limit stops it. It
is stopped as soon as execution reaches a ``block_api`` prologue — the
decoded payload starts there and is returned, never run.

Input JSON: {"data": hex, "arch": "x86" | "x64", "max_insn": n, "heads": [hex]}.
Output JSON: {"offset": n, "data": hex, "insn": n} or {"error": "..."}.
"""

from __future__ import annotations

import json
import sys

BASE = 0x00400000
STACK, STACK_SIZE = 0x00100000, 0x00040000


def _run(sc: bytes, arch: str, max_insn: int, heads: list[bytes]) -> dict:
    from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_32, UC_MODE_64, Uc, UcError
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_RSP

    mu = Uc(UC_ARCH_X86, UC_MODE_64 if arch == "x64" else UC_MODE_32)
    size = (len(sc) + 0x2000 + 0xFFF) & ~0xFFF
    mu.mem_map(BASE, size)
    mu.mem_write(BASE, sc)
    mu.mem_map(STACK, STACK_SIZE)
    mu.reg_write(UC_X86_REG_RSP if arch == "x64" else UC_X86_REG_ESP, STACK + STACK_SIZE - 0x1000)
    out: dict = {}
    count = [0]

    def on_code(uc, addr, sz, _user):
        count[0] += 1
        off = addr - BASE
        if not 0 <= off < len(sc):
            out["error"] = f"left the buffer at 0x{addr:x}"
            uc.emu_stop()
            return
        if off > 0:
            cur = bytes(uc.mem_read(addr, 16))
            if any(cur.startswith(h) for h in heads):
                out["offset"] = off
                out["data"] = bytes(uc.mem_read(BASE, len(sc)))[off:]
                uc.emu_stop()

    def on_intr(uc, _intno, _user):
        out.setdefault("error", "interrupt / system call reached")
        uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(UC_HOOK_INTR, on_intr)
    try:
        mu.emu_start(BASE, BASE + len(sc), timeout=5_000_000, count=max_insn)
    except UcError as exc:
        out.setdefault("error", f"emulation stopped: {exc}")
    if "data" in out:
        out.pop("error", None)
        out["insn"] = count[0]
    elif "error" not in out:
        out["error"] = "limit reached without a decoded payload"
    return out


def main() -> int:
    job = json.loads(sys.stdin.read())
    r = _run(bytes.fromhex(job["data"]), job.get("arch", "x86"), int(job.get("max_insn", 2_000_000)),
             [bytes.fromhex(h) for h in job.get("heads") or []])
    if "data" in r:
        r["data"] = r["data"].hex()
    sys.stdout.write(json.dumps(r))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
