"""Bounded emulation of Go string-decoding routines (Garble ``-literals``).

Run as a separate process (``python -I garble_emu.py < job.json``): Unicorn
(GPL-2) is never imported by DocuTraceX itself. Only the given routine runs,
on a simulated x86-64 CPU: the binary's sections are mapped read-only into an
empty address space, with a fake stack and a fake goroutine (``g``) so the
stack check never fires. There is no operating system, no API, no file, no
network: every other call returns 0 at once. The routine is stopped when it
reaches ``runtime.slicebytetostring`` (whose ``ptr`` / ``len`` arguments are
the decoded string), at a time / instruction limit, or on anything unexpected.

Input JSON: {"sections": [[va, hex]], "jobs": [{"entry": va}], "sbts": [va],
"functions": [va], "max_insn": n}. Output JSON: [{"entry", "value" | "error"}].
"""

from __future__ import annotations

import json
import sys

PAGE = 0x1000
STACK, STACK_SIZE = 0x7F0000000000, 0x100000
GPTR = 0x7E0000000000
SENTINEL = 0x7D0000000000


def _run(sections: list[tuple[int, bytes]], entry: int, sbts: set[int], funcs: set[int], max_insn: int) -> dict:
    from unicorn import (
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_UNMAPPED,
        UC_MODE_64,
        UC_PROT_ALL,
        Uc,
        UcError,
    )
    from unicorn.x86_const import (
        UC_X86_REG_R14,
        UC_X86_REG_RAX,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSP,
    )

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped: list[tuple[int, int]] = []

    def map_range(lo: int, hi: int) -> None:
        lo, hi = lo & ~(PAGE - 1), (hi + PAGE - 1) & ~(PAGE - 1)
        for a, b in mapped:                                   # skip what is already mapped
            if a <= lo < b:
                lo = b
            if a < hi <= b:
                hi = a
        if hi > lo:
            mu.mem_map(lo, hi - lo, UC_PROT_ALL)
            mapped.append((lo, hi))
    for va, data in sections:
        map_range(va, va + max(len(data), 1))
    for va, data in sections:
        mu.mem_write(va, data)
    map_range(STACK, STACK + STACK_SIZE)
    map_range(GPTR, GPTR + PAGE)                               # g: stackguard0 = 0, the stack check never trips
    map_range(SENTINEL, SENTINEL + PAGE)
    rsp = STACK + STACK_SIZE - 0x2000
    mu.mem_write(rsp, SENTINEL.to_bytes(8, "little"))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_R14, GPTR)
    out: dict = {}
    extra = [0]

    def on_code(uc, addr, size, _user):
        if addr in sbts:
            ptr, n = uc.reg_read(UC_X86_REG_RBX), uc.reg_read(UC_X86_REG_RCX)
            if 0 < n <= 4096:
                try:
                    out["value"] = bytes(uc.mem_read(ptr, n))
                except UcError:
                    out["error"] = "string outside mapped memory"
            else:
                out["error"] = f"implausible length {n}"
            uc.emu_stop()
        elif addr == SENTINEL:
            out.setdefault("error", "returned without building a string")
            uc.emu_stop()
        elif addr in funcs and addr != entry:                  # any other call: return 0 at once (no runtime, no API)
            sp = uc.reg_read(UC_X86_REG_RSP)
            ret = int.from_bytes(uc.mem_read(sp, 8), "little")
            uc.reg_write(UC_X86_REG_RSP, sp + 8)
            uc.reg_write(UC_X86_REG_RAX, 0)
            uc.reg_write(UC_X86_REG_RIP, ret)

    def on_unmapped(uc, _access, addr, size, _value, _user):
        if extra[0] >= 64:
            return False
        extra[0] += 1
        map_range(addr, addr + max(size, 1))                    # zero page (heap-like scratch), bounded
        return True
    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
    try:
        mu.emu_start(entry, SENTINEL + 0x10, timeout=2_000_000, count=max_insn)
    except UcError as exc:
        out.setdefault("error", f"emulation stopped: {exc}")
    if "value" not in out and "error" not in out:
        out["error"] = "limit reached"
    return out


def main() -> int:
    job = json.loads(sys.stdin.read())
    sections = [(int(va), bytes.fromhex(h)) for va, h in job["sections"]]
    sbts = {int(x) for x in job["sbts"]}
    funcs = {int(x) for x in job["functions"]}
    res = []
    for j in job["jobs"]:
        r = _run(sections, int(j["entry"]), sbts, funcs, int(job.get("max_insn", 200000)))
        res.append({"entry": j["entry"], **({"value": r["value"].hex()} if "value" in r else {"error": r["error"]})})
    sys.stdout.write(json.dumps(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
