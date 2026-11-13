"""Encoded shellcode: msfvenom / Cobalt Strike payloads wrapped in a decoder stub
(``x86/shikata_ga_nai``, ``x64/xor``…) — the bytes after the stub are noise
until the stub runs, so neither the Metasploit nor the Cobalt Strike reader
can see a ``block_api`` stager in them.

The stub is recognised by its GetPC idiom and run on Unicorn in a separate
process (``sc_decoder_emu.py``): no OS, no API, stopped at the first
``block_api`` prologue it reaches — the decoded payload — and never further.
"""

from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

TIMEOUT = 30
MAX_SC = 512 * 1024

# Where the decoded payload starts: block_api's ``cld; call <api_call>`` (x86: the
# call distance differs between payload generations) and its x64 form; a
# reflective DLL's MZ stub.
HEADS = [b"\xfc\xe8" + bytes([n]) + b"\x00\x00\x00\x60" for n in (0x82, 0x86, 0x89, 0x8F)] + \
        [b"\xfc\x48\x83\xe4\xf0\xe8", b"MZARUH", b"MZRE"]

# GetPC idioms of the encoders: x86 ``fnstenv [esp-0xc]`` (shikata_ga_nai and the
# other FPU-based ones) and x64/xor's ``lea rax, [rip-0x11]; mov rbx, key``.
_GETPC = (("x86", b"\xd9\x74\x24\xf4", 48, "FPU-GetPC encoder (shikata_ga_nai style)"),
          ("x64", b"\x48\x8d\x05\xef\xff\xff\xff\x48\xbb", 48, "x64/xor"))


def available() -> bool:
    return importlib.util.find_spec("unicorn") is not None


def decoder(sc: bytes) -> tuple[str, str] | None:
    """(arch, encoder name) when the shellcode starts with a known decoder stub."""
    head = sc[:64]
    if any(h in head[:16] for h in HEADS):
        return None                               # already plain
    for arch, sig, within, name in _GETPC:
        i = head.find(sig)
        if 0 <= i <= within:
            return arch, name
    return None


@functools.lru_cache(maxsize=32)
def _decode_cached(digest: str, sc: bytes, arch: str) -> dict[str, Any] | None:
    job = {"data": sc.hex(), "arch": arch, "max_insn": 2_000_000, "heads": [h.hex() for h in HEADS]}
    script = Path(__file__).with_name("sc_decoder_emu.py")
    try:
        p = subprocess.run([sys.executable, "-I", str(script)], input=json.dumps(job), capture_output=True,
                           text=True, timeout=TIMEOUT, check=False, stdin=None)
        out = json.loads(p.stdout or "{}")
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return None
    if "data" not in out:
        return None
    return {"offset": int(out["offset"]), "data": bytes.fromhex(out["data"]), "insn": int(out.get("insn", 0))}


def decode(sc: bytes) -> dict[str, Any] | None:
    """{offset, data, insn, arch, encoder} — the payload the stub decodes — or None."""
    found = decoder(sc)
    if not found or not sc or len(sc) > MAX_SC or not available():
        return None
    arch, name = found
    res = _decode_cached(hashlib.sha256(sc).hexdigest(), bytes(sc), arch)
    if not res:
        return None
    return {**res, "arch": arch, "encoder": name,
            "note": f"{name} decoder stub run on an emulated CPU (no OS, {res['insn']} instructions), "
                    f"stopped at the decoded payload (offset 0x{res['offset']:x})"}
