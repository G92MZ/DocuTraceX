"""Streaming hashing.

Copies a binary stream to disk while computing cryptographic hashes in a single
pass, by blocks, so arbitrarily large files never need to be held in memory
(aligns with the "no fixed size limit + streaming" policy).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

_CHUNK = 1024 * 1024  # 1 MiB
_ALGOS = ("md5", "sha1", "sha256")


def copy_and_hash(src: BinaryIO, dest: Path) -> tuple[dict[str, str], int]:
    """Stream ``src`` into ``dest``; return ({algo: hexdigest}, size_bytes)."""
    hashers = {name: hashlib.new(name) for name in _ALGOS}
    size = 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as out:
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            out.write(chunk)
            size += len(chunk)
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}, size


def hash_file(path: Path) -> dict[str, str]:
    """Compute hashes of an existing file (e.g. to re-verify an original)."""
    hashers = {name: hashlib.new(name) for name in _ALGOS}
    with path.open("rb") as fh:
        # trace: gmzpt
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}
