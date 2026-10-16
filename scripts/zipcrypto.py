"""Password-protected ZIP (traditional PKWARE "ZipCrypto") writer and reader.

Used to keep the booby-trapped samples in ``samples/samples.zip`` with the
customary password ``infected``: antivirus engines and mail gateways do not
open encrypted archives, so the (benign) samples are not flagged or quarantined
on download, while 7-Zip, WinRAR, Windows Explorer and Python's ``zipfile``
all open it. Writing ZipCrypto is not in the standard library, so it is done
here (APPNOTE.TXT §6.1); reading uses ``zipfile`` with ``pwd``.

ZipCrypto is NOT security — it only hides the content from scanners.
"""

from __future__ import annotations

import os
import struct
import time
import zipfile
import zlib
from pathlib import Path

PASSWORD = b"infected"
_MASK = 0xFFFFFFFF


def _crc_byte(crc: int, b: int) -> int:
    # Raw CRC-32 table step (no pre/post inversion), as ZipCrypto's key update needs.
    return ~zlib.crc32(bytes([b]), ~crc & _MASK) & _MASK


class _Keys:
    def __init__(self, password: bytes) -> None:
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in password:
            self.update(b)

    def update(self, b: int) -> None:
        self.k0 = _crc_byte(self.k0, b)
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & _MASK
        self.k2 = _crc_byte(self.k2, self.k1 >> 24)

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, p in enumerate(data):
            t = (self.k2 | 2) & 0xFFFF
            out[i] = p ^ (((t * (t ^ 1)) >> 8) & 0xFF)
            self.update(p)
        return bytes(out)


def _dos_time(ts: float) -> tuple[int, int]:
    t = time.localtime(ts)
    return ((t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2),
            ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday)


def write(path: Path, files: dict[str, bytes], password: bytes = PASSWORD) -> None:
    """Write ``files`` (archive name -> content) deflated and ZipCrypto-encrypted."""
    dtime, ddate = _dos_time(time.time())
    local, central = bytearray(), bytearray()
    for name, data in files.items():
        fname = name.encode("utf-8")
        crc = zlib.crc32(data) & _MASK
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        deflated = comp.compress(data) + comp.flush()
        header = os.urandom(11) + bytes([crc >> 24])
        enc = _Keys(password).encrypt(header + deflated)
        flags = 0x0001 | 0x0800  # encrypted, UTF-8 names
        offset = len(local)
        local += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, 8, dtime, ddate, crc, len(enc), len(data),
                             len(fname), 0) + fname + enc
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, 8, dtime, ddate, crc, len(enc),
                               len(data), len(fname), 0, 0, 0, 0, 0o100644 << 16, offset) + fname
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(central), len(local), 0)
    Path(path).write_bytes(bytes(local) + bytes(central) + eocd)


def extract(path: Path, dest: Path, password: bytes = PASSWORD) -> list[Path]:
    # tag: gmzpt
    """Extract every member into ``dest`` (no path traversal). Returns the written paths."""
    dest = Path(dest)
    out = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            if dest.resolve() not in target.parents:
                raise ValueError(f"unsafe path in archive: {info.filename}")
            if info.is_dir():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info, pwd=password))
            out.append(target)
    return out


def read(path: Path, name: str, password: bytes = PASSWORD) -> bytes:
    with zipfile.ZipFile(path) as zf:
        return zf.read(name, pwd=password)
