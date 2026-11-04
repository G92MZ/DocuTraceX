"""Visual C++ runtime next to rizin.exe: the pure-Python cabinet reader that
unpacks it from Microsoft's vc_redist.x64.exe (shipped in the pinned Cutter bundle)."""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import setup_portable_python as sp


def _mszip_blocks(raw: bytes, block: int = 32768) -> list[tuple[bytes, int]]:
    out, hist = [], b""
    for i in range(0, len(raw), block):
        piece = raw[i:i + block]
        c = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=hist) if hist else zlib.compressobj(9, zlib.DEFLATED, -15)
        out.append((b"CK" + c.compress(piece) + c.flush(), len(piece)))
        hist = piece[-32768:]
    return out


def make_cab(files: dict[str, bytes], compress: bool = True) -> bytes:
    """One-folder cabinet (MSZIP or stored), as makecab would write it."""
    names = list(files)
    raw = b"".join(files[n] for n in names)
    blocks = _mszip_blocks(raw) if compress else [(raw[i:i + 32768], len(raw[i:i + 32768]))
                                                  for i in range(0, len(raw), 32768)]
    hdr_len, folder_len = 36, 8
    file_entries = b""
    off = 0
    for n in names:
        file_entries += struct.pack("<IIHHHH", len(files[n]), off, 0, 0, 0, 0x20) + n.encode() + b"\x00"
        off += len(files[n])
    coff_files = hdr_len + folder_len
    data_start = coff_files + len(file_entries)
    data = b"".join(struct.pack("<IHH", 0, len(b), u) + b for b, u in blocks)
    total = data_start + len(data)
    head = b"MSCF" + struct.pack("<IIIII", 0, total, 0, coff_files, 0) + bytes([3, 1]) + \
        struct.pack("<HHHHH", 1, len(names), 0, 0, 0)
    folder = struct.pack("<IHH", data_start, len(blocks), 1 if compress else 0)
    return head + folder + file_entries + data


def test_cab_reader_mszip_with_history_and_stored() -> None:
    big = bytes(range(256)) * 600 + b"tail" * 5000          # > 2 blocks: later blocks need the history
    files = {"a.bin": big, "b.txt": b"hello cabinet\n" * 50}
    assert sp.cab_files(make_cab(files)) == files
    assert sp.cab_files(make_cab(files, compress=False)) == files
    assert sp.cab_files(b"not a cab") == {}


def test_vcruntime_from_a_wix_like_bundle(tmp_path: Path) -> None:
    dlls = {f"{n}_amd64": b"MZ" + n.encode() * 40 for n in sp.VCRUNTIME_DLLS}
    dlls["vcruntime140.dll_arm64"] = b"MZarm"
    inner = make_cab(dlls)
    outer = make_cab({"a0": b"\xd0\xcf\x11\xe0 msi", "a1": inner})
    bundle = b"MZ fake bootstrapper " + b"\x00" * 300 + outer + b"\x00" * 64   # never run, only read
    assert sp.vcruntime_app_local(bundle, tmp_path) == len(sp.VCRUNTIME_DLLS)
    assert (tmp_path / "vcruntime140.dll").read_bytes() == dlls["vcruntime140.dll_amd64"]
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(sp.VCRUNTIME_DLLS)
