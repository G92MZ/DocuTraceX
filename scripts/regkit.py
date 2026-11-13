"""A minimal Windows registry hive (regf) writer for the inert samples and tests.

Builds a valid hive from a nested dict: key nodes (nk), values (vk), value lists,
hash-leaf subkey lists (lh) and big-data-free values (data cells up to 16 KB).
Enough for regipy, Registry Explorer and DocuTraceX to read; nothing else.

    regkit.build({"Software": {"Microsoft": {"Windows": {"CurrentVersion": {"Run": {
        "@values": [("Updater", "REG_SZ", r"C:\\Users\\Public\\upd.exe")]}}}}}},
        root_name="ROOT", file_name="NTUSER.DAT", timestamp=...)

``deleted_keys`` / ``deleted_values`` add records in FREE cells, as Windows leaves them after a
deletion: ``[(parent_path, name, [(vname, type, data)...])]`` (the parent is a key of ``tree``,
``"Software\\X"``) and ``[(vname, type, data)]`` (values no key points to).

A node's ``"@ts"`` (FILETIME) sets its key's last-write time; the others take ``timestamp``.

Value types: REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ (list), REG_DWORD (int), REG_QWORD (int),
REG_BINARY (bytes), REG_NONE (bytes).
"""

from __future__ import annotations

import struct

TYPES = {"REG_NONE": 0, "REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3, "REG_DWORD": 4,
         "REG_MULTI_SZ": 7, "REG_QWORD": 11}
FILETIME_2026 = 134_070_000_000_000_000           # a fixed time keeps the samples stable


def _hash(name: str) -> int:
    h = 0
    for c in name.upper():
        h = (h * 37 + ord(c)) & 0xFFFFFFFF
    return h


def _value_data(vtype: str, data) -> bytes:  # noqa: ANN001
    t = TYPES[vtype]
    if t in (1, 2):
        return (str(data) + "\0").encode("utf-16-le")
    if t == 7:
        return ("\0".join(data) + "\0\0").encode("utf-16-le")
    if t == 4:
        return struct.pack("<I", int(data) & 0xFFFFFFFF)
    if t == 11:
        return struct.pack("<Q", int(data))
    return bytes(data)


def build(tree: dict, root_name: str = "ROOT", file_name: str = "hive", timestamp: int = FILETIME_2026,
          deleted_keys: list | None = None, deleted_values: list | None = None) -> bytes:
    """A regf hive holding ``tree`` (``{"Key": {...}, "@values": [(name, type, data), ...]}``)."""
    # Single hbin area: cells are written linearly; offsets are relative to the hbin start
    # (the first hbin header occupies 0x20 bytes).
    area = bytearray()

    def cell(payload: bytes) -> int:
        size = (len(payload) + 4 + 7) & ~7
        off = 0x20 + len(area)
        area.extend(struct.pack("<i", -size) + payload + b"\0" * (size - 4 - len(payload)))
        return off

    offsets: dict[str, int] = {}

    def free(off: int) -> None:                    # mark a written cell free (positive size)
        i = off - 0x20
        size = -struct.unpack_from("<i", area, i)[0]
        struct.pack_into("<i", area, i, size)

    def write_values(values: list) -> tuple[list[int], list[int]]:
        vk_offs, data_offs = [], []
        for vname, vtype, vdata in values:
            raw = _value_data(vtype, vdata)
            nm = vname.encode("ascii") if vname != "(default)" else b""
            if len(raw) <= 4:
                dsize, doff = len(raw) | 0x80000000, int.from_bytes(raw.ljust(4, b"\0"), "little")
            else:
                dsize, doff = len(raw), cell(raw)
                data_offs.append(doff)
            vk_offs.append(cell(b"vk" + struct.pack("<HIIIHH", len(nm), dsize, doff, TYPES[vtype], 1 if nm else 0, 0) + nm))
        return vk_offs, data_offs

    def write_key(name: str, node: dict, parent: int, is_root: bool, path: str = "") -> int:
        values = node.get("@values") or []
        subs = [(k, v) for k, v in node.items() if not k.startswith("@")]
        key_ts = node.get("@ts", timestamp)
        # values
        vk_offs = []
        for vname, vtype, vdata in values:
            raw = _value_data(vtype, vdata)
            nm = vname.encode("ascii") if vname != "(default)" else b""
            if len(raw) <= 4:
                dsize, doff = len(raw) | 0x80000000, int.from_bytes(raw.ljust(4, b"\0"), "little")
            else:
                dsize, doff = len(raw), cell(raw)
            vk_offs.append(cell(b"vk" + struct.pack("<HIIIHH", len(nm), dsize, doff, TYPES[vtype], 1 if nm else 0, 0) + nm))
        vlist = cell(b"".join(struct.pack("<I", o) for o in vk_offs)) if vk_offs else 0xFFFFFFFF
        # reserve the nk cell size first so children can point to it as parent
        nm = name.encode("ascii")
        nk_len = 76 + len(nm)
        nk_off = cell(b"\0" * nk_len)
        offsets[path] = nk_off
        child_offs = sorted(((k, write_key(k, v, nk_off, False, f"{path}\\{k}" if path else k)) for k, v in subs),
                            key=lambda kv: kv[0].upper())
        slist = (cell(b"lh" + struct.pack("<H", len(child_offs))
                      + b"".join(struct.pack("<II", o, _hash(k)) for k, o in child_offs))
                 if child_offs else 0xFFFFFFFF)
        flags = 0x20 | (0x0C if is_root else 0)
        max_vname = max((len(v[0]) * 2 for v in values), default=0)
        max_vdata = max((len(_value_data(v[1], v[2])) for v in values), default=0)
        max_sub = max((len(k) * 2 for k, _ in subs), default=0)
        nk = (b"nk" + struct.pack("<HQ4s" + "I" * 14, flags, key_ts, b"\0" * 4, parent, len(child_offs), 0,
                                  slist, 0xFFFFFFFF, len(vk_offs), vlist, 0xFFFFFFFF, 0xFFFFFFFF,
                                  max_sub, 0, max_vname, max_vdata, 0)
              + struct.pack("<HH", len(nm), 0) + nm)
        assert len(nk) == nk_len, (len(nk), nk_len)
        start = nk_off - 0x20 + 4
        area[start:start + nk_len] = nk
        return nk_off

    root = write_key(root_name, tree, 0xFFFFFFFF, True)
    for parent_path, name, values, *ts in deleted_keys or []:
        vk_offs, data_offs = write_values(values)
        vlist = cell(b"".join(struct.pack("<I", o) for o in vk_offs)) if vk_offs else 0xFFFFFFFF
        nm = name.encode("ascii")
        nk = (b"nk" + struct.pack("<HQ4s" + "I" * 14, 0x20, ts[0] if ts else timestamp, b"\0" * 4,
                                  offsets[parent_path], 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, len(vk_offs), vlist,
                                  0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0)
              + struct.pack("<HH", len(nm), 0) + nm)
        for o in [cell(nk), *([vlist] if vk_offs else []), *vk_offs, *data_offs]:
            free(o)
    vk_offs, data_offs = write_values(deleted_values or [])
    for o in vk_offs + data_offs:
        free(o)
    size = (0x20 + len(area) + 0xFFF) & ~0xFFF
    # the free space after the last cell is one free (positive-size) cell
    pad = size - 0x20 - len(area)
    if pad:
        area.extend(struct.pack("<i", pad) + b"\0" * (pad - 4))
    hbin = b"hbin" + struct.pack("<III4sQI", 0, size, 0, b"\0" * 4, timestamp, 0) + bytes(area)
    assert len(hbin) == size
    base = bytearray(4096)
    struct.pack_into("<4sIIQIIIIIII", base, 0, b"regf", 1, 1, timestamp, 1, 5, 0, 1, root, size, 1)
    fn = file_name.encode("utf-16-le")[:64]
    base[0x30:0x30 + len(fn)] = fn
    csum = 0
    for i in range(0, 0x1FC, 4):
        csum ^= struct.unpack_from("<I", base, i)[0]
    struct.pack_into("<I", base, 0x1FC, csum)
    return bytes(base) + hbin
