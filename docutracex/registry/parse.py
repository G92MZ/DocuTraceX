"""Readers for registry hives (regf, via regipy) and .reg exports (REGEDIT4 / version 5.00).

Both yield the same rows, with full paths under the usual roots (HKLM\\SOFTWARE…, HKCU…):

- keys:   (path, parent, name, last_write: datetime | None, subkeys, values, op)
- values: (key, name, type, data_text, size, raw: bytes | None, op)

``op`` is "" for what is set and "delete" for what a .reg removes ([-key], "name"=-).
"""

from __future__ import annotations

import codecs
import datetime as dt
import re
from pathlib import Path
from typing import Any, Iterator

MAX_RAW = 4 * 1024 * 1024            # binary data kept as a blob (payloads stored in values)
MAX_TEXT = 64 * 1024                 # data text kept in the table (the blob has the rest)

ROOTS = {"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU", "HKEY_CLASSES_ROOT": "HKCR",
         "HKEY_USERS": "HKU", "HKEY_CURRENT_CONFIG": "HKCC", "HKEY_PERFORMANCE_DATA": "HKPD"}

# Where each hive is mounted on a live system (regipy's hive types).
MOUNTS = {"ntuser": "HKCU", "usrclass": "HKCU\\Software\\Classes", "software": "HKLM\\SOFTWARE",
          "system": "HKLM\\SYSTEM", "sam": "HKLM\\SAM", "security": "HKLM\\SECURITY",
          "default": "HKU\\.DEFAULT", "bcd": "HKLM\\BCD00000000", "components": "HKLM\\COMPONENTS",
          "amcache": "Amcache", "drivers": "HKLM\\DRIVERS", "elam": "HKLM\\ELAM"}


def is_hive(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(4) == b"regf"
    except OSError:
        return False


def _reg_head(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            head = fh.read(256)
    except OSError:
        return ""
    return _head_text(head)


def _head_text(head: bytes) -> str:
    if head.startswith(codecs.BOM_UTF16_LE):
        return head[2:].decode("utf-16-le", "ignore")
    if head[1:2] == b"\0" and head[:1] != b"\0":
        return head.decode("utf-16-le", "ignore")
    return head.lstrip(codecs.BOM_UTF8).decode("latin-1", "ignore")


def is_reg_text(path: Path) -> bool:
    h = _reg_head(path).lstrip()
    return h.startswith("Windows Registry Editor Version 5.00") or h.startswith("REGEDIT4")


def is_registry_bytes(data: bytes) -> bool:
    """A hive or a .reg export, from its first bytes."""
    if data[:4] == b"regf":
        return True
    h = _head_text(data[:256]).lstrip()
    return h.startswith("Windows Registry Editor Version 5.00") or h.startswith("REGEDIT4")


def _norm_root(path: str) -> str:
    path = path.strip().strip("\\")
    first, _, rest = path.partition("\\")
    root = ROOTS.get(first.upper(), first.upper() if first.upper() in ROOTS.values() else first)
    return root + ("\\" + rest if rest else "")


def _parent(path: str) -> tuple[str, str]:
    p, _, n = path.rpartition("\\")
    return p, n


# --- .reg ---------------------------------------------------------------------------------
_TYPE_OF_HEX = {"": "REG_BINARY", "0": "REG_NONE", "1": "REG_SZ", "2": "REG_EXPAND_SZ", "3": "REG_BINARY",
                "4": "REG_DWORD", "5": "REG_DWORD_BIG_ENDIAN", "6": "REG_LINK", "7": "REG_MULTI_SZ",
                "8": "REG_RESOURCE_LIST", "9": "REG_FULL_RESOURCE_DESCRIPTOR",
                "a": "REG_RESOURCE_REQUIREMENTS_LIST", "b": "REG_QWORD"}


def _read_reg_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(codecs.BOM_UTF16_LE) or (raw[1:2] == b"\0" and raw[:1] != b"\0"):
        return raw.decode("utf-16-le", "replace").lstrip("﻿")
    return raw.decode("utf-8-sig", "replace") if raw.startswith(codecs.BOM_UTF8) else raw.decode("latin-1")


def _logical_lines(text: str) -> Iterator[str]:
    buf = ""
    for line in text.splitlines():
        s = line.rstrip()
        if buf:
            s = s.lstrip()
        if s.endswith("\\") and ("=hex" in (buf + s).lower() or buf):
            buf += s[:-1]
            continue
        yield buf + s
        buf = ""
    if buf:
        yield buf


def _unquote(s: str) -> tuple[str, str]:
    """The quoted string at the start of ``s`` (with \\\\ and \\" escapes) and what follows it."""
    out, i = [], 1
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
            continue
        if c == '"':
            return "".join(out), s[i + 1:]
        out.append(c)
        i += 1
    return "".join(out), ""


def _decode(vtype: str, raw: bytes) -> str:
    if vtype in ("REG_SZ", "REG_EXPAND_SZ", "REG_LINK"):
        return raw.decode("utf-16-le", "replace").split("\0", 1)[0]
    if vtype == "REG_MULTI_SZ":
        return "\n".join(x for x in raw.decode("utf-16-le", "replace").split("\0") if x)
    if vtype == "REG_DWORD" and len(raw) >= 4:
        return str(int.from_bytes(raw[:4], "little"))
    if vtype == "REG_DWORD_BIG_ENDIAN" and len(raw) >= 4:
        return str(int.from_bytes(raw[:4], "big"))
    if vtype == "REG_QWORD" and len(raw) >= 8:
        return str(int.from_bytes(raw[:8], "little"))
    return raw[: MAX_TEXT // 2].hex()


def _reg_value(rhs: str) -> tuple[str, str, bytes | None, str]:
    """(type, text, raw, op) of the right-hand side of a .reg assignment."""
    rhs = rhs.strip()
    if rhs == "-":
        return "", "", None, "delete"
    if rhs.startswith('"'):
        s, _ = _unquote(rhs)
        return "REG_SZ", s, None, ""
    low = rhs.lower()
    if low.startswith("dword:"):
        try:
            return "REG_DWORD", str(int(rhs[6:].strip(), 16)), None, ""
        except ValueError:
            return "REG_DWORD", rhs[6:].strip(), None, ""
    m = re.match(r"hex(?:\(([0-9a-fA-F]+)\))?:(.*)", rhs, re.S)
    if m:
        vtype = _TYPE_OF_HEX.get((m.group(1) or "").lower().lstrip("0") or ("0" if m.group(1) else ""), "REG_BINARY")
        hexs = re.sub(r"[^0-9a-fA-F]", "", m.group(2).replace(",", ""))
        try:
            raw = bytes.fromhex(hexs[: len(hexs) // 2 * 2])
        except ValueError:
            raw = b""
        return vtype, _decode(vtype, raw), raw, ""
    return "REG_SZ", rhs, None, ""


def iter_reg(path: Path) -> tuple[list[tuple], list[tuple]]:
    """Keys and values set or deleted by a .reg file."""
    keys: dict[str, tuple] = {}
    vals: list[tuple] = []
    cur, cur_del = "", False
    for line in _logical_lines(_read_reg_text(path)):
        s = line.strip()
        if not s or s.startswith(";") or s.startswith("Windows Registry Editor") or s == "REGEDIT4":
            continue
        if s.startswith("[") and s.endswith("]"):
            cur_del = s.startswith("[-")
            cur = _norm_root(s[2:-1] if cur_del else s[1:-1])
            parent, name = _parent(cur)
            keys[cur] = (cur, parent, name, None, 0, 0, "delete" if cur_del else "")
            continue
        if not cur or cur_del:
            continue
        if s.startswith("@="):
            name, rhs = "(default)", s[2:]
        elif s.startswith('"'):
            name, rest = _unquote(s)
            if not rest.lstrip().startswith("="):
                continue
            rhs = rest.lstrip()[1:]
        else:
            continue
        vtype, text, raw, op = _reg_value(rhs)
        size = len(raw) if raw is not None else len(text.encode("utf-16-le"))
        blob = raw if raw is not None and vtype in ("REG_BINARY", "REG_NONE") else None
        vals.append((cur, name, vtype, text[:MAX_TEXT], size, blob, op))
    counts: dict[str, int] = {}
    for v in vals:
        counts[v[0]] = counts.get(v[0], 0) + 1
    rows = [(k[0], k[1], k[2], k[3], 0, counts.get(k[0], 0), k[6]) for k in keys.values()]
    return rows, vals


# --- hives --------------------------------------------------------------------------------
def _data_of(vtype: str, value: Any) -> tuple[str, bytes | None]:
    if isinstance(value, bytes):
        return _decode(vtype, value) if vtype not in ("REG_BINARY", "REG_NONE") else value[: MAX_TEXT // 2].hex(), value
    if isinstance(value, list):
        return "\n".join(str(x) for x in value), None
    if vtype in ("REG_BINARY", "REG_NONE") and isinstance(value, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value or ""):
        raw = bytes.fromhex(value)
        return value[:MAX_TEXT], raw
    return ("" if value is None else str(value)), None


_TYPE_BY_NAME = (("ntuser.dat", "ntuser"), ("usrclass.dat", "usrclass"), ("amcache.hve", "amcache"),
                 ("software", "software"), ("system", "system"), ("sam", "sam"), ("security", "security"),
                 ("default", "default"), ("components", "components"), ("bcd", "bcd"), ("drivers", "drivers"))
# root subkeys that tell a hive apart when its name does not
_TYPE_BY_ROOT = (("ntuser", {"software", "environment", "control panel"}), ("system", {"select", "controlset001"}),
                 ("software", {"microsoft", "classes", "policies"}), ("sam", {"sam"}), ("security", {"policy"}),
                 ("amcache", {"root"}), ("usrclass", {"local settings"}))


def hive_info(path: Path) -> dict[str, Any]:
    from regipy.registry import RegistryHive
    h = RegistryHive(str(path))
    htype = (h.hive_type or "").lower()
    embedded = str(h.name or "")
    if not htype:
        for nm in (embedded.replace("\\", "/").rsplit("/", 1)[-1].lower(), path.name.lower()):
            base = re.sub(r"^sample_", "", nm)
            htype = next((t for n, t in _TYPE_BY_NAME if base == n or base.endswith("_" + n) or base.endswith("." + n)), "")
            if htype:
                break
    if not htype:
        try:
            roots = {s.name.lower() for s in (h.root.iter_subkeys() or [])}
        except Exception:  # noqa: BLE001
            roots = set()
        htype = next((t for t, need in _TYPE_BY_ROOT if need <= roots), "")
    return {"hive_type": htype, "mount": MOUNTS.get(htype, path.name), "embedded_name": embedded}


def apply_logs(path: Path, out: Path) -> tuple[Path, list[str]]:
    """The hive with its transaction logs (NAME.LOG1 / .LOG2 beside it) applied, when present."""
    logs = [p for p in (path.with_name(path.name + ".LOG1"), path.with_name(path.name + ".LOG2"),
                        path.with_name(path.name + ".LOG")) if p.is_file() and p.stat().st_size > 512]
    if not logs:
        return path, []
    try:
        from regipy.recovery import apply_transaction_logs
        out.parent.mkdir(parents=True, exist_ok=True)
        apply_transaction_logs(str(path), str(logs[0]), str(logs[1]) if len(logs) > 1 else None,
                               restored_hive_path=str(out))
        if out.is_file() and out.stat().st_size >= 4096:
            return out, [p.name for p in logs]
    except Exception:  # noqa: BLE001  (a dirty hive is still read as it is)
        pass
    return path, []


def iter_hive(path: Path, mount: str) -> Iterator[tuple[str, tuple]]:
    """("key", row) and ("value", row) for every key and value of the hive, depth first.

    The fast walker (``fastregf``) reads a full SOFTWARE hive in seconds; on a structure it
    cannot follow, regipy takes over for the keys not read yet."""
    from . import fastregf
    done: set[str] = set()
    try:
        for what, row in fastregf.iter_hive(path, mount, _decode, MAX_TEXT, MAX_RAW):
            if what == "key":
                done.add(row[0])
                parent, name = _parent(row[0])
                row = (row[0], parent, name, *row[3:])
            yield what, row
        return
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).warning("registry: fast walker stopped on %s (%s); regipy continues", path.name, exc)
    skip = False
    for what, row in _iter_hive_regipy(path, mount):
        if what == "key":
            skip = row[0] in done
        if not skip:
            yield what, row


def _iter_hive_regipy(path: Path, mount: str) -> Iterator[tuple[str, tuple]]:
    from regipy.registry import RegistryHive
    h = RegistryHive(str(path))

    def ts(nk) -> dt.datetime | None:  # noqa: ANN001
        try:
            from regipy.utils import convert_wintime
            return convert_wintime(nk.header.last_modified, as_json=False)
        except Exception:  # noqa: BLE001
            return None

    stack = [(h.root, mount)]
    while stack:
        nk, path_ = stack.pop()
        try:
            subs = list(nk.iter_subkeys() or []) if nk.header.subkey_count else []
        except Exception:  # noqa: BLE001  (a broken subkey list: keep what was read)
            subs = []
        values = []
        if nk.header.values_count:
            try:
                values = list(nk.iter_values(trim_values=False))
            except Exception:  # noqa: BLE001
                values = []
        parent, name = _parent(path_)
        yield "key", (path_, parent, name, ts(nk), len(subs), len(values), "")
        for v in values:
            vtype = str(getattr(v, "value_type", "") or "")
            text, raw = _data_of(vtype, getattr(v, "value", None))
            size = len(raw) if raw is not None else len(text.encode("utf-16-le"))
            yield "value", (path_, v.name or "(default)", vtype, text[:MAX_TEXT], size,
                            raw[:MAX_RAW] if raw is not None and vtype in ("REG_BINARY", "REG_NONE") else None, "")
        for s in reversed(subs):
            if hasattr(s, "header") and hasattr(s, "iter_values"):
                stack.append((s, f"{path_}\\{s.name}"))
