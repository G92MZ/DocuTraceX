"""Sweep of a whole case for files hidden in images and resources.

Generic complement of the per-child check in :mod:`nested`: after every parser
and the .NET / code analyses ran, it looks at

* **every image the case extracted** (Office media, PDF / OneNote / archive
  images, managed resources…) — even those not analysed as children —, and
* **the native resources of each PE** of the case (``RT_BITMAP`` rebuilt as a
  BMP, ``RT_RCDATA`` and custom types, icons),

and tries them with :mod:`stego` (pixels and data appended after the image)
using the **strings of the whole case as candidate keys** (literals of .NET
assemblies, strings they decrypt, .resources values). Only a well-formed file
becomes a child; an image or resource without one adds nothing to the case."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from .logging_config import get_logger
from .storage import read_json

log = get_logger(__name__)

DIRNAME = "hidden"
MAX_FILES = 2000
MAX_SIZE = 64 * 1024 * 1024
MAX_PES = 40
MAX_KEYS = 200


def case_keys(paths: Any) -> list[Any]:
    """Candidate keys gathered from the analyses that already ran."""
    out: list[Any] = []
    dn = read_json(paths.subresult("dotnet")) or {}
    for o in dn.get("objects") or []:
        r = o.get("result") or {}
        out += [d.get("output") for d in (r.get("cil") or {}).get("decrypted") or []]
        for x in r.get("resources") or []:
            out += [e.get("value") for e in x.get("entries") or [] if e.get("type") == "string"]
        out += r.get("strings") or []
    seen: set[str] = set()
    keys = []
    for k in out:
        if isinstance(k, str) and 4 <= len(k) <= 64 and k not in seen:
            seen.add(k)
            keys.append(k)
    return keys[:MAX_KEYS]


def _nested_shas(tree: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    """(sha256 of every nested node, sha256 of the images already decoded)."""
    allsh, done = set(), set()

    def walk(nodes: list[dict[str, Any]]) -> None:
        for n in nodes:
            if n.get("sha256"):
                allsh.add(n["sha256"])
                if n.get("stego"):
                    done.add(n["sha256"])
            walk(n.get("children") or [])
    walk(tree)
    return allsh, done


def _bmp_from_dib(dib: bytes) -> bytes | None:
    """RT_BITMAP holds a DIB without its 14-byte file header: rebuild it."""
    if len(dib) < 40:
        return None
    hsize = struct.unpack_from("<I", dib)[0]
    if hsize not in (12, 40, 52, 56, 108, 124):
        return None
    if hsize == 12:
        bpp, colors = struct.unpack_from("<H", dib, 10)[0], 0
    else:
        bpp = struct.unpack_from("<H", dib, 14)[0]
        colors = struct.unpack_from("<I", dib, 32)[0]
    pal = (colors or (1 << bpp if bpp <= 8 else 0)) * (3 if hsize == 12 else 4)
    if hsize == 40 and struct.unpack_from("<I", dib, 16)[0] == 3:      # BI_BITFIELDS masks
        pal += 12
    off = 14 + hsize + pal
    return b"BM" + struct.pack("<IHHI", 14 + len(dib), 0, 0, off) + dib


def _pe_resources(data: bytes) -> list[tuple[str, bytes]]:
    """(label, bytes) of the resources worth checking: bitmaps (as BMP files),
    RCDATA and custom types, icons."""
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception:  # noqa: BLE001
        return []
    out: list[tuple[str, bytes]] = []
    for t in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or []:
        tid = t.id if t.id is not None else str(t.name)
        if tid not in (2, 3, 10) and not isinstance(tid, str) and tid < 24:
            continue                                     # menus, dialogs, strings, versions, manifests…
        tname = {2: "RT_BITMAP", 3: "RT_ICON", 10: "RT_RCDATA"}.get(tid, str(tid))
        for n in getattr(t, "directory", None) and t.directory.entries or []:
            for lang in getattr(n, "directory", None) and n.directory.entries or []:
                d = getattr(lang, "data", None)
                if d is None:
                    continue
                try:
                    raw = pe.get_data(d.struct.OffsetToData, d.struct.Size)
                except Exception:  # noqa: BLE001
                    continue
                name = n.id if n.id is not None else str(n.name)
                if tid == 2:
                    raw = _bmp_from_dib(raw) or b""
                if len(raw) >= 64:
                    out.append((f"{tname}/{name}", raw))
                if len(out) >= 400:
                    return out
    return out


def _try(data: bytes, keys: list[Any]) -> tuple[str, bytes, str] | None:
    from . import stego
    if stego.is_image(data):
        return stego.extract(data, keys)
    got = stego.identify(data)                           # a file stored as it is in a resource
    if got:
        return "stored as it is", data[:got[1]], got[0]
    for how, out in stego._decodings(data, stego._keys(keys)):   # encoded / XOR-ed / compressed
        got = stego.identify(out)
        if got:
            return how, out[:got[1]], got[0]
    return None


def sweep(paths: Any, original: Path, tree: list[dict[str, Any]],
          pending: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Children ({path, filename, origin, recipe, source, finding}) for the files
    hidden in the case's images and PE resources. ``pending`` = children already
    queued for the nested scan (their files are not reported twice)."""
    from . import stego
    keys = case_keys(paths)
    allsh, done = _nested_shas(tree)
    for it in pending or []:
        try:
            allsh.add(hashlib.sha256(Path(it["path"]).read_bytes()).hexdigest())
        except (OSError, KeyError):
            continue
    out_dir = paths.extracted_dir / DIRNAME
    found: dict[str, dict[str, Any]] = {}

    def add(label: str, where: str, how: str, payload: bytes, kind: str, severity: str) -> None:
        sha = hashlib.sha256(payload).hexdigest()
        if sha in allsh or sha in found:
            return
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = f"{label}.{kind}".replace("/", "_")[-120:]
        p = out_dir / f"{sha[:12]}_{fname}"
        p.write_bytes(payload)
        found[sha] = {"path": str(p), "filename": fname, "origin": f"hidden in {where} ({how})",
                      "recipe": ["hidden", where, how], "source": "hidden",
                      "finding": {"tool": "stego", "rule": "stego:payload", "severity": severity,
                                  "detail": f"{kind.upper()} hidden in {where} ({len(payload)} bytes)",
                                  "evidence": how, "attack": "T1027.003"}}

    # 1. every image the case extracted (not only the ones analysed as children)
    files = []
    if paths.extracted_dir.is_dir():
        for p in sorted(paths.extracted_dir.rglob("*")):
            if len(files) >= MAX_FILES:
                break
            if p.is_file() and DIRNAME not in p.relative_to(paths.extracted_dir).parts[:1]:
                files.append(p)
    pes: list[tuple[str, bytes]] = []
    try:
        od = original.read_bytes()
        if od[:2] == b"MZ":
            pes.append((original.name, od))
        elif stego.is_image(od) and hashlib.sha256(od).hexdigest() not in done:
            got = stego.extract(od, keys)
            if got:
                add(f"{original.stem}.hidden", f"the image {original.name}", got[0], got[1], got[2], "high")
    except OSError:
        pass
    for p in files:
        try:
            if p.stat().st_size > MAX_SIZE:
                continue
            with p.open("rb") as fh:
                head = fh.read(16)
            if head[:2] == b"MZ" and len(pes) < MAX_PES:
                pes.append((p.name, p.read_bytes()))
                continue
            if not stego.is_image(head):
                continue
            data = p.read_bytes()
            if hashlib.sha256(data).hexdigest() in done:
                continue
            got = stego.extract(data, keys)
            if got:
                add(f"{p.stem}.hidden", f"the image {p.name}", got[0], got[1], got[2], "high")
        except OSError:
            continue
    # 2. native resources of every PE of the case
    for name, data in pes:
        for label, raw in _pe_resources(data):
            try:
                got = _try(raw, keys)
            except Exception as exc:  # noqa: BLE001
                log.debug("hidden: %s %s: %s", name, label, exc)
                continue
            if got:
                how, payload, kind = got
                sev = "medium" if how == "stored as it is" else "high"   # installers do store files as they are
                add(f"{Path(name).stem}.{label}", f"the resource {label} of {name}", how, payload, kind, sev)
    return list(found.values())
