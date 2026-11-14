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

import base64
import binascii
import hashlib
import re
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


def _signed(pe: bytes) -> bool:
    """The PE carries an Authenticode signature (its security directory is set)."""
    try:
        e = struct.unpack_from("<I", pe, 0x3C)[0]
        if pe[e:e + 4] != b"PE\x00\x00":
            return False
        opt = e + 24
        dd = opt + (96 if struct.unpack_from("<H", pe, opt)[0] == 0x10B else 112)
        va, size = struct.unpack_from("<II", pe, dd + 4 * 8)
        return bool(va and size)
    except struct.error:
        return False


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
        fname = f"{label.replace('/', '_')[:110]}.{kind}"          # cut at the end: the name stays readable
        p = out_dir / f"{sha[:12]}_{fname}"
        p.write_bytes(payload)
        stored = how == "stored as it is"
        found[sha] = {"path": str(p), "filename": fname,
                      "origin": f"{'stored in' if stored else 'hidden in'} {where}" + ("" if stored else f" ({how})"),
                      "recipe": ["hidden", where, how], "source": "hidden",
                      # a file kept as it is in a resource is how installers ship files, not steganography
                      "finding": ({"tool": "pe", "rule": "pe:resource_file", "severity": severity,
                                   "detail": f"{kind.upper()} stored as it is in {where} ({len(payload)} bytes)"
                                             + (" — normal for a signed installer / bootstrapper" if severity == "info" else ""),
                                   "evidence": how, "attack": "T1027.009"} if stored else
                                  {"tool": "stego", "rule": "stego:payload", "severity": severity,
                                   "detail": f"{kind.upper()} hidden in {where} ({len(payload)} bytes)",
                                   "evidence": how, "attack": "T1027.003"})}

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
                # installers do store files as they are; a signed one carrying signed files is routine
                sev = (("info" if _signed(data) and (kind not in ("exe", "dll") or _signed(payload)) else "medium")
                       if how == "stored as it is" else "high")
                add(f"{Path(name).stem}.{label}", f"the resource {label} of {name}", how, payload, kind, sev)
    return list(found.values())


# --- images as objects of their own ---------------------------------------------
# The sweep above only reports an image that hides something. The analyst also
# wants to *see* the images a document or a binary carries (a logo, a lure
# screenshot, an icon imitating a PDF): the Office media and the images in the
# native resources of each PE become children too, with where they came from.
IMG_DIR = "images"
MAX_IMAGES = 200
_IMG_EXT = {b"\x89PNG": "png", b"\xff\xd8\xff": "jpg", b"GIF8": "gif", b"BM": "bmp", b"RIFF": "webp",
            b"\x00\x00\x01\x00": "ico", b"II*\x00": "tif", b"MM\x00*": "tif"}


def _ext(data: bytes) -> str:
    return next((e for m, e in _IMG_EXT.items() if data.startswith(m)), "")


def _ico_from_icon(raw: bytes) -> bytes | None:
    """RT_ICON holds one image (a PNG, or a DIB without file header): wrap it as a .ico."""
    if raw.startswith(b"\x89PNG"):
        return raw
    if len(raw) < 40 or struct.unpack_from("<I", raw)[0] != 40:
        return None
    w, h2 = struct.unpack_from("<ii", raw, 4)
    bpp = struct.unpack_from("<H", raw, 14)[0]
    if not (0 < w <= 1024 and 0 < h2 <= 2048):
        return None
    entry = struct.pack("<BBBBHHII", w & 0xFF, (h2 // 2) & 0xFF, 0, 0, 1, bpp, len(raw), 22)
    return struct.pack("<HHH", 0, 1, 1) + entry + raw


def _pe_images(data: bytes) -> list[tuple[str, bytes]]:
    """(label, image file) of every image in the native resources of a PE."""
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception:  # noqa: BLE001
        return []
    out: list[tuple[str, bytes]] = []
    for t in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or []:
        tid = t.id if t.id is not None else str(t.name)
        if tid in (4, 5, 6, 9, 11, 14, 16, 24):              # menus, dialogs, strings, accelerators, groups, version, manifest
            continue
        tname = {2: "RT_BITMAP", 3: "RT_ICON", 10: "RT_RCDATA", 23: "RT_HTML"}.get(tid, str(tid))
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
                img = (_bmp_from_dib(raw) if tid == 2 else _ico_from_icon(raw) if tid == 3
                       else raw if _ext(raw) else None)
                if img and len(img) >= 32:
                    out.append((f"{tname}/{name}", img))
                if len(out) >= MAX_IMAGES:
                    return out
    return out


_MARKUP_EXT = (".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml", ".hta", ".eml")
_DATA_URI = re.compile(rb"data:image/(?:png|jpe?g|gif|bmp|webp|x-icon|vnd\.microsoft\.icon);base64,\s*([A-Za-z0-9+/=\s]{64,})",
                       re.IGNORECASE)
_PICT = re.compile(rb"\\(?:pngblip|jpegblip)[^{}]*?(?<![0-9A-Za-z])((?:[0-9a-fA-F]{2}\s*){64,})")
MAX_MARKUP = 8 * 1024 * 1024
MAX_MARKUP_FILES = 40


def _data_uri_images(src: bytes) -> list[bytes]:
    """Images written inline as base64 ``data:`` URIs (a logo, a lure, a QR)."""
    out = []
    for m in _DATA_URI.finditer(src):
        try:
            img = base64.b64decode(re.sub(rb"\s+", b"", m.group(1)), validate=False)
        except (ValueError, binascii.Error):
            continue
        if _ext(img) and len(img) >= 64:
            out.append(img)
        if len(out) >= MAX_IMAGES:
            break
    return out


def _rtf_pictures(src: bytes) -> list[bytes]:
    """PNG / JPEG pictures of an RTF (``\\pict`` with ``\\pngblip`` / ``\\jpegblip``, hex data)."""
    out = []
    for m in _PICT.finditer(src):
        try:
            img = bytes.fromhex(re.sub(rb"\s+", b"", m.group(1)).decode("ascii"))
        except ValueError:
            continue
        if _ext(img):
            out.append(img)
        if len(out) >= MAX_IMAGES:
            break
    return out


def _markup_sources(paths: Any, original: Path) -> list[tuple[str, str, bytes]]:
    """(label, "datauri" | "pict", bytes) of the markup and RTF files of the case: the
    file itself, the email's HTML body, and the HTML / SVG / MHT / RTF files extracted."""
    out: list[tuple[str, str, bytes]] = []

    def take(p: Path, label: str) -> None:
        try:
            if p.stat().st_size > MAX_MARKUP:
                return
            data = p.read_bytes()
        except OSError:
            return
        if data.lstrip()[:5] == b"{\\rtf":
            out.append((label, "pict", data))
        elif b"data:image/" in data:
            out.append((label, "datauri", data))

    take(original, original.name)
    em = read_json(paths.subresult("email")) or {}
    body = em.get("_html_source") or em.get("html_source_sample") or ""
    if "data:image/" in body:
        out.append((f"the HTML body of {original.name}", "datauri", body.encode("utf-8", "replace")))
    if paths.extracted_dir.is_dir():
        n = 0
        for p in sorted(paths.extracted_dir.rglob("*")):
            if n >= MAX_MARKUP_FILES:
                break
            try:
                rel = p.relative_to(paths.extracted_dir)
            except ValueError:
                continue
            if rel.parts[:1] == (IMG_DIR,) or not p.is_file():
                continue
            if p.suffix.lower() in _MARKUP_EXT + (".rtf", ".doc"):
                n += 1
                take(p, p.name)
    return out


def images(paths: Any, original: Path, tree: list[dict[str, Any]],
           pending: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Children for the images of the case that are not objects yet: Office
    media (``word/media/…``, ``ppt/media/…``, ``xl/media/…``) and the images in
    the native resources of every PE (bitmaps, icons, images in RCDATA or custom
    resources). Duplicates (same SHA-256) and images already in the tree are skipped."""
    allsh, _done = _nested_shas(tree)
    for it in pending or []:
        try:
            allsh.add(hashlib.sha256(Path(it["path"]).read_bytes()).hexdigest())
        except (OSError, KeyError):
            continue
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(path: Path, filename: str, origin: str, recipe: list[str]) -> None:
        try:
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return
        if sha in allsh or sha in seen or len(out) >= MAX_IMAGES:
            return
        seen.add(sha)
        out.append({"path": str(path), "filename": filename, "origin": origin, "recipe": recipe, "source": "images"})

    # 1. Office media already extracted by the OOXML engine
    ox = read_json(paths.subresult("ooxml")) or {}
    for e in ox.get("extracted") or []:
        sp = e.get("stored_path") or ""
        if "/media/" not in sp:
            continue
        p = paths.root / sp
        try:
            with p.open("rb") as fh:
                head = fh.read(16)
        except OSError:
            continue
        if _ext(head) or head.startswith((b"\xd7\xcd\xc6\x9a", b"\x01\x00\x00\x00")):   # + WMF / EMF
            part = sp.split("/", 1)[1] if sp.startswith("extracted/") else sp
            add(p, Path(sp).name, f"Office media {part} of {original.name}", ["office-media", part])
    # 2. images written into markup (data: URIs of an HTML / SVG / MHT, the email's HTML body)
    #    and the pictures of an RTF (\pict): files of their own only here
    for label, kind, src in _markup_sources(paths, original):
        for i, img in enumerate(_rtf_pictures(src) if kind == "pict" else _data_uri_images(src)):
            sha = hashlib.sha256(img).hexdigest()
            dest = paths.extracted_dir / IMG_DIR / sha[:12] / f"{kind}-{i + 1}.{_ext(img) or 'img'}"
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(img)
            except OSError:
                continue
            what = "picture" if kind == "pict" else "data: URI image"
            add(dest, dest.name, f"{what} {i + 1} in {label}", [kind, label])
    # 3. images in the native resources of every PE of the case
    pes: list[tuple[str, bytes]] = []
    try:
        od = original.read_bytes()
        if od[:2] == b"MZ":
            pes.append((original.name, od))
    except OSError:
        pass
    if paths.extracted_dir.is_dir():
        for p in sorted(paths.extracted_dir.rglob("*")):
            if len(pes) >= MAX_PES:
                break
            try:
                if p.is_file() and p.stat().st_size <= MAX_SIZE and IMG_DIR not in p.relative_to(paths.extracted_dir).parts[:1]:
                    with p.open("rb") as fh:
                        if fh.read(2) == b"MZ":
                            pes.append((p.name, p.read_bytes()))
            except OSError:
                continue
    for name, data in pes:
        sha = hashlib.sha256(data).hexdigest()
        for label, img in _pe_images(data):
            dest = paths.extracted_dir / IMG_DIR / sha[:12] / (label.replace("/", "_") + "." + (_ext(img) or "img"))
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(img)
            except OSError:
                continue
            add(dest, dest.name, f"image in the resource {label} of {name}", ["pe-resource", label])
    return out

