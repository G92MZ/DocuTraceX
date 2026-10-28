"""Hex tab: read-only byte access to the files of a case.

Every file the case holds — the original and everything under ``extracted/``
(archive members, nested children, unpacked / debloated / decrypted stages) —
can be opened in the Hex tab. The browser never receives a whole file: it asks
for windows of bytes, for search hits and for an entropy profile.

Only files inside the case folder are served (path checked by the API), and
nothing is ever written.
"""

from __future__ import annotations

import base64
import math
import mmap
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

MAX_WINDOW = 64 * 1024
MAX_HITS = 1000
MAX_FILES = 3000
REGEX_TIMEOUT = 20
ENTROPY_BLOCKS = 512
_SKIP_TOP = ("code",)            # extracted/code: the app's own source dumps (still text, but noise here)


def list_files(root: Path, nested_tree: list[dict[str, Any]] | None = None,
               original_rel: str = "") -> list[dict[str, Any]]:
    """Files of the case: ``{path, label, size, group}``, original first."""
    labels: dict[str, str] = {}

    def walk(nodes: list[dict[str, Any]], chain: str) -> None:
        for n in nodes or []:
            here = f"{chain} › {n.get('filename', '')}" if chain else n.get("filename", "")
            if n.get("stored_path"):
                labels[n["stored_path"]] = f"nested › {here}"
            walk(n.get("children") or [], here)

    walk(nested_tree or [], "")
    out: list[dict[str, Any]] = []
    if original_rel and (root / original_rel).is_file():
        out.append({"path": original_rel, "label": f"original › {Path(original_rel).name}",
                    "size": (root / original_rel).stat().st_size, "group": "original"})
    ext = root / "extracted"
    if ext.is_dir():
        for p in sorted(ext.rglob("*")):
            if len(out) >= MAX_FILES:
                break
            if not p.is_file() or p.is_symlink():
                continue
            rel = p.relative_to(root).as_posix()
            parts = p.relative_to(ext).parts
            if parts and parts[0] in _SKIP_TOP:
                continue
            out.append({"path": rel, "label": labels.get(rel) or rel.removeprefix("extracted/"),
                        "size": p.stat().st_size, "group": "nested" if rel in labels else "extracted"})
    return out


def read(target: Path, offset: int, length: int) -> dict[str, Any]:
    size = target.stat().st_size
    offset = max(0, min(int(offset), size))
    length = max(0, min(int(length), MAX_WINDOW, size - offset))
    with target.open("rb") as fh:
        fh.seek(offset)
        data = fh.read(length)
    return {"offset": offset, "size": size, "data": base64.b64encode(data).decode("ascii")}


def entropy(target: Path, blocks: int = ENTROPY_BLOCKS) -> dict[str, Any]:
    """Shannon entropy (0–8) of ``blocks`` equal slices of the file (each
    sampled over at most 64 KB), for the overview strip."""
    size = target.stat().st_size
    if size == 0:
        return {"size": 0, "block": 0, "values": []}
    blocks = max(1, min(blocks, math.ceil(size / 256)))      # >= 256 bytes per block
    step = math.ceil(size / blocks)
    vals = []
    with target.open("rb") as fh:
        for i in range(0, size, step):
            fh.seek(i)
            chunk = fh.read(min(step, 65536))
            if not chunk:
                break
            counts = [0] * 256
            for b in chunk:
                counts[b] += 1
            n = len(chunk)
            vals.append(round(abs(-sum(c / n * math.log2(c / n) for c in counts if c)), 3))
    return {"size": size, "block": step, "values": vals}


def _pattern(mode: str, query: str) -> tuple[bytes | None, re.Pattern[bytes] | None]:
    """Literal bytes, or a compiled bytes regex, for a search mode."""
    if mode == "hex":
        compact = re.sub(r"[\s,]|0x", "", query, flags=re.I)
        if not re.fullmatch(r"(?:\?\?|[0-9a-fA-F]{2})+", compact) or set(compact) <= {"?"}:
            raise ValueError("hex query: pairs of hex digits, ?? as a wildcard byte (e.g. 4D 5A ?? 00)")
        toks = re.findall(r"\?\?|[0-9a-fA-F]{2}", compact)
        if "??" not in toks:
            return bytes.fromhex("".join(toks)), None
        return None, re.compile(b"".join(b"." if t == "??" else re.escape(bytes.fromhex(t)) for t in toks), re.S)
    if mode == "ascii":
        return query.encode("latin-1", "replace"), None
    if mode == "utf16":
        return query.encode("utf-16-le"), None
    if mode == "regex":
        return None, re.compile(query.encode("latin-1", "replace"), re.S)
    raise ValueError(f"unknown search mode {mode!r}")


def search(target: Path, mode: str, query: str, start: int = 0, max_hits: int = MAX_HITS,
           ignore_case: bool = False) -> dict[str, Any]:
    """Offsets of ``query`` in the file. Literal modes use mmap.find; a regex
    (or a hex pattern with ?? wildcards) runs in a child process with a time
    limit, so a pathological pattern cannot hang the web service."""
    if not query:
        return {"hits": [], "truncated": False}
    lit, rx = _pattern(mode, query)
    if ignore_case and mode in ("ascii", "utf16") and lit is not None:
        lit, rx = None, re.compile(re.escape(lit), re.I | re.S)
    size = target.stat().st_size
    if size == 0:
        return {"hits": [], "truncated": False, "length": len(lit or b"")}
    if lit is not None:
        hits = []
        with target.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            i = mm.find(lit, max(0, start))
            while i != -1 and len(hits) < max_hits:
                hits.append([i, len(lit)])
                i = mm.find(lit, i + 1)
            more = i != -1
        return {"hits": hits, "truncated": more}
    code = ("import mmap,re,sys,json\n"
            "p,pat,fl,start,mx=sys.argv[1],bytes.fromhex(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]),int(sys.argv[5])\n"
            "rx=re.compile(pat,fl)\n"
            "f=open(p,'rb');mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)\n"
            "h=[]\n"
            "for m in rx.finditer(mm,start):\n"
            "    h.append([m.start(),max(1,m.end()-m.start())])\n"
            "    if len(h)>mx: break\n"
            "print(json.dumps(h))\n")
    try:
        r = subprocess.run([sys.executable, "-c", code, str(target), rx.pattern.hex(),
                            str(int(rx.flags & (re.I | re.S | re.M))), str(max(0, start)), str(max_hits)],
                           capture_output=True, text=True, timeout=REGEX_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"hits": [], "truncated": False, "error": f"pattern took longer than {REGEX_TIMEOUT}s — simplify it"}
    if r.returncode != 0:
        return {"hits": [], "truncated": False, "error": (r.stderr.strip().splitlines() or ["regex failed"])[-1][:200]}
    import json
    hits = json.loads(r.stdout or "[]")
    return {"hits": hits[:max_hits], "truncated": len(hits) > max_hits}


# --- structures (colouring + jumps) ---------------------------------------------------

def structures(target: Path) -> list[dict[str, Any]]:
    """Named byte ranges of the file itself, for colouring and jumps:
    PE (DOS header / stub / Rich / NT headers / data directories / section
    table / sections / overlay / directory contents) or ELF (header, program
    and section headers, sections). ``kind`` drives the colour."""
    try:
        with target.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return []
    if head[:2] == b"MZ":
        return _pe_structures(target)
    if head == b"\x7fELF":
        return _elf_structures(target)
    return []


def _r(name: str, kind: str, off: int, length: int, size: int) -> dict[str, Any] | None:
    off, length = int(off), int(length)
    if length <= 0 or off < 0 or off >= size:
        return None
    return {"name": name, "kind": kind, "offset": off, "length": min(length, size - off)}


def _pe_structures(target: Path) -> list[dict[str, Any]]:
    try:
        import pefile
    except ImportError:
        return []
    size = target.stat().st_size
    try:
        pe = pefile.PE(str(target), fast_load=True)
    except Exception:  # noqa: BLE001 - not a parseable PE: just the DOS header
        return [x for x in [_r("DOS header", "header", 0, 64, size)] if x]
    out = []
    e_lfanew = pe.DOS_HEADER.e_lfanew
    out.append(_r("DOS header", "header", 0, 64, size))
    rich = pe.get_data(0, min(e_lfanew, 0x400)) if e_lfanew else b""
    ri = rich.find(b"Rich")
    if ri > 0:
        # DanS is XOR-ed with the key that follows "Rich"
        key = rich[ri + 4:ri + 8]
        dans = bytes(a ^ b for a, b in zip(b"DanS", key))
        di = rich.find(dans)
        if 0 < di < ri:
            out.append(_r("DOS stub", "stub", 64, di - 64, size))
            out.append(_r("Rich header", "rich", di, ri + 8 - di, size))
        else:
            out.append(_r("DOS stub", "stub", 64, e_lfanew - 64, size))
    else:
        out.append(_r("DOS stub", "stub", 64, e_lfanew - 64, size))
    out.append(_r("PE signature", "header", e_lfanew, 4, size))
    out.append(_r("COFF header", "header", e_lfanew + 4, 20, size))
    opt_off = e_lfanew + 24
    opt_size = pe.FILE_HEADER.SizeOfOptionalHeader
    out.append(_r("optional header", "header", opt_off, opt_size, size))
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if dd:
        dd_off = dd[0].get_file_offset()
        out.append(_r("data directories", "table", dd_off, 8 * len(dd), size))
    sec_off = opt_off + opt_size
    out.append(_r("section table", "table", sec_off, 40 * len(pe.sections), size))
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace") or "?"
        kind = "code" if s.Characteristics & 0x20000020 else ("rsrc" if name == ".rsrc" else "data")
        out.append(_r(f"section {name}", kind, s.PointerToRawData, s.SizeOfRawData, size))
    names = {0: "export directory", 1: "import directory", 2: "resources", 3: "exception directory",
             5: "relocations", 6: "debug directory", 9: "TLS directory", 10: "load config",
             12: "import address table", 14: ".NET (COR20) header"}
    for i, name in names.items():
        if i < len(dd) and dd[i].VirtualAddress and dd[i].Size:
            try:
                off = pe.get_offset_from_rva(dd[i].VirtualAddress)
            except Exception:  # noqa: BLE001
                continue
            if off is not None:
                out.append(_r(name, "dir", off, dd[i].Size, size))
    if len(dd) > 14 and dd[14].VirtualAddress and dd[14].Size:    # .NET: metadata + managed resources
        try:
            import struct as _st
            cor = pe.get_data(dd[14].VirtualAddress, 32)
            md_rva, md_size = _st.unpack_from("<II", cor, 8)
            res_rva, res_size = _st.unpack_from("<II", cor, 24)
            if md_rva and md_size:
                out.append(_r(".NET metadata (BSJB)", "dir", pe.get_offset_from_rva(md_rva), md_size, size))
            if res_rva and res_size:
                out.append(_r(".NET managed resources", "rsrc", pe.get_offset_from_rva(res_rva), res_size, size))
        except Exception:  # noqa: BLE001
            pass
    if len(dd) > 4 and dd[4].VirtualAddress and dd[4].Size:       # security: a file offset
        out.append(_r("Authenticode signature", "sig", dd[4].VirtualAddress, dd[4].Size, size))
    ov = pe.get_overlay_data_start_offset()
    if ov is not None and ov < size:
        sig = dd[4].VirtualAddress if len(dd) > 4 and dd[4].Size else 0
        if not (sig and sig == ov and sig + dd[4].Size >= size):
            out.append(_r("overlay", "overlay", ov, size - ov, size))
    pe.close()
    return [x for x in out if x]


def _elf_structures(target: Path) -> list[dict[str, Any]]:
    import struct as _st
    size = target.stat().st_size
    with target.open("rb") as fh:
        h = fh.read(64)
        if len(h) < 52:
            return []
        is64, le = h[4] == 2, h[5] == 1
        e = "<" if le else ">"
        try:
            if is64:
                phoff, shoff = _st.unpack_from(e + "QQ", h, 32)
                ehsize, phentsize, phnum, shentsize, shnum, shstrndx = _st.unpack_from(e + "HHHHHH", h, 52)
            else:
                phoff, shoff = _st.unpack_from(e + "II", h, 28)
                ehsize, phentsize, phnum, shentsize, shnum, shstrndx = _st.unpack_from(e + "HHHHHH", h, 40)
        except _st.error:
            return []
        out = [_r("ELF header", "header", 0, ehsize, size),
               _r("program headers", "table", phoff, phentsize * phnum, size),
               _r("section headers", "table", shoff, shentsize * shnum, size)]
        secs = []
        if shoff and shentsize and shnum and shoff + shentsize * shnum <= size:
            fh.seek(shoff)
            tbl = fh.read(shentsize * shnum)
            for i in range(shnum):
                ent = tbl[i * shentsize:(i + 1) * shentsize]
                if is64:
                    name, typ, flags, _addr, off, sz = _st.unpack_from(e + "IIQQQQ", ent)
                else:
                    name, typ, flags, _addr, off, sz = _st.unpack_from(e + "IIIIII", ent)
                secs.append((name, typ, flags, off, sz))
            names = b""
            if shstrndx < len(secs):
                _, _, _, so, ss = secs[shstrndx]
                fh.seek(so)
                names = fh.read(min(ss, 65536))
            for name, typ, flags, off, sz in secs:
                if typ in (0, 8) or not sz:            # NULL / NOBITS (.bss)
                    continue
                nm = names[name:names.find(b"\x00", name)].decode("latin-1", "replace") if name < len(names) else "?"
                kind = "code" if flags & 4 else "data"
                out.append(_r(f"section {nm or '?'}", kind, off, sz, size))
    return [x for x in out if x]


# --- decode recipes ------------------------------------------------------------------

MAX_DECODE = 32 * 1024 * 1024
OPS = ("base64", "hex", "xor", "zlib", "reverse")


def parse_recipe(text: str) -> list[tuple[str, str]]:
    """``"base64 | xor 41 | zlib"`` → [("base64", ""), ("xor", "41"), ("zlib", "")]."""
    steps = []
    for part in re.split(r"[|→>]+", text or ""):
        part = part.strip()
        if not part:
            continue
        op, _, arg = part.partition(" ")
        op = op.lower()
        if op not in OPS:
            raise ValueError(f"unknown step {op!r} (use {', '.join(OPS)})")
        steps.append((op, arg.strip()))
    if len(steps) > 8:
        raise ValueError("at most 8 steps")
    return steps


def _printable_score(b: bytes) -> float:
    if not b:
        return 0.0
    sample = b[:4096]
    ok = sum(1 for c in sample if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(sample)


_MAGICS = (b"MZ", b"%PDF", b"PK\x03\x04", b"\x7fELF", b"\xd0\xcf\x11\xe0", b"7z\xbc\xaf", b"Rar!", b"\x1f\x8b")


def _xor_auto(data: bytes) -> tuple[bytes, int]:
    """Single-byte XOR key that gives a known magic, else the most printable output."""
    best, best_key, best_score = data, 0, -1.0
    for k in range(1, 256):
        head = bytes(c ^ k for c in data[:8])
        if any(head.startswith(m) for m in _MAGICS):
            return bytes(c ^ k for c in data), k
        s = _printable_score(bytes(c ^ k for c in data[:4096]))
        if s > best_score:
            best_score, best_key = s, k
    return bytes(c ^ best_key for c in data), best_key


def apply_recipe(data: bytes, steps: list[tuple[str, str]]) -> tuple[bytes, list[str]]:
    """Run decode steps; returns (bytes, the steps as applied — auto keys resolved)."""
    import binascii
    import zlib

    done: list[str] = []
    for op, arg in steps:
        if op == "base64":
            compact = re.sub(rb"[^A-Za-z0-9+/=_-]", b"", data)
            compact = compact.replace(b"-", b"+").replace(b"_", b"/")
            compact += b"=" * (-len(compact) % 4)
            try:
                data = base64.b64decode(compact)
            except binascii.Error as exc:
                raise ValueError(f"base64: {exc}") from exc
            done.append("base64")
        elif op == "hex":
            compact = re.sub(rb"[^0-9A-Fa-f]", b"", re.sub(rb"0x|\\x", b"", data))
            if len(compact) % 2:
                raise ValueError("hex: odd number of digits")
            data = bytes.fromhex(compact.decode())
            done.append("hex")
        elif op == "xor":
            if not arg or arg.lower() == "auto":
                data, k = _xor_auto(data)
                done.append(f"xor 0x{k:02x} (auto)")
            else:
                key_txt = re.sub(r"0x|\\x|[\s,]", "", arg)
                if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}){1,64}", key_txt):
                    raise ValueError("xor: key in hex bytes (e.g. 41 or 0x6b6579) or 'auto'")
                key = bytes.fromhex(key_txt)
                data = bytes(c ^ key[i % len(key)] for i, c in enumerate(data))
                done.append(f"xor 0x{key.hex()}")
        elif op == "zlib":
            out = None
            for wbits, label in ((31, "gzip"), (15, "zlib"), (-15, "deflate")):
                try:
                    d = zlib.decompressobj(wbits)
                    got = d.decompress(data, MAX_DECODE * 2)
                    if got:
                        out = got
                        done.append(f"inflate ({label})")
                        break
                except zlib.error:
                    continue
            if out is None:
                raise ValueError("zlib: not gzip / zlib / raw deflate data")
            data = out
        elif op == "reverse":
            data = data[::-1]
            done.append("reverse")
    return data, done


def _magic_name(b: bytes) -> str:
    for m, name in ((b"MZ", "PE / MZ"), (b"%PDF", "PDF"), (b"PK\x03\x04", "ZIP / OOXML / JAR / APK"),
                    (b"\x7fELF", "ELF"), (b"\xd0\xcf\x11\xe0", "OLE (Office 97-2003 / MSI)"),
                    (b"7z\xbc\xaf", "7-Zip"), (b"Rar!", "RAR"), (b"\x1f\x8b", "gzip"), (b"{\\rtf", "RTF")):
        if b.startswith(m):
            return name
    return "text" if _printable_score(b) > 0.9 else "data"


def _entropy_of(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for c in b[:1 << 20]:
        counts[c] += 1
    n = min(len(b), 1 << 20)
    return round(abs(-sum(c / n * math.log2(c / n) for c in counts if c)), 3)


def decode_preview(target: Path, offset: int, length: int, recipe: str) -> dict[str, Any]:
    """Decode a byte range with a recipe; preview (first 4 KB), size, type, entropy."""
    size = target.stat().st_size
    offset = max(0, min(int(offset), size))
    length = max(0, min(int(length), size - offset))
    if length > MAX_DECODE:
        raise ValueError(f"selection too large to decode (max {MAX_DECODE >> 20} MB)")
    with target.open("rb") as fh:
        fh.seek(offset)
        data = fh.read(length)
    out, done = apply_recipe(data, parse_recipe(recipe))
    return {"size": len(out), "recipe": done, "type": _magic_name(out), "entropy": _entropy_of(out),
            "data": base64.b64encode(out[:4096]).decode("ascii")}


# --- "extract selection as nested" --------------------------------------------------

EXTRACTS_FILE = "hex_extracts.json"
EXTRACT_DIR = "hex"
MAX_EXTRACTS = 64


def _ext_for(b: bytes) -> str:
    for m, ext in ((b"MZ", ".bin.exe"), (b"%PDF", ".pdf"), (b"PK\x03\x04", ".zip"), (b"\x7fELF", ".elf"),
                   (b"\xd0\xcf\x11\xe0", ".ole"), (b"7z\xbc\xaf", ".7z"), (b"Rar!", ".rar"), (b"{\\rtf", ".rtf"),
                   (b"\x1f\x8b", ".gz")):
        if b.startswith(m):
            return ext
    return ".txt" if _printable_score(b) > 0.9 else ".bin"


def load_extracts(root: Path) -> list[dict[str, Any]]:
    import json
    try:
        data = json.loads((root / EXTRACTS_FILE).read_text(encoding="utf-8"))
        return [x for x in data.get("extracts") or [] if isinstance(x, dict)]
    except (OSError, ValueError):
        return []


def save_extracts(root: Path, items: list[dict[str, Any]]) -> None:
    import json
    (root / EXTRACTS_FILE).write_text(json.dumps({"extracts": items}, indent=1), encoding="utf-8")


def add_extract(root: Path, rel: str, offset: int, length: int, recipe: str, name: str = "") -> dict[str, Any]:
    """Record an extraction (validated by decoding it now). The analysis pipeline
    re-creates the file from this spec on every run (see ``materialize``)."""
    target = (root / rel).resolve()
    if length <= 0:
        raise ValueError("empty selection")
    prev = decode_preview(target, offset, length, recipe)     # raises on a bad recipe / range
    items = load_extracts(root)
    if len(items) >= MAX_EXTRACTS:
        raise ValueError(f"at most {MAX_EXTRACTS} extractions per case")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "")[:60].strip("._")
    spec = {"path": rel, "offset": int(offset), "length": int(length), "recipe": recipe or "",
            "name": safe, "steps": prev["recipe"]}
    items.append(spec)
    save_extracts(root, items)
    return {**spec, "index": len(items) - 1, "size": prev["size"], "type": prev["type"]}


def materialize(root: Path, extracted_dir: Path) -> list[dict[str, Any]]:
    """Write every recorded extraction under ``extracted/hex/`` and return the
    items for ``nested.scan_children`` (``source: hex``, recipe = the steps).
    Specs are applied in order, so one can start from an earlier extraction."""
    import shutil
    out_dir = extracted_dir / EXTRACT_DIR
    shutil.rmtree(out_dir, ignore_errors=True)
    items = []
    for i, sp in enumerate(load_extracts(root)):
        try:
            src = (root / sp["path"]).resolve()
            src.relative_to(root.resolve())
            if not src.is_file():
                continue
            with src.open("rb") as fh:
                fh.seek(int(sp["offset"]))
                data = fh.read(min(int(sp["length"]), MAX_DECODE))
            data, done = apply_recipe(data, parse_recipe(sp.get("recipe") or ""))
        except (OSError, ValueError, KeyError) as exc:
            log_warn(f"hex extraction #{i + 1} skipped: {exc}")
            continue
        if not data:
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        base = sp.get("name") or f"{Path(sp['path']).name}_0x{int(sp['offset']):x}"
        dest = out_dir / f"{i + 1:02d}_{base}{'' if Path(base).suffix else _ext_for(data)}"
        dest.write_bytes(data)
        src_label = sp["path"].removeprefix("extracted/")
        items.append({"path": str(dest), "filename": dest.name, "source": "hex",
                      "origin": f"hex: {src_label} @ 0x{int(sp['offset']):x} (+{int(sp['length'])} B)",
                      "recipe": [f"hex selection 0x{int(sp['offset']):x} +{int(sp['length'])}"] + done})
    return items


def log_warn(msg: str) -> None:
    from .logging_config import get_logger
    get_logger(__name__).warning(msg)
