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


def regions(root: Path, rel: str, modules: dict[str, Any]) -> list[dict[str, Any]]:
    """Named byte ranges to jump to (PE sections, overlay) for this file, from
    the Binary analysis already done (case file or a nested PE view)."""
    out: list[dict[str, Any]] = []
    for it in ((modules.get("msi") or {}).get("items") or []):
        lf = it.get("lief") or {}
        if lf.get("status") != "ok":
            continue
        for s in lf.get("sections") or []:
            if s.get("size"):
                out.append({"name": f"section {s.get('name')}", "offset": s.get("offset", 0), "length": s["size"]})
        ov = lf.get("overlay") or {}
        if ov.get("size"):
            out.append({"name": "overlay", "offset": ov.get("offset", 0), "length": ov["size"]})
    return out
