"""The objects of a case that the on-demand scanners (YARA, Machine Learning,
C2) can look at — the original plus every file extracted, unpacked, decrypted
or carved — with a stable id (``original`` or the path relative to the case
folder), so the analyst can pick which ones a run covers.

Also the shared plumbing for those runs: the one-shot selection file the API
writes before queueing the task, the worker count for parallel scans, and the
merge of a partial run into the previous result."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from .storage import CasePaths, read_json

MAX_OBJECTS = 2000
ON_DEMAND = ("yara", "ml", "c2")


def workers(n_items: int, cap: int | None = None) -> int:
    """Parallel workers for a scan: a few, never more than the CPUs (minus one
    for the app) nor than the items. ``DOCUTRACEX_SCAN_WORKERS`` overrides."""
    try:
        env = int(os.environ.get("DOCUTRACEX_SCAN_WORKERS", "0"))
    except ValueError:
        env = 0
    cpu = max(1, (os.cpu_count() or 2) - 1)
    w = env or min(cap or 4, cpu)
    return max(1, min(w, n_items))


def _kind(head: bytes) -> str:
    if head[:2] == b"MZ":
        return "PE"
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    if head[:5] == b"%PDF-":
        return "PDF"
    if head[:4] == b"PK\x03\x04":
        return "ZIP / OOXML / APK"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE"
    if head[:4] == b"dex\n":
        return "DEX"
    if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:2] in (b"BM", b"\xff\xd8") or head[:4] == b"GIF8":
        return "image"
    if head and sum(1 for c in head if 32 <= c < 127 or c in (9, 10, 13)) >= 0.95 * len(head):
        return "text"
    return "data"


def case_objects(paths: CasePaths, original: Path) -> list[dict[str, Any]]:
    """[{id, label, size, kind}] — the original first, then every file under
    extracted/ (named by its nested chain when the nested scan saw it)."""
    chains: dict[str, str] = {}

    def walk(nodes: list[dict[str, Any]], chain: str) -> None:
        for n in nodes or []:
            here = f"{chain} › {n.get('filename', '')}" if chain else n.get("filename", "")
            if n.get("stored_path"):
                chains[n["stored_path"]] = here
            walk(n.get("children") or [], here)
    walk((read_json(paths.subresult("nested")) or {}).get("tree") or [], "")
    out: list[dict[str, Any]] = []

    def add(oid: str, label: str, p: Path) -> None:
        try:
            size = p.stat().st_size
            with p.open("rb") as fh:
                head = fh.read(512)
        except OSError:
            return
        out.append({"id": oid, "label": label, "size": size, "kind": _kind(head)})
    add("original", f"{original.name} (original)", original)
    ed = paths.extracted_dir
    if ed.is_dir():
        for p in sorted(ed.rglob("*")):
            if len(out) > MAX_OBJECTS:
                break
            if p.is_file():
                rel = p.relative_to(paths.root).as_posix()
                add(rel, chains.get(rel) or rel.removeprefix("extracted/"), p)
    return out


def object_id(paths_root: Path, original: Path, p: Path) -> str:
    try:
        if p.resolve() == original.resolve():
            return "original"
        return p.resolve().relative_to(paths_root.resolve()).as_posix()
    except ValueError:
        return p.name


def selection_file(paths: CasePaths, module: str) -> Path:
    return paths.root / "results" / f".{module}.selection.json"


def save_selection(paths: CasePaths, module: str, ids: list[str] | None) -> None:
    f = selection_file(paths, module)
    if ids is None:
        f.unlink(missing_ok=True)
        return
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"objects": list(ids)}), encoding="utf-8")


def take_selection(paths: CasePaths, module: str) -> set[str] | None:
    """The selection the API saved for this run (read once, then removed)."""
    f = selection_file(paths, module)
    try:
        ids = json.loads(f.read_text(encoding="utf-8")).get("objects")
    except (OSError, ValueError):
        return None
    f.unlink(missing_ok=True)
    return set(ids) if isinstance(ids, list) else None


def merge_partial(prev: dict[str, Any] | None, new: dict[str, Any], only: set[str] | None,
                  lists: dict[str, Callable[[dict[str, Any]], str]]) -> dict[str, Any]:
    """A run over some objects replaces their entries and keeps the others'.
    ``lists`` = {result key: entry → object id}."""
    if not only or not prev:
        new["selection"] = sorted(only) if only else None
        return new
    out = dict(new)
    for key, oid in lists.items():
        old = [e for e in prev.get(key) or [] if oid(e) not in only]
        out[key] = old + list(new.get(key) or [])
    out["selection"] = sorted(only)
    return out
