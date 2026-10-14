"""Case lifecycle: create, list and read cases.

A case holds exactly one input file. Creating a case:
  1. assigns a unique ``analysis_id`` and an isolated folder ``cases/<id>/``,
  2. stores the uploaded file unmodified under ``original/`` (best-effort
     read-only) and computes MD5/SHA-1/SHA-256 in one streaming pass,
  3. writes a versioned ``case.json`` manifest and a small ``summary.json``.

Reopening and re-analysis are built in later phases; this module does not run
any parser or execute file content.
"""

from __future__ import annotations

import os
import re
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__
from .errors import CaseError, StorageError
from .hashing import copy_and_hash
from .identify import identify
from .logging_config import get_logger
from .storage import CasePaths, read_json, write_json

log = get_logger(__name__)

SCHEMA_VERSION = 1

# Normalized case states (subset relevant to the lifecycle so far).
STATE_CREATED = "created"
STATE_ANALYZING = "analyzing"
STATE_PARTIAL = "partial"
STATE_COMPLETED = "completed"
STATE_ERROR = "error"

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_MAX_NAME = 120


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_analysis_id() -> str:
    """Timestamped, filesystem-safe, unique id. Doubles as the folder name."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{ts}-{uuid.uuid4().hex[:8]}"


def safe_filename(name: str) -> str:
    """Return a safe storage name, preserving the extension where possible.
    The original name is always kept verbatim in the manifest."""
    name = os.path.basename(name or "").strip()
    name = _UNSAFE.sub("_", name).lstrip(".")
    if not name:
        name = "original.bin"
    if len(name) > _MAX_NAME:
        root, ext = os.path.splitext(name)
        name = root[: _MAX_NAME - len(ext)] + ext
    return name


def _declared_extension(name: str) -> str:
    return os.path.splitext(name or "")[1].lower()


def create_case(
    src: BinaryIO, original_filename: str, cases_dir: Path | None = None
) -> dict[str, Any]:
    """Create a new case from an open binary stream. Returns the manifest."""
    analysis_id = new_analysis_id()
    paths = CasePaths(analysis_id, cases_dir=cases_dir)
    if paths.root.exists():  # astronomically unlikely, but never clobber
        raise CaseError(f"Case folder already exists: {analysis_id}")
    paths.ensure_dirs()

    stored_name = safe_filename(original_filename)
    dest = paths.original_dir / stored_name
    try:
        hashes, size = copy_and_hash(src, dest)
    except OSError as exc:
        raise CaseError(f"Could not store the original file: {exc}") from exc

    # Best-effort immutability: make the stored original read-only.
    try:
        os.chmod(dest, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        log.warning("Could not set original read-only: %s", dest)

    declared_ext = _declared_extension(original_filename)

    # Primary identification with libmagic (does not execute content).
    ident = identify(dest, declared_ext)
    tool_versions = {"docutracex": __version__}
    if ident.get("tool_version"):
        tool_versions["libmagic"] = ident["tool_version"]

    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analysis_id": analysis_id,
        "created_utc": _now(),
        "updated_utc": _now(),
        "state": STATE_CREATED,
        "original": {
            "filename": original_filename,
            "stored_path": str(dest.relative_to(paths.root).as_posix()),
            "declared_extension": declared_ext,
            "size_bytes": size,
            "hashes": hashes,
        },
        "format": {
            "declared": declared_ext,
            "detected": {
                "mime": ident.get("mime"),
                "name": ident.get("name"),
                "tool": ident.get("tool"),
                "tool_version": ident.get("tool_version"),
                "available": ident.get("available"),
                "error": ident.get("error"),
            },
            "discrepancy": ident.get("discrepancy"),
        },
        "tool_versions": tool_versions,
        "limits": {},
        "errors": [],
    }
    write_json(paths.manifest, manifest)
    write_json(paths.summary, _summary_from_manifest(manifest))
    log.info("Created case %s (%s, %d bytes)", analysis_id, original_filename, size)
    return manifest


def _summary_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Minimal data for the case list / Overview (fast to read)."""
    orig = manifest["original"]
    fmt = manifest["format"]
    detected = fmt.get("detected") or {}
    discrepancy = fmt.get("discrepancy") or {}
    return {
        "analysis_id": manifest["analysis_id"],
        "created_utc": manifest["created_utc"],
        "updated_utc": manifest["updated_utc"],
        "state": manifest["state"],
        "filename": orig["filename"],
        "size_bytes": orig["size_bytes"],
        "sha256": orig["hashes"].get("sha256"),
        "declared_extension": orig["declared_extension"],
        "detected_mime": detected.get("mime"),
        "detected_name": detected.get("name"),
        "discrepancy": discrepancy.get("status"),
        "counts": {"components": 0, "findings": 0, "iocs": 0},
    }


def get_case(analysis_id: str, cases_dir: Path | None = None) -> dict[str, Any]:
    """Read a case manifest. Raises CaseError if it does not exist."""
    paths = CasePaths(analysis_id, cases_dir=cases_dir)
    manifest = read_json(paths.manifest)
    if manifest is None:
        raise CaseError(f"Case not found: {analysis_id}")
    return manifest


def list_cases(cases_dir: Path | None = None) -> list[dict[str, Any]]:
    """List case summaries, newest first. Reads only the small summary files."""
    from .config import settings

    base = cases_dir or settings.cases_dir
    if not base.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for entry in base.iterdir():
        if not entry.is_dir():
            continue
        try:
            paths = CasePaths(entry.name, cases_dir=base)
        except StorageError:
            continue
        summary = read_json(paths.summary)
        if summary is None:
            # Fall back to the manifest if the summary is missing.
            manifest = read_json(paths.manifest)
            summary = _summary_from_manifest(manifest) if manifest else None
        if summary:
            out.append(summary)
    out.sort(key=lambda s: s.get("created_utc", ""), reverse=True)
    return out
