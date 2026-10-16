"""Case persistence — JSON per case, split by type of information.

Layout inside ``cases/<analysis_id>/`` (relative paths only)::

    case.json            manifest: id, dates, hashes, format, state, tool versions
    original/            immutable copy of the uploaded file
    extracted/           components extracted in isolation
    results/
        summary.json     minimal data to paint Overview / case list (fast read)
        <module>.json    one sub-result per parser/analyzer module
        marks.json       manual classification (TP/FP/...), kept SEPARATE
        tasks.json       attempt/task history for the case
    reports/             generated HTML/JSON report

Design goals:
- The case list and Overview read only ``case.json`` + ``results/summary.json``
  (small files), so they stay fast even with thousands of components.
- Heavy detail (components, findings, iocs) lives in per-module files loaded on
  demand, and very large blobs (reconstructed text, stream dumps) go to separate
  files under ``results/`` or ``extracted/`` referenced by path + hash.
- ``marks.json`` is never overwritten when an automatic analysis is re-run.

This module only defines paths and safe JSON read/write helpers; the case
lifecycle (create, reopen, manifest validation) is built in a later phase.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from .config import settings
from .errors import StorageError
from .logging_config import get_logger

log = get_logger(__name__)


class CasePaths:
    """Resolves the on-disk paths for a single case. All paths are relative
    to the configured ``cases`` directory; nothing escapes the case folder."""

    def __init__(self, analysis_id: str, cases_dir: Path | None = None) -> None:
        if not analysis_id or any(sep in analysis_id for sep in ("/", "\\", "..")):
            raise StorageError(f"Invalid analysis_id: {analysis_id!r}")
        base = (cases_dir or settings.cases_dir).resolve()
        self.root = (base / analysis_id).resolve()
        # Defence in depth: the resolved case root must stay under the cases dir.
        if base not in self.root.parents and self.root != base:
            raise StorageError("Resolved case path escapes the cases directory")

    @property
    def manifest(self) -> Path:
        return self.root / "case.json"

    @property
    def original_dir(self) -> Path:
        return self.root / "original"

    @property
    def extracted_dir(self) -> Path:
        return self.root / "extracted"

    @property
    def results_dir(self) -> Path:
        return self.root / "results"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def summary(self) -> Path:
        return self.results_dir / "summary.json"

    @property
    def marks(self) -> Path:
        return self.results_dir / "marks.json"

    @property
    def tasks(self) -> Path:
        return self.results_dir / "tasks.json"

    @property
    def password(self) -> Path:
        """Password the analyst gave for an encrypted original (kept apart from
        case.json so it isn't served with the manifest)."""
        return self.root / "password.json"

    def subresult(self, module: str) -> Path:
        """Path of a single module's sub-result (e.g. 'pdf', 'ooxml', 'email')."""
        if not module or any(sep in module for sep in ("/", "\\", "..")):
            raise StorageError(f"Invalid module name: {module!r}")
        return self.results_dir / f"{module}.json"

    def ensure_dirs(self) -> None:
        for d in (self.original_dir, self.extracted_dir, self.results_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise StorageError(f"Could not read {path}: {exc}") from exc


def write_json(path: Path, data: Any) -> None:
    """Atomic write: serialise to a temp file in the same dir, then replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
        ) as tmp:
            json.dump(data, tmp, ensure_ascii=False, indent=2)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except OSError as exc:
        raise StorageError(f"Could not write {path}: {exc}") from exc


def write_subresult(paths: CasePaths, module: str, data: Any) -> Path:
    """Persist one parser/analyzer module's result. Each module owns its file;
    re-running a module replaces only that file, never marks.json."""
    target = paths.subresult(module)
    write_json(target, data)
    log.info("Wrote sub-result for module %r to %s", module, target)
    return target
