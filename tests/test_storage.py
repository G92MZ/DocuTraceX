"""Tests for the case persistence helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from docutracex.errors import StorageError
from docutracex.storage import CasePaths, read_json, write_subresult


def test_subresult_roundtrip(tmp_path: Path) -> None:
    paths = CasePaths("abc123", cases_dir=tmp_path)
    paths.ensure_dirs()
    write_subresult(paths, "pdf", {"findings": [1, 2, 3]})
    assert read_json(paths.subresult("pdf")) == {"findings": [1, 2, 3]}


def test_rerun_replaces_only_its_module(tmp_path: Path) -> None:
    paths = CasePaths("abc123", cases_dir=tmp_path)
    paths.ensure_dirs()
    write_subresult(paths, "pdf", {"v": 1})
    write_subresult(paths, "email", {"v": 1})
    write_subresult(paths, "pdf", {"v": 2})  # re-run pdf only
    assert read_json(paths.subresult("pdf")) == {"v": 2}
    assert read_json(paths.subresult("email")) == {"v": 1}


def test_path_traversal_rejected(tmp_path: Path) -> None:
    with pytest.raises(StorageError):
        CasePaths("../escape", cases_dir=tmp_path)
    paths = CasePaths("ok", cases_dir=tmp_path)
    with pytest.raises(StorageError):
        paths.subresult("../../etc/passwd")


def test_read_missing_returns_none(tmp_path: Path) -> None:
    paths = CasePaths("abc123", cases_dir=tmp_path)
    assert read_json(paths.summary) is None
