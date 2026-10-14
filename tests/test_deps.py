"""Tests for the dependency self-check."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from docutracex.config import settings
from docutracex.deps import (
    Dependency,
    check_dependencies,
    check_in_interpreter,
    check_runtime,
    run_checks,
    summarize,
)


def test_core_dependencies_present() -> None:
    results = check_dependencies()
    by_name = {r.import_name: r for r in results}
    for mod in ("fastapi", "uvicorn", "jinja2", "multipart"):
        assert by_name[mod].installed, f"{mod} should be installed in the test env"
        assert by_name[mod].version


def test_missing_dependency_is_reported() -> None:
    fake = [Dependency("definitely_not_a_module_xyz", "ghost-pkg", "testing", required=False)]
    results = check_dependencies(fake)
    assert results[0].installed is False
    assert results[0].error
    summary = summarize(results)
    assert summary["ok"] is True  # optional missing does not break
    assert "ghost-pkg" in summary["missing_optional"]


def test_missing_required_sets_not_ok() -> None:
    fake = [Dependency("definitely_not_a_module_xyz", "ghost-pkg", "testing", required=True)]
    summary = summarize(check_dependencies(fake))
    assert summary["ok"] is False
    assert "ghost-pkg" in summary["missing_required"]


def test_probe_runs_inside_a_given_interpreter() -> None:
    # Probe the current interpreter via subprocess; results must match in-process.
    probed = check_in_interpreter(sys.executable)
    assert probed is not None
    info, results = probed
    assert info["executable"]
    assert info["python_version"]
    by_name = {r.import_name: r for r in results}
    assert by_name["fastapi"].installed


def test_probe_detects_missing_in_subprocess() -> None:
    fake = [Dependency("definitely_not_a_module_xyz", "ghost-pkg", "testing", required=False)]
    probed = check_in_interpreter(sys.executable, fake)
    assert probed is not None
    _, results = probed
    assert results[0].installed is False


def test_bad_interpreter_returns_none() -> None:
    assert check_in_interpreter("/nonexistent/python/xyz") is None


def test_check_runtime_falls_back_to_current(monkeypatch: pytest.MonkeyPatch) -> None:
    # No portable python bundled -> uses the current interpreter.
    monkeypatch.setattr(settings, "portable_python", lambda: None)
    interp, results = check_runtime()
    assert interp["source"] == "current"
    assert interp["executable"] == sys.executable
    assert results


def test_run_checks_structure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "portable_python", lambda: None)
    report = run_checks()
    assert "checks" in report and report["checks"]
    cats = {c["category"] for c in report["checks"]}
    assert "Runtime" in cats
    assert "App dependency" in cats and "Tool dependency" in cats
    # Portable-python check should warn when none is bundled, pointing at setup.
    portable = next(c for c in report["checks"] if c["name"] == "Portable Python (tools/)")
    assert portable["status"] == "warn"
    assert "setup_portable_python" in portable["remedy"]
    # App interpreter is always reported.
    assert any(c["name"] == "App interpreter" for c in report["checks"])
    assert all(c["status"] in ("ok", "warn", "fail") for c in report["checks"])
