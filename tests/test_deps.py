"""Tests for the dependency self-check."""

from __future__ import annotations

from docutracex.deps import Dependency, check_dependencies, summarize


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
