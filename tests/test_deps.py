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
    # gmzpt
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


# --- Diagnostics → Retry -------------------------------------------------------

def test_retry_components_match_setup_script() -> None:
    import importlib.util

    from docutracex import diag_retry
    spec = importlib.util.spec_from_file_location("setup_pp", diag_retry.SETUP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    assert set(mod.COMPONENTS) == set(diag_retry.COMPONENTS)


def test_non_ok_checks_carry_a_known_retry_component() -> None:
    from docutracex import diag_retry
    for c in run_checks()["checks"]:
        if c["status"] == "ok":
            assert c["retry"] == ""
        elif c["retry"]:
            assert (c["retry"] in diag_retry.COMPONENTS
                    or c["retry"].startswith(diag_retry.APP_DEP_PREFIX)), c


def test_retry_rejects_unknown_component() -> None:
    from docutracex import diag_retry
    with pytest.raises(ValueError):
        diag_retry.start("rm -rf /")
    with pytest.raises(ValueError):
        diag_retry.start("app-dep:not-an-app-dependency")


def test_retry_runs_in_background_and_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from fastapi.testclient import TestClient

    from docutracex import diag_retry
    from docutracex.app import create_app
    monkeypatch.setattr(diag_retry, "_command",
                        lambda c: [sys.executable, "-c", "print('[>] step'); print('[+] done')"])
    client = TestClient(create_app())
    assert client.post("/api/diagnostics/retry", json={"component": "ember"}).status_code == 200
    for _ in range(100):
        st = client.get("/api/diagnostics/retry").json()
        if st["state"] != "running":
            break
        time.sleep(0.05)
    assert st["state"] == "done" and st["returncode"] == 0 and st["component"] == "ember"
    assert "[+] done" in st["log"]
    monkeypatch.undo()
    assert client.post("/api/diagnostics/retry", json={"component": "nope"}).status_code == 400


# --- Provisioning fixes (Windows feedback) ---------------------------------------

def _setup_module():
    import importlib.util

    from docutracex import diag_retry
    spec = importlib.util.spec_from_file_location("setup_pp2", diag_retry.SETUP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_setup_never_uses_a_user_site() -> None:
    import os
    _setup_module()
    assert os.environ.get("PYTHONNOUSERSITE") == "1"


def test_webcrack_build_puts_portable_node_first_on_path(tmp_path: Path) -> None:
    import os
    mod = _setup_module()
    node = tmp_path / "node" / "node.exe"
    node.parent.mkdir()
    node.write_text("")
    env = mod._webcrack_build_env(node)
    assert env["PATH"].split(os.pathsep)[0] == str(node.parent.resolve())


def test_failed_marker_is_retried_after_an_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _setup_module()
    monkeypatch.setattr(mod, "TOOLS", tmp_path)
    monkeypatch.setattr(mod, "_app_version", lambda: "1.0.0")
    mod._mark_failed("webcrack")
    assert mod._marked("webcrack")
    monkeypatch.setattr(mod, "_app_version", lambda: "1.0.1")
    assert not mod._marked("webcrack")                    # new version → try again
    (tmp_path / ".pycdc_provision_failed").write_text("Provisioning failed.\n")
    assert not mod._marked("pycdc")                       # legacy marker → try again


def test_portable_children_ignore_the_user_site(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from docutracex import native
    monkeypatch.setattr(settings, "portable_python", lambda: tmp_path / "python.exe")
    assert native.subprocess_env()["PYTHONNOUSERSITE"] == "1"
