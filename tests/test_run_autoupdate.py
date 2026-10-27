"""run.py startup auto-update flow and update.py exit-code convention."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


run = _load("dtx_run", ROOT / "run.py")
upd = _load("dtx_update", ROOT / "update.py")


# --- run._auto_update --------------------------------------------------------
def test_auto_update_reprovisions_when_updated(monkeypatch):
    calls = []

    class R:
        def __init__(self, rc):
            self.returncode = rc

    def fake_run(cmd, **kw):
        calls.append(Path(cmd[1]).name)
        return R(2) if Path(cmd[1]).name == "update.py" else R(0)  # update applied

    monkeypatch.setattr(run.subprocess, "run", fake_run)
    run._auto_update()
    assert calls == ["update.py", "install.py"]  # update -> re-provision


def test_auto_update_skips_install_when_up_to_date(monkeypatch):
    calls = []

    class R:
        returncode = 0

    def fake_run(cmd, **kw):
        calls.append(Path(cmd[1]).name)
        return R()

    monkeypatch.setattr(run.subprocess, "run", fake_run)
    run._auto_update()
    assert calls == ["update.py"]  # no install.py when nothing changed


# --- update.py exit codes ----------------------------------------------------
def _update_rc(monkeypatch, local, remote, *, answer="y", apply_ok=True) -> int:
    monkeypatch.setattr(upd, "local_version", lambda: local)
    monkeypatch.setattr(upd, "remote_version", lambda: remote)
    monkeypatch.setattr(upd, "_remove_loose_samples", lambda: [])
    if apply_ok:
        monkeypatch.setattr(upd, "apply_update", lambda: 5)
    else:
        def boom():
            raise RuntimeError("fail")
        monkeypatch.setattr(upd, "apply_update", boom)
    monkeypatch.setattr("builtins.input", lambda *_: answer)
    monkeypatch.setattr(upd.sys, "argv", ["update.py"])
    try:
        upd.main()
        return 0
    except SystemExit as e:
        return e.code or 0


def test_update_exit_codes(monkeypatch):
    assert _update_rc(monkeypatch, "1.0.0", "1.0.0") == 0               # up to date
    assert _update_rc(monkeypatch, "1.0.0", "1.1.0", answer="y") == 2   # updated
    assert _update_rc(monkeypatch, "1.0.0", "1.1.0", answer="n") == 0   # cancelled
    assert _update_rc(monkeypatch, "1.0.0", "1.1.0", apply_ok=False) == 1  # update failed


def test_update_check_failure_is_error(monkeypatch):
    def boom():
        raise RuntimeError("net")
    monkeypatch.setattr(upd, "local_version", lambda: "1.0.0")
    monkeypatch.setattr(upd, "remote_version", boom)
    monkeypatch.setattr(upd.sys, "argv", ["update.py"])
    with pytest.raises(SystemExit) as ei:
        upd.main()
    assert ei.value.code == 1
