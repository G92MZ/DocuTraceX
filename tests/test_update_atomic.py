"""update.py never leaves a half-updated install that already claims the new version."""

from __future__ import annotations

import importlib.util
import io
import zipfile
from pathlib import Path

import pytest


def _load(tmp_path: Path):
    spec = importlib.util.spec_from_file_location("upd", Path(__file__).resolve().parent.parent / "update.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.HERE = str(tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("DocuTraceX-main/VERSION", "2.0.0")
        z.writestr("DocuTraceX-main/samples/samples.zip", b"new")
        z.writestr("DocuTraceX-main/run.py", "print()")
    m._download_zip = lambda: buf.getvalue()
    return m


def test_locked_file_keeps_old_version_and_retry_works(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "VERSION").write_text("1.0.0")
    m = _load(tmp_path)
    real = m.shutil.copy2

    def locked(a, b, *k, **kw):
        if str(b).endswith("samples.zip"):
            raise PermissionError(13, "Permission denied")
        return real(a, b)

    monkeypatch.setattr(m.shutil, "copy2", locked)
    with pytest.raises(RuntimeError, match="samples.zip"):
        m.apply_update()
    assert (tmp_path / "VERSION").read_text() == "1.0.0"     # next run retries
    monkeypatch.setattr(m.shutil, "copy2", real)
    m.apply_update()
    assert (tmp_path / "VERSION").read_text() == "2.0.0"
    assert (tmp_path / "samples" / "samples.zip").read_bytes() == b"new"
