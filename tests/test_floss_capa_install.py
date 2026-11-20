"""Setup: FLOSS / capa as Python libraries on the portable (flare-floss without its
dependencies: binary2strings has no Windows wheel), capa's rules from the pinned commit,
and the old standalone floss.exe / capa.exe folders removed."""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import setup_portable_python as spp  # noqa: E402


def _rules_zip(commit: str, n: int = 3) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(n):
            z.writestr(f"capa-rules-10.0.0/host-interaction/r{i}.yml", "rule:\n  meta:\n    name: r\n")
        z.writestr("capa-rules-10.0.0/README.md", "x")
        z.writestr("capa-rules-10.0.0/../evil.yml", "x")        # never written outside
        z.comment = commit.encode()
    return buf.getvalue()


def test_rules_from_the_pinned_commit(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(spp, "CAPA_RULES_DIR", tmp_path / "capa-rules")
    monkeypatch.setattr(spp, "CAPA_RULES_MIN", 3)
    monkeypatch.setattr(spp, "_get", lambda url: _rules_zip("0" * 40))
    assert spp.install_capa_rules() is False and not (tmp_path / "capa-rules").exists()   # wrong commit
    monkeypatch.setattr(spp, "_get", lambda url: _rules_zip(spp.CAPA_RULES_COMMIT))
    assert spp.install_capa_rules() is True
    got = sorted(p.relative_to(tmp_path / "capa-rules").as_posix() for p in (tmp_path / "capa-rules").rglob("*"))
    assert got == ["host-interaction", "host-interaction/r0.yml", "host-interaction/r1.yml", "host-interaction/r2.yml"]
    assert not (tmp_path / "evil.yml").exists()


def test_floss_installed_without_its_dependencies(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    calls: list[list[str]] = []
    done = [False]

    class R:
        returncode, stderr, stdout = 0, "", ""

    def run(cmd, **kw):  # noqa: ANN001, ANN003, ANN202
        calls.append(cmd)
        if "--no-deps" in cmd:
            done[0] = True
        return R()
    old = tmp_path / "floss"
    old.mkdir()
    (old / "floss.exe").write_bytes(b"MZ")
    monkeypatch.setattr(spp, "OLD_EXE_DIRS", (old,))
    monkeypatch.setattr(spp.subprocess, "run", run)
    monkeypatch.setattr(spp, "_portable_present", lambda: True)
    monkeypatch.setattr(spp, "_portable_python", lambda: Path("python"))
    monkeypatch.setattr(spp, "_floss_ok", lambda: done[0])
    assert spp.install_floss() is True
    assert not old.exists()                                        # the old standalone build is gone
    pips = [c for c in calls if "pip" in c]
    assert spp.CAPA_LIB in pips[0] and "binary2strings" not in " ".join(pips[0])
    assert pips[1][-2:] == ["--no-deps", spp.FLOSS_LIB]
