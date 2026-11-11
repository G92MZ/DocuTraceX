"""C2 extractor dependencies: optional with a warning. A missing required one
switches only that extractor off (missing_dependency); a missing optional one
leaves it working with less (degraded). Nothing else stops."""

from __future__ import annotations

from pathlib import Path

import pytest

from docutracex import c2
from docutracex.c2 import registry


@pytest.fixture(autouse=True)
def _fresh() -> None:
    registry._DEP_CACHE.clear()
    yield
    registry._DEP_CACHE.clear()


def _missing(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    real = registry._available
    monkeypatch.setattr(registry, "_available", lambda kind, name: name not in names and real(kind, name))


def test_policy_is_declared_for_every_extractor() -> None:
    assert set(registry.REQUIRES) == set(registry.EXTRACTORS)
    assert "missing_dependency" in registry.STATUSES
    d = {x["id"]: x for x in registry.descriptors()}
    assert d["cobalt"]["requires"][0] == {"kind": "python", "name": "dissect.cobaltstrike", "required": False,
                                          "for": "second parser and malleable profile (built-in fallback)"}
    assert d["remcos"]["dependency_status"] == {"missing_required": [], "missing_optional": []}


def test_missing_required_switches_only_that_extractor_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _missing(monkeypatch, "pefile")
    p = tmp_path / "x.bin"
    p.write_bytes(b"MZ" + b"\x00" * 200)
    _cfgs, runs = c2.scan_object_detailed(p, p.read_bytes())
    st = {r["extractor"]: r for r in runs}
    assert st["remcos"]["status"] == "missing_dependency" and "pefile" in st["remcos"]["error"]
    assert st["dotnet"]["status"] == "missing_dependency"
    assert st["metasploit"]["status"] in ("not_found", "not_applicable")              # the others still run
    assert st["stealers"]["degraded"] and "pefile" in st["stealers"]["degraded"][0]   # optional: works with less


def test_case_warns_and_diagnostics_lists_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import deps
    _missing(monkeypatch, "cryptography", "1768.py")
    (tmp_path / "case.json").write_text("{}")
    orig = tmp_path / "doc.txt"
    orig.write_bytes(b"plain")
    res = c2.analyze(orig, tmp_path / "extracted")
    w = " | ".join(res["warnings"])
    assert "AsyncRAT / DcRAT / QuasarRAT: switched off — needs cryptography" in w
    assert "Cobalt Strike: works with less — missing 1768.py" in w
    chk = next(x for x in deps.run_checks()["checks"] if x["name"] == "C2 extractors")
    assert chk["status"] == "warn" and "switched off" in chk["detail"] and "works with less" in chk["detail"]
