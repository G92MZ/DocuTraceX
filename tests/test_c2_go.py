"""Go ↔ C2: Go implants in the C2 contract — framework from BuildInfo / pclntab,
endpoints with provenance from the Go module when it ran; C2 runs without it."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import codeanalysis as ca
from docutracex.c2 import golang_c2

needs_rizin = pytest.mark.skipif(not ca.available(), reason="Rizin + rz-ghidra not provisioned")


def test_framework_from_pclntab_names_without_the_go_module(tmp_path: Path) -> None:
    p = tmp_path / "agent"
    p.write_bytes(ms.go_sliver_like_elf())
    (cfg,) = golang_c2.extract(p, p.read_bytes())
    assert cfg["family"] == "Sliver" and cfg["kind"] == "indicators" and not cfg["c2"]
    assert cfg["fields"]["go_analysis"].startswith("not run") and "sliverpb" in cfg["indicators"][0]
    assert cfg["summary"]["Go version"] == "go1.22.5"


def test_a_bare_literal_is_not_a_c2(tmp_path: Path) -> None:
    p = tmp_path / "tool"
    p.write_bytes(ms._go_elf(ms.GO_STD + ms.GO_USER) + b"\x00https://updates.example.org/check\x00")
    assert golang_c2.extract(p, p.read_bytes()) == []
    assert golang_c2.extract(p, b"MZ not go") == []


def test_c2_scan_runs_the_go_extractor_without_the_go_module(tmp_path: Path) -> None:
    from docutracex import c2
    p = tmp_path / "agent"
    p.write_bytes(ms.go_sliver_like_elf())
    cfgs, runs = c2.scan_object_detailed(p, p.read_bytes())
    assert [c["family"] for c in cfgs] == ["Sliver"]
    st = {r["extractor"]: r["status"] for r in runs}
    assert st["go"] == "indicators"
    q = tmp_path / "doc.txt"
    q.write_bytes(b"plain text")
    assert {r["extractor"]: r["status"] for r in c2.scan_object_detailed(q, q.read_bytes())[1]}["go"] == "not_applicable"


@needs_rizin
def test_case_exports_go_endpoints_with_provenance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    monkeypatch.setattr(settings, "goresym_executable", lambda: None)
    monkeypatch.setenv("DOCUTRACEX_AUTO_MODULES", "c2")
    m = cases.create_case(io.BytesIO(ms.go_code_exe()), "factura.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    res = read_json(CasePaths(m["analysis_id"]).subresult("c2")) or {}
    cfg = next(c for c in res["configs"] if c["family"] == "Go implant")
    ends = {e["value"]: e for e in cfg["fields"]["endpoints"]}
    assert ends["https://cdn-update.example.net/invoice/sync"]["confidence"] == "high"
    assert ends["https://cdn-update.example.net/invoice/sync"]["source"].startswith("go:embed assets/config.json")
    assert "203.0.113.47" in ends                                          # the embedded fallback
    assert cfg["fields"]["go_analysis"] == "used" and cfg["confidence"] == "high"
    assert any("main.beacon" in n for n in cfg["summary"]["Network functions"])
    f = next(x for x in res["findings"] if x["rule"] == "c2:go")
    assert f["severity"] == "high"
    go = read_json(CasePaths(m["analysis_id"]).subresult("golang")) or {}
    assert not any(x["rule"].startswith("c2:") for x in go["findings"])   # no finding twice
    assert json.dumps(cfg["normalized"])                                   # in the contract (normalized fields)
