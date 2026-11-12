"""Tasks: a step's note says why it did not run or failed — never "not provisioned" on a tool that ran."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import make_samples as ms  # noqa: E402

from docutracex import analyze, cases  # noqa: E402
from docutracex.config import settings  # noqa: E402
from docutracex.storage import CasePaths, read_json  # noqa: E402


def _steps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, dict]:
    from docutracex.parsers import didier, vipermonkey
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    monkeypatch.setattr(didier, "analyze", lambda *a, **k: {"module": "didier", "available": True, "status": "ok",
                                                            "findings": [], "counts": {"findings": 0}})
    monkeypatch.setattr(vipermonkey, "analyze", lambda *a, **k: {
        "module": "vipermonkey", "available": True, "status": "error", "findings": [],
        "tool": {"returncode": 1, "stderr": "Traceback (most recent call last):\nImportError: No module named pyparsing"}})
    m = cases.create_case(io.BytesIO(ms.word_docm()), "factura.docm", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    s = read_json(CasePaths(m["analysis_id"], cases_dir=tmp_path).summary) or {}
    return {x["step"]: x for x in s.get("steps") or []}


def test_notes_only_explain_what_did_not_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    st = _steps(tmp_path, monkeypatch)
    for name, x in st.items():
        if x["status"] in ("ok", "ok_with_findings"):
            assert x.get("note") != "not provisioned", name           # it ran: nothing to excuse
    did = next(x for n, x in st.items() if n.startswith("didier:"))
    assert did["status"] == "ok" and "note" not in did
    vm = next(x for n, x in st.items() if n.startswith("vipermonkey:"))
    assert vm["status"] == "error" and vm["note"] == "exit 1: ImportError: No module named pyparsing"


def test_unavailable_tool_gives_its_own_reason() -> None:
    assert analyze._short_reason({"available": False, "error": "XLMMacroDeobfuscator unavailable: No module named "
                                                                "'XLMMacroDeobfuscator'"}).endswith("'XLMMacroDeobfuscator'")
    assert analyze._short_reason({"available": False}) == ""                     # → the caller's fallback
