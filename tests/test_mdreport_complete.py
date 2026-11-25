"""The Markdown export is the whole analysis: every tool's complete output (past the 60,000
characters a module result keeps), the nested children's tools, every recovered script,
FLOSS's relevant strings (every string in the ZIP), the C2 extractors' raw output and every
result file of the case.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex import toolrun  # noqa: E402
from docutracex.storage import CasePaths, write_json  # noqa: E402


def test_bounded_keeps_the_whole_output(tmp_path: Path) -> None:
    big = "x" * 70000 + "\nLATE_LINE"
    with toolrun.case_scope(tmp_path):
        rec = toolrun.bounded({"command": "tool a.bin"}, big, "tool a.bin", err="e" * 5000)
    assert rec["output_truncated"] and len(rec["output"]) == toolrun.OUTPUT_BOUND
    assert (tmp_path / rec["output_full"]).read_text() == big
    assert (tmp_path / rec["stderr_full"]).read_text() == "e" * 5000
    small = toolrun.bounded({}, "short", "t")               # no case, under the bound: nothing written
    assert "output_full" not in small and small["output"] == "short"


def test_long_macro_output_is_whole_in_the_report(client) -> None:  # noqa: ANN001,F811
    import shutil
    if not shutil.which("olevba"):
        try:
            import oletools  # noqa: F401
        except ImportError:
            pytest.skip("oletools not installed")
    cid, res = _analyze(client, "Factura_2026-0187_largo.docm", _ms().long_macro_docm())
    ole = json.loads((res / "oletools.json").read_text())
    olevba = ole["tools"]["olevba"]
    assert olevba["output_truncated"] and "late_stage.ps1" not in olevba["output"]
    md = client.get(f"/api/cases/{cid}/mdreport.md").text
    tools = md.split("# Tool outputs (complete)", 1)[1].split("\n# ", 1)[0]
    assert "billing-portal.example/long/late_stage.ps1" in tools          # past the 60,000-char cut
    z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/cases/{cid}/mdreport.zip").content))
    names = z.namelist()
    assert any(n.endswith(".md") for n in names)
    full = [n for n in names if n.startswith("tool_output/olevba")]
    assert full and "late_stage.ps1" in z.read(full[0]).decode()


def test_sections_cover_children_scripts_floss_and_c2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import mdreport
    from docutracex.config import settings
    from docutracex.parsers import pe
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    cp = CasePaths("20261125-020000-abcdef12")
    write_json(cp.manifest, {"analysis_id": cp.root.name, "original": {"filename": "f.exe", "stored_path": "original/f.exe"}})
    # a nested child's own tool
    write_json(cp.results_dir / "nested_views" / "0123456789abcdef-a1b2c3.json", {
        "chain": "kit.zip › inner.doc", "filename": "inner.doc",
        "modules": {"oletools": {"tools": {"oleid": {"command": "oleid inner.doc", "returncode": 0,
                                                     "output": "CHILD_TOOL_OUTPUT"}}}}})
    # a script recovered whole
    (cp.extracted_dir / "code" / "powershell").mkdir(parents=True)
    (cp.extracted_dir / "code" / "powershell" / "01_stage.ps1").write_text("FULL_SCRIPT_TAIL")
    # FLOSS: complete output kept, relevant ones in the report
    floss = {"status": "ok", "detail": "3 string(s)", "version": "3.2.0",
             "located": [{"kind": "decoded", "string": "DECODED_ONE", "function": 0x401000}]}
    strings = ["harmless words", "https://cdn-update.example.net/a.bin", "DECODED_ONE"]
    pe.keep_floss_full(floss, strings, "f.exe", cp.root)
    write_json(cp.subresult("msi"), {"items": [{"label": "f.exe", "floss": floss, "floss_strings": strings}]})
    # a C2 run's raw records
    write_json(cp.results_dir / "c2_runs" / "r1" / "0001.json", {"object": "f.exe", "extractors": [
        {"extractor": "x", "status": "ok", "raw": "C2_RAW_OUTPUT"}]})
    secs = {s["id"]: s["markdown"] for s in mdreport.build(cp.root.name)}
    assert "CHILD_TOOL_OUTPUT" in secs["tools"] and "kit.zip › inner.doc" in secs["tools"]
    assert "FULL_SCRIPT_TAIL" in secs["codefiles"]
    assert "DECODED_ONE" in secs["floss"] and "cdn-update.example.net" in secs["floss"]
    assert "harmless words" not in secs["floss"]
    full = (cp.root / floss["output_full"]).read_text()
    assert "harmless words" in full and "function 0x401000" in full
    assert "C2_RAW_OUTPUT" in secs["c2"]
    assert "results/nested_views/0123456789abcdef-a1b2c3.json" in secs["modules"]
