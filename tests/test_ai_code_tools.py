"""AI / MCP tools over the deep analyses: code objects, functions, decrypted, stages, ML."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402

from docutracex import ai_tools  # noqa: E402


@pytest.fixture()
def cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from docutracex import analyze, cases as cs
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    out = {}
    for name, data in (("gallery.exe", ms.dotnet_bitmap_loader_exe(ms.dotnet_stealer_exe())),
                       ("loader.exe", ms.code_loader_exe())):
        m = cs.create_case(io.BytesIO(data), name, cases_dir=tmp_path)
        analyze.analyze_case(tmp_path / m["analysis_id"])
        out[name] = m["analysis_id"]
    return out


def test_dotnet_chain_through_the_tools(cases) -> None:
    cid = cases["gallery.exe"]
    objs = ai_tools.run_tool("list_code_objects", {"case_id": cid})["objects"]
    stealer = next(o for o in objs if o.get("assembly") == "InvoiceMailSync")
    assert stealer["engine"] == ".NET (CIL)" and stealer["decrypted_strings"] >= 3
    fns = ai_tools.run_tool("list_functions", {"case_id": cid, "object": stealer["object"]})["functions"]
    assert fns and all("name" in f for f in fns)
    fn = ai_tools.run_tool("get_function", {"case_id": cid, "object": stealer["object"], "function": "Program::Main"})
    assert "smtp.billing-portal.example" in {d["plain"] for d in fn["decrypted"]}
    dec = ai_tools.run_tool("get_decrypted", {"case_id": cid})["items"]
    kinds = {d["kind"] for d in dec}
    assert ".NET string" in kinds and "hidden in Bitmap pixels" in kinds
    tree = ai_tools.run_tool("get_nested_tree", {"case_id": cid})["tree"]
    assert any(n["file"].endswith("pixels.exe") for n in tree)
    ml = ai_tools.run_tool("get_ml", {"case_id": cid})
    assert "items" in ml


def test_native_function_with_pseudocode(cases) -> None:
    from docutracex import codeanalysis
    if not codeanalysis.available():
        pytest.skip("Rizin + rz-ghidra not provisioned")
    cid = cases["loader.exe"]
    objs = ai_tools.run_tool("list_code_objects", {"case_id": cid})["objects"]
    nat = next(o for o in objs if o["engine"].startswith("native"))
    fns = ai_tools.run_tool("list_functions", {"case_id": cid, "object": nat["object"], "category": "network"})["functions"]
    assert fns, "the function calling InternetOpenUrlA is a network one"
    fn = ai_tools.run_tool("get_function", {"case_id": cid, "object": nat["object"], "function": fns[0]["addr"]})
    assert fn["pseudocode"] and fn["disassembly"]
    assert any("cdn-update.example.net" in (s or "") for s in fn["strings"]) or "cdn-update" in fn["pseudocode"]


def test_errors_are_returned_to_the_model(cases) -> None:
    cid = cases["loader.exe"]
    assert "error" in ai_tools.run_tool("get_function", {"case_id": cid, "object": "nope", "function": "x"})
    assert "error" in ai_tools.run_tool("list_functions", {"case_id": "../etc", "object": "x"})
    assert {s["function"]["name"] for s in ai_tools.SCHEMAS} == set(ai_tools.TOOLS)
