""".NET analysis, phase 1: identification and metadata (dnfile)."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms

from docutracex import dotnet

pytestmark = pytest.mark.skipif(not dotnet.available(), reason="dnfile not installed")


def test_metadata_of_the_sample() -> None:
    r = dotnet.parse(ms.dotnet_loader_exe())
    assert r["assembly"] == {"name": "InvoiceViewer", "version": "2.1.0.0", "culture": ""}
    assert r["runtime"] == "v4.0.30319" and r["entry_point"] == "InvoiceViewer.Program::Main"
    assert [x["name"] for x in r["references"]] == ["mscorlib", "System"]
    assert {(p["dll"], p["entry"]) for p in r["pinvoke"]} == {("kernel32.dll", "VirtualAlloc"), ("kernel32.dll", "CreateThread")}
    assert all(p["injection"] for p in r["pinvoke"])
    apis = {a["type"]: a for a in r["apis"]}
    assert apis["System.Net.WebClient"]["members"] == ["DownloadData"]
    assert apis["System.Reflection.Assembly"]["members"] == ["Load"]
    assert {"Microsoft.Win32.RegistryKey", "System.Security.Cryptography.RijndaelManaged"} <= set(apis)
    assert [o["name"] for o in r["obfuscators"]] == ["ConfuserEx"]
    res = r["resources"][0]
    assert res["name"] == "InvoiceViewer.Resources.stage2.bin" and res["entropy"] > 7.5
    assert ms.CODE_URL in r["strings"] and "203.0.113.47" in r["strings"]
    rules = [f["rule"] for f in dotnet._findings({"label": "x", "result": r})]
    assert rules == ["dotnet:identified", "dotnet:obfuscator", "dotnet:pinvoke_injection", "dotnet:assembly_load"]


def test_existing_dotnet_samples_parse() -> None:
    for d in (ms.agenttesla_exe(), ms.asyncrat_exe(), ms.quasar_exe()):
        r = dotnet.parse(d)
        assert not r.get("error") and r["runtime"].startswith("v")


def test_case_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.dotnet_loader_exe()), "factura.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    d = read_json(paths.subresult("dotnet"))
    o = d["objects"][0]
    assert o["original"] and o["result"]["assembly"]["name"] == "InvoiceViewer"
    assert all("_data" not in x for x in o["result"]["resources"])
    assert {"dotnet:obfuscator", "dotnet:pinvoke_injection"} <= {f["rule"] for f in d["findings"]}
    iocs = {i["value"] for i in read_json(paths.subresult("iocs"))["iocs"]}
    assert {ms.CODE_URL, "203.0.113.47"} <= iocs
    # a native binary gets no .NET result
    m2 = cases.create_case(io.BytesIO(ms.code_loader_exe()),
                           "n.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m2["analysis_id"])
    assert read_json(CasePaths(m2["analysis_id"], cases_dir=tmp_path).subresult("dotnet")) is None
