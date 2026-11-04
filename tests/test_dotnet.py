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
    assert apis["System.Net.WebClient"]["members"] == [".ctor", "DownloadData"]
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
    stored = {x["name"]: x for x in o["result"]["resources"]}
    assert stored["costura.invoicehelper.dll.compressed"]["costura"] is True
    tree = read_json(paths.subresult("nested"))["tree"]
    kids = {n["filename"]: n for n in tree}
    assert "InvoiceViewer.Resources.stage2.bin" in kids and kids["costura.invoicehelper.dll"]["recipe"][-1] == "deflate"
    assert (paths.root / stored["InvoiceViewer.Resources.stage2.bin"]["stored_path"]).is_file()
    # phase 2: .resources entries become the children, CIL locates the loader and its strings
    rs = stored["InvoiceViewer.Properties.Resources.resources"]
    ents = {e["name"]: e for e in rs["entries"]}
    assert ents["UpdateHost"]["value"] == "cdn-update.example.net" and ents["invoice_stage3"]["pe"] is True
    assert any(k.endswith("invoice_stage3.exe") for k in kids)
    assert "dotnet:resource_pe" in {f["rule"] for f in d["findings"]}
    load = next(f for f in d["findings"] if f["rule"] == "dotnet:assembly_load")
    assert "InvoiceViewer.Program::LoadStage" in load["evidence"]
    locs = {s["location"] for s in o["ioc_sources"]}
    assert any(x.endswith("InvoiceViewer.Program::LoadStage") for x in locs)
    assert any("resources › UpdateHost" in x for x in locs)
    iocs = {i["value"] for i in read_json(paths.subresult("iocs"))["iocs"]}
    assert {ms.CODE_URL, "203.0.113.47"} <= iocs
    # a native binary gets no .NET result
    m2 = cases.create_case(io.BytesIO(ms.code_loader_exe()),
                           "n.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m2["analysis_id"])
    assert read_json(CasePaths(m2["analysis_id"], cases_dir=tmp_path).subresult("dotnet")) is None


def test_cil_and_resources_units() -> None:
    import dnkit
    from docutracex.dotnet import resources as R
    r = dotnet.parse(ms.dotnet_loader_exe())
    top = r["cil"]["interesting"][0]
    assert top["method"] == "InvoiceViewer.Program::LoadStage"
    assert top["calls"] == ["System.Net.WebClient::.ctor", "System.Net.WebClient::DownloadData", "System.Reflection.Assembly::Load"]
    assert {"loader", "network"} <= set(top["categories"]) and top["strings"] == [ms.CODE_URL]
    blob = dnkit.resources([("a", "x"), ("b", b"MZ" + b"t" * 30), ("c", ("stream", b"PK\x03\x04" + b"z" * 20))])
    ents = R.parse(blob)["entries"]
    assert [(e["name"], e["type"]) for e in ents] == [("a", "string"), ("b", "byte[]"), ("c", "Stream")]
    assert R.parse(blob[:40]).get("error") and R.parse(b"junk" * 10).get("error")
