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
    assert apis["System.Reflection.Assembly"]["members"] == ["GetManifestResourceStream", "Load"]
    assert {"Microsoft.Win32.RegistryKey", "System.Security.Cryptography.RijndaelManaged"} <= set(apis)
    assert [o["name"] for o in r["obfuscators"]] == ["ConfuserEx"]
    res = r["resources"][0]
    assert res["name"] == "InvoiceViewer.Resources.stage2.bin" and res["entropy"] > 7.5
    assert ms.CODE_URL in r["strings"] and "203.0.113.47" in r["strings"]
    rules = [f["rule"] for f in dotnet._findings({"label": "x", "result": r})]
    assert rules == ["dotnet:identified", "dotnet:obfuscator", "dotnet:pinvoke_injection", "dotnet:assembly_load",
                     "dotnet:strings_decrypted"]


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
    assert "dotnet:strings_decrypted" in {f["rule"] for f in d["findings"]}
    assert any(x.endswith("decrypted › InvoiceViewer.Program::Configure") for x in locs)
    assert stored["InvoiceViewer.Resources.stage2.bin"]["decrypted"]["type"] == "exe"
    assert "dotnet:resource_decrypted" in {f["rule"] for f in d["findings"]}
    assert any(k.endswith("stage2.bin.decrypted.exe") for k in kids)
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


def test_static_string_decryption() -> None:
    from docutracex.dotnet import strdec
    r = dotnet.parse(ms.dotnet_loader_exe())
    got = {d["output"]: d for d in r["cil"]["decrypted"]}
    assert got["smtp.billing-portal.example"]["how"].startswith("Base64 + AES-128") and "MD5" in got["smtp.billing-portal.example"]["how"]
    assert got["203.0.113.47:587"]["decryptor"] == "InvoiceViewer.StringCipher::Unmask"
    # single-byte XOR with no key, and garbage is never reported
    import base64
    enc = base64.b64encode(bytes(c ^ 0x5A for c in b"https://cdn-update.example.net/a")).decode()
    meths = [{"method": "A::Main", "rid": 1, "calls": [], "_ops": {"call"}, "_sites": [(2, [enc]), (2, ["Zm9vYmFyYmF6cXV4"[::-1] + "=="])],
              "_all_strings": []},
             {"method": "A::D", "rid": 2, "calls": ["System.Convert::FromBase64String"], "_ops": {"xor"}, "_sites": [],
              "_all_strings": []}]
    outs = [d["output"] for d in strdec.decrypt(meths)]
    assert outs == ["https://cdn-update.example.net/a"]


def test_static_arrays_encrypted_resource_and_c2(tmp_path: Path) -> None:
    from docutracex import c2
    r = dotnet.parse(ms.dotnet_loader_exe())
    got = {d["output"]: d for d in r["cil"]["decrypted"]}
    assert got[ms.CODE_URL + "/gate"]["how"] == 'byte[] + XOR key "inv"'
    assert got[ms.CODE_URL + "/gate"]["input"].startswith("byte[48] ")
    from docutracex.dotnet.strdec import decrypt_blob
    stage = next(x for x in r["resources"] if x["name"].endswith("stage2.bin"))
    how, plain, ext = decrypt_blob(stage["_data"], r["_cil_methods"])
    assert ext == "exe" and plain.startswith(b"MZinert") and "CBC iv=0" in how and "OpenStage" in how
    cfgs = c2.scan_object(tmp_path / "s.exe", ms.dotnet_stealer_exe())
    assert [c["family"] for c in cfgs] == ["AgentTesla-like stealer"]
    assert cfgs[0]["c2"] == ["smtp.billing-portal.example"]
    assert "accounts@billing-portal.example" in cfgs[0]["decrypted_statically"]
    assert "decrypted statically" in cfgs[0]["method"]
