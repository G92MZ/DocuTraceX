"""Code analysis engine (Rizin + rz-ghidra): Go phases 3-4 and the native Code tab."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from docutracex import codeanalysis as ca
from docutracex.codeanalysis import case as code_case
from docutracex.codeanalysis import priority
from docutracex.golang import detect

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms

CODE = ms.code_samples()
URL = ms.CODE_URL
needs_rizin = pytest.mark.skipif(not ca.available(), reason="Rizin + rz-ghidra not provisioned")


def test_priority_categories_and_reasons() -> None:
    fn = {"name": "main.beacon", "named": True, "size": 120, "loops": 1, "xor_ops": 3}
    pts, reasons, cats = priority.score(fn, ["net/http.(*Client).Do", "os/exec.(*Cmd).Run"], [URL], "go")
    assert {"network", "exec", "transform"} <= set(cats)
    assert pts >= 30 + 30 + 20 + 15
    assert any("URL" in r for r in reasons) and any("XOR" in r for r in reasons)
    _p, _r, ncats = priority.score({"name": "fcn.1"}, ["imp.KERNEL32.dll_VirtualAlloc", "imp.KERNEL32.dll_WriteProcessMemory"], [], "native")
    assert "process" in ncats
    # a huge init table gets no size bonus
    assert priority.score({"name": "x", "size": 160000}, [], [], "go")[0] == 0


def test_readable_callee_names() -> None:
    assert ca._readable("sym.imp.KERNEL32.dll_VirtualAlloc") == "imp.KERNEL32.dll_VirtualAlloc"
    assert ca._readable("sym.main.foo") == "main.foo"
    assert ca._readable("fcn.00401000") == "fcn.00401000"


def test_go_names_from_the_own_pclntab_parser() -> None:
    data = CODE["go/sample_go_code.exe"]
    r = detect.identify(data)
    assert r["state"] in ("Confirmed", "Likely")
    names = code_case.go_names(data, r)
    by = {n["name"]: n for n in names}
    assert {"main.main", "main.decryptConfig", "main.beacon", "net/http.(*Client).Do"} <= set(by)
    assert by["main.main"]["start"] == 0x140001000 and by["main.main"]["user"]
    assert not by["net/http.(*Client).Do"]["user"]


def test_dotnet_is_left_to_its_own_analysis() -> None:
    assert code_case.is_dotnet(ms.agenttesla_exe())
    assert not code_case.is_dotnet(CODE["code/sample_code_loader.exe"])


def test_result_ids_are_validated(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        code_case.result_file(tmp_path, "../../etc", "go")
    with pytest.raises(ValueError):
        code_case.result_file(tmp_path, "a" * 64, "python")


@needs_rizin
def test_native_engine(tmp_path: Path) -> None:
    p = tmp_path / "loader.exe"
    p.write_bytes(CODE["code/sample_code_loader.exe"])
    out = tmp_path / "code.json"
    s = ca.analyze(p, mode="native", names=None, out_file=out, lock_path=tmp_path / "lock")
    assert s["status"] == "ok" and s["functions_analyzed"] == 3 and s["decompiled"] == 3
    full = json.loads(out.read_text())
    top = full["functions"][0]
    assert "network" in top["categories"] and any(st["value"] == URL for st in top["strings"])
    dec = next(f for f in full["functions"] if f["xor_ops"] >= 2)
    assert dec["loops"] >= 1 and "transform" in dec["categories"]
    entry = next(f for f in full["functions"] if f["name"] == "entry0")
    assert len(entry["calls"]) == 2
    assert all(f["callers"] == [entry["addr"]] for f in full["functions"] if f is not entry)
    code = full["decompiled"][str(top["addr"])]["code"]
    assert "InternetOpenUrlA" in code and URL in code
    api = {a["name"]: a for a in full["apis"]}
    assert api["InternetOpenUrlA"]["used_by"] == [top["name"]] and "network" in api["InternetOpenUrlA"]["categories"]


@needs_rizin
def test_go_engine_restores_names(tmp_path: Path) -> None:
    data = CODE["go/sample_go_code.exe"]
    p = tmp_path / "agent.exe"
    p.write_bytes(data)
    names = code_case.go_names(data, detect.identify(data))
    out = tmp_path / "go.json"
    s = ca.analyze(p, mode="go", names=names, out_file=out, lock_path=tmp_path / "lock")
    assert s["status"] == "ok" and s["top"][0]["name"] == "main.beacon"
    full = json.loads(out.read_text())
    by = {f["name"]: f for f in full["functions"]}
    assert by["main.main"]["callee_names"] == ["main.decryptConfig", "runtime.newproc", "runtime.deferreturn"]
    assert {"entry", "goroutine", "defer"} <= set(by["main.main"]["traits"])
    assert by["main.main"]["spawns"] == [by["main.main.func1"]["addr"]]          # go func1()
    assert "closure" in by["main.main.func1"]["traits"]
    assert by["main.beacon"]["strings"][0]["value"] == URL                # Go string: pointer + length
    assert "net/http.(*Client).Do" in full["decompiled"][str(by["main.beacon"]["addr"])]["code"]
    one = ca.decompile_one(p, by["main.decryptConfig"]["addr"], mode="go", names=names, lock_path=tmp_path / "lock")
    assert one["status"] == "ok" and "0x5a" in one["code"] and one["ops"]

    g = code_case.graph(full)
    kinds = {(e["from"], e["to"]): e["kind"] for e in g["edges"]}
    assert kinds[(by["main.main"]["addr"], by["main.main.func1"]["addr"])] == "goroutine"
    assert g["roots"] == [by["main.main"]["addr"]]
    path = next(p["path"] for p in g["paths"] if p["target"] == "ext:net/http.(*Client).Do")
    assert path == [by["main.main"]["addr"], by["main.main.func1"]["addr"], by["main.beacon"]["addr"],
                    "ext:net/http.(*Client).Do"]
    cfg = ca.cfg_one(p, by["main.decryptConfig"]["addr"], mode="go", names=names, lock_path=tmp_path / "lock")
    assert cfg["status"] == "ok" and len(cfg["blocks"]) == 3 and cfg["loops"] == 1
    assert {e["kind"] for e in cfg["edges"]} >= {"jump", "fail"}


@needs_rizin
def test_case_pipeline_go_and_native(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex import analyze, cases
    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    monkeypatch.setattr(settings, "goresym_executable", lambda: None)
    client = TestClient(create_app())

    m = cases.create_case(io.BytesIO(CODE["go/sample_go_code.exe"]), "factura.exe", cases_dir=tmp_path)
    cid = m["analysis_id"]
    analyze.analyze_case(tmp_path / cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    obj = comp["modules"]["golang"]["objects"][0]
    assert "_pcln" not in obj["result"]
    c = obj["code"]
    assert c["status"] == "ok" and c["mode"] == "go" and c["functions_total"] >= 4
    assert "code" not in comp["modules"]                       # Go objects are not repeated in the Code tab
    ov = client.get(f"/api/cases/{cid}/code/{c['sha256']}/go").json()
    assert ov["functions"][0]["name"] == "main.beacon" and ov["strings"][0]["value"] == URL
    addr = ov["functions"][0]["addr"]
    fv = client.get(f"/api/cases/{cid}/code/{c['sha256']}/go/fn/{addr}").json()
    assert fv["decompiled"]["status"] == "ok" and fv["callers"][0]["name"] == "main.main.func1" and fv["ops"]
    dv = client.post(f"/api/cases/{cid}/code/{c['sha256']}/go/fn/{addr}/decompile").json()
    assert dv["decompiled"]["on_demand"] is True
    g = client.get(f"/api/cases/{cid}/code/{c['sha256']}/go/graph").json()
    assert any(e["kind"] == "goroutine" for e in g["edges"]) and g["paths"]
    cf = client.get(f"/api/cases/{cid}/code/{c['sha256']}/go/fn/{addr}/cfg").json()
    assert cf["status"] == "ok" and cf["blocks"]
    assert client.get(f"/api/cases/{cid}/code/{c['sha256']}/go/fn/{addr}/cfg").json() == cf     # cached
    assert client.get(f"/api/cases/{cid}/code/{'0' * 64}/go").status_code == 404
    assert client.get(f"/api/cases/{cid}/code/xyz/go").status_code == 400

    m2 = cases.create_case(io.BytesIO(CODE["code/sample_code_loader.exe"]), "loader.exe", cases_dir=tmp_path)
    cid2 = m2["analysis_id"]
    analyze.analyze_case(tmp_path / cid2)
    comp2 = client.get(f"/api/cases/{cid2}/components").json()
    co = comp2["modules"]["code"]["objects"][0]
    assert co["original"] and co["code"]["status"] == "ok" and co["code"]["apis"] == 5
    ov2 = client.get(f"/api/cases/{cid2}/code/{co['sha256']}/native").json()
    assert ov2["apis"][0]["used_by"]


def test_diagnostics_has_rizin_check() -> None:
    from docutracex.deps import run_checks

    c = next(x for x in run_checks()["checks"] if x["name"] == "Rizin + rz-ghidra (code analysis)")
    assert c["status"] == "ok" or c["retry"] == "rizin"
