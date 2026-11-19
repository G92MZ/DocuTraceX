"""Family YARA in the C2 analysis (CAPE / ditekSHen downloaded at run time; here invented
rules in their layout) and the YARA store reset."""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
pytest.importorskip("yara")
ms = pytest.importorskip("make_samples")

# invented rules shaped like CAPE's (one family per file, cape_type) and ditekSHen's (MALWARE_Win_*)
CAPE_LIKE = '''rule Formbook
{
    meta:
        author = "test"
        cape_type = "Formbook Payload"
    strings:
        $a = "DTX-TEST-FORMBOOK-1"
        $b = "DTX-TEST-FORMBOOK-2"
    condition:
        all of them
}
'''
DITEK_LIKE = '''rule MALWARE_Win_GuLoader {
    meta:
        description = "GuLoader-like test rule"
    strings:
        $a = "DTX-TEST-GULOADER"
    condition:
        $a
}
rule MALWARE_Win_AgentTeslaV2 {
    meta:
        description = "AgentTesla-like test rule"
    strings:
        $a = "DTX-TEST-AGENTTESLA"
    condition:
        $a
}
rule MALWARE_Win_Broken {
    condition:
        pe.number_of_sections > 0
}
'''


@pytest.fixture()
def rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    from docutracex.c2 import familyrules
    from docutracex.config import settings
    monkeypatch.setattr(settings, "tools_dir", tmp_path / "tools")
    (familyrules.base() / "cape").mkdir(parents=True)
    (familyrules.base() / "cape" / "Formbook.yar").write_text(CAPE_LIKE)
    (familyrules.base() / "ditekshen").mkdir()
    (familyrules.base() / "ditekshen" / "malware.yar").write_text(DITEK_LIKE)
    familyrules._loaded.update(key=None, rules=None)
    yield familyrules
    familyrules._loaded.update(key=None, rules=None)


def test_compile_skips_a_broken_file_and_names_families(rules) -> None:  # noqa: ANN001
    rep = rules.ensure_compiled()
    # the ditekSHen-like file uses `pe` without importing it: that file is skipped, the rest compiles
    assert [e["file"] for e in rep["errors"]] == ["ditekshen/malware.yar"]
    (rules.base() / "ditekshen" / "malware.yar").write_text(DITEK_LIKE.replace(
        "rule MALWARE_Win_Broken {\n    condition:\n        pe.number_of_sections > 0\n}\n", ""))
    rep = rules.ensure_compiled()
    assert not rep["errors"] and rep["rule_count"] == 4          # 1 CAPE + 2 ditekSHen + the built-in marker
    got = {h["family"]: h for h in rules.extract(b"MZ DTX-TEST-FORMBOOK-1 DTX-TEST-FORMBOOK-2 DTX-TEST-GULOADER")}
    assert set(got) == {"Formbook", "GuLoader"}
    assert got["Formbook"]["confidence"] == "medium" and got["GuLoader"]["confidence"] == "low"   # CAPE vs one set
    assert got["Formbook"]["yara"][0] == {"source": "CAPE", "rule": "Formbook", "description": ""}


def test_names_map_to_ours() -> None:
    from docutracex.c2 import familyrules as f
    assert f.family_name("MALWARE_Win_AgentTeslaV2", {}) == "AgentTesla"
    assert f.family_name("CobaltStrikeBeacon", {"cape_type": "CobaltStrikeBeacon Config"}) == "Cobalt Strike"
    assert f.family_name("MALWARE_Win_GuLoader", {}) == "GuLoader"
    assert f.family_name("PureLogsStealer", {}) == "Pure family"
    assert f.family_name("Lumma", {"cape_type": "Lumma Payload"}) == "Lumma Stealer"
    assert f.family_name("X", {"family": "Own name"}) == "Own name"


def test_c2_scan_identifies_and_corroborates(rules) -> None:  # noqa: ANN001
    """An object only the rules know: identified (high with CAPE). An object an extractor reads:
    the configuration carries the YARA names, no second entry."""
    from docutracex import c2
    (rules.base() / "ditekshen" / "malware.yar").write_text(DITEK_LIKE.split("rule MALWARE_Win_Broken")[0])
    cfgs, runs = c2.scan_object_detailed(Path("x.exe"), b"MZ" + b"\0" * 64 + b"DTX-TEST-FORMBOOK-1 DTX-TEST-FORMBOOK-2")
    assert [(c["family"], c["kind"]) for c in cfgs] == [("Formbook", "indicators")]
    f = c2._finding(cfgs[0])
    assert f["severity"] == "high" and f["detail"] == "Formbook identified by YARA (CAPE)"
    assert {r["extractor"]: r["status"] for r in runs}["family_yara"] == "indicators"
    tesla = ms.agenttesla_exe() if hasattr(ms, "agenttesla_exe") else None
    if tesla is None:
        pytest.skip("no AgentTesla sample generator")
    cfgs, _ = c2.scan_object_detailed(Path("t.exe"), tesla + b"DTX-TEST-AGENTTESLA")
    tes = [c for c in cfgs if c["family"] == "AgentTesla"]
    assert len(tes) == 1 and tes[0]["yara"][0]["rule"] == "MALWARE_Win_AgentTeslaV2"


def test_sample_needs_nothing_downloaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The inert sample matches the built-in marker rule: identification offline, end to end."""
    from docutracex import analyze, cases, findings
    from docutracex.c2 import familyrules
    from docutracex.config import settings
    monkeypatch.setattr(settings, "tools_dir", tmp_path / "tools")
    familyrules._loaded.update(key=None, rules=None)
    m = cases.create_case(io.BytesIO(ms.family_yara_exe()), "actualizador.exe", cases_dir=tmp_path / "cases")
    root = tmp_path / "cases" / m["analysis_id"]
    analyze.analyze_case(root)
    analyze.run_module(root, "c2")
    res = json.loads((root / "results" / "c2.json").read_text())
    fams = {c["family"] for c in res["configs"]}
    assert "FacturaLoader (sample)" in fams and res["family_yara"]["rule_count"] >= 1
    assert any(f["rule"] == "c2:facturaloader" for f in findings.consolidate({"c2": res}))
    familyrules._loaded.update(key=None, rules=None)


def test_download_with_github_listing(rules, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from docutracex import mailintel
    calls: list[str] = []

    class Op:
        def open(self, req, timeout=60):  # noqa: ANN001, ANN201
            url = req.full_url
            calls.append(url)
            if "api.github.com" in url:
                body = json.dumps([{"type": "file", "name": "Formbook.yar"}, {"type": "file", "name": "README.md"}])
            elif url.endswith("Formbook.yar"):
                body = CAPE_LIKE
            else:
                body = DITEK_LIKE

            class R(io.BytesIO):
                def __enter__(self):  # noqa: ANN204
                    return self

                def __exit__(self, *a):  # noqa: ANN002, ANN204
                    return False
            return R(body.encode())
    monkeypatch.setattr(mailintel, "_routes", lambda proxy: [("direct", Op())])
    st = rules.download()
    assert {s["id"]: s["files"] for s in st["sources"]} == {"cape": 1, "ditekshen": 1}
    assert any("contents/data/yara/CAPE" in c for c in calls) and not any("README" in c for c in calls)


def test_yara_store_reset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import yara_engine
    from docutracex.config import settings
    monkeypatch.setattr(settings, "yara_dir", tmp_path / "yara")
    ext = tmp_path / "myrules"
    ext.mkdir()
    (ext / "a.yar").write_text("rule A { condition: true }")
    yara_engine.register_path(str(ext))
    yara_engine.add_upload("b.yar", b"rule B { condition: true }")
    yara_engine.set_enabled(["A"], True)
    for _ in yara_engine.compile_stream():
        pass
    assert yara_engine.list_rules()["compiled"]
    out = yara_engine.reset("compiled")
    assert "compiled.yarc" in out["removed"] and not yara_engine.list_rules()["compiled"]
    assert yara_engine.list_rules()["sources_config"]["uploaded"] == ["b.yar"]      # sources stay
    out = yara_engine.reset("all")
    lr = yara_engine.list_rules()
    assert not lr["sources_config"]["uploaded"] and not lr["sources_config"]["external_paths"]
    assert yara_engine.enabled_rules() == set() and (ext / "a.yar").is_file()     # nothing on disk deleted
