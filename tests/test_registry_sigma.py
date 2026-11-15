"""Sigma registry rules from the folder set in Settings, run on the case's registry database."""

from __future__ import annotations

from pathlib import Path

import pytest

import make_samples as ms
from docutracex import appsettings
from docutracex.registry import sigma

S = ms.registry_sigma_samples()


def _rule(det: dict, cat: str = "registry_set", **kw) -> dict:  # noqa: ANN003
    return {"title": "t", "id": "x", "logsource": {"category": cat, "product": "windows"}, "detection": det, **kw}


def test_values_and_modifiers() -> None:
    w = sigma.compile_rule(_rule({"s": {"TargetObject|endswith": "\\Run\\a*b?c"}, "condition": "s"}))["where"]
    assert "regexp_full_match(lower(target), '(?is).*\\\\Run\\\\a.*b.c')" in w
    w = sigma.compile_rule(_rule({"s": {"Details": "C:\\Tools\\*"}, "condition": "s"}))["where"]
    assert "lower(details) = 'c:\\tools*'" in w                    # \* is a literal star (Sigma escape): no wildcard
    w = sigma.compile_rule(_rule({"s": {"Details|windash|contains": " -enc "}, "condition": "s"}))["where"]
    assert "' /enc '" in w and "' -enc '" in w
    w = sigma.compile_rule(_rule({"s": {"Details|contains|all": ["a", "b"]}, "condition": "s"}))["where"]
    assert "contains(lower(details), 'a') AND contains(lower(details), 'b')" in w
    w = sigma.compile_rule(_rule({"s": {"TargetObject|re": "Run\\\\[A-Z]+$"}, "condition": "s"}))["where"]
    assert "regexp_matches(target, 'Run\\\\[A-Z]+$')" in w
    w = sigma.compile_rule(_rule({"s": {"Details|cased": "ABC"}, "condition": "s"}))["where"]
    assert "details = 'ABC'" in w
    w = sigma.compile_rule(_rule({"sel": {"Details": "x"}, "s": {"Details": None}, "condition": "sel and not s"}))["where"]
    assert "NOTFALSE" in w.replace("(", "").replace(")", "").replace(" ", "")


def test_conditions() -> None:
    det = {"selection_a": {"Details": "a"}, "selection_b": {"Details": "b"}, "filter_x": {"Details": "x"},
           "condition": "1 of selection_* and not (filter_x or all of selection_*)"}
    w = sigma.compile_rule(_rule(det))["where"]
    assert w.count("lower(details) = 'a'") == 2 and "NOT" in w and " OR " in w
    assert "kind = 'value'" in w
    w = sigma.compile_rule(_rule({"s": {"EventType": "CreateKey"}, "condition": "s"}, cat="registry_add"))["where"]
    assert w.startswith("(kind = 'key')")
    assert "op = 'recovered'" in sigma.compile_rule(_rule({"s": {"Details": "a"}, "condition": "s"},
                                                          cat="registry_delete"))["where"]


@pytest.mark.parametrize("det, why", [
    ({"k": ["a"], "condition": "k"}, "keyword"),
    ({"s": {"Details|base64": "a"}, "condition": "s"}, "modifier base64"),
    ({"s": {"Details": "a"}, "condition": "s | count() > 5"}, "aggregation"),
    ({"s": {"Image|endswith": "\\x.exe", "Details": "a"}, "condition": "s"}, "not in a hive"),
    ({"s": {"Details": "a"}, "f": {"Image": "y"}, "condition": "s and not f"}, "not in a hive"),
    ({"s": {"Details": "a"}, "condition": "s and t"}, "unknown selection"),
])
def test_skipped(det: dict, why: str) -> None:
    with pytest.raises(sigma.Skip, match=why):
        sigma.compile_rule(_rule(det))


def test_process_filter_unapplied_when_allowed() -> None:
    r = sigma.compile_rule(_rule({"s": {"Details": "a"}, "f": {"Image": "y"}, "condition": "s and not f"}), True)
    assert r["process_filters_unapplied"] == ["Image"]
    assert "NOTFALSE" in r["where"].replace("(", "").replace(")", "").replace(" ", "")


def _write(tmp: Path) -> Path:
    for k, v in S.items():
        p = tmp / k
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(v)
    return tmp / "registry" / "sigma"


def test_load_folder(tmp_path: Path) -> None:
    folder = _write(tmp_path)
    got = sigma.load(folder)
    assert len(got["rules"]) == 5 and got["files"] == 9
    assert {s["title"] for s in got["skipped"]} == {"Defender Path Exclusion Added", "Keyword Rule (skipped)",
                                                    "Value Written By A Script Host (skipped)",
                                                    "Service Binary In A Suspicious Folder"}
    on = sigma.load(folder, True)
    # + the Defender one (its Image filter not applied) and the service one (its Image selection left out);
    # a rule whose only selection needs Image cannot be confirmed on a hive: still skipped
    assert len(on["rules"]) == 7
    assert any("nothing left" in s["reason"] for s in on["skipped"] if "Script Host" in s["title"])
    assert sigma.load(tmp_path / "missing")["error"].startswith("not a folder")


def test_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import registry
    folder = _write(tmp_path)
    monkeypatch.setattr(appsettings, "sigma_settings", lambda: {"folder": str(folder), "process_filters": False})
    res = registry.analyze([(tmp_path / "registry" / "sample_sigma.reg", "sample_sigma.reg")], tmp_path / "case",
                           tmp_path / "work")
    assert not any(f["rule"].startswith("sigma:") for f in res["findings"])      # hunting: no findings, no IOCs
    monkeypatch.setattr(appsettings, "sigma_settings", lambda: {"folder": "", "process_filters": False})
    base = registry.analyze([(tmp_path / "registry" / "sample_sigma.reg", "sample_sigma.reg")], tmp_path / "case0",
                            tmp_path / "work0")
    assert res["ioc_sources"] == base["ioc_sources"] and len(res["findings"]) == len(base["findings"])
    sig = {h["rule"]: h for h in res["hits"] if h.get("hunting")}
    assert {h["title"] for h in sig.values()} == {"Sigma: Encoded PowerShell In A Run Key", "Sigma: WDigest UseLogonCredential Enabled",
                                                  "Sigma: Sync Tool Key Created Under A User", "Sigma: Hidden PowerShell Window In A Value"}
    wd = sig["sigma:3f1c9a2e-7b4d-4e61-9a0b-5c2d8e7f1a02"]
    assert wd["severity"] == "high" and "T1003.001" in wd["attack"] and "ControlSet001" in wd["items"][0]["key"]
    assert res["sigma"]["loaded"] == 5 and res["sigma"]["matched"] == 4 and res["sigma"]["skipped_count"] == 4
    hit = sig["sigma:3f1c9a2e-7b4d-4e61-9a0b-5c2d8e7f1a01"]
    assert hit["sigma"]["file"] == "run_encoded_powershell.yml" and hit["items"][0]["name"] == "FacturaUpd"

    monkeypatch.setattr(appsettings, "sigma_settings", lambda: {"folder": str(folder), "process_filters": True})
    res = registry.analyze([(tmp_path / "registry" / "sample_sigma.reg", "sample_sigma.reg")], tmp_path / "case2",
                           tmp_path / "work2")
    d = next(h for h in res["hits"] if "Defender Path Exclusion" in h["title"])
    assert d["sigma"]["ignored_fields"] == ["Image"]
    sv = next(h for h in res["hits"] if "Suspicious Folder" in h["title"])
    assert [(it["key"].rsplit("\\", 1)[-1], it["name"]) for it in sv["items"]] == [("FacturaSvc", "ImagePath")]
    assert sv["sigma"]["selections_left_out"] == ["selection_proc"] and sv["sigma"]["ignored_fields"] == ["EventID"]
    assert not any(f["rule"].startswith("sigma:") for f in res["findings"])


def test_settings_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(appsettings, "settings_path", lambda: tmp_path / "settings.json")
    assert appsettings.set_sigma_settings(str(tmp_path), True) == {"folder": str(tmp_path), "process_filters": True}
    with pytest.raises(ValueError):
        appsettings.set_sigma_settings(str(tmp_path / "nope"), False)
    assert appsettings.set_sigma_settings("", False)["folder"] == ""


def test_fields_a_hive_does_not_have(tmp_path: Path) -> None:
    det = {"sel_id": {"EventID": 13}, "sel": {"TargetObject|contains": "\\Run\\"},
           "f": {"Image|endswith": "\\svchost.exe"}, "condition": "all of sel* and not f"}
    r = sigma.compile_rule(_rule(det), True)
    assert r["ignored_fields"] == ["EventID", "Image"] and "contains(lower(target), '\\run\\')" in r["where"]
    # event metadata is dropped even with the option off; a selection that needs Image is left out
    r = sigma.compile_rule(_rule({"s": {"EventID": 13, "TargetObject|contains": "\\Run\\"}, "condition": "s"}))
    assert r["ignored_fields"] == ["EventID"] and r["selections_left_out"] == []
    r = sigma.compile_rule(_rule({"a": {"Image|endswith": "\\x.exe", "TargetObject|endswith": "\\Start"},
                                  "b": {"Details|contains": "\\Public\\"}, "condition": "a or b"}), True)
    assert r["selections_left_out"] == ["a"] and "FALSE" in r["where"] and "start" not in r["where"]
    with pytest.raises(sigma.Skip, match="nothing left to match"):
        sigma.compile_rule(_rule({"s": {"Image|endswith": "\\reg.exe"}, "condition": "s"}), True)
    # Security 4657 fields and Sysmon's NewName read from the key / value
    w = sigma.compile_rule(_rule({"s": {"ObjectName|contains": "\\REGISTRY\\MACHINE\\SOFTWARE",
                                        "ObjectValueName": "Debugger", "NewName|endswith": "\\x"},
                                  "condition": "s"}))["where"]
    assert "lower(objname)" in w and "lower(vname) = 'debugger'" in w and "ends_with(lower(target)" in w


def test_objectname_and_rules_with_colons(tmp_path: Path) -> None:
    from docutracex import registry
    folder = _write(tmp_path)
    (folder / "custom_security.yml").write_bytes(
        b"title: Run key via Security logs: 4657\nid: c0ffee00-0000-4000-8000-000000000001\n"
        b"description: Hand-written rule: an unquoted colon\nlogsource:\n    product: windows\n    category: registry_set\n"
        b"detection:\n    selection:\n        EventID: 4657\n"
        b"        ObjectName|endswith: '\\REGISTRY\\USER\\S-1-5-21-0-0-0-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'\n"
        b"        ObjectValueName: FacturaUpd\n    condition: selection\nlevel: high\n")
    loaded = sigma.load(folder, True)
    assert any(r["title"] == "Run key via Security logs: 4657" for r in loaded["rules"])
    registry.ingest([(tmp_path / "registry" / "sample_sigma.reg", "sample_sigma.reg")], tmp_path / "c", tmp_path / "w")
    from docutracex.registry import store
    hits = sigma.run(store.db_path(tmp_path / "c"), loaded)
    h = next(x for x in hits if x["title"] == "Sigma: Run key via Security logs: 4657")
    assert h["items"][0]["name"] == "FacturaUpd" and h["sigma"]["ignored_fields"] == ["EventID"]
