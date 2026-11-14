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
    w = sigma.compile_rule(_rule({"s": {"Details": None}, "condition": "not s"}))["where"]
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
    ({"s": {"Image|endswith": "\\x.exe", "Details": "a"}, "condition": "s"}, "selection the rule needs"),
    ({"s": {"Details": "a"}, "f": {"Image": "y"}, "condition": "s and not f"}, "process filters are off"),
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
    assert len(got["rules"]) == 5 and got["files"] == 8
    assert {s["title"] for s in got["skipped"]} == {"Defender Path Exclusion Added", "Keyword Rule (skipped)",
                                                    "Value Written By A Script Host (skipped)"}
    assert len(sigma.load(folder, True)["rules"]) == 6
    assert sigma.load(tmp_path / "missing")["error"].startswith("not a folder")


def test_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import registry
    folder = _write(tmp_path)
    monkeypatch.setattr(appsettings, "sigma_settings", lambda: {"folder": str(folder), "process_filters": False})
    res = registry.analyze([(tmp_path / "registry" / "sample_sigma.reg", "sample_sigma.reg")], tmp_path / "case",
                           tmp_path / "work")
    sig = {f["rule"]: f for f in res["findings"] if f["rule"].startswith("sigma:")}
    titles = {f["detail"].split(" — ")[0] for f in sig.values()}
    assert titles == {"Sigma: Encoded PowerShell In A Run Key", "Sigma: WDigest UseLogonCredential Enabled",
                      "Sigma: Sync Tool Key Created Under A User", "Sigma: Hidden PowerShell Window In A Value"}
    wd = sig["sigma:3f1c9a2e-7b4d-4e61-9a0b-5c2d8e7f1a02"]
    assert wd["severity"] == "high" and "T1003.001" in wd["detail"] and "ControlSet001" in wd["evidence"]
    assert res["sigma"]["loaded"] == 5 and res["sigma"]["matched"] == 4 and res["sigma"]["skipped_count"] == 3
    hit = next(h for h in res["hits"] if h["rule"] == "sigma:3f1c9a2e-7b4d-4e61-9a0b-5c2d8e7f1a01")
    assert hit["sigma"]["file"] == "run_encoded_powershell.yml" and hit["items"][0]["name"] == "FacturaUpd"
    assert any("powershell.exe -nop -enc" in s["text"] for s in res["ioc_sources"])

    monkeypatch.setattr(appsettings, "sigma_settings", lambda: {"folder": str(folder), "process_filters": True})
    res = registry.analyze([(tmp_path / "registry" / "sample_sigma.reg", "sample_sigma.reg")], tmp_path / "case2",
                           tmp_path / "work2")
    d = next(f for f in res["findings"] if "Defender Path Exclusion" in f["detail"])
    assert "process filter on Image was not applied" in d["detail"]


def test_settings_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(appsettings, "settings_path", lambda: tmp_path / "settings.json")
    assert appsettings.set_sigma_settings(str(tmp_path), True) == {"folder": str(tmp_path), "process_filters": True}
    with pytest.raises(ValueError):
        appsettings.set_sigma_settings(str(tmp_path / "nope"), False)
    assert appsettings.set_sigma_settings("", False)["folder"] == ""
