"""Warzone / AveMaria: .bss configuration, version, raw options and traces."""

from __future__ import annotations

import make_samples as ms

from docutracex.c2 import families, stealers


def test_config_version_options():
    r = stealers.extract_all(ms.warzone_exe())[0]
    s = r["summary"]
    assert s["C2"] == ["cdn-update.example.net:5200"] and s["Version"] == "1.60"
    assert r["fields"]["options (raw)"] == "010001" and "registry key _rptls" in s["Traces"]


def test_traces_only():
    r = stealers.extract_all(ms.warzone_traces_exe())[0]
    assert r["family"] == "Warzone / AveMaria" and r["kind"] == "indicators" and r["c2"] == []


def test_family_card():
    assert families.for_family("Warzone / AveMaria")["id"] == "warzone"
