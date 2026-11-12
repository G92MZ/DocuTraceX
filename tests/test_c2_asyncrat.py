"""AsyncRAT / DcRAT in depth: settings named by their field, the pinned certificate,
the Pastebin dead drop, options and persistence in plain words, builder defaults,
and indicators when nothing decrypts."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import make_samples as ms  # noqa: E402

from docutracex.c2 import correlate, dotnet_rats  # noqa: E402


def test_settings_named_by_field() -> None:
    names, cls = dotnet_rats.settings_fields(ms.asyncrat_exe())
    assert cls == "Client.Settings"
    assert {"Hosts", "Ports", "MTX", "Pastebin", "Certificate", "Anti", "BDOS", "Delay"} <= {f for fs in names.values() for f in fs}


def test_asyncrat_card() -> None:
    r = dotnet_rats.extract(ms.asyncrat_exe())
    s = r["summary"]
    assert r["family"] == "AsyncRAT" and r["c2"] == ["cdn-update.example.net", "203.0.113.47"]
    assert s["C2"][0] == "cdn-update.example.net:6606" and len(s["C2"]) == 6        # the delay (3) is not a port
    assert s["Install path"] == "%AppData%\\WinUpdate.exe"
    assert any("WinUpdate" in p for p in s["Persistence"])
    assert s["Certificate CN"] == "AsyncRAT Server" and len(s["Certificate SHA-1"]) == 40
    assert any("builder default mutex" in d for d in s["Builder defaults"])
    assert "named from Client.Settings" in r["method"] and r["fields"]["MTX"] == "AsyncMutex_6SI8OkPnk"
    assert "Certificate" not in r["fields"]                                           # the blob stays out of the card
    assert correlate.fingerprints({"summary": s})["pubkey"] == s["Certificate SHA-1"]


def test_pastebin_dead_drop_and_options() -> None:
    r = dotnet_rats.extract(ms.asyncrat_pastebin_exe())
    s = r["summary"]
    assert s["Dead drop (Pastebin)"] == "https://paste.invoice-support.example/raw/Fct0187"
    assert r["c2"] == ["paste.invoice-support.example"] and "C2" not in s
    assert any(o.startswith("anti-analysis") for o in s["Options"]) and any(o.startswith("BDOS") for o in s["Options"])
    assert s["Install"].startswith("no")


def test_traces_when_nothing_decrypts() -> None:
    r = dotnet_rats.extract(ms.asyncrat_traces_exe())
    assert r["kind"] == "indicators" and r["c2"] == [] and len(r["indicators"]) >= 3
    assert dotnet_rats.traces(b"MZ BSJB just a Pastebin word") is None


def test_ratking_undecrypted_is_nothing() -> None:
    from docutracex.c2 import ratking
    v = ratking.view({"status": "found", "lib": "4.2.4", "report": {"key": "None", "config": {"Hosts": ["Zm9v=="]}}})
    assert v["status"] == "nothing" and "could not decrypt" in v["note"]


def test_family_cards_and_markdown(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    import io
    import os

    from docutracex import analyze, cases, mdreport
    from docutracex.c2 import families
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    assert {f["id"] for f in families.FAMILIES} == {"cobalt", "asyncrat", "rmm"}
    assert families.for_family("RMM: AnyDesk")["id"] == "rmm" and families.for_family("Remcos") is None
    monkeypatch.setitem(os.environ, "DOCUTRACEX_AUTO_MODULES", "c2")
    m = cases.create_case(io.BytesIO(ms.asyncrat_exe()), "factura.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    md = {s["id"]: s["markdown"] for s in mdreport.build(m["analysis_id"])}
    assert "### About AsyncRAT / DcRAT" in md["c2"] and "Certificate SHA-1" in md["c2"]
    assert "### About Cobalt Strike" not in md["c2"]                       # only the families present
    assert md["yara"].startswith("# YARA") and md["rmm"].startswith("# RMM / remote-access tools")
    m2 = cases.create_case(io.BytesIO(ms.rmm_screenconnect_msi()), "VisorFacturas.msi", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m2["analysis_id"])
    rmm_md = {s["id"]: s["markdown"] for s in mdreport.build(m2["analysis_id"])}["rmm"]
    assert "### About RMM / remote-access tools" in rmm_md and ms.RMM_RELAY in rmm_md
