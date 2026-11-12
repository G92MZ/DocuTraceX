"""RMM tools in the IOCs (tags) and in the text (rmm:mention findings)."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import make_samples as ms  # noqa: E402

from docutracex import lolrmm, rmmintel  # noqa: E402


@pytest.fixture
def builtin_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lolrmm, "path", lambda: tmp_path / "none.json")


def _m(text: str, c2: dict | None = None) -> list[tuple[str, str]]:
    r = rmmintel.mentions([{"module": "email", "location": "body", "text": text}], c2)
    return [(f["severity"], f["detail"].split(": ", 1)[1].split(" (")[0]) for f in r["findings"]]


def test_mention_severity(builtin_only: None) -> None:
    assert _m("Descargue AnyDesk desde https://x.example/AnyDesk.exe y envíe el ID") == [("medium", "AnyDesk")]
    assert _m("Instale TeamViewer y mándeme su ID 123 456 789") == [("low", "TeamViewer")]
    assert _m("Firma: el equipo usa TeamViewer en formación.") == [("info", "TeamViewer")]
    assert _m("https://x.example/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest") == \
        [("medium", "ScreenConnect")]


def test_no_mention_for_words_or_partial_names(builtin_only: None) -> None:
    assert _m("Remotely, the level of access is fine; anydeskish is not a product.") == []


def test_one_finding_per_product_and_not_when_c2_bound(builtin_only: None) -> None:
    r = rmmintel.mentions([{"module": "email", "location": "body", "text": "AnyDesk"},
                           {"module": "email", "location": "body_html", "text": "AnyDesk again"}])
    assert len(r["findings"]) == 1 and "2 mention(s) in 2 place(s)" in r["findings"][0]["evidence"]
    c2 = {"configs": [{"family": "RMM: AnyDesk", "c2": ["relay.example"]}]}
    assert _m("Descargue AnyDesk", c2) == []


def test_ioc_tags(builtin_only: None) -> None:
    res = {"iocs": [{"type": "url", "value": "https://dl.example/AnyDesk.exe"},
                    {"type": "domain", "value": "relay.screenconnect.com"},
                    {"type": "filepath", "value": r"C:\Users\Public\anydesk.exe"},
                    {"type": "domain", "value": "factura.example"}]}
    assert rmmintel.tag_iocs(res) == 3
    assert [(i.get("rmm") or {}).get("product") for i in res["iocs"]] == \
        ["AnyDesk", "ScreenConnect (ConnectWise Control)", "AnyDesk", None]


def test_support_scam_email_end_to_end(tmp_path: Path, builtin_only: None) -> None:
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json
    m = cases.create_case(io.BytesIO(ms.rmm_support_scam_eml()), "scam.eml", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    p = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    found = {(f["rule"], f["severity"], f["detail"].split(": ", 1)[1].split(" (")[0])
             for f in read_json(p.subresult("findings"))["findings"] if f["rule"] == "rmm:mention"}
    assert found == {("rmm:mention", "medium", "AnyDesk"), ("rmm:mention", "info", "TeamViewer")}
    tagged = [(i["value"], i["rmm"]["product"]) for i in read_json(p.subresult("iocs"))["iocs"] if i.get("rmm")]
    assert tagged == [("https://descargas.factura-soporte.example/AnyDesk.exe", "AnyDesk")]


def test_rmm_objects_in_a_normal_analysis(tmp_path: Path, builtin_only: None) -> None:
    """No C2 run: the trojanised installer still gives c2:rmm with its relay, and the relay joins the IOCs;
    running C2 afterwards does not duplicate the finding."""
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json
    m = cases.create_case(io.BytesIO(ms.rmm_screenconnect_msi()), "VisorFacturas.msi", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    p = CasePaths(m["analysis_id"], cases_dir=tmp_path)

    def rmm_findings() -> list[tuple[str, str]]:
        return [(f["rule"], f["severity"]) for f in read_json(p.subresult("findings"))["findings"] if "rmm" in f["rule"]]
    assert rmm_findings() == [("c2:rmm", "medium")]
    relay = [i for i in read_json(p.subresult("iocs"))["iocs"] if i["value"] == ms.RMM_RELAY]
    assert relay and relay[0]["rmm"]["product"].startswith("ScreenConnect")
    analyze.run_module(tmp_path / m["analysis_id"], "c2")
    assert rmm_findings() == [("c2:rmm", "medium")]
