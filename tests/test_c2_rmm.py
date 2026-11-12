"""RMM / remote-access tools: the product, and the instance an installer binds it to."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import make_samples as ms  # noqa: E402

from docutracex import c2  # noqa: E402
from docutracex.c2 import rmm  # noqa: E402


def test_screenconnect_msi_relay(tmp_path: Path) -> None:
    p = tmp_path / "VisorFacturas.msi"
    p.write_bytes(ms.rmm_screenconnect_msi())
    cfgs, runs = c2.scan_object_detailed(p, p.read_bytes())
    sc = next(c for c in cfgs if c["family"].startswith("RMM: ScreenConnect"))
    assert sc["kind"] == "rmm" and sc["c2"] == [ms.RMM_RELAY]
    assert sc["summary"]["C2"] == [f"{ms.RMM_RELAY}:8041"] and sc["summary"]["Session type"] == "Access"
    assert next(r for r in runs if r["extractor"] == "rmm")["status"] == "extracted"
    f = c2._finding(sc)
    assert f["rule"] == "c2:rmm" and f["severity"] == "medium" and ms.RMM_RELAY in f["detail"]


def test_netsupport_gateway() -> None:
    r = rmm.extract(ms.rmm_netsupport_ini(), "client32.ini")[0]
    assert r["family"] == "RMM: NetSupport Manager"
    assert r["c2"] == ["198.51.100.61", "update-cdn.invoice-support.example"]


def test_product_only_is_indicators_and_low() -> None:
    r = rmm.extract(b"MZ AnyDesk.exe philandro Software GmbH", "AnyDesk.exe")[0]
    assert r["kind"] == "indicators" and r["c2"] == []
    assert c2._finding(r)["severity"] == "low"
    assert rmm.extract(b"just the word anydesk once", "x") == []          # one weak string is not enough


def test_utf16_at_odd_offset() -> None:
    data = b"\x00\x01" + b"X" + "rutserv.exe".encode("utf-16-le") + b"\x00" * 10
    assert rmm.extract(data, "x")[0]["family"] == "RMM: Remote Utilities"


# --- LOLRMM catalogue ------------------------------------------------------------------------

def _catalogue(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    import json

    from docutracex import lolrmm
    tools = [{"Name": "GetScreen", "Category": "RMM", "Details": {"Website": "https://getscreen.me/",
              "PEMetadata": [{"Filename": "getscreen.exe", "OriginalFileName": "", "Description": ""}],
              "InstallationPaths": ["C:\\Program Files\\Getscreen\\getscreen.exe", "*\\setup.exe"]},
              "Artifacts": {"Network": [{"Domains": ["*.getscreen.me", "*.amazonaws.com"]}]},
              "CodeSigning": {"certificates": [{"signer_name": "Kopetra Ltd."}]}},
             {"Name": "Sophos-Remote Management System", "Category": "RMM", "Details": {"PEMetadata": []},
              "Artifacts": {"Network": [{"Domains": ["*.sophos.com"]}]}},
             {"Name": "ScreenConnect", "Category": "RMM", "Details": {"PEMetadata": [],
              "InstallationPaths": ["screenconnect.windowsclient.exe"]}, "Artifacts": {}}]
    tools += [{"Name": f"Filler {i}", "Details": {}} for i in range(60)]
    p = tmp_path / "lolrmm" / "rmm_tools.json"
    p.parent.mkdir()
    p.write_text(json.dumps(tools))
    monkeypatch.setattr(lolrmm, "path", lambda: p)


def test_lolrmm_only_product(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    from docutracex import lolrmm
    _catalogue(tmp_path, monkeypatch)
    cat = lolrmm.products()
    assert cat["GetScreen"]["domains"] == ["getscreen.me"]               # generic cloud domains dropped
    assert "setup.exe" not in cat["GetScreen"]["files"]                   # generic installer names dropped
    r = rmm.extract(ms.rmm_lolrmm_only_exe(), "soporte.exe")
    assert [(x["family"], x["kind"], x["summary"]["LOLRMM"]) for x in r] == [("RMM: GetScreen", "indicators", "GetScreen (RMM)")]
    assert lolrmm.status()["source"] == "lolrmm"


def test_lolrmm_vendor_domain_alone_is_not_a_product(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    _catalogue(tmp_path, monkeypatch)
    assert rmm.extract(b"see https://www.sophos.com/support for help", "mail.eml") == []


def test_lolrmm_merges_into_builtin(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    _catalogue(tmp_path, monkeypatch)
    r = rmm.extract(ms.rmm_screenconnect_msi(), "x.msi")
    assert len(r) == 1 and r[0]["family"] == "RMM: ScreenConnect (ConnectWise Control)"
    assert r[0]["summary"]["Relay"] == ms.RMM_RELAY and r[0]["summary"]["LOLRMM"] == "ScreenConnect (RMM)"


def test_without_catalogue_builtin_only(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    from docutracex import lolrmm
    monkeypatch.setattr(lolrmm, "path", lambda: tmp_path / "missing.json")
    assert lolrmm.status()["source"] == "builtin"
    assert rmm.extract(ms.rmm_lolrmm_only_exe(), "x.exe") == []


def test_same_relay_host_once() -> None:
    d = (b'ScreenConnect.ClientService.exe "?e=Access&y=Guest&h=instance-abc123-relay.screenconnect.com&p=443&k=x" '
         b'instance-abc123-relay.screenconnect.com')
    r = rmm.extract(d, "x.exe")[0]
    assert r["summary"]["C2"] == ["instance-abc123-relay.screenconnect.com:443"]
    assert r["c2"] == ["instance-abc123-relay.screenconnect.com"]
