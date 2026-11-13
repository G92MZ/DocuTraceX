"""Registry module: .reg / hive parsing, the case database, rules, carving, API and AI tool."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402
import regkit  # noqa: E402

pytest.importorskip("duckdb")
pytest.importorskip("regipy")

from docutracex import registry  # noqa: E402
from docutracex.registry import parse, rules, store  # noqa: E402


def _write(tmp: Path, name: str, data: bytes) -> Path:
    p = tmp / name
    p.write_bytes(data)
    return p


# --- parsing --------------------------------------------------------------------------------
def test_reg_text_parser(tmp_path: Path) -> None:
    text = ("Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Demo]\r\n"
            '"Str"="a \\"quoted\\" value"\r\n'
            '"Num"=dword:0000002a\r\n'
            '"Bin"=hex:01,02,\\\r\n  03,04\r\n'
            '"Multi"=hex(7):61,00,00,00,62,00,00,00,00,00\r\n'
            '"Gone"=-\r\n'
            "@=\"default\"\r\n\r\n"
            "[-HKEY_LOCAL_MACHINE\\SOFTWARE\\Old]\r\n")
    p = _write(tmp_path, "x.reg", text.encode("utf-16"))
    assert parse.is_reg_text(p) and not parse.is_hive(p)
    keys, vals = parse.iter_reg(p)
    assert {k[0]: k[6] for k in keys} == {"HKCU\\Software\\Demo": "", "HKLM\\SOFTWARE\\Old": "delete"}
    v = {r[1]: r for r in vals}
    assert v["Str"][3] == 'a "quoted" value' and v["Str"][2] == "REG_SZ"
    assert v["Num"][2] == "REG_DWORD" and v["Num"][3] == "42"
    assert v["Bin"][5] == b"\x01\x02\x03\x04"
    assert v["Multi"][3] == "a\nb"
    assert v["Gone"][6] == "delete" and v["(default)"][3] == "default"


def test_regkit_hive_reads_back(tmp_path: Path) -> None:
    tree = {"Software": {"Demo": {"@values": [("Path", "REG_SZ", "C:\\x.exe"), ("N", "REG_DWORD", 7),
                                              ("B", "REG_BINARY", b"\x00\x01")]}}}
    p = _write(tmp_path, "NTUSER.DAT", regkit.build(tree, file_name="ntuser.dat"))
    assert parse.is_hive(p)
    info = parse.hive_info(p)
    assert info["mount"] == "HKCU"
    rows = list(parse.iter_hive(p, info["mount"]))
    keys = {r[0] for w, r in rows if w == "key"}
    assert "HKCU\\Software\\Demo" in keys
    vals = {r[1]: r for w, r in rows if w == "value"}
    assert vals["Path"][3] == "C:\\x.exe" and vals["N"][3] == "7" and vals["B"][5] == b"\x00\x01"


# --- the case database + rules on the two shipped samples --------------------------------------
@pytest.fixture()
def analysed(tmp_path: Path):
    case = tmp_path / "case"
    files = [(_write(tmp_path, "sample_persistence.reg", ms.registry_persistence_reg()), "sample_persistence.reg"),
             (_write(tmp_path, "sample_NTUSER.DAT", ms.registry_ntuser_hive()), "sample_NTUSER.DAT")]
    res = registry.analyze(files, case, tmp_path / "work")
    return case, res


def test_ingest_and_rules(analysed) -> None:
    case, res = analysed
    assert res["status"] == "ok" and store.db_path(case).is_file()
    kinds = {s["kind"] for s in res["sources"]}
    assert kinds == {"reg", "hive"} and not any(s["error"] for s in res["sources"])
    got = {f["rule"] for f in res["findings"]}
    for rule in ("reg_autorun", "reg_ifeo_debugger", "reg_defender_exclusion", "reg_uac_bypass_handler", "reg_wdigest",
                 "reg_com_hijack", "reg_logon_script", "reg_proxy", "reg_root_certificate", "reg_payload_in_value"):
        assert rule in got, rule
    auto = next(f for f in res["findings"] if f["rule"] == "reg_autorun")
    assert auto["severity"] == "high" and "suspicious command" in auto["detail"]
    assert res["carved"] and all(Path(p).is_file() for p, _n in res["_carved_paths"])
    assert any(c.get("subject", "").find("inert") >= 0 for c in res["certificates"])


def test_rules_are_well_formed() -> None:
    ids = [r["id"] for r in rules.RULES]
    assert len(ids) == len(set(ids))
    for r in rules.RULES:
        assert r["severity"] in ("high", "medium", "low", "info") and r["attack"] and r["key"]
        sql, args = rules.sql_for(r)
        assert sql.lstrip().upper().startswith("SELECT") and isinstance(args, list)


def test_benign_autorun_not_suspicious(tmp_path: Path) -> None:
    text = ("Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
            '"OneDrive"="\\"C:\\\\Users\\\\ana\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDrive.exe\\" /background"\r\n')
    p = _write(tmp_path, "ok.reg", text.encode("utf-16"))
    res = registry.analyze([(p, "ok.reg")], tmp_path / "c", tmp_path / "w")
    hit = next(h for h in res["hits"] if h["rule"] == "reg_autorun")
    assert hit["suspicious"] == 0 and hit["severity"] != "high"


def test_queries_browse_and_search(analysed) -> None:
    case, _res = analysed
    db = store.db_path(case)
    roots = store.children(db, 0, "")["subkeys"]
    assert {r["name"] for r in roots} >= {"HKCU", "HKLM"}
    reg_src = next(r["src"] for r in roots if r["name"] == "HKLM")
    sub = store.children(db, reg_src, "HKLM")["subkeys"]
    assert any(s["name"].upper() == "SOFTWARE" for s in sub)
    found = store.search(db, "mshta", "data")
    assert found["rows"] and all("mshta" in (r[4] or "").lower() for r in found["rows"])
    rx = store.search(db, r"currentversion\\run$", "key", regex=True)
    assert rx["rows"]
    res = store.user_query(db, "SELECT count(*) AS n FROM vals WHERE type = 'REG_DWORD'")
    assert res["columns"] == ["n"] and res["rows"][0][0] > 0


@pytest.mark.parametrize("sql", [
    "DROP TABLE vals", "SELECT 1; DROP TABLE vals", "SELECT * FROM read_csv('/etc/passwd')",
    "ATTACH '/tmp/x.db'", "COPY vals TO '/tmp/x.csv'", "SET enable_external_access = true",
    "SELECT * FROM 'http://198.51.100.7/x.csv'", "INSTALL httpfs",
])
def test_user_query_is_read_only(analysed, sql: str) -> None:
    case, _res = analysed
    with pytest.raises(Exception):
        store.user_query(store.db_path(case), sql)


def test_database_persists_across_connections(analysed) -> None:
    case, res = analysed
    db = store.db_path(case)
    n = store.query(db, "SELECT sum(vals) FROM sources")["rows"][0][0]
    assert n == res["counts"]["values"] > 0
    assert store.query(db, "SELECT sum(vals) FROM sources")["rows"][0][0] == n  # reopened, nothing re-parsed


# --- pipeline, API and the AI / MCP tool -------------------------------------------------------
def test_pipeline_api_and_ai_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex import ai_tools, analyze, cases as cs
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cs.create_case(io.BytesIO(ms.registry_persistence_reg()), "sample_persistence.reg", cases_dir=tmp_path)
    cid = m["analysis_id"]
    analyze.analyze_case(tmp_path / cid)
    sub = read_json(CasePaths(cid, cases_dir=tmp_path).subresult("registry"))
    assert sub and sub["status"] == "ok" and any(f["rule"] == "reg_uac_bypass_handler" for f in sub["findings"])

    info = ai_tools.run_tool("query_registry", {"case_id": cid})
    assert info["rows"] and "vals" in info["schema"]
    q = ai_tools.run_tool("query_registry", {"case_id": cid, "sql": "SELECT name FROM vals WHERE name = 'DisableAntiSpyware'"})
    assert "error" not in q
    bad = ai_tools.run_tool("query_registry", {"case_id": cid, "sql": "DELETE FROM vals"})
    assert "error" in bad

    from docutracex.app import app
    client = TestClient(app)
    if client.get(f"/api/cases/{cid}/registry/sources").status_code in (401, 403):
        pytest.skip("auth enabled in this environment")
    assert client.get(f"/api/cases/{cid}/registry/sources").json()["rows"]
    r = client.post(f"/api/cases/{cid}/registry/sql", json={"sql": "SELECT count(*) FROM keys"})
    assert r.status_code == 200 and r.json()["rows"][0][0] > 0
    assert client.post(f"/api/cases/{cid}/registry/sql", json={"sql": "DROP TABLE keys"}).status_code == 400
    csv = client.post(f"/api/cases/{cid}/registry/export.csv", json={"q": "fodhelper"})
    assert csv.status_code == 200 and csv.text.splitlines()[0].startswith("src,")


def test_reads_on_the_portable_when_the_host_has_no_duckdb(analysed, tmp_path: Path,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    """The web app's Python carries no DuckDB: reads go to the portable interpreter."""
    import os

    from docutracex.registry import remote
    case, _res = analysed
    shim = tmp_path / "portable-python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    shim.chmod(0o755)
    monkeypatch.setenv("DOCUTRACEX_PYTHON", str(shim))
    monkeypatch.setattr(store, "available", lambda: False)
    if os.name == "nt":
        pytest.skip("shell shim")
    db = store.db_path(case)
    assert remote.available()
    res = remote.call("search", path=db, q="mshta", where="data", src=0, regex=False, limit=10, offset=0)
    assert res["rows"]
    assert remote.call("children", path=db, src=0, key="")["subkeys"]
    with pytest.raises(ValueError):
        remote.call("user_query", path=db, sql="DROP TABLE vals", limit=10)


def test_less_common_autostarts_and_tampering(tmp_path: Path) -> None:
    """sample_system_tampering.reg: each technique is flagged, the ordinary value next to it is not."""
    p = _write(tmp_path, "sample_system_tampering.reg", ms.registry_system_tampering_reg())
    res = registry.analyze([(p, p.name)], tmp_path / "c", tmp_path / "w")
    by = {f["rule"]: f for f in res["findings"]}
    for rule in ("reg_windows_load", "reg_active_setup", "reg_boot_execute", "reg_appcert_dlls", "reg_print_monitor",
                 "reg_cmd_autorun", "reg_service", "reg_service_dll", "reg_service_masquerade", "reg_com_script_moniker",
                 "reg_file_association", "reg_script_logging_disabled", "reg_amsi_disabled", "reg_obfuscated_script",
                 "reg_base64_blob", "reg_wmi_consumer", "reg_ransomware_extension", "reg_ransomware_file"):
        assert rule in by, rule
    assert "ie4uinit" not in by["reg_active_setup"]["evidence"]
    assert "tcpmon" not in by["reg_print_monitor"]["evidence"]
    assert "reg_ifeo_debugger" not in by                       # a Visual Studio JIT debugger only
    assert "fsync.exe" in by["reg_boot_execute"]["evidence"]
    assert by["reg_service"]["severity"] == "high" and "fupd.exe" in by["reg_service"]["evidence"]


def test_generic_rules_do_not_repeat_reported_values(analysed) -> None:
    _case, res = analysed
    rules_by_value: dict = {}
    for f in res["findings"]:
        for line in f["evidence"].splitlines():
            rules_by_value.setdefault(line.split(" = ")[0], set()).add(f["rule"])
    generic = {"reg_command_in_value", "reg_obfuscated_script", "reg_base64_blob", "reg_long_string", "reg_file_association"}
    for value, rs in rules_by_value.items():
        assert len(rs & generic) == 0 or len(rs - {"reg_payload_in_value", "reg_root_certificate"}) == 1, (value, rs)


def test_host_duckdb_of_another_version_reads_through_the_portable(analysed, tmp_path: Path,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    """The web app's Python has a DuckDB other than the portable's (which wrote the file): reads go
    to the portable instead of failing with a storage-version error."""
    import os

    from docutracex.registry import remote
    if os.name == "nt":
        pytest.skip("shell shim")
    case, _res = analysed
    shim = tmp_path / "portable-python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    shim.chmod(0o755)
    monkeypatch.setenv("DOCUTRACEX_PYTHON", str(shim))
    real = remote._duckdb_version
    monkeypatch.setattr(remote, "_duckdb_version", lambda py: "0.0.1" if py is None else real(py))
    monkeypatch.setattr(remote, "_LOCAL", None)
    called = []
    monkeypatch.setattr(store, "children", lambda **kw: called.append(kw) or {})
    res = remote.call("children", path=store.db_path(case), src=0, key="")
    assert not called and res["subkeys"]          # not read in-process; the portable answered


def test_storage_version_error_falls_back_to_the_portable(analysed, tmp_path: Path,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    from docutracex.registry import remote
    if os.name == "nt":
        pytest.skip("shell shim")
    case, _res = analysed
    shim = tmp_path / "portable-python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    shim.chmod(0o755)
    monkeypatch.setenv("DOCUTRACEX_PYTHON", str(shim))
    monkeypatch.setattr(remote, "_LOCAL", True)

    def old(**kw):  # noqa: ANN003, ANN202
        raise OSError("IO Error: Trying to read a database file with version number 69, but we can only read 64-68")
    monkeypatch.setattr(store, "search", old)
    res = remote.call("search", path=store.db_path(case), q="mshta", where="data", src=0, regex=False, limit=5, offset=0)
    assert res["rows"] and remote._LOCAL is False
