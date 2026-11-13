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
        assert r["severity"] in ("high", "medium", "low", "info") and r["attack"] and (r.get("key") or r.get("custom"))
        if r.get("custom"):
            assert r["custom"].lstrip().upper().startswith("SELECT")
            continue
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


# --- catalogue (RECmd batch files) and decoded artifacts (regipy plugins) -----------------------
_REB = """Description: test batch
Author: tests
Version: 1
Id: 00000000-0000-0000-0000-000000000000
Keys:
    -
        Description: Run (NTUSER)
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\\Microsoft\\Windows\\CurrentVersion\\Run
        Recursive: false
        Comment: "Program execution upon successful user logon"
    -
        Description: TypedPaths
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths
        Recursive: false
        Comment: "Paths typed in Explorer"
    -
        Description: WordWheelQuery
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery
        ValueName: "0"
        Recursive: false
        Comment: "User searches"
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Environment
        ValueName: OneDrive
        Recursive: false
        Comment: "absent in the sample: no bookmark"
    -
        Description: WDigest
        HiveType: SYSTEM
        Category: Threat Hunting
        KeyPath: ControlSet00*\\Control\\SecurityProviders\\WDigest
        ValueName: UseLogonCredential
        Recursive: false
        Comment: "clear-text passwords"
    -
        Description: Last shutdown
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet00*\\Control\\Windows
        ValueName: ShutdownTime
        BinaryConvert: FILETIME
        Recursive: false
        Comment: "FILETIME"
    -
        Description: not a hive type
        HiveType: Nope
        Category: Other
        KeyPath: Anything
        Recursive: false
"""


@pytest.fixture()
def catalogue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from docutracex.config import settings
    tools = tmp_path / "tools"
    (tools / "recmd").mkdir(parents=True)
    (tools / "recmd" / "Kroll_Batch.reb").write_text(_REB, encoding="utf-8")
    monkeypatch.setattr(settings, "tools_dir", tools)
    return tools


def test_reb_parsing_and_paths() -> None:
    from docutracex.registry import catalog
    es = catalog.parse_reb(_REB, "t.reb")
    assert len(es) == 6 and {e["hive"] for e in es} == {"ntuser", "system"}
    lit, rx = catalog.key_regex("HKLM\\SYSTEM", "ControlSet00*\\Control\\Windows", False)
    import re
    assert re.match(rx, "HKLM\\SYSTEM\\ControlSet001\\Control\\Windows", re.I)
    assert re.match(rx, "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows", re.I)
    assert not re.match(rx, "HKLM\\SYSTEM\\ControlSet001\\Control\\Windows\\Sub", re.I)
    _lit, rx2 = catalog.key_regex("HKCU", "Software\\X", True)
    assert re.match(rx2, "HKCU\\Software\\X\\Y\\Z", re.I)
    assert catalog.convert("FILETIME", (133542000000000000).to_bytes(8, "little"), "") == "2024-03-06 12:00:00"
    assert catalog.convert("EPOCH", (1762526460).to_bytes(4, "little"), "") == "2025-11-07 14:41:00"
    assert catalog.convert("IP", bytes([198, 51, 100, 7]), "") == "198.51.100.7"
    assert catalog.convert(None, "factura".encode("utf-16-le") + b"\0\0", "hex") == "factura"
    assert catalog.convert(None, bytes.fromhex("00000000ffffffff"), "hex") == "hex"


def test_catalogue_bookmarks_and_artifacts_on_the_hive(tmp_path: Path, catalogue: Path) -> None:
    from docutracex.registry import catalog
    assert catalog.status()["entries"] == 7 and not catalog.stale() is None
    p = _write(tmp_path, "sample_NTUSER.DAT", ms.registry_ntuser_hive())
    res = registry.analyze([(p, p.name)], tmp_path / "case", tmp_path / "w")
    db = store.db_path(tmp_path / "case")
    assert res["counts"]["catalog"] > 0 and res["counts"]["artifacts"] > 0
    bms = store.bookmarks(db, 1)["bookmarks"]
    assert {b["description"] for b in bms} == {"Run (NTUSER)", "TypedPaths", "WordWheelQuery"}   # no OneDrive
    ua = store.artifact_rows(db, 1, plugin="user_assist")
    rows = [dict(zip(ua["columns"], r)) for r in ua["rows"]]
    sync = [r for r in rows if r["name"].endswith("sync.exe")]
    assert len(sync) == 1 and sync[0]["run_counter"] == 3 and sync[0]["timestamp"].startswith("2025-11-07T14:41")
    act = store.artifact_rows(db, 1, category="User Activity")
    vals = {r[2]: r[3] for r in act["rows"]}
    assert vals["url1"] == "\\\\198.51.100.23\\facturas" and vals["0"] == "factura 0613"
    summary = store.artifact_summary(db)
    assert {"user_assist", "typed_paths", "word_wheel_query"} <= {p["plugin"] for p in summary["plugins"]}
    tl = store.timeline(db)
    assert tl["rows"][0][2] == "artifact: user_assist"
    q = store.user_query(db, "SELECT json_extract_string(entry, '$.name') FROM artifacts WHERE plugin = 'user_assist'")
    assert any(r[0].endswith("sync.exe") for r in q["rows"])


def test_catalogue_on_a_reg_export_uses_the_mounts(tmp_path: Path, catalogue: Path) -> None:
    p = _write(tmp_path, "sample_persistence.reg", ms.registry_persistence_reg())
    registry.analyze([(p, p.name)], tmp_path / "case", tmp_path / "w")
    db = store.db_path(tmp_path / "case")
    bms = {b["description"]: b for b in store.bookmarks(db, 1)["bookmarks"]}
    assert "WDigest" in bms and bms["WDigest"]["key"].startswith("HKLM\\SYSTEM\\CurrentControlSet")
    assert "Run (NTUSER)" in bms
    assert store.artifact_summary(db)["plugins"] == []          # a .reg has no hive to decode


def test_older_databases_without_the_new_tables(tmp_path: Path) -> None:
    import duckdb
    db = tmp_path / "registry.duckdb"
    con = duckdb.connect(str(db))
    con.execute(store.SCHEMA.split("CREATE TABLE IF NOT EXISTS catalog")[0])
    con.close()
    assert store.bookmarks(db, 1) == {"bookmarks": []}
    assert store.artifact_summary(db) == {"catalog": [], "plugins": []}
    assert store.timeline(db)["rows"] == []


def test_artifact_flattening() -> None:
    from docutracex.registry import artifacts
    rows = artifacts._rows("p", {"\\Software\\Run": {"timestamp": "2025-11-07T14:40:00+00:00",
                                                       "values": [{"name": "a", "value": "x"}, {"name": "b", "value": "y"}]}})
    assert len(rows) == 2 and rows[0][2] == "\\Software\\Run" and rows[0][1] == "2025-11-07 14:40:00"
    dup = artifacts._rows("p", [{"name": "a"}, {"name": "a"}])
    assert len(dup) == 1
    assert artifacts._rows("p", {"error": "boom"}) == []
    flat = artifacts._rows("p", {"last_write": "2025-11-07T14:40:00", "entries": [{"url1": "u"}]})
    assert len(flat) == 1 and '"url1": "u"' in flat[0][4]


def test_concurrent_reads_of_the_same_database(analysed) -> None:
    """Browse and Bookmarks load at once: the second connection shares the locked instance."""
    case, _res = analysed
    db = store.db_path(case)
    first = store.connect_ro(db)
    try:
        assert store.children(db, 0, "")["subkeys"]
        assert store.bookmarks(db, 1) is not None
        with pytest.raises(Exception):
            store.user_query(db, "SELECT * FROM read_csv('/etc/passwd')")
    finally:
        first.close()


def test_artifact_keys_are_mounted(tmp_path: Path) -> None:
    p = _write(tmp_path, "sample_NTUSER.DAT", ms.registry_ntuser_hive())
    registry.analyze([(p, p.name)], tmp_path / "case", tmp_path / "w")
    db = store.db_path(tmp_path / "case")
    r = store.artifact_rows(db, 1, plugin="ntuser_persistence")
    keys = {row[r["columns"].index("key")] for row in r["rows"]}
    assert keys == {"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}


# --- deleted entries, hiding, machine context, IOCs, exports ------------------------------------
def test_recovers_deleted_keys_and_values(tmp_path: Path) -> None:
    from docutracex.registry import recover
    tree = {"Software": {"GrupoEjemplo": {"@values": [("Version", "REG_DWORD", 1)]}}}
    data = regkit.build(tree, file_name="ntuser.dat",
                        deleted_keys=[("Software\\GrupoEjemplo", "Instalador",
                                       [("Url", "REG_SZ", "https://cdn-update.example.net/x.msi"),
                                        ("Blob", "REG_BINARY", b"MZ" + b"\0" * 40)])],
                        deleted_values=[("FacturaSync", "REG_SZ", "powershell.exe -w hidden")])
    p = _write(tmp_path, "NTUSER.DAT", data)
    rows = list(recover.recover(p, "HKCU"))
    keys = {r[0] for w, r in rows if w == "key"}
    vals = {(r[0], r[1]): r for w, r in rows if w == "value"}
    assert "HKCU\\Software\\GrupoEjemplo\\Instalador" in keys
    assert "HKCU\\Software\\GrupoEjemplo" not in keys                      # the live key is not repeated
    assert vals[("HKCU\\Software\\GrupoEjemplo\\Instalador", "Url")][3].endswith("x.msi")
    assert vals[("HKCU\\Software\\GrupoEjemplo\\Instalador", "Blob")][5][:2] == b"MZ"
    assert vals[(f"HKCU\\{recover.ORPHAN_VALUES}", "FacturaSync")][6] == "recovered"
    # nothing to recover in a clean hive
    clean = _write(tmp_path, "clean.dat", regkit.build(tree, file_name="ntuser.dat"))
    assert list(recover.recover(clean, "HKCU")) == []


def test_recovered_entries_in_the_case(analysed) -> None:
    case, res = analysed
    db = store.db_path(case)
    by = {f["rule"]: f for f in res["findings"]}
    assert res["counts"]["recovered"] >= 3
    assert "reg_recovered_suspicious" in by and "recovered" in by["reg_recovered_suspicious"]["evidence"]
    sub = store.children(db, 2, "HKCU\\Software\\GrupoEjemplo")["subkeys"]
    assert any(k["name"] == "Instalador" and k["op"] == "recovered" for k in sub)


def test_hiding_tricks(analysed) -> None:
    _case, res = analysed
    by = {f["rule"]: f for f in res["findings"]}
    assert "␀InvoiceHelper" in by["reg_hidden_name"]["evidence"]
    assert "reg_script_in_autostart" in by


def test_timestamps_in_the_future(tmp_path: Path) -> None:
    future = (4102444800 + 11644473600) * 10_000_000 - 86400 * 10_000_000 * 30   # late 2099
    p = _write(tmp_path, "NTUSER.DAT", regkit.build({"Software": {"X": {}}}, file_name="ntuser.dat", timestamp=future))
    res = registry.analyze([(p, p.name)], tmp_path / "c", tmp_path / "w")
    assert "reg_future_timestamp" in {f["rule"] for f in res["findings"]}


def test_machine_context_across_hives(tmp_path: Path) -> None:
    import zipfile
    import io as _io
    zipfile.ZipFile(_io.BytesIO(ms.registry_machine_hives_zip())).extractall(tmp_path / "x")
    files = [(p, str(p.relative_to(tmp_path / "x"))) for p in sorted((tmp_path / "x").rglob("*")) if p.is_file()]
    res = registry.analyze(files, tmp_path / "c", tmp_path / "w")
    m = res["context"]["machine"]
    assert m["computer_name"] == "FACT-PC01" and m["utc_offset_min"] == 60 and m["control_set"] == "ControlSet001"
    assert m["product"] == "Windows 11 Pro" and m["install_date"].startswith("2025-01-10")
    assert m["last_shutdown"].startswith("2025-11-07")
    nt = next(s for s in res["sources"] if s["hive_type"] == "ntuser")
    assert nt["user"].startswith("facturacion (S-1-5-21-")
    db = store.db_path(tmp_path / "c")
    assert store.user_query(db, "SELECT value FROM context WHERE item = 'computer_name'")["rows"] == [["FACT-PC01"]]
    # the SYSTEM service in Public is a finding; nothing is "before install"
    rules_hit = {f["rule"] for f in res["findings"]}
    assert "reg_service" in rules_hit and "reg_before_install" not in rules_hit


def test_iocs_only_from_findings(analysed) -> None:
    from docutracex import ioc
    _case, res = analysed
    texts = " ".join(i["text"] for i in res["ioc_sources"])
    assert "cdn-update.example.net" in texts and "198.51.100.7" in texts
    assert "OneDrive.exe" not in texts                                    # a benign autorun is not an IOC source
    srcs = ioc.sources_from_modules({"registry": res})
    assert srcs and all(s["module"] == "registry" for s in srcs)
    assert len(srcs) == len([i for i in res["ioc_sources"] if i["text"].strip()])   # not the whole result walked


def test_reg_export_round_trip(analysed, tmp_path: Path) -> None:
    from docutracex.registry import export
    case, _res = analysed
    db = store.db_path(case)
    tree = store.subtree(db, 2, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")
    text = export.reg_text(tree, "test")
    p = _write(tmp_path, "out.reg", text)
    keys, vals = parse.iter_reg(p)
    got = {(r[0], r[1]): r for r in vals}
    ua = [k for k in got if k[0].endswith("\\Count")]
    assert ua and got[ua[0]][2] == "REG_BINARY" and len(got[ua[0]][5]) == 72
    assert got[("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "url1")][3] == "\\\\198.51.100.23\\facturas"
    # DWORD / EXPAND_SZ / MULTI_SZ survive too
    t2 = export.reg_text({"keys": [["HKLM\\SOFTWARE\\X", ""]], "values": [
        ["HKLM\\SOFTWARE\\X", "D", "REG_DWORD", "4294967236", None, ""],
        ["HKLM\\SOFTWARE\\X", "E", "REG_EXPAND_SZ", "%TEMP%\\a", None, ""],
        ["HKLM\\SOFTWARE\\X", "M", "REG_MULTI_SZ", "a\nb", None, ""],
        ["HKLM\\SOFTWARE\\X", "(default)", "REG_SZ", 'say "hi"', None, ""]]})
    _k, v2 = parse.iter_reg(_write(tmp_path, "t2.reg", t2))
    d2 = {r[1]: r for r in v2}
    assert d2["D"][3] == "4294967236" and d2["E"][3] == "%TEMP%\\a" and d2["M"][3] == "a\nb"
    assert d2["(default)"][3] == 'say "hi"'


def test_timeline_bodyfile_streams_in_pages(analysed) -> None:
    from docutracex.registry import export
    case, _res = analysed
    db = store.db_path(case)
    calls = []

    def fetch(limit, offset):  # noqa: ANN001, ANN202
        calls.append(offset)
        return store.timeline(db, 0, limit, offset)
    body = b"".join(export.timeline_chunks(fetch, "bodyfile", chunk=10)).decode()
    lines = body.strip().splitlines()
    total = len(store.timeline(db, 0, 100000, 0)["rows"])
    assert len(lines) == total and len(calls) > 1 and all(x.count("|") == 10 for x in lines)
    assert any("user_assist" in x for x in lines)
    csv_text = b"".join(export.timeline_chunks(fetch, "csv", chunk=1000)).decode()
    assert csv_text.startswith("ts_utc,src,what,key,detail")


def test_exports_are_audited() -> None:
    from docutracex import audit
    assert audit.audits_get("/api/cases/x/registry/export.reg")
    assert audit.audits_get("/api/cases/x/registry/timeline.export")
    assert not audit.audits_get("/api/cases/x/registry/key")


# --- the fast walker and a machine-sized sample -------------------------------------------------
def _norm(rows):  # noqa: ANN001, ANN202
    return sorted((w, r[0], r[1], r[2], str(r[3])[:19], r[-1]) if w == "key" else (w, r[0], r[1], r[2], r[3], r[-1])
                  for w, r in rows)


def test_fast_walker_matches_regipy(tmp_path: Path) -> None:
    hives = ms.registry_large_hives(0.02)
    for name, mount in (("NTUSER.DAT", "HKCU"), ("SYSTEM", "HKLM\\SYSTEM")):
        p = _write(tmp_path, name, hives[name])
        fast = list(parse.iter_hive(p, mount))
        assert _norm(fast) == _norm(parse._iter_hive_regipy(p, mount))
    p = _write(tmp_path, "sample_NTUSER.DAT", ms.registry_ntuser_hive())
    assert _norm(parse.iter_hive(p, "HKCU")) == _norm(parse._iter_hive_regipy(p, "HKCU"))


def test_fast_walker_falls_back_on_a_broken_structure(tmp_path: Path) -> None:
    data = bytearray(ms.registry_ntuser_hive())
    i = data.index(b"lh", 0x1000)
    data[i:i + 2] = b"zz"                                  # an unknown subkey-list signature
    p = _write(tmp_path, "NTUSER.DAT", bytes(data))
    rows = list(parse.iter_hive(p, "HKCU"))                 # regipy takes over; nothing raises
    assert rows and rows[0][0] == "key"


def test_machine_sized_sample_small_scale(tmp_path: Path) -> None:
    """The generator behind `samplegen.py --large-registry`, at 3 % of its size."""
    hives = ms.registry_large_hives(0.03)
    files = [(_write(tmp_path, n, d), n) for n, d in hives.items()]
    res = registry.analyze(files, tmp_path / "c", tmp_path / "w")
    got = {f["rule"] for f in res["findings"]}
    for rule in ("reg_autorun", "reg_defender_exclusion", "reg_service", "reg_wdigest", "reg_com_server_path",
                 "reg_recovered_suspicious"):
        assert rule in got, rule
    assert "reg_ifeo_debugger" not in got                  # only a Visual Studio JIT debugger
    assert not any("DeviceDesc" in c["name"] for c in res["carved"])     # "PowerShell" in a name is not a script
    assert res["context"]["machine"]["computer_name"] == "FACT-PC01"
    db = store.db_path(tmp_path / "c")
    q = store.user_query(db, "SELECT count(*) FROM artifacts WHERE plugin = 'shimcache' AND summary ILIKE '%sync.exe%'")
    assert q["rows"][0][0] >= 1


def test_recovered_list(analysed) -> None:
    case, res = analysed
    db = store.db_path(case)
    r = store.recovered(db)
    rows = [dict(zip(r["columns"], x)) for x in r["rows"]]
    assert {"Url", "Path", "FacturaSync"} <= {x["name"] for x in rows}
    assert all(x["src"] == 2 for x in rows)                                 # the hive, not the .reg
    assert store.recovered(db, src=1)["rows"] == []
    # the same query, through the read-only SQL of the tab (CSV export)
    q = store.user_query(db, f"SELECT * FROM ({store.RECOVERED_SQL.rsplit('ORDER BY', 1)[0]})")
    assert len(q["rows"]) == len(rows)


def test_hives_in_an_archive_do_not_flood_the_iocs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hives inside a zip are read by the Registry module, not string-mined as unknown binaries."""
    from docutracex import analyze, cases as cs
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cs.create_case(io.BytesIO(ms.registry_machine_hives_zip()), "sample_machine_hives.zip", cases_dir=tmp_path)
    cid = m["analysis_id"]
    analyze.analyze_case(tmp_path / cid)
    paths = CasePaths(cid, cases_dir=tmp_path)
    iocs = read_json(paths.subresult("iocs")) or {}
    items = iocs.get("iocs") or iocs.get("items") or []
    provs = " ".join(str(x) for x in items)
    assert "› strings" not in provs and "› text" not in provs
    assert len(items) < 60, len(items)
    nested = read_json(paths.subresult("nested")) or {}
    assert '"read_as": "registry"' in __import__("json").dumps(nested)
