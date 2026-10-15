"""Tests for the YARA engine: store, compile, markable findings, API."""

from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("yara")

from fastapi.testclient import TestClient  # noqa: E402

from docutracex import yara_engine  # noqa: E402
from docutracex.app import create_app  # noqa: E402
from docutracex.config import settings  # noqa: E402
from docutracex.storage import CasePaths, read_json  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
has_samples = pytest.mark.skipif(not (SAMPLES / "sample.xlsm").exists(),
                                 reason="samples not generated")

RULE = ('rule Has_VBA { meta: description="VBA project present" severity="medium" '
        'strings: $v="vbaProject" condition: $v }')


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(settings, "yara_dir", tmp_path / "yara")
    (tmp_path / "cases").mkdir()
    return tmp_path


@pytest.fixture()
def client(env) -> TestClient:
    return TestClient(create_app())


def _compile(client: TestClient) -> dict:
    lines = client.post("/api/yara/compile/stream").text.strip().splitlines()
    import json
    return json.loads(lines[-1])


def test_upload_does_not_compile_until_asked(client: TestClient) -> None:
    r = client.post("/api/yara/upload", files={"file": ("t.yar", RULE.encode())})
    assert r.status_code == 201 and "compile" not in r.json()
    listing = client.get("/api/yara").json()
    assert listing["compiled"] is False and listing["stale"] is True and not listing["rules"]
    done = _compile(client)
    assert done["done"] and done["rule_count"] == 1
    listing = client.get("/api/yara").json()
    assert listing["compiled"] and not listing["stale"]
    assert [(x["name"], x["description"]) for x in listing["rules"]] == [("Has_VBA", "VBA project present")]
    # Adding rules afterwards marks the cache stale until the next Recompile.
    client.post("/api/yara/upload", files={"file": ("u.yar", b'rule U { condition: true }')})
    assert client.get("/api/yara").json()["stale"] is True


def test_zip_archive_upload(client: TestClient) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.yar", RULE)
        z.writestr("b.yara", 'rule R2 { strings: $a="MZ" condition: $a }')
        z.writestr("ignore.txt", "not a rule")
    r = client.post("/api/yara/upload", files={"file": ("rules.zip", buf.getvalue())})
    assert r.json()["count"] == 2  # only the rule files


def test_register_server_path(client: TestClient, env: Path) -> None:
    rd = env / "ext_rules"
    rd.mkdir()
    (rd / "x.yar").write_text(RULE)
    (rd / "bad.yar").write_text("rule Broken { condition: nope }")
    r = client.post("/api/yara/path", json={"path": str(rd)})
    assert r.status_code == 200 and r.json()["rule_files"] == 2
    done = _compile(client)
    assert done["rule_count"] == 1 and len(done["errors"]) == 1
    assert client.get("/api/yara").json()["errors"][0]["path"].endswith("bad.yar")


def test_register_missing_path_404(client: TestClient) -> None:
    assert client.post("/api/yara/path", json={"path": "/does/not/exist"}).status_code == 404


def _wait_case(client: TestClient, cid: str) -> None:
    for _ in range(200):
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            return
        time.sleep(0.05)


def _run_yara(client: TestClient, cid: str) -> None:
    tid = client.post(f"/api/cases/{cid}/rerun", json={"module": "yara"}).json()["task"]["id"]
    for _ in range(200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            return
        time.sleep(0.05)


@has_samples
def test_yara_runs_only_on_demand_and_hits_are_markable(client: TestClient, env: Path) -> None:
    client.post("/api/yara/upload", files={"file": ("t.yar", RULE.encode())})
    _compile(client)
    with (SAMPLES / "sample.xlsm").open("rb") as fh:
        cid = client.post("/api/cases", files={"file": ("sample.xlsm", fh.read())}).json()["analysis_id"]
    _wait_case(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "yara" not in comp["modules"]  # not run automatically

    _run_yara(client, cid)  # the "Scan case" button
    comp = client.get(f"/api/cases/{cid}/components").json()
    ymod = comp["modules"]["yara"]
    assert ymod["match_count"] >= 1
    yf = [f for f in comp["findings"] if f["source"] == "yara"]
    assert yf and yf[0]["rule"] == "yara:Has_VBA"

    hit = ymod["scanned"][0]
    m = hit["matches"][0]
    assert m["finding_id"] in {f["id"] for f in yf}
    assert Path(hit["path"]).is_file()                       # local path of the target
    assert m["strings"][0]["text"] == "vbaProject"           # what matched, readable
    assert m["strings"][0]["data"] == b"vbaProject".hex()
    ctx = m["strings"][0]["context"]                         # bytes around the match
    raw = bytes.fromhex(ctx["data"])
    rel = m["strings"][0]["offset"] - ctx["start"]
    assert raw[rel:rel + 10] == b"vbaProject" and ctx["start"] % 16 == 0
    assert rel >= min(48, m["strings"][0]["offset"])         # some lines before
    src = ymod["rules_info"][f"{m['namespace']}:Has_VBA"]
    assert src["source"].startswith("rule Has_VBA") and src["file"].endswith("t.yar")

    # The report lists only confirmed (TP) findings, so mark it, then it appears.
    assert "yara:Has_VBA" not in client.get(f"/api/cases/{cid}/report").text
    client.put(f"/api/cases/{cid}/marks/{m['finding_id']}", json={"state": "true_positive"})
    assert "yara:Has_VBA" in client.get(f"/api/cases/{cid}/report").text

    # A full re-analysis keeps the previous YARA results (and so the mark).
    client.post(f"/api/cases/{cid}/rerun", json={})
    time.sleep(0.2)
    _wait_case(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "yara" in comp["modules"]
    assert any(f["mark"]["state"] == "true_positive" for f in comp["findings"] if f["source"] == "yara")


@has_samples
def test_scan_without_compiled_rules_says_so(client: TestClient, env: Path) -> None:
    client.post("/api/yara/upload", files={"file": ("t.yar", RULE.encode())})
    with (SAMPLES / "sample.xlsm").open("rb") as fh:
        cid = client.post("/api/cases", files={"file": ("sample.xlsm", fh.read())}).json()["analysis_id"]
    _wait_case(client, cid)
    _run_yara(client, cid)
    ymod = client.get(f"/api/cases/{cid}/components").json()["modules"]["yara"]
    assert "not compiled" in ymod["error"]


def test_enabled_persists_in_config(env: Path) -> None:
    yara_engine.add_upload("t.yar", RULE.encode())
    yara_engine.set_enabled(["Has_VBA"], True)
    assert "Has_VBA" in yara_engine.enabled_rules()
    yara_engine.set_enabled(["Has_VBA"], False)
    assert "Has_VBA" not in yara_engine.enabled_rules()


def test_compile_delegates_to_portable(client: TestClient, monkeypatch) -> None:
    """Compilation always runs on the portable (here: a child interpreter)."""
    import sys

    client.post("/api/yara/upload", files={"file": ("t.yar", RULE.encode())})
    monkeypatch.setattr(yara_engine, "_load_yara", lambda: (None, "no yara here"))
    calls = []

    def cmd(op):
        calls.append(op)
        return [sys.executable, "-m", "docutracex.yara_engine", op]

    monkeypatch.setattr(yara_engine, "_portable_cmd", cmd)
    assert _compile(client)["rule_count"] == 1 and set(calls) == {"stream"}
    listing = client.get("/api/yara").json()  # read from the cache the portable wrote
    assert [r["name"] for r in listing["rules"]] == ["Has_VBA"]


def test_no_yara_anywhere_reports_clear_error(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(yara_engine, "_load_yara", lambda: (None, "yara-python not installed"))
    monkeypatch.setattr(yara_engine, "_portable_cmd", lambda op: None)
    assert "yara-python not installed" in _compile(client)["fatal"]


def test_rules_folder_is_not_mistaken_for_yara(tmp_path: Path) -> None:
    """Without yara-python (-S hides site-packages) 'import yara' resolves to a
    bare yara/ folder; that must be reported as not installed."""
    import subprocess
    import sys

    (tmp_path / "yara").mkdir()
    root = Path(__file__).resolve().parent.parent
    code = (f"import sys; sys.path.insert(0, {str(root)!r}); "
            "from docutracex.yara_engine import _load_yara; m, why = _load_yara(); "
            "print(m is None, why)")
    out = subprocess.run([sys.executable, "-S", "-c", code], cwd=tmp_path,
                         capture_output=True, text=True, check=True).stdout
    assert out.startswith("True") and "resolved to the folder" in out





def test_rule_source_extraction(tmp_path: Path) -> None:
    text = (
        'import "pe"\n// rule Fake { }\n'
        'rule A : t { meta: d="}{" strings: $h = { 4D 5A [2-4] ( 90 | 91 ) } '
        '$r = /ab\\/c{2}}/ condition: $h and $r }\n'
        'private rule B { condition: pe.sections[0].name matches /\\.te{1}xt/ }\n'
        'rule C { condition: true }\n'
    )
    f = tmp_path / "r.yar"
    f.write_text(text)
    assert yara_engine.rule_source(f, "A").endswith("condition: $h and $r }")
    assert yara_engine.rule_source(f, "B").startswith("private rule B")
    assert yara_engine.rule_source(f, "B").endswith("/\\.te{1}xt/ }")
    assert yara_engine.rule_source(f, "C") == "rule C { condition: true }"
    assert yara_engine.rule_source(f, "Fake") == ""
