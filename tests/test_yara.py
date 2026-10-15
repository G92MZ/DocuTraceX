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


def test_upload_and_compile(client: TestClient) -> None:
    r = client.post("/api/yara/upload", files={"file": ("t.yar", RULE.encode())})
    assert r.status_code == 201
    assert r.json()["compile"]["rule_count"] == 1
    listing = client.get("/api/yara").json()
    names = {x["name"] for x in listing["rules"]}
    assert "Has_VBA" in names
    assert all(not x["enabled"] for x in listing["rules"])  # nothing enabled by default


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
    r = client.post("/api/yara/path", json={"path": str(rd)})
    assert r.status_code == 200
    assert r.json()["compile"]["rule_count"] >= 1


def test_register_missing_path_404(client: TestClient) -> None:
    assert client.post("/api/yara/path", json={"path": "/does/not/exist"}).status_code == 404


@has_samples
def test_every_hit_is_a_markable_finding_with_details(client: TestClient, env: Path) -> None:
    client.post("/api/yara/upload", files={"file": ("t.yar", RULE.encode())})
    with (SAMPLES / "sample.xlsm").open("rb") as fh:
        cid = client.post("/api/cases", files={"file": ("sample.xlsm", fh.read())}).json()["analysis_id"]
    for _ in range(100):
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            break
        time.sleep(0.05)
    comp = client.get(f"/api/cases/{cid}/components").json()
    ymod = comp["modules"]["yara"]
    assert ymod["match_count"] >= 1
    # No opt-in needed: the hit is a finding right away, ready to be marked.
    yf = [f for f in comp["findings"] if f["source"] == "yara"]
    assert yf and yf[0]["rule"] == "yara:Has_VBA"

    hit = ymod["scanned"][0]
    m = hit["matches"][0]
    assert m["finding_id"] in {f["id"] for f in yf}
    assert Path(hit["path"]).is_file()                       # local path of the target
    assert m["strings"][0]["text"] == "vbaProject"           # what matched, readable
    assert m["strings"][0]["data"] == b"vbaProject".hex()
    src = ymod["rules_info"][f"{m['namespace']}:Has_VBA"]
    assert src["source"].startswith("rule Has_VBA") and src["file"].endswith("t.yar")

    # The report lists only confirmed (TP) findings, so mark it, then it appears.
    assert "yara:Has_VBA" not in client.get(f"/api/cases/{cid}/report").text
    client.put(f"/api/cases/{cid}/marks/{m['finding_id']}", json={"state": "true_positive"})
    assert "yara:Has_VBA" in client.get(f"/api/cases/{cid}/report").text


def test_enabled_persists_in_config(env: Path) -> None:
    yara_engine.add_upload("t.yar", RULE.encode())
    yara_engine.set_enabled(["Has_VBA"], True)
    assert "Has_VBA" in yara_engine.enabled_rules()
    yara_engine.set_enabled(["Has_VBA"], False)
    assert "Has_VBA" not in yara_engine.enabled_rules()


def test_delegates_to_portable_when_app_has_no_yara(client: TestClient, monkeypatch) -> None:
    """The app's Python may lack yara-python (and 'import yara' may resolve to the
    yara/ rules folder): compile/list must then run on the portable."""
    import sys

    client.post("/api/yara/upload", files={"file": ("t.yar", RULE.encode())})
    monkeypatch.setattr(yara_engine, "_load_yara", lambda: (None, "no yara here"))
    monkeypatch.setattr(yara_engine, "_portable_cmd",
                        lambda op: [sys.executable, "-m", "docutracex.yara_engine", op])
    listing = client.get("/api/yara").json()
    assert listing["rule_count"] == 1
    assert [r["name"] for r in listing["rules"]] == ["Has_VBA"]
    events = list(yara_engine.compile_stream())
    assert events[-1]["done"] and events[-1]["rule_count"] == 1
    assert yara_engine.compile_rules()[1]["rule_count"] == 1


def test_no_yara_anywhere_reports_clear_error(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(yara_engine, "_load_yara", lambda: (None, "yara-python not installed"))
    monkeypatch.setattr(yara_engine, "_portable_cmd", lambda op: None)
    rep = client.get("/api/yara").json()
    assert rep["available"] is False and "yara-python not installed" in rep["error"]
    assert "fatal" in list(yara_engine.compile_stream())[-1]


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


def test_always_uses_portable_even_if_app_has_yara(client: TestClient, monkeypatch) -> None:
    import sys

    client.post("/api/yara/upload", files={"file": ("t.yar", RULE.encode())})
    calls = []

    def cmd(op):
        calls.append(op)
        return [sys.executable, "-m", "docutracex.yara_engine", op]

    monkeypatch.setattr(yara_engine, "_portable_cmd", cmd)
    assert client.get("/api/yara").json()["rule_count"] == 1
    assert calls  # went to the portable although yara-python is importable here


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
