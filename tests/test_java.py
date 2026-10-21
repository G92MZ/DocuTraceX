"""Java family: .class constant-pool parsing, MANIFEST/web.xml/signing, JSP
webshell rules, and the jar/war/class/jsp pipeline incl. the nested path."""

from __future__ import annotations

import io
import sys
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from docutracex.app import create_app
from docutracex.config import settings
from docutracex.identify import classify_discrepancy
from docutracex.parsers import java, script_rules

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402

_CLASS = ms.java_class_stub()
_JSP = ('<%@ page import="java.io.*" %>\n'
        '<% String c = request.getParameter("cmd"); Runtime.getRuntime().exec(c); %>\n')


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    return tmp_path


@pytest.fixture()
def client(env) -> TestClient:
    return TestClient(create_app())


def _wait(client, cid):
    for _ in range(1200):
        if client.get(f"/api/cases/{cid}").json().get("state") in ("completed", "error"):
            return
        time.sleep(0.05)


# --- rules / parser ----------------------------------------------------------
def test_java_lang_rules() -> None:
    assert len(script_rules.rules_for(script_rules.JAVA)) >= 14


def test_parse_class_refs() -> None:
    p = java.parse_class(_CLASS)
    assert "java/lang/Runtime.exec" in p["refs"]
    assert any("URL" in r for r in p["refs"])


def test_class_fires_rules(tmp_path: Path) -> None:
    c = tmp_path / "Shell.class"
    c.write_bytes(_CLASS)
    fnd, sc = java.scan_class(c, _CLASS, "file:Shell.class", [8])
    rules = {f["rule"] for f in fnd}
    assert {"java_exec", "java_download", "java_script_engine"} <= rules


def test_jsp_webshell() -> None:
    fnd, sc = java.scan_jsp(_JSP, "file:cmd.jsp")
    rules = {f["rule"] for f in fnd}
    assert "java_exec" in rules and "java_webshell_input" in rules


def test_manifest_agent() -> None:
    mf = java.parse_manifest("Manifest-Version: 1.0\r\nMain-Class: Shell\r\nPremain-Class: Ag\r\n")
    fnd = java.manifest_findings(mf, "file:MANIFEST.MF")
    rules = {f["rule"] for f in fnd}
    assert "java_main_class" in rules and "java_agent" in rules


def test_manifest_continuation_lines() -> None:
    mf = java.parse_manifest("Main-Class: com.ex.Very\r\n LongClassName\r\n")
    assert mf["Main-Class"] == "com.ex.VeryLongClassName"


# --- identify ----------------------------------------------------------------
def test_java_family_identify() -> None:
    assert classify_discrepancy(".jar", "application/zip", "Zip archive data")["declared_family"] == "java"
    assert classify_discrepancy(".jar", "application/java-archive", "Java archive data (JAR)")["status"] == "match"
    assert classify_discrepancy(".class", "application/x-java-applet", "compiled Java class data")["status"] == "match"
    assert classify_discrepancy(".jsp", "text/plain", "ASCII text")["status"] == "match"


# --- end-to-end --------------------------------------------------------------
def _jar() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: Shell\r\nPremain-Class: Shell\r\n")
        z.writestr("Shell.class", _CLASS)
    return buf.getvalue()


def _war() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("WEB-INF/web.xml", "<web-app><servlet><servlet-class>x.Y</servlet-class></servlet></web-app>")
        z.writestr("cmd.jsp", _JSP)
        z.writestr("WEB-INF/classes/Shell.class", _CLASS)
    return buf.getvalue()


def test_case_jar(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("app.jar", _jar())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert {"java", "archive", "nested"} <= set(comp["modules"])
    jm = comp["modules"]["java"]
    assert jm["kind"] == "jar" and jm["manifest"].get("Main-Class") == "Shell"
    rules = {f["rule"] for f in comp["findings"]}
    assert {"java_exec", "java_agent", "java_main_class"} <= rules


def test_case_war(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("app.war", _war())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    jm = comp["modules"]["java"]
    assert jm["kind"] == "war" and jm["jsp"] >= 1
    rules = {f["rule"] for f in comp["findings"]}
    assert "java_webshell_input" in rules and "java_web_descriptor" in rules


def test_case_loose_class(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("Shell.class", _CLASS)}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert comp["modules"]["java"]["kind"] == "class"
    assert "java_exec" in {f["rule"] for f in comp["findings"]}


def test_nested_jar_in_zip(client: TestClient, tmp_path: Path) -> None:
    buf = tmp_path / "b.zip"
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("plugin.jar", _jar())
    cid = client.post("/api/cases", files={"file": ("b.zip", buf.read_bytes())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "nested" in comp["modules"]
    assert "java_exec" in {f["rule"] for f in comp["findings"]}
