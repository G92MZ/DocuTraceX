"""Go Malware Intelligence — phase 1: identification of Go binaries."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

from docutracex import golang
from docutracex.golang import detect

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402

GO = ms.go_samples()


@pytest.mark.parametrize("name, fmt", [("go/sample_go_agent", "elf"), ("go/sample_go_agent.exe", "pe")])
def test_go_binary_confirmed(name: str, fmt: str) -> None:
    r = detect.identify(GO[name])
    assert r["state"] == "Confirmed" and r["binary"]["format"] == fmt
    assert r["go_version"] == "go1.22.5"
    assert r["buildinfo"]["path"] == "example.com/invoicesync"
    assert r["buildinfo"]["settings"]["CGO_ENABLED"] == "0"
    assert [d["path"] for d in r["buildinfo"]["deps"]] == ["github.com/kbinani/screenshot", "golang.org/x/sys"]
    assert r["pclntab"]["magic"] == "0xfffffff1" and r["pclntab"]["version_range"] == "1.20+"
    assert r["moduledata"]["layout"] == "1.16+"
    assert r["go_build_id"]
    assert r["function_sample"][0] == "main.main" and "main.beacon" in r["function_sample"]
    kinds = {e["kind"]: e for e in r["evidence"]}
    assert {"buildinfo", "pclntab", "moduledata", "go_build_id", "runtime"} <= set(kinds)
    data = GO[name]
    assert data[kinds["pclntab"]["offset"]:kinds["pclntab"]["offset"] + 4] == struct.pack("<I", 0xFFFFFFF1)
    assert data[kinds["buildinfo"]["offset"]:].startswith(detect.BUILDINFO_MAGIC)


def test_stripped_vs_debug() -> None:
    assert detect.identify(GO["go/sample_go_agent"])["traits"]["stripped"] is True
    assert detect.identify(GO["go/sample_go_agent_debug"])["traits"]["stripped"] is False


def test_damaged_buildinfo_still_identified_from_pclntab() -> None:
    r = detect.identify(GO["go/sample_go_damaged_buildinfo"])
    assert r["state"] == "Confirmed" and r["score"] == 80
    assert r["traits"]["metadata_altered"] == "BuildInfo unreadable"
    assert r["go_version"] == "Go 1.20+ (from pclntab)"


def test_garble_style_names() -> None:
    g = detect.identify(GO["go/sample_go_garble"])["traits"]["garble"]
    assert g["random_package_share"] > 0.8 and "kQ7xMpR2" in g["examples"]
    assert "garble" not in detect.identify(GO["go/sample_go_agent"])["traits"]


def test_old_pclntab_layout_names() -> None:
    names = ["runtime.main", "runtime.goexit", "runtime.gopanic", "runtime.morestack", "main.main"]
    nf, ps = len(names), 8
    functab = 8 + ps
    funcs = functab + (2 * nf + 1) * ps
    blob = b""
    name_off = funcs + nf * (ps + 4)
    ftab = b""
    fstructs = b""
    for k, n in enumerate(names):
        ftab += struct.pack("<QQ", 0x401000 + k * 16, funcs + k * (ps + 4))
        fstructs += struct.pack("<Qi", 0x401000 + k * 16, name_off + len(blob))
        blob += n.encode() + b"\x00"
    pcln = struct.pack("<IBBBBQ", 0xFFFFFFFB, 0, 0, 1, 8, nf) + ftab + struct.pack("<Q", 0x402000) + fstructs + blob
    h = detect._pcln_header(pcln, 0)
    assert h["version_range"] == "1.2-1.15" and h["nfunc"] == nf
    assert detect._func_names(pcln, h) == names


def test_packed_go_is_inconclusive() -> None:
    import binkit as bk

    exe = bk.pe(bits=64, sections=[("UPX0", b"\x00" * 64, 0xE0000080), ("UPX1", bk.noise(0x20000, 7), 0xE0000040)],
                strings=["runtime.gopanic", "runtime.morestack"], imports={"kernel32.dll": ["LoadLibraryA"]})
    r = detect.identify(exe)
    assert r["state"] == "Inconclusive" and r["traits"]["packed"]


@pytest.mark.parametrize("name", ["ml/sample_win32_invoice_calc.dll", "ml/sample_dotnet_loader.exe",
                                  "ml/sample_elf_invoice_sync", "ml/sample_win64_packed_loader.exe"])
def test_non_go_binaries(name: str) -> None:
    r = detect.identify(ms.ml_samples()[name])
    assert r["state"] == "Not detected" and r["score"] == 0


def test_not_a_binary() -> None:
    assert detect.identify(b"%PDF-1.7 hello")["state"] == "Not detected"
    assert detect.identify(b"MZ" + b"\x00" * 10)["state"] == "Not detected"


def test_analyze_case_with_nested_and_duplicates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex.config import settings

    monkeypatch.setattr(settings, "goresym_executable", lambda: None)
    orig = tmp_path / "original" / "agent.exe"
    orig.parent.mkdir()
    orig.write_bytes(GO["go/sample_go_agent.exe"])
    (tmp_path / "extracted" / "a").mkdir(parents=True)
    (tmp_path / "extracted" / "a" / "agent").write_bytes(GO["go/sample_go_agent"])
    (tmp_path / "extracted" / "a" / "copy.exe").write_bytes(GO["go/sample_go_agent.exe"])
    (tmp_path / "extracted" / "a" / "notes.txt").write_text("hola")
    tree = [{"filename": "agent", "stored_path": "extracted/a/agent", "children": []},
            {"filename": "copy.exe", "stored_path": "extracted/a/copy.exe", "children": []},
            {"filename": "notes.txt", "stored_path": "extracted/a/notes.txt", "children": []}]
    res = golang.analyze_case(tmp_path, orig, tree)
    assert res["objects_scanned"] == 3 and res["counts"]["go"] == 3
    assert res["objects"][0]["stored_path"] == "original/agent.exe" and res["objects"][0]["original"]
    assert res["objects"][2]["duplicate_of"] == "agent.exe"
    assert any("GoReSym not provisioned" in w for w in res["warnings"])
    f = [x for x in res["findings"] if x["rule"] == "go:identified"]
    assert len(f) == 2 and f[0]["severity"] == "info" and "go1.22.5" in f[0]["detail"]


def test_goresym_contrast(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex.config import settings

    out = {"Version": "1.22.5", "BuildId": detect.identify(GO["go/sample_go_agent.exe"])["go_build_id"],
           "Arch": "amd64", "OS": "windows", "TabMeta": {"VA": 1, "Version": "1.20", "PointerSize": 8},
           "ModuleMeta": {"VA": 2}, "BuildInfo": {"GoVersion": "go1.22.5", "Path": "example.com/invoicesync",
                                                  "Main": {"Path": "example.com/invoicesync"}, "Deps": []},
           "UserFunctions": [{"FullName": "main.main"}]}
    fake = tmp_path / "goresym.py"
    fake.write_text(f"import sys\nprint({json.dumps(json.dumps(out))})\n")
    exe = tmp_path / "GoReSym"
    exe.write_text(f"#!/bin/sh\nexec {sys.executable} {fake} \"$@\"\n")
    exe.chmod(0o755)
    if sys.platform.startswith("win"):
        pytest.skip("shell wrapper")
    monkeypatch.setattr(settings, "goresym_executable", lambda: exe)
    orig = tmp_path / "agent.exe"
    orig.write_bytes(GO["go/sample_go_agent.exe"])
    r = golang.analyze_case(tmp_path, orig, [])["objects"][0]["result"]
    assert r["goresym"]["user_functions"] == 1
    assert r["contrast"]["disagreements"] == []
    assert {x["field"]: x["agree"] for x in r["contrast"]["rows"]}["Go version"] is True
    assert (tmp_path / "raw" / "golang").is_dir()


def test_case_pipeline_runs_go_step(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    from fastapi.testclient import TestClient

    from docutracex import analyze, cases
    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(GO["go/sample_go_agent.exe"]), "factura.exe", cases_dir=tmp_path)
    cid = m["analysis_id"]
    analyze.analyze_case(tmp_path / cid)
    comp = TestClient(create_app()).get(f"/api/cases/{cid}/components").json()
    g = comp["modules"]["golang"]
    assert g["counts"]["go"] == 1
    assert any(f["source"] == "golang" and f["rule"] == "go:identified" for f in comp["findings"])
    assert not any(i["value"] in ("github.com", "golang.org") for i in comp["iocs"]["iocs"])


def test_diagnostics_has_goresym_check() -> None:
    from docutracex.deps import run_checks

    c = next(x for x in run_checks()["checks"] if x["name"] == "GoReSym (Go metadata)")
    assert c["status"] == "ok" or c["retry"] == "goresym"


# --- phase 2: types, interfaces, methods, source files ----------------------------

def test_types_from_goresym_and_method_names() -> None:
    from docutracex.golang import types as go_types
    raw = {"Types": [{"VA": 0x5000, "Str": "main.Config", "Kind": "Struct",
                      "Reconstructed": "type main.Config struct {\n    C2    string\n    Sleep int\n}"},
                     {"VA": 0x5100, "Str": "*main.Config", "Kind": "Pointer", "Reconstructed": "type *main.Config = main_Config"},
                     {"VA": 0x5200, "Str": "fs.PathError", "Kind": "Struct", "Reconstructed": "type fs.PathError struct {}"},
                     {"VA": 0x5300, "Str": "[0]*go.shape.int", "Kind": "Array"}],
           "Interfaces": [{"VA": 0x6000, "Str": "main.Beaconer", "Kind": "Interface",
                           "Reconstructed": "type main.Beaconer interface {Beacon() error\n}"}],
           "Files": ["/home/dev/agent/main.go", "/usr/local/go/src/runtime/proc.go",
                     "/root/go/pkg/mod/golang.org/x/sys@v0.21.0/windows/zsyscall.go"]}
    names = [{"name": "main.(*Config).load", "start": 0x1000, "user": True},
             {"name": "main.Config.String", "start": 0x1100, "user": True},
             {"name": "main.main.func1", "start": 0x1200, "user": True},
             {"name": "io/fs.(*PathError).Error", "start": 0x2000, "user": False}]
    r = go_types.build(raw, names, "example.com/agent")
    by = {t["name"]: t for t in r["types"]}
    cfg = by["main.Config"]
    assert cfg["user"] and cfg["kind"] == "Struct" and cfg["fields"] == 2 and cfg["va"] == 0x5000
    assert [(m["method"], m["pointer"], m["addr"]) for m in cfg["methods"]] == [("String", False, 0x1100), ("load", True, 0x1000)]
    assert by["main.Beaconer"]["kind"] == "Interface" and not by["fs.PathError"]["user"]
    assert by["fs.PathError"]["methods"][0]["method"] == "Error"
    assert not any("go.shape" in n or n.startswith("*") for n in by)
    assert r["user_files"] == ["/home/dev/agent/main.go"]
    # without GoReSym the receivers still come from the function table
    r2 = go_types.build({}, names)
    assert {t["name"] for t in r2["types"]} == {"main.Config", "fs.PathError"} and not r2["summary"]["goresym"]
