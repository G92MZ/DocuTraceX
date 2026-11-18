"""HTML polyglots, portable interpreters and PEs carved behind a shellcode stub."""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from docutracex import decrypted, interpreters, polyglot  # noqa: E402

ms = pytest.importorskip("make_samples")

_LANG = {"python": "Python", "powershell": "PowerShell", "batch": "batch", "jscript": "JavaScript",
         "lua": "Lua", "ruby": "Ruby", "perl": "Perl", "autoit": "AutoIt", "autohotkey": "AutoHotkey",
         "tcl": "Tcl", "shell": "shell", "php": "PHP"}


@pytest.mark.parametrize("name", sorted(_LANG))
def test_each_polyglot_sample_is_found_with_its_language(name: str) -> None:
    samples = ms.polyglot_samples()
    key = next(k for k in samples if k.startswith(f"sample_polyglot_{name}."))
    rec = polyglot.detect(samples[key], key)
    assert rec and rec["language"] == _LANG[name]
    assert "<h1>" not in rec["code"]                       # the page is out of the extracted code
    f = polyglot.finding(rec, key)
    assert f["rule"] == f"polyglot_html_{rec['ext']}"


def test_python_polyglot_names_what_the_code_does() -> None:
    rec = polyglot.detect(ms.lure_polyglot_html(), "InstallNotes.html")
    assert rec["language"] == "Python" and {"exec", "zlib", "[::-1]"} <= set(rec["suspicious"])
    assert polyglot.finding(rec, "x")["severity"] == "high"
    compile(rec["code"], "extracted", "exec")              # still valid Python without the page


@pytest.mark.parametrize("name,data", [
    ("page.html", b"<!doctype html><html><head><title>x</title><script>var a = 1; function f(){}</script>"
                  b"<style>/* <div>not</div> <p>hidden</p> */ body{}</style></head><body><p>hi</p></body></html>"),
    ("render.py", b"import os\nimport sys\n\n" + b"# helper\n" * 80
                  + b'PAGE = """<html><body><h1>Report</h1><p>ok</p></body></html>"""\nprint(PAGE)\n'),
    ("tpl.php", b"<html><body><h1><?php echo htmlspecialchars($title); ?></h1><p>x</p></body></html>"),
    ("notes.txt", b"just text, <b>bold</b> and <p>a paragraph</p> but no code around it"),
])
def test_ordinary_files_are_not_polyglots(name: str, data: bytes) -> None:
    assert polyglot.detect(data, name) is None


def test_pes_behind_a_stub_are_carved_whole_and_the_padding_left_out() -> None:
    inner = ms._lure_inner_pe()
    shell = b"\xe9\x0b\x00\x00\x00" + b"\x90" * 11 + inner
    kids = decrypted.payload_children(shell, "python-stage", "python x", recipe=["bytes literal"])
    assert [k["ext"] for k in kids] == [".dll", ".exe"]
    assert all(k["data"][:2] == b"MZ" and decrypted.pe_extent(k["data"]) == len(k["data"]) for k in kids)
    assert any("padding stripped" in step for step in kids[1]["recipe"])
    assert "word lists" in kids[1]["origin"]


def _bundle(gen, tmp: Path) -> list[tuple[str, str]]:  # noqa: ANN001
    z = zipfile.ZipFile(io.BytesIO(gen()))
    z.extractall(tmp)
    return [(n, str(tmp / n)) for n in z.namelist()]


def test_portable_python_bundle_is_an_embedded_interpreter(tmp_path: Path) -> None:
    got = interpreters.findings(_bundle(ms.portable_python_bundle_zip, tmp_path), "bundle.zip")
    assert [f["rule"] for f in got] == ["embedded_interpreter_python"]
    f = got[0]
    assert f["severity"] == "high" and "python311._pth" in f["detail"] and "notas.html" in f["detail"]
    assert "Abrir factura.bat" in f["evidence"]


def test_portable_node_bundle_names_the_disguised_script(tmp_path: Path) -> None:
    got = interpreters.findings(_bundle(ms.portable_node_bundle_zip, tmp_path), "bundle.zip")
    assert [f["rule"] for f in got] == ["embedded_interpreter_nodejs"]
    assert got[0]["severity"] == "high" and "readme.txt" in got[0]["detail"]


def test_lone_interpreter_without_runtime_or_launcher_is_medium() -> None:
    got = interpreters.findings([("tools/node.exe", None), ("tools/LICENSE", None)], "x")
    assert got and got[0]["severity"] == "medium"
    assert interpreters.findings([("setup.exe", None), ("readme.txt", None)], "x") == []


def test_lure_html_peels_down_to_the_final_pes(tmp_path: Path) -> None:
    """InstallNotes.html → Python code around the page → exec layer → loader → DLL + EXE
    (padding stripped), all statically."""
    from docutracex import analyze, cases
    m = cases.create_case(io.BytesIO(ms.lure_polyglot_html()), "InstallNotes.html", cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    pres = json.loads((root / "results" / "polyglot.json").read_text())
    assert pres["language"] == "Python" and pres["findings"][0]["severity"] == "high"
    tree = json.loads((root / "results" / "nested.json").read_text())["tree"]
    names: list[str] = []
    origins: list[str] = []

    def walk(nodes):  # noqa: ANN001, ANN202
        for n in nodes:
            names.append(n["filename"])
            origins.append(n.get("decrypted_from") or "")
            walk(n.get("children"))
    walk(tree)
    assert "InstallNotes.polyglot.py" in names
    assert sum(n.endswith(".dll") for n in names) == 1 and sum(n.endswith(".exe") for n in names) == 1
    assert not any(n.endswith(".bin") for n in names)       # no pieces of the shellcode as extra children
    assert any("padding" in o for o in origins)


def test_bundle_archive_finding_and_polyglot_child(tmp_path: Path) -> None:
    from docutracex import analyze, cases, findings
    m = cases.create_case(io.BytesIO(ms.portable_python_bundle_zip()), "factura.zip", cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    arc = json.loads((root / "results" / "archive.json").read_text())
    assert any(f["rule"] == "embedded_interpreter_python" and f["severity"] == "high" for f in arc["findings"])
    mods = {p.stem: json.loads(p.read_text()) for p in (root / "results").glob("*.json")}
    rules = {f["rule"] for f in findings.consolidate(mods)}
    assert {"embedded_interpreter_python", "polyglot_html_py"} <= rules


def test_autoit_loader_is_flagged_and_its_pes_carved(tmp_path: Path) -> None:
    from docutracex.parsers import genscript
    p = tmp_path / "loader.au3"
    p.write_bytes(ms.autoit_loader_au3())
    res = genscript.analyze(p)
    rules = {f["rule"]: f["severity"] for f in res["findings"]}
    assert rules.get("script_shellcode_loader") == "high"
    pays = decrypted.payloads_from({"script": res}, tmp_path)
    assert sorted(x["ext"] for x in pays if x.get("ext") in (".dll", ".exe")) == [".dll", ".exe"]


def test_a3x_is_recognised_by_content_and_its_script_recovered(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    from docutracex.parsers import autoit, unpack
    blob = ms.autoit_a3x()
    assert autoit.version(blob).startswith("EA06") and not autoit.is_a3x(b"MZ" + blob)
    p = tmp_path / "datos.dat"
    p.write_bytes(blob)

    def fake_ripper(path: Path, out: Path) -> dict:
        out.mkdir(parents=True, exist_ok=True)
        (out / "script.au3").write_bytes(ms.autoit_loader_au3())
        return {"tool": "autoit-ripper", "status": "ok"}
    monkeypatch.setattr(unpack, "_unpack_autoit", fake_ripper)
    res = autoit.analyze(p, tmp_path / "out")
    f = res["findings"][0]
    assert f["rule"] == "autoit_a3x" and f["severity"] == "high" and "datos.dat" in f["detail"]
    assert [n for _p, n in res["_files"]] == ["script.au3"]
    from docutracex import nested
    assert nested._kind(p, "datos.dat") == "autoit"


def test_a3x_sample_is_readable_by_autoit_ripper() -> None:
    ripper = pytest.importorskip("autoit_ripper.autoit_unpack")
    got = ripper.extract(data=ms.autoit_a3x(), version=ripper.AutoItVersion.EA05)
    assert got and got[0][0] == "script.au3" and b"VirtualAlloc" in got[0][1]


def test_renamed_autoit_interpreter_and_a3x_in_a_bundle(tmp_path: Path) -> None:
    got = interpreters.findings(_bundle(ms.portable_autoit_bundle_zip, tmp_path), "bundle.zip")
    assert [f["rule"] for f in got] == ["embedded_interpreter_autoit"]
    d = got[0]["detail"]
    assert got[0]["severity"] == "high" and "really autoit3.exe" in d and "datos.dat" in d


def test_standalone_au3_runs_the_generic_engine(tmp_path: Path) -> None:
    from docutracex import analyze, cases
    m = cases.create_case(io.BytesIO(ms.autoit_loader_au3()), "loader.au3", cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    sres = json.loads((root / "results" / "script.json").read_text())
    assert any(f["rule"] == "script_shellcode_loader" for f in sres["findings"])
    tree = json.loads((root / "results" / "nested.json").read_text())["tree"]
    names = [n["filename"] for n in tree]
    assert any(n.endswith(".dll") for n in names) and any(n.endswith(".exe") for n in names)
