"""DLL side-loading: a signed program next to a DLL with a system library's name."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from docutracex import sideload

ms = pytest.importorskip("make_samples")
bk = pytest.importorskip("binkit")


def _entries(tmp: Path, files: dict[str, bytes], folder: str = "Factura") -> list[tuple[str, str]]:
    out = []
    for n, b in files.items():
        p = tmp / n
        p.write_bytes(b)
        out.append((f"{folder}/{n}", str(p)))
    return out


def test_signed_exe_and_unsigned_proxy_dll(tmp_path: Path) -> None:
    got = sideload.findings(_entries(tmp_path, ms.sideloading_parts()), "x.zip")
    assert len(got) == 1
    f = got[0]
    assert f["rule"] == "dll_sideloading" and f["severity"] == "high" and f["attack"] == "T1574.002"
    assert "which imports it" in f["detail"] and "Visor Facturas Example S.L." in f["detail"]
    assert "17 of its 18 exports are forwarded" in f["detail"] and "Iniciar" in f["detail"]
    r = sideload.pairs(_entries(tmp_path, ms.sideloading_parts()))[0]
    assert r["exe_signed"] and not r["dll_signed"] and r["imported"]


def test_other_signer_and_genuine_microsoft_copy(tmp_path: Path) -> None:
    exe = ms._fake_signed_by(bk.pe(bits=64, imports={"dbghelp.dll": ["MiniDumpWriteDump"]}), "Visor Facturas Example S.L.")
    other = ms._fake_signed_by(bk.pe(bits=64, dll=True, exports=["MiniDumpWriteDump"]), "Otra Empresa Example Ltd")
    f = sideload.findings(_entries(tmp_path, {"app.exe": exe, "dbghelp.dll": other}), "x")[0]
    assert f["severity"] == "high" and "signed by someone else" in f["detail"]
    ms_copy = ms._fake_signed_by(bk.pe(bits=64, dll=True, exports=["MiniDumpWriteDump"]), "Microsoft Corporation")
    f = sideload.findings(_entries(tmp_path, {"app.exe": exe, "dbghelp.dll": ms_copy}), "x")[0]
    assert f["severity"] == "low" and "redistributable" in f["detail"]


def test_nothing_without_the_pattern(tmp_path: Path) -> None:
    exe = ms._fake_signed_by(bk.pe(bits=64, imports={"helper.dll": ["Run"]}), "Visor Facturas Example S.L.")
    helper = bk.pe(bits=64, dll=True, exports=["Run"])
    assert sideload.findings(_entries(tmp_path, {"app.exe": exe, "helper.dll": helper}), "x") == []   # not a system name
    parts = ms.sideloading_parts()
    ents = _entries(tmp_path, {"VisorFacturas.exe": parts["VisorFacturas.exe"]}, "a") + \
        [("b/version.dll", str(tmp_path / "version.dll"))]
    (tmp_path / "version.dll").write_bytes(parts["version.dll"])
    assert sideload.findings(ents, "x") == []                                               # different folders
    # a text file called version.dll is not a DLL
    (tmp_path / "v.dll").write_bytes(b"not a pe")
    assert sideload.findings(_entries(tmp_path, {"app.exe": exe}) + [("Factura/version.dll", str(tmp_path / "v.dll"))],
                             "x") == []


@pytest.mark.parametrize("name,rule", [("sample_dll_sideloading.zip", "dll_sideloading"),
                                       ("sample_dll_sideloading.iso", "dll_sideloading"),
                                       ("sample_dll_sideloading.msi", "msi_dll_sideloading")])
def test_samples_end_to_end(tmp_path: Path, name: str, rule: str) -> None:
    from docutracex import analyze, cases, findings
    data = ms.sideloading_samples()[name]
    m = cases.create_case(io.BytesIO(data), name, cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    mods = {p.stem: json.loads(p.read_text()) for p in (root / "results").glob("*.json")}
    got = [f for f in findings.consolidate(mods) if f["rule"] == rule]
    assert got and got[0]["severity"] == "high"


def test_nested_zip_in_zip(tmp_path: Path) -> None:
    """The pair one level down (a ZIP inside a ZIP) is found by the nested analysis."""
    import zipfile

    from docutracex import analyze, cases, findings
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("factura.zip", ms.sideloading_samples()["sample_dll_sideloading.zip"])
    m = cases.create_case(io.BytesIO(buf.getvalue()), "outer.zip", cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    mods = {p.stem: json.loads(p.read_text()) for p in (root / "results").glob("*.json")}
    assert any(f["rule"] == "dll_sideloading" for f in findings.consolidate(mods))
