"""Windows minidumps: modules, memory, PEs carved from memory (mapped → rebuilt,
flat Assembly.Load buffers), private executable memory, and the case pipeline."""

from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms

from docutracex.parsers import minidump


@pytest.fixture(scope="module")
def dump(tmp_path_factory: pytest.TempPathFactory) -> Path:
    p = tmp_path_factory.mktemp("md") / "factura.exe.dmp"
    p.write_bytes(ms.memdump_dmp())
    return p


def test_process_and_modules(dump: Path) -> None:
    r = minidump.analyze(dump)
    assert r["status"] == "ok"
    assert r["process"] == {"arch": "x86", "windows": "10.0.19045", "pid": 4812,
                            "image": "C:\\Users\\invoice\\AppData\\Local\\Temp\\factura.exe"}
    assert [m["system"] for m in r["modules"]] == [False, True]
    assert r["counts"]["system_modules_skipped"] == 1          # ntdll: listed, not carved


def test_carving(dump: Path, tmp_path: Path) -> None:
    r = minidump.analyze(dump, tmp_path)
    by = {c["name"]: c for c in r["carved"]}
    assert set(by) == {"factura.exe_400000.exe", "unbacked_2a40018.exe", "unbacked_5b10000.dll",
                       "exec_private_6c20000.bin"}
    heap = by["unbacked_2a40018.exe"]
    assert heap["layout"] == "flat (file layout)" and heap["dotnet"] and not heap["backed"]
    assert Path(heap["_path"]).read_bytes() == ms.xworm_named_exe()[:heap["size"]]
    inj = by["unbacked_5b10000.dll"]
    assert inj["layout"] == "mapped → rebuilt"
    assert b"cdn-update.example.net" in Path(inj["_path"]).read_bytes()
    assert by["exec_private_6c20000.bin"]["protect"] == "RWX"
    rules = {f["rule"]: f for f in r["findings"]}
    assert rules["memdump_unbacked_pe"]["severity"] == "high" and rules["memdump_exec_private"]["severity"] == "medium"


def test_rebuilt_image_is_file_layout(dump: Path, tmp_path: Path) -> None:
    r = minidump.analyze(dump, tmp_path)
    data = Path(next(c for c in r["carved"] if c["va"] == "0x400000")["_path"]).read_bytes()
    import pefile
    pe = pefile.PE(data=data)
    for s in pe.sections:
        if s.SizeOfRawData:
            assert data[s.PointerToRawData:s.PointerToRawData + 16] == s.get_data()[:16]


def test_not_a_dump(tmp_path: Path) -> None:
    p = tmp_path / "x.dmp"
    p.write_bytes(b"PAGEDU64" + b"\x00" * 64)                  # a kernel dump: not a minidump
    assert minidump.analyze(p)["status"] == "error"
    q = tmp_path / "empty.dmp"
    q.write_bytes(struct.pack("<4sIIIIIQ", b"MDMP", 0xA793, 0, 32, 0, 0, 0))
    r = minidump.analyze(q)
    assert r["status"] == "ok" and r["carved"] == [] and r["warnings"]


def test_case_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("dnfile")
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.memdump_dmp()), "factura.exe.dmp", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    md = read_json(paths.subresult("memdump"))
    assert md["status"] == "ok" and all(c.get("stored_path") for c in md["carved"])
    assert not any("_path" in c for c in md["carved"])
    names = {n["filename"] for n in read_json(paths.subresult("nested"))["tree"]}
    assert "unbacked_2a40018.exe" in names
    from docutracex import c2
    original = next(paths.original_dir.iterdir())
    res = c2.analyze(original, paths.extracted_dir)
    fams = {c["family"] for c in res["configs"]}
    assert "XWorm" in fams and "Metasploit payload (exec)" in fams
