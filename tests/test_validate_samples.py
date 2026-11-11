"""scripts/validate_samples.py: a folder of samples → one row each, with the expected family checked."""

from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import make_samples as ms  # noqa: E402


def test_validate_folder(tmp_path: Path) -> None:
    src = tmp_path / "in"
    src.mkdir()
    (src / "VisorFacturas.msi").write_bytes(ms.rmm_screenconnect_msi())
    (src / "notes.txt").write_bytes(b"factura 2026-0187, nada que ver")
    (tmp_path / "exp.csv").write_text("VisorFacturas.msi,ScreenConnect\nnotes.txt,Remcos\n")
    out = tmp_path / "rep"
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "validate_samples.py"), str(src), "--out", str(out),
                        "--expected", str(tmp_path / "exp.csv")], capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-2000:]
    rows = {x["name"]: x for x in csv.DictReader((out.with_suffix(".csv")).open(encoding="utf-8"))}
    assert rows["VisorFacturas.msi"]["result"] == "OK" and ms.RMM_RELAY in rows["VisorFacturas.msi"]["c2"]
    assert rows["notes.txt"]["result"] == "MISS"
    assert "| ScreenConnect | 1 | 0 | 0 |" in out.with_suffix(".md").read_text()
