"""A collection zip of a machine (several users, hives with their .LOG1 / .LOG2):
logs are not read as hives, each hive is labelled with its path in the archive and
gets the logs of its own folder although extraction renamed same-named files."""

from __future__ import annotations

import io
import json
import struct
import time
import zipfile
from pathlib import Path

import pytest

import make_samples as ms
import regkit
from docutracex import analyze
from docutracex.config import settings
from docutracex.registry import parse


def _log(hive: bytes) -> bytes:
    """A transaction log: the hive's base block with file type 2, then padding."""
    head = bytearray(hive[:4096])
    struct.pack_into("<I", head, 28, 2)
    return bytes(head) + b"\x00" * 1024


def test_logs_are_not_hives(tmp_path: Path) -> None:
    hive = ms.registry_ntuser_hive()
    (tmp_path / "NTUSER.DAT").write_bytes(hive)
    (tmp_path / "NTUSER.DAT.LOG1").write_bytes(_log(hive))
    assert parse.is_hive(tmp_path / "NTUSER.DAT") and not parse.is_hive(tmp_path / "NTUSER.DAT.LOG1")


def test_explicit_logs_are_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}
    import regipy.recovery as rec
    monkeypatch.setattr(rec, "apply_transaction_logs", lambda h, l1, l2=None, restored_hive_path=None: seen.update(l1=l1, l2=l2))
    h = tmp_path / "NTUSER_1.DAT"
    h.write_bytes(ms.registry_ntuser_hive())
    l1, l2 = tmp_path / "NTUSER.DAT_1.LOG1", tmp_path / "NTUSER.DAT_1.LOG2"
    l1.write_bytes(b"x" * 1000)
    l2.write_bytes(b"x" * 1000)
    parse.apply_logs(h, tmp_path / "out", [l1, l2])
    assert seen == {"l1": str(l1), "l2": str(l2)}


def test_collection_zip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    ana = regkit.build({"Software": {"Ana": {"@values": [("Who", "REG_SZ", "ana")]}}}, file_name="ntuser.dat")
    luis = regkit.build({"Software": {"Luis": {"@values": [("Who", "REG_SZ", "luis")]}}}, file_name="ntuser.dat")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for user, hive in (("ana", ana), ("luis", luis)):
            z.writestr(f"Users/{user}/NTUSER.DAT", hive)
            z.writestr(f"Users/{user}/NTUSER.DAT.LOG1", _log(hive))
            z.writestr(f"Users/{user}/NTUSER.DAT.LOG2", _log(hive))
    pairs = {}
    real = analyze._registry_sources

    def spy(paths, found):  # noqa: ANN001, ANN202
        out = real(paths, found)
        pairs.update({x[1]: [p.name for p in x[2]] for x in out if len(x) > 2})
        return out
    monkeypatch.setattr(analyze, "_registry_sources", spy)
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    c = TestClient(create_app())
    r = c.post("/api/cases", files={"file": ("hives_PC.zip", buf.getvalue())}).json()
    for _ in range(1200):
        t = next((x for x in c.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.1)
    reg = json.loads((tmp_path / "cases" / r["analysis_id"] / "results" / "registry.json").read_text())
    labels = sorted(s["label"] for s in reg["sources"])
    assert labels == ["archive › Users/ana/NTUSER.DAT", "archive › Users/luis/NTUSER.DAT"]   # no .LOG read as a hive
    # each hive gets the logs of its own folder, whatever extraction renamed them to
    a, b = pairs["archive › Users/ana/NTUSER.DAT"], pairs["archive › Users/luis/NTUSER.DAT"]
    assert len(a) == len(b) == 2 and set(a).isdisjoint(b)
