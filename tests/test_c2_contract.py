"""C2 extractor contract (roadmap GEN / CS-004): registry statuses, RAW per run
(never overwritten), normalized fields, re-interpretation without re-running,
cross-case correlation; plus shellcode written as numbers and embedded beacons."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from docutracex import c2, decrypted
from docutracex.c2 import cobalt, normalize, registry

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms  # noqa: E402


def _case(cases: Path, name: str, data: bytes) -> tuple[Path, Path]:
    root = cases / name
    (root / "original").mkdir(parents=True)
    (root / "extracted").mkdir()
    (root / "results").mkdir()
    (root / "case.json").write_text("{}")
    orig = root / "original" / "beacon.bin"
    orig.write_bytes(data)
    return orig, root


def test_every_extractor_reports_a_status(tmp_path: Path) -> None:
    p = tmp_path / "b.bin"
    p.write_bytes(ms.cs_beacon_blob())
    cfgs, runs = c2.scan_object_detailed(p, p.read_bytes())
    st = {r["extractor"]: r["status"] for r in runs}
    assert st["cobalt"] == "extracted" and st["remcos"] == "not_applicable"
    assert set(st.values()) <= set(registry.STATUSES)
    assert cfgs[0]["extractor"] == "cobalt" and cfgs[0]["extractor_version"] == registry.EXTRACTORS["cobalt"]["version"]
    raw = next(r for r in runs if r["extractor"] == "cobalt")["raw"][0]
    assert raw["tools"], "the tools' own output is kept"


def test_raw_per_run_normalized_and_reinterpreted(tmp_path: Path) -> None:
    from docutracex.storage import CasePaths, read_json, write_subresult
    orig, root = _case(tmp_path / "cases", "case-a", ms.cs_beacon_blob())
    paths = CasePaths(root.name, cases_dir=root.parent)
    res = c2.analyze(orig, root / "extracted")
    write_subresult(paths, "c2", res)
    cfg = res["configs"][0]
    assert cfg["run_id"] == res["run_id"] and cfg["raw_ref"].startswith(f"c2_runs/{res['run_id']}/")
    raw_file = root / "results" / cfg["raw_ref"]
    rec = json.loads(raw_file.read_text())
    assert rec["sha256"] == hashlib.sha256(orig.read_bytes()).hexdigest()
    n = {f["name"]: f for f in cfg["normalized"]}
    assert n["C2"]["value"] == "cdn-update.example.net:443" and n["C2"]["type"] == "host:port"
    assert n["C2"]["status"] in ("extracted", "decrypted") and n["C2"]["run_id"] == res["run_id"]
    if "Domain fronting" in n:
        assert n["Domain fronting"]["status"] == "inferred"
    before = hashlib.sha256(raw_file.read_bytes()).hexdigest()
    # a later parser fix: re-interpret the stored RAW (tools not run again)
    stored = read_json(paths.subresult("c2"))
    stored["configs"][0]["summary"] = {"C2": ["tampered"]}
    stored["configs"][0]["normalized"] = []
    write_subresult(paths, "c2", stored)
    out = c2.reinterpret(root)
    again = read_json(paths.subresult("c2"))["configs"][0]
    assert out["configs"] == 1 and again["summary"]["C2"] == ["cdn-update.example.net:443"] and again["normalized"]
    assert hashlib.sha256(raw_file.read_bytes()).hexdigest() == before
    assert list((raw_file.parent).glob("reinterpreted-*.json"))
    # a new run never overwrites the earlier one
    res2 = c2.analyze(orig, root / "extracted")
    assert res2["run_id"] != res["run_id"] and len(res2["runs"]) == 2 and raw_file.is_file()


def test_related_across_cases(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    oa, ra = _case(cases, "case-a", ms.cs_beacon_blob())
    ob, rb = _case(cases, "case-b", ms.cs_beacon_blob())
    c2.analyze(oa, ra / "extracted")
    res = c2.analyze(ob, rb / "extracted")
    rel = res["configs"][0]["related"]
    assert rel and rel[0]["case"] == "case-a" and rel[0]["strength"] == "strong"
    assert "RSA" in rel[0]["match"] or "C2 host" in rel[0]["match"]


def test_normalize_conflicting_and_inferred() -> None:
    cfg = {"family": "Cobalt Strike", "kind": "beacon", "confidence": "high", "method": "1768.py (XOR 0x2e)",
           "tools": {"1768": {"tool": "1768.py", "status": "found", "method": "1768.py (XOR 0x2e)",
                              "summary": {"C2": ["a.example:443"], "Sleep / jitter": "60s / 0%", "Version (guess)": "4.2"}},
                     "dissect": {"tool": "dissect.cobaltstrike", "status": "found", "method": "dissect (XOR 0x2e)",
                                 "summary": {"C2": ["b.example:443"], "Sleep / jitter": "60s / 0%"}}},
           "sections": {"Guardrails": {"Keyed to": "computer", "Value (recovered)": "desktop-inv01", "Note": "x"}}}
    f = normalize.normalize(cfg, "cobalt", "2.0", "r1", "c2_runs/r1/0000.json")
    by = {(x["name"], x["value"]): x for x in f}
    assert by[("C2", "a.example:443")]["status"] == "conflicting" and by[("C2", "b.example:443")]["status"] == "conflicting"
    sl = by[("Sleep / jitter", "60s / 0%")]
    assert sl["confidence"] == "high" and "1768.py" in sl["extractor"] and "dissect" in sl["extractor"]
    assert by[("Version (guess)", "4.2")]["status"] == "inferred"
    assert by[("Guardrails / Value (recovered)", "desktop-inv01")]["status"] == "decrypted"
    assert not any(x["name"].endswith("Note") for x in f)


def test_shellcode_written_as_numbers() -> None:
    sc = b"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5" + bytes(range(1, 120))
    c = 'unsigned char buf[] =\n"' + "".join(f"\\x{b:02x}" for b in sc[:60]) + '"\n"' + "".join(f"\\x{b:02x}" for b in sc[60:]) + '";'
    assert decrypted.byte_arrays(c) == [("escaped bytes", sc)]
    cs = "byte[] buf = new byte[] { " + ",".join(f"0x{b:02x}" for b in sc) + " };"
    assert decrypted.byte_arrays(cs) == [("hex array", sc)]
    vba = "Myarray = Array(" + ",".join(str(b - 256 if b > 127 else b) for b in sc[:50]) + ", _\n" \
        + ",".join(str(b - 256 if b > 127 else b) for b in sc[50:]) + ")"
    assert decrypted.byte_arrays(vba, binary_only=True) == [("number array", sc)]
    assert decrypted.byte_arrays("t = [" + ",".join(str(i) for i in range(90)) + "]") == []      # a table, not code
    mods = {"oletools": {"tools": {"olevba": {"_full_code": vba}}}}
    kids = [p for p in decrypted.payloads_from(mods) if p.get("data") == sc]
    assert kids and kids[0]["ext"] == ".bin" and kids[0]["recipe"][:2] == ["vba", "number array"]


def test_embedded_beacon_is_carved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    beacon = b"MZARUH" + b"\x00" * 64 + ms.cs_beacon_blob()[len(ms.C2_STUB):]
    data = b"\xe8\x00\x00\x00\x00\x59" + b"\x90" * 300 + beacon
    assert any(off == 306 for off, _ in cobalt.carve_reflective(data))
    real = cobalt._extract
    monkeypatch.setattr(cobalt, "_extract", lambda p, d: real(p, d) if d.startswith(b"MZARUH") else None)
    p = tmp_path / "loader.bin"
    p.write_bytes(data)
    r = cobalt.extract(p, data)
    assert r and r["carved_at"] == 306 and r["summary"]["Carved at"].startswith("0x132")
