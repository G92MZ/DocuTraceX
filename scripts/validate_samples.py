#!/usr/bin/env python3
"""Batch validation with real samples: run the full analysis over a folder (or a
password-protected zip, as MalwareBazaar ships them) and tabulate what came out.

    python scripts/validate_samples.py <folder | file.zip> [--out report] [--expected expected.csv]
                                      [--modules c2,yara] [--keep]

For every file: a throw-away case, the full static pipeline plus the on-demand
modules (C2 by default), then one row with what matters for validation —
C2 configurations (family, kind, C2, engines and their agreement), each
extractor's status, the Go / .NET identification, the number of findings and
IOCs, the time it took and any error.

``--expected`` is a CSV ``name_or_sha256,family`` (family = what the sample is,
e.g. MalwareBazaar's signature): each row is then marked OK / MISS / OTHER, and
the totals per family say where the extractors need work.

Writes ``<out>.csv`` (one row per sample), ``<out>.json`` (everything) and
``<out>.md`` (a table to read or paste). STATIC ONLY: the same pipeline as the
app — nothing in a sample is ever run. Cases go to a temporary folder that is
deleted at the end (``--keep`` keeps it, to open them in the app).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MAX_FILE = 200 * 1024 * 1024


def _iter_samples(src: Path, password: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []

    def from_zip(z: Path) -> None:
        with zipfile.ZipFile(z) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > MAX_FILE:
                    continue
                try:
                    data = zf.read(info, pwd=password)
                except (RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
                    print(f"  ! {z.name}:{info.filename}: {exc}", file=sys.stderr)
                    continue
                out.append((f"{z.name}:{info.filename}", data))

    if src.is_file():
        if zipfile.is_zipfile(src):
            from_zip(src)
        else:
            out.append((src.name, src.read_bytes()))
        return out
    for p in sorted(src.rglob("*")):
        if not p.is_file() or p.stat().st_size > MAX_FILE:
            continue
        if p.suffix.lower() == ".zip" and zipfile.is_zipfile(p):
            from_zip(p)
        else:
            out.append((str(p.relative_to(src)), p.read_bytes()))
    return out


def _expected(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    exp: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) >= 2 and row[0].strip() and not row[0].startswith("#"):
                exp[row[0].strip().lower()] = row[1].strip()
    return exp


def _verdict(expected: str, families: list[str]) -> str:
    if not expected:
        return ""
    e = expected.lower().replace(" ", "").replace("-", "")
    fams = [f.lower().replace(" ", "").replace("-", "") for f in families]
    if any(e in f or f.split("/")[0] in e for f in fams if f):
        return "OK"
    return "OTHER" if families else "MISS"


def analyse(name: str, data: bytes, cases_dir: Path) -> dict[str, Any]:
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json

    sha = hashlib.sha256(data).hexdigest()
    row: dict[str, Any] = {"name": name, "sha256": sha, "size": len(data)}
    t0 = time.perf_counter()
    try:
        m = cases.create_case(io.BytesIO(data), Path(name.split(":")[-1]).name or sha, cases_dir=cases_dir)
        analyze.analyze_case(cases_dir / m["analysis_id"])
        paths = CasePaths(m["analysis_id"], cases_dir=cases_dir)
        row["case"] = m["analysis_id"]
    except Exception as exc:  # noqa: BLE001  (one sample never stops the batch)
        row["error"] = f"{type(exc).__name__}: {exc}"[:300]
        row["seconds"] = round(time.perf_counter() - t0, 1)
        return row
    row["seconds"] = round(time.perf_counter() - t0, 1)
    c2 = read_json(paths.subresult("c2")) or {}
    cfgs = c2.get("configs") or []
    row["c2_configs"] = [{"family": c.get("family"), "kind": c.get("kind"), "c2": (c.get("c2") or [])[:10],
                          "confidence": c.get("confidence"), "agreement": c.get("agreement", ""),
                          "object": c.get("object", ""), "method": c.get("method", "")} for c in cfgs]
    rank = ("extracted", "partial", "indicators", "error", "missing_dependency", "unsupported_format",
            "not_found", "not_applicable")
    statuses: dict[str, str] = {}
    for ext, counts in (c2.get("extractor_status") or {}).items():   # best status over the case's objects
        best = min(counts, key=lambda s: rank.index(s) if s in rank else len(rank)) if counts else ""
        statuses[ext] = best
    row["extractors"] = statuses
    go = read_json(paths.subresult("golang")) or {}
    row["go"] = ", ".join(sorted({(o.get("result") or {}).get("state", "") for o in go.get("objects") or []} - {""}))
    dn = read_json(paths.subresult("dotnet")) or {}
    row["dotnet_objects"] = len(dn.get("objects") or [])
    summ = read_json(paths.summary) or {}
    counts = summ.get("counts") or {}
    row["findings"] = counts.get("findings", "")
    row["iocs"] = counts.get("iocs", "")
    row["warnings"] = [w for w in (c2.get("warnings") or [])][:5]
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", type=Path, help="folder of samples, or a zip (MalwareBazaar: password infected)")
    ap.add_argument("--out", type=Path, default=Path("validation"), help="report path without extension")
    ap.add_argument("--expected", type=Path, help="CSV name_or_sha256,family")
    ap.add_argument("--password", default="infected", help="zip password (default: infected)")
    ap.add_argument("--modules", default="c2", help="on-demand modules to run too (default: c2; e.g. c2,yara,ml)")
    ap.add_argument("--keep", action="store_true", help="keep the cases (prints where)")
    a = ap.parse_args()

    os.environ["DOCUTRACEX_AUTO_MODULES"] = a.modules
    samples = _iter_samples(a.source, a.password.encode())
    if not samples:
        print("no samples found", file=sys.stderr)
        return 1
    exp = _expected(a.expected)
    cases_dir = Path(tempfile.mkdtemp(prefix="dtx-validate-"))
    rows = []
    try:
        for i, (name, data) in enumerate(samples, 1):
            print(f"[{i}/{len(samples)}] {name}", flush=True)
            row = analyse(name, data, cases_dir)
            want = exp.get(row["sha256"]) or exp.get(Path(name.split(":")[-1]).name.lower()) or ""
            row["expected"] = want
            row["result"] = _verdict(want, [c["family"] or "" for c in row.get("c2_configs") or []
                                            if c.get("kind") != "indicators"])
            rows.append(row)
    finally:
        if a.keep:
            print(f"cases kept in {cases_dir}")
        else:
            shutil.rmtree(cases_dir, ignore_errors=True)

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.with_suffix(".json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    cols = ["name", "sha256", "expected", "result", "c2_families", "c2", "agreement", "extractors", "go",
            "dotnet_objects", "findings", "iocs", "seconds", "error"]
    flat = []
    for r in rows:
        cf = r.get("c2_configs") or []
        flat.append({"name": r["name"], "sha256": r["sha256"], "expected": r.get("expected", ""),
                     "result": r.get("result", ""),
                     "c2_families": "; ".join(f"{c['family']} ({c['kind']})" for c in cf),
                     "c2": "; ".join(h for c in cf for h in c["c2"]),
                     "agreement": "; ".join(c["agreement"] for c in cf if c["agreement"]),
                     "extractors": "; ".join(f"{k}={v}" for k, v in (r.get("extractors") or {}).items()
                                             if v not in ("not_applicable", "not_found")),
                     "go": r.get("go", ""), "dotnet_objects": r.get("dotnet_objects", ""),
                     "findings": r.get("findings", ""), "iocs": r.get("iocs", ""),
                     "seconds": r.get("seconds", ""), "error": r.get("error", "")})
    with a.out.with_suffix(".csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(flat)
    md = ["| Sample | Expected | Result | C2 configuration | C2 | Engines | Go | s |", "|---|---|---|---|---|---|---|---|"]
    for f in flat:
        md.append(f"| {f['name'][:60]} | {f['expected']} | {f['result']} | {f['c2_families'][:80]} | "
                  f"{f['c2'][:80]} | {f['agreement']} | {f['go']} | {f['seconds']} |")
    tot: dict[str, dict[str, int]] = {}
    for f in flat:
        if f["expected"]:
            t = tot.setdefault(f["expected"], {"OK": 0, "MISS": 0, "OTHER": 0})
            t[f["result"]] = t.get(f["result"], 0) + 1
    if tot:
        md += ["", "| Family | OK | MISS | OTHER |", "|---|---|---|---|"]
        md += [f"| {k} | {v['OK']} | {v['MISS']} | {v['OTHER']} |" for k, v in sorted(tot.items())]
    errors = sum(1 for f in flat if f["error"])
    md += ["", f"{len(flat)} sample(s), {errors} error(s), "
               f"{sum(float(f['seconds'] or 0) for f in flat):.0f} s in total."]
    a.out.with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"report: {a.out.with_suffix('.md')} / .csv / .json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
