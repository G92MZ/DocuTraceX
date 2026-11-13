"""C2 / implant configuration extraction (static).

Runs over every object of a case — the original, everything extracted, nested
children and decoded / decrypted stages — and pulls the configuration out of
the implants it recognises, without running anything:

* Cobalt Strike beacons and stagers (``1768.py``, built-in fallback)
* Metasploit / Meterpreter stagers (shellcode shapes)
* Remcos (RC4 ``SETTINGS`` resource)
* AsyncRAT / DcRAT / QuasarRAT (.NET, AES + HMAC settings)
* njRAT (plain settings), XWorm (AES-ECB, key from the mutex), AgentTesla-style
  stealers (exfiltration channel in clear), NanoCore (identification only)
* RedLine / META, Snake Keylogger, Raccoon v2, Warzone / AveMaria, DarkGate
* Go implants (Sliver, Merlin, Mythic Go agents, generic): framework and C2
  endpoints from the Go analysis, when it ran (``golang_c2``)

Each configuration becomes a high-severity finding with the C2 endpoints in
its evidence, and its values feed the common IOC extractor.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

MAX_FILES = 500
MAX_SIZE = 64 * 1024 * 1024
FAMILIES = ("Cobalt Strike", "Metasploit / Meterpreter", "Remcos", "AsyncRAT", "DcRAT", "QuasarRAT",
            "njRAT", "XWorm", "AgentTesla", "NanoCore", "RedLine / META", "Snake Keylogger",
            "Raccoon Stealer v2", "Warzone / AveMaria", "DarkGate", "Sliver", "Merlin", "Mythic (Go agent)",
            "Go implant")


# Files other analyses derived from the sample (managed resources, pixels,
# decrypted stages, hidden payloads, unpacked code): scanned first, so a big
# extraction (an MSI with hundreds of files) never pushes them past MAX_FILES.
_DERIVED_DIRS = ("dotnet_resources", "stages", "decrypted", "hidden", "unpacked", "go_embed", "code_streams")
_DERIVED_SOURCES = ("code-resources", "decrypted", "stage", "hidden", "unpacked")


def _targets(original: Path, extracted_dir: Path, prov: dict[str, dict[str, Any]] | None = None):
    yield original.name, original, ""
    if extracted_dir.is_dir():
        prov = prov or {}
        files = [p for p in extracted_dir.rglob("*") if p.is_file()]

        def rank(p: Path) -> tuple[int, str]:
            rel = p.relative_to(extracted_dir.parent).as_posix()
            derived = (any(part in _DERIVED_DIRS for part in p.relative_to(extracted_dir).parts[:-1])
                       or (prov.get(rel) or {}).get("source") in _DERIVED_SOURCES)
            return (0 if derived else 1, rel)
        for n, p in enumerate(sorted(files, key=rank)):
            if n >= MAX_FILES:
                break
            rel = p.relative_to(extracted_dir.parent).as_posix()
            yield rel, p, rel


def provenance(case_root: Path | None, root_name: str = "") -> dict[str, dict[str, Any]]:
    """stored_path → how the object was obtained from the sample: the chain of
    objects above it and each step (".NET resource X", "bitmap pixels: XOR key …",
    "decrypted: AES …"), from the nested tree."""
    if case_root is None:
        return {}
    try:
        tree = (json.loads((case_root / "results" / "nested.json").read_text(encoding="utf-8")) or {}).get("tree") or []
    except (OSError, ValueError):
        return {}
    out: dict[str, dict[str, Any]] = {}

    def step(n: dict[str, Any]) -> str:
        rec = [r for r in (n.get("recipe") or []) if r and r != "dotnet-resource"]
        how = " › ".join(rec[-2:]) if rec else (n.get("origin") or n.get("decrypted_from") or "")
        return f"{n.get('filename', '?')}" + (f" ({how})" if how else "")

    def walk(nodes: list[dict[str, Any]], chain: list[str], depth: int = 0) -> None:
        if depth > 16:
            return
        for n in nodes:
            here = chain + [step(n)]
            if n.get("stored_path"):
                out[n["stored_path"]] = {"chain": here, "source": n.get("source", ""),
                                         "text": " › ".join(here)}
            walk(n.get("children") or [], here, depth + 1)
    walk(tree, [root_name] if root_name else [])
    return out


def scan_object(path: Path, data: bytes) -> list[dict[str, Any]]:
    """Every configuration found in one object (normally zero or one)."""
    return scan_object_detailed(path, data)[0]


def _applicable(name: str, data: bytes) -> bool:
    from . import cobalt, metasploit, remcos
    if name == "cobalt":
        return cobalt.applicable(data)
    if name == "remcos":
        return remcos.prefilter(data)
    if name == "metasploit":
        return metasploit.prefilter(data)
    if name == "dotnet":
        from . import dotnet_rats
        return dotnet_rats.prefilter(data)
    if name == "go":
        from . import golang_c2
        return golang_c2.prefilter(data)
    return True                       # string-based extractors read any object


def scan_object_detailed(path: Path, data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(configurations, runs): every registered extractor runs on the object and
    says what happened (``registry.STATUSES``), with its RAW output.

    Shellcode wrapped in an encoder stub (shikata_ga_nai, x64/xor) is decoded
    first (``sc_decoder``: the stub alone, emulated) and the extractors read
    the decoded payload."""
    from . import sc_decoder
    if not sc_decoder.decoder(data):
        return _scan_detailed(path, data)
    dec = sc_decoder.decode(data)
    if not dec:
        return _scan_detailed(path, data)
    import tempfile
    with tempfile.TemporaryDirectory(prefix="dtx_sc_") as tmp:
        dp = Path(tmp) / f"{path.stem}.decoded.bin"
        dp.write_bytes(dec["data"])
        out, runs = _scan_detailed(dp, dec["data"])
    for cfg in out:
        cfg["method"] = f"{cfg.get('method', '')} · {dec['encoder']} decoded by emulation".strip(" ·")
        cfg["summary"] = {"Encoder": dec["note"], **(cfg.get("summary") or {})}
        cfg.setdefault("fields", {})["encoder"] = dec["encoder"]
        cfg["fields"]["decoded payload"] = f"{len(dec['data'])} bytes at offset 0x{dec['offset']:x}"
    return out, runs


def _scan_detailed(path: Path, data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    import time as _time

    from . import cobalt, dotnet_more, dotnet_rats, metasploit, remcos, stealers
    from .registry import EXTRACTORS, dependency_status, status_of

    out: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []

    def run(name: str, fn) -> list[dict[str, Any]]:  # noqa: ANN001
        t0 = _time.perf_counter()
        deps = dependency_status(name)
        if deps["missing_required"]:                  # switched off, never a crash: the others still run
            runs.append({"extractor": name, "version": EXTRACTORS.get(name, {}).get("version", ""),
                         "status": "missing_dependency", "seconds": 0.0,
                         "error": "needs " + "; ".join(deps["missing_required"]), "raw": []})
            return []
        applicable = _applicable(name, data)
        found: list[dict[str, Any]] = []
        err = ""
        if applicable:
            try:
                res = fn()
                found = [r for r in (res if isinstance(res, list) else [res]) if r]
            except Exception as exc:  # noqa: BLE001  (one extractor never breaks the scan)
                log.warning("c2 extractor %s failed on %s: %s", name, path.name, exc)
                err = f"{type(exc).__name__}: {exc}"[:300]
        raw: Any
        if name == "cobalt":
            raw = [{"tools": c.pop("_raw", []), "indicators": c.get("indicators") or []} for c in found]
        else:
            raw = [{k: v for k, v in c.items() if not k.startswith("_")} for c in found]
        for c in found:
            c["extractor"] = name
            c["extractor_version"] = EXTRACTORS.get(name, {}).get("version", "")
        runs.append({"extractor": name, "version": EXTRACTORS.get(name, {}).get("version", ""),
                     "status": status_of(found, applicable, err), "seconds": round(_time.perf_counter() - t0, 3),
                     "error": err, "raw": raw, **({"degraded": deps["missing_optional"]} if deps["missing_optional"] else {})})
        return found

    out += run("cobalt", lambda: cobalt.extract(path, data))
    out += run("remcos", lambda: remcos.extract(data))
    def dotnet_both() -> dict[str, Any] | None:
        own = dotnet_rats.extract(data)
        from . import ratking
        from .registry import _available
        if not _available("python", "rat_king_parser"):
            return own
        return ratking.combine(own, ratking.extract(path))
    out += run("dotnet", dotnet_both)
    out += run("metasploit", lambda: metasploit.extract(data))
    if not any(r.get("kind") == "RAT" for r in out):
        out += run("dotnet_more", lambda: dotnet_more.extract_all(data))
    if not any(r.get("kind") in ("RAT", "stealer") and r.get("c2") for r in out):
        out += run("stealers", lambda: stealers.extract_all(data))
    from . import rmm
    out += run("rmm", lambda: rmm.extract(data, path.name))
    if not any(r.get("c2") and r.get("kind") not in ("indicators", "rmm") for r in out):
        from . import golang_c2
        out += run("go", lambda: golang_c2.extract(path, data))
    # settings the .NET analysis decrypted statically (CIL decryptors, .resources)
    if out and data[:2] == b"MZ" and b"BSJB" in data:
        try:
            from ..dotnet import static_strings
            dec = set(static_strings(data))
        except Exception:  # noqa: BLE001
            dec = set()
        for cfg in out:
            vals = [str(v) for v in (cfg.get("fields") or {}).values()] + [str(v) for v in cfg.get("c2") or []]
            hit = sorted({d for d in dec for v in vals if d and (d == v or (len(d) >= 6 and d in v) or (len(v) >= 6 and v in d))})
            if hit:
                cfg["decrypted_statically"] = hit[:20]
                cfg["method"] = (f"{cfg.get('method', '')}".replace("plain .NET strings", ".NET strings")
                                 + " · settings decrypted statically by the .NET analysis")
    # A Cobalt Strike stager also matches the generic block_api shape: keep CS.
    if any(r["family"] == "Cobalt Strike" and r.get("kind") != "indicators" for r in out):
        out = [r for r in out if not r["family"].startswith("Metasploit")]
    return out, runs


def _finding(cfg: dict[str, Any]) -> dict[str, Any]:
    s = cfg.get("summary") or {}
    c2 = s.get("C2") or s.get("Hosts") or cfg.get("c2") or []
    detail = f"{cfg['family']} configuration ({cfg['kind']})" + (f": C2 {', '.join(c2[:4])}" if c2 else "")
    evidence = "; ".join(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}"
                         for k, v in s.items())[:1500]
    if cfg.get("provenance"):                   # evidence, not detail: the finding id stays the same
        evidence = (f"from: {cfg['provenance']}; " + evidence)[:1800]
    sev = "high" if c2 and cfg.get("confidence") != "low" else "medium"
    if cfg["family"].startswith("RMM: "):         # legitimate software: who deployed it decides
        sev = "medium" if c2 else "low"
        detail = (f"{cfg['family'][5:]} (remote-access tool)"
                  + (f" bound to {', '.join(c2[:4])}" if c2 else ": product only, no instance in the file"))
        return {"tool": "c2", "rule": "c2:rmm", "severity": sev, "detail": detail,
                "location": cfg.get("object", ""), "evidence": evidence}
    return {"tool": "c2", "rule": "c2:" + cfg["family"].split(" /")[0].split(" ")[0].lower(),
            "severity": sev, "detail": detail, "location": cfg.get("object", ""), "evidence": evidence}


def _scan_worker(path_s: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], float, str]:
    """One object in a worker process: (configs, extractor runs, seconds, error)."""
    import time as _time
    t0 = _time.perf_counter()
    p = Path(path_s)
    try:
        cfgs, runs = scan_object_detailed(p, p.read_bytes())
        return cfgs, runs, _time.perf_counter() - t0, ""
    except Exception as exc:  # noqa: BLE001
        return [], [], _time.perf_counter() - t0, str(exc)[:200]


def _scan_all(todo: list[tuple[str, Path, str]], prog: Any) -> list[tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
    """(configs, runs) of every object, in order; several worker processes when it
    pays (the extractors are pure Python: threads would share one CPU)."""
    from ..objects import workers
    n = workers(len(todo), 4)
    if n > 1 and len(todo) >= 4:
        try:
            from concurrent.futures import ProcessPoolExecutor
            out: list[tuple[list[dict[str, Any]], list[dict[str, Any]]]] = []
            with ProcessPoolExecutor(max_workers=n) as ex:
                for (label, _p, _s), (found, runs, secs, err) in zip(todo, ex.map(_scan_worker, [str(t[1]) for t in todo])):
                    prog.record(label, secs, len(found), err or ", ".join(c["family"] for c in found)[:200])
                    out.append((found, runs))
            return out
        except Exception as exc:  # noqa: BLE001  (no process pool here: one by one)
            log.warning("c2: parallel scan unavailable (%s), scanning sequentially", exc)
    out = []
    for label, path, _s in todo:
        found, runs, secs, err = _scan_worker(str(path))
        prog.record(label, secs, len(found), err or ", ".join(c["family"] for c in found)[:200])
        out.append((found, runs))
    return out


RUNS_DIR = "c2_runs"


def _case_root(extracted_dir: Path) -> Path | None:
    root = extracted_dir.parent
    return root if (root / "case.json").is_file() else None


def runs_history(case_root: Path) -> list[str]:
    d = case_root / "results" / RUNS_DIR
    return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.is_dir() else []


def analyze(original: Path, extracted_dir: Path, only: set[str] | None = None) -> dict[str, Any]:
    """``only`` = object ids (``original`` / path relative to the case folder)."""
    from ..findings import finding_id

    import hashlib
    import json
    import secrets
    import time as _time

    from .normalize import normalize
    from .registry import EXTRACTORS, dependency_status, descriptors

    run_id = f"{_time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"
    case_root = _case_root(extracted_dir)
    run_dir = case_root / "results" / RUNS_DIR / run_id if case_root else None
    result: dict[str, Any] = {"module": "c2", "objects_scanned": 0, "configs": [], "findings": [],
                              "families": list(FAMILIES), "status": "ok", "run_id": run_id,
                              "registry": descriptors(), "extractor_status": {}, "warnings": []}
    for ex in EXTRACTORS:                              # dependency policy: optional, with a warning
        d = dependency_status(ex, refresh=True)
        if d["missing_required"]:
            result["warnings"].append(f"{EXTRACTORS[ex]['name']}: switched off — needs {'; '.join(d['missing_required'])}")
        elif d["missing_optional"]:
            result["warnings"].append(f"{EXTRACTORS[ex]['name']}: works with less — missing {'; '.join(d['missing_optional'])}")
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    from ..progress import ObjectProgress
    todo = []
    prov = provenance(case_root, original.name)
    for label, path, stored in _targets(original, extracted_dir, prov):
        if only is not None and (stored or "original") not in only:
            continue
        try:
            if path.stat().st_size > MAX_SIZE:
                continue
        except OSError:
            continue
        todo.append((label, path, stored))
    prog = ObjectProgress(len(todo))
    die_by_name = _die_detects(case_root)
    for idx, ((label, path, stored), (found, runs)) in enumerate(zip(todo, _scan_all(todo, prog))):
        result["objects_scanned"] += 1
        if not any(c.get("kind") != "indicators" and c.get("c2") for c in found):
            _protected(result, label, path, die_by_name)
        raw_ref = f"{RUNS_DIR}/{run_id}/{idx:04d}.json"
        for r in runs:
            st = result["extractor_status"].setdefault(r["extractor"], {})
            st[r["status"]] = st.get(r["status"], 0) + 1
        if run_dir is not None:          # RAW: written once per run, never overwritten
            try:
                run_dir.mkdir(parents=True, exist_ok=True)
                try:
                    sha = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    sha = ""
                (run_dir / f"{idx:04d}.json").write_text(json.dumps(
                    {"run_id": run_id, "object": label, "stored_path": stored, "sha256": sha,
                     "extractors": runs}, default=str), encoding="utf-8")
            except OSError as exc:
                log.warning("c2: RAW record not written for %s: %s", label, exc)
        for cfg in found:
            cfg["run_id"] = run_id
            cfg["raw_ref"] = raw_ref if run_dir is not None else ""
            cfg["normalized"] = normalize(cfg, cfg.get("extractor", ""), cfg.get("extractor_version", ""),
                                          run_id, cfg["raw_ref"])
            key = (cfg["family"], ",".join(sorted(cfg.get("c2") or [])))
            if cfg.get("kind") == "indicators":           # the same traces in a script and its decoded copies
                key = (cfg["family"], "indicators:" + "|".join(cfg.get("indicators") or []))
                if key in seen:
                    seen[key].setdefault("also_in", []).append(label)
                    continue
            if key in seen and cfg.get("c2"):   # the same config carried by several objects
                seen[key].setdefault("also_in", []).append(label)
                continue
            seen[key] = cfg
            cfg["object"] = label
            cfg["stored_path"] = stored
            if stored and prov.get(stored):
                cfg["provenance"] = prov[stored]["text"]
            f = _finding(cfg)
            cfg["finding_id"] = finding_id(f["tool"], f["rule"], f["location"], f["detail"])
            result["configs"].append(cfg)
            result["findings"].append(f)
    # a family whose configuration was recovered does not also need its bare traces
    with_cfg = {c["family"] for c in result["configs"] if c.get("kind") != "indicators" and c.get("c2")}
    drop = {c.get("finding_id") for c in result["configs"] if c.get("kind") == "indicators" and c["family"] in with_cfg}
    if drop:
        result["configs"] = [c for c in result["configs"] if c.get("finding_id") not in drop]
        result["findings"] = [f for f in result["findings"]
                              if finding_id(f["tool"], f["rule"], f["location"], f["detail"]) not in drop]
    if case_root is not None:
        try:
            from .correlate import relate_and_index
            relate_and_index(case_root.parent, case_root.name, result["configs"], partial=only is not None)
        except Exception as exc:  # noqa: BLE001
            log.warning("c2: cross-case correlation skipped: %s", exc)
        result["runs"] = runs_history(case_root)
    result["timings"] = prog.timings()
    result["counts"] = {"configs": len(result["configs"]), "findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result


def _die_detects(case_root: Path | None) -> dict[str, list[dict[str, Any]]]:
    """File name → Detect It Easy detects, from the PE analysis of the case (when DIE ran)."""
    if case_root is None:
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    try:
        import json
        msi = json.loads((case_root / "results" / "msi.json").read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}
    for it in msi.get("items") or []:
        dets = ((it.get("unpack") or {}).get("die") or {}).get("detects") or []
        if it.get("file") and dets:
            out[str(it["file"])] = dets
    return out


def _protected(result: dict[str, Any], label: str, path: Path, die_by_name: dict[str, list[dict[str, Any]]]) -> None:
    """No configuration in this object: say so when a protector is why."""
    from . import protection
    try:
        data = path.read_bytes()
    except OSError:
        return
    if data[:2] != b"MZ":
        return
    found = protection.detect(data, die_by_name.get(path.name) or die_by_name.get(label))
    if found:
        result.setdefault("protected", []).append({"object": label, "protectors": found,
                                                   "note": protection.note(found)})


def reinterpret(case_root: Path, run_id: str | None = None) -> dict[str, Any]:
    """Re-read a run's RAW records with the current parsers and normalizer —
    no extractor is run again, the RAW stays as it is. The new interpretation
    is written next to the run (``reinterpreted-<time>.json``, earlier ones
    kept) and replaces the configurations' parsed values in the C2 result."""
    import json
    import time as _time

    from ..storage import CasePaths, read_json, write_subresult
    from . import cobalt
    from .normalize import normalize
    from .registry import EXTRACTORS

    paths = CasePaths(case_root.name, cases_dir=case_root.parent)
    res = read_json(paths.subresult("c2")) or {}
    run_id = run_id or res.get("run_id") or ""
    run_dir = case_root / "results" / RUNS_DIR / run_id
    if not run_id or not run_dir.is_dir():
        raise FileNotFoundError(f"no RAW record for run {run_id!r}")
    by_ref: dict[str, dict[str, Any]] = {}
    for f in sorted(run_dir.glob("[0-9]*.json")):
        try:
            by_ref[f"{RUNS_DIR}/{run_id}/{f.name}"] = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    changed, out = 0, []
    for cfg in res.get("configs") or []:
        rec = by_ref.get(cfg.get("raw_ref") or "")
        if rec is None:
            continue
        ext = cfg.get("extractor") or ""
        new = None
        if ext == "cobalt":
            runs = [r for r in rec.get("extractors") or [] if r["extractor"] == "cobalt"]
            for raw in (runs[0].get("raw") or []) if runs else []:
                got = cobalt.reinterpret(raw.get("tools") or [], raw.get("indicators") or [])
                if got and got.get("family") == cfg.get("family"):
                    new = got
                    break
        if new is not None:
            keep = {k: cfg[k] for k in ("object", "stored_path", "finding_id", "also_in", "run_id", "raw_ref",
                                       "related", "extractor") if k in cfg}
            cfg.clear()
            cfg.update(new, **keep)
        cfg["extractor_version"] = EXTRACTORS.get(ext, {}).get("version", cfg.get("extractor_version", ""))
        before = json.dumps(cfg.get("normalized"), sort_keys=True, default=str)
        cfg["normalized"] = normalize(cfg, ext, cfg["extractor_version"], run_id, cfg.get("raw_ref", ""))
        changed += before != json.dumps(cfg["normalized"], sort_keys=True, default=str)
        out.append({"object": cfg.get("object"), "family": cfg.get("family"), "normalized": cfg["normalized"]})
    stamp = _time.strftime("%Y%m%d-%H%M%S")
    (run_dir / f"reinterpreted-{stamp}.json").write_text(json.dumps(
        {"run_id": run_id, "at": stamp, "extractor_versions": {k: v["version"] for k, v in EXTRACTORS.items()},
         "configs": out}, default=str), encoding="utf-8")
    res.setdefault("interpretations", []).append({"at": stamp, "run_id": run_id, "changed": changed})
    write_subresult(paths, "c2", res)
    return {"run_id": run_id, "configs": len(out), "changed": changed, "at": stamp}
