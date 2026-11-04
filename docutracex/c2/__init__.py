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

Each configuration becomes a high-severity finding with the C2 endpoints in
its evidence, and its values feed the common IOC extractor.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

MAX_FILES = 500
MAX_SIZE = 64 * 1024 * 1024
FAMILIES = ("Cobalt Strike", "Metasploit / Meterpreter", "Remcos", "AsyncRAT", "DcRAT", "QuasarRAT",
            "njRAT", "XWorm", "AgentTesla", "NanoCore", "RedLine / META", "Snake Keylogger",
            "Raccoon Stealer v2", "Warzone / AveMaria", "DarkGate")


def _targets(original: Path, extracted_dir: Path):
    yield original.name, original, ""
    if extracted_dir.is_dir():
        n = 0
        for p in sorted(extracted_dir.rglob("*")):
            if n >= MAX_FILES:
                break
            if p.is_file():
                n += 1
                rel = p.relative_to(extracted_dir.parent).as_posix()
                yield rel, p, rel


def scan_object(path: Path, data: bytes) -> list[dict[str, Any]]:
    """Every configuration found in one object (normally zero or one)."""
    from . import cobalt, dotnet_more, dotnet_rats, metasploit, remcos, stealers

    out: list[dict[str, Any]] = []
    for name, fn in (("cobalt", lambda: cobalt.extract(path, data)),
                     ("remcos", lambda: remcos.extract(data) if remcos.prefilter(data) else None),
                     ("dotnet", lambda: dotnet_rats.extract(data)),
                     ("metasploit", lambda: metasploit.extract(data) if metasploit.prefilter(data) else None)):
        try:
            res = fn()
        except Exception as exc:  # noqa: BLE001  (one extractor never breaks the scan)
            log.warning("c2 extractor %s failed on %s: %s", name, path.name, exc)
            continue
        if res:
            out.append(res)
    if not any(r.get("kind") == "RAT" for r in out):
        try:
            out += dotnet_more.extract_all(data)
        except Exception as exc:  # noqa: BLE001
            log.warning("c2 extractor dotnet_more failed on %s: %s", path.name, exc)
    if not any(r.get("kind") in ("RAT", "stealer") and r.get("c2") for r in out):
        try:
            out += stealers.extract_all(data)
        except Exception as exc:  # noqa: BLE001
            log.warning("c2 extractor stealers failed on %s: %s", path.name, exc)
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
    if any(r["family"] == "Cobalt Strike" for r in out):
        out = [r for r in out if not r["family"].startswith("Metasploit")]
    return out


def _finding(cfg: dict[str, Any]) -> dict[str, Any]:
    s = cfg.get("summary") or {}
    c2 = s.get("C2") or s.get("Hosts") or cfg.get("c2") or []
    detail = f"{cfg['family']} configuration ({cfg['kind']})" + (f": C2 {', '.join(c2[:4])}" if c2 else "")
    evidence = "; ".join(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}"
                         for k, v in s.items())[:1500]
    sev = "high" if c2 and cfg.get("confidence") != "low" else "medium"
    return {"tool": "c2", "rule": "c2:" + cfg["family"].split(" /")[0].split(" ")[0].lower(),
            "severity": sev, "detail": detail, "location": cfg.get("object", ""), "evidence": evidence}


def _scan_worker(path_s: str) -> tuple[list[dict[str, Any]], float, str]:
    """One object in a worker process: (configs, seconds, error)."""
    import time as _time
    t0 = _time.perf_counter()
    p = Path(path_s)
    try:
        return scan_object(p, p.read_bytes()), _time.perf_counter() - t0, ""
    except Exception as exc:  # noqa: BLE001
        return [], _time.perf_counter() - t0, str(exc)[:200]


def _scan_all(todo: list[tuple[str, Path, str]], prog: Any) -> list[list[dict[str, Any]]]:
    """Configs of every object, in order; several worker processes when it pays
    (the extractors are pure Python: threads would share one CPU)."""
    from ..objects import workers
    n = workers(len(todo), 4)
    if n > 1 and len(todo) >= 4:
        try:
            from concurrent.futures import ProcessPoolExecutor
            out: list[list[dict[str, Any]]] = []
            with ProcessPoolExecutor(max_workers=n) as ex:
                for (label, _p, _s), (found, secs, err) in zip(todo, ex.map(_scan_worker, [str(t[1]) for t in todo])):
                    prog.record(label, secs, len(found), err or ", ".join(c["family"] for c in found)[:200])
                    out.append(found)
            return out
        except Exception as exc:  # noqa: BLE001  (no process pool here: one by one)
            log.warning("c2: parallel scan unavailable (%s), scanning sequentially", exc)
    out = []
    for label, path, _s in todo:
        found, secs, err = _scan_worker(str(path))
        prog.record(label, secs, len(found), err or ", ".join(c["family"] for c in found)[:200])
        out.append(found)
    return out


def analyze(original: Path, extracted_dir: Path, only: set[str] | None = None) -> dict[str, Any]:
    """``only`` = object ids (``original`` / path relative to the case folder)."""
    from ..findings import finding_id

    result: dict[str, Any] = {"module": "c2", "objects_scanned": 0, "configs": [], "findings": [],
                              "families": list(FAMILIES), "status": "ok"}
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    from ..progress import ObjectProgress
    todo = []
    for label, path, stored in _targets(original, extracted_dir):
        if only is not None and (stored or "original") not in only:
            continue
        try:
            if path.stat().st_size > MAX_SIZE:
                continue
        except OSError:
            continue
        todo.append((label, path, stored))
    prog = ObjectProgress(len(todo))
    for (label, path, stored), found in zip(todo, _scan_all(todo, prog)):
        result["objects_scanned"] += 1
        for cfg in found:
            key = (cfg["family"], ",".join(sorted(cfg.get("c2") or [])))
            if key in seen and cfg.get("c2"):   # the same config carried by several objects
                seen[key].setdefault("also_in", []).append(label)
                continue
            seen[key] = cfg
            cfg["object"] = label
            cfg["stored_path"] = stored
            f = _finding(cfg)
            cfg["finding_id"] = finding_id(f["tool"], f["rule"], f["location"], f["detail"])
            result["configs"].append(cfg)
            result["findings"].append(f)
    result["timings"] = prog.timings()
    result["counts"] = {"configs": len(result["configs"]), "findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
