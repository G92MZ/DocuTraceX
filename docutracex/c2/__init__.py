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


def analyze(original: Path, extracted_dir: Path) -> dict[str, Any]:
    from ..findings import finding_id

    result: dict[str, Any] = {"module": "c2", "objects_scanned": 0, "configs": [], "findings": [],
                              "families": list(FAMILIES), "status": "ok"}
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for label, path, stored in _targets(original, extracted_dir):
        try:
            if path.stat().st_size > MAX_SIZE:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        result["objects_scanned"] += 1
        for cfg in scan_object(path, data):
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
    result["counts"] = {"configs": len(result["configs"]), "findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
