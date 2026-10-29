"""Cobalt Strike beacon configuration with Fox-IT's ``dissect.cobaltstrike`` (MIT), the second parser
next to Didier Stevens' ``1768.py`` (see ``cobalt.py``, which runs both and shows one sub-tab each).

dissect finds the config by the RSA OID of ``SETTING_PUBKEY`` (single-byte, multi-byte and guardrail
XOR, ArtifactKit / xorencoded stages), reports the Cobalt Strike version, kill date, trial flag and
rebuilds the **malleable C2 profile**. It parses *beacons*: a stager carries no beacon config, so on a
stager only 1768.py (and the shellcode reader in cobalt.py) give results.

Runs in a child process (``_dissect_worker.py``) with a timeout. ``DOCUTRACEX_DISSECT_CS=0`` disables it.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

TOOL = "dissect.cobaltstrike"
TIMEOUT = 120
_WORKER = Path(__file__).with_name("_dissect_worker.py")


def enabled() -> bool:
    return os.environ.get("DOCUTRACEX_DISSECT_CS", "1") != "0"


def _run(path: Path, all_xor: bool) -> dict[str, Any]:
    try:
        r = subprocess.run([sys.executable, str(_WORKER), str(path), "1" if all_xor else "0"],
                           capture_output=True, text=True, check=False, encoding="utf-8",
                           errors="replace", timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        log.warning("dissect.cobaltstrike timed out on %s", path.name)
        return {"status": "timeout", "error": f"no result in {TIMEOUT} s"}
    except Exception as exc:  # noqa: BLE001
        log.warning("dissect.cobaltstrike failed on %s: %s", path.name, exc)
        return {"status": "error", "error": str(exc)}
    try:
        return json.loads((r.stdout or "").strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        log.warning("dissect.cobaltstrike: unreadable output on %s (rc=%s): %s",
                    path.name, r.returncode, (r.stderr or "")[-300:])
        return {"status": "error", "error": f"unreadable output (rc={r.returncode})"}


def _sleep(ms: Any, jitter: Any) -> str:
    return f"{int(ms) // 1000}s / {jitter or 0}%" if isinstance(ms, int) else ""


def view(raw: dict[str, Any]) -> dict[str, Any]:
    """Worker JSON → a view (same shape as the 1768.py one: status, method, summary, fields, hosts)."""
    st = raw.get("status", "error")
    lib = raw.get("lib") or ""
    v: dict[str, Any] = {"tool": TOOL, "status": st, "lib_version": lib}
    if st != "found":
        v["note"] = {
            "not_installed": "dissect.cobaltstrike is not installed in the portable Python "
                             "(pip install dissect.cobaltstrike, or re-run setup).",
            "nothing": "No beacon configuration found. dissect parses beacons (config block with the RSA "
                       "public key); stagers carry none.",
            "disabled": "Disabled (DOCUTRACEX_DISSECT_CS=0).",
            "timeout": raw.get("error", "timeout"),
            "error": raw.get("error", "error"),
        }.get(st, raw.get("error", ""))
        return v
    s = raw.get("settings") or {}
    port = raw.get("port")
    hosts = [h for h in raw.get("domains") or [] if h]
    wm = raw.get("watermark")
    summary: dict[str, Any] = {
        "Type": (raw.get("protocol") or "").upper(),
        "C2": [f"{h}:{port}" if port else h for h in hosts],
        "GET URI": raw.get("uris") or [],
        "POST URI": raw.get("submit_uri") or "",
        "User-Agent": s.get("SETTING_USERAGENT") or "",
        "Host header": s.get("SETTING_HOST_HEADER") or "",
        "Sleep / jitter": _sleep(raw.get("sleeptime"), raw.get("jitter")),
        "Pipe": s.get("SETTING_PIPENAME") or "",
        "Spawn to": " · ".join(x for x in (s.get("SETTING_SPAWNTO_X86"), s.get("SETTING_SPAWNTO_X64")) if x),
        "Watermark": (f"{wm}" + (" (trial)" if raw.get("is_trial") else "")) if wm is not None else "",
        "Version": raw.get("version") or "",
        "Kill date": raw.get("killdate") or "",
        "Public key SHA-256": raw.get("pubkey_sha256") or "",
        "Architecture": raw.get("architecture") or "",
    }
    fields = {k: (", ".join(map(str, x)) if isinstance(x, list) else str(x)) for k, x in s.items()}
    for k in ("xorkey", "xorencoded", "stages", "pe_compile_stamp", "pe_export_stamp", "guardrails",
              "modifications"):
        if raw.get(k) not in (None, [], "", False):
            fields[k] = ", ".join(map(str, raw[k])) if isinstance(raw[k], list) else str(raw[k])
    v.update({
        "method": f"{TOOL} {lib}".strip() + (f" (XOR 0x{raw['xorkey']})" if raw.get("xorkey") else ""),
        "summary": {k: x for k, x in summary.items() if x not in ("", [], None)},
        "fields": fields, "hosts": hosts,
        "profile": raw.get("profile") or "",
        "kind": "beacon",
    })
    return v


def extract(path: Path, all_xor: bool = True) -> dict[str, Any]:
    if not enabled():
        return view({"status": "disabled"})
    return view(_run(path, all_xor))
