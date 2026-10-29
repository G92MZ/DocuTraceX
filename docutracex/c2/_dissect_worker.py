"""Child process: Cobalt Strike beacon configuration with Fox-IT's dissect.cobaltstrike (MIT).

Run by ``docutracex.c2.cobalt_dissect`` as ``python _dissect_worker.py <file> <all_xor 0|1>`` so a slow
or crashing parse never takes the analysis down (and gets a timeout). Prints one JSON object.

STATIC ONLY: uses ``BeaconConfig`` (file parsing) and ``C2Profile`` (rebuilds the malleable profile
text from the config). ``dissect.cobaltstrike.client`` / ``pcap`` — which talk to a team server or
read network captures — are never imported.
"""

from __future__ import annotations

import json
import logging
import sys


def _plain(v):
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v).rstrip(b"\x00")
        try:
            s = b.decode("ascii")
            if s and s.isprintable():
                return s
        except UnicodeDecodeError:
            pass
        return b.hex()
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, (int, float, str, bool)) or v is None:
        return v
    return str(v)


def main() -> None:
    logging.basicConfig(level=logging.ERROR)
    path, all_xor = sys.argv[1], sys.argv[2:3] == ["1"]
    try:
        from dissect.cobaltstrike.beacon import BeaconConfig, sha256sum_pubkey
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "not_installed", "error": str(exc)}))
        return
    try:
        from importlib.metadata import version
        lib = version("dissect.cobaltstrike")
    except Exception:  # noqa: BLE001
        lib = ""
    try:
        with open(path, "rb") as fh:
            b = BeaconConfig.from_file(fh, all_xor_keys=all_xor)
    except ValueError as exc:
        print(json.dumps({"status": "nothing", "lib": lib, "error": str(exc)}))
        return
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "lib": lib, "error": f"{type(exc).__name__}: {exc}"}))
        return

    try:
        settings = dict(b.settings)
    except Exception:  # noqa: BLE001  (a pretty function choked: raw values)
        settings = dict(b.raw_settings)
    profile = ""
    try:
        from dissect.cobaltstrike.c2profile import C2Profile
        profile = C2Profile.from_beacon_config(b).as_text()
    except Exception as exc:  # noqa: BLE001
        profile = f"(profile could not be rebuilt: {type(exc).__name__}: {exc})"

    def safe(fn):
        try:
            return fn()
        except Exception:  # noqa: BLE001
            return None

    out = {
        "status": "found", "lib": lib,
        "domain_uri_pairs": safe(lambda: [list(p) for p in b.domain_uri_pairs]) or [],
        "domains": safe(lambda: b.domains) or [], "uris": safe(lambda: b.uris) or [],
        "submit_uri": safe(lambda: b.submit_uri), "port": safe(lambda: b.port),
        "protocol": safe(lambda: b.protocol), "watermark": safe(lambda: b.watermark),
        "is_trial": safe(lambda: b.is_trial), "version": safe(lambda: str(b.version)),
        "sleeptime": safe(lambda: b.sleeptime), "jitter": safe(lambda: b.jitter),
        "killdate": safe(lambda: b.killdate),
        "pubkey_sha256": safe(lambda: sha256sum_pubkey(b.public_key)) if safe(lambda: b.public_key) else None,
        "xorkey": b.xorkey.hex() if b.xorkey else None, "xorencoded": b.xorencoded,
        "architecture": b.architecture, "pe_compile_stamp": b.pe_compile_stamp,
        "pe_export_stamp": b.pe_export_stamp, "stages": list(b.stages or []),
        "guardrails": str(b.guardrails) if b.guardrails else None,
        "modifications": str(b.modifications) if b.modifications else None,
        "settings": settings, "profile": profile,
    }
    print(json.dumps(_plain(out)))


if __name__ == "__main__":
    main()
