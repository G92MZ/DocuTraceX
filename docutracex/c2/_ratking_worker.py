"""Child process: .NET RAT configuration with jeFF0Falltrades' rat-king-parser (MIT).

Run by ``docutracex.c2.ratking`` as ``python _ratking_worker.py <file>`` so a slow or crashing
parse never takes the analysis down (and gets a timeout). Prints one JSON object.

STATIC ONLY: rat-king-parser reads the .NET metadata and decrypts the configuration
with the keys it finds there; nothing in the file is ever run.
"""

from __future__ import annotations

import json
import logging
import sys


def _plain(v):
    if isinstance(v, (bytes, bytearray)):
        try:
            return bytes(v).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(v).hex()
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    return v if isinstance(v, (str, int, float, bool)) or v is None else str(v)


def main() -> None:
    logging.disable(logging.CRITICAL)
    try:
        from pathlib import Path

        import rat_king_parser.rkp as rkp
        from rat_king_parser._version import __version__ as ver
        from rat_king_parser.config_parser import RATConfigParser
    except ImportError as exc:
        print(json.dumps({"status": "not_installed", "error": str(exc)[:200]}))
        return
    try:
        from rat_king_parser.yara_utils import YARC_PATH
        rule = rkp.load_yara(str(Path(rkp.__file__).parent / YARC_PATH))
        rep = RATConfigParser(sys.argv[1], rule, remap_config=True).report
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "lib": ver, "error": f"{type(exc).__name__}: {exc}"[:300]}))
        return
    rep = _plain(rep or {})
    cfg = rep.get("config") or {}
    found = isinstance(cfg, dict) and bool(cfg) and not rep.get("error")
    print(json.dumps({"status": "found" if found else "nothing", "lib": ver, "report": rep}))


if __name__ == "__main__":
    main()
