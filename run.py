#!/usr/bin/env python3
"""Launch DocuTraceX.

Runs on YOUR Python (the web app). On startup it ensures the portable Python and
the bundled analysis tools exist under tools/ — provisioning them on first run —
then starts the app. The analysis tools run on the portable; the app does not.

    python run.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Make scripts/ importable so we can call the provisioner in-process.
sys.path.insert(0, str(ROOT / "scripts"))


def main() -> None:
    print("=" * 60)
    print("DocuTraceX — ensuring portable Python and tools (tools/)")
    print("=" * 60)
    try:
        from setup_portable_python import ensure  # type: ignore
        ok = ensure()  # provisions on first run; returns fast if already present
    except Exception as exc:  # noqa: BLE001  (never block app startup)
        print(f"[!] Could not run the portable setup: {exc}")
        print("[!] Starting the app anyway; analysis tools may be unavailable.")
        ok = False
    print(f"[i] Portable tools ready: {ok}")
    print("-" * 60)

    # Start the web app on THIS interpreter.
    from docutracex.__main__ import main as run_app
    run_app()


if __name__ == "__main__":
    main()
