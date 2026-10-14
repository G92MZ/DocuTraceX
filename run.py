#!/usr/bin/env python3
"""Launch DocuTraceX.

Runs on YOUR Python (the web app). On startup it ensures the portable Python and
the bundled analysis tools exist under tools/ — provisioning them on first run —
then starts the app. The analysis tools run on the portable; the app does not.

    python run.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    setup = ROOT / "scripts" / "setup_portable_python.py"
    print("Ensuring portable Python and tools (tools/) ...")
    # Best-effort: provisions only if missing; never blocks app startup.
    subprocess.run([sys.executable, str(setup), "--ensure"], check=False)

    # Start the web app on THIS interpreter.
    from docutracex.__main__ import main as run_app
    run_app()


if __name__ == "__main__":
    main()
