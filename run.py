#!/usr/bin/env python3
"""Launch DocuTraceX.

Convenience launcher. The app runs on YOUR Python; the analysis tools run on the
portable Python under tools/. On startup it checks for a newer version
(``update.py``) and, if you accept the update, re-provisions the toolchain
(``install.py``) so new tools are installed; then the portable is ensured and
the app starts.

    python run.py                       # http://127.0.0.1:8000
    python run.py --port 8001           # another port (e.g. next to WinHound)
    python run.py --host 0.0.0.0 --port 9000
    python run.py --no-update           # skip the update check (offline / CI)

HOST / PORT environment variables work too (arguments take priority).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

if sys.version_info < (3, 10):
    sys.exit(f"DocuTraceX needs Python 3.10 or newer to run the web app (this is "
             f"{sys.version.split()[0]}). Analysis runs on its own portable Python.")

HERE = Path(__file__).resolve().parent


def _auto_update() -> None:
    """Run update.py interactively; if it applied an update (exit 2), run
    install.py to re-provision. Never blocks startup on a failure."""
    update_py = HERE / "update.py"
    if not update_py.is_file():
        return
    try:
        # Interactive (inherits the terminal) so the [y/N] prompt works.
        rc = subprocess.run([sys.executable, str(update_py)], cwd=str(HERE)).returncode
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001  (update is best-effort, never fatal)
        print(f"[run] update check skipped: {exc}")
        return
    if rc != 2:
        return  # 0 = up to date / cancelled, 1 = error — start as usual
    install_py = HERE / "install.py"
    if not install_py.is_file():
        return
    print("\n[run] Update applied — re-provisioning the toolchain (install.py)...\n")
    try:
        r = subprocess.run([sys.executable, str(install_py)], cwd=str(HERE))
        if r.returncode != 0:
            print("[run] install.py did not finish cleanly; starting anyway "
                  "(the portable is healed on start).")
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[run] re-provisioning skipped: {exc}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="run.py", description="DocuTraceX web service")
    ap.add_argument("--host", default=None, help="listen interface (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=None,
                    help="port (default 8000; change it to run several apps at once)")
    ap.add_argument("--no-update", action="store_true",
                    help="skip the startup update check (offline / CI)")
    args = ap.parse_args()
    if args.host:
        # gmzpt
        os.environ["DOCUTRACEX_HOST"] = args.host
    if args.port:
        os.environ["DOCUTRACEX_PORT"] = str(args.port)

    if not args.no_update:
        _auto_update()

    # Import after the (possible) update so the newest code is loaded, and after
    # env is set so settings pick up the overrides.
    from docutracex.__main__ import main

    main()
