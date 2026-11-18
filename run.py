#!/usr/bin/env python3
"""Launch DocuTraceX.

Convenience launcher. The app runs on YOUR Python; the analysis tools run on the
portable Python under tools/. On startup it checks for a newer version
(``update.py``) and, if you accept the update, re-provisions the toolchain
(``install.py``) so new tools are installed; then the portable is ensured and
the app starts.

    python run.py                       # http://<this IP>:8000 (all interfaces)
    python run.py --port 8001           # another port (e.g. next to WinHound)
    python run.py --host 127.0.0.1      # this computer only
    python run.py --no-update           # skip the update check (offline / CI)
    python run.py --update              # update without asking, then start

The app's **Update** button runs ``run.py --update --wait-port HOST:PORT``: it waits
until the running app has freed its port, updates, re-provisions and starts again.

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


def _wait_port(spec: str, timeout: float = 90.0) -> bool:
    """Wait until nothing listens on HOST:PORT any more (the app being replaced has
    exited). True when free, False on timeout (start anyway: uvicorn says why)."""
    import socket
    import time
    host, _, port = spec.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection((host, int(port)), timeout=1):
                pass
        except OSError:
            return True
        time.sleep(0.5)
    return False


def _auto_update(ask: bool = True) -> None:
    """Run update.py (asking first, or ``--yes``); if it applied an update (exit 2),
    run install.py to re-provision. Never blocks startup on a failure."""
    update_py = HERE / "update.py"
    if not update_py.is_file():
        return
    try:
        # Interactive (inherits the terminal) so the [y/N] prompt works.
        cmd = [sys.executable, str(update_py)] + ([] if ask else ["--yes"])
        rc = subprocess.run(cmd, cwd=str(HERE)).returncode
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
    ap.add_argument("--host", default=None, help="listen interface (default 0.0.0.0: reachable from other computers; 127.0.0.1: this one only)")
    ap.add_argument("--port", type=int, default=None,
                    help="port (default 8000; change it to run several apps at once)")
    ap.add_argument("--no-update", action="store_true",
                    help="skip the startup update check (offline / CI)")
    ap.add_argument("--update", action="store_true",
                    help="update without asking (if there is a newer version), then start")
    ap.add_argument("--wait-port", metavar="HOST:PORT", default=None,
                    help="first wait until nothing listens there (the app's Update button)")
    args = ap.parse_args()
    if args.wait_port:
        print(f"[run] waiting for the running DocuTraceX to stop ({args.wait_port})...")
        if not _wait_port(args.wait_port):
            print("[run] it is still listening; trying anyway")
    if args.host:
        # gmzpt
        os.environ["DOCUTRACEX_HOST"] = args.host
    if args.port:
        os.environ["DOCUTRACEX_PORT"] = str(args.port)

    if args.update:
        _auto_update(ask=False)
    elif not args.no_update:
        _auto_update()

    # Import after the (possible) update so the newest code is loaded, and after
    # env is set so settings pick up the overrides.
    from docutracex.__main__ import main

    try:                                    # first start: say where the admin password is set
        from docutracex import users
        if users.needs_setup():
            print("\n[run] First start: open the app in a browser and set the password of the "
                  "'admin' user.\n      Forgot it later? python -m docutracex.users reset-admin\n")
    except Exception:  # noqa: BLE001
        pass

    main()
