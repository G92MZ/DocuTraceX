#!/usr/bin/env python3
"""One-shot installer for DocuTraceX.

Run this once. It does the whole setup:

  1. Installs the WEB SERVICE on *this* Python (just fastapi/uvicorn/jinja2/
     multipart — nothing heavy, so your machine's Python is never a constraint).
  2. Provisions a PORTABLE Python under tools/ and installs the full analysis
     toolchain into it (oletools, YARA, STPyV8, Playwright, pikepdf, ViperMonkey
     via PyPy 2.7, the Didier Stevens scripts, OfficeMalScanner, the IP database
     and Chromium for screenshots). None of that touches your Python.

After it finishes, every day you just run:

    python run.py

Usage:
    python install.py                 # full install (web + portable toolchain)
    python install.py --web-only      # only the web service (no portable tools)
    python install.py --force         # reinstall the portable from scratch
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REQ = HERE / "requirements.txt"


def _step(n: int, total: int, msg: str) -> None:
    print(f"\n[{n}/{total}] {msg}")


def install_web() -> None:
    """Install the web-service dependencies on the launching interpreter."""
    args = [sys.executable, "-m", "pip", "install", "-r", str(REQ)] if REQ.is_file() \
        else [sys.executable, "-m", "pip", "install", "fastapi", "uvicorn[standard]",
              "jinja2", "python-multipart"]
    subprocess.run(args, check=True)


def provision_tools(force: bool) -> bool:
    """Provision the portable Python + the analysis toolchain under tools/."""
    sys.path.insert(0, str(HERE / "scripts"))
    try:
        import setup_portable_python as spp  # type: ignore
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not load the portable provisioner: {exc}")
        return False
    try:
        spp.provision(force=force)
        return True
    except SystemExit as exc:  # provisioner stops with a reason
        print(f"[!] Provisioning stopped: {exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Provisioning failed: {exc}")
    print("    You can re-run `python install.py` later, or the app also heals "
          "the portable on start.")
    return False


def main() -> int:
    ap = argparse.ArgumentParser(prog="install.py",
                                 description="Install DocuTraceX (web service + portable toolchain).")
    ap.add_argument("--web-only", action="store_true",
                    help="install only the web service; skip the portable toolchain")
    ap.add_argument("--force", action="store_true",
                    help="reinstall the portable Python from scratch")
    args = ap.parse_args()

    total = 1 if args.web_only else 2
    print("DocuTraceX installer")
    print("====================")

    _step(1, total, "Installing the web service on this Python "
                    f"({sys.version.split()[0]} · {sys.executable})")
    try:
        install_web()
    except subprocess.CalledProcessError as exc:
        print(f"[!] Web install failed (pip exit {exc.returncode}).")
        return 1

    ok = True
    if not args.web_only:
        _step(2, total, "Provisioning the portable Python + analysis toolchain under tools/ "
                        "(this downloads a fair bit on first run)")
        ok = provision_tools(args.force)

    print("\n" + "=" * 52)
    if args.web_only:
        print("Web service installed. Provision the tools later with:\n"
              "    python install.py")
    elif ok:
        print("Done. DocuTraceX is installed. Start it with:\n\n    python run.py\n")
    else:
        print("Web service installed, but the portable toolchain is incomplete.\n"
              "Re-run `python install.py` when you have connectivity — or just\n"
              "`python run.py`, which keeps trying to heal the portable on start.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
