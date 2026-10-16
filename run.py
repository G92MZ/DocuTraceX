#!/usr/bin/env python3
"""Launch DocuTraceX.

Convenience launcher. The app runs on YOUR Python; the analysis tools run on the
portable Python under tools/. On startup the portable is ensured (provisioned on
first run, healed if tool dependencies are missing), then the app starts.

    python run.py                       # http://127.0.0.1:8000
    python run.py --port 8001           # another port (e.g. next to WinHound)
    python run.py --host 0.0.0.0 --port 9000

HOST / PORT environment variables work too (arguments take priority).
"""

from __future__ import annotations

import argparse
import os

if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="run.py", description="DocuTraceX web service")
    ap.add_argument("--host", default=None, help="listen interface (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=None,
                    help="port (default 8000; change it to run several apps at once)")
    args = ap.parse_args()
    if args.host:
        # gmzpt
        os.environ["DOCUTRACEX_HOST"] = args.host
    if args.port:
        os.environ["DOCUTRACEX_PORT"] = str(args.port)

    # Import after env is set so settings pick up the overrides.
    from docutracex.__main__ import main

    main()
