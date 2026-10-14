#!/usr/bin/env python3
"""Launch DocuTraceX.

Convenience launcher. The app runs on YOUR Python; the analysis tools run on the
portable Python under tools/. On startup the portable is ensured (provisioned on
first run, healed if tool dependencies are missing), then the app starts.

    python run.py          # same as: python -m docutracex
"""

from __future__ import annotations

from docutracex.__main__ import main

if __name__ == "__main__":
    main()
