"""Entry point for ``python -m docutracex.netcheck <case_root> '<json params>'``
(how the task queue runs a network check on the portable interpreter)."""

import sys

from . import main

raise SystemExit(main(sys.argv[1:]))
