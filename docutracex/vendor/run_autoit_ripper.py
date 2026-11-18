"""Run the bundled AutoIt-Ripper on one file in its own process:
``python -I run_autoit_ripper.py IN OUT_DIR`` (the same as ``-m autoit_ripper.cli``)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))      # -I does not add the script's folder

from autoit_ripper.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.argv = ["autoit-ripper", *sys.argv[1:]]
    sys.exit(main())
