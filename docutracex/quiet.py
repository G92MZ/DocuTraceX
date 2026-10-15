"""Silence harmless third-party noise in tool output.

- XLMMacroDeobfuscator prints "pywin32 is not installed (only is required if
  you want to use MS Excel)" when imported (oletools.olevba imports it). pywin32
  is only needed to drive a real Microsoft Excel through COM, which opens the
  document in Excel — something a static analyzer must never do. The static
  wrappers used here (xls_wrapper_2, xlsb, xlsm) need nothing else, so the
  message is pure noise. ``process_file()`` resets SILENT from its own
  arguments on every call, so this hides only that import-time banner.
- Recent pyparsing versions emit deprecation warnings for the API oletools uses.
"""

from __future__ import annotations

import warnings

# Deprecation notices from libraries (e.g. pyparsing via oletools) are not results.
WARNINGS_FILTER = "ignore::DeprecationWarning"


def silence() -> None:
    """Call before importing oletools.olevba / XLMMacroDeobfuscator."""
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", message=r".*deprecated - use .*")
    try:
        from XLMMacroDeobfuscator.configs import settings as _xlm_settings
        _xlm_settings.SILENT = True
    except Exception:  # noqa: BLE001  (not installed: nothing to silence)
        pass


# Run an oletools CLI module with the same silencing, e.g.
#   python -c CLI_WRAPPER oletools.olevba --decode file
CLI_WRAPPER = (
    "import sys, runpy; from docutracex.quiet import silence; silence(); "
    "mod = sys.argv.pop(1); runpy.run_module(mod, run_name='__main__', alter_sys=True)"
)
