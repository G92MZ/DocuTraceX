# -*- coding: utf-8 -*-
"""Runs ViperMonkey (``vipermonkey.vmonkey``) with its hard-coded ``/tmp/...`` paths
redirected to the real temporary folder.

ViperMonkey writes Excel / Word copies to ``/tmp/tmp_excel_file_N`` and
``/tmp/tmp_word_file_N`` before trying LibreOffice. On Windows ``/tmp`` is
``<drive>:\\tmp``, which does not exist, so the emulation aborted with
``[Errno 2] No such file or directory: '/tmp/tmp_excel_file_…'``. Every file
function ViperMonkey uses gets those paths mapped to ``DTX_VM_TMP`` (the analysis'
own temp folder) instead. Nothing else changes.

Runs on PyPy 2.7: Python 2 and 3 compatible. DocuTraceX copies it into the
analysis' work folder and runs it from there, so no DocuTraceX module can shadow
one of ViperMonkey's imports.
"""
import os
import runpy
import shutil
import sys
import tempfile

try:
    import builtins
except ImportError:  # Python 2
    import __builtin__ as builtins  # noqa: N813

import io

TMP = os.environ.get("DTX_VM_TMP") or tempfile.gettempdir()
FORCE = os.environ.get("DTX_VM_TMP_FORCE") == "1"   # tests: redirect on any OS
# only ViperMonkey's own names: /tmp/tmp_excel_file_N, /tmp/tmp_word_file_N, /tmp/tmp_file_N, /tmp/sheet_…
_OURS = ("tmp_excel_file_", "tmp_word_file_", "tmp_file_", "sheet_")
if not os.path.isdir(TMP):
    os.makedirs(TMP)                                   # before anything is patched


def fix(p):
    try:
        s = p if isinstance(p, str) else (p.decode("utf-8") if isinstance(p, bytes) else p)
    except Exception:  # noqa: BLE001
        return p
    if not isinstance(s, str) and not (sys.version_info[0] == 2 and isinstance(s, unicode)):  # noqa: F821
        return p
    if s == TMP or s.startswith(TMP.rstrip("/\\") + os.sep):
        return p                                       # already there (TMP itself may live under /tmp)
    if (os.name == "nt" or FORCE) and (s.startswith("/tmp/") or s.startswith("\\tmp\\")) \
            and s[5:].startswith(_OURS):
        return os.path.join(TMP, s[5:].replace("/", os.sep).replace("\\", os.sep))
    return p


def wrap(fn, *positions):
    def inner(*args, **kw):
        args = list(args)
        for i in positions:
            if i < len(args):
                args[i] = fix(args[i])
        return fn(*args, **kw)
    inner.__name__ = getattr(fn, "__name__", "wrapped")
    return inner


builtins.open = wrap(builtins.open, 0)
io.open = wrap(io.open, 0)
for name in ("remove", "unlink", "mkdir", "makedirs", "listdir", "rmdir", "stat", "chdir"):
    if hasattr(os, name):
        setattr(os, name, wrap(getattr(os, name), 0))
for name in ("exists", "isfile", "isdir", "getsize"):
    setattr(os.path, name, wrap(getattr(os.path, name), 0))
for name in ("rmtree", "copyfile", "copy", "move"):
    setattr(shutil, name, wrap(getattr(shutil, name), 0, 1))
if __name__ == "__main__":
    sys.argv = ["vmonkey"] + sys.argv[1:]
    runpy.run_module("vipermonkey.vmonkey", run_name="__main__", alter_sys=True)
