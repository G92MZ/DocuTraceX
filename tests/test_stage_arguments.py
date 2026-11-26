"""A stage that reads the file its arguments name: when Nested analyses it on its own, the arguments
name the sample above it (only files of the case, never this machine's)."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _ms  # noqa: E402

from docutracex import decrypted  # noqa: E402
from docutracex.resolve import argv, js_eval  # noqa: E402

JS = ('var a = WScript.Arguments; var fso = new ActiveXObject("Scripting.FileSystemObject");'
      'var t = fso.OpenTextFile(a(0), 1).ReadAll(); eval(t.substring(t.indexOf("/*") + 2, t.indexOf("*/")));')


def test_arguments_name_the_parent() -> None:
    tok = argv.PARENTS.set((("factura.vbs", "' x\n/*WScript.Echo(1); var u = 'http://cdn-update.example.net/f';*/"),))
    try:
        s = js_eval.resolve(JS)
    finally:
        argv.PARENTS.reset(tok)
    assert any("cdn-update.example.net" in str(x.data) for x in s.stages)


def test_without_a_parent_the_arguments_stay_unknown() -> None:
    s = js_eval.resolve(JS)
    assert not any("cdn-update" in str(x.data) for x in s.stages)
    assert argv.text_of("C:\\Windows\\win.ini") is None


def test_base64_text_of_a_pe_is_written_as_the_pe() -> None:
    pe = _ms().xworm_named_exe()
    raw, ext = decrypted._b64_file(base64.b64encode(pe))
    assert raw == pe and ext == ".exe"
    assert decrypted._b64_file(base64.b64encode(b"just some text, not a file" * 4)) is None
