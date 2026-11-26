"""Improve languages, T20: no script makes an evaluator hang or run out of memory.

Every language gets the same bombs: an endless loop, endless recursion, a string that doubles in a
loop, a huge repeat / array, and (where the language decompresses) a gzip that inflates past the
output limit. Each must end quickly, with the analysis still standing.
"""

from __future__ import annotations

import base64
import time
import zlib

import pytest

from docutracex.resolve import (au3_eval, bat_eval, dyn_eval, js_eval, ps_eval, py_eval, sh_eval, tcl_eval,
                                transforms, vbs_eval)


def _gz_bomb() -> str:
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    chunk = b"\x00" * (1 << 20)
    out = bytearray()
    for _ in range(transforms.MAX_OUT // len(chunk) * 3):          # 3 × the limit
        out += co.compress(chunk)
    out += co.flush()
    return base64.b64encode(bytes(out)).decode()


GZ = _gz_bomb()

FN = {"powershell": ps_eval.resolve, "python": py_eval.resolve, "javascript": js_eval.resolve,
      "vbscript": vbs_eval.resolve, "batch": bat_eval.resolve, "php": dyn_eval.resolver("PHP"),
      "perl": dyn_eval.resolver("Perl"), "ruby": dyn_eval.resolver("Ruby"), "lua": dyn_eval.resolver("Lua"),
      "shell": sh_eval.resolve, "tcl": tcl_eval.resolve, "autoit": au3_eval.resolve}

BOMBS = [
    ("powershell", "gzip", "$b=[Convert]::FromBase64String('%s'); $m=New-Object IO.MemoryStream(,$b); "
                           "$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress); "
                           "$r=New-Object IO.StreamReader($g); iex $r.ReadToEnd()" % GZ),
    ("powershell", "loop", "while ($true) { $x = 1 }"),
    ("powershell", "recursion", "function f { f }; f"),
    ("powershell", "doubling", "$s='ab'; for ($i=0; $i -lt 100; $i++) { $s = $s + $s }; iex $s"),
    ("powershell", "array", "$a = New-Object byte[] 2000000000; $a[5] = 1"),
    ("python", "gzip", "import base64, zlib\nexec(zlib.decompress(base64.b64decode('%s'), 31))" % GZ),
    ("python", "loop", "while True:\n    x = 1"),
    ("python", "recursion", "def f():\n    return f()\nf()"),
    ("python", "doubling", "s = 'ab'\nfor i in range(100):\n    s = s + s\nexec(s)"),
    ("python", "array", "a = bytearray(2000000000)\nb = 'x' * 2000000000"),
    ("javascript", "gzip", "var z=require('zlib'); eval(z.gunzipSync(Buffer.from('%s','base64')).toString())" % GZ),
    ("javascript", "loop", "while(true){ var x = 1; }"),
    ("javascript", "recursion", "function f(){ return f(); } f();"),
    ("javascript", "doubling", "var s='ab'; for (var i=0;i<100;i++){ s = s + s; } eval(s);"),
    ("javascript", "array", "var a = new Array(2000000000); var b = new Uint8Array(2000000000); 'x'.repeat(2000000000)"),
    ("vbscript", "loop", "Do\n x = 1\nLoop"),
    ("vbscript", "recursion", "Function F()\n F = F()\nEnd Function\nF()"),
    ("vbscript", "doubling", "s = \"ab\"\nFor i = 1 To 100\n s = s & s\nNext\nExecute s"),
    ("vbscript", "array", "Dim a(2000000000)\nReDim b(2000000000)\nc = Space(2000000000)"),
    ("batch", "loop", ":a\nset x=1\ngoto a"),
    ("batch", "recursion", ":f\ncall :f\n"),
    ("batch", "doubling", "set s=ab\nfor /l %%i in (1,1,100) do call set s=%%s%%%%s%%\necho %s%"),
    ("batch", "bigloop", "for /l %%i in (1,1,2000000000) do set x=%%i"),
    ("php", "gzip", "<?php eval(gzdecode(base64_decode('%s')));" % GZ),
    ("php", "loop", "<?php while(true){ $x = 1; }"),
    ("php", "recursion", "<?php function f(){ return f(); } f();"),
    ("php", "doubling", "<?php $s='ab'; for($i=0;$i<100;$i++){ $s = $s . $s; } eval($s);"),
    ("php", "repeat", "<?php $s = str_repeat('a', 2000000000); eval($s);"),
    ("perl", "loop", "while (1) { my $x = 1; }"),
    ("perl", "recursion", "sub f { return f(); } f();"),
    ("perl", "doubling", "my $s='ab'; for (my $i=0;$i<100;$i++) { $s = $s . $s; } eval $s;"),
    ("perl", "repeat", "my $s = 'a' x 2000000000; eval $s;"),
    ("ruby", "loop", "while true\n x = 1\nend"),
    ("ruby", "recursion", "def f\n f\nend\nf"),
    ("ruby", "doubling", "s = 'ab'\n100.times { s = s + s }\neval(s)"),
    ("lua", "loop", "while true do local x = 1 end"),
    ("lua", "recursion", "local function f() return f() end\nf()"),
    ("lua", "doubling", "local s = 'ab'\nfor i = 1, 100 do s = s .. s end\nload(s)()"),
    ("lua", "repeat", "load(string.rep('a', 2000000000))()"),
    ("shell", "gzip", "echo '%s' | base64 -d | gunzip | sh" % GZ),
    ("shell", "loop", "while true; do x=1; done"),
    ("shell", "recursion", "f() { f; }\nf"),
    ("shell", "forloop", "for ((i=0;i<2000000000;i++)); do x=1; done"),
    ("tcl", "loop", "while {1} { set x 1 }"),
    ("tcl", "recursion", "proc f {} { f }\nf"),
    ("tcl", "doubling", "set s ab\nfor {set i 0} {$i < 100} {incr i} { set s $s$s }\neval $s"),
    ("tcl", "repeat", "eval [string repeat a 2000000000]"),
    ("autoit", "loop", "While 1\n $x = 1\nWEnd"),
    ("autoit", "recursion", "Func F()\n Return F()\nEndFunc\nExecute(F())"),
    ("autoit", "doubling", "$s = \"ab\"\nFor $i = 1 To 100\n $s &= $s\nNext\nExecute($s)"),
]


@pytest.mark.parametrize(("lang", "kind", "code"), BOMBS, ids=[f"{lang}-{kind}" for lang, kind, _ in BOMBS])
def test_bomb_ends(lang: str, kind: str, code: str) -> None:
    t = time.monotonic()
    s = FN[lang](code, "")
    took = time.monotonic() - t
    assert took < 45, f"{lang} {kind}: {took:.1f}s"
    # nothing absurd reached Nested: no stage larger than the output limit
    assert all(len(st.data) <= transforms.MAX_OUT for st in s.stages)


def test_limits_are_shared() -> None:
    """Every evaluator stops at its own step and time budgets (no global hang)."""
    for mod in (py_eval, js_eval, dyn_eval):
        assert mod.MAX_STEPS <= 10_000_000 and mod.MAX_SECONDS <= 90
    # PowerShell / VBScript ciphers written byte by byte need tens of millions of steps; the time cap still bounds it
    for mod in (ps_eval, vbs_eval):
        assert mod.MAX_STEPS <= 60_000_000 and mod.MAX_SECONDS <= 90
    for mod in (bat_eval, sh_eval, tcl_eval):
        assert mod.MAX_STEPS <= 1_000_000 and mod.MAX_SECONDS <= 30
