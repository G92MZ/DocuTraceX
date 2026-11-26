"""PowerShell as .NET runs it: the details hand-written ciphers rely on (JS → PowerShell chains of 2025)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _ms  # noqa: E402

from docutracex.resolve import ps_eval  # noqa: E402


def _out(code: str) -> str:
    s = ps_eval.resolve(code)
    assert not s.errors, s.errors
    return str(s.stages[-1].data)


def test_integer_semantics() -> None:
    assert _out('iex ("w "+(-7 % 3)+" "+(7 % -3)+" "+(1 -shl 31)+" "+(1 -shl 32)+" "+([long]1 -shl 40))') == \
        "w -1 1 -2147483648 1 1099511627776"


def test_new_arrays_hold_zeros_and_increments_write_nothing() -> None:
    assert _out('function c { $a=[int[]]::new(3); $a[1]++; ++$a[2]; return ,$a }; $r = c; '
                'iex ("w "+$r.Length+" "+($r -join ","))') == "w 3 0,1,1"


def test_blockcopy_and_chunked_gzip() -> None:
    assert _out('$a=[byte[]](1,2,3,4);$b=[byte[]]::new(4);[System.Buffer]::BlockCopy($a,1,$b,0,3);'
                'iex ("w "+($b -join ","))') == "w 2,3,4,0"


def test_script_block_from_text_gets_its_arguments_and_as_type() -> None:
    code = ("$rc=$executioncontext.InvokeCommand.NewScriptBlock('param($x) if(''NoSuchType'' -as [type]){''t''}"
            "else{''w'' + $x}'); iex (& $rc 5)")
    assert _out(code) == "w5"


def test_vault_loader_sample_yields_the_client() -> None:
    s = ps_eval.resolve(_ms().ps_vault_loader_ps1().decode())
    (pe,) = [x for x in s.stages if "Assembly.Load" in x.sink]
    assert bytes(pe.data) == _ms().xworm_named_exe() + bytes(6000)
