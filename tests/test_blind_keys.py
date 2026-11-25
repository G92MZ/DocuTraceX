"""Improve languages, T16: blind trials on literals no evaluator reached.

A blob the script decrypts with code that is not in it (a module it imports, a native helper) is
tried with the script's own key material and what loaders derive from it — RC4, AES and 3DES, keys
as written or as their MD5 / SHA-1 / SHA-256, IVs zero / in front / from the script — and kept when
it turns into a file, text or compressed data. Base64 written backwards is read the other way.
Noise stays an opaque blob, quickly.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex import decrypted  # noqa: E402
from docutracex.resolve.transforms import rc4  # noqa: E402

PE = (b"MZ" + b"\x90" * 58 + (0x80).to_bytes(4, "little") + b"\x00" * 64
      + b"This program cannot be run in DOS mode. Inert DocuTraceX stub. " * 6)


def _pad(b: bytes, n: int = 16) -> bytes:
    k = n - len(b) % n
    return b + bytes([k]) * k


def _children(code: str) -> list[dict]:
    mods = {"powershell": {"scripts": [{"location": "x.ps1", "code": code, "_full_code": code}]}}
    return decrypted.payloads_from(mods)


def _aes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(_pad(data))


def test_aes_with_a_hashed_password() -> None:
    ct = _aes_cbc(hashlib.sha256(b"Factura#2026").digest(), b"\x00" * 16, PE)
    got = _children(f"$p = 'Factura#2026'\n$blob = '{base64.b64encode(ct).decode()}'\n")
    assert got[0]["ext"] == ".exe" and got[0]["data"] == PE
    assert got[0]["recipe"][1] == "aes-256-cbc(key sha256('Factura#2026'), iv zero)"


def test_3des_md5_and_rc4() -> None:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    ct = Cipher(TripleDES(hashlib.md5(b"clave0187").digest()), modes.ECB()).encryptor().update(_pad(PE, 8))  # noqa: S324
    got = _children(f"$p = 'clave0187'\n$blob = '{base64.b64encode(ct).decode()}'\n")
    assert got[0]["data"] == PE and got[0]["recipe"][1] == "3des-ecb(key md5('clave0187'))"
    got = _children(f"$p = 'Factura0187'\n$blob = '{base64.b64encode(rc4(PE, b'Factura0187')).decode()}'\n")
    assert got[0]["data"] == PE and got[0]["recipe"][1] == "rc4(key 'Factura0187')"


def test_compressed_plaintext_and_reversed_base64() -> None:
    k, iv = bytes(range(1, 33)), bytes(range(16))
    ct = _aes_cbc(k, iv, gzip.compress(PE))
    got = _children(f"$k = @({','.join(map(str, k))})\n$v = @({','.join(map(str, iv))})\n"
                    f"$blob = '{base64.b64encode(ct).decode()}'\n")
    assert got[0]["data"] == PE and got[0]["recipe"][-2:] == ["gzip", "exe"]
    got = _children(f"$blob = '{base64.b64encode(PE).decode()[::-1]}'\n")
    assert got[0]["data"] == PE and got[0]["recipe"][0] == "reversed base64"


def test_noise_stays_opaque_and_fast() -> None:
    noise = base64.b64encode(bytes((i * 37 + 11) & 0xFF for i in range(6000))).decode()
    code = " ".join(f"$s{i}='password number {i}'" for i in range(60)) + "".join(
        f"\n$b{i} = '{noise[i:] + noise[:i]}'" for i in range(5))
    t = time.monotonic()
    got = _children(code)
    assert time.monotonic() - t < 15
    assert all(p.get("recipe", [""])[-1] == "opaque" for p in got)


def test_blind_keys_sample_end_to_end(client) -> None:  # noqa: ANN001,F811
    _cid, res = _analyze(client, "sample_blind_keys.ps1", _ms().blind_keys_ps1())
    tree = json.loads((res / "nested.json").read_text())["tree"]
    recipes = [" → ".join(n.get("recipe") or []) for n in tree if n.get("format") == "PE"]
    assert any("aes-256-cbc(key sha256('Factura#2026-0187'), iv zero)" in r for r in recipes), recipes
    assert any("3des-ecb(key md5('clave-0187'))" in r for r in recipes), recipes
    assert any("rc4(key 'Proveedor0187')" in r for r in recipes), recipes
