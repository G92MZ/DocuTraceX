"""C# loaders compiled by PowerShell (``Add-Type``) that decrypt the payload they are handed.

A PowerShell stage compiles a small C# class and calls ``[Class]::Run([byte[]]$enc)``; the class splits
``salt | IV | ciphertext`` out of the bytes, derives the AES key from a password with PBKDF2
(``Rfc2898DeriveBytes``) and ``Assembly.Load``\\ s the result (XWorm / AsyncRAT batch chains of 2025). The
password, iteration count, hash and layout are read from the C# source; the decryption is done here.
"""

from __future__ import annotations

import hashlib
import re

_CHARS = re.compile(r"new\s+string\s*\(\s*new\s+char\s*\[\s*\]\s*\{([^}]{1,4000})\}", re.S)
_STR = re.compile(r'string\s+(\w+)\s*=\s*"((?:[^"\\]|\\.){1,200})"')
_KDF = re.compile(r"new\s+Rfc2898DeriveBytes\s*\(\s*([^,]{1,200}?)\s*,\s*(\w+)\s*(?:,\s*(\d+)\s*)?"
                  r"(?:,\s*HashAlgorithmName\.(\w+)\s*)?\)")
_COPY = re.compile(r"Array\.Copy\s*\(\s*\w+\s*,\s*(\d+)\s*,\s*(\w+)\s*,\s*0\s*,\s*(\d+|\w+\.Length)\s*\)")
_KEYLEN = re.compile(r"\.GetBytes\s*\(\s*(16|24|32)\s*\)")


def _char_text(body: str) -> str:
    return "".join(chr(int(x, 0)) for x in re.findall(r"\(char\)\s*(0x[0-9a-fA-F]+|\d+)", body))


def _password(src: str, expr: str) -> str | None:
    expr = expr.strip()
    if expr.startswith('"') and expr.endswith('"'):
        return bytes(expr[1:-1], "utf-8").decode("unicode_escape")
    m = _CHARS.search(expr)
    if m:
        return _char_text(m.group(1))
    name = re.escape(expr)
    m = re.search(rf"string\s+(?:\w+\s*=[^;]*,\s*)?{name}\s*=\s*new\s+string\s*\(\s*new\s+char\s*\[\s*\]\s*\{{([^}}]{{1,4000}})\}}", src)
    if m:
        return _char_text(m.group(1))
    for n, v in _STR.findall(src):
        if n == expr:
            return bytes(v, "utf-8").decode("unicode_escape")
    return None


def recipe(src: str) -> dict | None:
    """What the C# source does to the bytes it is handed, or None when it is not this kind of loader."""
    if "Rfc2898DeriveBytes" not in src or not re.search(r"\b(?:Aes|Rijndael|AesManaged|AesCryptoServiceProvider)\b", src):
        return None
    m = _KDF.search(src)
    if not m:
        return None
    pw = _password(src, m.group(1))
    if pw is None:
        return None
    salt_var = m.group(2)
    copies = {dst: (int(off), ln) for off, dst, ln in _COPY.findall(src)}
    salt_at = copies.get(salt_var, (0, "16"))
    iv_at = next(((o, ln) for d, (o, ln) in copies.items() if d.lower() == "iv"), None)
    ct_at = next((o for d, (o, ln) in copies.items() if d.lower() in ("ct", "cipher", "data", "enc", "body")), None)
    kl = [int(x) for x in _KEYLEN.findall(src)]
    return {"password": pw, "iterations": int(m.group(3) or 1000), "hash": (m.group(4) or "SHA1").lower(),
            "salt": (salt_at[0], int(salt_at[1]) if str(salt_at[1]).isdigit() else 16),
            "iv": (iv_at[0], 16) if iv_at else None, "ct": ct_at,
            "key_len": kl[0] if kl else 32,
            "mode": "ecb" if re.search(r"CipherMode\.ECB", src) else "cbc"}


def decrypt(src: str, data: bytes) -> tuple[bytes, str] | None:
    """(plaintext, how) or None."""
    r = recipe(src)
    if not r or len(data) < 48:
        return None
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    so, sl = r["salt"]
    salt = data[so:so + sl]
    if r["iv"]:
        io = r["iv"][0]
        iv = data[io:io + 16]
        body = data[r["ct"] if r["ct"] is not None else max(so + sl, io + 16):]
        key = hashlib.pbkdf2_hmac(r["hash"], r["password"].encode("utf-8"), salt, r["iterations"], r["key_len"])
    else:
        kb = hashlib.pbkdf2_hmac(r["hash"], r["password"].encode("utf-8"), salt, r["iterations"], r["key_len"] + 16)
        key, iv = kb[:r["key_len"]], kb[r["key_len"]:]
        body = data[r["ct"] if r["ct"] is not None else so + sl:]
    if not body or len(body) % 16:
        return None
    try:
        mode = modes.ECB() if r["mode"] == "ecb" else modes.CBC(iv)
        d = Cipher(algorithms.AES(key), mode).decryptor()
        pt = d.update(body) + d.finalize()
    except ValueError:
        return None
    pad = pt[-1] if pt else 0
    if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    how = (f"AES-{r['key_len'] * 8}-{r['mode'].upper()}, key PBKDF2-{r['hash'].upper()} ({r['iterations']} rounds) "
           "of the password in the C# source, salt / IV from the bytes")
    return pt[:-pad], how
