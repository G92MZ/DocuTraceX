"""Static cryptography analysis (Go phase 8, also used for native binaries).

* Algorithms, from three kinds of evidence: well-known constants in the
  file (AES S-boxes / T-tables, SHA-1/2 and MD5 constants, ChaCha/Salsa
  sigma, Blowfish, Curve25519 prime, CRC32, custom Base64 alphabets), the Go
  crypto packages that have code in pclntab, and the crypto APIs imported.
* Crypto functions: program functions that call crypto code or point at a
  crypto constant, with their role (encrypt / decrypt / hash / KDF / key
  exchange) and the material they reference.
* Key material: byte slices of key / nonce / IV size handed to crypto code.
* Static decryption: AES-GCM, ChaCha20-Poly1305 (authenticated: certain),
  AES-CBC / CTR and RC4 (plausibility checks) and single-byte XOR loops are
  tried on the data those functions reference. Nothing of the sample runs:
  the algorithms are re-implemented by ``cryptography`` on extracted bytes.

Every item carries a status: ``recovered`` (read directly from the file),
``reconstructed`` (computed statically), ``inferred`` (from evidence) or
``not recoverable``.
"""

from __future__ import annotations

import math
import re
import string
import struct
from typing import Any

MAX_TRIES = 4000
MAX_PLAIN = 64 * 1024


def _dw(*v: int, be: bool = False) -> bytes:
    return struct.pack((">" if be else "<") + "I" * len(v), *v)


_AES_SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
_AES_INV = bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb")
CONSTANTS: list[tuple[str, str, bytes]] = [
    ("AES", "AES S-box", _AES_SBOX),
    ("AES", "AES inverse S-box", _AES_INV),
    ("AES", "AES T-table (Te0)", _dw(0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D)),
    ("AES", "AES T-table (Te0, big-endian)", _dw(0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D, be=True)),
    ("SHA-256", "SHA-256 round constants", _dw(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)),
    ("SHA-256", "SHA-256 round constants (big-endian)", _dw(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, be=True)),
    ("SHA-256", "SHA-256 initial hash", _dw(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)),
    ("SHA-512", "SHA-512 round constants", struct.pack("<QQ", 0x428A2F98D728AE22, 0x7137449123EF65CD)),
    ("SHA-1", "SHA-1 initial hash", _dw(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)),
    ("MD5", "MD5 sine table", _dw(0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE)),
    ("ChaCha20 / Salsa20", "ChaCha / Salsa sigma (\"expand 32-byte k\")", b"expand 32-byte k"),
    ("ChaCha20 / Salsa20", "ChaCha / Salsa tau (\"expand 16-byte k\")", b"expand 16-byte k"),
    ("Blowfish", "Blowfish P-array", _dw(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344)),
    ("Curve25519 / Ed25519", "field prime 2^255-19", b"\xed" + b"\xff" * 30 + b"\x7f"),
    ("CRC32", "CRC32 table", _dw(0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)),
    ("RSA", "RSA-2048 public key (PKCS#1 DER)", b"\x30\x82\x01\x0a\x02\x82\x01\x01\x00"),
    ("RSA", "RSA-4096 public key (PKCS#1 DER)", b"\x30\x82\x02\x0a\x02\x82\x02\x01\x00"),
]

GO_PACKAGES: list[tuple[str, str]] = [
    ("crypto/aes.", "AES"), ("crypto/cipher.", "block-cipher modes"), ("crypto/rc4.", "RC4"),
    ("crypto/des.", "DES / 3DES"), ("crypto/rsa.", "RSA"), ("crypto/ecdsa.", "ECDSA"), ("crypto/ed25519.", "Ed25519"),
    ("crypto/ecdh.", "ECDH / X25519"), ("golang.org/x/crypto/curve25519", "X25519"),
    ("golang.org/x/crypto/chacha20poly1305", "ChaCha20-Poly1305"), ("golang.org/x/crypto/chacha20.", "ChaCha20"),
    ("golang.org/x/crypto/salsa20", "Salsa20"), ("golang.org/x/crypto/nacl/", "NaCl box / secretbox"),
    ("golang.org/x/crypto/blowfish", "Blowfish"), ("golang.org/x/crypto/twofish", "Twofish"),
    ("crypto/sha1.", "SHA-1"), ("crypto/sha256.", "SHA-256"), ("crypto/sha512.", "SHA-512"), ("crypto/md5.", "MD5"),
    ("crypto/hmac.", "HMAC"), ("golang.org/x/crypto/pbkdf2", "PBKDF2"), ("golang.org/x/crypto/scrypt", "scrypt"),
    ("golang.org/x/crypto/argon2", "Argon2"), ("golang.org/x/crypto/hkdf", "HKDF"), ("crypto/tls.", "TLS"),
]
APIS: list[tuple[str, str]] = [
    ("bcryptencrypt", "CNG encrypt"), ("bcryptdecrypt", "CNG decrypt"), ("bcryptgeneratesymmetrickey", "CNG key"),
    ("bcryptderivekey", "CNG KDF"), ("cryptencrypt", "CryptoAPI encrypt"), ("cryptdecrypt", "CryptoAPI decrypt"),
    ("cryptimportkey", "CryptoAPI key import"), ("cryptderivekey", "CryptoAPI KDF"), ("crypthashdata", "CryptoAPI hash"),
    ("cryptacquirecontext", "CryptoAPI"), ("cryptprotectdata", "DPAPI protect"), ("cryptunprotectdata", "DPAPI unprotect"),
    ("evp_encryptinit", "OpenSSL encrypt"), ("evp_decryptinit", "OpenSSL decrypt"), ("evp_cipherinit", "OpenSSL cipher"),
    ("aes_set_encrypt_key", "OpenSSL AES"), ("aes_set_decrypt_key", "OpenSSL AES"), ("rsa_public_encrypt", "OpenSSL RSA"),
    ("systemfunction032", "RC4 (SystemFunction032)"), ("systemfunction033", "RC4 (SystemFunction033)"),
]
_ROLE = [("decrypt", re.compile(r"decrypt|\.open$|\.open\b|unseal|unprotect|newcbcdecrypter|cryptdecrypt", re.IGNORECASE)),
         ("encrypt", re.compile(r"encrypt|\.seal\b|seal$|protectdata|newcbcencrypter", re.IGNORECASE)),
         ("key exchange", re.compile(r"x25519|curve25519|ecdh|sharedkey|scalarmult|precompute", re.IGNORECASE)),
         ("KDF", re.compile(r"pbkdf2|scrypt|argon2|hkdf|derivekey", re.IGNORECASE)),
         ("hash", re.compile(r"sha1|sha256|sha512|md5|hmac|hashdata", re.IGNORECASE)),
         ("stream", re.compile(r"xorkeystream|rc4|chacha20\.|salsa20|newctr|systemfunction03", re.IGNORECASE))]
_B64 = re.compile(rb"[A-Za-z0-9+/\-_.!~*]{64}")
_STD64 = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
_PRINT = set(string.printable.encode())
_STD_ALPHABETS = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                  b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
                  b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")   # crypt(3) / bcrypt-style


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    return -sum(n / len(b) * math.log2(n / len(b)) for n in c if n)


def _printable(b: bytes) -> float:
    return sum(1 for x in b if x in _PRINT) / len(b) if b else 0.0


def scan_constants(data: bytes, binf) -> list[dict[str, Any]]:
    out = []
    for algo, name, pat in CONSTANTS:
        start = 0
        while True:
            i = data.find(pat, start)
            if i < 0:
                break
            out.append({"algorithm": algo, "constant": name, "offset": i, "va": binf.off_to_va(i), "size": len(pat),
                        "status": "recovered"})
            start = i + 1
            if sum(1 for x in out if x["constant"] == name) >= 8:
                break
    for m in _B64.finditer(data):
        alpha = m.group(0)
        if len(set(alpha)) == 64 and len(set(alpha) & _STD64) >= 60 and alpha not in _STD_ALPHABETS:
            out.append({"algorithm": "Base64 (custom alphabet)", "constant": alpha.decode(), "offset": m.start(),
                            "va": binf.off_to_va(m.start()), "size": 64, "status": "recovered"})
    return out


def _read(reader, va: int, n: int | None) -> bytes:
    if n:
        return reader.at(va, n)
    raw = reader.at(va, 256)
    i = raw.find(b"\x00")
    return raw[:i] if i >= 0 else raw


def _role(names: list[str]) -> list[str]:
    roles = []
    for r, rx in _ROLE:
        if any(rx.search(n) for n in names):
            roles.append(r)
    return roles


def _try_decrypt(alg: str, key: bytes, nonce: bytes | None, ct: bytes) -> tuple[bytes, str] | None:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    except ImportError:
        return None
    try:
        if alg == "AES-GCM" and nonce is not None and len(key) in (16, 24, 32) and len(ct) > 16:
            return AESGCM(key).decrypt(nonce, ct, None), "AES-GCM (authenticated)"
        if alg == "ChaCha20-Poly1305" and nonce is not None and len(key) == 32 and len(ct) > 16:
            return ChaCha20Poly1305(key).decrypt(nonce, ct, None), "ChaCha20-Poly1305 (authenticated)"
        if alg == "AES-CBC" and nonce is not None and len(nonce) == 16 and len(ct) % 16 == 0 and ct:
            d = Cipher(algorithms.AES(key), modes.CBC(nonce)).decryptor()
            pt = d.update(ct) + d.finalize()
            pad = pt[-1]
            if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad) and _printable(pt[:-pad]) >= 0.9:
                return pt[:-pad], "AES-CBC (PKCS#7 padding and text check)"
        if alg == "AES-CTR" and nonce is not None and len(nonce) == 16 and len(ct) >= 8:
            d = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
            pt = d.update(ct) + d.finalize()
            if _printable(pt) >= 0.95:
                return pt, "AES-CTR (text check)"
        if alg == "RC4" and 5 <= len(key) <= 256 and len(ct) >= 8:
            pt = _rc4(key, ct)
            if _printable(pt) >= 0.95:
                return pt, "RC4 (text check)"
    except Exception:  # noqa: BLE001  (wrong key / nonce / tag: not this combination)
        return None
    return None


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def analyze(full: dict[str, Any], data: bytes, binf, reader, names: list[dict[str, Any]] | None,
            mode: str) -> dict[str, Any]:
    fns = full.get("functions") or []
    by_addr = {f["addr"]: f for f in fns}
    consts = scan_constants(data, binf)
    algos: dict[str, dict[str, Any]] = {}

    def add(algo: str, kind: str, detail: str) -> None:
        a = algos.setdefault(algo, {"algorithm": algo, "evidence": [], "status": "recovered"})
        if len(a["evidence"]) < 12 and (kind, detail) not in [(e["kind"], e["detail"]) for e in a["evidence"]]:
            a["evidence"].append({"kind": kind, "detail": detail})
    for c in consts:
        add(c["algorithm"], "constant", f"{c['constant']} @0x{c['offset']:x}")
    for n in names or []:
        for pre, algo in GO_PACKAGES:
            if n["name"].startswith(pre):
                add(algo, "go package", pre.rstrip("."))
                break
    for api in full.get("apis") or []:
        low = (api.get("name") or "").lower()
        for k, label in APIS:
            if low.startswith(k):
                add(label, "import", f"{api.get('lib') or ''} {api['name']}".strip())
    # program functions using crypto
    const_ranges = [(c["va"], c["va"] + c["size"], c) for c in consts if c.get("va")]
    cfuncs = []
    for f in fns:
        if not f.get("user", True) and mode == "go":
            continue
        cn = f.get("callee_names") or []
        hits = []
        for n in cn:
            low = n.lower()
            for pre, algo in GO_PACKAGES:
                if n.startswith(pre):
                    hits.append(algo)
            for k, label in APIS:
                if k in low:
                    hits.append(label)
        for a, _n in f.get("data_refs") or []:
            for lo, hi, c in const_ranges:
                if lo <= a < hi:
                    hits.append(c["algorithm"])
        if hits:
            cfuncs.append({"addr": f["addr"], "name": f["name"], "algorithms": sorted(set(hits)),
                           "roles": _role(cn) or ["uses crypto"],
                           "calls": [n for n in cn if any(n.startswith(p) for p, _ in GO_PACKAGES)
                                     or any(k in n.lower() for k, _ in APIS)][:20]})
    # key material and static decryption
    keys, plains, notes = [], [], []
    tries = 0
    seen_plain: set[bytes] = set()

    def refs_of(f: dict[str, Any]) -> list[list[int | None]]:
        out = list(f.get("data_refs") or [])
        for c in f.get("callers") or []:
            out += (by_addr.get(c) or {}).get("data_refs") or []
        return out
    for cf in cfuncs:
        f = by_addr[cf["addr"]]
        material = []
        for a, n in refs_of(f):
            if n in (8, 12, 16, 24, 32):
                b = reader.at(a, n)
                if len(b) == n and _entropy(b) >= 2.5:
                    label = {8: "nonce / IV (8 bytes)", 12: "nonce (12 bytes: GCM / ChaCha20)",
                             16: "AES-128 key or IV", 24: "AES-192 key", 32: "256-bit key (AES-256 / ChaCha20)"}[n]
                    material.append((a, n, b, label))
        for a, n, b, label in material:
            keys.append({"function": cf["name"], "va": a, "size": n, "hex": b.hex(), "label": label,
                         "entropy": round(_entropy(b), 2), "printable": _printable(b) == 1.0, "status": "inferred"})
        blobs = [(a, n) for a, n in refs_of(f) if n and n > 16 and n <= MAX_PLAIN]
        kk = [m for m in material if m[1] in (16, 24, 32)]
        nn = [m for m in material if m[1] in (12, 16)]
        algs = set(cf["algorithms"])
        cands = []
        if algs & {"AES", "block-cipher modes"}:
            cands += ["AES-GCM", "AES-CBC", "AES-CTR"]
        if algs & {"ChaCha20-Poly1305", "ChaCha20", "ChaCha20 / Salsa20"}:
            cands.append("ChaCha20-Poly1305")
        if algs & {"RC4", "RC4 (SystemFunction032)", "RC4 (SystemFunction033)"}:
            cands.append("RC4")
        done = False
        for alg in cands:
            for ka, kn, kb, _l in (material if alg == "RC4" else kk):
                for ba, bn in blobs:
                    ct = reader.at(ba, bn)
                    for na, _nn, nb, _l2 in ([(None, 0, None, "")] if alg == "RC4" else nn):
                        if na == ka or ba in (ka, na):
                            continue
                        tries += 1
                        if tries > MAX_TRIES:
                            break
                        r = _try_decrypt(alg, kb, nb, ct)
                        if r is None and nb is not None and alg in ("AES-GCM", "ChaCha20-Poly1305") and len(ct) > 28:
                            r = _try_decrypt(alg, kb, ct[:12], ct[12:])          # nonce prepended to the data
                        if r and r[0] not in seen_plain:
                            seen_plain.add(r[0])
                            plains.append({"function": cf["name"], "method": r[1], "key_va": ka, "nonce_va": na,
                                           "data_va": ba, "data_size": bn, "plaintext": r[0][:MAX_PLAIN],
                                           "status": "reconstructed"})
                            done = True
        if not done and "decrypt" in cf["roles"]:
            why = ("no key-sized data referenced" if not kk else "no ciphertext referenced next to the key"
                   if not blobs else "no tried combination decrypted (mode / key derivation not static?)")
            notes.append({"function": cf["name"], "status": "not recoverable", "detail": why})
    # XOR decoding loops (single-byte key): data referenced by the loop or by its callers
    for f in fns:
        if not (f.get("loops") and f.get("xor_keys")):
            continue
        for k in [x for x in f["xor_keys"] if x < 256][:4]:
            for a, n in refs_of(f)[:32]:
                b = _read(reader, a, n)
                if len(b) < 8:
                    continue
                tries += 1
                pt = bytes(x ^ k for x in b)
                if _printable(pt) >= 0.95 and _printable(b) < 0.8 and pt not in seen_plain:
                    seen_plain.add(pt)
                    plains.append({"function": f["name"], "method": f"XOR with 0x{k:02x} (decoding loop)",
                                   "key_va": None, "nonce_va": None, "data_va": a, "data_size": len(b),
                                   "plaintext": pt, "status": "reconstructed"})
    for p in plains:
        add(p["method"].split(" ")[0], "decrypted", f"{p['function']}: {len(p['plaintext'])} bytes")
    return {"algorithms": sorted(algos.values(), key=lambda a: a["algorithm"]), "constants": consts[:200],
            "functions": cfuncs[:300], "keys": keys[:200], "plaintexts": plains[:100], "not_recoverable": notes[:100],
            "tries": tries}


def jsonable(res: dict[str, Any]) -> dict[str, Any]:
    out = dict(res)
    out["plaintexts"] = []
    for p in res.get("plaintexts") or []:
        q = dict(p)
        raw: bytes = q.pop("plaintext")
        q["size"] = len(raw)
        q["text"] = raw.decode("utf-8", "replace") if _printable(raw) >= 0.9 else ""
        q["hex"] = raw[:4096].hex()
        out["plaintexts"].append(q)
    return out
