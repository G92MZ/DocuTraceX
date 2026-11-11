"""Go phase 8: layered payloads (decrypt → decompress), static key derivation
(PBKDF2 / scrypt / HKDF) and the call-graph route to every crypto function."""

from __future__ import annotations

import base64
import gzip
import hashlib
import zlib
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import codeanalysis as ca
from docutracex.codeanalysis import crypto

needs_rizin = pytest.mark.skipif(not ca.available(), reason="Rizin + rz-ghidra not provisioned")


def test_unwrap_layers() -> None:
    inner = b'{"c2": "https://relay.example/api"}'
    assert crypto.unwrap(gzip.compress(inner)) == (inner, ["gzip"])
    assert crypto.unwrap(base64.b64encode(zlib.compress(inner))) == (inner, ["Base64", "zlib"])
    assert crypto.unwrap(b"plain text, nothing to unwrap") == (b"plain text, nothing to unwrap", [])
    assert crypto._plausible_plain(gzip.compress(inner)) and not crypto._plausible_plain(b"\x00\x01" * 40)


def test_kdf_derivations() -> None:
    pw, salt = b"InvoiceSync-2026!", bytes(range(16))
    assert crypto._derive("PBKDF2", pw, salt, 4096, "sha256", 32) == hashlib.pbkdf2_hmac("sha256", pw, salt, 4096, 32)
    assert len(crypto._derive("HKDF", pw, salt, 0, "sha256", 32)) == 32
    assert crypto._derive("scrypt", pw, salt, 1024, "-", 16) == hashlib.scrypt(pw, salt=salt, n=1024, r=8, p=1, dklen=16)


@needs_rizin
def test_sample_kdf_layers_and_paths(tmp_path: Path) -> None:
    from docutracex.codeanalysis import case as cc
    from docutracex.golang import detect
    p = tmp_path / "agent.exe"
    p.write_bytes(ms.go_code_exe())
    d = p.read_bytes()
    sha = hashlib.sha256(d).hexdigest()
    (tmp_path / "case.json").write_text("{}")
    names = cc.go_names(d, detect.identify(d))
    assert cc.analyze_object(tmp_path, p, sha, "go", names)["status"] == "ok"
    item = {"label": "agent.exe", "stored_path": "", "original": True}
    cc.enrich(tmp_path, p, d, sha, "go", item, names=names)
    cr = cc.load(tmp_path, sha, "go")["crypto"]
    (k,) = cr["kdf"]
    assert k["function"] == "main.loadSecret" and k["status"] == "reconstructed"
    assert k["parameters"] == "PBKDF2-HMAC-SHA256, 4096 iterations, 32-byte key" and k["password"] == "InvoiceSync-2026!"
    pt = next(x for x in cr["plaintexts"] if x["function"] == "main.loadSecret")
    assert pt["method"] == "AES-GCM (authenticated) with a PBKDF2-derived key → gzip" and pt["layers"] == ["gzip"]
    assert "relay.invoice-sync.example" in pt["text"]
    assert any(x["label"].startswith("derived key (PBKDF2") for x in cr["keys"])
    paths = {x["function"]: x["path"] for x in cr["paths"]}
    assert paths["main.loadSecret"] == ["main.main", "main.main.func1", "main.loadSecret"]
    assert item["code"]["resources"]["derived_keys"] == 1
    assert any("relay.invoice-sync.example" in s["text"] for s in item["ioc_sources"])   # IOCs of the layered payload
