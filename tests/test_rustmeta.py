"""Rust binaries: the compiler, the crates (and what they say the binary does), the build
machine's user and the project's paths, read from the source paths rustc leaves in — even
with the strings glued together, as Rust keeps them."""

from __future__ import annotations

import sys
from pathlib import Path

from docutracex import rustmeta

ROOT = Path(__file__).resolve().parent.parent
REG = "C:\\Users\\builder\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\"


def _glued(*parts: str) -> bytes:
    return b"".join(p.encode() for p in parts)


def test_reads_compiler_crates_user_and_project_from_glued_strings() -> None:
    data = b"MZ\x90\x00" + _glued(
        "/rustc/79e9716c980570bfd1f666e3b16ac583f0168962/library/std/src/panicking.rs",
        "https://facturas-cdn.example/gate.php",                      # a URL glued right before a path
        REG + "reqwest-0.11.27\\src\\async_impl\\client.rs",
        REG + "obfstr-0.4.3\\src\\lib.rs",
        REG + "aes-gcm-0.10.3\\src\\aes.rs",
        "Mozilla/5.0",
        "C:\\Users\\builder\\proyectos\\factura-loader\\src\\main.rs",
        "src\\modules\\exfil.rs",                                      # relative, glued after the previous .rs
        "/home/dev/.cargo/git/checkouts/screenshots-rs-1a2b3c4d5e6f7a8b/abc1234/src/lib.rs",
        ".rsrc", "called `Option::unwrap()` on a `None` value")
    r = rustmeta.analyze_bytes(data)
    assert r["rustc_commit"] == "79e9716c980570bfd1f666e3b16ac583f0168962"
    assert {c["name"]: c["versions"] for c in r["crates"]} == {"reqwest": ["0.11.27"], "obfstr": ["0.4.3"],
                                                                 "aes-gcm": ["0.10.3"]}
    assert r["roles"]["string obfuscation"] == ["obfstr"] and r["roles"]["encryption"] == ["aes-gcm"]
    assert r["git_dependencies"] == ["screenshots-rs@1a2b3c4d5e6f7a8b"]
    assert r["build_users"] == ["builder", "dev"]
    assert r["project_paths"] == ["C:\\Users\\builder\\proyectos\\factura-loader\\src\\main.rs", "src\\modules\\exfil.rs"]
    assert r["projects"] == ["factura-loader"]


def test_not_rust_is_none() -> None:
    assert rustmeta.analyze_bytes(b"MZ" + b"C:\\Users\\x\\proj\\src\\main.c\x00kernel32.dll") is None


def test_findings() -> None:
    def finding(rule, sev, title, loc, detail="", attack=""):  # noqa: ANN001, ANN202
        return {"rule": rule, "severity": sev, "title": title, "detail": detail}
    info = {"rustc_version": "1.74.0", "crates": [{"name": "reqwest"}, {"name": "obfstr"}, {"name": "aes-gcm"}],
            "roles": {"HTTP / network client": ["reqwest"], "string obfuscation": ["obfstr"], "encryption": ["aes-gcm"]},
            "build_users": ["builder"], "projects": ["factura-loader"]}
    got = {(f["rule"], f["severity"]): f for f in rustmeta.findings(info, "x.exe", finding)}
    assert ("pe_rust_binary", "info") in got and "rustc 1.74.0" in got[("pe_rust_binary", "info")]["title"]
    assert "string obfuscation" in got[("pe_rust_crates_capabilities", "medium")]["title"]
    assert ("pe_rust_crates_capabilities", "low") in got                  # HTTP + encryption
    assert "builder" in got[("pe_rust_build_user", "info")]["title"]


def test_pe_triage_on_the_sample() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import zipcrypto

    from docutracex.parsers import pe
    data = zipcrypto.read(ROOT / "samples" / "samples.zip", "windows-pe/sample_rust_strings.exe")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "sample_rust_strings.exe"
        p.write_bytes(data)
        res = pe.analyze(p, "sample_rust_strings.exe")
    item = res["items"][0] if "items" in res else res
    r = item["rust"]
    assert {c["name"] for c in r["crates"]} == {"reqwest", "obfstr", "aes-gcm", "sysinfo"}
    assert r["build_users"] == ["builder"] and r["projects"] == ["factura-loader"]
    rules = {f["rule"] for f in item["findings"]}
    assert {"pe_rust_binary", "pe_rust_crates_capabilities", "pe_rust_build_user"} <= rules
