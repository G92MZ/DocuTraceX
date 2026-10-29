"""Plain-language explanation of the ML top features, with the place in the file."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _ms  # noqa: E402

pytestmark = pytest.mark.skipif(not all(importlib.util.find_spec(m) for m in ("pefile", "mmh3", "signify")),
                                reason="EMBER extractor deps not installed")


def _explain(data: bytes, feats: list[tuple[str, str, float, list]]) -> list[dict]:
    from docutracex.ml import explain
    top = [{"block": b, "feature": f, "value": v, "contribution": 0.5, "matches": m} for b, f, v, m in feats]
    explain.explain_top(top, data, {})
    return top


def test_header_and_directories_in_words_with_offsets() -> None:
    data = _ms().ml_samples()["ml/sample_win32_downloader.exe"]
    t = _explain(data, [("header", "characteristic DLL", 0.0, []),
                        ("header", "COFF timestamp", float(0x2A425E19), []),
                        ("header", "subsystem", 3.0, []),
                        ("header", "header checksum", 0.0, []),
                        ("data directories", "DEBUG size", 0.0, []),
                        ("header", "DLL characteristic NX_COMPAT", 1.0, [])])
    assert [x["plain"] for x in t] == ["not a DLL", "compiled (COFF timestamp) 1992-06-19 22:22 UTC",
                                       "subsystem: Windows console", "header checksum is zero (not set)",
                                       "no debug directory (PDB / build info)", "DEP (NX compatible): enabled"]
    lf = int.from_bytes(data[60:64], "little")
    ts = t[1]["at"]
    assert ts["offset"] == lf + 8 and data[ts["offset"]:ts["offset"] + 4] == (0x2A425E19).to_bytes(4, "little")
    assert t[2]["at"]["offset"] == lf + 24 + 68            # PE32 optional header subsystem


def test_strings_imports_and_sections_point_at_the_bytes() -> None:
    data = _ms().ml_samples()["ml/sample_dotnet_stealer.exe"]
    t = _explain(data, [("strings", "strings matching 'base64'", 1.0, []),
                        ("strings", "strings matching 'btc_wallet'", 0.0, []),
                        ("imports", "imported function #360", -1.0, ["mscoree.dll:_CorExeMain"]),
                        ("sections", "section entropy #7", -0.12, [".text"])])
    b64, none, imp, sec = t
    assert b64["plain"] == "1 string(s) contain base64 text" and b64["evidence"] == ["FromBase64String"]
    assert data[b64["at"]["offset"]:b64["at"]["offset"] + b64["at"]["length"]] == b"FromBase64String"
    assert none["plain"].startswith("no string contains") and "at" not in none
    assert imp["plain"] == "imports mscoree.dll:_CorExeMain"            # hashed sign ignored
    assert data[imp["at"]["offset"]:imp["at"]["offset"] + 11] == b"_CorExeMain"
    assert sec["plain"] == "entropy of section '.text': 0.12 of 8" and sec["at"]["label"] == "section .text"


def test_non_pe_and_unknown_features_never_break() -> None:
    data = _ms().ml_samples()["ml/sample_elf_backdoor"]
    t = _explain(data, [("strings", "strings matching '/bin/'", 1.0, []),
                        ("byte histogram", "byte 0xff frequency", 0.0028, []),
                        ("header", "subsystem", 2.0, []),                     # not a PE: no offset
                        ("weird", "something new", 1.0, [])])
    assert t[0]["evidence"] == ["/bin/sh"] and data[t[0]["at"]["offset"]:t[0]["at"]["offset"] + 7] == b"/bin/sh"
    assert t[1]["plain"] == "byte 0xff makes up 0.28% of the file"
    assert "at" not in t[2] and t[3]["plain"] == "something new"


@pytest.mark.skipif(not (Path(__file__).parents[1] / "tools" / "ember" / "EMBER2024_Dot_Net.model").is_file(),
                    reason="EMBER models not provisioned")
def test_classify_returns_explained_features(tmp_path: Path) -> None:
    from docutracex.ml import ember_ml
    p = tmp_path / "s.exe"
    p.write_bytes(_ms().ml_samples()["ml/sample_dotnet_stealer.exe"])
    it = ember_ml.classify([p])[0]
    assert it["status"] == "ok" and all(t.get("plain") for t in it["top_features"])
    assert any(t.get("at") for t in it["top_features"])
