"""Inno Setup parts and children no analyzer claims: none is left unread."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import make_samples as ms  # noqa: E402

from docutracex import analyze, cases, ioc  # noqa: E402
from docutracex.config import settings  # noqa: E402
from docutracex.storage import CasePaths, read_json  # noqa: E402


def _walk(nodes):  # noqa: ANN001, ANN202
    for n in nodes or []:
        yield n
        yield from _walk(n.get("children"))


def test_every_child_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.inno_parts_zip()), "setup_parts.zip", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    p = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    nodes = {n["filename"]: n for n in _walk((read_json(p.subresult("nested")) or {}).get("tree"))}
    code = nodes["CompiledCode.bin"]
    assert code["kind"] == "ifps"
    rules = {f["rule"] for f in code["findings"]}
    assert {"ifps_download", "ifps_execute", "ifps_download_execute", "ifps_dll_imports"} <= rules
    assert nodes["settings.dat"]["read_as"] == "strings" and nodes["settings.dat"]["strings_count"] >= 2
    assert nodes["en.isl"]["read_as"] == "text"
    assert nodes["logo.png"]["read_as"] == "image" and nodes["logo.png"]["image"] == {
        "format": "PNG", "width": 2, "height": 2}
    vals = {(i["type"], i["value"]) for i in (read_json(p.subresult("iocs")) or {})["iocs"]}
    assert ("url", "https://cdn-update.example.net/offers/config.json") in vals          # from the [Code]
    assert ("url", "https://telemetry.invoice-sync.example/v1/ping") in vals             # from the binary blob
    assert ("ipv4", "203.0.113.47") in vals
    assert not any(v.endswith("urlmon.dll") for _, v in vals)                            # a call, not an IOC


def test_ioc_noise_from_installers() -> None:
    text = "CN=SOFTONIC-LIKE SA, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=ES"
    got = ioc.extract([{"module": "msi", "location": "items[0]/lief/authenticode/signer/subject", "text": text}])
    assert not any(i["type"] == "ipv4" for i in got["iocs"]), got["iocs"]
    chatter = "consider filing a bug report at https://innoextract.constexpr.org/issues"
    mod = {"items": [{"unpack": {"attempts": [{"tool_output": chatter, "tried": [{"tool_output": chatter}]}]}}]}
    got = ioc.extract(ioc.sources_from_modules({"msi": mod}))
    assert got["iocs"] == []


def test_overlay_head_is_not_a_hash() -> None:
    from docutracex.parsers import lief_info
    assert lief_info._spaced("7a6c621a89504e470d0a1a0a0000000d").startswith("7a 6c 62 1a 89 50")


def test_installer_stub_traits_are_info() -> None:
    from docutracex.parsers import pe
    f = [{"rule": r, "severity": "medium", "detail": r} for r in
         ("pe_entrypoint_section", "pe_tls_callback", "lief_overlay_encrypted", "pe_dynamic_resolve")]
    pe._installer_context(f, {"family": "inno"}, {"sections": [{"name": ".text"}, {"name": ".itext"}]})
    by = {x["rule"]: x for x in f}
    assert by["pe_entrypoint_section"]["severity"] == "info" and "Delphi" in by["pe_entrypoint_section"]["detail"]
    assert by["lief_overlay_encrypted"]["severity"] == "info" and by["pe_dynamic_resolve"]["severity"] == "medium"
    f2 = [{"rule": "pe_entrypoint_section", "severity": "medium", "detail": "x"}]
    pe._installer_context(f2, {"family": "nsis"}, {"sections": [{"name": ".text"}]})
    assert f2[0]["severity"] == "medium"                   # not Delphi / not Inno: left as it was


def test_inno_script_note_says_what_is_there(tmp_path: Path) -> None:
    from docutracex.parsers import unpack
    (tmp_path / "embedded").mkdir()
    (tmp_path / "install_script.iss").write_text("[Setup]\nAppName=x\n\n[Files]\nSource: a\n\n[Languages]\n")
    (tmp_path / "embedded" / "CompiledCode.bin").write_bytes(b"IFPS")
    note = unpack._inno_script_note(tmp_path)
    assert note == " (install_script.iss recovered: [Files]; [Code] compiled (CompiledCode.bin, Pascal Script))"
    assert "[Run]" not in note


def test_own_hash_is_not_an_ioc(tmp_path: Path) -> None:
    import hashlib
    data = b"OutputBaseFilename=<its own hash>\n"
    m = cases.create_case(io.BytesIO(data), "x.txt", cases_dir=tmp_path)
    p = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    own = hashlib.sha256(data).hexdigest()
    res = {"iocs": [{"type": "hash_like", "value": own, "occurrences": []},
                    {"type": "hash_like", "value": "ab" * 32, "occurrences": []}]}
    analyze._drop_own_hashes(p, res)
    assert [i["value"] for i in res["iocs"]] == ["ab" * 32] and res["counts"]["total"] == 1
