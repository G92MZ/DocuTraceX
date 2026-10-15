"""Tests for the common IOC extractor."""

from __future__ import annotations

from docutracex import ioc


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
    srcs = ioc.sources_from_modules(modules)
    texts = " ".join(s["text"] for s in srcs)
    assert "evil.example" in texts and "feed.example" in texts
    assert "word/document.xml" not in texts  # internal rels not included


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
