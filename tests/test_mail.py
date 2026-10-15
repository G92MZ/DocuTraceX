"""Tests for the email parser (.eml / .emlx / .msg) and header analysis."""

from __future__ import annotations

import sys
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

import pytest

from docutracex.parsers import mail

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


def _spoofy_eml() -> bytes:
    msg = EmailMessage()
    msg["Received"] = ("from mx.corp.example (mx.corp.example [198.51.100.2]) "
                       "by inbox.corp.example with ESMTP id def; Wed, 14 Oct 2026 20:00:05 +0000")
    msg["Received"] = ("from evil.example (unknown [203.0.113.9]) "
                       "by mx.corp.example with ESMTP id abc; Wed, 14 Oct 2026 20:00:00 +0000")
    msg["From"] = '"IT Support <support@corp.example>" <attacker@evil.example>'
    msg["To"] = "bob@corp.example"
    msg["Return-Path"] = "<bounce@evil.example>"
    msg["Reply-To"] = "billing@evil.example"
    msg["Subject"] = "Invoice"
    msg["Date"] = formatdate(localtime=False)
    msg["Authentication-Results"] = "mx.corp.example; spf=fail; dkim=none; dmarc=fail"
    msg.set_content("Body http://evil.example/pay\n")
    msg.add_attachment(b"MZ payload", maintype="application", subtype="octet-stream",
                       filename="invoice.pdf.exe")
    return msg.as_bytes()


def test_eml_received_chain_ordered_origin_first(tmp_path: Path) -> None:
    p = tmp_path / "m.eml"
    p.write_bytes(_spoofy_eml())
    r = mail.analyze(p, ".eml", tmp_path / "extracted")
    assert r["hop_count"] == 2
    hops = r["received_chain"]
    # Origin (last Received header) comes first.
    assert hops[0]["from"] == "evil.example"
    assert hops[0]["ip"] == "203.0.113.9"
    # Δt between hops is computed on the later hop.
    assert hops[1]["delta_seconds"] == 5


def test_eml_auth_and_spoof_findings(tmp_path: Path) -> None:
    p = tmp_path / "m.eml"
    p.write_bytes(_spoofy_eml())
    r = mail.analyze(p, ".eml", tmp_path / "extracted")
    rules = {f["rule"] for f in r["findings"]}
    assert "spf_fail" in rules
    assert "dmarc_fail" in rules
    assert "display_name_spoof" in rules
    assert "dangerous_attachment" in rules
    assert "double_extension" in rules
    assert r["authentication"]["spf"] == "fail"


def test_from_returnpath_mismatch(tmp_path: Path) -> None:
    msg = EmailMessage()
    msg["From"] = "ceo@corp.example"
    msg["Return-Path"] = "<reply@attacker.test>"
    msg["Subject"] = "hi"
    msg.set_content("x\n")
    p = tmp_path / "m.eml"
    p.write_bytes(msg.as_bytes())
    r = mail.analyze(p, ".eml", tmp_path / "extracted")
    assert "from_returnpath_mismatch" in {f["rule"] for f in r["findings"]}


def test_eml_attachment_extracted_and_hashed(tmp_path: Path) -> None:
    p = tmp_path / "m.eml"
    p.write_bytes(_spoofy_eml())
    extracted = tmp_path / "extracted"
    r = mail.analyze(p, ".eml", extracted)
    assert r["attachment_count"] == 1
    att = r["attachments"][0]
    assert att["filename"] == "invoice.pdf.exe"
    assert att["sha256"] and att["size_bytes"] > 0
    assert (extracted.parent / att["stored_path"]).is_file()


def test_emlx_prefix_stripped(tmp_path: Path) -> None:
    body = _spoofy_eml()
    emlx = f"{len(body)}\n".encode() + body + b"<plist></plist>\n"
    p = tmp_path / "m.emlx"
    p.write_bytes(emlx)
    r = mail.analyze(p, ".emlx", tmp_path / "extracted")
    assert r["status"] in ("ok", "ok_with_findings")
    assert r["addresses"]["from"] == "attacker@evil.example"


def test_msg_mapi_over_ole(tmp_path: Path) -> None:
    from mkmsg import write_msg

    headers = ("Received: from evil.example (unknown [203.0.113.9]) by mx.corp.example "
               "with ESMTP id abc; Wed, 14 Oct 2026 20:00:00 +0000\n"
               'From: "IT <support@corp.example>" <attacker@evil.example>\n'
               "Return-Path: <bounce@evil.example>\n"
               "Subject: Invoice\n"
               "Authentication-Results: mx; spf=fail; dmarc=fail\n")
    p = tmp_path / "m.msg"
    write_msg(p, headers, "Invoice", "body http://evil.example/x", "attacker@evil.example",
              [("invoice.pdf.exe", b"MZ payload")])
    r = mail.analyze(p, ".msg", tmp_path / "extracted")
    assert r["status"] in ("ok", "ok_with_findings")
    assert r["hop_count"] == 1
    assert r["addresses"]["from"] == "attacker@evil.example"
    assert r["attachment_count"] == 1
    rules = {f["rule"] for f in r["findings"]}
    assert "spf_fail" in rules and "dangerous_attachment" in rules


def test_msg_rejects_non_ole(tmp_path: Path) -> None:
    p = tmp_path / "x.msg"
    p.write_bytes(b"not an OLE file")
    r = mail.analyze(p, ".msg", tmp_path / "extracted")
    assert r["status"] == "error"
    assert any(f["rule"] == "not_ole" for f in r["findings"])


# --- enriched samples --------------------------------------------------------

has_samples = pytest.mark.skipif(
    not (SAMPLES / "sample.eml").exists(),
    reason="samples not generated (run scripts/make_samples.py)",
)


@has_samples
@pytest.mark.parametrize("name,ext", [("sample.eml", ".eml"), ("sample.emlx", ".emlx"),
                                      ("sample.msg", ".msg")])
def test_sample_emails_have_findings(tmp_path: Path, name: str, ext: str) -> None:
    r = mail.analyze(SAMPLES / name, ext, tmp_path / "extracted")
    assert r["hop_count"] == 2
    rules = {f["rule"] for f in r["findings"]}
    assert "spf_fail" in rules and "dangerous_attachment" in rules


@has_samples
@pytest.mark.parametrize("name", ["sample.eml", "sample.msg"])
def test_recursive_attachment_scan(tmp_path: Path, name: str) -> None:
    """The .docm attachment is scanned recursively; msodde's DDE finding reaches
    the consolidated view and the case state is 'completed'."""
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json

    with (SAMPLES / name).open("rb") as fh:
        manifest = cases.create_case(fh, name, cases_dir=tmp_path)
    cid = manifest["analysis_id"]
    summary = analyze.analyze_case(tmp_path / cid)
    assert summary["state"] == "completed"  # no more "partial"
    assert "nested" in summary["modules_run"]

    paths = CasePaths(cid, cases_dir=tmp_path)
    nested = read_json(paths.subresult("nested"))
    docm = next(n for n in nested["tree"] if "report.docm" in n["filename"])
    assert docm["kind"] == "ooxml"
    assert any(f["tool"] == "msodde" and f["rule"] == "dde_link" for f in docm["findings"])

    # The nested third-party finding is in the consolidated findings.
    consolidated = read_json(paths.subresult("findings"))["findings"]
    assert any(f["source"] == "msodde" for f in consolidated)


def test_html_only_body_interpreted_as_text(tmp_path: Path) -> None:
    msg = EmailMessage()
    msg["From"] = "a@x.example"
    msg["To"] = "b@y.example"
    msg["Subject"] = "html"
    msg.set_content(
        "<html><head><style>p{color:red}</style><script>alert(1)</script></head>"
        "<body><p>Hola&nbsp;mundo</p><a href='https://evil.example/login'>Pulse aqu&iacute;</a>"
        "</body></html>", subtype="html")
    p = tmp_path / "h.eml"
    p.write_bytes(bytes(msg))
    res = mail.analyze(p, ".eml")
    assert res["body_sample"] == ""
    text = res["html_text_sample"]
    assert "Hola mundo" in text and "Pulse aquí <https://evil.example/login>" in text
    assert "alert" not in text and "color" not in text
    assert res["html_links"] == ["https://evil.example/login"]
    assert "<script>" in res["html_source_sample"]
