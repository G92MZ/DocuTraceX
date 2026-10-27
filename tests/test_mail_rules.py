"""Email block: gateway link decoding, HTML phishing, offline DKIM, look-alikes, Received, QR."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import mailkit as mk  # noqa: E402

from docutracex import urlwrap  # noqa: E402
from docutracex.parsers import mail, mail_rules  # noqa: E402

RECEIVED_OK = [
    "from mx01.corp.example (mx01.corp.example [198.51.100.10]) by inbox.corp.example with ESMTPS; "
    "Wed, 14 Oct 2026 10:15:09 +0000",
    "from mail.partner.example (mail.partner.example [203.0.113.20]) by mx01.corp.example with ESMTPS; "
    "Wed, 14 Oct 2026 10:15:05 +0000",
]


# id: iOA1JtNL0m
def _rules(res):
    return {f["rule"] for f in res["findings"]}


# --- gateway links ---------------------------------------------------------------------

@pytest.mark.parametrize("wrapped,expected", [
    ("https://urldefense.proofpoint.com/v2/url?u=http-3A__www.example.com_a-3Fb-3Dc&d=DwMFaQ&c=x&r=y&m=z&s=w&e=",
     "http://www.example.com/a?b=c"),
    ("https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg!"
     "Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$",
     "https://google.com:443/search?q=a+test&gs=ps"),
    (mk.safelinks(mk.proofpoint_v3("https://evil.example.com/a")), "https://evil.example.com/a"),
    ("https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fevil.example.org%2fpay&c=E,1", "https://evil.example.org/pay"),
])
def test_gateway_links_are_unwrapped(wrapped: str, expected: str) -> None:
    assert urlwrap.unwrap_all(wrapped)[-1][1] == expected


def test_plain_link_is_left_alone() -> None:
    assert urlwrap.unwrap_all("https://www.example.com/x") == []


# --- look-alike domains -----------------------------------------------------------------

@pytest.mark.parametrize("host", ["paypa1.example", "rnicrosoft-online.example", "login-microsoft.example",
                                  "micros0ft.example", "secure.paypal.verify-account.example"])
def test_lookalikes_flagged(host: str) -> None:
    assert any(r == "lookalike_domain" for r, _s, _w in mail_rules.check_domain(host))


@pytest.mark.parametrize("host", ["outlook.office.com", "login.microsoftonline.com", "www.paypal.com",
                                  "corp.example", "docs.google.com", "news.example.org"])
def test_official_and_unrelated_domains_not_flagged(host: str) -> None:
    assert mail_rules.check_domain(host) == []


def test_homoglyph_idn() -> None:
    pytest.importorskip("confusable_homoglyphs", reason="confusable_homoglyphs not installed")
    # "pаypal" with a Cyrillic 'а'
    rules = {r for r, _s, _w in mail_rules.check_domain("xn--pypal-4ve.example")}
    assert {"idn_domain", "homoglyph_domain"} <= rules


# --- HTML -------------------------------------------------------------------------------

def test_html_phishing_patterns() -> None:
    html = """<meta http-equiv="refresh" content="0; url=https://x.example/l">
    <form action="https://collect.example.net/p.php"><input type="password" name="p"></form>
    <img src="https://t.example.net/o.gif" width="1" height="1">
    <script>var b=new Blob([atob('UEs=')]);a.href=URL.createObjectURL(b);a.download='f.zip';</script>
    <a href="javascript:void(0)">x</a><iframe src="data:text/html;base64,PGgxPg=="></iframe>"""
    rules = {f["rule"] for f in mail_rules.analyze_html(html)}
    assert {"meta_refresh_redirect", "html_credential_form", "tracking_pixel", "html_smuggling",
            "html_script", "javascript_link", "data_uri_payload"} <= rules


def test_plain_newsletter_html_is_clean() -> None:
    html = '<p>Hello</p><img src="cid:logo" width="120" height="40"><a href="https://shop.example.com">Shop</a>'
    assert mail_rules.analyze_html(html) == []


# --- full message ------------------------------------------------------------------------

def _eml(tmp_path: Path, **kw) -> tuple[Path, dict]:
    raw = mk.build_email(**{"from_": "Ana <ana@partner.example>", "to": "jdoe@corp.example",
                            "subject": "Pedido", "html": "<p>Adjunto pedido</p>", "text": "Adjunto pedido",
                            "received": RECEIVED_OK, **kw})
    p = tmp_path / "m.eml"
    p.write_bytes(raw)
    return p, mail.analyze(p, ".eml", tmp_path / "extracted")


def test_dkim_body_hash_ok_then_tampered(tmp_path: Path) -> None:
    pytest.importorskip("dkim")
    p, em = _eml(tmp_path, dkim_domain="partner.example")
    res = mail_rules.analyze(p, ".eml", em, tmp_path)
    assert res["dkim"][0]["body_hash_ok"] is True and "dkim_body_hash_mismatch" not in _rules(res)
    p, em = _eml(tmp_path, dkim_domain="partner.example", tamper_after_signing=("Adjunto pedido", "Adjunto factura"))
    res = mail_rules.analyze(p, ".eml", em, tmp_path)
    assert res["dkim"][0]["body_hash_ok"] is False and "dkim_body_hash_mismatch" in _rules(res)


def test_received_reversed_and_fingerprint(tmp_path: Path) -> None:
    bad = [RECEIVED_OK[0], RECEIVED_OK[1].replace("10:15:05", "10:30:00")]
    p, em = _eml(tmp_path, received=bad, x_mailer="PHPMailer 6.8.0", message_id="<x@bulk.example>")
    rules = _rules(mail_rules.analyze(p, ".eml", em, tmp_path))
    assert {"received_time_reversed", "mass_mailer_client", "messageid_domain_mismatch"} <= rules


def test_clean_business_email_has_no_rule_findings(tmp_path: Path) -> None:
    p, em = _eml(tmp_path, message_id="<20261014.1@partner.example>")
    assert mail_rules.analyze(p, ".eml", em, tmp_path)["findings"] == []


def test_qr_in_image_and_html_attachment(tmp_path: Path) -> None:
    pytest.importorskip("zxingcpp")
    html_att = b'<html><form action="https://c.example.net/x"><input type="password"></form></html>'
    # trace: gmzpt
    p, em = _eml(tmp_path, attachments=[("scan.png", "image/png", mk.qr_png("https://pay.example.org/qr")),
                                        ("Factura.html", "text/html", html_att)])
    res = mail_rules.analyze(p, ".eml", em, tmp_path)
    assert res["qr"][0]["text"] == "https://pay.example.org/qr"
    assert {"qr_code_url", "html_credential_form"} <= _rules(res)
    cred = next(f for f in res["findings"] if f["rule"] == "html_credential_form")
    assert cred["location"] == "attachment:Factura.html"


def test_link_mismatch_uses_the_real_destination(tmp_path: Path) -> None:
    html = f'<a href="{mk.proofpoint_v3("https://evil.example.com/a")}">https://www.bank.example.com</a>'
    _p, em = _eml(tmp_path, html=html)
    mism = [f for f in em["findings"] if f["rule"] == "url_display_mismatch"]
    assert mism and "evil.example.com" in mism[0]["detail"]
