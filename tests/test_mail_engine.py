"""Declarative email rules (docutracex/rules/email/*.yml) and the verdict."""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import mailkit as mk  # noqa: E402

from docutracex import mailengine, mailintel  # noqa: E402
from docutracex.parsers import mail, mail_rules  # noqa: E402

RCV = ["from mail.partner.example (mail.partner.example [203.0.113.20]) by mx01.corp.example with ESMTPS; "
       "Wed, 14 Oct 2026 10:15:05 +0000"]
AUTH_OK = "mx01.corp.example; spf=pass smtp.mailfrom=partner.example; dkim=none; dmarc=pass header.from=partner.example"


def _run(tmp_path: Path, name: str = "m.eml", **kw) -> dict:
    kw.setdefault("from_", "Partner <ops@partner.example>")
    kw.setdefault("to", "Ana <ana@corp.example>")
    kw.setdefault("subject", "Hola")
    kw.setdefault("text", "Hola.")
    kw.setdefault("html", "<p>Hola.</p>")
    kw.setdefault("received", RCV)
    kw.setdefault("auth_results", AUTH_OK)
    raw = mk.build_email(**kw)
    p = tmp_path / name
    p.write_bytes(raw)
    email = mail.analyze(p, ".eml", tmp_path / "extracted")
    return mail_rules.analyze(p, ".eml", email, tmp_path)


def _ids(res: dict) -> set[str]:
    return {m["id"] for m in res["engine"]["matched"]}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from docutracex import appsettings
    from docutracex.config import settings
    monkeypatch.setattr(settings, "tools_dir", tmp_path / "tools")
    monkeypatch.setattr(appsettings, "email_settings", lambda: {"own_domains": [], "brands": []})
    mailengine._load_rules.cache_clear()


def test_rules_load_and_conditions() -> None:
    rs = mailengine.rules()
    assert len(rs["rules"]) >= 30 and {"payment", "bank_change", "credential"} <= set(rs["lexicons"])
    f = {"a": {"b": 3, "c": ["x"]}, "text": {"all": "Factura pendiente: nuevo IBAN ES91 2100 0418 4502 0005 1332"}}
    ctx = {"lex": rs["_lex"]}
    assert mailengine.evaluate({"all": [{"fact": "a.b", "gte": 2}, {"fact": "a.c"}, {"text": "bank_change"}]}, f, ctx)
    assert not mailengine.evaluate({"not": {"fact": "a.c"}}, f, ctx)


def test_bec_from_free_webmail_with_new_iban(tmp_path: Path) -> None:
    res = _run(tmp_path, from_="Juan Pérez - Director Financiero <jperez.finanzas@accountant.com>",
               subject="URGENTE: factura pendiente", text="Le informamos del cambio de cuenta bancaria. "
               "Nuevo IBAN ES91 2100 0418 4502 0005 1332. Abone la factura hoy mismo, es confidencial.",
               html="<p>Escríbame a <a href='mailto:pagos.urgentes@usa.com'>pagos.urgentes@usa.com</a></p>")
    ids = _ids(res)
    assert {"sender_freemail", "freemail_business_request", "bec_bank_details_change", "bec_urgent_payment",
            "mailto_freemail_in_body", "executive_display_name_external"} <= ids
    assert res["engine"]["facts"]["body"]["ibans"] == ["ES9121000418450200051332"]
    assert res["verdict"]["verdict"] in ("phishing", "malicious") and res["verdict"]["score"] >= 70
    assert res["verdict"]["verdict"] == "phishing"            # no payload: not "malicious"


def test_reply_to_diversion_and_abused_tld(tmp_path: Path) -> None:
    res = _run(tmp_path, from_="Billing <billing@supplier.top>", reply_to="billing.dept@gmail.com",
               text="Please see the attached invoice.")
    assert {"reply_to_freemail_diversion", "sender_abused_tld"} <= _ids(res)


def test_callback_phishing(tmp_path: Path) -> None:
    res = _run(tmp_path, from_="Geek Squad <noreply@renewals-support.example>", subject="Your subscription renewal",
               text="Your Norton subscription was renewed and you have been charged $499.99. "
                    "To cancel this order call our support line at +1 (808) 555-0142 within 24 hours.",
               html="<p>Order #88721 confirmed.</p>")
    ids = _ids(res)
    assert "callback_phishing" in ids and res["engine"]["facts"]["body"]["phones"]


def test_hosting_abuse_fake_reply_and_redirect(tmp_path: Path) -> None:
    res = _run(tmp_path, subject="RE: documentos firmados",
               text="Le han compartido un documento. Ver documento: "
                    "https://corpexample-my.sharepoint.com/:b:/g/personal/x/EfakeID "
                    "https://www.example-news.example/r?url=https%3A%2F%2Flogin-portal.example%2F",
               html="<p>ver documento</p>")
    ids = _ids(res)
    assert {"link_legit_hosting_abuse", "fake_reply_thread", "link_open_redirect"} <= ids


def test_attachments_svg_ics_encrypted_zip_and_password(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("factura.txt", b"inert")
    data = bytearray(buf.getvalue())
    data[6] |= 0x1                                                  # "encrypted" flag on the local header
    i = data.find(b"PK\x01\x02")
    data[i + 8] |= 0x1                                              # …and on the central directory entry
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>window.location="https://x.example"</script></svg>'
    ics = b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDESCRIPTION:Join https://meet-login.example/j\r\nEND:VEVENT\r\nEND:VCALENDAR"
    res = _run(tmp_path, text="Adjunto la factura. Contraseña: Fct2026", attachments=[
        ("factura.zip", "application/zip", bytes(data)), ("logo.svg", "image/svg+xml", svg),
        ("reunion.ics", "text/calendar", ics)])
    ids = _ids(res)
    assert {"password_protected_attachment", "svg_active_content", "calendar_invite_links"} <= ids
    assert res["engine"]["facts"]["body"]["password_hint"] == "Fct2026"


def test_invisible_chars_and_image_only(tmp_path: Path) -> None:
    res = _run(tmp_path, subject="Factura\u200b pendiente", text="",
               html='<img src="cid:x" width="600"><a href="https://pay-portal.example/x">.</a>')
    assert {"invisible_characters", "image_only_lure"} <= _ids(res)


def test_own_domain_lookalike_and_spoof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import appsettings
    monkeypatch.setattr(appsettings, "email_settings", lambda: {"own_domains": ["corpexample.example"], "brands": []})
    res = _run(tmp_path, from_="IT <it@corpexarnple.example>", text="Verify your account")
    assert "own_domain_lookalike" in _ids(res)
    res = _run(tmp_path, name="s.eml", from_="CEO <ceo@corpexample.example>",
               auth_results="mx01.corp.example; spf=fail smtp.mailfrom=corpexample.example; dmarc=fail header.from=corpexample.example")
    assert "own_domain_spoofed" in _ids(res)


def test_reputation_feeds(tmp_path: Path) -> None:
    from docutracex.config import settings
    d = settings.tools_dir / "mailintel"
    d.mkdir(parents=True)
    (d / "phishing_domains.txt").write_text("evil-portal.example\n")
    (d / "urlhaus_hosts.txt").write_text("198.51.100.66\n")
    res = _run(tmp_path, text="Login: https://secure.evil-portal.example/a and http://198.51.100.66/x.exe")
    ids = _ids(res)
    assert {"link_bad_reputation", "link_direct_download", "link_ip_address"} <= ids
    assert res["verdict"]["verdict"] == "malicious"
    assert mailintel.bad_reputation("evil-portal.example") and not mailintel.bad_reputation("example.org")


def test_feed_parsing() -> None:
    assert mailintel.parse("freemail", '["gmail.com", "Accountant.com"]') == {"gmail.com", "accountant.com"}
    assert mailintel.parse("urlhaus_hosts", "# c\n127.0.0.1\tbad.example\n0.0.0.0 worse.example\nplain.example\n") \
        == {"bad.example", "worse.example", "plain.example"}
    assert mailintel.is_freemail("mail.com") and mailintel.is_freemail("accountant.com")
    assert not mailintel.is_freemail("corp.example")


def test_clean_mail_stays_clean(tmp_path: Path) -> None:
    res = _run(tmp_path, subject="Acta de la reunión", text="Adjunto el acta de ayer. Un saludo.")
    assert res["verdict"]["verdict"] == "clean" and not [f for f in res["findings"] if f.get("location") == "rules"]


def test_newsletter_from_esp_is_not_phishing(tmp_path: Path) -> None:
    res = _run(tmp_path, from_="Tienda <news@shop.example>", subject="Novedades de noviembre",
               text="Descubre las novedades.", return_path="bounce-123@em123.sendgrid.net",
               html='<p>Ofertas</p><a href="https://u123.ct.sendgrid.net/ls/click?upn=abc">shop.example</a>'
                    '<img src="https://u123.ct.sendgrid.net/wf/open?upn=x" width="1" height="1">',
               extra_headers=[("List-Unsubscribe", "<https://shop.example/unsub>"), ("X-SG-EID", "abc"),
                              ("List-Id", "news.shop.example")])
    email_rules = {f["rule"]: f["severity"] for f in res["findings"]}
    assert "url_display_mismatch" not in email_rules
    assert res["verdict"]["verdict"] == "clean"
    assert any(f["rule"] == "tracking_pixel" for f in res["findings"])       # still reported: useful to know


def test_case_stage_payload(tmp_path: Path) -> None:
    from docutracex.storage import CasePaths, read_json, write_subresult
    root = tmp_path / "cases" / "c1"
    (root / "results").mkdir(parents=True)
    (root / "case.json").write_text("{}")
    raw = mk.build_email(from_="ops@partner.example", to="ana@corp.example", subject="Pedido", text="Adjunto.",
                         html="<p>Adjunto.</p>", received=RCV, auth_results=AUTH_OK)
    p = root / "m.eml"
    p.write_bytes(raw)
    email = mail.analyze(p, ".eml")
    paths = CasePaths("c1", cases_dir=root.parent)
    write_subresult(paths, "email", email)
    write_subresult(paths, "mailrules", mail_rules.analyze(p, ".eml", email, root))
    write_subresult(paths, "nested", {"tree": [{"filename": "pedido.docm", "findings": [
        {"rule": "vba_autoexec_shell", "severity": "high"}], "children": []}]})
    write_subresult(paths, "c2", {"findings": [{"rule": "c2:cobalt", "severity": "high", "location": "stage.bin"}]})
    v = mail_rules.case_stage(root)
    res = read_json(paths.subresult("mailrules"))
    rules = {f["rule"] for f in res["findings"]}
    assert {"payload_implant_configuration", "payload_malicious_content", "email_verdict"} <= rules
    assert v["verdict"] == "malicious"


@pytest.mark.parametrize("fn, verdict, must", [
    ("bec_freemail_eml", "phishing", {"bec_bank_details_change", "freemail_business_request", "mailto_freemail_in_body"}),
    ("toad_eml", "phishing", {"callback_phishing"}),
    ("newsletter_eml", "clean", {"legit_esp_newsletter"}),
    ("lure_attachments_eml", "malicious", {"password_protected_attachment", "svg_active_content",
                                           "calendar_invite_links", "fake_reply_thread"}),
    ("gateway_links_eml", "clean", set()),
])
def test_samples(tmp_path: Path, fn: str, verdict: str, must: set) -> None:
    import make_samples as ms
    p = tmp_path / "m.eml"
    p.write_bytes(getattr(ms, fn)())
    email = mail.analyze(p, ".eml", tmp_path / "extracted")
    res = mail_rules.analyze(p, ".eml", email, tmp_path)
    assert res["verdict"]["verdict"] == verdict and must <= _ids(res)
