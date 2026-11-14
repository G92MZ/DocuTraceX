"""HTML section: offline preview, structure, phishing rules, loader layers, the victim's
prefilled address (tagged in the IOCs) and QR codes drawn with HTML / SVG."""

from __future__ import annotations

import json
import time
from email.message import EmailMessage
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import htmlpage
from docutracex.config import settings

S = ms.html_samples()
PAGE = S["sample_phish_factura.html"].decode()


def test_structure_and_rules() -> None:
    st = htmlpage.structure(PAGE)
    f = st["forms"][0]
    assert f["action"] == "https://recogida-datos.example/factura/post.php" and f["password"]
    assert f["hidden"] == ["ref"] and f["posts_to"] == "recogida-datos.example"
    ext = {r["url"] for r in st["resources"] if r["external"]}
    assert {"https://cdn.estilos-ejemplo.example/portal.css", "https://cdn.portal-facturas.example/logo.png"} <= ext
    assert st["title"].startswith("Portal de facturas") and "contraseña" in st["login_words"]
    victims = htmlpage._victims(PAGE, st)
    assert [v["address"] for v in victims] == [ms.HTML_VICTIM]
    rules = {x["rule"]: x for x in htmlpage.rules(PAGE, st, victims, "p", [])}
    assert {"html_victim_prefilled", "html_typed_data_sent_by_script", "html_anti_analysis",
            "html_identity_mismatch"} <= set(rules)
    anti = rules["html_anti_analysis"]["detail"]
    assert all(k in anti for k in ("right-click", "F12", "IP / geolocation", "CAPTCHA"))
    assert "html_loader_page" not in rules


def test_victim_only_in_base64() -> None:
    page = '<html><body><script>var email = "' + "YW5hLmdhcmNpYUBjbGllbnRlLWVqZW1wbG8uZXhhbXBsZQ==" + '";</script></body></html>'
    assert htmlpage._victims(page, htmlpage.structure(page)) == [
        {"address": ms.HTML_VICTIM, "where": "Base64 in a variable of the page"}]


def test_loader_layer_recovered_statically() -> None:
    layers = htmlpage.recover_layers(S["sample_phish_loader.html"].decode())
    assert [x["how"] for x in layers] == ["base64 literal"] and "recogida-datos.example" in layers[0]["markup"]


def test_markup_detection(tmp_path: Path) -> None:
    p = tmp_path / "x.bin"
    p.write_bytes(b"\xef\xbb\xbf<!DOCTYPE html><html>")
    assert htmlpage.is_markup(p)
    p.write_bytes(b"MZ\x90\x00")
    assert not htmlpage.is_markup(p)


def _chromium(tmp: Path) -> bool:
    return bool(htmlpage.render("<p>x</p>", tmp / "probe.png").get("ok"))


def _case(c, name: str, data: bytes, tmp: Path) -> Path:  # noqa: ANN001
    r = c.post("/api/cases", files={"file": (name, data)}).json()
    for _ in range(1500):
        t = next((x for x in c.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.1)
    return tmp / "cases" / r["analysis_id"] / "results"


def test_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not _chromium(tmp_path):
        pytest.skip("Chromium (Playwright) not available")
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    c = TestClient(create_app())

    # the loader: the preview is the recovered page, and its HTML-table QR is read from it
    res = _case(c, "factura.html", S["sample_phish_loader.html"], tmp_path)
    h = json.loads((res / "html.json").read_text())
    assert h["screenshot"]["stored_path"].endswith("page.png") and h["screenshot"]["layer"] == 1
    assert h["qr"][0]["text"] == "https://portal-facturas.example/qr/tabla?f=2026-0187"
    assert {"html_loader_page", "html_credential_form", "qr_code_url"} <= {f["rule"] for f in h["findings"]}
    iocs = json.loads((res / "iocs.json").read_text())["iocs"]
    v = next(i for i in iocs if i["type"] == "email" and i["value"] == ms.HTML_VICTIM)
    assert v["victim"]["recipient"] is None                       # no email in this case
    assert c.get(f"/api/cases/{res.parent.name}/netcheck/asset",
                 params={"path": h["screenshot"]["stored_path"]}).status_code == 200

    # an SVG whose QR is drawn with rectangles
    res = _case(c, "qr.svg", S["sample_qr_drawn.svg"], tmp_path)
    assert json.loads((res / "html.json").read_text())["qr"][0]["text"].endswith("/qr/svg?f=2026-0187")

    # an email whose HTML body is the page: preview + QR of the body, victim = the recipient
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "facturacion@portal-facturas.example", ms.HTML_VICTIM, "Factura"
    m.set_content("Factura")
    m.add_alternative(PAGE, subtype="html")
    res = _case(c, "factura.eml", bytes(m), tmp_path)
    h = json.loads((res / "html.json").read_text())
    assert h["kind"] == "email body" and h["qr"][0]["text"].endswith("/qr/tabla?f=2026-0187")
    assert not any(f["rule"] == "html_credential_form" for f in h["findings"])   # judged by the email engine
    iocs = json.loads((res / "iocs.json").read_text())["iocs"]
    assert next(i for i in iocs if i["value"] == ms.HTML_VICTIM)["victim"]["recipient"] is True
