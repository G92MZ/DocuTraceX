"""A legitimate signed installer bootstrapper must not look like a dropper:
embedded client, routine imports, reproducible build, .NET member names."""

from __future__ import annotations

import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import make_samples as ms  # noqa: E402

from docutracex import ioc  # noqa: E402
from docutracex.parsers import pe  # noqa: E402


def test_same_name_tolerates_extraction_names() -> None:
    assert pe._same_name("InvoiceSync.WindowsClient.exe", "0a1b2c3d4e5f_Setup.RT_RCDATA_INVOICESYNC.WINDOWSCLIENT.EXE.exe")
    assert pe._same_name("InvoiceSync.WindowsClient.exe", "nc.WindowsClient.exe")          # cut at the front
    assert pe._same_name("InvoiceSync.WindowsClient.dll", "InvoiceSync.WindowsClient.exe")  # another extension
    assert not pe._same_name("svchost.exe", "factura_2026.pdf.exe")                          # a real masquerade
    assert pe._tool_named("extracted/hidden/x_y.exe") and not pe._tool_named("extracted/zip/factura.exe")


def test_iocs_skip_code_members_and_certificate_serials() -> None:
    r = ioc.extract([{"module": "pe", "location": "strings", "text":
                      "IntPtr.Zero InvoiceSync.Client.Cloud default.cab relay.invoice-support.example PayPal.Com"}])
    assert {i["value"] for i in r["iocs"] if i["type"] == "domain"} == {"relay.invoice-support.example", "paypal.com"}
    src = ioc.sources_from_modules({"pe": {"items": [{"lief": {"signatures": [{"certificates": [
        {"subject": "CN=InvoiceSync Example", "serial": "0fcd7f003c9a632c40869" + "9f8fafae36e"}]}]}}]}})
    assert not any("serial" in s["location"] for s in src)


def test_signed_bootstrapper_end_to_end(tmp_path: Path) -> None:
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json
    m = cases.create_case(io.BytesIO(ms.signed_bootstrapper_exe()), "InvoiceSync.ClientSetup.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    fs = read_json(CasePaths(m["analysis_id"], cases_dir=tmp_path).subresult("findings"))["findings"]
    by = {}
    for f in fs:
        by.setdefault(f["rule"], []).append(f)
    assert "pe_masquerade" not in by and "stego:payload" not in by and "pe_timestamp_anomaly" not in by
    assert by["pe:resource_file"][0]["severity"] == "info"
    assert {f["severity"] for f in by["pe_dynamic_resolve"] + by["pe_antidebug_imports"]} == {"low"}
    # signed, but the (inert) signature cannot be verified: not high, not dismissed either
    assert by["pe_embedded_pe"][0]["severity"] == "medium"
    assert any("reproducible build" in f["detail"] for f in by["pe_image"])
