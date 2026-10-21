"""The shipped deobfuscation-demo samples really deobfuscate to the campaign IOCs.

Builds the samples straight from the generators (no archive / heavy deps) and
runs each engine's analysis, so the demo files can never silently stop
exercising the deobfuscation path they document.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import make_samples as ms  # noqa: E402

from docutracex.parsers import javascript, powershell, vbscript  # noqa: E402

STAGE2 = "198.51.100.23/a.ps1"


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    ex = tmp_path / "extracted" / "a"
    ex.mkdir(parents=True, exist_ok=True)
    (ex / name).write_bytes(data)
    return ex.parent


def test_js_dropper_sample_is_deobfuscated(tmp_path: Path) -> None:
    ex = _write(tmp_path, "factura_visor.js", ms.obf_js())
    res = javascript.analyze(tmp_path / "o.eml", ex, {})
    sc = res["scripts"][0]
    assert sc["code_is_deobfuscated"]
    rules = {f["rule"] for f in res["findings"]}
    assert {"js_deobfuscated", "js_wscript_shell"} <= rules
    assert "cdn-update.example.net" in sc["code"]


def test_powershell_stage2_sample_is_deobfuscated(tmp_path: Path) -> None:
    ex = _write(tmp_path, "actualizador.ps1", ms.stage2_ps1())
    res = powershell.analyze(tmp_path / "o.ps1", ex, {})
    assert any(s["code_is_deobfuscated"] for s in res["scripts"])
    assert any("DownloadString" in s["code"] and STAGE2 in s["code"] for s in res["scripts"])


def test_vbs_dropper_sample_is_deobfuscated(tmp_path: Path) -> None:
    ex = _write(tmp_path, "factura.pdf.vbs", ms.dropper_vbs())
    res = vbscript.analyze(tmp_path / "o.vbs", ex, {})
    assert any(s["code_is_deobfuscated"] for s in res["scripts"])
    assert any(STAGE2 in s["code"] for s in res["scripts"])


def test_bundle_zip_bundles_every_script_engine() -> None:
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(ms.dropper_bundle_zip())) as zf:
        assert set(zf.namelist()) == {
            "factura_visor.js", "visor_seguro.js", "actualizador.ps1",
            "factura.pdf.vbs", "instalador.bat", "factura.hta",
            "factura.pdf.lnk", "factura.url", "instalador.msi",
            "visor.py", "visor.pyc", "plugin.jar", "notas.one",
        }


def test_obfuscatorio_sample_is_obfuscated_js() -> None:
    # The committed obfuscator.io sample decodes to real JS and looks obfuscated
    # (hex identifiers, a string array) — the case webcrack flattens.
    code = ms.obf_obfuscatorio_js().decode("utf-8", "replace")
    assert "_0x" in code and ("function" in code or "var " in code)


def test_bat_and_hta_samples_build() -> None:
    bat = ms.dropper_bat().decode()
    assert "set a=power" in bat and "^" in bat
    hta = ms.loader_hta().decode()
    assert "VBScript" in hta and "JScript" in hta
