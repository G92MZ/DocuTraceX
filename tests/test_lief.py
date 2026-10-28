"""LIEF deep binary parsing (PE / ELF) and its place in the Binary tab."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

pytestmark = pytest.mark.skipif(importlib.util.find_spec("lief") is None, reason="lief not installed")


def test_lief_pe_details(tmp_path: Path) -> None:
    from docutracex.parsers import lief_info
    p = tmp_path / "invoice_helper.dll"
    p.write_bytes(_ms().lief_helper_dll())
    r = lief_info.analyze(p, p.name)
    assert r["status"] == "ok" and r["format"] == "PE" and r["imphash"] == ""  # no imports
    assert r["pdb"][0]["path"].endswith(r"InvoiceSync\x64\Release\invoice_helper.pdb")
    assert r["exports"][0]["forward"] == "version.GetFileVersionInfoW"
    assert r["mitigations"]["aslr"] and r["mitigations"]["dep"] and not r["mitigations"]["cfg"]
    assert not r["checksum"]["valid"] and r["overlay"]["entropy"] > 7.5
    assert {"lief_pdb_path", "lief_manifest_admin", "lief_manifest_autoelevate", "lief_checksum_mismatch",
            "lief_forwarded_exports", "lief_overlay_encrypted"} <= {f["rule"] for f in r["findings"]}


def test_lief_crash_is_contained(tmp_path: Path) -> None:
    from docutracex.parsers import lief_info
    p = tmp_path / "junk.exe"
    p.write_bytes(b"MZ" + b"\xff" * 200)
    r = lief_info.analyze(p, p.name)
    assert r["status"] in ("error", "ok") and isinstance(r["findings"], list)


def test_lief_in_binary_tab_end_to_end(client) -> None:
    _, res = _analyze(client, "invoice_helper.dll", _ms().lief_helper_dll())
    msi = json.loads((res / "msi.json").read_text())
    it = msi["items"][0]
    assert it["kind"] == "pe" and it["lief"]["status"] == "ok"
    rules = {f["rule"] for f in msi["findings"]}
    assert {"lief_forwarded_exports", "lief_manifest_autoelevate"} <= rules
    iocs = {i["value"] for i in json.loads((res / "iocs.json").read_text())["iocs"]}
    assert any(v.endswith("invoice_helper.pdb") for v in iocs)


def test_elf_without_extension_is_a_binary(client) -> None:
    elf = Path(shutil.which("true") or "/bin/true").read_bytes()
    _, res = _analyze(client, "update", elf)
    it = json.loads((res / "msi.json").read_text())["items"][0]
    assert it["kind"] == "native" and it["format"] == "ELF" and it["lief"]["status"] == "ok"
    assert any(f["rule"] == "lief_elf" for f in it["findings"])
