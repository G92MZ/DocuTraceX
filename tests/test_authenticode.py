"""Shared Authenticode normalization used by MSI and PE analysis."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from docutracex.parsers import authenticode, msi


def _cert(subject: str) -> dict:
    return {
        "subject": subject, "issuer": "CN=Example CA", "thumbprint": "AABBCCDD",
        "sha256_fingerprint": "11" * 32, "serial_number": "010203",
        "valid_from": "2025-01-01T00:00:00Z", "valid_to": "2027-01-01T00:00:00Z",
        "certificate_signature_algorithm_oid": "1.2.840.113549.1.1.11",
        "certificate_signature_algorithm": "sha256RSA",
        "eku": [{"oid": "1.3.6.1.5.5.7.3.3", "name": "Code Signing"}],
        "certificate_policies": ["Policy: 1.2.3.4"],
        "chain_build_succeeded": True, "chain_status": [], "certificate_chain": [],
        "revocation_status": "good",
    }


def _ps_result(status: str, signer: dict | None = None,
               signature_type: str = "Embedded") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout=json.dumps({"status": status, "status_message": "Windows trust result",
                           "signature_type": signature_type,
                           "signer": signer if signer is not None else _cert("CN=Example Publisher"),
                           "timestamp_signer": _cert("CN=Example TSA")}),
        stderr="",
    )


def test_shared_verifier_normalizes_signer_and_timestamp(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "signed.msi"
    target.write_bytes(b"sample")
    monkeypatch.setattr(authenticode, "_powershell_executable", lambda: "powershell.exe")
    monkeypatch.setattr(authenticode.subprocess, "run", lambda *a, **kw: _ps_result("Valid"))

    result = authenticode.verify(target, content_digest_algorithm="SHA256")

    assert result["status"] == "valid" and result["signed"] is True
    assert result["signature_type"] == "embedded"
    assert result["signature_source"] == "embedded"
    assert result["signer"]["subject"] == "CN=Example Publisher"
    assert result["signer"]["eku"][0]["name"] == "Code Signing"
    assert result["signer"]["revocation_status"] == "good"
    assert result["timestamp_signer"]["subject"] == "CN=Example TSA"
    assert result["content_digest_algorithm"] == "SHA256"
    assert result["timestamp_time_status"] == "not_exposed_by_powershell_api"


def test_shared_verifier_distinguishes_not_signed_and_hash_mismatch(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "sample.exe"
    target.write_bytes(b"sample")
    monkeypatch.setattr(authenticode, "_powershell_executable", lambda: "powershell.exe")

    monkeypatch.setattr(authenticode.subprocess, "run", lambda *a, **kw: _ps_result("NotSigned", {}))
    unsigned = authenticode.verify(target)
    assert unsigned["status"] == "not_signed" and unsigned["signed"] is False
    assert authenticode.findings(unsigned, "file:sample.exe") == []

    monkeypatch.setattr(authenticode.subprocess, "run", lambda *a, **kw: _ps_result("HashMismatch"))
    mismatch = authenticode.verify(target)
    findings = authenticode.findings(mismatch, "file:sample.exe")
    assert mismatch["status"] == "hash_mismatch"
    assert findings[0]["rule"] == "authenticode_hash_mismatch"
    assert findings[0]["severity"] == "high"


def test_shared_verifier_preserves_catalog_signature_type(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "cmd.exe"
    target.write_bytes(b"MZ" + b"\x00" * 128)
    monkeypatch.setattr(authenticode, "_powershell_executable", lambda: "powershell.exe")
    monkeypatch.setattr(authenticode.subprocess, "run",
                        lambda *a, **kw: _ps_result("Valid", signature_type="Catalog"))

    result = authenticode.verify(target)

    assert result["status"] == "valid"
    assert result["signed"] is True
    assert result["signature_type"] == "catalog"
    assert result["signature_source"] == "catalog"
    assert result["signer"]["subject"] == "CN=Example Publisher"


def test_shared_verifier_reports_unavailable_without_windows(monkeypatch) -> None:
    monkeypatch.setattr(authenticode, "_powershell_executable", lambda: None)
    result = authenticode.verify(Path("sample.msi"))
    assert result["status"] == "unavailable" and result["signed"] is None
    assert authenticode.findings(result, "file:sample.msi")[0]["rule"] == "authenticode_check_unavailable"


def test_msi_uses_shared_verifier_and_finding_schema(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "signed.msi"
    target.write_bytes(b"sample")
    signature = {"status": "valid", "signed": True,
                 "signer": {"subject": "CN=Publisher"}, "status_message": ""}
    monkeypatch.setattr(authenticode, "verify", lambda path: signature)
    result = msi._verify_msi_authenticode(target)
    assert result is signature
    findings = msi._msi_signature_findings(result, "file:signed.msi")
    assert findings[0]["rule"] == "authenticode_valid"
    assert findings[0]["tool"] == "msi"


def test_pe_lief_result_is_enriched_by_the_same_authenticode_layer(monkeypatch, tmp_path: Path) -> None:
    from docutracex.parsers import lief_info

    target = tmp_path / "signed.exe"
    target.write_bytes(b"MZ" + b"\x00" * 128)
    parsed = {
        "status": "ok", "format": "PE", "signatures": [{"digest": "SHA256", "certificates": []}],
        "pdb": [], "mitigations": {}, "checksum": {"valid": True},
    }
    monkeypatch.setattr("importlib.util.find_spec", lambda name: object() if name == "lief" else None)
    monkeypatch.setattr(lief_info.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps(parsed), stderr=""))
    shared = {"status": "valid", "signed": True, "content_digest_algorithm": "SHA256",
              "signer": _cert("CN=Example Publisher"), "timestamp_signer": _cert("CN=Example TSA")}
    monkeypatch.setattr(authenticode, "verify", lambda path, **kw: shared)

    result = lief_info.analyze(target, target.name)

    assert result["status"] == "ok"
    assert result["authenticode"]["signer"]["subject"] == "CN=Example Publisher"
    assert any(f["rule"] == "authenticode_valid" for f in result["findings"])


def test_pe_without_embedded_certificate_still_checks_windows_catalog(monkeypatch, tmp_path: Path) -> None:
    from docutracex.parsers import lief_info

    target = tmp_path / "cmd.exe"
    target.write_bytes(b"MZ" + b"\x00" * 128)
    parsed = {
        "status": "ok", "format": "PE", "signatures": [],
        "pdb": [], "mitigations": {}, "checksum": {"valid": True},
    }
    monkeypatch.setattr("importlib.util.find_spec", lambda name: object() if name == "lief" else None)
    monkeypatch.setattr(lief_info.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps(parsed), stderr=""))
    calls = []
    catalog = {"status": "valid", "signed": True, "signature_type": "catalog",
               "signature_source": "catalog", "signer": _cert("CN=Microsoft Windows"),
               "timestamp_signer": {}}
    def verify(path, **kwargs):
        calls.append((path, kwargs))
        return catalog
    monkeypatch.setattr(authenticode, "verify", verify)

    result = lief_info.analyze(target, target.name)

    assert len(calls) == 1
    assert calls[0][1]["content_digest_algorithm"] == ""
    assert result["authenticode"]["signature_type"] == "catalog"
    assert any(f["rule"] == "authenticode_valid" for f in result["findings"])
