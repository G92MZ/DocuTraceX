"""Shared Windows Authenticode verification and certificate enrichment.

The file-format parser remains format-specific (LIEF for PE, Windows SIP for
MSI), while this module normalizes the Windows trust result and certificate
metadata for the UI. Verification is static: no installer or sample code runs.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _powershell_executable() -> str | None:
    if os.name != "nt":
        return None
    return shutil.which("powershell.exe") or shutil.which("powershell")


def _empty(status: str, detail: str) -> dict[str, Any]:
    return {
        "status": status,
        "status_raw": "",
        "status_message": detail,
        "signed": None if status in ("unavailable", "error", "timeout") else False,
        "signature_type": "",
        "signature_source": "unknown",
        "verification": "Windows Authenticode / WinTrust",
        "content_digest_algorithm": "",
        "content_digest_algorithm_status": "not_exposed_by_powershell_api",
        "signer": {},
        "timestamp_signer": {},
    }


# Windows PowerShell 5.1 / .NET Framework compatible. Revocation is checked
# online with a short URL timeout; an offline/unknown result is never called
# good. Certificate signature algorithm is deliberately distinguished from
# the digest algorithm used to sign the file.
_PS_SCRIPT = r'''$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
function Get-CertRecord($c) {
  if (-not $c) { return $null }
  $eku = @()
  $ekuExt = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
  if ($ekuExt) {
    try { $ekuParsed = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExt; foreach ($e in $ekuParsed.EnhancedKeyUsages) { $eku += [ordered]@{ oid=[string]$e.Value; name=[string]$e.FriendlyName } } } catch {}
  }
  $policies = @()
  $polExt = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.32' } | Select-Object -First 1
  if ($polExt) { try { $policies += [string]$polExt.Format($false) } catch {} }
  $sha = New-Object System.Security.Cryptography.SHA256Managed
  $fp = ([BitConverter]::ToString($sha.ComputeHash($c.RawData))).Replace('-', '')
  $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
  $chainEvaluationTime = [DateTime]::UtcNow
  $chain.ChainPolicy.VerificationTime = $chainEvaluationTime
  $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
  $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
  $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(3)
  $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
  $built = $false
  $chainStatus = @()
  $elements = @()
  try {
    $built = [bool]$chain.Build($c)
    foreach ($st in $chain.ChainStatus) {
      $chainStatus += [ordered]@{ status=[string]$st.Status; information=([string]$st.StatusInformation).Trim() }
    }
    foreach ($el in $chain.ChainElements) {
      $ec = $el.Certificate
      $ecSha = New-Object System.Security.Cryptography.SHA256Managed
      $ecFp = ([BitConverter]::ToString($ecSha.ComputeHash($ec.RawData))).Replace('-', '')
      $elements += [ordered]@{
        subject=[string]$ec.Subject; issuer=[string]$ec.Issuer
        thumbprint=[string]$ec.Thumbprint; sha256_fingerprint=$ecFp
        serial_number=[string]$ec.SerialNumber
        valid_from=$ec.NotBefore.ToUniversalTime().ToString('o')
        valid_to=$ec.NotAfter.ToUniversalTime().ToString('o')
      }
    }
  } catch { $chainStatus += [ordered]@{ status='ChainBuildError'; information=$_.Exception.Message } }
  $revNames = @($chainStatus | ForEach-Object { $_.status })
  if ($revNames -contains 'Revoked') { $revocation='revoked' }
  elseif (($revNames -contains 'RevocationStatusUnknown') -or ($revNames -contains 'OfflineRevocation')) { $revocation='unknown' }
  elseif ($revNames.Count -eq 0 -and $built) { $revocation='good' }
  else { $revocation='not_determined' }
  $sigAlg = $c.SignatureAlgorithm
  return [ordered]@{
    subject=[string]$c.Subject; issuer=[string]$c.Issuer
    thumbprint=[string]$c.Thumbprint; sha256_fingerprint=$fp
    serial_number=[string]$c.SerialNumber
    valid_from=$c.NotBefore.ToUniversalTime().ToString('o')
    valid_to=$c.NotAfter.ToUniversalTime().ToString('o')
    certificate_signature_algorithm_oid=[string]$sigAlg.Value
    certificate_signature_algorithm=[string]$sigAlg.FriendlyName
    eku=$eku; certificate_policies=$policies
    chain_build_succeeded=$built; chain_evaluation_time=$chainEvaluationTime.ToString('o'); chain_status=$chainStatus
    certificate_chain=$elements; revocation_status=$revocation
  }
}
$s = Get-AuthenticodeSignature -LiteralPath $env:DOCUTRACEX_AUTHENTICODE_TARGET
$signatureType = ''
if ($s.PSObject.Properties['SignatureType']) {
  $signatureType = [string]$s.SignatureType
}
$o = [ordered]@{
  status=[string]$s.Status; status_message=[string]$s.StatusMessage
  signature_type=$signatureType
  signer=(Get-CertRecord $s.SignerCertificate)
  timestamp_signer=(Get-CertRecord $s.TimeStamperCertificate)
}
[Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 8))'''


def verify(path: Path, *, content_digest_algorithm: str = "") -> dict[str, Any]:
    """Return normalized Authenticode status and signer/TSA certificate data.

    ``content_digest_algorithm`` is populated from LIEF for PE files. Windows'
    Get-AuthenticodeSignature does not expose the file's CMS digest algorithm
    for MSI, so that field remains empty rather than misreporting the
    certificate's own signature algorithm as the file digest.
    """
    exe = _powershell_executable()
    if not exe:
        result = _empty("unavailable", "Windows PowerShell / Authenticode is unavailable on this platform")
        result["content_digest_algorithm"] = content_digest_algorithm
        result["content_digest_algorithm_status"] = "from_lief" if content_digest_algorithm else "not_exposed_by_powershell_api"
        return result

    encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    env = os.environ.copy()
    env["DOCUTRACEX_AUTHENTICODE_TARGET"] = str(path.resolve())
    try:
        proc = subprocess.run(
            [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=18, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        result = _empty("timeout", "Windows Authenticode verification timed out")
        result["content_digest_algorithm"] = content_digest_algorithm
        result["content_digest_algorithm_status"] = "from_lief" if content_digest_algorithm else "not_exposed_by_powershell_api"
        return result
    except OSError as exc:
        result = _empty("error", f"Could not start Windows Authenticode verification: {exc}")
        result["content_digest_algorithm"] = content_digest_algorithm
        result["content_digest_algorithm_status"] = "from_lief" if content_digest_algorithm else "not_exposed_by_powershell_api"
        return result

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or f"PowerShell exited {proc.returncode}").strip()
        result = _empty("error", detail[-1000:])
        result["content_digest_algorithm"] = content_digest_algorithm
        result["content_digest_algorithm_status"] = "from_lief" if content_digest_algorithm else "not_exposed_by_powershell_api"
        return result
    try:
        raw = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        result = _empty("error", "PowerShell returned an unreadable Authenticode result")
        result["content_digest_algorithm"] = content_digest_algorithm
        result["content_digest_algorithm_status"] = "from_lief" if content_digest_algorithm else "not_exposed_by_powershell_api"
        return result

    raw_status = str(raw.get("status") or "UnknownError")
    status = {
        "Valid": "valid", "NotSigned": "not_signed", "HashMismatch": "hash_mismatch",
        "NotTrusted": "not_trusted", "UnknownError": "unknown_error",
        "NotSupportedFileFormat": "unsupported_format",
    }.get(raw_status, "unknown")
    signature_type_raw = str(raw.get("signature_type") or "").strip()
    signature_type_key = signature_type_raw.casefold()
    signature_type = {
        "embedded": "embedded",
        "catalog": "catalog",
    }.get(signature_type_key, "none" if raw_status == "NotSigned" else "unknown")
    signature_source = {
        "embedded": "embedded",
        "catalog": "catalog",
        "none": "none",
    }.get(signature_type, "unknown")
    signer = raw.get("signer") or {}
    timestamp_signer = raw.get("timestamp_signer") or {}
    for cert in (signer, timestamp_signer):
        if not isinstance(cert, dict):
            continue
        for key in ("eku", "certificate_policies", "chain_status", "certificate_chain"):
            value = cert.get(key)
            if value is None:
                cert[key] = []
            elif not isinstance(value, list):
                cert[key] = [value]
    signed = False if status == "not_signed" else (
        True if signer.get("subject") or status in ("valid", "hash_mismatch", "not_trusted") else None
    )
    return {
        "status": status,
        "status_raw": raw_status,
        "status_message": str(raw.get("status_message") or ""),
        "signed": signed,
        "signature_type": signature_type,
        "signature_source": signature_source,
        "verification": "Windows Authenticode / WinTrust (Get-AuthenticodeSignature)",
        "content_digest_algorithm": content_digest_algorithm,
        "content_digest_algorithm_status": "from_lief" if content_digest_algorithm else "not_exposed_by_powershell_api",
        "signer": signer,
        "timestamp_signer": timestamp_signer,
        # Get-AuthenticodeSignature exposes the TSA certificate, but not the
        # countersignature's SigningTime. Do not substitute the TSA cert dates.
        "timestamp_time": "",
        "timestamp_time_status": "not_exposed_by_powershell_api",
    }


def findings(signature: dict[str, Any], location: str, *, tool: str = "authenticode") -> list[dict[str, Any]]:
    """Create conservative findings from a normalized verification result."""
    status = signature.get("status")
    signer = (signature.get("signer") or {}).get("subject", "")
    message = str(signature.get("status_message") or "")

    def item(rule: str, severity: str, detail: str, evidence: str = "", attack: str = "") -> dict[str, Any]:
        return {"tool": tool, "rule": rule, "severity": severity,
                "detail": detail + (f" · {attack}" if attack else ""),
                "location": location, "evidence": evidence[:2000]}

    if status == "valid":
        return [item("authenticode_valid", "info",
                     f"Authenticode signature verifies — signer: {signer[:160] or 'unknown'}", signer)]
    if status == "hash_mismatch":
        return [item("authenticode_hash_mismatch", "high",
                     "Authenticode signature is present but the file hash does not match", message or signer,
                     "T1553.002")]
    if status == "not_trusted":
        return [item("authenticode_not_trusted", "medium",
                     f"Authenticode signature is present but Windows does not trust it: {message[:300]}", signer,
                     "T1553.002")]
    if status in ("unavailable", "timeout", "error", "unsupported_format", "unknown_error", "unknown"):
        return [item("authenticode_check_unavailable", "low",
                     f"Authenticode verification unavailable ({status}): {message[:300]}")]
    return []
