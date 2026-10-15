"""Encrypted Office documents via msoffcrypto-tool (external tool, portable).

Detects whether an Office document is encrypted and, as a forensic aid, tries a
short list of *known default* passwords that malware uses to stay encrypted (so
AV skips them) while still auto-opening — most famously Excel's
``VelvetSweatshop``. It never brute-forces or guesses real passwords.

When it decrypts with a default password, that is itself a strong indicator, and
the decrypted copy is written to ``extracted/decrypted/`` for a separate,
explicit analysis (not analyzed automatically here).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

# Known default passwords used as an evasion (not a cracking list).
_DEFAULT_PASSWORDS = ["VelvetSweatshop"]


def _finding(rule: str, severity: str, detail: str) -> dict:
    return {"tool": "msoffcrypto", "rule": rule, "severity": severity,
            "detail": detail, "location": "document"}


def analyze(original_path: Path, extracted_dir: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "msoffcrypto",
        "available": False,
        "tool_version": None,
        "encrypted": None,
        "decrypted": False,
        "findings": [],
        "error": None,
        "status": "ok",
    }
    try:
        import msoffcrypto
        import importlib.metadata as md
        result["tool_version"] = md.version("msoffcrypto-tool")
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"msoffcrypto unavailable: {exc}"
        return result

    result["available"] = True
    try:
        with original_path.open("rb") as fh:
            of = msoffcrypto.OfficeFile(fh)
            encrypted = of.is_encrypted()
            result["encrypted"] = bool(encrypted)
            if not encrypted:
                return _finalize(result)
    except Exception as exc:  # noqa: BLE001
        # Unrecognized format (not an encryptable Office doc) — not applicable.
        result["error"] = str(exc)
        result["encrypted"] = False
        return _finalize(result)

    result["findings"].append(
        _finding("encrypted_document", "medium",
                 "Document is encrypted; analysis is partial until decrypted."))

    # Try known default passwords (evasion), not real cracking.
    for pw in _DEFAULT_PASSWORDS:
        try:
            with original_path.open("rb") as fh:
                of = msoffcrypto.OfficeFile(fh)
                of.load_key(password=pw)
                if extracted_dir is not None:
                    out_dir = extracted_dir / "decrypted"
                    out_dir.mkdir(parents=True, exist_ok=True)
                    out = out_dir / (original_path.stem + ".decrypted")
                    with out.open("wb") as o:
                        of.decrypt(o)
                    result["decrypted_path"] = str(out.relative_to(extracted_dir.parent).as_posix())
                result["decrypted"] = True
                result["decrypted_password"] = pw
                result["findings"].append(
                    _finding("encrypted_default_password", "high",
                             f"Decrypts with the default password '{pw}' — a common "
                             f"malware evasion. Decrypted copy saved for review."))
                break
        except Exception:  # noqa: BLE001
            continue

    return _finalize(result)


def _finalize(result: dict[str, Any]) -> dict[str, Any]:
    # Readable record of what msoffcrypto reported (shown in the Tools pane).
    lines = [f"msoffcrypto-tool {result.get('tool_version') or ''}".strip()]
    if result.get("error"):
        lines.append(f"Not applicable / error: {result['error']}")
    else:
        lines.append(f"is_encrypted: {bool(result.get('encrypted'))}")
        if result.get("encrypted"):
            lines.append(f"default passwords tried: {', '.join(repr(p) for p in _DEFAULT_PASSWORDS)}")
            lines.append(f"decrypted with: {result['decrypted_password']!r} -> {result.get('decrypted_path', '')}"
                         if result.get("decrypted") else "no default password worked")
    result["command"] = "msoffcrypto (python API): OfficeFile.is_encrypted / load_key"
    result["output"] = "\n".join(lines)
    result["counts"] = {"findings": len(result["findings"])}
    if result["findings"]:
        result["status"] = "ok_with_findings"
    return result
