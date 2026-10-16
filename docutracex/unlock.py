"""Encrypted documents and archives: detect, unlock with known passwords, and
hand a decrypted copy to the analysis.

An encrypted Office file or PDF hides almost everything from static tools
(macros, objects, JavaScript, links), so the analysis only scratches the
surface. When the password is known — typed by the analyst at upload, given in
the email body that carried the file, or one of the well-known defaults that
malware uses to stay encrypted while still opening automatically — the file is
decrypted to ``extracted/decrypted/`` and that copy becomes the subject of the
analysis. The original stays untouched; it keeps only the encryption findings.

* Office (OOXML agile/standard, legacy .doc/.xls/.ppt RC4/CryptoAPI): msoffcrypto-tool.
* PDF (RC4/AES user or owner password): pikepdf, pypdf as fallback; an "owner-only" PDF opens with
  the empty password but its strings/streams are still encrypted on disk.
* ZIP (ZipCrypto and WinZip AES: pyzipper, stdlib fallback) and 7z (py7zr):
  entries extracted with bounds against archive bombs.

Nothing is brute-forced: only the candidates above are tried.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .logging_config import get_logger

log = get_logger(__name__)

# Well-known defaults (not a cracking list). Office: Excel's built-in
# "VelvetSweatshop" opens without prompting, a classic AV evasion. Archives:
# the conventions used to pass malware around.
OFFICE_DEFAULTS = ["VelvetSweatshop"]
ARCHIVE_DEFAULTS = ["infected", "malware", "virus"]

MAX_ENTRIES = 50
MAX_FILE = 100 * 1024 * 1024
MAX_TOTAL = 250 * 1024 * 1024

_7Z_MAGIC = b"7z\xbc\xaf\x27\x1c"


# --- candidates -------------------------------------------------------------

def candidates(user: str | None = None, harvested: list[dict[str, Any]] | None = None,
               kind: str = "document", words: list[dict[str, str]] | None = None) -> list[dict[str, str]]:
    """Ordered, de-duplicated passwords to try: the analyst's, the ones found in
    the carrying email, the defaults for the kind of file and, when the analyst
    asked for it, every word of the email (``words``, see passwords.email_words)."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(pw: str | None, source: str, context: str = "") -> None:
        if pw is None or pw in seen:
            return
        seen.add(pw)
        out.append({"password": pw, "source": source, **({"context": context} if context else {})})

    if user:
        add(user, "user")
    for h in harvested or []:
        add(h.get("password"), "email", h.get("context", ""))
    archive = kind in ("zip", "7z", "archive")
    if not archive:
        add("", "empty")  # PDFs only: an "owner-only" PDF opens with it
    if archive:
        for pw in ARCHIVE_DEFAULTS:
            add(pw, "default")
    else:
        # k: gmzpt
        for pw in OFFICE_DEFAULTS:
            add(pw, "default")
    for w in words or []:
        add(w.get("password"), "email_words", w.get("origin", ""))
    return out


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- detection --------------------------------------------------------------

def detect(path: Path) -> dict[str, Any]:
    """``{encrypted, kind, detail}`` — kind: office | pdf | zip | 7z | None."""
    try:
        with path.open("rb") as fh:
            head = fh.read(1024)
    except OSError as exc:
        return {"encrypted": False, "kind": None, "detail": str(exc)}
    if head.startswith(b"%PDF") or b"%PDF-" in head:
        try:
            from pypdf import PdfReader
            r = PdfReader(str(path), strict=False)
            if r.is_encrypted:
                enc = r.trailer.get("/Encrypt")
                enc = enc.get_object() if enc is not None else {}
                return {"encrypted": True, "kind": "pdf",
                        "detail": f"PDF /Encrypt V={enc.get('/V')} R={enc.get('/R')} "
                                  f"filter={enc.get('/Filter')}"}
        except Exception as exc:  # noqa: BLE001
            return {"encrypted": False, "kind": "pdf", "detail": f"pypdf: {exc}"}
        return {"encrypted": False, "kind": "pdf", "detail": ""}
    if head.startswith(_7Z_MAGIC):
        try:
            import py7zr
            with py7zr.SevenZipFile(path) as sz:
                return {"encrypted": bool(sz.needs_password()), "kind": "7z", "detail": "7-Zip archive"}
        except ImportError:
            return {"encrypted": False, "kind": "7z", "detail": "py7zr not installed"}
        except Exception as exc:  # noqa: BLE001  (encrypted headers need the password to list)
            enc = "password" in str(exc).lower() or "encrypt" in str(exc).lower()
            return {"encrypted": enc, "kind": "7z",
                    "detail": "7-Zip archive (encrypted headers)" if enc else f"7-Zip archive ({exc})"[:200]}
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                if "[Content_Types].xml" in names:
                    return {"encrypted": False, "kind": None, "detail": "OOXML package"}
                enc = any(i.flag_bits & 0x1 for i in zf.infolist())
                aes = any(i.compress_type == 99 for i in zf.infolist())
                return {"encrypted": enc, "kind": "zip",
                        "detail": "ZIP archive" + (" (WinZip AES)" if aes else " (ZipCrypto)" if enc else "")}
        except zipfile.BadZipFile as exc:
            return {"encrypted": False, "kind": None, "detail": str(exc)}
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        try:
            import msoffcrypto
            with path.open("rb") as fh:
                of = msoffcrypto.OfficeFile(fh)
                if of.is_encrypted():
                    return {"encrypted": True, "kind": "office",
                            "detail": f"Office {type(of).__name__.replace('File', '')} encryption"}
        except Exception as exc:  # noqa: BLE001  (OLE that msoffcrypto doesn't know: .msg, ...)
            return {"encrypted": False, "kind": None, "detail": str(exc)}
        return {"encrypted": False, "kind": "office", "detail": ""}
    return {"encrypted": False, "kind": None, "detail": ""}


# --- single-file documents (Office, PDF) -----------------------------------

def _try_office(path: Path, pw: str, out: Path) -> bool:
    import msoffcrypto

    try:
        with path.open("rb") as fh:
            of = msoffcrypto.OfficeFile(fh)
            try:
                of.load_key(password=pw, verify_password=True)
            except TypeError:  # older msoffcrypto without verify_password
                of.load_key(password=pw)
            with out.open("wb") as o:
                of.decrypt(o)
    except Exception:  # noqa: BLE001  (wrong password / unsupported variant)
        out.unlink(missing_ok=True)
        return False
    return out.is_file() and out.stat().st_size > 0


def _try_pdf(path: Path, pw: str, out: Path) -> bool:
    """pikepdf (qpdf) keeps the objects and strings as they are; pypdf is the
    fallback (it re-escapes strings, which raw scanners read less well)."""
    try:
        import pikepdf
    except ImportError:
        pikepdf = None
    if pikepdf is not None:
        try:
            with pikepdf.open(str(path), password=pw) as pdf:
                pdf.save(str(out), encryption=False)
            return out.is_file() and out.stat().st_size > 0
        except pikepdf.PasswordError:
            return False
        except Exception as exc:  # noqa: BLE001  (damaged file: let pypdf try)
            log.debug("pikepdf decrypt failed: %s", exc)
            out.unlink(missing_ok=True)

    from pypdf import PdfReader, PdfWriter

    try:
        reader = PdfReader(str(path), strict=False)
        if not reader.decrypt(pw):
            return False
        writer = PdfWriter(clone_from=reader)
        with out.open("wb") as o:
            writer.write(o)
    except Exception as exc:  # noqa: BLE001
        log.debug("pdf decrypt failed: %s", exc)
        out.unlink(missing_ok=True)
        return False
    return out.is_file() and out.stat().st_size > 0


def _finding(rule: str, severity: str, detail: str, location: str = "document") -> dict[str, Any]:
    return {"tool": "unlock", "rule": rule, "severity": severity, "detail": detail, "location": location}


def _decrypted_findings(kind: str, used: dict[str, str], name: str, location: str) -> list[dict[str, Any]]:
    """What the way it was unlocked says about the file."""
    src, pw = used["source"], used["password"]
    what = {"office": "Office document", "pdf": "PDF", "zip": "ZIP archive", "7z": "7z archive"}[kind]
    if src == "default" and kind == "office":
        return [_finding("encrypted_default_password", "high",
                         f"{what} decrypts with the default password '{pw}' — opens without a prompt "
                         "while hiding its content from scanners (a common malware evasion).", location)]
    if src == "empty":
        return [_finding("encrypted_empty_password", "medium",
                         "PDF encrypted with an empty user password: it opens without a prompt, the "
                         "encryption only hides strings/streams from scanners.", location)]
    if src == "email":
        return [_finding("password_in_email", "medium",
                         f"Encrypted {what} '{name}' opens with a password given in the email "
                         f"('{pw}') — encryption used to get the payload past mail gateways and AV.",
                         location)]
    if src == "email_words":
        return [_finding("password_in_email", "medium",
                         f"Encrypted {what} '{name}' opens with '{pw}', a word of the email "
                         f"({used.get('context') or 'body'}) found by trying every word — the "
                         "password was sent with the payload, disguised.", location)]
    if src == "default":
        return [_finding("encrypted_archive_default", "low",
                         f"{what} protected with the conventional password '{pw}'.", location)]
    return [_finding("encrypted_document", "low",
                     f"{what} was encrypted; decrypted with the password provided by the analyst "
                     "and analysed in full.", location)]


def unlock_file(path: Path, out_dir: Path, tries: list[dict[str, str]],
                location: str = "document", name: str | None = None) -> dict[str, Any]:
    """Detect encryption of a document and, if possible, write a decrypted copy.

    Returns a record ``{encrypted, kind, decrypted, password_source, decrypted_file,
    findings, ...}``; ``decrypted_file`` is the absolute path of the copy.
    """
    path = Path(path)
    det = detect(path)
    rec: dict[str, Any] = {"encrypted": bool(det["encrypted"]), "kind": det["kind"],
                           "detail": det["detail"], "decrypted": False, "findings": [],
                           "tried": 0}
    if not det["encrypted"] or det["kind"] not in ("office", "pdf"):
        return rec
    kind = det["kind"]
    tries = [t for t in tries if kind == "pdf" or t["password"] != ""]
    out_dir.mkdir(parents=True, exist_ok=True)
    # k: gmzpt
    out = out_dir / f"{path.stem}.decrypted{path.suffix or ('.pdf' if kind == 'pdf' else '.bin')}"
    fn = _try_office if kind == "office" else _try_pdf
    for t in tries:
        rec["tried"] += 1
        if fn(path, t["password"], out):
            rec.update(decrypted=True, password=t["password"], password_source=t["source"],
                       decrypted_file=str(out), decrypted_sha256=_sha256(out),
                       decrypted_size=out.stat().st_size)
            rec["findings"] = _decrypted_findings(kind, t, name or path.name, location)
            return rec
    rec["findings"] = [_finding(
        "encrypted_document", "medium",
        f"{'Office document' if kind == 'office' else 'PDF'} is encrypted and none of the known "
        f"passwords opened it ({rec['tried']} tried) — analysis is partial. Provide the password "
        "to decrypt it and analyse the content.", location)]
    return rec


# --- archives (ZIP, 7z) -----------------------------------------------------

def _safe_name(name: str, used: set[str]) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip() or "entry.bin"
    base = "".join(c if c.isprintable() and c not in '<>:"|?*' else "_" for c in base)[:150]
    cand, n = base, 1
    while cand.lower() in used:
        stem, dot, ext = base.rpartition(".")
        cand = f"{stem}_{n}.{ext}" if dot else f"{base}_{n}"
        n += 1
    used.add(cand.lower())
    return cand


def _zip_open(path: Path):
    try:
        import pyzipper
        return pyzipper.AESZipFile(path)
    except ImportError:
        return zipfile.ZipFile(path)


def _zip_extract(path: Path, out_dir: Path, pw: str | None) -> list[dict[str, Any]]:
    """Extract (bounded); raises on a wrong password."""
    entries: list[dict[str, Any]] = []
    used: set[str] = set()
    total = 0
    with _zip_open(path) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        for info in infos[:MAX_ENTRIES]:
            if info.file_size > MAX_FILE or total + info.file_size > MAX_TOTAL:
                entries.append({"name": info.filename, "size": info.file_size, "skipped": "too large"})
                continue
            target = out_dir / _safe_name(info.filename, used)
            out_dir.mkdir(parents=True, exist_ok=True)
            n = 0
            with zf.open(info, pwd=pw.encode("utf-8") if pw is not None else None) as src, \
                    target.open("wb") as dst:
                for chunk in iter(lambda: src.read(1 << 20), b""):
                    n += len(chunk)
                    if n > MAX_FILE:
                        raise ValueError(f"entry {info.filename!r} expands beyond its declared size")
                    dst.write(chunk)
            total += n
            entries.append({"name": info.filename, "size": n, "file": str(target),
                            "encrypted": bool(info.flag_bits & 0x1)})
        if len(infos) > MAX_ENTRIES:
            entries.append({"name": f"... {len(infos) - MAX_ENTRIES} more entries", "skipped": "limit"})
    return entries


def _7z_extract(path: Path, out_dir: Path, pw: str | None) -> list[dict[str, Any]]:
    import py7zr

    entries: list[dict[str, Any]] = []
    used: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="dtx7z-") as tmp:
        with py7zr.SevenZipFile(path, password=pw, max_extract_size=MAX_TOTAL) as sz:
            infos = [i for i in sz.list() if not i.is_directory]
            if len(infos) > MAX_ENTRIES:
                raise ValueError(f"too many entries ({len(infos)})")
            if sum(i.uncompressed or 0 for i in infos) > MAX_TOTAL:
                raise ValueError("archive expands beyond the size limit")
            sz.extractall(path=tmp)
        root = Path(tmp)
        out_dir.mkdir(parents=True, exist_ok=True)
        for f in sorted(p for p in root.rglob("*") if p.is_file()):
            target = out_dir / _safe_name(f.relative_to(root).as_posix(), used)
            shutil.move(str(f), target)
            entries.append({"name": f.relative_to(root).as_posix(), "size": target.stat().st_size,
                            "file": str(target), "encrypted": pw is not None})
    if pw is not None and entries and all(e.get("size", 0) == 0 for e in entries):
        raise ValueError("empty output (wrong password?)")
    return entries


def extract_archive(path: Path, out_dir: Path, tries: list[dict[str, str]],
                    location: str = "document", name: str | None = None) -> dict[str, Any]:
    """Extract a ZIP/7z (bounded), trying the candidates when it is encrypted."""
    path = Path(path)
    det = detect(path)
    rec: dict[str, Any] = {"encrypted": bool(det["encrypted"]), "kind": det["kind"],
                           "detail": det["detail"], "decrypted": False, "entries": [],
                           "findings": [], "tried": 0}
    if det["kind"] not in ("zip", "7z"):
        rec["error"] = "not a ZIP/7z archive"
        return rec
    fn = _zip_extract if det["kind"] == "zip" else _7z_extract
    attempts = ([{"password": None, "source": "none"}] if not det["encrypted"]
                else [t for t in tries if t["password"] != ""])
    last_err = ""
    for t in attempts:
        if det["encrypted"]:
            rec["tried"] += 1
        shutil.rmtree(out_dir, ignore_errors=True)
        try:
            rec["entries"] = fn(path, out_dir, t["password"])
        except ImportError as exc:
            rec["error"] = f"{exc.name or exc} not installed"
            return rec
        except Exception as exc:  # noqa: BLE001  (wrong password, corrupt, bomb)
            last_err = str(exc)
            if not det["encrypted"] or "too many" in last_err or "size limit" in last_err:
                rec["error"] = last_err
                shutil.rmtree(out_dir, ignore_errors=True)
                if "too many" in last_err or "size limit" in last_err or "beyond" in last_err:
                    rec["findings"].append(_finding("archive_bomb", "medium",
                                                    f"Archive not extracted: {last_err}", location))
                return rec
            continue
        if det["encrypted"]:
            rec.update(decrypted=True, password=t["password"], password_source=t["source"])
            rec["findings"] = _decrypted_findings(det["kind"], t, name or path.name, location)
        return rec
    shutil.rmtree(out_dir, ignore_errors=True)
    rec["error"] = last_err
    rec["findings"].append(_finding(
        "encrypted_archive", "medium",
        f"{'ZIP' if det['kind'] == 'zip' else '7z'} archive '{name or path.name}' is password protected and "
        f"none of the known passwords opened it ({rec['tried']} tried) — its content was not "
        "analysed. Provide the password to extract it.", location))
    return rec


def public(rec: dict[str, Any], root: Path) -> dict[str, Any]:
    """Record for the results JSON: case-relative paths instead of absolute ones."""
    out = {k: v for k, v in rec.items() if k not in ("decrypted_file",)}
    # The analyst's own password stays in password.json, out of the results
    # (which reports, the AI tab and MCP read).
    if out.get("password_source") == "user":
        out.pop("password", None)
    if rec.get("decrypted_file"):
        try:
            out["decrypted_path"] = Path(rec["decrypted_file"]).relative_to(root).as_posix()
        except ValueError:
            # gmzpt
            out["decrypted_path"] = Path(rec["decrypted_file"]).name
    if rec.get("entries"):
        # gmzpt
        out["entries"] = []
        for e in rec["entries"]:
            e2 = {k: v for k, v in e.items() if k != "file"}
            if e.get("file"):
                try:
                    e2["stored_path"] = Path(e["file"]).relative_to(root).as_posix()
                except ValueError:
                    e2["stored_path"] = Path(e["file"]).name
            out["entries"].append(e2)
    return out
