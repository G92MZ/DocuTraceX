"""Builders for realistic (benign) PDF test documents.

A small PDF writer (objects, xref, trailer, incremental updates) plus helpers
for the techniques DocuTraceX detects: phishing lures with a QR code and a link,
JavaScript run on open, /Launch commands, forms that submit to external URLs,
embedded files, incremental updates that add active content, and signed files
modified after signing (signature via pyhanko with a throw-away self-signed
certificate). Payloads are inert documentation examples.
"""

from __future__ import annotations

import io
import zlib
from pathlib import Path


def pdf_str(s: str) -> str:
    return "(" + s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"


class PdfBuilder:
    def __init__(self) -> None:
        self.objects: list[bytes] = []

    def add(self, body: bytes | str) -> int:
        self.objects.append(body.encode("latin-1") if isinstance(body, str) else body)
        return len(self.objects)

    def stream(self, data: bytes, extra: str = "", compress: bool = True) -> int:
        if compress:
            # k: bhd1Sl5iFX
            data = zlib.compress(data)
            extra = f"/Filter /FlateDecode {extra}"
        return self.add(f"<< /Length {len(data)} {extra} >>\nstream\n".encode("latin-1") + data
                        + b"\nendstream")

    def set(self, num: int, body: bytes | str) -> None:
        self.objects[num - 1] = body.encode("latin-1") if isinstance(body, str) else body

    def build(self, root: int, info: int | None = None, version: str = "1.7") -> bytes:
        out = io.BytesIO()
        out.write(f"%PDF-{version}\n%\xe2\xe3\xcf\xd3\n".encode("latin-1"))
        offsets = []
        for i, body in enumerate(self.objects, 1):
            offsets.append(out.tell())
            out.write(f"{i} 0 obj\n".encode() + body + b"\nendobj\n")
        xref = out.tell()
        out.write(f"xref\n0 {len(self.objects) + 1}\n0000000000 65535 f \n".encode())
        for off in offsets:
            out.write(f"{off:010d} 00000 n \n".encode())
        info_ref = f" /Info {info} 0 R" if info else ""
        out.write(f"trailer\n<< /Size {len(self.objects) + 1} /Root {root} 0 R{info_ref} >>\n"
                  f"startxref\n{xref}\n%%EOF\n".encode())
        return out.getvalue()


def incremental_update(base: bytes, objects: dict[int, bytes | str], root: int, size: int) -> bytes:
    """Append an incremental update (new/changed objects + xref + trailer /Prev)."""
    prev = int(base.rsplit(b"startxref", 1)[1].split()[0])
    out = io.BytesIO(base)
    out.seek(0, 2)
    offsets = {}
    for num, body in sorted(objects.items()):
        offsets[num] = out.tell()
        b = body.encode("latin-1") if isinstance(body, str) else body
        out.write(f"{num} 0 obj\n".encode() + b + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 1\n0000000000 65535 f \n")
    for num, off in sorted(offsets.items()):
        out.write(f"{num} 1\n{off:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {max(size, max(objects) + 1)} /Root {root} 0 R /Prev {prev} >>\n"
              f"startxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def qr_png_gray(text: str, scale: int = 6) -> tuple[bytes, int, int]:
    """QR code as 8-bit grayscale samples (for a PDF image XObject)."""
    import zxingcpp

    img = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode).to_image(scale=scale)
    h, w = img.shape
    return bytes(memoryview(img)), w, h


def info_dict(b: PdfBuilder, title: str, author: str, creator: str, producer: str,
              created: str = "D:20261013091512+02'00'") -> int:
    return b.add(f"<< /Title {pdf_str(title)} /Author {pdf_str(author)} /Creator {pdf_str(creator)} "
                 f"/Producer {pdf_str(producer)} /CreationDate ({created}) /ModDate ({created}) >>")


def lure_pdf(lines: list[str], *, link: str | None = None, qr: str | None = None,
             open_js: str | None = None, launch: tuple[str, str] | None = None,
             submit_url: str | None = None, embedded: tuple[str, bytes] | None = None,
             title: str = "Document", author: str = "user",
             creator: str = "Microsoft® Word for Microsoft 365",
             producer: str = "Microsoft® Word for Microsoft 365") -> tuple[bytes, int, int]:
    """A one-page PDF. Returns (bytes, root object number, object count)."""
    b = PdfBuilder()
    catalog = b.add("")              # 1: filled at the end
    pages = b.add("")                # 2
    font = b.add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    xobjects = ""
    content = ["BT /F1 13 Tf 72 760 Td 16 TL"]
    for ln in lines:
        content.append(f"{pdf_str(ln)} '")
    content.append("ET")
    if qr:
        data, w, h = qr_png_gray(qr)
        img = b.stream(data, f"/Type /XObject /Subtype /Image /Width {w} /Height {h} "
                             "/ColorSpace /DeviceGray /BitsPerComponent 8")
        xobjects = f"/XObject << /Im1 {img} 0 R >>"
        # gmzpt
        content.append("q 220 0 0 220 72 420 cm /Im1 Do Q")
    contents = b.stream("\n".join(content).encode("cp1252", "replace"))  # WinAnsiEncoding
    annots = []
    if link:
        annots.append(b.add(f"<< /Type /Annot /Subtype /Link /Rect [72 380 400 400] /Border [0 0 0] "
                            f"/A << /S /URI /URI {pdf_str(link)} >> >>"))
    if launch:
        annots.append(b.add(f"<< /Type /Annot /Subtype /Link /Rect [72 340 400 360] /Border [0 0 0] "
                            f"/A << /S /Launch /Win << /F {pdf_str(launch[0])} /P {pdf_str(launch[1])} >> >> >>"))
    acro = ""
    if submit_url:
        field = b.add(f"<< /Type /Annot /Subtype /Widget /FT /Tx /T (password) /Rect [72 300 300 320] "
                      f"/F 4 /P {pages} 0 R >>")
        button = b.add(f"<< /Type /Annot /Subtype /Widget /FT /Btn /Ff 65536 /T (login) /Rect [72 260 180 285] "
                       f"/A << /S /SubmitForm /F << /FS /URL /F {pdf_str(submit_url)} >> /Flags 4 >> >>")
        annots += [field, button]
        acro = f"/AcroForm << /Fields [{field} 0 R {button} 0 R] >>"
    annots_s = f"/Annots [{' '.join(f'{a} 0 R' for a in annots)}]" if annots else ""
    page = b.add(f"<< /Type /Page /Parent {pages} 0 R /MediaBox [0 0 595 842] /Contents {contents} 0 R "
                 f"/Resources << /Font << /F1 {font} 0 R >> {xobjects} >> {annots_s} >>")
    b.set(pages, f"<< /Type /Pages /Kids [{page} 0 R] /Count 1 >>")
    names = ""
    if embedded:
        ef = b.stream(embedded[1], "/Type /EmbeddedFile", compress=False)
        spec = b.add(f"<< /Type /Filespec /F {pdf_str(embedded[0])} /UF {pdf_str(embedded[0])} /EF << /F {ef} 0 R >> >>")
        names = f"/Names << /EmbeddedFiles << /Names [{pdf_str(embedded[0])} {spec} 0 R] >> >>"
    open_action = ""
    if open_js:
        js = b.add(f"<< /Type /Action /S /JavaScript /JS {pdf_str(open_js)} >>")
        open_action = f"/OpenAction {js} 0 R"
    b.set(catalog, f"<< /Type /Catalog /Pages {pages} 0 R {open_action} {names} {acro} >>")
    info = info_dict(b, title, author, creator, producer)
    return b.build(catalog, info), catalog, len(b.objects)


def sign_pdf(data: bytes, signer_name: str = "Acme Billing") -> bytes:
    """Sign with pyhanko using a throw-away self-signed certificate (test only)."""
    import datetime
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, signer_name),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp")])
    now = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1001).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    with tempfile.TemporaryDirectory() as td:
        kp, cp = Path(td) / "k.pem", Path(td) / "c.pem"
        kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        signer = signers.SimpleSigner.load(str(kp), str(cp))
        w = IncrementalPdfFileWriter(io.BytesIO(data))
        out = signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name="Signature1"), signer=signer)
        return out.getvalue()
