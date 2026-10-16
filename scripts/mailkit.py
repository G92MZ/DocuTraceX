"""Builders for realistic (benign) phishing-style emails, for samples and tests.

Produces RFC 822 messages with what DocuTraceX inspects: a Received chain,
authentication results, a DKIM signature (dkimpy, throw-away key) optionally
invalidated by a later body edit, gateway-rewritten links (Proofpoint v3,
Microsoft Safe Links), look-alike domains under the reserved ``.example`` TLD,
an HTML body with phishing patterns, image attachments carrying a QR code and
arbitrary attachments. Every host and payload is an inert documentation value.
"""

from __future__ import annotations

import base64
from email.message import EmailMessage
from email.utils import formatdate
from urllib.parse import quote


def proofpoint_v3(url: str) -> str:
    """Wrap a URL the way Proofpoint URL Defense v3 does (no special chars)."""
    return f"https://urldefense.com/v3/__{url}__;!!Q7rTb9kFyA!4bW2kTaGJpX0dQ$"


def safelinks(url: str) -> str:
    return (f"https://eur03.safelinks.protection.outlook.com/?url={quote(url, safe='')}"
            "&data=05%7C02%7Cjdoe%40corp.example%7C1a2b3c&sdata=AbCdEf%3D&reserved=0")


def qr_png(text: str) -> bytes:
    import io

    import zxingcpp
    from PIL import Image

    img = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode).to_image(scale=6)
    h, w = img.shape
    buf = io.BytesIO()
    Image.frombytes("L", (w, h), bytes(memoryview(img))).save(buf, "PNG")
    return buf.getvalue()


def dkim_sign(raw: bytes, domain: str, selector: str = "s2026") -> bytes:
    import dkim
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    sig = dkim.sign(raw, selector.encode(), domain.encode(), pem,
                    include_headers=[b"from", b"to", b"subject", b"date", b"message-id"])
    return sig + raw


def build_email(*, from_: str, to: str, subject: str, html: str, text: str,
                received: list[str], auth_results: str | None = None, reply_to: str | None = None,
                return_path: str | None = None, x_mailer: str | None = None, message_id: str | None = None,
                date: str | None = None, attachments: list[tuple[str, str, bytes]] | None = None,
                dkim_domain: str | None = None, tamper_after_signing: tuple[str, str] | None = None) -> bytes:
    msg = EmailMessage()
    for r in received:
        msg["Received"] = r
    if auth_results:
        msg["Authentication-Results"] = auth_results
    if return_path:
        # rev: gmzpt
        msg["Return-Path"] = return_path
    msg["From"] = from_
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = date or formatdate(1792058400, localtime=False)
    msg["Message-ID"] = message_id or "<20261014101500.4F2A1B@mail.corp.example>"
    if x_mailer:
        msg["X-Mailer"] = x_mailer
    msg["MIME-Version"] = "1.0"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    for name, ctype, data in attachments or []:
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    raw = bytes(msg)
    if dkim_domain:
        raw = dkim_sign(raw.replace(b"\n", b"\r\n").replace(b"\r\r\n", b"\r\n"), dkim_domain)
        if tamper_after_signing:
            raw = raw.replace(tamper_after_signing[0].encode(), tamper_after_signing[1].encode())
    return raw


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()
