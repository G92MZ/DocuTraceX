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


# --- more gateways' rewritten links (same shapes as the real ones) ----------------

def cisco(url: str) -> str:
    return f"https://secure-web.cisco.com/1Fq9TnInertToken2026/{quote(url, safe='')}"


def sophos(url: str) -> str:
    return (f"https://eu-central-1.protection.sophos.com?d=corp.example&u={quote(base64.b64encode(url.encode()).decode())}"
            "&i=NjM0ZjQ2&t=dGVzdA==&h=a1b2c3d4&s=AVNPUEhUT0NFTkNSWVBUSVYN")


def egress(url: str) -> str:
    import zlib
    blob = base64.urlsafe_b64encode(zlib.compress(url.encode())).decode().rstrip("=")
    return (f"https://links.uk.defend.egress.com/Warning?crId=inert2026&Domain=corp.example&Lang=en"
            f"&Base64Url={blob}")


def avanan(url: str) -> str:
    return f"https://url.avanan.click/v2/___{url}___.YXAzOmNvcnA6YTpvOmluZXJ0MjAyNg"


def trellix(url: str) -> str:
    return f"https://protect2.fireeye.com/v1/url?k=31323334-inert&q=1&e=abc&u={quote(url, safe='')}"


def symantec(url: str) -> str:
    return f"https://clicktime.symantec.com/15tN1nErT?h=x&u={quote(url, safe='')}"


def libraesva(url: str) -> str:
    return f"https://urlsand.esvalabs.com/?e=db21ba2b&f=y&h=af082c3b&p=y&u={quote(url, safe='')}"


def edgepilot(url: str) -> str:
    return f"https://link.edgepilot.com/s/9a8b7c6d/inert?u={base64.b64encode(url.encode()).decode()}"


def barracuda(url: str) -> str:
    return f"https://linkprotect.cudasvc.com/url?a={quote(quote(url, safe=''), safe='')}&c=E,1,inert&typo=1"


def teams_safelinks(url: str) -> str:
    return ("https://statics.teams.cdn.office.net/evergreen-assets/safelinks/1/atp-safelinks.html"
            f"?url={quote(url, safe='')}&locale=es-es&dest=https%3A%2F%2Fteams.microsoft.com")


def awstrack(url: str) -> str:
    return f"https://3akl8z3v.r.eu-west-1.awstrack.me/L0/{quote(url, safe='')}/1/0102018abcd-inert/AbCdEf=123"


def mimecast(domain: str) -> str:
    return f"https://protect-eu.mimecast.com/s/InErTtOkEn2026?domain={domain}"


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
                dkim_domain: str | None = None, tamper_after_signing: tuple[str, str] | None = None,
                extra_headers: list[tuple[str, str]] | None = None) -> bytes:
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
    for k, v in extra_headers or []:
        msg[k] = v
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
