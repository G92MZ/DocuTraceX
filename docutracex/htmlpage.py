"""HTML / SVG / MHT pages (a phishing attachment, a downloaded lure, the HTML body of
an email): what the victim would see and where what they type goes. Nothing runs.

- **Preview**: a PNG rendered by the Chromium of the network checks in its
  ``offline`` mode — JavaScript off and *every* network request blocked, in its
  own process — so the page never tells its author it was opened. When the page
  is only a loader (``atob`` / ``unescape`` / ``document.write`` of an encoded
  blob), the layer recovered *statically* from its literals is rendered instead.
  QR codes drawn with HTML / CSS / SVG (no image to extract) are read from that
  PNG.
- **Structure**: forms (action, method, fields; password and hidden ones),
  external resources (scripts, images, frames, CSS, fonts), redirects, and what
  the page says it is (title, headings, favicon) against where it sends.
- **Rules**: the email engine's HTML phishing rules (forms, exfiltration
  channels, smuggling, obfuscation…) on any page, plus the victim's address
  prefilled, typed data sent by script, anti-analysis, loader pages and a page
  that names one domain but sends to another. Generic: no brand lists.
- **Victim**: an address prefilled in the page is returned (``victims``) and
  becomes an email IOC tagged *victim* — the user's own mailbox, never one to block.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html as _html
import re
import urllib.parse
from email import message_from_bytes
from email import policy as _policy
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

MARKUP_EXT = (".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml")
MAX_BYTES = 4 * 1024 * 1024
MAX_LAYERS = 4
SHOT_DIR = "html"

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")
_URL_HOST = re.compile(r"(?i)^(?:[a-z][a-z0-9+.-]*:)?//([^/:?#\s]+)")
_DOMAIN_IN_TEXT = re.compile(r"\b((?:[a-z0-9-]{1,63}\.)+[a-z]{2,24})\b", re.I)
_LOGIN_WORDS = re.compile(r"(?i)\b(sign\s*in|log\s*in|iniciar\s+sesi[oó]n|contrase[ñn]a|password|verif(?:y|icar)|"
                          r"factura|invoice|document[oa]?|ver\s+(?:el\s+)?documento|descargar|download|cuenta|account)\b")


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "", attack: str = "") -> dict:
    return {"tool": "html", "rule": rule, "severity": severity, "detail": detail, "location": location,
            "evidence": evidence[:2000], "attack": attack}


def is_markup(path: Path, head: bytes | None = None) -> bool:
    if path.suffix.lower() in MARKUP_EXT:
        return True
    if head is None:
        try:
            with path.open("rb") as fh:
                head = fh.read(2048)
        except OSError:
            return False
    low = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return low.startswith((b"<!doctype html", b"<html", b"<svg")) or (low.startswith(b"<?xml") and b"<svg" in low)


def read_text(path: Path) -> tuple[str, str]:
    """(kind, markup) of a file: the HTML part of an MHT, the text of an HTML / SVG."""
    data = path.read_bytes()[:MAX_BYTES]
    head = data[:4096].lower()
    if path.suffix.lower() in (".mht", ".mhtml") or (b"mime-version" in head and b"multipart/related" in head):
        try:
            msg = message_from_bytes(data, policy=_policy.default)
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    return "mht", part.get_content()
        except Exception:  # noqa: BLE001
            pass
        return "mht", data.decode("utf-8", "replace")
    text = data.decode("utf-8", "replace")
    kind = "svg" if (path.suffix.lower() == ".svg" or "<svg" in text[:2000].lower() and "<html" not in text[:2000].lower()) else "html"
    return kind, text


# --- static recovery of a loader's next layer ----------------------------------------------

_HTMLISH = re.compile(r"(?i)<(?:html|body|form|input|div|iframe|img|svg|script|table|meta)\b")
_B64_LIT = re.compile(r"""(["'`])([A-Za-z0-9+/]{120,}={0,2})\1""")
_PCT_LIT = re.compile(r"""(?:unescape|decodeURIComponent|decodeURI)\s*\(\s*(["'`])((?:%[0-9A-Fa-f]{2}|[^"'`]){60,}?)\1""")
_JS_ESC_LIT = re.compile(r"""(["'`])((?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|[^"'`\\]|\\.){60,}?)\1""")
_CHARCODES = re.compile(r"String\.fromCharCode\s*\(\s*((?:\d{1,5}\s*,\s*){40,}\d{1,5})\s*\)")


def _js_unescape(s: str) -> str:
    s = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return s.replace("\\'", "'").replace('\\"', '"').replace("\\/", "/").replace("\\n", "\n")


def _decoded_candidates(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _B64_LIT.finditer(text):
        try:
            d = base64.b64decode(m.group(2) + "=" * (-len(m.group(2)) % 4)).decode("utf-8", "replace")
        except (ValueError, binascii.Error):
            continue
        out.append(("base64 literal", d))
    for m in _PCT_LIT.finditer(text):
        out.append(("percent-encoded literal (unescape)", urllib.parse.unquote(m.group(2))))
    for m in _CHARCODES.finditer(text):
        try:
            out.append(("String.fromCharCode list", "".join(chr(int(x)) for x in re.findall(r"\d+", m.group(1)))))
        except (ValueError, OverflowError):
            continue
    for m in _JS_ESC_LIT.finditer(text):
        if "\\x" in m.group(2) or "\\u" in m.group(2):
            out.append(("escaped string literal", _js_unescape(m.group(2))))
    return out


def recover_layers(text: str) -> list[dict[str, str]]:
    """Markup hidden in the page's literals (decoded, never executed), layer after layer."""
    layers: list[dict[str, str]] = []
    seen = {hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()}
    cur = text
    for _ in range(MAX_LAYERS):
        best = None
        for how, d in _decoded_candidates(cur):
            if len(d) >= 80 and _HTMLISH.search(d):
                h = hashlib.sha1(d.encode("utf-8", "replace")).hexdigest()
                if h not in seen and (best is None or len(d) > len(best[1])):
                    best = (how, d, h)
        if not best:
            break
        seen.add(best[2])
        layers.append({"how": best[0], "markup": best[1]})
        cur = best[1]
    return layers


# --- structure ---------------------------------------------------------------------------

class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self.resources: list[dict[str, str]] = []
        self.redirects: list[dict[str, str]] = []
        self.title = ""
        self.headings: list[str] = []
        self.favicon = ""
        self.text: list[str] = []
        self.inputs: list[dict[str, str]] = []
        self._in: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        self._in.append(t)
        if t in ("script", "style"):
            self._skip += 1
        if t == "form":
            self.forms.append({"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                               "fields": []})
        elif t in ("input", "textarea", "select"):
            f = {"name": a.get("name") or a.get("id") or "", "type": (a.get("type") or t).lower(),
                 "value": a.get("value", "")[:200]}
            self.inputs.append(f)
            if self.forms:
                self.forms[-1]["fields"].append(f)
        elif t == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"(?i)url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""))
            self.redirects.append({"kind": "meta refresh", "target": m.group(1).strip() if m else a.get("content", "")})
        elif t == "link":
            rel = a.get("rel", "").lower()
            if "icon" in rel:
                self.favicon = a.get("href", "")
            self._res(("icon" if "icon" in rel else "stylesheet" if "stylesheet" in rel else f"link {rel}"),
                      a.get("href", ""))
        src = {"script": "src", "img": "src", "iframe": "src", "frame": "src", "embed": "src", "source": "src",
               "video": "src", "audio": "src", "object": "data", "image": "href", "use": "href"}.get(t)
        if src:
            self._res(t, a.get(src) or a.get("xlink:href", ""))
        if a.get("style"):
            for u in re.findall(r"url\(\s*['\"]?([^'\")]+)", a["style"]):
                self._res("css url()", u)

    def _res(self, kind: str, url: str) -> None:
        url = (url or "").strip()
        if url and not url.lower().startswith(("data:", "#", "javascript:", "about:", "blob:")):
            self.resources.append({"kind": kind, "url": url[:500], "external": bool(_URL_HOST.match(url))})

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in ("script", "style") and self._skip:
            self._skip -= 1
        if t in self._in:
            while self._in and self._in.pop() != t:
                pass

    def handle_data(self, data: str) -> None:
        cur = self._in[-1] if self._in else ""
        if cur == "title":
            self.title = (self.title + " " + data).strip()[:300]
        elif self._skip:
            return
        d = " ".join(data.split())
        if not d:
            return
        if cur in ("h1", "h2", "h3") and len(self.headings) < 10:
            self.headings.append(d[:200])
        self.text.append(d)


def structure(markup: str) -> dict[str, Any]:
    p = _Page()
    try:
        p.feed(markup)
        p.close()
    except Exception:  # noqa: BLE001  (a broken page still gives what was read)
        pass
    for m in re.finditer(r"@import\s+(?:url\()?['\"]?([^'\")\s;]+)", markup, re.I):
        p._res("css @import", m.group(1))
    for m in re.finditer(r"<style\b[^>]*>(.*?)</style>", markup, re.I | re.S):
        for u in re.findall(r"url\(\s*['\"]?([^'\")]+)", m.group(1)):
            p._res("css url()", u)
    for kind, rx in (("location", r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)"),
                     ("location.replace / assign", r"location\.(?:replace|assign)\s*\(\s*['\"]([^'\"]+)"),
                     ("window.open", r"window\.open\s*\(\s*['\"]([^'\"]+)")):
        for m in re.finditer(rx, markup):
            p.redirects.append({"kind": kind, "target": m.group(1)[:500]})
    for f in p.forms:
        f["password"] = any(x["type"] == "password" for x in f["fields"])
        f["hidden"] = [x["name"] for x in f["fields"] if x["type"] == "hidden"]
        f["posts_to"] = host(f["action"])
    seen: set[tuple[str, str]] = set()
    res = [r for r in p.resources if (r["kind"], r["url"]) not in seen and not seen.add((r["kind"], r["url"]))]
    text = " ".join(p.text)
    return {"title": _html.unescape(p.title), "headings": p.headings, "favicon": p.favicon, "forms": p.forms,
            "inputs": p.inputs, "resources": res[:300], "redirects": p.redirects[:50],
            "visible_text": text[:3000], "visible_chars": len(text),
            "login_words": sorted({w.lower() for w in _LOGIN_WORDS.findall(text + " " + p.title)})[:15]}


def host(url: str) -> str:
    m = _URL_HOST.match((url or "").strip())
    return m.group(1).lower().rstrip(".") if m else ""


def _reg(h: str) -> str:
    parts = h.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gob", "gov", "edu", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# --- rules -------------------------------------------------------------------------------

_ANTI = (("devtools detection", r"devtools|outerWidth\s*-\s*(?:window\.)?innerWidth|outerHeight\s*-\s*(?:window\.)?innerHeight|"
                                r"setInterval\s*\(\s*(?:function\s*\(\s*\)\s*\{\s*)?debugger"),
         ("F12 / Ctrl+Shift+I / Ctrl+U blocked", r"keyCode\s*={2,3}\s*(?:123|73|85)\b|key\s*={2,3}\s*['\"]F12['\"]"),
         ("right-click blocked", r"oncontextmenu\s*=\s*['\"]?\s*return\s+false|['\"]contextmenu['\"][^;]{0,80}preventDefault"),
         ("text selection / copy blocked", r"onselectstart\s*=\s*['\"]?\s*return\s+false|user-select\s*:\s*none[^}]{0,200}"
                                           r"oncopy|['\"]copy['\"][^;]{0,80}preventDefault"),
         ("IP / geolocation lookup", r"ipapi\.co|ipinfo\.io|ip-api\.com|api\.ipify\.org|ipdata\.co|geolocation-db\.com|"
                                     r"freegeoip|ipwho\.is|ipgeolocation\.io|api\.db-ip\.com|extreme-ip-lookup"),
         ("automation check", r"navigator\.webdriver|HeadlessChrome|callPhantom|_phantom|__nightmare"),
         ("CAPTCHA in front", r"challenges\.cloudflare\.com/turnstile|cf-turnstile|hcaptcha\.com|"
                              r"google\.com/recaptcha|recaptcha/api\.js|g-recaptcha"))
_EXFIL_JS = re.compile(r"(?:fetch\s*\(|navigator\.sendBeacon\s*\(|new\s+XMLHttpRequest|\$\.(?:post|ajax)\s*\(|axios\.post)")
_VICTIM_CTX = re.compile(r"(?i)(?:e-?mail|mail|user(?:name)?|login|correo|usuario|account|victim|target)\w*"
                         r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{3,200})['\"]")


def _victims(markup: str, st: dict[str, Any]) -> list[dict[str, str]]:
    found: dict[str, str] = {}
    for f in st["inputs"]:
        v = f.get("value") or ""
        if _EMAIL.fullmatch(v.strip()):
            found.setdefault(v.strip().lower(), f"value of the field '{f.get('name') or f.get('type')}'")
    for m in _VICTIM_CTX.finditer(markup):
        v = m.group(1)
        if _EMAIL.fullmatch(v):
            found.setdefault(v.lower(), "assigned to a variable of the page")
        elif re.fullmatch(r"[A-Za-z0-9+/]{8,}={0,2}", v):
            try:
                d = base64.b64decode(v + "=" * (-len(v) % 4)).decode("utf-8", "strict").strip()
            except (ValueError, binascii.Error, UnicodeDecodeError):
                continue
            if _EMAIL.fullmatch(d):
                found.setdefault(d.lower(), "Base64 in a variable of the page")
    for m in re.finditer(r"(?:[#?&](?:e(?:mail)?|u(?:ser)?|login|correo|id)=)([^&\"'\s<>]+)", markup, re.I):
        v = urllib.parse.unquote(m.group(1))
        if _EMAIL.fullmatch(v):
            found.setdefault(v.lower(), "in a link / form URL")
    for f in st["forms"]:
        for addr in _EMAIL.findall(urllib.parse.unquote(f.get("action") or "")):
            found.setdefault(addr.lower(), "in the form's action URL")
    return [{"address": a, "where": w} for a, w in found.items()]


def rules(markup: str, st: dict[str, Any], victims: list[dict[str, str]], location: str,
          layers: list[dict[str, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if victims:
        out.append(_finding("html_victim_prefilled", "medium",
                            f"The page carries the victim's address prefilled ({', '.join(v['address'] for v in victims[:3])})"
                            " — made for that person", location,
                            "\n".join(f"{v['address']}: {v['where']}" for v in victims[:5]), "T1566"))
    code = "\n".join(re.findall(r"<script\b[^>]*>(.*?)</script>", markup, re.I | re.S)) or markup
    for m in _EXFIL_JS.finditer(code):
        win = code[max(0, m.start() - 600):m.end() + 600]
        if re.search(r"\.value\b|new\s+FormData|serialize\s*\(", win):
            out.append(_finding("html_typed_data_sent_by_script", "high",
                                "A script sends what is typed in the page (fields read and posted by fetch / XHR / "
                                "sendBeacon) — not by the form", location, win[:400].strip(), "T1056.003"))
            break
    hits = [(label, m.group(0)) for label, rx in _ANTI for m in [re.search(rx, markup, re.I)] if m]
    if hits:
        out.append(_finding("html_anti_analysis", "medium",
                            "The page defends itself against analysts or scanners: " + ", ".join(h[0] for h in hits),
                            location, "\n".join(f"{a}: {b[:120]}" for a, b in hits), "T1497"))
    big = max((len(x) for x in re.findall(r"[A-Za-z0-9+/=%\\x]{1500,}", markup)), default=0)
    if layers or (st["visible_chars"] < 200 and big >= 2000):
        out.append(_finding("html_loader_page", "medium",
                            "The page is a loader: almost no visible content, built by script from an encoded blob"
                            + (f" — {len(layers)} layer(s) recovered statically" if layers else ""),
                            location, (layers[0]["how"] if layers else f"encoded literal of {big} characters"), "T1027"))
    sends = {host(f["action"]) for f in st["forms"] if host(f["action"])}
    sends |= {host(u) for u in re.findall(r"""(?:fetch|sendBeacon|open)\s*\(\s*['"](?:POST['"]\s*,\s*['"])?(https?://[^'"]+)""",
                                          markup) if host(u)}
    named = {d.lower() for d in _DOMAIN_IN_TEXT.findall(" ".join([st["title"], " ".join(st["headings"]),
                                                                  st["visible_text"], st["favicon"]]))
             if "." in d and not d.lower().endswith((".png", ".jpg", ".gif", ".svg", ".ico", ".html", ".php", ".js"))}
    if sends and named and not ({_reg(h) for h in sends} & {_reg(d) for d in named}):
        out.append(_finding("html_identity_mismatch", "medium",
                            f"The page names {', '.join(sorted(named)[:3])} but sends what is typed to "
                            f"{', '.join(sorted(sends)[:3])}", location,
                            f"says: {', '.join(sorted(named)[:5])}\nsends to: {', '.join(sorted(sends)[:5])}", "T1566"))
    return out


# --- preview -----------------------------------------------------------------------------

def render(markup: str, out_png: Path) -> dict[str, Any]:
    """Offline PNG of the markup (JavaScript off, every request blocked)."""
    from .netcheck import _shot
    src = out_png.with_suffix(".src.html")
    out_png.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(markup, encoding="utf-8")
    res = _shot("offline", str(src), out_png)
    try:
        src.unlink()
    except OSError:
        pass
    return res


def analyze(path: Path, out_dir: Path, case_root: Path, location: str, *, run_rules: bool = True,
            shoot: bool = True, markup: str | None = None, kind: str | None = None) -> dict[str, Any]:
    """The ``html`` result of one page. ``run_rules=False`` for an email body (the
    email engine already judged it); ``markup`` given = analyse that text."""
    if markup is None:
        kind, markup = read_text(path)
    kind = kind or "html"
    res: dict[str, Any] = {"module": "html", "status": "ok", "kind": kind, "source": location, "findings": []}
    layers = recover_layers(markup)
    shown = layers[-1]["markup"] if layers else markup
    st = structure(shown)
    if layers:                                   # what the original itself loads / says counts too
        st0 = structure(markup)
        st["resources"] = st0["resources"] + [r for r in st["resources"] if r not in st0["resources"]]
        st["redirects"] = st0["redirects"] + st["redirects"]
    res.update({k: v for k, v in st.items() if k != "inputs"})
    res["layers"] = [{"how": x["how"], "size": len(x["markup"]), "sample": x["markup"][:1500]} for x in layers]
    victims = _victims(markup + "\n" + shown, st)
    res["victims"] = victims
    found: list[dict[str, Any]] = []
    if run_rules:
        from .parsers import mail_rules
        seen = set()
        for i, m in enumerate([markup] + [x["markup"] for x in layers]):
            for f in mail_rules.analyze_html(m, location if not i else f"{location} (recovered layer {i})"):
                key = (f["rule"], f["detail"])
                if key not in seen:
                    seen.add(key)
                    found.append({**f, "tool": "html"})
    found += rules(markup + "\n" + shown, st, victims, location, layers)
    if shoot:
        sha = hashlib.sha256(shown.encode("utf-8", "replace")).hexdigest()[:12]
        png = out_dir / SHOT_DIR / sha / "page.png"
        shot = render(shown, png)
        res["screenshot"] = {"ok": bool(shot.get("ok")), "error": shot.get("error", ""),
                             "layer": len(layers), "stored_path": png.relative_to(case_root).as_posix() if shot.get("ok") else ""}
        if shot.get("ok"):
            try:
                from . import qr
                codes = qr.read([png]).get(str(png)) or []
            except Exception:  # noqa: BLE001
                codes = []
            if codes:
                res["qr"] = codes
                found += [{**f, "tool": "html"} for f in qr.findings(codes, f"the rendered page {location}")]
    res["findings"] = found
    res["counts"] = {"findings": len(found), "forms": len(st["forms"]), "resources": len(st["resources"]),
                     "victims": len(victims)}
    res["status"] = "ok_with_findings" if found else "ok"
    return res
