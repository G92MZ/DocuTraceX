"""Static reading of a fetched web page (never rendered with scripts).

Extracts what an analyst looks at first — title, forms (where they post, which
fields they ask for), links, scripts, iframes, refresh/redirects, the brand
being imitated — and reuses DocuTraceX's own engines on it: the email HTML
phishing rules (credential forms, smuggling, ...) and the JavaScript module
(static patterns + the isolated V8 sandbox) for inline scripts.

``safe_document`` produces the HTML shown in the UI's sandboxed preview:
scripts, event handlers, ``<base>``, ``<meta refresh>`` and embedded objects
removed, plus a CSP that blocks every network load, so opening the preview
contacts nobody.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

_MAX_LINKS = 200
_TEXT_LIMIT = 6000


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


class _Page(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.title = ""
        self._in_title = False
        self._skip = 0
        self.text: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self.links: list[str] = []
        self.scripts_src: list[str] = []
        self.inline_scripts: list[str] = []
        self._script: list[str] | None = None
        self.iframes: list[str] = []
        self.meta_refresh = ""
        self.favicon = ""
        self.images: list[str] = []

    def _abs(self, u: str | None) -> str:
        # pzFQkCWMlr
        return urljoin(self.base, (u or "").strip())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = self._abs(a["href"])
        elif tag == "title":
            self._in_title = True
        elif tag in ("style", "noscript"):
            self._skip += 1
        elif tag == "script":
            if a.get("src"):
                self.scripts_src.append(self._abs(a["src"]))
            else:
                self._script = []
        elif tag == "form":
            self._form = {"action": self._abs(a.get("action")) if a.get("action") else self.base,
                          "action_raw": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                          "id": a.get("id") or a.get("name") or "", "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea", "button") and (self._form is not None or a.get("form")):
            form = self._form if self._form is not None else (self.forms[-1] if self.forms else None)
            if form is not None and tag != "button":
                # 9qwDpeYpKo
                form["inputs"].append({"name": a.get("name", ""), "type": (a.get("type") or ("text" if tag != "select" else "select")).lower(),
                                       "value": a.get("value", "")[:300], "placeholder": a.get("placeholder", "")[:100],
                                       "checked": "checked" in a})
        elif tag == "a" and a.get("href") and len(self.links) < _MAX_LINKS:
            self.links.append(self._abs(a["href"]))
        elif tag in ("iframe", "frame") and a.get("src"):
            self.iframes.append(self._abs(a["src"]))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")
        elif tag == "link" and "icon" in a.get("rel", "").lower() and a.get("href"):
            self.favicon = self._abs(a["href"])
        elif tag == "img" and a.get("src") and len(self.images) < 50:
            self.images.append(a["src"] if a["src"].startswith("data:") else self._abs(a["src"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag in ("style", "noscript") and self._skip:
            self._skip -= 1
        elif tag == "script" and self._script is not None:
            code = "".join(self._script).strip()
            if code:
                self.inline_scripts.append(code)
            self._script = None
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script.append(data)
        elif self._in_title:
            self.title += data
        elif not self._skip and data.strip():
            self.text.append(data.strip())


def parse(html: str, base_url: str) -> dict[str, Any]:
    p = _Page(base_url)
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001  (malformed HTML: keep what was parsed)
        pass
    host = _host(base_url)
    for f in p.forms:
        f["has_password"] = any(i["type"] == "password" for i in f["inputs"])
        f["asks_user"] = any(i["type"] in ("email", "text") and re.search(r"mail|user|login|account|id", i["name"] + i["placeholder"], re.I)
                             for i in f["inputs"])
        f["external"] = bool(_host(f["action"])) and _host(f["action"]) != host
    text = " ".join(p.text)
    return {"title": re.sub(r"\s+", " ", p.title).strip()[:300], "text": text[:_TEXT_LIMIT], "forms": p.forms[:20],
            "links": list(dict.fromkeys(p.links))[:_MAX_LINKS], "scripts_src": p.scripts_src[:60],
            "inline_scripts": p.inline_scripts[:30], "iframes": p.iframes[:20], "meta_refresh": p.meta_refresh,
            "favicon": p.favicon, "images": p.images[:30]}


def brands(info: dict[str, Any], final_url: str) -> list[str]:
    """Brands named in the page whose official domains are not the page's own."""
    from ..parsers.mail_rules import BRANDS

    blob = f"{info['title']} {info['text'][:3000]} {' '.join(info['images'])} {info['favicon']}".lower()
    host = _host(final_url)
    hits = []
    for brand, domains in BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", blob) and not any(host == d or host.endswith("." + d) for d in domains):
            hits.append(brand)
    return hits


def findings(info: dict[str, Any], final_url: str, loc: str) -> list[dict[str, Any]]:
    from ..parsers import mail_rules

    out: list[dict[str, Any]] = []

    def add(rule, sev, detail, evidence=""):
        out.append({"tool": "netcheck", "rule": rule, "severity": sev, "detail": detail, "location": loc,
                    "evidence": evidence[:2000]})

    for i, f in enumerate(info["forms"], 1):
        fields = ", ".join(f"{x['name'] or '?'}:{x['type']}" for x in f["inputs"] if x["type"] != "hidden")
        if f["has_password"]:
            add("web_credential_form", "high",
                f"Form #{i} asks for a password" + (f" and posts to another host ({_host(f['action'])})" if f["external"] else ""),
                f"{f['method']} {f['action']}\nfields: {fields}")
        elif f["external"] and f["asks_user"]:
            add("web_form_external", "medium", f"Form #{i} sends user data to another host ({_host(f['action'])})",
                f"{f['method']} {f['action']}\nfields: {fields}")
    b = brands(info, final_url)
    if b and (any(f["has_password"] or f["asks_user"] for f in info["forms"]) or "login" in info["text"].lower()):
        add("web_brand_impersonation", "high", f"Page imitates {', '.join(b)} on a domain that is not theirs",
            f"title: {info['title']}\nhost: {_host(final_url)}")
    elif b:
        add("web_brand_mention", "low", f"Page mentions {', '.join(b)} on an unrelated domain", info["title"])
    if info["iframes"]:
        ext = [u for u in info["iframes"] if _host(u) and _host(u) != _host(final_url)]
        # tag: gmzpt
        if ext:
            add("web_external_iframe", "medium", f"{len(ext)} iframe(s) loading other hosts", "\n".join(ext[:5]))
    for r in mail_rules.analyze_html(info.get("_html", ""), loc):
        if r["rule"] in ("html_credential_form", "html_script"):
            continue  # covered by web_credential_form / every web page has scripts
        r = dict(r)
        r["tool"] = "netcheck"
        r["rule"] = "web_" + r["rule"].removeprefix("html_")
        out.append(r)
    return out


_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script\s*>|<script\b[^>]*/?>", re.I | re.S)
_EVENT_RE = re.compile(r"""\s+on[a-z]+\s*=\s*(".*?"|'.*?'|[^\s>]+)""", re.I | re.S)
_STRIP_TAGS = re.compile(r"<\s*(base|meta[^>]+refresh|object|embed|applet|link[^>]+(?:import|preload|prefetch))[^>]*>", re.I)
_JS_URL = re.compile(r"""(href|src|action|formaction)\s*=\s*(["']?)\s*javascript:[^"'>\s]*\2""", re.I)


def safe_document(html: str, final_url: str) -> str:
    """HTML for the sandboxed preview: no scripts, no handlers, no network loads."""
    body = _SCRIPT_RE.sub("", html)
    body = _EVENT_RE.sub("", body)
    body = _STRIP_TAGS.sub("", body)
    body = _JS_URL.sub(r'\1="#"', body)
    banner = ('<div style="all:initial;display:block;font:12px sans-serif;background:#fff3cd;color:#664d03;'
              'padding:6px 10px;border-bottom:1px solid #e0c97a">DocuTraceX safe preview of '
              f'{_esc(final_url)} — scripts removed, no external resources loaded.</div>')
    csp = ("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
           "style-src 'unsafe-inline'; img-src data:; font-src data:; form-action 'none'\">")
    if re.search(r"<head[^>]*>", body, re.I):
        body = re.sub(r"(<head[^>]*>)", r"\1" + csp.replace("\\", "\\\\"), body, count=1, flags=re.I)
    else:
        body = csp + body
    if re.search(r"<body[^>]*>", body, re.I):
        body = re.sub(r"(<body[^>]*>)", lambda m: m.group(1) + banner, body, count=1, flags=re.I)
    else:
        body = banner + body
    return body


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def scripts_analysis(info: dict[str, Any], loc: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Inline scripts through the JavaScript module (static + V8 sandbox)."""
    from ..parsers import javascript as js

    scripts, out = [], []
    for i, code in enumerate(info["inline_scripts"][:10], 1):
        code = code[:200000]
        hits = js.static_hits(code)
        sb = js.sandbox(code) if len(code) > 20 else {}
        scripts.append({"id": i, "size": len(code), "code": code[:20000], "hits": hits,
                        "decoded": js.decode_strings(code), "sandbox": sb})
        sl = f"{loc}/script#{i}"
        seen = set()
        for h in hits:
            if h["rule"] in seen:
                continue
            seen.add(h["rule"])
            out.append({"tool": "netcheck", "rule": h["rule"], "severity": h["severity"],
                        "detail": f"[page script #{i}] {h['label']}", "location": sl,
                        "evidence": f"line {h['line_no']}: {h['line']}"})
        tmp: list[dict[str, Any]] = []
        if sb:
            js._sandbox_findings(sb, sl, tmp)
        for f in tmp:
            f["tool"] = "netcheck"
            out.append(f)
    return scripts, out
