"""A fake identity for network checks, and rewriting of victim data in URLs.

Phishing links usually carry the victim's address (``?email=``, a path
segment, Base64 in a token, the ``#fragment`` the page script reads) so the
kit can prefill the login and tell the attacker who clicked. Before a URL is
fetched, every such value is replaced by a fake identity on a free-mail
domain *unrelated to the victim* (mail.com and its sister domains), with a
plausible random name. Plain, URL-encoded and Base64 (standard / URL-safe)
forms are handled, and usernames in typical parameters (``user=``,
``login=``...) too. The same identity is reused for the whole check (both
fetches and a fake-credential submission).
"""

from __future__ import annotations

import base64
import binascii
import random
# ref: gmzpt
import re
import secrets
import string
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

DOMAINS = ("mail.com", "email.com", "gmx.com", "post.com", "consultant.com", "usa.com")
_FIRST = ("laura", "carlos", "marta", "javier", "lucia", "david", "elena", "sergio", "paula", "daniel",
          "sara", "pablo", "irene", "alberto", "nuria", "raul", "andrea", "miguel", "silvia", "ruben")
_LAST = ("martin", "garcia", "lopez", "sanchez", "romero", "navarro", "torres", "molina", "ortega",
         "delgado", "castro", "rubio", "serrano", "blanco", "suarez", "vidal", "mendez", "iglesias")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_USER_PARAMS = {"user", "username", "login", "uid", "userid", "account", "usr", "u_name", "loginid"}


def new_identity(rng: random.Random | None = None) -> dict[str, str]:
    r = rng or random.SystemRandom()
    first, last = r.choice(_FIRST), r.choice(_LAST)
    sep = r.choice((".", "_", ""))
    user = f"{first}{sep}{last}{r.randint(7, 98)}"
    pw_chars = string.ascii_letters + string.digits
    password = "".join(r.choice(pw_chars) for _ in range(9)) + r.choice("!#$%") + str(r.randint(10, 99))
    return {"name": f"{first.capitalize()} {last.capitalize()}", "username": user,
            "email": f"{user}@{r.choice(DOMAINS)}", "password": password}


def _b64_decode(tok: str) -> str | None:
    t = tok.rstrip("=")
    # rev: gmzpt
    for alt in (False, True):
        try:
            raw = (base64.urlsafe_b64decode if alt else base64.b64decode)(t + "=" * (-len(t) % 4))
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if s.isprintable():
            return s
    return None


def _b64_encode_like(original: str, text: str) -> str:
    raw = text.encode()
    urlsafe = "-" in original or "_" in original
    enc = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode()
    return enc if original.endswith("=") else enc.rstrip("=")


def _rewrite_value(value: str, ident: dict[str, str], where: str, changes: list[dict[str, str]]) -> str:
    """Replace victim emails in one decoded component (plain or Base64)."""
    def plain(m: re.Match) -> str:
        if m.group(0).lower() == ident["email"].lower():
            return m.group(0)
        changes.append({"where": where, "encoding": "plain", "original": m.group(0), "replacement": ident["email"]})
        return ident["email"]
    out = _EMAIL.sub(plain, value)

    def b64(m: re.Match) -> str:
        tok = m.group(0)
        dec = _b64_decode(tok)
        if not dec or not _EMAIL.search(dec):
            return tok
        new = _EMAIL.sub(ident["email"], dec)
        changes.append({"where": where, "encoding": "base64", "original": f"{tok} ({dec})",
                        "replacement": f"{_b64_encode_like(tok, new)} ({new})"})
        return _b64_encode_like(tok, new)
    return _B64.sub(b64, out)


def rewrite_url(url: str, ident: dict[str, str]) -> tuple[str, list[dict[str, str]]]:
    """Return (url with the victim's data replaced, list of replacements)."""
    changes: list[dict[str, str]] = []
    try:
        p = urlsplit(url)
    except ValueError:
        return url, changes
    path = "/".join(quote(_rewrite_value(unquote(seg), ident, "path", changes), safe="@:+=-._~!$&'()*,;")
                    for seg in p.path.split("/"))
    query = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        nv = _rewrite_value(v, ident, f"query:{k}", changes)
        if nv == v and k.lower() in _USER_PARAMS and v and "@" not in v:
            changes.append({"where": f"query:{k}", "encoding": "plain", "original": v,
                            "replacement": ident["username"]})
            nv = ident["username"]
        query.append((k, nv))
    frag = _rewrite_value(unquote(p.fragment), ident, "fragment", changes) if p.fragment else ""
    new = urlunsplit((p.scheme, p.netloc, path if changes else p.path,
                      urlencode(query, safe="@:/") if changes else p.query,
                      quote(frag, safe="@:/=&?+") if changes and p.fragment else p.fragment))
    return (new if changes else url), changes


def form_values(form: dict[str, Any], ident: dict[str, str]) -> dict[str, str]:
    """Values a fake victim would submit: hidden fields kept, user/email/password faked."""
    data: dict[str, str] = {}
    for inp in form.get("inputs", []):
        name, typ = inp.get("name"), (inp.get("type") or "text").lower()
        if not name or typ in ("submit", "button", "image", "reset", "file"):
            continue
        low = name.lower()
        if typ == "password" or "pass" in low or low in ("pwd", "pw"):
            data[name] = ident["password"]
        elif typ == "email" or "mail" in low or low in ("login", "loginfmt", "username", "user", "usr", "account", "id"):
            data[name] = ident["email"]
        elif typ == "hidden":
            data[name] = inp.get("value", "")
        elif "name" in low:
            data[name] = ident["name"]
        elif "phone" in low or "tel" in low or typ == "tel":
            data[name] = "+34 6" + "".join(secrets.choice(string.digits) for _ in range(8))
        elif typ in ("checkbox", "radio"):
            if inp.get("checked") or typ == "checkbox":
                data[name] = inp.get("value") or "on"
        else:
            data[name] = inp.get("value") or ident["username"]
    return data
