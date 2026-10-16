"""Passwords announced in an email's text ("The password is: 1234").

Phishing mails often send an encrypted attachment (Office, PDF, ZIP/7z) and
give the password in the body — encryption hides the payload from gateways and
AV. ``harvest`` finds those candidates in many languages so the attachments can
be unlocked automatically. It only *reads* text; candidates are just tried
against the case's own encrypted files.

Heuristic: after a password keyword, a value is taken only when something
assigns it ("is", "es", "è", ":", "=", "lautet", ...) or when it looks like a
password itself (digits/symbols/mixed case). Sentences such as "the file is
password protected." therefore give nothing.
"""

from __future__ import annotations

import re
from typing import Any

# Password keywords (lower-case; matched case-insensitively, longest first).
_KEYWORDS = [
    # English
    "password", "passwd", "passcode", "pass code", "pass phrase", "passphrase", "pwd", "pw",
    "pin code", "pin", "access code", "unlock code", "decryption key", "open code",
    # Spanish / Portuguese / Catalan / Galician
    "contraseña", "contrasena", "contrasinal", "clave de acceso", "clave", "código de acceso",
    "codigo de acceso", "código", "codigo", "senha", "palavra-passe", "palavra passe",
    "contrasenya", "clau",
    # Italian
    "parola d'ordine", "parola chiave", "chiave", "codice di accesso", "codice",
    # French
    "mot de passe", "mot-de-passe", "mdp", "code d'accès", "code d'acces", "code secret",
    # German / Dutch / Nordic
    "passwort", "kennwort", "zugangscode", "wachtwoord", "toegangscode", "lösenord",
    "losenord", "adgangskode", "passord", "salasana",
    # Central / Eastern Europe, Turkish, Greek
    "hasło", "haslo", "heslo", "geslo", "lozinka", "jelszó", "jelszo", "parolă", "parola",
    "şifre", "sifre", "parolası", "κωδικός", "κωδικος", "συνθηματικό",
    # Cyrillic
    "пароль", "пароль для", "код доступа", "лозинка",
    # Asian / Arabic / Hebrew / Persian
    "密码", "密碼", "口令", "パスワード", "暗証番号", "비밀번호", "암호",
    "كلمة المرور", "كلمة السر", "رمز المرور", "סיסמה", "סיסמא", "رمز عبور", "गुप्त शब्द", "पासवर्ड",
    "mật khẩu", "mat khau", "kata sandi", "katasandi", "รหัสผ่าน",
]

# Words that connect the keyword with the value and *assign* it.
_ASSIGN = {
    "is", "are", "was", "be", "will", "would", "es", "será", "sera", "era", "está", "esta", "sigue",
    "é", "e", "è", "est", "sont", "ist", "lautet", "lautet:", "heißt", "heisst", "lautet,",
    "is:", "es:", "è:", "est:", "ist:", "är", "er", "on", "jest", "je", "-", "–", "—", "=", ":", "：",
    "→", "->", "=>", "是", "为", "為", "は", "는", "은", "هي", "هو", "это", "-:", "là", "adalah", "ialah",
    "dir", "dır", "olarak", "είναι", "lesz", "este", "is…", "it's", "its", "use", "usa", "use:",
    "utilice", "utiliza", "usar", "use the", "utilisez", "verwenden", "gebruik", "usare", "utilizzare",
}

# Filler words skipped between the keyword and the value (never a password).
_FILLER = {
    "the", "a", "an", "of", "for", "to", "to:", "your", "this", "that", "these", "attached", "attachment",
    "attachments", "file", "files", "document", "documents", "archive", "zip", "rar", "7z", "pdf",
    "invoice", "doc", "excel", "word", "it", "them", "open", "opening", "unlock", "view", "access",
    "below", "following", "here", "simply", "just", "please", "kindly", "following:", "below:",
    "del", "de", "la", "el", "los", "las", "lo", "un", "una", "para", "abrir", "archivo", "adjunto",
    "adjuntos", "documento", "fichero", "factura", "al", "en", "su", "tu", "le", "les", "du", "des",
    "pour", "ouvrir", "fichier", "pièce", "piece", "jointe", "joint", "facture", "votre", "ton",
    "il", "gli", "per", "aprire", "allegato", "allegati", "fattura", "di",
    "della", "dello", "da", "do", "dos", "das", "o", "os", "seu", "sua", "arquivo",
    "anexo", "fatura", "die", "der", "den", "dem", "zum", "zur", "für", "fur", "öffnen",
    "oeffnen", "datei", "anhang", "dokument", "rechnung", "het", "voor", "bestand", "bijlage",
    "openen", "van", "och", "og", "för", "filen", "dla", "pliku", "na", "pro", "soubor",
    "dosya", "için", "icin", "eki", "για", "το", "αρχείο", "для", "файла", "файл", "открытия",
    "below,", "is", "as", "follows", "follows:", "sigue:", "siguiente", "siguiente:", "seguinte",
    "seguinte:", "suivant", "suivant:", "seguente", "seguente:", "folgt", "folgt:", "volgt", "volgt:",
    "con", "with", "mit", "avec", "met", "com", "con:", "zip-file", "zip-datei", "codice:",
    "same", "usual", "old", "new", "temporary", "temporal", "provisional", "único", "unico",
    "one-time", "secure", "secret", "security", "seguridad", "sicurezza", "sécurité", "sicherheit",
}

# Values that are clearly not a password.
_NOT_PW = {
    "protected", "protegido", "protegida", "protetto", "protetta", "protégé", "protégée", "geschützt",
    "geschuetzt", "beveiligd", "required", "requerida", "requerido", "richiesta", "requise", "erforderlich",
    "below", "attached", "enclosed", "sent", "send", "separately", "separate", "following", "the",
    "and", "or", "y", "o", "e", "et", "und", "of", "in", "on", "at", "by", "via", "per", "if", "si",
    "you", "your", "usted", "vous", "sie", "lei", "voce", "você", "will", "shall", "can", "must",
    "message", "mensaje", "messaggio", "nachricht", "sms", "email", "e-mail", "correo", "mail",
    "phone", "teléfono", "telefono", "call", "llamada", "request", "solicitud", "reset", "change",
    "expired", "expire", "expires", "manager", "policy", "field", "box", "is", "es", "est", "ist",
    "not", "no", "nicht", "pas", "non", "never", "nunca", "mai", "jamais", "nie", "and/or",
    "otp", "protection", "protección", "protezione", "schutz", "encryption", "encrypted",
    "cifrado", "cifrada", "crittografato", "chiffré", "verschlüsselt", "case", "sensitive",
    "number", "número", "numero", "nummer", "code", "código", "codice", "letters", "digits",
}

_SEP_CHARS = ":：=→"
_QUOTES = "\"'`“”«»‘’„‚‹›*_[](){}<>"
_MAX_CANDIDATES = 20
_WINDOW = 90

_kw_alt = "|".join(re.escape(k) for k in sorted(_KEYWORDS, key=len, reverse=True))
# Keyword not glued to a preceding/following letter (so "pin" is not "pinned",
# "pw" is not "pwned"); CJK keywords have no word boundaries.
_RE_KW = re.compile(rf"(?<![^\W\d_])(?:{_kw_alt})(?![^\W\d_])|(?:密码|密碼|口令|パスワード|暗証番号|비밀번호|암호)",
                    re.IGNORECASE)
_RE_TAGS = re.compile(r"<[^>]+>")


def _looks_like_password(tok: str) -> bool:
    """A bare value right after the keyword (no "is"/":"): only if it looks like
    a password — has a digit or symbol, or mixes upper and lower case."""
    if len(tok) < 4:
        return False
    has_digit = any(c.isdigit() for c in tok)
    has_sym = any(not c.isalnum() for c in tok)
    mixed = any(c.isupper() for c in tok) and any(c.islower() for c in tok[1:])
    return has_digit or has_sym or mixed


def _clean(tok: str) -> str:
    tok = tok.strip(_QUOTES)
    # A sentence-ending dot/comma after the value is not part of it.
    while tok and tok[-1] in ".,;:!?)]}\"'”’»":
        tok = tok[:-1]
    return tok.strip(_QUOTES)


def _value_after(text: str, start: int) -> list[str]:
    window = text[start:start + _WINDOW]
    # Only the rest of this line, or the next line when this one ends right
    # after the keyword ("Password:\n  Xy12!").
    lines = window.split("\n")
    first = lines[0]
    if not first.strip(" \t" + _SEP_CHARS + _QUOTES + "-–—") and len(lines) > 1:
        first = first + " " + lines[1]
    # Separators glued to the keyword ("Password:1234", "pwd=1234") count.
    for ch in _SEP_CHARS:
        first = first.replace(ch, f" {ch} ")
    toks = first.split()
    assigned = False
    for i, raw in enumerate(toks[:10]):
        low = raw.lower().strip(_QUOTES)
        if raw in _SEP_CHARS or low in _ASSIGN or low.rstrip(":") in _ASSIGN and low.endswith(":"):
            assigned = True
            continue
        if low in _FILLER or low.rstrip(":,") in _FILLER:
            if low.endswith(":"):
                assigned = True
            continue
        # A sentence ended before any value: stop.
        val = _clean(raw)
        if not val or len(val) < 3 or len(val) > 64:
            if raw.endswith((".", "!", "?")):
                return []
            continue
        if val.lower() in _NOT_PW or val.lower().startswith(("http", "www.")) or "@" in val:
            return []
        if assigned or (i == 0 and _looks_like_password(val)):
            # The trailing "!"/"." may be part of the password or end the
            # sentence: try both.
            full = raw.strip(_QUOTES)
            return [val] + ([full] if full != val and 3 <= len(full) <= 64 else [])
        return []
    return []


def harvest(*texts: str) -> list[dict[str, Any]]:
    """Password candidates in the given texts (subject, plain body, HTML-as-text),
    each ``{password, context}`` — deduplicated, in order of appearance."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        if "<" in text and ">" in text:
            text = _RE_TAGS.sub(" ", text)
        text = text.replace("\r", "").replace(" ", " ")
        for m in _RE_KW.finditer(text):
            lo = max(0, m.start() - 30)
            ctx = " ".join(text[lo:m.end() + 50].split())[:140]
            for val in _value_after(text, m.end()):
                if val in seen:
                    continue
                seen.add(val)
                out.append({"password": val, "context": ctx})
                if len(out) >= _MAX_CANDIDATES:
                    return out
    return out


# --- every word of the email (on demand) ------------------------------------

_RE_WORD = re.compile(r"\w+(?:[-_.]\w+)*")


def _variants(tok: str) -> list[str]:
    """A token as written, without the punctuation around it, and its word pieces
    ("(Fact-2026)." -> "(Fact-2026).", "Fact-2026", "Fact", "2026")."""
    out = [tok, _clean(tok), tok.strip(_QUOTES + ".,;:!?¡¿")]
    pieces = _RE_WORD.findall(tok)
    out += pieces
    for p in pieces:
        out += re.findall(r"\w+", p)
    return out


def email_words(mail_res: dict[str, Any]) -> list[dict[str, str]]:
    """Every word of the email as a password candidate, for when the password is
    not announced in a recognisable way: the text body (the HTML body as text
    only if there is no text part — it carries gateway banners), the subject,
    the attachment names, and the sender's/recipients' addresses, names and
    domains. In order of appearance, de-duplicated, ``{password, origin}``."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(word: str, origin: str) -> None:
        word = (word or "").strip()
        if 2 <= len(word) <= 64 and word not in seen:
            seen.add(word)
            out.append({"password": word, "origin": origin})

    text = mail_res.get("body_sample") or mail_res.get("html_text_sample") or ""
    for tok in text.split():
        for v in _variants(tok):
            add(v, "body")
    addrs = mail_res.get("addresses") or {}
    for tok in (addrs.get("subject") or "").split():
        for v in _variants(tok):
            add(v, "subject")
    for att in mail_res.get("attachments") or []:
        name = att.get("filename") or ""
        stem = name.rsplit(".", 1)[0] if "." in name else name
        for v in (name, stem, *_variants(stem)):
            add(v, "attachment name")
    people = [addrs.get(k) for k in ("from", "reply_to", "return_path", "sender")] + list(addrs.get("to") or [])
    for addr in filter(None, people):
        local, _, domain = addr.partition("@")
        add(addr, "address")
        add(local, "address")
        for v in _variants(local):
            add(v, "address")
        if domain:
            add(domain, "address")
            labels = domain.split(".")
            for i in range(len(labels) - 1):
                add(".".join(labels[i:]), "address")
                add(labels[i], "address")
                for v in _variants(labels[i]):
                    add(v, "address")
    display = addrs.get("from_display") or ""
    if display:
        add(display, "sender name")
        add(display.replace(" ", ""), "sender name")
        for tok in display.split():
            for v in _variants(tok):
                add(v, "sender name")
    return out
