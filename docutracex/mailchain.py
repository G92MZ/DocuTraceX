"""Chain: the messages of an email conversation and how their participants change.

Built statically from one email file:

* the message itself (``root``);
* messages attached to it (``message/rfc822`` parts, ``.eml`` / ``.msg``
  attachments) — ``attached``;
* earlier messages **quoted in the body** — Outlook header blocks
  (From / Sent / To / Cc / Subject, also in ES / DE / FR / IT / PT / NL) and
  "On … X <x@y> wrote:" lines — ``quoted`` (they carry no Message-ID).

Nothing is invented: quoted messages are ordered by their position in the body
(the deepest quote is the oldest), messages with identifiers by
In-Reply-To / References, and an attached message that is neither linked by
identifiers nor shares the subject is listed apart (``related: False``).
Consecutive messages are compared (participants added / removed / moved between
roles, sender changes) and identifiers referenced but not present are listed,
so an incomplete chain says so.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

ROLES = ("from", "sender", "reply_to", "to", "cc", "bcc")
ROLE_LABEL = {"from": "From", "sender": "Sender", "reply_to": "Reply-To", "to": "To", "cc": "CC", "bcc": "BCC",
              "return_path": "Return-Path", "delivered_to": "Delivered-To", "x_original_to": "X-Original-To"}
_HEADER_ROLES = {"from": "From", "sender": "Sender", "reply_to": "Reply-To", "to": "To", "cc": "Cc", "bcc": "Bcc",
                 "return_path": "Return-Path", "delivered_to": "Delivered-To", "x_original_to": "X-Original-To"}
MAX_MESSAGES = 60
_ID = re.compile(r"<[^<>\s]+>")


# --- addresses ---------------------------------------------------------------

def _clean_addr_text(value: str) -> str:
    # Outlook: "John Smith [mailto:john@x]" / "'John' <john@x>"; HTML-escaped "&lt;john@x&gt;";
    # bold rendered in plain text ("*De:* …" / "**From:** …") leaves the asterisks in the value
    import html
    value = html.unescape(value or "")
    value = re.sub(r"\[mailto:([^\]]+)\]", r"<\1>", value, flags=re.I)
    value = re.sub(r"<\s*mailto:", "<", value, flags=re.I)
    return value.replace("​", "").replace("\u00a0", " ").strip().strip("*_").strip()


# "Name <addr>" / "addr <addr>" / "<addr>" / a bare address — read by hand: the standard parser
# (Python 3.13's strict getaddresses) rejects "addr <addr>", which is how Outlook quotes a sender
# without a display name, and returns nothing
_PAIR = re.compile(r"\s*(?P<name>[^<>;]*?)\s*<\s*(?P<addr>[^<>\s;]+@[^<>\s;]+?)\s*>")
_BARE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _pairs(piece: str) -> list[tuple[str, str]]:
    found = [(m.group("name").strip().strip(",").strip(), m.group("addr")) for m in _PAIR.finditer(piece)]
    rest = _PAIR.sub(" ", piece)
    found += [("", a) for a in _BARE.findall(rest)]
    if found:
        return found
    return getaddresses([piece])


def parse_people(values: list[str] | str | None) -> list[dict[str, str]]:
    """``[{name, address}]`` from header values; a name without address (as in
    quoted Outlook blocks, "Smith, John") is kept with an empty address."""
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in values:
        value = _clean_addr_text(str(value))
        pieces = [p for p in re.split(r";", value) if p.strip()] if ";" in value or "@" not in value else [value]
        for piece in pieces:
            if "@" not in piece:
                name = piece.strip().strip("'\"").strip()
                pairs = [(name, "")] if name else []
            else:
                pairs = _pairs(piece)
            for name, addr in pairs:
                addr = (addr or "").strip().strip("<>").lower()
                name = (name or "").strip().strip("'\"*_").strip()
                if name.lower() == addr:                    # "addr <addr>": no display name
                    name = ""
                if addr and "@" not in addr:
                    name, addr = (name or addr), ""
                key = addr or name.lower()
                if not key or key in seen:
                    continue
                seen.add(key)
                out.append({"name": name, "address": addr})
    return out


def _key(p: dict[str, str]) -> str:
    return p.get("address") or ("name:" + re.sub(r"\s+", " ", p.get("name", "").lower()).strip())


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


# --- dates -------------------------------------------------------------------

_MONTHS = {
    "enero": "jan", "febrero": "feb", "marzo": "mar", "abril": "apr", "mayo": "may", "junio": "jun", "julio": "jul",
    "agosto": "aug", "septiembre": "sep", "setiembre": "sep", "octubre": "oct", "noviembre": "nov", "diciembre": "dec",
    "januar": "jan", "februar": "feb", "märz": "mar", "mai": "may", "juni": "jun", "juli": "jul", "oktober": "oct",
    "dezember": "dec", "janvier": "jan", "février": "feb", "mars": "mar", "avril": "apr", "juin": "jun",
    "juillet": "jul", "août": "aug", "septembre": "sep", "octobre": "oct", "novembre": "nov", "décembre": "dec",
    "gennaio": "jan", "febbraio": "feb", "aprile": "apr", "maggio": "may", "giugno": "jun", "luglio": "jul",
    "settembre": "sep", "ottobre": "oct", "dicembre": "dec", "janeiro": "jan", "fevereiro": "feb", "março": "mar",
    "junho": "jun", "julho": "jul", "setembro": "sep", "outubro": "oct", "dezembro": "dec",
    "january": "jan", "february": "feb", "march": "mar", "april": "apr", "june": "jun", "july": "jul",
    "august": "aug", "september": "sep", "october": "oct", "november": "nov", "december": "dec",
    "ene": "jan", "abr": "apr", "ago": "aug", "dic": "dec", "dez": "dec", "mär": "mar", "okt": "oct",
}
_NOISE = re.compile(r"(?i)\b(?:lunes|martes|miércoles|miercoles|jueves|viernes|sábado|sabado|domingo|montag|dienstag|"
                    r"mittwoch|donnerstag|freitag|samstag|sonntag|lundi|mardi|mercredi|jeudi|vendredi|samedi|dimanche|"
                    r"lunedì|martedì|mercoledì|giovedì|venerdì|sabato|domenica|segunda-feira|terça-feira|quarta-feira|"
                    r"quinta-feira|sexta-feira|de|del|a las|um|à|às|alle|le|el|am|em|at|the)\b\.?")


def parse_date(raw: str) -> str:
    """ISO 8601 for a header or quoted date ('' when it cannot be read)."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        return parsedate_to_datetime(raw).isoformat()
    except (TypeError, ValueError, IndexError):
        pass
    txt = re.sub(r"^[a-zà-ü]{2,4}\.?,?\s+(?=\d)", "", raw.lower())     # "lun, 10 nov" / "Di. 11."
    for k, v in sorted(_MONTHS.items(), key=lambda kv: -len(kv[0])):
        txt = re.sub(rf"(?<![a-zà-ü]){re.escape(k)}(?![a-zà-ü])", v, txt)
    txt = _NOISE.sub(" ", txt).replace(",", " ")
    txt = re.sub(r"\s+", " ", txt).strip()
    try:
        from dateutil import parser as dparser  # optional
        return dparser.parse(txt, fuzzy=True, dayfirst=not re.search(r"[a-z]{3} \d", txt)).isoformat()
    except Exception:  # noqa: BLE001
        pass
    txt = re.sub(r"(?i)\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday|mon|tue|wed|thu|fri|sat|sun)\b\.?", " ", txt)
    txt = re.sub(r"(\d)\.(?=\s)", r"\1", txt)          # "10. nov"
    txt = re.sub(r"\s+", " ", txt).strip()
    m = re.search(r"\d{1,2}:\d{2}(?::\d{2})?(?:\s*[ap]\.?m\.?)?", txt, re.I)
    if m:
        txt = txt[:m.end()].replace(".", "")
    for fmt in ("%d %b %Y %H:%M", "%b %d %Y %I:%M %p", "%b %d %Y %H:%M", "%d %b %Y %I:%M %p", "%d/%m/%Y %H:%M",
                "%Y-%m-%d %H:%M", "%d.%m.%Y %H:%M", "%d/%m/%Y %H:%M:%S", "%d %b %Y %H:%M:%S"):
        try:
            return datetime.strptime(txt, fmt).isoformat()
        except ValueError:
            continue
    return ""


# --- messages ------------------------------------------------------------------

def _ids(value: str | None) -> list[str]:
    return _ID.findall(value or "")


def from_headers(msg: Message, kind: str, source: str) -> dict[str, Any]:
    """A chain message from a parsed header set (root or attached)."""
    people = {role: parse_people(msg.get_all(h, [])) for role, h in _HEADER_ROLES.items()}
    date_raw = str(msg.get("Date", "") or "")
    headers = [{"name": k, "value": str(v)} for k, v in msg.items()][:300]
    return {
        "kind": kind, "source": source,
        "subject": str(msg.get("Subject", "") or ""),
        "date_raw": date_raw, "date": parse_date(date_raw),
        "message_id": (_ids(str(msg.get("Message-ID", "") or "")) or [""])[0],
        "in_reply_to": _ids(str(msg.get("In-Reply-To", "") or "")),
        "references": _ids(" ".join(str(v) for v in msg.get_all("References", []) or [])),
        "thread_index": str(msg.get("Thread-Index", "") or ""),
        "thread_topic": str(msg.get("Thread-Topic", "") or ""),
        **people,
        "headers": headers,
        "ms_headers": [h for h in headers if h["name"].lower().startswith(("x-ms-", "x-microsoft-", "x-forefront-"))],
    }


def from_people(kind: str, source: str, subject: str, date_raw: str, people: dict[str, list[dict[str, str]]],
                **extra: Any) -> dict[str, Any]:
    m = {"kind": kind, "source": source, "subject": subject, "date_raw": date_raw, "date": parse_date(date_raw),
         "message_id": "", "in_reply_to": [], "references": [], "thread_index": "", "thread_topic": "",
         "headers": [], "ms_headers": []}
    for role in _HEADER_ROLES:
        m[role] = people.get(role, [])
    m.update(extra)
    return m


# --- quoted messages in the body ------------------------------------------------

_F = {
    "from": r"from|de|von|da|van|från|fra|od|от|寄件者|发件人",
    "date": r"sent|date|enviado(?: el)?|enviada em|fecha|gesendet|datum|inviato|data|envoyé|verzonden|skickat|"
            r"sendt|wysłano|отправлено|日期|发送时间",
    "to": r"to|para|an|a|à|aan|till|til|do|кому|收件者|收件人",
    "cc": r"cc|copia|kopie|copie|kopia|копия|抄送",
    "bcc": r"bcc|cco|cci|ccn|bkopie|скрытая копия|密件抄送",
    "subject": r"subject|asunto|betreff|oggetto|objet|assunto|onderwerp|ämne|emne|temat|тема|主旨|主题",
    "reply_to": r"reply-to|responder a|antwort an|répondre à",
}
_FIELD = re.compile(r"^[\s>*]*(" + "|".join(f"(?P<{k}>{v})" for k, v in _F.items()) + r")\s*:\s*(?P<val>.*)$",
                    re.I | re.U)
_WROTE = re.compile(
    r"^[\s>]*(?:on|el|am|le|il|em|op|den)\s+(?P<pre>[^<>\n]+?)\s*[(<]\s*<?(?P<addr>[\w.+-]+@[\w-]+(?:\.[\w-]+)+)>?\s*\)?"
    r"\s+(?:wrote|escribió|schrieb|a écrit|ha scritto|escreveu|schreef|skrev)\s*:\s*$", re.I | re.U)


def quoted_messages(text: str) -> list[dict[str, Any]]:
    """Quoted header blocks, in order of appearance (newest first)."""
    lines = (text or "").splitlines()
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(lines) and len(out) < MAX_MESSAGES:
        line = lines[i]
        w = _WROTE.match(line)
        if w:
            pre = w.group("pre").strip()
            t = list(re.finditer(r"\d{1,2}:\d{2}(?::\d{2})?(?:\s*[ap]\.?\s?m\.?)?", pre, re.I))
            if t:                                # "… 9:15 AM John Smith" / "… a las 7:00, Zed"
                date, who = pre[:t[-1].end()], pre[t[-1].end():].strip(" ,")
            else:
                date, _, who = pre.rpartition(",") if "," in pre else (pre, "", "")
            who = who.strip().strip("\"'")
            out.append(from_people("quoted", f"body line {i + 1}", "", date.strip(),
                                   {"from": [{"name": who, "address": w.group("addr").lower()}]}))
            i += 1
            continue
        m = _FIELD.match(line)
        if not (m and m.group("from")):
            i += 1
            continue
        fields: dict[str, str] = {}
        j = i
        last = ""
        while j < len(lines) and j - i < 25:
            mm = _FIELD.match(lines[j])
            if mm:
                key = next(k for k in _F if mm.group(k))
                if key in fields and key == "from":
                    break                                   # next block
                fields[key] = mm.group("val").strip().strip("*_").strip()
                last = key
            elif lines[j].strip() and last in ("to", "cc", "bcc") and not lines[j].lstrip().startswith(">") \
                    and ("@" in lines[j] or ";" in lines[j]):
                fields[last] += " " + lines[j].strip()     # wrapped recipient list
            elif not lines[j].strip() or last == "subject":
                if j > i:
                    break
            else:
                break
            j += 1
        if "from" in fields and ("date" in fields or "subject" in fields) and \
                ("to" in fields or "subject" in fields):
            out.append(from_people("quoted", f"body line {i + 1}", fields.get("subject", ""), fields.get("date", ""),
                                   {r: parse_people(fields.get(r, "")) for r in ("from", "to", "cc", "bcc", "reply_to")}))
            i = max(j, i + 1)
        else:
            i += 1
    return out


# --- ordering, relations, comparison ------------------------------------------

def _norm_subject(s: str) -> str:
    s = (s or "").lower()
    while True:
        t = re.sub(r"^\s*(?:re|fw|fwd|rv|tr|wg|aw|sv|vs|r|i|enc|res|antw|odp|ответ)\s*(?:\[\d+\])?\s*:\s*", "", s)
        t = re.sub(r"^\s*\[[^\]]{1,40}\]\s*", "", t)
        if t == s:
            return re.sub(r"\s+", " ", s).strip()
        s = t


def _participants(m: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """key → {name, address, roles}"""
    out: dict[str, dict[str, Any]] = {}
    for role in ROLES:
        for p in m.get(role) or []:
            k = _key(p)
            e = out.setdefault(k, {"name": p.get("name", ""), "address": p.get("address", ""), "roles": []})
            if role not in e["roles"]:
                e["roles"].append(role)
            if not e["name"] and p.get("name"):
                e["name"] = p["name"]
    return out


def compare(prev: dict[str, Any], cur: dict[str, Any]) -> list[dict[str, Any]]:
    """Changes from ``prev`` to ``cur``: added / removed / changed (moved between
    roles, new sender, Reply-To appearing, display name changing)."""
    a, b = _participants(prev), _participants(cur)
    # a quoted block without addresses matches by name: link names to addresses
    names_b = {re.sub(r"\s+", " ", v["name"].lower()).strip(): k for k, v in b.items() if v["name"]}
    names_a = {re.sub(r"\s+", " ", v["name"].lower()).strip(): k for k, v in a.items() if v["name"]}
    for src, other_names in ((a, names_b), (b, names_a)):
        for k in [k for k in src if k.startswith("name:")]:
            twin = other_names.get(k[5:])
            if twin and twin not in src:
                src[twin] = src.pop(k)
    changes: list[dict[str, Any]] = []
    send_a = {k for k, v in a.items() if "from" in v["roles"]}
    primary_a = {k for k, v in a.items() if {"from", "to"} & set(v["roles"])}
    for k, v in b.items():
        if k not in a:
            changes.append({"type": "added", "address": v["address"], "name": v["name"], "roles": v["roles"],
                            "detail": f"new participant in {', '.join(ROLE_LABEL[r] for r in v['roles'])}"})
            continue
        ra, rb = set(a[k]["roles"]), set(v["roles"])
        # a reply swaps From and To: that is the conversation, not a change
        core_a, core_b = ra - {"from", "to"}, rb - {"from", "to"}
        if core_a != core_b and not ("from" in rb and "from" not in ra):   # → sender: reported below
            gone, new = sorted(core_a - core_b), sorted(core_b - core_a)
            changes.append({"type": "changed", "address": v["address"], "name": v["name"], "roles": v["roles"],
                            "detail": "moved: " + ", ".join([f"left {ROLE_LABEL[r]}" for r in gone]
                                                             + [f"now in {ROLE_LABEL[r]}" for r in new])})
        if a[k]["name"] and v["name"] and v["address"] and \
                re.sub(r"\W", "", a[k]["name"].lower()) != re.sub(r"\W", "", v["name"].lower()):
            changes.append({"type": "changed", "address": v["address"], "name": v["name"], "roles": v["roles"],
                            "detail": f'display name changed: "{a[k]["name"]}" → "{v["name"]}"'})
    for k, v in a.items():
        if k not in b:
            bcc_only = v["roles"] == ["bcc"]
            changes.append({"type": "removed", "address": v["address"], "name": v["name"], "roles": v["roles"],
                            "detail": f"no longer in the message (was {', '.join(ROLE_LABEL[r] for r in v['roles'])})"
                                      + (" — expected: BCC is only visible in the sender's copy" if bcc_only else ""),
                            **({"expected": True} if bcc_only else {})})
    for k, v in b.items():
        if "from" in v["roles"] and k not in send_a and k not in primary_a and send_a:
            changes.append({"type": "changed", "address": v["address"], "name": v["name"], "roles": v["roles"],
                            "detail": "sender change: writes now but was not a sender or main recipient before",
                            "attention": True})
    if (cur.get("reply_to") or []) and _key(cur["reply_to"][0]) not in {_key(p) for p in prev.get("reply_to") or []} \
            and _key(cur["reply_to"][0]) not in {_key(p) for p in cur.get("from") or []}:
        p = cur["reply_to"][0]
        changes.append({"type": "changed", "address": p["address"], "name": p["name"], "roles": ["reply_to"],
                        "detail": "Reply-To points elsewhere than the sender", "attention": True})
    return changes


def _dt(iso: str) -> datetime:
    try:
        d = datetime.fromisoformat(iso)
        return d.astimezone(timezone.utc).replace(tzinfo=None) if d.tzinfo else d   # naive, comparable
    except ValueError:
        return datetime.min


def local_zone(headers: list[dict[str, str]]) -> dict[str, Any]:
    """The time zone quoted dates (which carry none) are most likely written in.

    Mail clients write quoted "Sent:" lines in the reader's local time, while
    Exchange Online / Gmail often stamp ``Date`` in UTC (+0000). The receiving
    side's zone is taken from the Received hops, newest (last hop, the topmost
    header) first, then from ``Date``: the first offset that is not +0000.
    {offset: "+01:00", minutes, source} — or {} when every stamp is UTC / absent
    (then quoted and header dates are compared as written)."""
    cands: list[tuple[str, str]] = []
    rec = [h.get("value", "") for h in headers or [] if (h.get("name") or "").lower() == "received"]
    for i, v in enumerate(rec):
        if ";" in v:
            cands.append((v.rsplit(";", 1)[1].strip(), "last Received hop" if i == 0 else f"Received hop {i + 1} from the top"))
    cands += [(h.get("value", ""), "Date header") for h in headers or [] if (h.get("name") or "").lower() == "date"][:1]
    for raw, src in cands:
        try:
            d = parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError):
            continue
        off = d.utcoffset() if d and d.tzinfo else None
        if off and off.total_seconds():
            mins = int(off.total_seconds() // 60)
            return {"offset": f"{'+' if mins >= 0 else '-'}{abs(mins) // 60:02d}:{abs(mins) % 60:02d}",
                    "minutes": mins, "source": src}
    return {}


def _tz(zone: dict[str, Any] | None) -> timezone | None:
    from datetime import timedelta
    return timezone(timedelta(minutes=zone["minutes"])) if zone and "minutes" in zone else None


def in_zone(iso: str, zone: dict[str, Any] | None) -> str:
    """A date as the reader saw it: a zoned date converted to ``zone`` (naive
    ISO), a zone-less (quoted) date as written."""
    try:
        d = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return iso or ""
    tz = _tz(zone)
    return (d.astimezone(tz) if d.tzinfo and tz else d).replace(tzinfo=None).isoformat()


def later(a: str, b: str, zone: dict[str, Any] | None = None) -> bool:
    """``a`` is later than ``b``. Quoted dates carry no zone: when one side has
    none, the zoned one is first converted to the reader's zone (``local_zone``)
    and the wall-clock times are compared; without a known zone, as written."""
    try:
        da, db = datetime.fromisoformat(a), datetime.fromisoformat(b)
    except ValueError:
        return False
    if (da.tzinfo is None) != (db.tzinfo is None):
        tz = _tz(zone)
        da, db = ((x.astimezone(tz) if x.tzinfo and tz else x).replace(tzinfo=None) for x in (da, db))
    return da > db


def _same_message(q: dict[str, Any], m: dict[str, Any]) -> bool:
    fq = {_key(p) for p in q.get("from") or []}
    fm = {_key(p) for p in m.get("from") or []} | {"name:" + p.get("name", "").lower() for p in m.get("from") or []}
    if not (fq & fm):
        return False
    if q.get("subject") and _norm_subject(q["subject"]) != _norm_subject(m.get("subject", "")):
        return False
    return not (q.get("date") and m.get("date")) or q["date"][:16] == m["date"][:16]


def _linked(m: dict[str, Any], others: list[dict[str, Any]]) -> bool:
    ids = {o["message_id"] for o in others if o.get("message_id")}
    refs = {r for o in others for r in (o.get("in_reply_to") or []) + (o.get("references") or [])}
    if m.get("message_id") and m["message_id"] in refs:
        return True
    if ids & set((m.get("in_reply_to") or []) + (m.get("references") or [])):
        return True
    subj = _norm_subject(m.get("subject", ""))
    return bool(subj) and any(subj == _norm_subject(o.get("subject", "")) for o in others)


def build(root: dict[str, Any], attached: list[dict[str, Any]], quoted: list[dict[str, Any]]) -> dict[str, Any]:
    zone = local_zone(root.get("headers") or [{"name": "Date", "value": root.get("date_raw") or ""}])
    # quoted blocks appear newest first: the oldest is the deepest
    thread = list(reversed(quoted[:MAX_MESSAGES])) + [root]
    related, apart = [], []
    for m in attached[:MAX_MESSAGES]:
        (related if _linked(m, thread) else apart).append(m)
    ref_order: list[str] = []
    for r in (root.get("references") or []) + (root.get("in_reply_to") or []):
        if r not in ref_order:
            ref_order.append(r)
    for m in sorted(related, key=lambda x: (x.get("date") or "~", x.get("message_id") or "")):
        same = next((i for i, t in enumerate(thread) if t["kind"] == "quoted" and _same_message(t, m)), None)
        if same is not None:                 # the quoted copy of an attached message: keep the richer one
            m["also_quoted"] = thread[same]["source"]
            thread[same] = m
            continue
        pos = None
        if m.get("date") and any(t.get("date") for t in thread):
            pos = next((i for i, t in enumerate(thread) if t.get("date") and later(t["date"], m["date"], zone)), None)
        if pos is None and m.get("message_id") in ref_order:
            pos = min(ref_order.index(m["message_id"]), len(thread) - 1)
        thread.insert(len(thread) - 1 if pos is None else min(pos, len(thread) - 1), m)
    for n, m in enumerate(thread, 1):
        m["index"] = n
        if m.get("date"):
            m["date_local"] = in_zone(m["date"], zone)     # what the reader's client showed
        m["related"] = True
        m["changes"] = compare(thread[n - 2], m) if n > 1 else []
        m["change_count"] = sum(1 for c in m["changes"] if not c.get("expected"))
        m["baseline"] = n == 1
    for n, m in enumerate(apart, len(thread) + 1):
        m.update(index=n, related=False, changes=[], change_count=0, baseline=False)
    present = {m["message_id"] for m in thread + apart if m.get("message_id")}
    referenced: list[str] = []
    for m in thread + apart:
        for r in (m.get("references") or []) + (m.get("in_reply_to") or []):
            if r not in referenced:
                referenced.append(r)
    missing = [r for r in referenced if r not in present]
    participants: dict[str, dict[str, Any]] = {}
    for m in thread + apart:
        for role in list(_HEADER_ROLES):
            for p in m.get(role) or []:
                e = participants.setdefault(_key(p), {"name": p.get("name", ""), "address": p.get("address", ""),
                                                      "domain": _domain(p.get("address", "")), "roles": [],
                                                      "messages": []})
                if role not in e["roles"]:
                    e["roles"].append(role)
                if m["index"] not in e["messages"]:
                    e["messages"].append(m["index"])
                if not e["name"] and p.get("name"):
                    e["name"] = p["name"]
    quoted_n = sum(1 for m in thread if m["kind"] == "quoted")
    return {
        "messages": thread + apart,
        "count": len(thread), "unrelated": len(apart), "quoted": quoted_n,
        "missing_references": missing,
        "incomplete": bool(missing),
        "participants": sorted(participants.values(), key=lambda p: (p["address"] == "", p["address"] or p["name"])),
        "changes": sum(m["change_count"] for m in thread),
        "zone": zone,
    }
