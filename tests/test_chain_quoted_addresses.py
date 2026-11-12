"""Chain: quoted messages keep their participants whatever way the address is written."""

from __future__ import annotations

import email
import sys
from email import policy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import make_samples as ms  # noqa: E402

from docutracex import mailchain as mc  # noqa: E402


@pytest.mark.parametrize("text,frm,to", [
    # Outlook, sender without a display name: "addr <addr>" (Python 3.13's getaddresses returns nothing)
    ("De: juan@e.example <juan@e.example>\nPara: ana@e.example <ana@e.example>\nAsunto: RE: Envío\n",
     [("", "juan@e.example")], [("", "ana@e.example")]),
    # bold rendered in plain text
    ("**De:** Ana López <ana@e.example>\n**Enviado el:** lunes\n**Para:** Juan <juan@e.example>\n**Asunto:** RE: x\n",
     [("Ana López", "ana@e.example")], [("Juan", "juan@e.example")]),
    ("*De:* Ana <ana@e.example>\n*Para:* Juan <juan@e.example>\n*Asunto:* RE: x\n",
     [("Ana", "ana@e.example")], [("Juan", "juan@e.example")]),
    # HTML-escaped brackets
    ("De: Ana &lt;ana@e.example&gt;\nPara: Juan &lt;juan@e.example&gt;; Pedro &lt;pedro@e.example&gt;\nAsunto: x\n",
     [("Ana", "ana@e.example")], [("Juan", "juan@e.example"), ("Pedro", "pedro@e.example")]),
    # the usual forms still read as before
    ("From: Pérez, Juan <juan@e.example>\nSent: Monday\nTo: a@e.example, b@e.example\nSubject: x\n",
     [("Pérez, Juan", "juan@e.example")], [("", "a@e.example"), ("", "b@e.example")]),
    ("De: Juan Pérez [mailto:juan@e.example]\nEnviado el: lunes\nPara: Ana López\nAsunto: RE: x\n",
     [("Juan Pérez", "juan@e.example")], [("Ana López", "")]),
])
def test_quoted_participants(text: str, frm: list, to: list) -> None:
    q = mc.quoted_messages(text)
    assert len(q) == 1
    assert [(p["name"], p["address"]) for p in q[0]["from"]] == frm
    assert [(p["name"], p["address"]) for p in q[0]["to"]] == to
    assert not q[0]["subject"].startswith("*")


def test_long_thread_without_display_names() -> None:
    m = email.message_from_bytes(ms.email_chain_no_display_eml(), policy=policy.default)
    q = mc.quoted_messages(m.get_body().get_content())
    assert len(q) == 5 and all(x["from"] and x["to"] and x["subject"] == "RE: Envío de facturas" for x in q)
    assert q[0]["cc"] == [{"name": "", "address": "archivo@grupoejemplo.example"}]


def test_header_values_unchanged() -> None:
    assert mc.parse_people('"Juan Pérez" <juan@e.example>, ana@e.example') == [
        {"name": "Juan Pérez", "address": "juan@e.example"}, {"name": "", "address": "ana@e.example"}]
