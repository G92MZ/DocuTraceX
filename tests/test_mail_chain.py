"""Chain: the conversation's messages (root, attached, quoted in the body),
ordered without inventing continuity, compared message by message, and the
participants fed to the IOC extractor."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from docutracex import ioc, mailchain
from docutracex.parsers import mail

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


def _chain_of(data: bytes, ext: str = ".eml") -> dict:
    d = Path(tempfile.mkdtemp())
    p = d / f"m{ext}"
    p.write_bytes(data)
    return mail.analyze(p, ext, d / "x")


def test_quoted_blocks_in_several_languages() -> None:
    body = ("ok\n\nFrom: Alice Brown <alice@prov.example>\nSent: Monday, November 10, 2025 9:32 AM\n"
            "To: John Smith <john@corp.example>; Ops <ops@corp.example>\nCc: x@evil.example\nSubject: RE: Doc\n\nfine\n\n"
            "De: John Smith [mailto:john@corp.example]\nEnviado el: lunes, 10 de noviembre de 2025 9:15\n"
            "Para: Alice Brown <alice@prov.example>\nCC: Bob White <bob@corp.example>\nAsunto: Doc\n\nhola\n\n"
            "Von: Eve <eve@corp.example>\nGesendet: Montag, 10. November 2025 08:00\nAn: John Smith\nBetreff: Doc\n\n"
            "El lun, 10 nov 2025 a las 7:00, Zed (<zed@corp.example>) escribió:\n> antes\n"
            "On Mon, Nov 10, 2025 at 6:15 AM Ann Lee <ann@corp.example> wrote:\n> older\n")
    q = mailchain.quoted_messages(body)
    assert [m["from"][0]["address"] for m in q] == ["alice@prov.example", "john@corp.example", "eve@corp.example",
                                                     "zed@corp.example", "ann@corp.example"]
    assert q[4]["from"][0]["name"] == "Ann Lee" and q[4]["date"].startswith("2025-11-10T06:15")
    assert [p["address"] for p in q[0]["to"]] == ["john@corp.example", "ops@corp.example"]
    assert q[0]["cc"][0]["address"] == "x@evil.example" and q[1]["cc"][0]["address"] == "bob@corp.example"
    assert q[0]["date"].startswith("2025-11-10T09:32") and q[1]["date"].startswith("2025-11-10T09:15")
    assert q[2]["to"] == [{"name": "John Smith", "address": ""}]          # a name only, as Outlook quotes it


def test_compare_reply_is_not_a_change_but_new_cc_is() -> None:
    a = mailchain.from_people("quoted", "", "Doc", "", {"from": [{"name": "J", "address": "j@c.example"}],
                                                        "to": [{"name": "A", "address": "a@p.example"}],
                                                        "cc": [{"name": "B", "address": "b@c.example"}]})
    b = mailchain.from_people("quoted", "", "RE: Doc", "", {"from": [{"name": "A", "address": "a@p.example"}],
                                                            "to": [{"name": "J", "address": "j@c.example"}],
                                                            "cc": [{"name": "B", "address": "b@c.example"}]})
    assert mailchain.compare(a, b) == []                         # From/To swap of a reply
    b["cc"].append({"name": "X", "address": "x@evil.example"})
    b["reply_to"] = [{"name": "", "address": "pay@evil.example"}]
    ch = mailchain.compare(a, b)
    assert {c["type"] for c in ch} == {"added", "changed"}
    assert any(c.get("attention") and "Reply-To" in c["detail"] for c in ch)


def test_sample_chain_end_to_end() -> None:
    import make_samples as ms
    r = _chain_of(ms.email_chain_eml())
    c = r["chain"]
    assert [m["kind"] for m in c["messages"]] == ["attached", "quoted", "root"]
    assert c["messages"][0]["bcc"][0]["address"].startswith("archivo@")
    m2, m3 = c["messages"][1], c["messages"][2]
    assert any(x["type"] == "added" and x["address"].startswith("facturacion@") for x in m2["changes"])
    assert any(x["type"] == "removed" and x["address"].startswith("bob.white@") for x in m2["changes"])
    assert any(x.get("expected") for x in m2["changes"]) and m2["change_count"] == 2
    assert any(x.get("attention") and "sender change" in x["detail"] for x in m3["changes"])
    assert c["incomplete"] and "<msg-000@grupoejemplo.example>" in c["missing_references"]
    assert "<msg-001@grupoejemplo.example>" not in c["missing_references"]
    assert r["addresses"]["cc"] == [] and r["addresses"]["bcc"] == []


def test_unlinked_attached_message_is_listed_apart() -> None:
    root = mailchain.from_people("root", "", "Pedido 77", "Mon, 10 Nov 2026 10:00:00 +0100",
                                 {"from": [{"name": "", "address": "a@c.example"}]})
    other = mailchain.from_people("attached", "", "Newsletter", "Mon, 10 Nov 2026 09:00:00 +0100",
                                  {"from": [{"name": "", "address": "n@news.example"}]})
    c = mailchain.build(root, [other], [])
    assert c["count"] == 1 and c["unrelated"] == 1 and c["messages"][1]["related"] is False


def test_participants_are_iocs_with_their_field() -> None:
    import make_samples as ms
    r = _chain_of(ms.email_chain_eml())
    res = ioc.extract(ioc.sources_from_modules({"email": r}))
    by = {(i["type"], i["value"]): i for i in res["iocs"]}
    assert ("email", "archivo@grupoejemplo.example") in by          # BCC of the attached original
    assert ("domain", "proveedor-pagos.example") in by
    locs = {o["location"] for o in by[("email", "bob.white@grupoejemplo.example")]["occurrences"]}
    assert "chain/message 1 (attached)/CC" in locs


def test_chain_never_breaks_the_email(monkeypatch) -> None:  # noqa: ANN001
    import make_samples as ms
    monkeypatch.setattr(mailchain, "build", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = _chain_of(ms.email_chain_eml())
    assert r["status"].startswith("ok") and r["chain"]["error"] == "boom"


def test_dates_without_dateutil(monkeypatch) -> None:  # noqa: ANN001
    import builtins
    real = builtins.__import__

    def no_dateutil(name, *a, **k):  # noqa: ANN001, ANN002, ANN003
        if name.startswith("dateutil"):
            raise ImportError(name)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_dateutil)
    cases = {"Monday, November 10, 2025 9:32 AM": "2025-11-10T09:32", "lunes, 10 de noviembre de 2025 9:15": "2025-11-10T09:15",
             "Montag, 10. November 2025 08:00": "2025-11-10T08:00", "lun, 10 nov 2025 a las 7:00": "2025-11-10T07:00",
             "jeudi 13 novembre 2025 10:20": "2025-11-13T10:20", "Mon, 10 Nov 2025 09:15:23 +0100": "2025-11-10T09:15"}
    for raw, iso in cases.items():
        assert mailchain.parse_date(raw).startswith(iso), raw
