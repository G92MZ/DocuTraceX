"""Thread identifiers (Message-ID / In-Reply-To / References) read against Chain:
incomplete is info, contradictions and hijack patterns are findings."""

from __future__ import annotations

from docutracex import mailchain, mailengine


def P(addr: str, name: str = "") -> list[dict]:  # noqa: N802
    return [{"name": name, "address": addr}]


def _root(mid: str = "<r@x.example>", irt: list | None = None, refs: list | None = None, frm: str = "a@corp.example",
          date: str = "Mon, 10 Nov 2026 10:00:00 +0100", **people) -> dict:  # noqa: ANN003
    m = mailchain.from_people("root", "", "RE: Pedido", date, {"from": P(frm), **people})
    m.update(message_id=mid, in_reply_to=irt or [], references=refs or [])
    return m


def test_incomplete_is_info_and_orphan() -> None:
    f = mailengine.thread_facts(mailchain.build(_root(irt=["<p@x.example>"], refs=["<p@x.example>"]), [], []))
    assert f["missing_refs"] == ["<p@x.example>"] and f["orphan"]
    assert not (f["self_reference"] or f["irt_not_in_refs"] or f["irt_not_last"] or f["chronology"] or f["newcomer_sender"])


def test_contradictions() -> None:
    f = mailengine.thread_facts(mailchain.build(
        _root(irt=["<b@x.example>"], refs=["<r@x.example>", "<a@x.example>", "<a@x.example>"]), [], []))
    assert f["self_reference"] == "<r@x.example>" and f["irt_not_in_refs"] == "<b@x.example>"
    assert f["duplicate_refs"] == ["<a@x.example>"]
    f = mailengine.thread_facts(mailchain.build(_root(irt=["<a@x.example>"], refs=["<a@x.example>", "<b@x.example>"]), [], []))
    assert f["irt_not_last"] == "<a@x.example>" and not f["irt_not_in_refs"]


def test_newcomer_and_chronology() -> None:
    old = mailchain.from_people("quoted", "", "Pedido", "Mon, 10 Nov 2026 11:00:00 +0100",
                                {"from": P("b@prov.example"), "to": P("a@corp.example")})
    root = _root(irt=["<q@prov.example>"], refs=["<q@prov.example>"], frm="eve@evil.example", to=P("a@corp.example"))
    f = mailengine.thread_facts(mailchain.build(root, [], [old]))
    assert f["newcomer_sender"] == "eve@evil.example"
    assert f["chronology"] and "older than" in f["chronology"][0]


def test_quoted_local_time_vs_zoned_header_is_not_inverted() -> None:
    q = mailchain.from_people("quoted", "", "Pedido", "Monday, November 10, 2026 9:32 AM",
                              {"from": P("b@prov.example"), "to": P("a@corp.example")})
    root = _root(irt=["<q@prov.example>"], refs=["<q@prov.example>"], frm="b@prov.example",
                 date="Mon, 10 Nov 2026 09:48:52 +0100", to=P("a@corp.example"))
    assert mailengine.thread_facts(mailchain.build(root, [], [q]))["chronology"] == []


def test_sample_hijack_rules() -> None:
    import sys
    import tempfile
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import make_samples as ms

    from docutracex.parsers import mail, mail_rules
    d = Path(tempfile.mkdtemp())
    p = d / "m.eml"
    p.write_bytes(ms.email_chain_eml())
    r = mail_rules.analyze(p, ".eml", mail.analyze(p, ".eml", d / "x"), d)
    ids = {m["id"] for m in r["engine"]["matched"]}
    assert {"thread_hijack_injected_participant", "thread_references_missing"} <= ids
    assert "thread_chronology_inverted" not in ids
    assert r["verdict"]["verdict"] == "phishing"


def test_utc_date_header_is_read_in_the_last_hop_zone() -> None:
    """Exchange stamps Date in UTC (15:03 +0000) while the quoted "Sent:" line is the
    reader's local time (15:08, Madrid): the reply at 16:03 local is not older."""
    q = mailchain.from_people("quoted", "", "Pedido", "martes, 10 de noviembre de 2026 15:08",
                              {"from": P("b@prov.example"), "to": P("a@corp.example")})
    root = _root(irt=["<q@prov.example>"], refs=["<q@prov.example>"], frm="a@corp.example",
                 date="Tue, 10 Nov 2026 15:03:40 +0000", to=P("b@prov.example"))
    root["headers"] = [
        {"name": "Received", "value": "from AM0PR.prod.outlook.example by mx.corp.example; Tue, 10 Nov 2026 16:03:45 +0100"},
        {"name": "Received", "value": "from client by AM0PR.prod.outlook.example; Tue, 10 Nov 2026 15:03:41 +0000"},
        {"name": "Date", "value": "Tue, 10 Nov 2026 15:03:40 +0000"}]
    ch = mailchain.build(root, [], [q])
    assert ch["zone"] == {"offset": "+01:00", "minutes": 60, "source": "last Received hop"}
    assert mailengine.thread_facts(ch)["chronology"] == []
    assert ch["messages"][-1]["date_local"].startswith("2026-11-10T16:03")       # shown as the reader saw it
    # without any zone in the headers the dates are compared as written (and flagged)
    root["headers"] = [{"name": "Date", "value": "Tue, 10 Nov 2026 15:03:40 +0000"}]
    f = mailengine.thread_facts(mailchain.build(root, [], [dict(q)]))
    assert f["chronology"] and "older than" in f["chronology"][0]
    # a genuinely older reply is still reported, with the zone named
    root["headers"][0:0] = [{"name": "Received", "value": "by mx.corp.example; Tue, 10 Nov 2026 15:00:00 +0100"}]
    root["date"] = "2026-11-10T13:50:00+00:00"
    f = mailengine.thread_facts(mailchain.build(root, [], [dict(q)]))
    assert "14:50" in f["chronology"][0] and "times in +01:00, from the last Received hop" in f["chronology"][0]
