"""Microsoft 365 headers decoded, their rules, and the tenant lookup (AZMap,
mocked: tests never reach the network)."""

from __future__ import annotations

import io
import json
import socket
import sys
import tempfile
import urllib.error
from pathlib import Path

import pytest

from docutracex import appsettings, ioc, msheaders, tenantintel
from docutracex.config import settings
from docutracex.parsers import mail, mail_rules

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import make_samples as ms  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setattr(settings, "tools_dir", tmp_path / "tools")


def _analyse(data: bytes) -> tuple[dict, dict]:
    d = Path(tempfile.mkdtemp())
    p = d / "m.eml"
    p.write_bytes(data)
    e = mail.analyze(p, ".eml", d / "x")
    return e, mail_rules.analyze(p, ".eml", e, d)


class _Opener:
    """AZMap answers ``answer``; Microsoft's endpoints answer from ``ms``
    ({domain: tenant_id or None}; unknown domains: not in Microsoft 365)."""

    def __init__(self, answer: object, calls: list, ms: dict | None = None) -> None:
        self.answer, self.calls, self.ms = answer, calls, ms or {}

    def open(self, req, timeout=None):  # noqa: ANN001
        url = req.full_url
        if "login.microsoftonline.com" in url:
            dom = url.split("login=user@")[1].split("&")[0] if "getuserrealm" in url else url.split("/")[3]
            tid = self.ms.get(dom)
            if "getuserrealm" in url:
                return io.BytesIO(json.dumps({"NameSpaceType": "Managed" if tid else "Unknown",
                                              "FederationBrandName": "Brand" if tid else None}).encode())
            body = {"issuer": f"https://login.microsoftonline.com/{tid}/v2.0"} if tid else {"error": "invalid_tenant"}
            return io.BytesIO(json.dumps(body).encode())
        self.calls.append(url)
        if isinstance(self.answer, Exception):
            raise self.answer
        return io.BytesIO(json.dumps(self.answer).encode())


def test_decode_sample() -> None:
    e, _ = _analyse(ms.m365_headers_eml())
    m = e["microsoft"]
    assert m["tenant_id"] == ms.M365_SENDER_TENANT and m["tenant_role"] == "sender"
    roles = {b["tenant_id"]: b["role"] for b in m["tenant_blocks"]}
    assert roles == {ms.M365_RECEIVER_TENANT: "receiver", ms.M365_SENDER_TENANT: "sender"}
    rep = m["antispam"]
    assert rep["CAT"] == "PHSH" and rep["CAT_meaning"] == "phishing" and rep["SFTY_meaning"] == "first contact safety tip"
    assert m["compauth"] == {"result": "fail", "reason": "601",
                             "reason_text": "the sending domain is one of the organisation's accepted domains (intra-org spoofing)"}
    assert m["originating_ip"] == "198.51.100.77" and m["mailbox_delivery"]["dest"] == "J"


def test_rules_and_iocs(tmp_path: Path) -> None:
    appsettings.set_email_settings([ms.VICTIM_DOMAIN], [])
    e, r = _analyse(ms.m365_headers_eml())
    ids = {x["id"] for x in r["engine"]["matched"]}
    assert {"ms_classified_phishing", "ms_spam_verdict", "ms_compauth_fail", "ms_first_contact",
            "ms_own_domain_from_internet"} <= ids
    assert r["tenant"]["status"] == "skipped"                     # no network under tests
    vals = {(i["type"], i["value"]) for i in ioc.extract(ioc.sources_from_modules({"email": e}))["iocs"]}
    assert ("ipv4", "198.51.100.23") in vals and ("ipv4", "198.51.100.77") in vals
    assert ("domain", "smtp.attacker-tenant.example") in vals


def test_lookup_ok_cached_and_crossed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    answer = {"tenant_id": ms.M365_SENDER_TENANT, "tenant_name": None, "brand_name": "Attacker Ltd",
              "related_domains": ["attacker-tenant.example", "other.example"], "related_count": 2}
    monkeypatch.setattr("docutracex.mailintel._routes", lambda proxy: [("direct", _Opener(answer, calls))])
    m = msheaders.parse([{"name": "X-MS-Exchange-CrossTenant-Id", "value": ms.M365_SENDER_TENANT},
                         {"name": "X-MS-Exchange-CrossTenant-AuthAs", "value": "Internal"}])
    r = tenantintel.resolve(m, ["attacker-tenant.example", "grupoejemplo.example"], ["grupoejemplo.example"])
    t = r["tenants"][0]
    assert t["status"] == "ok" and t["data"]["brand_name"] == "Attacker Ltd" and t["raw"] == answer
    assert t["matched_domains"] == ["attacker-tenant.example"] and t["role"] == "sender" and not t["own_tenant"]
    again = tenantintel.lookup(ms.M365_SENDER_TENANT)
    assert again["cached"] and len(calls) == 1
    assert calls[0] == f"https://azmap.dev/api/tenant?tenant_id={ms.M365_SENDER_TENANT}"


def test_lookup_failures_never_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("docutracex.mailintel._routes",
                        lambda proxy: [("direct", _Opener(urllib.error.URLError(socket.timeout("timed out")), []))])
    r = tenantintel.lookup("11111111-1111-4111-8111-111111111111")
    assert r["status"] == "error" and "timed out" in r["error"]
    monkeypatch.setattr("docutracex.mailintel._routes", lambda proxy: [("direct", _Opener(
        urllib.error.HTTPError("u", 404, "nf", None, io.BytesIO(b"")), []))])
    assert tenantintel.lookup("22222222-2222-4222-8222-222222222222")["status"] == "not_found"
    assert tenantintel.lookup("not-a-guid")["status"] == "invalid"


def test_own_tenant_and_unrelated_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import mailengine
    answers = {ms.M365_SENDER_TENANT: {"brand_name": "Contoso", "related_domains": ["contoso.example"]},
               ms.M365_RECEIVER_TENANT: {"brand_name": "Grupo Ejemplo", "related_domains": ["grupoejemplo.example"]}}

    class _O:
        def open(self, req, timeout=None):  # noqa: ANN001
            tid = req.full_url.rsplit("=", 1)[1]
            return io.BytesIO(json.dumps(answers[tid]).encode())

    monkeypatch.setattr("docutracex.mailintel._routes", lambda proxy: [("direct", _O())])
    e, _ = _analyse(ms.m365_headers_eml())
    r = tenantintel.resolve(e["microsoft"], ["grupoejemplo.example"], ["grupoejemplo.example"])
    by = {t["tenant_id"]: t for t in r["tenants"]}
    assert by[ms.M365_RECEIVER_TENANT]["own_tenant"] and by[ms.M365_RECEIVER_TENANT]["role"].startswith("receiver")
    f = mailengine.tenant_facts(r, "grupoejemplo.example")
    assert f["brand"] == "Contoso" and "not among the 1 domain(s) of tenant Contoso" in f["sender_domain_unrelated"]


def test_disabled_in_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    data = appsettings.load()
    data["tenant_lookup"] = False
    appsettings.save(data)
    m = msheaders.parse([{"name": "X-MS-Exchange-CrossTenant-Id", "value": ms.M365_SENDER_TENANT}])
    r = tenantintel.resolve(m, [], [])
    assert r["status"] == "disabled" and r["tenants"][0]["status"] == "disabled"


def test_thread_index_decoding() -> None:
    import base64
    from datetime import datetime, timezone
    st = int((datetime(2026, 11, 10, 9, 15, tzinfo=timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10**7)
    diff = 17 * 60 * 10**7
    raw = (st >> 16).to_bytes(6, "big") + bytes(16) + ((((diff >> 18) & 0x7FFFFFFF) << 8) | 0x5A).to_bytes(5, "big")
    ti = msheaders.thread_index(base64.b64encode(raw).decode())
    assert ti["start"].startswith("2026-11-10T09:14:59") and ti["replies"] == 1
    assert ti["reply_times"][0].startswith("2026-11-10T09:31:59")
    assert msheaders.thread_index("not base64 !!") == {} or msheaders.thread_index("not base64 !!")["replies"] >= 0
    assert msheaders.arrival_iso("13 Oct 2026 17:12:09.0000 (UTC)") == "2026-10-13T17:12:09+00:00"


def test_sample_new_microsoft_rules() -> None:
    e, r = _analyse(ms.m365_headers_eml())
    ids = {x["id"]: x for x in r["engine"]["matched"]}
    assert {"ms_originator_org_mismatch", "ms_date_vs_arrival", "thread_index_after_date"} <= set(ids)
    assert "after Exchange received it" in ids["ms_date_vs_arrival"]["evidence"]
    assert e["microsoft"]["thread_index"]["replies"] == 0


def test_allowed_countries_setting() -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    c = TestClient(create_app())
    assert c.put("/api/settings/allowed-countries", json={"countries": "es, pt fr xx1 Z"}).json() == \
        {"countries": ["ES", "FR", "PT"]}
    _, r = _analyse(ms.m365_headers_eml())
    m = next(x for x in r["engine"]["matched"] if x["id"] == "ms_country_not_allowed")
    assert "connecting IP in NL" in m["evidence"]
    c.put("/api/settings/allowed-countries", json={"countries": ["NL"]})
    _, r = _analyse(ms.m365_headers_eml())
    assert "ms_country_not_allowed" not in {x["id"] for x in r["engine"]["matched"]}


def test_reply_subject_with_new_conversation_index() -> None:
    from docutracex import mailengine
    f = mailengine.ms_extra_facts({"thread_index": {"start": "2026-10-01T00:00:00+00:00", "replies": 0}},
                                  "a.example", "Mon, 05 Oct 2026 10:00:00 +0000", "RE: Factura", {})
    assert f["thread_index_new_for_reply"] and not f["thread_index_after_date"]


def test_tool_bookkeeping_is_not_mined_for_iocs(monkeypatch: pytest.MonkeyPatch) -> None:
    """The AZMap lookup (its URL and the tenant's related domains), the thread
    Message-IDs / References and the rules' evidence are the app's own
    bookkeeping: none of it becomes an IOC. The message's real indicators stay."""
    answer = {"tenant_name": "Attacker Tenant", "brand_name": "Attacker",
              "related_domains": ["attacker-tenant.example", "unrelated-subsidiary.example"], "related_count": 2}
    monkeypatch.setattr("docutracex.mailintel._routes", lambda proxy: [("direct", _Opener(answer, []))])
    monkeypatch.setattr(tenantintel, "enabled", lambda: True)
    import docutracex.parsers.mail_rules as mr
    src = mr._tenant
    def _tenant(email, res):  # noqa: ANN001, ANN202  (force the lookup under tests)
        res["tenant"] = tenantintel.resolve(email.get("microsoft") or {}, ["attacker-tenant.example"], [])
    monkeypatch.setattr(mr, "_tenant", _tenant)
    e, r = _analyse(ms.m365_headers_eml())
    assert r["tenant"]["tenants"] and r["tenant"]["tenants"][0]["source"].startswith("https://azmap.dev/")
    monkeypatch.setattr(mr, "_tenant", src)
    e2, r2 = _analyse(ms.email_chain_eml())
    vals = {(i["type"], i["value"]) for i in ioc.extract(ioc.sources_from_modules(
        {"email": e, "mailrules": r}))["iocs"]}
    vals2 = {(i["type"], i["value"]) for i in ioc.extract(ioc.sources_from_modules(
        {"email": e2, "mailrules": r2}))["iocs"]}
    flat = {v for _t, v in vals | vals2}
    assert not any("azmap.dev" in v for v in flat)
    assert "unrelated-subsidiary.example" not in flat                     # a tenant's other domains
    assert not any(v.startswith("msg-") for v in flat)                    # Message-IDs are not mailboxes
    assert ("email", "facturacion@proveedor-pagos.example") in vals2      # real participants stay
    assert ("ipv4", "198.51.100.23") in vals


def test_sender_domain_outside_its_tenant_is_phishing_on_its_own() -> None:
    from docutracex import mailengine
    t = {"tenants": [{"tenant_id": "x", "role": "sender", "status": "ok",
                      "data": {"brand_name": "Northwind Community College",
                               "related_domains": ["stmarys-school.example"]}}]}
    f = {"tenant": mailengine.tenant_facts(t, "lookalike-corp.example")}
    hit = next(r for r in mailengine.run(f, "email", {}) if r["id"] == "tenant_sender_domain_unrelated")
    assert hit["severity"] == "high" and hit["score"] >= 40
    assert mailengine.verdict([{"id": hit["id"], "score": hit["score"]}])["verdict"] == "phishing"


TYPOSQUAT_TENANT_ANSWER = {   # shaped like AZMap's page for a throw-away tenant (current + removed domains)
    "tenant_name": "nwcollege0", "brand_name": "Northwind Community College",
    "related_domains": [{"domain": d, "type": "Managed"} for d in
                        ("lumenfold.example", "grupoejernplo.example", "nwcollege1.example", "sarps.example",
                         "nwcollege0.example", "quorvane.example")] + [{"domain": "nwcollege0.onmicrosoft.com"}],
    "former_domains": ["pelmaris.example", "oxbrinte.example", "verdalune.example", "fenwickery.example"]}


def test_typosquat_verified_in_a_throwaway_tenant(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from docutracex import appsettings
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("DOCUTRACEX_TENANT_LOOKUP", "1")
    monkeypatch.setattr("docutracex.mailintel._routes", lambda proxy: [("direct", _Opener(
        TYPOSQUAT_TENANT_ANSWER, [], {"grupoejernplo.example": ms.M365_TYPOSQUAT_TENANT}))])
    appsettings.set_email_settings(["grupoejemplo.example"], [], None)
    _e, r = _analyse(ms.tenant_typosquat_eml())
    data = r["tenant"]["tenants"][0]["data"]
    assert "grupoejernplo.example" in data["related_domains"] and len(data["former_domains"]) == 4
    got = {m["id"]: m for m in r["engine"]["matched"]}
    assert "tenant_sender_domain_unrelated" not in got                  # it IS a domain of that tenant…
    ev = got["tenant_sender_lookalike"]["evidence"]                     # …and still detected: it imitates yours
    assert "grupoejernplo.example looks like grupoejemplo.example" in ev and "Managed domain of" in ev
    doms = r["tenant"]["domains"]
    assert doms[0]["domain"] == "grupoejernplo.example" and doms[0]["tenant_id"] == ms.M365_TYPOSQUAT_TENANT
    assert "4 removed" in got["tenant_domain_sprawl"]["evidence"]
    assert r["verdict"]["verdict"] == "phishing"


def test_former_domain_and_unverified_typosquat() -> None:
    from docutracex import mailengine
    data = tenantintel._normalise(TYPOSQUAT_TENANT_ANSWER)
    t = {"tenants": [{"tenant_id": "x", "role": "sender", "status": "ok", "data": data}]}
    f = mailengine.tenant_facts(t, "verdalune.example", ["grupoejemplo.example"], [])
    assert f["sender_domain_unrelated"].startswith("verdalune.example was removed from tenant")
    f = mailengine.tenant_facts(t, "grupoejemplo-pagos.example", ["grupoejemplo.example"], [])   # not in the tenant
    assert f["sender_domain_unrelated"] and "sent from tenant" in f["sender_lookalike"]
    f = mailengine.tenant_facts(t, "sarps.example", ["grupoejemplo.example"], [])
    assert any("grupoejernplo.example looks like grupoejemplo.example" in x for x in f["tenant_lookalikes"])


def test_microsoft_says_which_tenant_the_sender_domain_belongs_to(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    """Microsoft's answer (domain → tenant now) decides before AZMap's list: a
    domain registered to another tenant, or to none, is unrelated even if AZMap
    still lists it; only the sender's domains are sent, never your own."""
    from docutracex import appsettings, mailengine
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("DOCUTRACEX_TENANT_LOOKUP", "1")
    appsettings.set_email_settings(["grupoejemplo.example"], [], None)
    for owner, expect in (("11111111-0000-4000-8000-000000000000", "registered to another Microsoft 365 tenant"),
                          (None, "not registered to any Microsoft 365 tenant")):
        opener = _Opener(TYPOSQUAT_TENANT_ANSWER, [], {"grupoejernplo.example": owner})
        seen: list = []
        orig = opener.open
        monkeypatch.setattr(opener, "open", lambda req, timeout=None, o=orig: (seen.append(req.full_url), o(req))[1])
        monkeypatch.setattr("docutracex.mailintel._routes", lambda proxy, op=opener: [("direct", op)])
        _e, r = _analyse(ms.tenant_typosquat_eml())
        got = {m["id"]: m for m in r["engine"]["matched"]}
        assert expect in got["tenant_sender_domain_unrelated"]["evidence"]
        assert "tenant_sender_lookalike" in got
        assert not any("grupoejemplo.example" in u for u in seen if "microsoftonline" in u)   # never your domain
    assert mailengine.tenant_facts({}, "x.example")["sender_domain_unrelated"] == ""


def test_domain_lookups_are_never_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    owners = {"moved.example": "11111111-0000-4000-8000-000000000000"}
    monkeypatch.setattr("docutracex.mailintel._routes", lambda proxy: [("direct", _Opener({}, [], owners))])
    assert tenantintel.domain_lookup("moved.example")["tenant_id"].startswith("11111111")
    owners["moved.example"] = "22222222-0000-4000-8000-000000000000"            # moved to another tenant
    again = tenantintel.domain_lookup("moved.example")
    assert again["tenant_id"].startswith("22222222") and not again["cached"]
    assert tenantintel.MAX_DOMAINS == 10
