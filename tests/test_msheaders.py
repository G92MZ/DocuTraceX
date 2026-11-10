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
    def __init__(self, answer: object, calls: list) -> None:
        self.answer, self.calls = answer, calls

    def open(self, req, timeout=None):  # noqa: ANN001
        self.calls.append(req.full_url)
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
