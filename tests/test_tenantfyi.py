"""tenant.fyi: names and current / former domains of a tenant, kept for good, into the card and the IOCs."""

from __future__ import annotations

import io
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_samples as ms  # noqa: E402
from test_msheaders import TYPOSQUAT_TENANT_ANSWER, _Opener  # noqa: E402

from docutracex import appsettings, mdreport, tenantintel  # noqa: E402,F401
from docutracex.config import settings  # noqa: E402

TID = ms.M365_TYPOSQUAT_TENANT


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setattr(settings, "tools_dir", tmp_path / "tools")


def _route(monkeypatch, opener) -> None:  # noqa: ANN001
    monkeypatch.setattr("docutracex.mailintel._routes", lambda proxy: [("direct", opener)])


def _ms() -> dict:
    return {"tenant_ids": [TID], "tenant_blocks": [{"tenant_id": TID, "role": "sender"}]}


def test_on_by_default_and_merged(monkeypatch: pytest.MonkeyPatch) -> None:
    assert tenantintel.fyi_enabled()
    calls: list = []
    _route(monkeypatch, _Opener(TYPOSQUAT_TENANT_ANSWER, calls, fyi=ms.TENANT_FYI_ANSWER))
    r = tenantintel.resolve(_ms(), [], [])["tenants"][0]
    assert any(c.startswith(f"https://tenant.fyi/api/tenants/{TID}?status=all") for c in calls)
    d = r["data"]
    assert "salvenor.example" in d["former_domains"] and len(d["former_domains"]) == 5   # 4 from AZMap + 1 more
    assert "Quorvane Trading" in d["names"] and d["sources"] == ["AZMap", "tenant.fyi"]
    assert r["fyi"]["status"] == "ok" and r["fyi"]["raw"]["total"] == 12               # the raw answer is stored
    pel = next(x for x in d["domains"] if x["domain"] == "pelmaris.example")
    assert pel["first_seen"] == "2026-03-02" and pel["last_seen"] == "2026-05-18"


def test_last_answer_kept_when_the_site_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _route(monkeypatch, _Opener(TYPOSQUAT_TENANT_ANSWER, [], fyi=ms.TENANT_FYI_ANSWER))
    assert tenantintel.fyi_lookup(TID)["status"] == "ok"
    c = tenantintel._load_cache("tenantfyi_cache.json")
    c[TID]["ts"] = 0                                                   # expired
    tenantintel._save_cache(c, "tenantfyi_cache.json")
    _route(monkeypatch, _Opener(TYPOSQUAT_TENANT_ANSWER, [], fyi=urllib.error.URLError("down")))
    r = tenantintel.fyi_lookup(TID)
    assert r["status"] == "ok" and r["stale"] and "down" in r["stale_reason"]
    assert "salvenor.example" in r["data"]["former_domains"]
    c = tenantintel._load_cache("tenantfyi_cache.json")
    c[TID]["ts"] = 0
    tenantintel._save_cache(c, "tenantfyi_cache.json")
    _route(monkeypatch, _Opener(TYPOSQUAT_TENANT_ANSWER, [], fyi=None))  # the site no longer has it
    assert tenantintel.fyi_lookup(TID)["stale"]


def test_unknown_tenant_and_switches(monkeypatch: pytest.MonkeyPatch) -> None:
    _route(monkeypatch, _Opener(TYPOSQUAT_TENANT_ANSWER, [], fyi=None))
    assert tenantintel.fyi_lookup("33333333-3333-4333-8333-333333333333")["status"] == "not_found"
    assert tenantintel.fyi_lookup("nope")["status"] == "invalid"
    appsettings.save({**appsettings.load(), "tenant_lookup": False})            # AZMap off, tenant.fyi on
    calls: list = []
    _route(monkeypatch, _Opener(TYPOSQUAT_TENANT_ANSWER, calls, fyi=ms.TENANT_FYI_ANSWER))
    r = tenantintel.resolve(_ms(), ["x.example"], [])
    assert all("tenant.fyi" in c for c in calls) and r["domains"] == []
    assert r["tenants"][0]["status"] == "ok" and r["tenants"][0]["data"]["brand_name"] == "Northwind Community College"
    appsettings.save({**appsettings.load(), "tenant_fyi_lookup": False})
    assert tenantintel.resolve(_ms(), [], [])["status"] == "disabled"


def test_tenant_into_the_iocs(monkeypatch: pytest.MonkeyPatch) -> None:
    _route(monkeypatch, _Opener(TYPOSQUAT_TENANT_ANSWER, [], fyi=ms.TENANT_FYI_ANSWER))
    t = tenantintel.resolve(_ms(), [], [])
    res = {"iocs": [{"type": "domain", "value": "verdalune.example", "occurrences": [], "count": 0}]}
    n = tenantintel.add_iocs(res, {"tenant": t})
    by = {(i["type"], i["value"]): i for i in res["iocs"]}
    assert by[("ms_tenant", TID)]["tenant"]["why"] == "tenant ID"
    assert "Quorvane Trading" in by[("ms_tenant", TID)]["occurrences"][0]["context"]
    assert ("domain", "nwcollege0.onmicrosoft.com") in by
    assert by[("domain", "salvenor.example")]["tenant"]["why"] == "former domain (2026-01-20 → 2026-02-27)"
    assert by[("domain", "verdalune.example")]["count"] == 1                    # an existing IOC gets the tag
    assert ("domain", "lumenfold.example") not in by                           # current domains stay context
    assert n == 7 and res["counts"]["ms_tenant"] == 1
    t["tenants"][0]["own_tenant"] = True                                       # never your own tenant
    res2: dict = {"iocs": []}
    assert tenantintel.add_iocs(res2, {"tenant": t}) == 0


def test_settings_api_default_on() -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import app
    c = TestClient(app)
    assert c.get("/api/settings/tenant-fyi-lookup").json() == {"enabled": True}
    assert c.put("/api/settings/tenant-fyi-lookup", json={"enabled": False}).json() == {"enabled": False}
    assert c.get("/api/settings/tenant-fyi-lookup").json() == {"enabled": False}



def test_end_to_end_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setenv("DOCUTRACEX_TENANT_LOOKUP", "1")
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    _route(monkeypatch, _Opener(TYPOSQUAT_TENANT_ANSWER, [], {"grupoejernplo.example": TID}, fyi=ms.TENANT_FYI_ANSWER))
    appsettings.set_email_settings(["grupoejemplo.example"], [], None)
    m = cases.create_case(io.BytesIO(ms.tenant_typosquat_eml()), "factura.eml", cases_dir=tmp_path / "cases")
    analyze.analyze_case(tmp_path / "cases" / m["analysis_id"])
    p = CasePaths(m["analysis_id"], cases_dir=tmp_path / "cases")
    iocs = {(i["type"], i["value"]): i for i in (read_json(p.subresult("iocs")) or {})["iocs"]}
    assert ("ms_tenant", TID) in iocs and iocs[("domain", "salvenor.example")]["tenant"]["why"].startswith("former")
    stored = (read_json(p.subresult("mailrules")) or {})["tenant"]["tenants"][0]["fyi"]
    assert stored["raw"]["total"] == 12                                       # tenant.fyi's answer kept in the case
    md = {s["id"]: s["markdown"] for s in mdreport.build(m["analysis_id"])}
    assert "former domain (2026-01-20 → 2026-02-27)" in md["iocs"]
