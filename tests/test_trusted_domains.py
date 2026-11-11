"""Look-alike tuning: the brand written with one edit inside a longer name, a
third distance tier for long names, and the generic legitimate domains
(services never compared; platforms: only the tenant part)."""

from __future__ import annotations

from pathlib import Path

import pytest

from docutracex import appsettings, domainsim, mailengine, similarity, trusted
from docutracex.parsers import mail_rules


@pytest.fixture(autouse=True)
def _cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "cfg"))


def _cmp(cand: str, ref: str, kind: str = "brand") -> tuple | None:
    m = domainsim.compare(cand, ref, kind, similarity.thresholds())
    return m and (m["algorithm"], m["distance"])


def test_brand_inside_a_longer_name() -> None:
    assert _cmp("outloook-outlet.example", "outlook") == ("embedded name + 1 edit", 1)      # typo + extra word
    assert _cmp("outloook-outlet.example", "outlook.com", "own") == ("embedded name + 1 edit", 1)
    assert _cmp("myoutlok365.example", "outlook") == ("embedded name + 1 edit", 1)           # glued, 7+ letters
    assert _cmp("secureoutlook.example", "outlook") == ("embedded name", 0)                 # anywhere, 6+ letters
    assert _cmp("loginmicrosoftonline.example", "microsoft") == ("embedded name", 0)


def test_no_new_false_positives() -> None:
    for host, ref in (("pineapple.example", "apple"),        # 5 letters: word / prefix only
                      ("amazing-deals.example", "amazon"),   # 6 letters: no edit glued to other text
                      ("outdoor-shop.example", "outlook"),   # 2 edits
                      ("microsd.example", "microsoft"),      # 9 letters: still 2 edits
                      ("officemax.example", "office365"),
                      ("google.example", "outlook")):
        assert _cmp(host, ref) is None, host


def test_third_tier_for_long_names() -> None:
    assert similarity.max_distance("santanderbank") == 3
    assert _cmp("santandrbnk.example", "santanderbank") == ("Levenshtein", 2)
    assert _cmp("sntandrbnk.example", "santanderbank") == ("Levenshtein", 3)
    appsettings.set_email_settings([], [], {"short_len": 4, "short_dist": 1, "long_len": 9, "long_dist": 2,
                                            "xlong_dist": 2, "min_len": 4})
    assert _cmp("sntandrbnk.example", "santanderbank") is None


def test_lists_keep_user_changes_across_default_updates() -> None:
    cur = trusted.lists({})
    assert "office.com" in cur["services"] and "sharepoint.com" in cur["platforms"]
    st = trusted.to_stored([d for d in cur["services"] if d != "zoom.us"] + ["corp-mail.example"], cur["platforms"])
    assert st == {"services_added": ["corp-mail.example"], "services_removed": ["zoom.us"],
                  "platforms_added": [], "platforms_removed": []}
    new = trusted.lists(st)
    assert "zoom.us" not in new["services"] and "corp-mail.example" in new["services"]
    assert "gmail.com" in new["services"]                                 # untouched defaults stay


def test_matcher_services_platforms_and_tenants() -> None:
    tm = trusted.Matcher(trusted.lists({}))
    assert tm.view("outlook.office.com") == (None, "")
    assert tm.view("bucket.storage.googleapis.com") == ("bucket.invalid", "storage.googleapis.com")  # longest wins
    assert tm.view("fonts.googleapis.com") == (None, "")
    assert tm.view("a.b.blob.core.windows.net") == ("a.b.invalid", "blob.core.windows.net")
    assert tm.view("sharepoint.com") == (None, "sharepoint.com")
    assert tm.view("evil.example") == ("evil.example", "")


def _run(*hosts: str, own: list[str] | None = None, brands: list[str] | None = None) -> dict:
    iocs = {"iocs": [{"type": "domain", "value": h, "occurrences": [{"module": "x", "location": "y"}]} for h in hosts]}
    return domainsim.run(iocs, own or [], brands or [])


def test_run_skips_services_and_judges_tenants() -> None:
    r = _run("outlook.office.com", "contoso.sharepoint.com", "outlook-login.sharepoint.com",
             "micros0ft-secure.onmicrosoft.com", own=["outlook.com", "contoso.com"])
    got = {m["candidate"]: m for m in r["matches"]}
    assert "outlook.office.com" not in got and "contoso.sharepoint.com" not in got
    assert got["outlook-login.sharepoint.com"]["platform"] == "sharepoint.com"
    assert got["outlook-login.sharepoint.com"]["candidate_registrable"] == "outlook-login.sharepoint.com"
    assert ".invalid" not in got["micros0ft-secure.onmicrosoft.com"]["reason"]
    assert r["trusted_skipped"] == 1


def test_email_checks_use_the_lists() -> None:
    assert mailengine.own_lookalike("outlook.office.com", ["outlook.com"]) == ""
    assert mailengine.own_lookalike("contoso.sharepoint.com", ["contoso.com"]) == ""
    assert mailengine.own_lookalike("contoso-pay.sharepoint.com", ["contoso.com"])
    assert mail_rules.check_domain("outlook.office.com") == []
    hit = mail_rules.check_domain("micros0ft-login.onmicrosoft.com")
    assert hit and "a tenant on onmicrosoft.com" in hit[0][2] and ".invalid" not in hit[0][2]


def test_user_added_service_and_api(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    c = TestClient(create_app())
    cur = c.get("/api/settings/trusted-domains").json()
    assert "gmail.com" in cur["defaults"]["services"]
    r = c.put("/api/settings/trusted-domains", json={"services": "\n".join(cur["services"] + ["outloook-outlet.example"]),
                                                     "platforms": cur["platforms"]}).json()
    assert "outloook-outlet.example" in r["services"]
    assert not [m for m in _run("outloook-outlet.example")["matches"]]          # listed by the user: never compared
    r = c.put("/api/settings/trusted-domains", json={"restore": True}).json()
    assert "outloook-outlet.example" not in r["services"] and r["services"] == list(trusted.SERVICES)
