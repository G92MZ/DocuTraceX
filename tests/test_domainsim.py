"""Global domain similarity: any file's domains vs your domains, the brands and
each other (Levenshtein, Damerau-Levenshtein, homoglyphs, IDN, other TLD,
embedded name), thresholds from Settings, no duplicate of the email rules."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from docutracex import appsettings, domainsim, similarity
from docutracex.config import settings


@pytest.fixture(autouse=True)
def _cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "cfg"))


def _cmp(cand: str, ref: str, kind: str = "brand", legit: tuple = ()) -> tuple | None:
    m = domainsim.compare(cand, ref, kind, similarity.thresholds(), legit)
    return m and (m["algorithm"], m["distance"])


def test_algorithms() -> None:
    assert _cmp("docusing.example", "docusign") == ("Damerau-Levenshtein", 1)
    assert similarity.levenshtein("docusing", "docusign") == 2 and similarity.damerau("docusing", "docusign") == 1
    assert _cmp("xn--pypal-4ve.example", "paypal") == ("homoglyph", 0)
    assert _cmp("login.rnicrosoft-online.example", "microsoft", legit=("microsoft.com",)) == ("embedded name + homoglyph", 0)
    assert _cmp("secure-pellizzaroti.test", "pellizzaroti.example", "own") == ("embedded name", 0)
    assert _cmp("pellizzaroti.co", "pellizzaroti.example", "own") == ("same name, other TLD", 0)
    assert _cmp("pelizaroti.example", "pellizzaroti.example", "own") == ("Levenshtein", 2)
    assert _cmp("www.microsoft.com", "microsoft", legit=("microsoft.com",)) is None      # the real one
    assert _cmp("pineapple.example", "apple") is None                                   # not a combosquat
    assert _cmp("https://user@docusing.example:8443/x?y", "docusign") == ("Damerau-Levenshtein", 1)


def test_thresholds_from_settings() -> None:
    appsettings.set_email_settings([], [], {"short_len": 4, "short_dist": 1, "long_dist": 1, "min_len": 4})
    assert _cmp("pelizaroti.example", "pellizzaroti.example", "own") is None
    assert _cmp("pelizzaroti.example", "pellizzaroti.example", "own") == ("Levenshtein", 1)


def _iocs(*values: tuple[str, str, str]) -> dict:
    return {"iocs": [{"type": t, "value": v, "occurrences": [{"module": "x", "location": loc}]} for t, v, loc in values]}


def test_run_own_brand_case_and_email_participants() -> None:
    r = domainsim.run(_iocs(("domain", "grupoejemp1o.example", "pdf/text"),
                            ("email", "facturacion@grupoejemplo-pagos.example", "email/chain/message 2 (quoted)/CC"),
                            ("url", "https://suministros-iberia.example/f", "js"),
                            ("url", "https://suministros-lberia.example/p", "js"),
                            ("domain", "grupoejemplo.example", "email/From")),
                      ["grupoejemplo.example"], [])
    by = {(m["candidate"], m["reference_kind"]): m for m in r["matches"]}
    assert ("grupoejemp1o.example", "own") in by and ("grupoejemplo-pagos.example", "own") in by
    assert ("suministros-iberia.example", "case") in by
    assert not any(m["candidate"] == "grupoejemplo.example" for m in r["matches"])      # our own domain
    rules = sorted(f["rule"] for f in r["findings"])
    assert rules.count("domain_lookalike_own") == 2 and "domain_similar_in_case" in rules
    f = next(f for f in r["findings"] if "grupoejemp1o" in f["detail"])
    assert f["severity"] == "high" and "pdf/text" in f["evidence"] and "threshold" in f["detail"]


def test_no_duplicate_of_email_rules() -> None:
    mail = [{"rule": "lookalike_domain", "detail": "Look-alike of docusign: 'docusing' ... (docusing.example)"}]
    r = domainsim.run(_iocs(("domain", "docusing.example", "email/body")), [], [], mail)
    assert r["matches"][0]["reported_by_email"] and not r["findings"]


def test_sample_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import make_samples as ms
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    c = TestClient(create_app())
    r = c.post("/api/cases", files={"file": ("visor.js", ms.lookalike_domains_js())}).json()
    for _ in range(600):
        t = next((x for x in c.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.1)
    res = c.get(f"/api/cases/{r['analysis_id']}/components").json()
    ds = res["modules"]["domainsim"]
    algos = {m["algorithm"] for m in ds["matches"]}
    assert {"Damerau-Levenshtein", "homoglyph", "embedded name + homoglyph", "Levenshtein",
            "embedded name + 1 edit"} <= algos
    assert "outlook.office.com" not in {m["candidate"] for m in ds["matches"]}     # a generic legitimate service
    rules = {f["rule"] for f in res["findings"] if f.get("source") == "domainsim"}
    assert {"domain_lookalike_brand", "domain_similar_in_case"} <= rules
