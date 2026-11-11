"""Look-alike thresholds: one place, editable in Settings, used by own-domain
and brand look-alikes."""

from __future__ import annotations

from pathlib import Path

import pytest

from docutracex import appsettings, mailengine, similarity
from docutracex.parsers import mail_rules


@pytest.fixture(autouse=True)
def _cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path))


def test_defaults() -> None:
    th = similarity.thresholds()
    assert th == {"short_len": 4, "short_dist": 1, "long_len": 9, "long_dist": 2, "xlong_dist": 3, "min_len": 4}
    assert similarity.max_distance("zara") == 1 and similarity.max_distance("inditex") == 2
    assert similarity.max_distance("microsoft") == 2 and similarity.max_distance("santanderbank") == 3
    assert similarity.max_distance("ups") == 0                      # below min_len: not compared
    assert similarity.lookalike_distance("zura", "zara") == 1
    assert similarity.lookalike_distance("zuro", "zara") == 0       # 2 edits on a short name
    assert similarity.lookalike_distance("masimoduti", "massimodutti") == 2
    assert similarity.lookalike_distance("masimodti", "massimodutti") == 3      # 12 letters: up to 3
    assert similarity.lookalike_distance("zara", "zara") == 0


def test_own_domain_lookalike_uses_settings() -> None:
    own = ["zara.com", "massimodutti.com"]
    assert mailengine.own_lookalike("zura.example", own).startswith("zura.example ≈ zara.com (1 edit)")
    assert mailengine.own_lookalike("masimoduti.example", own).endswith("(2 edits)")
    assert mailengine.own_lookalike("zara.com", own) == "" and mailengine.own_lookalike("mail.zara.com", own) == ""
    appsettings.set_email_settings(own, [], {"short_len": 4, "short_dist": 0, "long_dist": 1, "min_len": 4})
    assert mailengine.own_lookalike("zura.example", own) == ""
    assert mailengine.own_lookalike("masimoduti.example", own) == ""
    assert mailengine.own_lookalike("massimodutti.example", own)          # same name, other TLD: always


def test_brand_lookalike_uses_settings() -> None:
    assert any(r == "lookalike_domain" and "2 edits" in e for r, _s, e in mail_rules.check_domain("paypall-secure.example")) is False
    hits = mail_rules.check_domain("micrsoft.example")
    assert hits and "1 edit away from 'microsoft'" in hits[0][2]
    assert not mail_rules.check_domain("dhs.example")                # 'dhl' is below min_len


def test_settings_api_validates(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    c = TestClient(create_app())
    r = c.put("/api/settings/email", json={"own_domains": "zara.com", "brands": "",
                                           "similarity": {"short_len": "5", "short_dist": 9, "long_dist": -1, "min_len": 3}}).json()
    assert r["similarity"] == {"short_len": 5, "short_dist": 5, "long_len": 9, "long_dist": 0, "xlong_dist": 0,
                               "min_len": 3}                     # a custom long distance carries to longer names
    assert c.get("/api/settings/email").json()["similarity_defaults"]["short_dist"] == 1


def test_sample_brand_lookalike() -> None:
    import sys
    import tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import make_samples as ms

    from docutracex.parsers import mail
    d = Path(tempfile.mkdtemp())
    p = d / "m.eml"
    p.write_bytes(ms.brand_lookalike_eml())
    e = mail.analyze(p, ".eml", d / "x")
    r = mail_rules.analyze(p, ".eml", e, d)
    assert any(f["rule"] == "lookalike_domain" and "2 edits away from 'microsoft'" in f.get("evidence", f.get("detail", "")) + str(f)
               for f in r["findings"])
