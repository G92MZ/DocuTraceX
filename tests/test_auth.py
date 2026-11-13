"""Sign-in gate, first start, users, audit trail and the MCP token."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from docutracex import audit, users

H = {"X-DTX": "1"}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DOCUTRACEX_TEST_NO_AUTH", "0")              # the real gate
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path / "config"))
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    users._failures.clear()
    from docutracex.app import create_app
    with TestClient(create_app()) as c:
        yield c


def _setup(c: TestClient, pw: str = "Adm1n-pass!") -> None:
    r = c.post("/api/auth/setup", json={"password": pw}, headers=H)
    assert r.status_code == 200, r.text


def test_first_start_gate(client: TestClient) -> None:
    assert client.get("/api/auth/status").json()["setup_required"] is True
    r = client.get("/api/cases")
    assert r.status_code == 401 and r.json()["setup_required"] is True
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert "First start" in client.get("/login").text
    assert client.post("/api/auth/setup", json={"password": "short"}, headers=H).status_code == 400
    _setup(client)
    assert client.get("/api/cases").status_code == 200                # signed in by the setup
    assert client.post("/api/auth/setup", json={"password": "another-pass"}, headers=H).status_code == 409
    assert "Sign in" in client.get("/login").text


def test_login_logout_and_csrf_header(client: TestClient) -> None:
    _setup(client)
    client.post("/api/auth/logout", headers=H)
    assert client.get("/api/cases").status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "nope"}, headers=H).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "Adm1n-pass!"},
                       headers=H).status_code == 200
    # a change without the page's header is refused (CSRF), with it it goes through
    assert client.put("/api/settings/email", json={"own_domains": ["grupoejemplo.example"], "brands": []}).status_code == 403
    assert client.put("/api/settings/email", json={"own_domains": ["grupoejemplo.example"], "brands": []},
                      headers=H).status_code == 200


def test_lockout(client: TestClient) -> None:
    _setup(client)
    client.post("/api/auth/logout", headers=H)
    for _ in range(users.MAX_FAILURES):
        client.post("/api/auth/login", json={"username": "admin", "password": "bad"}, headers=H)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Adm1n-pass!"}, headers=H)
    assert r.status_code == 429


def test_users_admin_only_and_password_changes(client: TestClient) -> None:
    _setup(client)
    r = client.post("/api/users", json={"username": "analista", "password": "Analista-1"}, headers=H)
    assert r.status_code == 200 and r.json()["role"] == "user"
    assert client.post("/api/users", json={"username": "analista", "password": "Analista-1"}, headers=H).status_code == 400
    client.post("/api/auth/logout", headers=H)
    client.post("/api/auth/login", json={"username": "analista", "password": "Analista-1"}, headers=H)
    assert client.get("/api/cases").status_code == 200                # same cases for everyone
    assert client.get("/api/users").status_code == 403                # but no user management
    assert client.get("/api/audit").status_code == 403
    assert client.post("/api/mcp/token", headers=H).status_code == 403
    assert client.get("/api/mcp/token").json()["can_regenerate"] is False
    r = client.post("/api/auth/password", json={"current": "wrong", "new": "Nueva-clave-1"}, headers=H)
    assert r.status_code == 400
    r = client.post("/api/auth/password", json={"current": "Analista-1", "new": "Nueva-clave-1"}, headers=H)
    assert r.status_code == 200 and client.get("/api/cases").status_code == 200
    # admin disables the user: their session ends
    other = TestClient(client.app)
    other.post("/api/auth/login", json={"username": "admin", "password": "Adm1n-pass!"}, headers=H)
    assert other.put("/api/users/analista", json={"active": False}, headers=H).status_code == 200
    assert client.get("/api/cases").status_code == 401
    assert other.put("/api/users/admin", json={"active": False}, headers=H).status_code == 400
    assert other.delete("/api/users/admin", headers=H).status_code == 400
    assert other.delete("/api/users/analista", headers=H).status_code == 200


def test_audit_trail(client: TestClient) -> None:
    _setup(client)
    client.put("/api/settings/email", json={"own_domains": ["grupoejemplo.example"], "brands": ["grupoejemplo"]},
               headers=H)
    client.post("/api/users", json={"username": "analista", "password": "Analista-1"}, headers=H)
    client.post("/api/auth/logout", headers=H)
    client.post("/api/auth/login", json={"username": "analista", "password": "mal"}, headers=H)
    client.post("/api/auth/login", json={"username": "admin", "password": "Adm1n-pass!"}, headers=H)
    entries = client.get("/api/audit").json()["entries"]
    acts = [(e["user"], e["action"]) for e in entries]
    assert ("admin", "set the admin password (first start)") in acts
    assert ("admin", "changed settings") in acts
    assert ("admin", "created a user") in acts
    assert ("analista", "failed sign-in") in acts
    settings_e = next(e for e in entries if e["action"] == "changed settings")
    assert settings_e["detail"] == "fields: brands, own_domains"
    raw = (Path(audit._path())).read_text()
    assert "Analista-1" not in raw and "Adm1n-pass!" not in raw          # never a password
    csv = client.get("/api/audit.csv?user=analista").text
    assert csv.splitlines()[0].startswith("time,user,action") and "failed sign-in" in csv


def test_rerun_detail_and_uploader(client: TestClient) -> None:
    _setup(client)
    r = client.post("/api/cases", files={"file": ("factura.txt", b"hola")}, headers=H)
    aid = r.json()["analysis_id"]
    assert r.json()["uploaded_by"] == "admin"
    client.post(f"/api/cases/{aid}/rerun", json={"module": "yara"}, headers=H)
    e = client.get(f"/api/audit?case={aid}").json()["entries"]
    assert any(x["action"] == "uploaded a file for analysis" and x["detail"] == "factura.txt" for x in e)
    assert any(x["action"] == "re-ran the analysis" and x["detail"] == "yara" for x in e)


def test_sessions_stored_hashed_and_scrypt(client: TestClient, tmp_path: Path) -> None:
    _setup(client)
    tok = client.cookies.get(users.COOKIE)
    sess = json.loads((tmp_path / "config" / "sessions.json").read_text())
    assert tok not in sess and len(sess) == 1                           # the file alone signs nobody in
    stored = json.loads((tmp_path / "config" / "users.json").read_text())["users"]["admin"]["hash"]
    assert stored.startswith("scrypt$") and users.check_password("Adm1n-pass!", stored)


def test_reset_admin_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path))
    assert users.main(["reset-admin", "--password", "Primera-1"]) == 0     # creates it on a fresh install
    assert users.main(["reset-admin", "--password", "Segunda-1"]) == 0
    assert users.authenticate("admin", "Segunda-1", "t") == "admin"
    assert users.main(["reset-admin", "--password", "corta"]) == 1


def test_mcp_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_CONFIG_DIR", str(tmp_path))
    t = users.mcp_token()
    assert t.startswith("dtx_") and users.mcp_token() == t and users.mcp_token_ok(t)
    t2 = users.regenerate_mcp_token()
    assert t2 != t and not users.mcp_token_ok(t) and users.mcp_token_ok(t2) and not users.mcp_token_ok("")
