from __future__ import annotations

from fastapi.testclient import TestClient

from key_store.api import create_app
from key_store.store import KeyStore


def _store(tmp_path):
    db_path = tmp_path / "api.duckdb"
    keys = {"v1": KeyStore.generate_key()}
    return KeyStore(db_path=db_path, keks_b64=keys, active_kek_version="v1")


def test_password_endpoints(tmp_path):
    store = _store(tmp_path)
    client = TestClient(create_app(store=store))

    save_resp = client.put(
        "/v1/passwords",
        json={
            "agent_id": "agent-1",
            "name": "github",
            "username": "svc",
            "password": "secret-123",
            "url": "https://github.com",
        },
    )
    assert save_resp.status_code == 200
    assert save_resp.json()["password"] == "secret-123"

    get_resp = client.get("/v1/passwords/agent-1/github")
    assert get_resp.status_code == 200
    assert get_resp.json()["username"] == "svc"

    del_resp = client.delete("/v1/passwords/agent-1/github")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    missing_resp = client.get("/v1/passwords/agent-1/github")
    assert missing_resp.status_code == 404

    store.close()


def test_authorization_endpoints(tmp_path):
    store = _store(tmp_path)
    client = TestClient(create_app(store=store))

    save_resp = client.put(
        "/v1/authorizations",
        json={
            "agent_id": "agent-1",
            "provider": "discord",
            "account_id": "user-1",
            "access_token": "token-a",
            "refresh_token": "token-r",
            "scopes": ["identify"],
        },
    )
    assert save_resp.status_code == 200
    assert save_resp.json()["access_token"] == "token-a"

    get_resp = client.get(
        "/v1/authorizations/agent-1/discord",
        params={"account_id": "user-1"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["refresh_token"] == "token-r"

    del_resp = client.delete(
        "/v1/authorizations/agent-1/discord",
        params={"account_id": "user-1"},
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    store.close()


def test_key_endpoints(tmp_path):
    store = _store(tmp_path)
    client = TestClient(create_app(store=store))

    status_resp = client.get("/v1/keys/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["active_kek_version"] == "v1"

    rewrap_resp = client.post("/v1/keys/rewrap", json={})
    assert rewrap_resp.status_code == 200
    assert rewrap_resp.json()["target_kek_version"] == "v1"

    store.close()


def test_bearer_auth_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("KEY_STORE_BEARER_TOKEN", "test-token")
    store = _store(tmp_path)
    client = TestClient(create_app(store=store))

    missing = client.get("/v1/keys/status")
    assert missing.status_code == 401

    wrong = client.get("/v1/keys/status", headers={"Authorization": "Bearer wrong-token"})
    assert wrong.status_code == 401

    ok = client.get("/v1/keys/status", headers={"Authorization": "Bearer test-token"})
    assert ok.status_code == 200
    assert ok.json()["active_kek_version"] == "v1"

    store.close()
